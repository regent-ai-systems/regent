"""regent CLI: serve | compile | ingest | evidence | verify | approve | decide | shim | lint"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import click

from regent import __version__
from regent.core.packs import PackError, load_packs


def _packs(paths: tuple[str, ...], firm: str | None = None) -> list:
    if not paths:
        paths = ("packs/dev_default",)
    try:
        return load_packs(list(paths), firm)
    except PackError as e:
        raise click.ClickException(f"pack error: {e}")


firm_option = click.option("--firm-overlay", "firm", default=None, type=click.Path(exists=True),
                           help="Firm overlay YAML (thresholds, lists). Default: firm.yaml beside the pack.")


def _store(db: str):
    if db == ":memory:":
        from regent.stores.memory import MemoryStore
        return MemoryStore()
    from regent.stores.sqlite import SQLiteStore
    return SQLiteStore(db)


def _parse_dt(s: str | None, default: datetime) -> datetime:
    if not s:
        return default
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


@click.group()
@click.version_option(__version__, prog_name="regent")
def cli() -> None:
    """Regent — vertical compliance layer for AI agents (policy decision service + evidence)."""
    import os
    logging.basicConfig(level=logging.DEBUG if os.environ.get("REGENT_DEBUG") else logging.INFO, format="%(message)s")


# ------------------------------------------------------------------------------------------ serve
@cli.command()
@click.option("--pack", "packs", multiple=True, help="Pack file or directory (repeatable).")
@firm_option
@click.option("--db", default="regent.db", show_default=True, help="SQLite path or :memory:")
@click.option("--grpc-port", default=9000, show_default=True)
@click.option("--http-port", default=9100, show_default=True, help="HTTP ext_authz (/authz) + admin API")
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--target", "targets", multiple=True, help="agentgateway MCP target names (for tool-name splitting).")
@click.option("--separator", default="_", show_default=True, help="agentgateway <target><sep><tool> separator")
@click.option("--approver", type=click.Choice(["inbox", "auto", "auto-reject"]), default="inbox", show_default=True,
              help="inbox: out-of-band via `regent approve` (+notifiers). auto*: demos only.")
@click.option("--slack-webhook", default=None, help="Slack incoming webhook URL to announce holds.")
@click.option("--teams-webhook", default=None)
@click.option("--webhook", default=None, help="Generic webhook URL (POST JSON hold).")
@click.option("--strict/--passthrough", default=False, show_default=True,
              help="strict: deny non-tools/call bodies at ext_authz instead of passing them through.")
def serve(packs, firm, db, grpc_port, http_port, host, targets, separator, approver, slack_webhook, teams_webhook, webhook, strict):
    """Run the Policy Decision Service (ext_authz gRPC + HTTP, admin API)."""
    from regent.approvers.inbox import AutoApprover, InboxApprover, PrintNotifier
    from regent.core.engine import Engine
    from regent.runtimes.agentgateway_extauthz import AgentgatewayRuntime

    loaded = _packs(packs, firm)
    store = _store(db)
    inbox = None
    if approver == "inbox":
        notifiers = [PrintNotifier()]
        admin = f"http://{host}:{http_port}"
        if slack_webhook:
            from regent.approvers.webhook import SlackNotifier
            notifiers.append(SlackNotifier(slack_webhook, admin))
        if teams_webhook:
            from regent.approvers.webhook import TeamsNotifier
            notifiers.append(TeamsNotifier(teams_webhook, admin))
        if webhook:
            from regent.approvers.webhook import WebhookNotifier
            notifiers.append(WebhookNotifier(webhook, admin))
        inbox = InboxApprover(notifiers)
        appr = inbox
    else:
        appr = AutoApprover(approvers=("auto-1", "auto-2"), roles=("trading_supervisor", "cco", "operations_manager",
                                                                    "ciso", "marketing_reviewer"),
                            decision="approve" if approver == "auto" else "reject")
    engine = Engine(loaded, store, appr)
    rt = AgentgatewayRuntime(engine, inbox, grpc_port, http_port, list(targets) or None, separator, not strict, host)

    async def main():
        await engine.record_policies("regent serve")
        click.echo(f"regent {__version__} · packs: {', '.join(p.name for p in loaded)} · db: {db}")
        click.echo(f"ext_authz gRPC {host}:{grpc_port} · HTTP authz http://{host}:{http_port}/authz · admin http://{host}:{http_port}/v1")
        await rt.serve()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


# ------------------------------------------------------------------------------------------ compile
@cli.command("compile")
@click.option("--pack", "packs", multiple=True)
@firm_option
@click.option("--dialect", type=click.Choice(["cel", "cedar", "rego"]), default="cel", show_default=True)
@click.option("--pds", default="localhost:9000", show_default=True, help="PDS host:port for extAuthz (cel).")
@click.option("--protocol", type=click.Choice(["grpc", "http"]), default="grpc", show_default=True)
@click.option("--full", is_flag=True, help="cel: emit a complete agentgateway config (needs --targets-file).")
@click.option("--targets-file", type=click.Path(exists=True), default=None,
              help="YAML list of agentgateway MCP targets for --full.")
@click.option("--port", default=3000, show_default=True, help="gateway port for --full")
@click.option("-o", "--out", type=click.Path(), default=None)
@click.option("--validate", type=click.Path(exists=True), default=None,
              help="Path to the agentgateway binary; validate the emitted config with --validate-only (cel --full).")
def compile_cmd(packs, firm, dialect, pds, protocol, full, targets_file, port, out, validate):
    """Compile packs to a runtime's native policy dialect (cheap rules native; the rest routed to the PDS)."""
    import yaml
    loaded = _packs(packs, firm)
    if dialect == "cel":
        from regent.compilers.cel import CELCompiler, agentgateway_config
        if full:
            if not targets_file:
                raise click.ClickException("--full needs --targets-file")
            targets = yaml.safe_load(Path(targets_file).read_text())
            text = agentgateway_config(loaded, targets, port, pds, protocol)
            res = CELCompiler(pds, protocol).compile(loaded)
        else:
            res = CELCompiler(pds, protocol).compile(loaded)
            text = res.text
    elif dialect == "cedar":
        from regent.compilers.cedar import CedarCompiler
        res = CedarCompiler().compile(loaded)
        text = res.text
    else:
        from regent.compilers.rego import RegoCompiler
        res = RegoCompiler().compile(loaded)
        text = res.text
    if out:
        Path(out).write_text(text)
        click.echo(f"wrote {out}")
    else:
        click.echo(text)
    click.echo(f"\n# native: {len(res.native_rule_ids)} rule(s) {res.native_rule_ids}", err=True)
    click.echo(f"# PDS:    {len(res.pds_rule_ids)} rule(s) {res.pds_rule_ids}", err=True)
    for n in res.notes:
        click.echo(f"#   {n}", err=True)
    if validate and dialect == "cel" and full:
        import subprocess
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(text)
        r = subprocess.run([validate, "-f", f.name, "--validate-only"], capture_output=True, text=True)
        click.echo(f"# agentgateway --validate-only: {'OK' if r.returncode == 0 else 'FAILED'}", err=True)
        if r.returncode != 0:
            click.echo(r.stderr.splitlines()[0] if r.stderr else r.stdout, err=True)
            sys.exit(2)


# ------------------------------------------------------------------------------------------ ingest
@cli.command()
@click.option("--pack", "packs", multiple=True)
@firm_option
@click.option("--db", default="regent.db", show_default=True)
@click.option("--source", type=click.Choice(["otlp", "jsonl", "agt"]), default="otlp", show_default=True)
@click.option("--file", "path", type=click.Path(exists=True), default=None, help="jsonl/agt input file")
@click.option("--port", default=4318, show_default=True, help="OTLP/HTTP listen port")
@click.option("--host", default="127.0.0.1", show_default=True)
def ingest(packs, firm, db, source, path, port, host):
    """Ingest audit events (OTLP receiver, JSONL file, AGT Merkle log) into the hash chain."""
    from regent.sources.ingest import ingest as run_ingest
    loaded = _packs(packs, firm)
    store = _store(db)

    async def main():
        if source == "otlp":
            from regent.sources.otel_otlp import OTLPSource
            src = OTLPSource(host, port)
            await src.start()
            click.echo(f"OTLP/HTTP receiver on http://{host}:{port}/v1/traces and /v1/logs → {db}  (Ctrl-C to stop)")
            try:
                n = await run_ingest(src, loaded, store)
            finally:
                await src.stop()
        elif source == "jsonl":
            from regent.sources.jsonl import JSONLSource
            if not path:
                raise click.ClickException("--file required")
            n = await run_ingest(JSONLSource(path), loaded, store)
        else:
            from regent.sources.agt_merkle import AGTMerkleSource
            if not path:
                raise click.ClickException("--file required")
            src = AGTMerkleSource(path)
            n = await run_ingest(src, loaded, store)
            if not src.chain_ok:
                click.echo(f"WARNING: {src.chain_error}", err=True)
        click.echo(f"ingested {n} event(s)")

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


# ------------------------------------------------------------------------------------------ evidence
@cli.command()
@click.option("--pack", "packs", multiple=True)
@firm_option
@click.option("--db", default="regent.db", show_default=True)
@click.option("--from", "start", default=None, help="ISO datetime (default: 90 days ago)")
@click.option("--to", "end", default=None, help="ISO datetime (default: now)")
@click.option("--firm", "firm_name", default="", help="Firm name for the package header")
@click.option("--reachable", type=click.Path(exists=True), default=None,
              help="Text file, one tool per line, of tools reachable through the gateway (coverage gaps).")
@click.option("-o", "--out", type=click.Path(), default="evidence", show_default=True, help="Output basename")
@click.option("--format", "fmt", type=click.Choice(["md", "json", "both"]), default="both", show_default=True)
def evidence(packs, firm, db, start, end, firm_name, reachable, out, fmt):
    """Generate the period evidence package (Markdown + JSON) from the chain."""
    from regent.core.evidence import build_evidence, render_markdown
    loaded = _packs(packs, firm)
    store = _store(db)
    now = datetime.now(timezone.utc)
    ps, pe = _parse_dt(start, now - timedelta(days=90)), _parse_dt(end, now + timedelta(seconds=1))
    tools = [ln.strip() for ln in Path(reachable).read_text().splitlines() if ln.strip()] if reachable else None

    async def main():
        entries = await store.entries()
        ev = build_evidence(entries, loaded, ps, pe, tools, firm_name)
        if fmt in ("json", "both"):
            Path(f"{out}.json").write_text(json.dumps(ev, indent=2, default=str))
            click.echo(f"wrote {out}.json")
        if fmt in ("md", "both"):
            Path(f"{out}.md").write_text(render_markdown(ev))
            click.echo(f"wrote {out}.md")
        t, s = ev["totals"], ev["supervision"]
        click.echo(f"period {ps.date()} → {pe.date()}: {t['decisions']} decisions · {t['allowed']} allow · {t['denied']} deny · "
                   f"{t['held']} hold · {s['holds']} holds ({s['approved']} approved) · chain "
                   f"{'INTACT' if ev['chain_integrity']['ok'] else 'BROKEN'} · gaps {len(ev['coverage_gaps'])}")

    asyncio.run(main())


# ------------------------------------------------------------------------------------------ verify
@cli.command()
@click.option("--db", default="regent.db", show_default=True)
@click.option("--json", "as_json", is_flag=True)
def verify(db, as_json):
    """Verify the hash chain. Exit 1 on a break."""
    from regent.core.chain import verify as run_verify
    store = _store(db)
    res = run_verify(asyncio.run(store.entries()))
    if as_json:
        click.echo(json.dumps(res.to_dict()))
    else:
        click.echo(f"{'OK' if res.ok else 'BROKEN'}: {res.entries} entries" + (f" · head {res.head_hash}" if res.head_hash else "")
                   + (f" · first bad seq {res.first_bad_seq}: {res.reason}" if not res.ok else ""))
    sys.exit(0 if res.ok else 1)


# ------------------------------------------------------------------------------------------ approve
@cli.command()
@click.argument("hold_id", required=False)
@click.option("--pds", default="http://127.0.0.1:9100", show_default=True, help="PDS admin URL")
@click.option("--as", "approver", default=None, help="Approver username")
@click.option("--role", "roles", multiple=True, help="Approver role(s), e.g. trading_supervisor, cco")
@click.option("--attest", is_flag=True, help="Accept the rule's attestation text")
@click.option("--reject", is_flag=True)
@click.option("--comment", default=None)
@click.option("--list", "list_", is_flag=True, help="List pending holds")
def approve(hold_id, pds, approver, roles, attest, reject, comment, list_):
    """Approve or reject a pending hold on a running PDS (out-of-band)."""
    import httpx
    if list_ or not hold_id:
        r = httpx.get(f"{pds}/v1/holds", timeout=10)
        r.raise_for_status()
        holds = r.json()
        if not holds:
            click.echo("no pending holds")
        for h in holds:
            a = h["approval"]
            click.echo(f"{h['id']}  {h['call']['tool']}  user={h['call']['principal']['user']}  rule={h['rule_id']}  "
                       f"{a['workflow']} approvers={a['approvers']}  args={json.dumps(h['call']['args'])[:80]}")
            if a["attest"]:
                click.echo(f"    attest: {a['attest']}")
        return
    if not approver:
        raise click.ClickException("--as <approver> is required")
    body = {"approver": approver, "roles": list(roles), "decision": "reject" if reject else "approve",
            "attestation_accepted": attest, "comment": comment}
    r = httpx.post(f"{pds}/v1/holds/{hold_id}/approve", json=body, timeout=15)
    if r.status_code >= 400:
        raise click.ClickException(f"{r.status_code}: {r.text}")
    h = r.json()["hold"]
    click.echo(f"{hold_id}: {h['status']}  approvals={[(x['approver'], x['decision']) for x in h['approvals']]}")


# ------------------------------------------------------------------------------------------ decide
@cli.command()
@click.argument("tool")
@click.option("--args", "args_json", default="{}", help="JSON arguments")
@click.option("--user", default="dev")
@click.option("--agent", default="cli")
@click.option("--role", "roles", multiple=True)
@click.option("--claim", "claims", multiple=True, help="key=json  e.g. assigned_accounts='[\"A1\"]'")
@click.option("--pds", default=None, help="Ask a running PDS instead of deciding locally")
@click.option("--pack", "packs", multiple=True)
@firm_option
@click.option("--db", default=":memory:", show_default=True)
def decide(tool, args_json, user, agent, roles, claims, pds, packs, firm, db):
    """Decide one call (locally or against a running PDS). Exit 0 allow, 3 hold, 1 deny."""
    cl = {}
    for c in claims:
        k, _, v = c.partition("=")
        try:
            cl[k] = json.loads(v)
        except json.JSONDecodeError:
            cl[k] = v
    payload = {"tool": tool, "args": json.loads(args_json),
               "principal": {"user": user, "agent": agent, "roles": list(roles), "claims": cl}}
    if pds:
        import httpx
        d = httpx.post(f"{pds}/v1/decide", json=payload, timeout=15).json()
    else:
        from regent.approvers.inbox import AutoApprover
        from regent.core.engine import Engine
        from regent.core.models import Principal, ToolCall
        eng = Engine(_packs(packs, firm), _store(db), AutoApprover())
        call = ToolCall(tool=tool, args=payload["args"], principal=Principal(user=user, agent=agent, roles=tuple(roles), claims=cl))
        d = asyncio.run(eng.decide(call)).to_dict()
    click.echo(json.dumps(d, indent=2))
    sys.exit({"allow": 0, "hold": 3, "deny": 1}[d["verdict"]])


# ------------------------------------------------------------------------------------------ shim
@cli.command(context_settings={"ignore_unknown_options": True})
@click.option("--pack", "packs", multiple=True)
@firm_option
@click.option("--db", default=":memory:", show_default=True)
@click.option("--target", default="local", show_default=True, help="Target name prefix for tools")
@click.option("--user", default="local-user")
@click.option("--auto-approve", is_flag=True, help="Demo: approve holds automatically")
@click.argument("cmd", nargs=-1, required=True)
def shim(packs, firm, db, target, user, auto_approve, cmd):
    """Run Regent inline between an MCP client and a stdio MCP server: regent shim -- npx server ..."""
    from regent.approvers.cli import CLIApprover
    from regent.approvers.inbox import AutoApprover
    from regent.core.engine import Engine
    from regent.core.models import Principal
    from regent.runtimes.stdio_shim import StdioShim
    cmd = [c for c in cmd if c != "--"]
    eng = Engine(_packs(packs, firm), _store(db), AutoApprover() if auto_approve else CLIApprover())
    asyncio.run(StdioShim(eng, list(cmd), target, Principal(user=user, agent="stdio-shim")).serve())


# ------------------------------------------------------------------------------------------ lint
@cli.command()
@click.argument("paths", nargs=-1, required=True)
@firm_option
def lint(paths, firm):
    """Validate packs: syntax, expressions, every rule cites controls + examiner_asks, firm overlay complete."""
    ok = True
    for p in paths:
        try:
            pk = load_packs([p], firm)[0]
            click.echo(f"OK   {p}: {pk.name} v{pk.version} · {len(pk.rules)} rules · "
                       f"{sum(1 for r in pk.rules if r.needs_args)} need args · {sum(1 for r in pk.rules if r.no_override)} no-override · "
                       f"{len(pk.firm)} firm keys · {len(pk.exam_requests)} exam-request items")
            unknown = {c for r in pk.rules for c in r.controls if pk.controls and c not in pk.controls}
            if unknown:
                click.echo(f"     warning: controls cited but not defined in controls: map: {sorted(unknown)}")
            for item in pk.exam_requests:
                bad = [rid for rid in item.get("answered_by", []) if pk.rule(rid) is None]
                if bad:
                    ok = False
                    click.echo(f"FAIL {p}: exam_requests item {item.get('item')!r} cites unknown rule(s) {bad}")
        except PackError as e:
            ok = False
            click.echo(f"FAIL {p}: {e}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    cli()
