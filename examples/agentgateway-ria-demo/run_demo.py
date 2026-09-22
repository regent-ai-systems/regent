"""End-to-end RIA demo against the REAL agentgateway binary.

    python examples/agentgateway-ria-demo/run_demo.py --agentgateway /path/to/agentgateway

What it does (all local, ~20 s):
  1. Generates an RSA key, a JWKS file and a JWT for user "agent7" (assigned accounts, no options approval).
  2. Compiles the RIA pack to an agentgateway config (CEL allow-list + extAuthz → Regent) and validates it
     with `agentgateway --validate-only`.
  3. Starts the Regent PDS (ext_authz gRPC :9000, admin :9100, SQLite demo.db) and agentgateway (:3000).
  4. Runs an MCP client through the gateway:
       tools/list                       → delete/void tools are hidden by the gateway (native CEL)
       small trade                      → allow
       large trade                      → hold → `regent approve` ×2 (four-eyes, attestation) → retry → allow
       options trade                    → deny (PDS, args)
       email with an SSN                → deny, no override
       crm.delete_contact               → deny natively by the gateway (never reaches Regent)
       custodian.get_positions          → deny by default + coverage gap
  5. Verifies the chain and writes evidence.md / evidence.json.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
OUT = HERE / "out"
GW_PORT, PDS_GRPC, PDS_HTTP = 3000, 9000, 9100


def make_jwt_material() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key().public_numbers()

    def b64(n: int) -> str:
        import base64
        return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

    jwks = {"keys": [{"kty": "RSA", "kid": "demo", "use": "sig", "alg": "RS256", "n": b64(pub.n), "e": b64(pub.e)}]}
    (OUT / "jwks.json").write_text(json.dumps(jwks))
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    claims = {"iss": "regent-demo", "aud": "ria-agents", "sub": "agent7", "azp": "portfolio-assistant",
              "roles": ["trader"], "assigned_accounts": ["ACC-1001", "ACC-1002"],
              "approved_templates": ["IMA-2026-v3"], "exp": int(time.time()) + 3600, "iat": int(time.time())}
    tok = jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "demo"})
    (OUT / "token.jwt").write_text(tok)
    return tok


def build_config(agentgateway: str) -> Path:
    sys.path.insert(0, str(ROOT))
    import yaml
    from regent.compilers.cel import agentgateway_config
    from regent.core.packs import load_packs
    packs = load_packs([str(ROOT / "packs" / "ria")], str(ROOT / "packs" / "ria" / "firm.example.yaml"))
    targets = yaml.safe_load((HERE / "targets.yaml").read_text())
    cfg = agentgateway_config(packs, targets, GW_PORT, f"localhost:{PDS_GRPC}", "grpc",
                              jwt={"issuer": "regent-demo", "audiences": ["ria-agents"], "jwks": {"file": str(OUT / "jwks.json")}})
    path = OUT / "agentgateway.yaml"
    path.write_text(cfg)
    r = subprocess.run([agentgateway, "-f", str(path), "--validate-only"], capture_output=True, text=True)
    print(f"[demo] agentgateway --validate-only: {(r.stdout + r.stderr).strip().splitlines()[0]}")
    if r.returncode != 0:
        sys.exit(2)
    return path


async def wait_http(url: str, timeout: float = 20) -> None:
    t0 = time.time()
    async with httpx.AsyncClient() as c:
        while time.time() - t0 < timeout:
            try:
                r = await c.get(url, timeout=1)
                if r.status_code < 500:
                    return
            except Exception:
                pass
            await asyncio.sleep(0.25)
    raise RuntimeError(f"timeout waiting for {url}")


async def approve(hold_id: str, who: str, role: str) -> dict:
    async with httpx.AsyncClient() as c:
        r = await c.post(f"http://127.0.0.1:{PDS_HTTP}/v1/holds/{hold_id}/approve",
                         json={"approver": who, "roles": [role], "decision": "approve", "attestation_accepted": True}, timeout=15)
        return r.json()


class McpHttp:
    """Minimal MCP streamable-HTTP client. The official SDK raises and tears the session
    down on any non-2xx, but a Regent hold/deny *is* a 403 with a JSON body, so we speak
    JSON-RPC over httpx directly and keep the session alive."""

    def __init__(self, url: str, token: str):
        self.url, self.token, self.sid, self.n = url, token, None, 0
        self.c = httpx.AsyncClient(timeout=20)

    def _headers(self) -> dict:
        h = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json",
             "Accept": "application/json, text/event-stream"}
        if self.sid:
            h["Mcp-Session-Id"] = self.sid
        return h

    @staticmethod
    def _parse(r: httpx.Response) -> dict:
        if r.headers.get("content-type", "").startswith("text/event-stream"):
            for line in r.text.splitlines():
                if line.startswith("data:"):
                    return json.loads(line[5:].strip())
            return {}
        return r.json() if r.content else {}

    async def rpc(self, method: str, params: dict | None = None, notify: bool = False) -> tuple[int, dict]:
        self.n += 1
        msg = {"jsonrpc": "2.0", "method": method, "params": params or {}}
        if not notify:
            msg["id"] = self.n
        r = await self.c.post(self.url, headers=self._headers(), content=json.dumps(msg))
        if r.headers.get("mcp-session-id"):
            self.sid = r.headers["mcp-session-id"]
        try:
            body = self._parse(r)
        except Exception:
            body = {"raw": r.text[:300]}
        return r.status_code, body

    async def initialize(self) -> None:
        st, _ = await self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                              "clientInfo": {"name": "regent-demo", "version": "0.1"}})
        assert st == 200, f"initialize failed: {st}"
        await self.rpc("notifications/initialized", notify=True)

    async def list_tools(self) -> list[str]:
        _, body = await self.rpc("tools/list")
        return sorted(t["name"] for t in body.get("result", {}).get("tools", []))

    async def call(self, name: str, args: dict) -> dict:
        st, body = await self.rpc("tools/call", {"name": name, "arguments": args})
        if st == 200:
            res = body.get("result", {})
            return {"verdict": "error" if res.get("isError") else "allow", "http": st,
                    "detail": (res.get("content") or [{}])[0].get("text", "")[:200]}
        if st == 403 and "verdict" in body:
            return {"http": st, **{k: body.get(k) for k in ("verdict", "rule_id", "reason", "hold_id", "retry_after_s")}}
        return {"verdict": "blocked", "http": st, "detail": json.dumps(body)[:300]}


async def scenario(token: str) -> list[dict]:
    results: list[dict] = []
    cli = McpHttp(f"http://127.0.0.1:{GW_PORT}/mcp", token)
    await cli.initialize()
    names = await cli.list_tools()
    print(f"[demo] tools/list through the gateway: {names}")
    results.append({"label": "tools/list", "tools": names})
    hidden = [n for n in names if "delete" in n or "get_" in n]
    print(f"[demo] ungoverned/denied tools visible: {hidden or 'none (hidden natively by the CEL allow-list)'}")

    async def call(name: str, args: dict, label: str) -> dict:
        info = {"label": label, "tool": name, **(await cli.call(name, args))}
        print(f"[demo] {label:38s} → {info['verdict']:7s} {info.get('rule_id') or ''}  {info.get('reason') or info.get('detail', '')[:60]}")
        results.append(info)
        return info

    trade = {"account": "ACC-1001", "security_id": "VTI", "notional_usd": 12000,
             "order_terms": {"side": "buy", "quantity": 40, "order_type": "market", "tif": "day"},
             "discretionary": True, "recommended_by": "model:core-60-40", "placed_by": "portfolio-assistant on behalf of agent7",
             "executing_broker": "CUSTODIAN-BD"}
    big = {**trade, "notional_usd": 400000, "order_terms": {**trade["order_terms"], "quantity": 1300}}
    email = {"to": ["client@example.com"], "subject": "Hello", "body": "Quarterly review is Tuesday.", "archived": True}
    xfer = {"account": "ACC-1001", "amount_usd": 5000, "destination": "X"}

    await call("custodian_place_trade", trade, "routine discretionary trade")
    h = await call("custodian_place_trade", big, "large trade (exception hold)")
    if h.get("hold_id"):
        bad = await approve(h["hold_id"], "agent7", "trading_supervisor")
        print(f"[demo]   approval by requester agent7 (SoD)   → {bad['hold']['status']} · approvals counted: "
              f"{sum(1 for a in bad['hold']['approvals'] if a['decision'] == 'approve')}")
        a1 = await approve(h["hold_id"], "maria.cco", "trading_supervisor")
        print(f"[demo]   approval by maria.cco (attested)     → {a1['hold']['status']}")
        await asyncio.sleep(0.3)
        await call("custodian_place_trade", big, "large trade retry after approval")
        await call("custodian_place_trade", big, "same trade again (grant is single-use)")
    await call("custodian_place_trade", {**trade, "security_id": "ACME"}, "restricted-list security (hold)")
    await call("custodian_place_trade", {**trade, "discretionary": False}, "non-discretionary, no instruction")
    await call("custodian_place_trade", {**trade, "discretionary": False, "client_instruction_id": "CI-42"}, "non-discretionary with instruction")
    await call("custodian_place_trade", {k: v for k, v in trade.items() if k != "executing_broker"}, "order memorandum incomplete")
    await call("custodian_place_trade", {**trade, "security_type": "options"}, "options, account not approved")
    await call("custodian_place_trade", {**trade, "capacity": "principal"}, "principal trade without consent")
    await call("custodian_transfer_funds", {**xfer, "destination_type": "first_party", "transfer_type": "journal", "like_titled": True},
               "like-titled journal (custody-free)")
    await call("custodian_transfer_funds", {**xfer, "destination_type": "first_party", "transfer_type": "wire"}, "first-party wire (ops hold)")
    await call("custodian_transfer_funds", {**xfer, "destination_type": "third_party", "transfer_type": "wire", "sloa_id": "S1",
                                            "sloa_all_seven_conditions_met": True}, "third-party with SLOA (four-eyes)")
    await call("custodian_transfer_funds", {**xfer, "destination_type": "third_party", "transfer_type": "wire"}, "third-party without SLOA")
    await call("custodian_transfer_funds", {**xfer, "destination_type": "first_party", "transfer_type": "journal", "like_titled": True,
                                            "instructions_changed_days_ago": 4}, "payee changed 4 days ago (red flag)")
    await call("email_send", {**email, "body": "Hi, confirming SSN 123-45-6789 on file."}, "email containing an SSN")
    await call("email_send", email, "one-to-one client email")
    await call("email_send", {**email, "audience": "prospect", "offers_services": True}, "one-to-one prospect email (not an ad)")
    await call("email_send", {**email, "to": ["a@x.com", "b@x.com"], "offers_services": True}, "multi-recipient offer (advertisement)")
    await call("email_send", {**email, "body": "Your statement for account 12345678 is attached."}, "account number, not email of record")
    await call("email_send", {**email, "archived": False}, "unarchived email")
    await call("crm_delete_contact", {"contact_id": "C-1"}, "crm.delete_contact (no-override deny)")
    await call("custodian_get_positions", {"account": "ACC-1001"}, "custodian.get_positions (no rule)")
    await cli.c.aclose()
    return results


async def main(agentgateway: str) -> None:
    OUT.mkdir(exist_ok=True)
    for f in ("demo.db", "demo.db-wal", "demo.db-shm"):
        (OUT / f).unlink(missing_ok=True)
    token = make_jwt_material()
    cfg = build_config(agentgateway)
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    pds = subprocess.Popen([sys.executable, "-m", "regent.cli.main", "serve", "--pack", str(ROOT / "packs" / "ria"),
                            "--firm-overlay", str(ROOT / "packs" / "ria" / "firm.example.yaml"),
                            "--db", str(OUT / "demo.db"), "--grpc-port", str(PDS_GRPC), "--http-port", str(PDS_HTTP),
                            "--target", "custodian", "--target", "crm", "--target", "email", "--target", "esign"],
                           env=env, cwd=ROOT, stdout=open(OUT / "pds.log", "w"), stderr=subprocess.STDOUT)
    gw = None
    try:
        await wait_http(f"http://127.0.0.1:{PDS_HTTP}/healthz")
        gw = subprocess.Popen([agentgateway, "-f", str(cfg)], cwd=ROOT, env=env,
                              stdout=open(OUT / "agentgateway.log", "w"), stderr=subprocess.STDOUT)
        await asyncio.sleep(2.5)
        if gw.poll() is not None:
            print((OUT / "agentgateway.log").read_text()[-2000:])
            raise SystemExit("agentgateway exited")
        results = await scenario(token)
        (OUT / "results.json").write_text(json.dumps(results, indent=2))
        async with httpx.AsyncClient() as c:
            v = (await c.get(f"http://127.0.0.1:{PDS_HTTP}/v1/verify")).json()
        print(f"[demo] chain: {'INTACT' if v['ok'] else 'BROKEN'} · {v['entries']} entries · head {v.get('head_hash', '')[:16]}…")
    finally:
        for p in (gw, pds):
            if p and p.poll() is None:
                p.send_signal(signal.SIGINT)
                try:
                    p.wait(5)
                except subprocess.TimeoutExpired:
                    p.kill()
    reach = OUT / "reachable_tools.txt"
    reach.write_text("\n".join(["custodian.place_trade", "custodian.transfer_funds", "custodian.debit_fee", "custodian.get_positions",
                                "crm.get_contact", "crm.export", "crm.delete_contact", "email.send", "esign.send_envelope",
                                "esign.void_envelope"]))
    subprocess.run([sys.executable, "-m", "regent.cli.main", "evidence", "--pack", str(ROOT / "packs" / "ria"),
                    "--firm-overlay", str(ROOT / "packs" / "ria" / "firm.example.yaml"), "--db", str(OUT / "demo.db"),
                    "--firm", "Demo Capital Advisors LLC", "--reachable", str(reach), "-o", str(OUT / "evidence")], env=env, cwd=ROOT)
    print(f"[demo] wrote {OUT / 'evidence.md'} and {OUT / 'evidence.json'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--agentgateway", default=shutil.which("agentgateway") or os.environ.get("AGENTGATEWAY"),
                    help="path to the agentgateway binary")
    a = ap.parse_args()
    if not a.agentgateway:
        sys.exit("need --agentgateway /path/to/binary (https://github.com/agentgateway/agentgateway/releases)")
    asyncio.run(main(a.agentgateway))
