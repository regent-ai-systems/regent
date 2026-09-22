"""Pack → agentgateway CEL (``mcpAuthorization.rules``) + extAuthz policy block.

Facts about agentgateway (verified against v1.5.0 with ``--validate-only``):

- ``mcpAuthorization.rules`` is an allow-list of CEL expressions; a tool call is
  allowed if any rule is true, otherwise denied, and unauthorized tools are
  filtered out of ``tools/list``. Variables: ``mcp.tool.name``, ``mcp.tool.target``,
  ``jwt.<claim>``, ``has(jwt.x)``.
- Tool *arguments are not available* in mcpAuthorization (``mcp.tool.arguments``
  is post-request, logging only). Rules that reference ``args`` therefore
  cannot be native. They compile to a tool-level allow (so the call reaches
  ``extAuthz``) and the PDS enforces the argument logic.
- ``extAuthz`` takes ``includeRequestBody`` at the policy level, protocol
  ``grpc`` (with CEL ``metadata``) or ``http``.

So for every rule:
  native-only (no args, no hold, no state):  allow-rule = tool match && translated condition
  PDS-required (args / hold_if / approval):   allow-rule = tool match         (PDS decides)
Tools with no rule at all get no allow-rule → agentgateway denies them natively
and hides them from tools/list. That is the deny-by-default, enforced twice.
"""
from __future__ import annotations

import yaml

from regent.compilers.translate import Dialect, Uncompilable, split_tool, translate
from regent.core.models import Pack, Rule
from regent.core.ports import CompiledPolicy

CEL = Dialect(
    name="cel",
    args_ref=lambda a: f"mcp.tool.arguments.{a}",
    principal_ref=lambda p: {"user": "jwt.sub", "agent": "jwt.azp", "roles": "jwt.roles"}.get(p, f"jwt.{p}"),
    has=lambda ref: f"has({ref})",
    functions={
        "len": lambda a: f"size({a[0]})",
        "lower": lambda a: f"{a[0]}.lowerAscii()",
        "upper": lambda a: f"{a[0]}.upperAscii()",
        "startswith": lambda a: f"{a[0]}.startsWith({a[1]})",
        "endswith": lambda a: f"{a[0]}.endsWith({a[1]})",
        "matches": lambda a: f"{a[0]}.matches({a[1]})",
        "any_in": lambda a: f"{a[0]}.exists(x, x in {a[1]})",
    },
    args_supported=False,
)


def tool_match(tool: str) -> str:
    target, name = split_tool(tool)
    parts = []
    if target and target != "*":
        parts.append(f'mcp.tool.target == "{target}"' if "*" not in target
                     else f'mcp.tool.target.matches("^{target.replace("*", ".*")}$")')
    if name != "*":
        parts.append(f'mcp.tool.name == "{name}"' if "*" not in name
                     else f'mcp.tool.name.matches("^{name.replace("*", ".*")}$")')
    return " && ".join(parts) if parts else "true"


def compile_rule(rule: Rule, firm: dict | None = None) -> tuple[str, bool, str | None]:
    """Return (cel_expr, native, note). native=False means the PDS decides."""
    tm = tool_match(rule.tool)
    pds_reasons: list[str] = []
    if rule.hold_if or rule.approval:
        pds_reasons.append("hold/approval needs state")
    if rule.needs_args:
        pds_reasons.append("references tool arguments (not available in mcpAuthorization)")
    if pds_reasons:
        return tm, False, "; ".join(pds_reasons)
    conds = []
    try:
        if rule.deny_if:
            conds.append(f"!({translate(rule.deny_if, CEL, firm)})")
        if rule.allow_if:
            conds.append(translate(rule.allow_if, CEL, firm))
    except Uncompilable as e:
        return tm, False, str(e)
    conds = [c for c in conds if c not in ("true", "!(false)")]
    expr = tm if not conds else f"{tm} && " + " && ".join(conds)
    return expr, True, None


class CELCompiler:
    dialect = "cel"

    def __init__(self, pds_host: str = "localhost:9000", protocol: str = "grpc", max_body: int = 65536):
        self.pds_host, self.protocol, self.max_body = pds_host, protocol, max_body

    def compile(self, packs: list[Pack]) -> CompiledPolicy:
        from regent.core.match import tool_matches

        native, pds, notes = [], [], []
        allows: list[tuple[Rule, str, bool]] = []  # (rule, expr, is_native)
        guards: list[tuple[Rule, str]] = []  # native pure-deny rules: (rule, negated condition)
        for p in packs:
            for r in p.rules:
                expr, is_native, note = compile_rule(r, p.firm)
                pure_deny = bool(r.deny_if) and not r.allow_if and not r.hold_if
                if pure_deny and is_native:
                    # A deny-only rule allows nothing by itself (a sibling rule must allow the
                    # tool). It becomes a guard AND-ed onto every allow-rule for tools it covers.
                    guards.append((r, f"!({translate(r.deny_if, CEL, p.firm)})"))
                    native.append(r.id)
                    continue
                allows.append((r, expr, is_native))
                (native if is_native else pds).append(r.id)
                if note:
                    notes.append(f"{r.id}: routed to PDS — {note}")
        rules_out: list[str] = []
        for r, expr, is_native in allows:
            applicable = [g for gr, g in guards if tool_matches(gr.tool, r.tool) or tool_matches(r.tool, gr.tool)]
            full = expr if not applicable else f"{expr} && " + " && ".join(applicable)
            rules_out.append(f"{full}  # {r.id}" + ("" if is_native else "  [PDS]"))
        for gr, _ in guards:
            if not any(tool_matches(gr.tool, r.tool) or tool_matches(r.tool, gr.tool) for r, _, _ in allows):
                notes.append(f"{gr.id}: deny-only rule with no allow-rule for {gr.tool}; the gateway denies that tool "
                             "by default (no rule emitted)")
        # de-duplicate identical allow expressions while keeping comments meaningful
        seen: dict[str, str] = {}
        for line in rules_out:
            expr = line.split("  #", 1)[0]
            seen.setdefault(expr, line)
        policies = {
            "mcpAuthorization": {"rules": [k for k in seen]},
            "extAuthz": {
                "host": self.pds_host,
                "includeRequestBody": {"maxRequestBytes": self.max_body},
                "protocol": ({"grpc": {"metadata": {"dev.agentgateway.jwt": '{"claims": jwt}'}}} if self.protocol == "grpc"
                             else {"http": {"path": '"/authz"'}}),
            },
        }
        if self.protocol == "http":
            policies["extAuthz"]["includeRequestHeaders"] = ["authorization", "mcp-session-id", "x-regent-grant"]
        header = ("# Generated by `regent compile --dialect cel` from " + ", ".join(f"{p.name}@{(p.source_hash or '')[:12]}" for p in packs)
                  + "\n# Paste under routes[].policies in your agentgateway config. Rules marked [PDS] are\n"
                  "# decided by the Regent policy decision service via extAuthz; the rest never leave the gateway.\n")
        text = header + yaml.safe_dump({"policies": policies}, sort_keys=False, width=200)
        # re-attach the rule comments (yaml dump drops them)
        for expr, line in seen.items():
            text = text.replace(f"- {expr}\n", f"- {expr}\n", 1)
        text += "\n# Rule map:\n" + "\n".join(f"#   {line}" for line in seen.values()) + "\n"
        return CompiledPolicy("cel", text, native, pds, notes)


def agentgateway_config(packs: list[Pack], targets: list[dict], port: int = 3000, pds_host: str = "localhost:9000",
                        protocol: str = "grpc", jwt: dict | None = None) -> str:
    """Full standalone agentgateway config (binds/listeners/routes) for the demo."""
    compiled = CELCompiler(pds_host, protocol).compile(packs)
    policies = yaml.safe_load(compiled.text.split("\n# Rule map", 1)[0])["policies"]
    if jwt:
        policies["jwtAuth"] = jwt
    cfg = {"config": {"readinessAddr": "127.0.0.1:15021", "statsAddr": "127.0.0.1:15020", "adminAddr": "127.0.0.1:15000", "enableIpv6": False},
           "binds": [{"port": port, "listeners": [{"routes": [{"policies": policies,
                                                                "backends": [{"mcp": {"targets": targets}}]}]}]}]}
    return ("# Generated by `regent compile --dialect cel --full`\n" + yaml.safe_dump(cfg, sort_keys=False, width=200)
            + "\n# Rule map:\n" + "\n".join(f"#   {line}" for line in compiled.text.split("# Rule map:\n", 1)[1].splitlines()))
