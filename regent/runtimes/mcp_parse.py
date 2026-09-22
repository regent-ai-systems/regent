"""Turn what a gateway hands us (headers, JWT claims, JSON-RPC body) into a ToolCall."""
from __future__ import annotations

import base64
import json
from typing import Any, Mapping

from regent.core.models import Principal, ToolCall

GRANT_HEADER = "x-regent-grant"
SESSION_HEADER = "mcp-session-id"


class NotAToolCall(Exception):
    """Body is MCP but not tools/call (initialize, tools/list, ...) — pass through."""


def _b64url_json(seg: str) -> dict[str, Any]:
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg.encode()))


def claims_from_bearer(auth_header: str | None) -> dict[str, Any]:
    """Unverified decode. The gateway already validated the signature (its
    mcpAuthentication / jwtAuth policy); we only need the claims. Never call
    this on a request that did not come through the gateway."""
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return {}
    tok = auth_header[7:].strip()
    parts = tok.split(".")
    if len(parts) != 3:
        return {}
    try:
        return _b64url_json(parts[1])
    except Exception:
        return {}


def principal_from(headers: Mapping[str, str], metadata: Mapping[str, str] | None = None) -> Principal:
    h = {k.lower(): v for k, v in headers.items()}
    claims: dict[str, Any] = {}
    md = {k.lower(): v for k, v in (metadata or {}).items()}
    for key in ("dev.agentgateway.jwt", "x-regent-jwt", "x-jwt-claims"):
        raw = md.get(key) or h.get(key)
        if raw:
            try:
                obj = json.loads(raw)
                claims = obj.get("claims", obj) if isinstance(obj, dict) else {}
                break
            except json.JSONDecodeError:
                pass
    if not claims:
        claims = claims_from_bearer(h.get("authorization"))
    user = str(claims.get("sub") or h.get("x-regent-user") or h.get("x-auth-request-user") or "anonymous")
    agent = str(claims.get("agent") or claims.get("azp") or claims.get("client_id") or h.get("x-regent-agent")
                or h.get("x-api-key-name") or h.get("user-agent", "unknown-agent")[:64])
    roles = claims.get("roles") or claims.get("groups") or []
    if isinstance(roles, str):
        roles = [r.strip() for r in roles.split(",") if r.strip()]
    if h.get("x-regent-roles"):
        roles = list(roles) + [r.strip() for r in h["x-regent-roles"].split(",") if r.strip()]
    return Principal(user=user, agent=agent, roles=tuple(str(r) for r in roles), claims=dict(claims))


def qualify_tool(name: str, targets: list[str] | None = None, separator: str = "_") -> str:
    """agentgateway exposes federated tools as ``<target><sep><tool>``. Convert to
    Regent's ``<target>.<tool>``. With known target names we match the longest
    prefix; otherwise we split on the first separator."""
    if "." in name and separator != ".":
        return name
    if targets:
        for t in sorted(targets, key=len, reverse=True):
            if name.startswith(t + separator):
                return f"{t}.{name[len(t) + len(separator):]}"
    if separator and separator in name:
        t, _, rest = name.partition(separator)
        return f"{t}.{rest}"
    return name


def parse_body(body: bytes | str | None, headers: Mapping[str, str], metadata: Mapping[str, str] | None = None,
               targets: list[str] | None = None, separator: str = "_") -> ToolCall:
    if not body:
        raise NotAToolCall("empty body")
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    try:
        msg = json.loads(body)
    except json.JSONDecodeError as e:
        raise NotAToolCall(f"not json: {e}")
    if isinstance(msg, list):  # JSON-RPC batch: govern the first tools/call
        msg = next((m for m in msg if isinstance(m, dict) and m.get("method") == "tools/call"), None)
        if msg is None:
            raise NotAToolCall("batch without tools/call")
    if not isinstance(msg, dict) or msg.get("method") != "tools/call":
        raise NotAToolCall(str(msg.get("method") if isinstance(msg, dict) else "?"))
    params = msg.get("params") or {}
    name = params.get("name")
    if not name:
        raise NotAToolCall("tools/call without name")
    h = {k.lower(): v for k, v in headers.items()}
    return ToolCall(tool=qualify_tool(str(name), targets, separator), args=dict(params.get("arguments") or {}),
                    principal=principal_from(headers, metadata), session_id=h.get(SESSION_HEADER),
                    grant_token=h.get(GRANT_HEADER))
