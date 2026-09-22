"""OTLP/HTTP receiver for agentgateway traces and logs → AuditEvent.

agentgateway exports OpenTelemetry spans for MCP calls with attributes such as
``mcp.tool.name``, ``mcp.tool.target``, ``mcp.method``, ``jwt.sub``, ``mcp.session.id``
and (post-request) ``mcp.tool.arguments``. Point its tracing exporter here:

    tracing:
      otlpEndpoint: http://localhost:4318

We accept OTLP JSON *and* protobuf on ``/v1/traces`` and ``/v1/logs``. Attribute
names differ slightly across agentgateway versions, so mapping is by suffix
match on a small alias table; unknown attributes are kept in ``payload``.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, AsyncIterator

from aiohttp import web

from regent.core.models import AuditEvent

ALIASES = {
    "tool": ("mcp.tool.name", "gen_ai.tool.name", "tool.name"),
    "target": ("mcp.tool.target", "mcp.target", "backend.name"),
    "user": ("jwt.sub", "enduser.id", "user.id", "principal.user"),
    "agent": ("jwt.azp", "jwt.client_id", "agent.id", "api_key.name", "principal.agent"),
    "method": ("mcp.method", "mcp.methodName", "rpc.method"),
    "session": ("mcp.session.id", "mcp.sessionId", "session.id"),
    "args": ("mcp.tool.arguments", "gen_ai.tool.call.arguments"),
    "error": ("mcp.tool.error", "error.type", "exception.message"),
    "verdict": ("regent.verdict", "x-regent-verdict", "http.response.header.x-regent-verdict"),
    "rule": ("regent.rule", "x-regent-rule", "http.response.header.x-regent-rule"),
    "hold": ("regent.hold", "x-regent-hold"),
    "status": ("http.response.status_code", "http.status_code"),
}


def _anyvalue(v: dict[str, Any]) -> Any:
    if "stringValue" in v:
        return v["stringValue"]
    if "intValue" in v:
        return int(v["intValue"])
    if "doubleValue" in v:
        return v["doubleValue"]
    if "boolValue" in v:
        return v["boolValue"]
    if "arrayValue" in v:
        return [_anyvalue(x) for x in v["arrayValue"].get("values", [])]
    if "kvlistValue" in v:
        return {kv["key"]: _anyvalue(kv["value"]) for kv in v["kvlistValue"].get("values", [])}
    return v


def attrs_to_dict(attrs: list[dict[str, Any]]) -> dict[str, Any]:
    return {a["key"]: _anyvalue(a.get("value", {})) for a in attrs or []}


def pick(attrs: dict[str, Any], key: str) -> Any:
    for name in ALIASES[key]:
        if name in attrs:
            return attrs[name]
    return None


def _ns_to_dt(ns: str | int | None) -> datetime:
    if not ns:
        return datetime.now(timezone.utc)
    return datetime.fromtimestamp(int(ns) / 1e9, tz=timezone.utc)


def span_to_event(span: dict[str, Any], resource_attrs: dict[str, Any] | None = None) -> AuditEvent | None:
    attrs = attrs_to_dict(span.get("attributes", []))
    method = pick(attrs, "method") or span.get("name", "")
    tool = pick(attrs, "tool")
    if not tool and "tools/call" not in str(method):
        return None
    target = pick(attrs, "target")
    qualified = f"{target}.{tool}" if target and tool and "." not in str(tool) else tool
    args = pick(attrs, "args")
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            pass
    status = span.get("status", {}) or {}
    verdict = pick(attrs, "verdict")
    if not verdict:
        code = pick(attrs, "status")
        verdict = "deny" if (code and int(code) == 403) or status.get("code") == 2 else "allow"
    return AuditEvent(kind="tool_call", at=_ns_to_dt(span.get("startTimeUnixNano")), source="agentgateway-otlp",
                      tool=qualified, user=pick(attrs, "user"), agent=pick(attrs, "agent"), rule_id=pick(attrs, "rule"),
                      verdict=str(verdict), hold_id=pick(attrs, "hold"), event_id=f"span_{span.get('spanId', '')}",
                      payload={"trace_id": span.get("traceId"), "span_id": span.get("spanId"), "session_id": pick(attrs, "session"),
                               "args": args, "error": pick(attrs, "error"), "duration_ns": (int(span.get("endTimeUnixNano", 0) or 0)
                                                                                          - int(span.get("startTimeUnixNano", 0) or 0)),
                               "service": (resource_attrs or {}).get("service.name"), "attributes": attrs})


def parse_traces_json(doc: dict[str, Any]) -> list[AuditEvent]:
    out = []
    for rs in doc.get("resourceSpans", []):
        rattrs = attrs_to_dict(rs.get("resource", {}).get("attributes", []))
        for ss in rs.get("scopeSpans", []) or rs.get("instrumentationLibrarySpans", []):
            for span in ss.get("spans", []):
                ev = span_to_event(span, rattrs)
                if ev:
                    out.append(ev)
    return out


def parse_logs_json(doc: dict[str, Any]) -> list[AuditEvent]:
    out = []
    for rl in doc.get("resourceLogs", []):
        for sl in rl.get("scopeLogs", []):
            for rec in sl.get("logRecords", []):
                attrs = attrs_to_dict(rec.get("attributes", []))
                body = rec.get("body", {})
                body_v = _anyvalue(body) if isinstance(body, dict) else body
                if isinstance(body_v, str):
                    try:
                        body_v = json.loads(body_v)
                    except json.JSONDecodeError:
                        pass
                if isinstance(body_v, dict):
                    attrs = {**body_v, **attrs}
                tool = pick(attrs, "tool")
                if not tool:
                    continue
                target = pick(attrs, "target")
                out.append(AuditEvent(kind="tool_call", at=_ns_to_dt(rec.get("timeUnixNano")), source="agentgateway-otlp",
                                      tool=f"{target}.{tool}" if target and "." not in str(tool) else tool,
                                      user=pick(attrs, "user"), agent=pick(attrs, "agent"),
                                      verdict=str(pick(attrs, "verdict") or "allow"), rule_id=pick(attrs, "rule"),
                                      payload={"args": pick(attrs, "args"), "attributes": attrs}))
    return out


def _proto_to_json(body: bytes, kind: str) -> dict[str, Any]:
    from google.protobuf.json_format import MessageToDict
    if kind == "traces":
        from opentelemetry.proto.collector.trace.v1 import trace_service_pb2 as ts
        msg = ts.ExportTraceServiceRequest()
    else:
        from opentelemetry.proto.collector.logs.v1 import logs_service_pb2 as ls
        msg = ls.ExportLogsServiceRequest()
    msg.ParseFromString(body)
    return MessageToDict(msg)


class OTLPSource:
    """Runs an OTLP/HTTP receiver; ``events()`` yields AuditEvents as they arrive."""

    name = "otel_otlp"

    def __init__(self, host: str = "127.0.0.1", port: int = 4318):
        self.host, self.port = host, port
        self.queue: asyncio.Queue[AuditEvent | None] = asyncio.Queue()
        self._runner: web.AppRunner | None = None
        self.received = 0

    async def _handle(self, req: web.Request) -> web.Response:
        kind = "traces" if req.path.endswith("/traces") else "logs"
        raw = await req.read()
        ctype = req.headers.get("content-type", "")
        try:
            if "protobuf" in ctype:
                doc = _proto_to_json(raw, kind)
            else:
                doc = json.loads(raw or b"{}")
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)
        events = parse_traces_json(doc) if kind == "traces" else parse_logs_json(doc)
        for ev in events:
            self.received += 1
            await self.queue.put(ev)
        return web.json_response({"partialSuccess": {}})

    async def start(self) -> None:
        app = web.Application(client_max_size=16 * 1024 * 1024)
        app.router.add_post("/v1/traces", self._handle)
        app.router.add_post("/v1/logs", self._handle)
        self._runner = web.AppRunner(app, access_log=None)
        await self._runner.setup()
        await web.TCPSite(self._runner, self.host, self.port).start()

    async def stop(self) -> None:
        await self.queue.put(None)
        if self._runner:
            await self._runner.cleanup()

    async def events(self) -> AsyncIterator[AuditEvent]:
        if self._runner is None:
            await self.start()
        while True:
            ev = await self.queue.get()
            if ev is None:
                return
            yield ev
