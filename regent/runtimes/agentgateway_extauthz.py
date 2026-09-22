"""agentgateway runtime: Envoy-style ext_authz (gRPC and HTTP) + the PDS admin API.

agentgateway config (see examples/agentgateway-ria-demo/out/agentgateway.yaml):

    policies:
      extAuthz:
        host: localhost:9000
        includeRequestBody: { maxRequestBytes: 65536 }
        protocol:
          grpc:
            metadata:
              dev.agentgateway.jwt: '{"claims": jwt}'

Verified against agentgateway v1.5.0: the MCP ``tools/call`` JSON-RPC body arrives in
``attributes.request.http.body`` (tool name + arguments), and the CEL ``metadata`` map
arrives as Envoy filter metadata (``attributes.metadata_context.filter_metadata``).

Responses:
    allow → OK (+ x-regent-decision headers)
    deny  → 403, JSON body {verdict: deny, rule_id, reason}
    hold  → 403, JSON body {verdict: hold, hold_id, retry_after_s}, Retry-After header.
            The agent re-issues the same call (same args) after approval; the
            grant is bound to the call fingerprint so no token is strictly
            required, but ``x-regent-grant: <token>`` pins a specific grant.

Admin API (HTTP, default :9100):
    GET  /healthz
    GET  /v1/holds                       pending holds
    GET  /v1/holds/{id}
    POST /v1/holds/{id}/approve          {approver, roles[], decision, attestation_accepted, comment}
    POST /v1/decide                      {tool, args, principal{...}}  (direct PDS call: AGT plugin / tests)
    GET  /v1/verify                      chain verification
"""
from __future__ import annotations

import asyncio
import json
import logging

import grpc
from aiohttp import web
from envoy.service.auth.v3 import external_auth_pb2 as ea
from envoy.service.auth.v3 import external_auth_pb2_grpc as ea_grpc
from envoy.config.core.v3 import base_pb2 as core
from envoy.type.v3 import http_status_pb2 as http_status
from google.protobuf.json_format import MessageToDict
from google.rpc import code_pb2, status_pb2

from regent.approvers.inbox import InboxApprover
from regent.core.chain import verify
from regent.core.engine import Engine
from regent.core.models import Approval, Decision, HoldStatus, Principal, ToolCall, Verdict
from regent.core.ports import Decider
from regent.runtimes.mcp_parse import NotAToolCall, parse_body
from regent.stores.sqlite import hold_to_dict

log = logging.getLogger("regent.extauthz")


def decision_headers(d: Decision) -> dict[str, str]:
    h = {"x-regent-verdict": d.verdict.value, "x-regent-rule": d.rule_id or "", "x-regent-call": d.call_id or ""}
    if d.hold_id:
        h["x-regent-hold"] = d.hold_id
    if d.grant_id:
        h["x-regent-grant-id"] = d.grant_id
    if d.retry_after_s:
        h["retry-after"] = str(d.retry_after_s)
    return h


def deny_body(d: Decision) -> str:
    return json.dumps({"verdict": d.verdict.value, "rule_id": d.rule_id, "pack": d.pack, "reason": d.reason,
                       "hold_id": d.hold_id, "retry_after_s": d.retry_after_s, "call_id": d.call_id,
                       "hint": ("approval pending; re-issue the identical call after approval" if d.verdict is Verdict.HOLD
                                else None)})


class AuthzServicer(ea_grpc.AuthorizationServicer):
    def __init__(self, decide: Decider, targets: list[str] | None, separator: str, passthrough: bool):
        self.decide, self.targets, self.separator, self.passthrough = decide, targets, separator, passthrough

    async def Check(self, request: ea.CheckRequest, context: grpc.aio.ServicerContext) -> ea.CheckResponse:
        http = request.attributes.request.http
        headers = dict(http.headers)
        if http.HasField("header_map"):  # newer Envoy API puts headers here (repeated keys allowed)
            for hv in http.header_map.headers:
                headers.setdefault(hv.key, hv.value if hv.value else hv.raw_value.decode("utf-8", "replace"))
        # agentgateway delivers the CEL `metadata:` map as Envoy filter metadata
        # (attributes.metadata_context.filter_metadata[<key>] = Struct), verified against v1.5.0.
        metadata: dict[str, str] = {k: v for k, v in context.invocation_metadata()}
        for key, st in request.attributes.metadata_context.filter_metadata.items():
            metadata[key] = json.dumps(MessageToDict(st))
        metadata.update(dict(request.attributes.context_extensions))
        body = http.raw_body if http.raw_body else http.body.encode("utf-8")
        log.debug("ext_authz check: headers=%s metadata=%s body=%dB", sorted(headers), sorted(metadata), len(body))
        try:
            call = parse_body(body, headers, metadata, self.targets, self.separator)
        except NotAToolCall as e:
            if self.passthrough:
                return ea.CheckResponse(status=status_pb2.Status(code=code_pb2.OK),
                                        ok_response=ea.OkHttpResponse(headers=[_hv("x-regent-verdict", "passthrough")]))
            return _denied(Decision(Verdict.DENY, None, None, f"not a tools/call: {e}"))
        d = await self.decide(call)
        if d.verdict is Verdict.ALLOW:
            return ea.CheckResponse(status=status_pb2.Status(code=code_pb2.OK),
                                    ok_response=ea.OkHttpResponse(headers=[_hv(k, v) for k, v in decision_headers(d).items()]))
        return _denied(d)


def _hv(k: str, v: str) -> core.HeaderValueOption:
    return core.HeaderValueOption(header=core.HeaderValue(key=k, value=v),
                                  append_action=core.HeaderValueOption.OVERWRITE_IF_EXISTS_OR_ADD)


def _denied(d: Decision) -> ea.CheckResponse:
    return ea.CheckResponse(
        status=status_pb2.Status(code=code_pb2.PERMISSION_DENIED, message=d.reason),
        denied_response=ea.DeniedHttpResponse(
            status=http_status.HttpStatus(code=http_status.Forbidden),
            headers=[_hv(k, v) for k, v in {**decision_headers(d), "content-type": "application/json"}.items()],
            body=deny_body(d)))


class AgentgatewayRuntime:
    """Serves gRPC ext_authz on ``grpc_port``, HTTP ext_authz + admin on ``http_port``."""

    name = "agentgateway_extauthz"

    def __init__(self, engine: Engine, inbox: InboxApprover | None = None, grpc_port: int = 9000,
                 http_port: int = 9100, targets: list[str] | None = None, separator: str = "_",
                 passthrough_non_tool_calls: bool = True, host: str = "127.0.0.1"):
        self.engine, self.inbox = engine, inbox
        self.grpc_port, self.http_port, self.host = grpc_port, http_port, host
        self.targets, self.separator, self.passthrough = targets, separator, passthrough_non_tool_calls
        self._grpc: grpc.aio.Server | None = None
        self._runner: web.AppRunner | None = None

    # ---- http ext_authz + admin
    def app(self) -> web.Application:
        app = web.Application(client_max_size=4 * 1024 * 1024)
        app.router.add_route("*", "/authz", self.http_authz)
        app.router.add_route("*", "/authz/{tail:.*}", self.http_authz)
        app.router.add_get("/healthz", self.healthz)
        app.router.add_get("/v1/holds", self.list_holds)
        app.router.add_get("/v1/holds/{id}", self.get_hold)
        app.router.add_post("/v1/holds/{id}/approve", self.approve)
        app.router.add_post("/v1/decide", self.decide_http)
        app.router.add_get("/v1/verify", self.verify_http)
        app.router.add_get("/v1/packs", self.packs_http)
        return app

    async def http_authz(self, req: web.Request) -> web.Response:
        body = await req.read()
        try:
            call = parse_body(body, req.headers, None, self.targets, self.separator)
        except NotAToolCall as e:
            if self.passthrough:
                return web.Response(status=200, headers={"x-regent-verdict": "passthrough"})
            d = Decision(Verdict.DENY, None, None, f"not a tools/call: {e}")
            return web.Response(status=403, text=deny_body(d), content_type="application/json",
                                headers=decision_headers(d))
        d = await self.engine.decide(call)
        if d.verdict is Verdict.ALLOW:
            return web.Response(status=200, headers=decision_headers(d))
        return web.Response(status=403, text=deny_body(d), content_type="application/json", headers=decision_headers(d))

    async def healthz(self, req: web.Request) -> web.Response:
        return web.json_response({"ok": True, "runtime": self.name, "packs": [p.name for p in self.engine.packs]})

    async def list_holds(self, req: web.Request) -> web.Response:
        holds = await self.engine.store.pending_holds()
        return web.json_response([hold_to_dict(h) for h in holds])

    async def get_hold(self, req: web.Request) -> web.Response:
        h = await self.engine.store.get_hold(req.match_info["id"])
        if not h:
            raise web.HTTPNotFound(text="no such hold")
        return web.json_response(hold_to_dict(h))

    async def approve(self, req: web.Request) -> web.Response:
        if self.inbox is None:
            raise web.HTTPConflict(text="this PDS is not configured for out-of-band approvals")
        hold_id = req.match_info["id"]
        h = await self.engine.store.get_hold(hold_id)
        if not h:
            raise web.HTTPNotFound(text="no such hold")
        if h.status is not HoldStatus.PENDING:
            raise web.HTTPConflict(text=f"hold is {h.status.value}")
        body = await req.json()
        a = Approval(approver=str(body["approver"]), decision=str(body.get("decision", "approve")),
                     attestation_accepted=bool(body.get("attestation_accepted", False)), attestation_text=None,
                     comment=body.get("comment"))
        a.roles = tuple(body.get("roles") or ())  # type: ignore[attr-defined]
        ok = await self.inbox.submit(hold_id, a)
        if not ok:
            raise web.HTTPConflict(text="hold is not awaiting approvals in this process")
        # give the workflow a moment to process so the caller sees the new state
        for _ in range(50):
            await asyncio.sleep(0.05)
            h2 = await self.engine.store.get_hold(hold_id)
            if h2 and (h2.status is not HoldStatus.PENDING or len(h2.approvals) > len(h.approvals)):
                break
        h2 = await self.engine.store.get_hold(hold_id)
        return web.json_response({"accepted": True, "hold": hold_to_dict(h2) if h2 else None})

    async def decide_http(self, req: web.Request) -> web.Response:
        body = await req.json()
        p = body.get("principal") or {}
        call = ToolCall(tool=body["tool"], args=body.get("args") or {}, session_id=body.get("session_id"),
                        grant_token=body.get("grant_token"),
                        principal=Principal(user=p.get("user", "anonymous"), agent=p.get("agent", "unknown-agent"),
                                            roles=tuple(p.get("roles") or ()), claims=p.get("claims") or {}))
        d = await self.engine.decide(call)
        return web.json_response(d.to_dict(), status=200 if d.verdict is Verdict.ALLOW else 403)

    async def verify_http(self, req: web.Request) -> web.Response:
        return web.json_response(verify(await self.engine.store.entries()).to_dict())

    async def packs_http(self, req: web.Request) -> web.Response:
        return web.json_response([{"pack": p.name, "version": p.version, "source_hash": p.source_hash,
                                   "rules": [r.id for r in p.rules]} for p in self.engine.packs])

    # ---- lifecycle
    async def start(self) -> None:
        self._grpc = grpc.aio.server()
        ea_grpc.add_AuthorizationServicer_to_server(
            AuthzServicer(self.engine.decide, self.targets, self.separator, self.passthrough), self._grpc)
        self._grpc.add_insecure_port(f"{self.host}:{self.grpc_port}")
        await self._grpc.start()
        self._runner = web.AppRunner(self.app(), access_log=None)
        await self._runner.setup()
        await web.TCPSite(self._runner, self.host, self.http_port).start()
        log.info("regent PDS: ext_authz gRPC %s:%d · HTTP authz+admin %s:%d", self.host, self.grpc_port, self.host,
                 self.http_port)

    async def stop(self) -> None:
        await self.engine.drain()
        if self._grpc:
            await self._grpc.stop(grace=1)
        if self._runner:
            await self._runner.cleanup()

    async def serve(self, decide: Decider | None = None) -> None:
        await self.start()
        try:
            while True:
                await asyncio.sleep(3600)
        finally:
            await self.stop()
