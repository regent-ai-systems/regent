"""Contract tests per adapter: MCP body parsing, ext_authz gRPC + HTTP, admin API, SQLite store, OTLP/JSONL ingest, evidence."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import grpc
import pytest
from aiohttp import ClientSession
from envoy.service.auth.v3 import external_auth_pb2 as ea
from envoy.service.auth.v3 import external_auth_pb2_grpc as ea_grpc
from google.protobuf.struct_pb2 import Struct

from regent.approvers.inbox import AutoApprover, InboxApprover
from regent.core.chain import verify
from regent.core.engine import Engine
from regent.core.evidence import build_evidence, render_markdown
from regent.runtimes.agentgateway_extauthz import AgentgatewayRuntime
from regent.runtimes.mcp_parse import NotAToolCall, parse_body, qualify_tool
from regent.sources.ingest import ingest
from regent.sources.jsonl import JSONLSource
from regent.sources.otel_otlp import parse_traces_json
from regent.stores.memory import MemoryStore
from regent.stores.sqlite import SQLiteStore

from tests.conftest import TRADE

TOOLS_CALL = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "custodian_place_trade", "arguments": {**TRADE, "notional_usd": 100}}})
BIG_CALL = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                       "params": {"name": "custodian_place_trade", "arguments": {**TRADE, "notional_usd": 999999}}})


def test_qualify_tool():
    assert qualify_tool("custodian_place_trade", ["custodian", "crm"]) == "custodian.place_trade"
    assert qualify_tool("my_target_read_file", ["my_target"]) == "my_target.read_file"
    assert qualify_tool("fs_read_file") == "fs.read_file"
    assert qualify_tool("custodian.place_trade") == "custodian.place_trade"


def test_parse_body_principal_from_metadata():
    md = {"dev.agentgateway.jwt": json.dumps({"claims": {"sub": "u1", "roles": ["trader"], "assigned_accounts": ["A1"]}})}
    c = parse_body(TOOLS_CALL, {"mcp-session-id": "s1"}, md, ["custodian"])
    assert c.tool == "custodian.place_trade" and c.args["notional_usd"] == 100
    assert c.principal.user == "u1" and c.principal.roles == ("trader",) and c.session_id == "s1"


def test_parse_body_unverified_bearer_fallback():
    import base64
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "u2"}).encode()).rstrip(b"=").decode()
    c = parse_body(TOOLS_CALL, {"authorization": f"Bearer aaa.{payload}.bbb"}, None, ["custodian"])
    assert c.principal.user == "u2"


def test_parse_body_rejects_non_tool_call():
    with pytest.raises(NotAToolCall):
        parse_body(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}), {}, None)
    with pytest.raises(NotAToolCall):
        parse_body(b"", {}, None)


@pytest.fixture
async def runtime(ria, tmp_path, unused_tcp_port_factory):
    inbox = InboxApprover(poll_s=0.01)
    eng = Engine(ria, SQLiteStore(tmp_path / "t.db"), inbox)
    await eng.record_policies("test")
    rt = AgentgatewayRuntime(eng, inbox, unused_tcp_port_factory(), unused_tcp_port_factory(), ["custodian", "crm", "email", "esign"])
    await rt.start()
    yield rt
    await rt.stop()


def _check_request(body: str, claims: dict) -> ea.CheckRequest:
    req = ea.CheckRequest()
    req.attributes.request.http.method = "POST"
    req.attributes.request.http.path = "/mcp"
    req.attributes.request.http.headers["content-type"] = "application/json"
    req.attributes.request.http.body = body
    st = Struct()
    st.update({"claims": claims})
    req.attributes.metadata_context.filter_metadata["dev.agentgateway.jwt"].CopyFrom(st)
    return req


async def test_grpc_extauthz_allow_hold_approve_retry(runtime):
    claims = {"sub": "agent7", "assigned_accounts": ["A1"], "roles": ["trader"]}
    async with grpc.aio.insecure_channel(f"127.0.0.1:{runtime.grpc_port}") as ch:
        stub = ea_grpc.AuthorizationStub(ch)
        ok = await stub.Check(_check_request(TOOLS_CALL, claims))
        assert ok.status.code == 0 and any(h.header.key == "x-regent-verdict" and h.header.value == "allow" for h in ok.ok_response.headers)
        big = BIG_CALL
        held = await stub.Check(_check_request(big, claims))
        assert held.status.code == 7 and held.denied_response.status.code == 403
        body = json.loads(held.denied_response.body)
        assert body["verdict"] == "hold" and body["hold_id"]
        # non tools/call passes through
        lst = await stub.Check(_check_request(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}), claims))
        assert lst.status.code == 0
    # approve twice via admin API (four-eyes), then retry
    base = f"http://127.0.0.1:{runtime.http_port}"
    async with ClientSession() as s:
        async with s.get(f"{base}/v1/holds") as r:
            holds = await r.json()
            assert len(holds) == 1 and holds[0]["id"] == body["hold_id"]
        async with s.post(f"{base}/v1/holds/{body['hold_id']}/approve",
                          json={"approver": "maria", "roles": ["trading_supervisor"], "attestation_accepted": True}) as r:
            assert r.status == 200
            assert (await r.json())["hold"]["status"] == "approved"
        async with s.post(f"{base}/v1/holds/{body['hold_id']}/approve",
                          json={"approver": "late", "roles": ["trading_supervisor"], "attestation_accepted": True}) as r:
            assert r.status == 409
    async with grpc.aio.insecure_channel(f"127.0.0.1:{runtime.grpc_port}") as ch:
        stub = ea_grpc.AuthorizationStub(ch)
        again = await stub.Check(_check_request(big, claims))
        assert again.status.code == 0
    async with ClientSession() as s:
        async with s.get(f"{base}/v1/verify") as r:
            assert (await r.json())["ok"]


async def test_http_extauthz_and_decide(runtime):
    base = f"http://127.0.0.1:{runtime.http_port}"
    import base64
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "agent7", "assigned_accounts": ["A1"]}).encode()).rstrip(b"=").decode()
    async with ClientSession() as s:
        async with s.post(f"{base}/authz", data=TOOLS_CALL, headers={"authorization": f"Bearer x.{payload}.y"}) as r:
            assert r.status == 200 and r.headers["x-regent-verdict"] == "allow"
        async with s.post(f"{base}/authz", data=TOOLS_CALL.replace('"account": "A1"', '"account": "ZZ"'),
                          headers={"authorization": f"Bearer x.{payload}.y"}) as r:
            assert r.status == 403 and (await r.json())["verdict"] == "deny"
        async with s.post(f"{base}/v1/decide", json={"tool": "crm.delete_contact", "args": {}, "principal": {"user": "u"}}) as r:
            assert r.status == 403 and (await r.json())["rule_id"] == "RIA-REC-009"


async def test_sqlite_store_roundtrip(ria, mk, tmp_path):
    store = SQLiteStore(tmp_path / "s.db")
    eng = Engine(ria, store, AutoApprover(("a1", "a2"), ("trading_supervisor",)))
    d = await eng.decide(mk("custodian.place_trade", {**TRADE, "notional_usd": 300000}))
    await eng.drain()
    store.close()
    store2 = SQLiteStore(tmp_path / "s.db")
    hold = await store2.get_hold(d.hold_id)
    assert hold.status.value == "approved" and hold.call.args["notional_usd"] == 300000
    assert len(await store2.grants()) == 1
    assert verify(await store2.entries()).ok
    eng2 = Engine(ria, store2, AutoApprover())
    assert (await eng2.decide(mk("custodian.place_trade", {**TRADE, "notional_usd": 300000}))).verdict.value == "allow"


def _otlp_doc(tool="place_trade", target="custodian", status=200):
    return {"resourceSpans": [{"resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "agentgateway"}}]},
                               "scopeSpans": [{"spans": [{"traceId": "t1", "spanId": "s1", "name": "tools/call",
                                                          "startTimeUnixNano": "1758200000000000000", "endTimeUnixNano": "1758200000500000000",
                                                          "attributes": [
                                                              {"key": "mcp.tool.name", "value": {"stringValue": tool}},
                                                              {"key": "mcp.tool.target", "value": {"stringValue": target}},
                                                              {"key": "jwt.sub", "value": {"stringValue": "agent7"}},
                                                              {"key": "mcp.tool.arguments", "value": {"stringValue": json.dumps({**TRADE, "note": "SSN 123-45-6789"})}},
                                                              {"key": "http.response.status_code", "value": {"intValue": str(status)}}]}]}]}]}


def test_parse_otlp_traces():
    evs = parse_traces_json(_otlp_doc())
    assert len(evs) == 1 and evs[0].tool == "custodian.place_trade" and evs[0].user == "agent7" and evs[0].verdict == "allow"
    assert parse_traces_json(_otlp_doc(status=403))[0].verdict == "deny"


async def test_jsonl_ingest_maps_controls_and_redacts(ria, tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text(json.dumps(_otlp_doc()) + "\n" + json.dumps({"kind": "decision", "at": "2026-09-18T10:00:00Z", "tool": "crm.export",
                                                               "user": "u", "verdict": "hold", "rule_id": "RIA-DAT-007", "pack": "ria/v1"}) + "\n"
                 + json.dumps({"mcp.tool.name": "get_positions", "mcp.tool.target": "custodian", "time": "2026-09-18T10:00:01Z"}) + "\n")
    store = MemoryStore()
    n = await ingest(JSONLSource(p), ria, store)
    assert n == 3
    e0, e1, e2 = store.chain
    assert e0.event.rule_id == "RIA-TRD-001" and "SEC-206(4)-7" in e0.controls
    assert "123-45-6789" not in json.dumps(e0.event.to_dict())
    assert "SEC-RegS-P-248.30" in e1.controls
    assert e2.event.payload.get("coverage_gap") is True
    assert verify(store.chain).ok


async def test_evidence_package(ria, mk):
    eng = Engine(ria, MemoryStore(), AutoApprover(("a1", "a2"), ("trading_supervisor",)))
    await eng.record_policies("test")
    big = {**TRADE, "notional_usd": 300000}
    await eng.decide(mk("custodian.place_trade", big))
    await eng.drain()
    await eng.decide(mk("custodian.place_trade", big))
    await eng.decide(mk("custodian.place_trade", TRADE))
    await eng.decide(mk("email.send", {"to": ["x@y.z"], "body": "SSN 123-45-6789", "archived": True}))
    await eng.decide(mk("custodian.get_positions", {}))
    now = datetime.now(timezone.utc)
    ev = build_evidence(eng.store.chain, ria, now - timedelta(hours=1), now + timedelta(seconds=1),
                        reachable_tools=["custodian.place_trade", "custodian.get_positions", "crm.get_contact"], firm="Test RIA")
    s = ev["supervision"]
    assert s["holds"] == 1 and s["approved"] == 1 and s["executed_after_approval"] == 1 and s["unapproved_executions"] == 0
    assert ev["data_protection"]["no_override_blocks"] == 1
    assert ev["coverage_gaps"] == ["crm.get_contact", "custodian.get_positions"]
    assert ev["chain_integrity"]["ok"]
    assert len(ev["trade_blotter"]["orders"]) == 2 and ev["trade_blotter"]["incomplete_memoranda"] == []
    assert any(r["item"].startswith("Trade blotter") for r in ev["exam_request_index"])
    md = render_markdown(ev)
    assert "Unapproved executions: 0" in md and "RIA-DAT-005" in md and "123-45-6789" not in md
    assert "## 8. Trade blotter" in md and "## 9. Examination request-list index" in md and "CUSTODIAN-BD" in md
