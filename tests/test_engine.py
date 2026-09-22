"""Core loop with fakes: deny by default, hold → approve → grant → retry, SoD, four-eyes, attestation, TTL, single-use, chain."""
from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from regent.approvers.inbox import AutoApprover, CallbackApprover, InboxApprover
from regent.core.chain import verify
from regent.core.engine import Engine
from regent.core.models import Approval, HoldStatus, Verdict
from regent.core.workflow import WorkflowError, apply_approval
from regent.stores.memory import MemoryStore

from tests.conftest import TRADE

BIG = {**TRADE, "notional_usd": 300000}  # above firm.large_trade_threshold_usd (250k in the example overlay)
ROLES = ("trading_supervisor",)


async def _engine(ria, approver=None):
    eng = Engine(ria, MemoryStore(), approver or AutoApprover(("a1", "a2"), ROLES))
    await eng.record_policies("test")
    return eng


async def test_deny_by_default(ria, mk):
    eng = await _engine(ria)
    d = await eng.decide(mk("nothing.here", {}))
    assert d.verdict is Verdict.DENY and d.rule_id is None


async def test_hold_then_grant_then_retry_single_use(ria, mk):
    eng = await _engine(ria)
    d1 = await eng.decide(mk("custodian.place_trade", BIG))
    assert d1.verdict is Verdict.HOLD and d1.hold_id and d1.retry_after_s
    await eng.drain()
    hold = await eng.store.get_hold(d1.hold_id)
    assert hold.status is HoldStatus.APPROVED and len(hold.approvals) == 1  # single-approver exception review
    d2 = await eng.decide(mk("custodian.place_trade", BIG))
    assert d2.verdict is Verdict.ALLOW and d2.grant_id
    d3 = await eng.decide(mk("custodian.place_trade", BIG))  # grant consumed → new hold
    assert d3.verdict is Verdict.HOLD and d3.hold_id != d1.hold_id
    await eng.drain()


async def test_grant_bound_to_args(ria, mk):
    eng = await _engine(ria)
    d1 = await eng.decide(mk("custodian.place_trade", BIG))
    await eng.drain()
    d2 = await eng.decide(mk("custodian.place_trade", {**BIG, "notional_usd": 300001}))
    assert d2.verdict is Verdict.HOLD and d2.hold_id != d1.hold_id
    await eng.drain()


async def test_four_eyes_needs_two_distinct_attested_approvers(ria, mk):
    # one approver, twice → still pending; requester → rejected; no attestation → rejected
    from regent.core.models import Hold
    rule = ria[0].rule("RIA-CUS-016")  # third-party transfer: four-eyes
    ROLES = ("operations_manager",)
    call = mk("custodian.transfer_funds", {"destination_type": "third_party", "transfer_type": "wire", "sloa_id": "S1",
                                           "sloa_all_seven_conditions_met": True, "amount_usd": 5000})
    hold = Hold(id="h1", call=call, rule_id=rule.id, pack=ria[0].name, approval=rule.approval)
    a = Approval("maria", "approve", True, None)
    apply_approval(hold, a, ROLES)
    assert hold.status is HoldStatus.PENDING
    with pytest.raises(WorkflowError, match="already acted"):
        apply_approval(hold, Approval("maria", "approve", True, None), ROLES)
    with pytest.raises(WorkflowError, match="separation of duties"):
        apply_approval(hold, Approval("agent7", "approve", True, None), ROLES)
    with pytest.raises(WorkflowError, match="attestation"):
        apply_approval(hold, Approval("raj", "approve", False, None), ROLES)
    with pytest.raises(WorkflowError, match="not in"):
        apply_approval(hold, Approval("raj", "approve", True, None), ("intern",))
    apply_approval(hold, Approval("raj", "approve", True, None), ROLES)
    assert hold.status is HoldStatus.APPROVED
    assert all(x.attestation_text for x in hold.approvals)


async def test_adapter_returning_nothing_expires_hold(ria, mk):
    eng = await _engine(ria, CallbackApprover(lambda h: asyncio.sleep(0, result=[])))
    d = await eng.decide(mk("custodian.place_trade", BIG))
    await eng.drain()
    assert (await eng.store.get_hold(d.hold_id)).status is HoldStatus.EXPIRED


async def test_reject_closes_hold(ria, mk):
    eng = await _engine(ria, AutoApprover(("a1",), ROLES, decision="reject"))
    d = await eng.decide(mk("custodian.place_trade", BIG))
    await eng.drain()
    hold = await eng.store.get_hold(d.hold_id)
    assert hold.status is HoldStatus.REJECTED
    d2 = await eng.decide(mk("custodian.place_trade", BIG))
    assert d2.verdict is Verdict.HOLD  # a new hold, no grant
    await eng.drain()


async def test_inbox_approver_out_of_band(ria, mk):
    inbox = InboxApprover(poll_s=0.01)
    eng = await _engine(ria, inbox)
    d = await eng.decide(mk("custodian.place_trade", BIG))
    await asyncio.sleep(0.05)
    assert len(inbox.open_holds()) == 1
    a = Approval("maria", "approve", True, None)
    a.roles = ROLES
    assert await inbox.submit(d.hold_id, a)
    await eng.drain()
    assert (await eng.store.get_hold(d.hold_id)).status is HoldStatus.APPROVED
    assert (await eng.decide(mk("custodian.place_trade", BIG))).verdict is Verdict.ALLOW


async def test_sla_expiry(ria, mk):
    inbox = InboxApprover(poll_s=0.01)
    eng = await _engine(ria, inbox)
    rule = ria[0].rule("RIA-TRD-001")
    object.__setattr__(rule.approval, "sla", timedelta(milliseconds=50))
    try:
        d = await eng.decide(mk("custodian.place_trade", BIG))
        await eng.drain()
        assert (await eng.store.get_hold(d.hold_id)).status is HoldStatus.EXPIRED
        expired = [e.event for e in eng.store.chain if e.event.kind == "hold_expired"]
        assert expired and expired[0].payload["on_sla_expiry"] == "cancel_and_log_trade_error"
    finally:
        object.__setattr__(rule.approval, "sla", timedelta(minutes=30))


async def test_no_override_never_holds(ria, mk):
    eng = await _engine(ria)
    d = await eng.decide(mk("email.send", {"to": ["a@b.com"], "body": "SSN 123-45-6789", "archived": True}))
    assert d.verdict is Verdict.DENY and "no override" in d.reason


async def test_chain_is_intact_and_redacted(ria, mk):
    eng = await _engine(ria)
    await eng.decide(mk("email.send", {"to": ["a@b.com"], "body": "SSN 123-45-6789 please", "password": "hunter2", "archived": True}))
    await eng.decide(mk("custodian.place_trade", BIG))
    await eng.drain()
    entries = eng.store.chain
    res = verify(entries)
    assert res.ok and res.entries == len(entries) >= 5
    dumped = str([e.event.to_dict() for e in entries])
    assert "123-45-6789" not in dumped and "hunter2" not in dumped
    assert "[REDACTED:SSN]" in dumped
    # tamper
    entries[1].event.payload["reason"] = "tampered"
    bad = verify(entries)
    assert not bad.ok and bad.first_bad_seq == 1
