"""Approval workflows: single, four_eyes; separation of duties; time-boxed grants.

A hold is resolved by approvals collected through an Approver adapter. The
workflow enforces what the adapter cannot be trusted to:

- SoD: the requesting user can never approve their own hold.
- four_eyes: two *distinct* approvers, each must accept the attestation text.
- Attestation: an approval without the attestation accepted does not count.
- Grant: issued once, bound to the call fingerprint (tool + args + user),
  single-use, expires after ``grant_ttl``. A different arg set needs a new hold.
- SLA: unresolved holds expire; expiry is recorded, never silently dropped.
"""
from __future__ import annotations

import fnmatch
from datetime import timedelta

from regent.core.models import (Approval, AuditEvent, Grant, Hold, HoldStatus, new_id, utcnow)
from regent.core.ports import Approver, Store


class WorkflowError(ValueError):
    pass


def approver_allowed(hold: Hold, approver: str, approver_roles: tuple[str, ...] = ()) -> str | None:
    """Return a rejection reason, or None if this approver may act on the hold."""
    if hold.approval.sod and approver == hold.call.principal.user:
        return "separation of duties: requester cannot approve own hold"
    if any(a.approver == approver for a in hold.approvals):
        return "approver already acted on this hold"
    if not hold.approval.approvers:
        return None
    for spec in hold.approval.approvers:
        kind, _, value = spec.partition(":")
        if kind == "user" and fnmatch.fnmatchcase(approver, value):
            return None
        if kind == "role" and value in approver_roles:
            return None
        if kind == "any":
            return None
    return f"approver {approver!r} not in {list(hold.approval.approvers)}"


def apply_approval(hold: Hold, approval: Approval, approver_roles: tuple[str, ...] = ()) -> Hold:
    if hold.status is not HoldStatus.PENDING:
        raise WorkflowError(f"hold {hold.id} is {hold.status.value}")
    if reason := approver_allowed(hold, approval.approver, approver_roles):
        raise WorkflowError(reason)
    if approval.decision == "approve" and hold.approval.attest and not approval.attestation_accepted:
        raise WorkflowError("attestation must be accepted to approve")
    if approval.decision == "approve":
        approval.attestation_text = hold.approval.attest
    hold.approvals.append(approval)
    if approval.decision == "reject":
        hold.status = HoldStatus.REJECTED
        hold.closed_at = utcnow()
    elif hold.approvals_granted >= hold.required_approvals:
        hold.status = HoldStatus.APPROVED
        hold.closed_at = utcnow()
    return hold


def issue_grant(hold: Hold) -> Grant:
    if hold.status is not HoldStatus.APPROVED:
        raise WorkflowError("grant requires an approved hold")
    now = utcnow()
    return Grant(
        id=new_id("grant"),
        hold_id=hold.id,
        fingerprint=hold.fingerprint,
        user=hold.call.principal.user,
        tool=hold.call.tool,
        rule_id=hold.rule_id,
        pack=hold.pack,
        issued_at=now,
        expires_at=now + hold.approval.grant_ttl,
        approvers=tuple(a.approver for a in hold.approvals if a.decision == "approve"),
    )


def expire_if_due(hold: Hold, now=None) -> bool:
    now = now or utcnow()
    if hold.status is HoldStatus.PENDING and now - hold.opened_at > hold.approval.sla:
        hold.status = HoldStatus.EXPIRED
        hold.closed_at = now
        return True
    return False


async def run_workflow(hold: Hold, approver: Approver, store: Store, audit) -> Hold:
    """Drive a hold to resolution through an Approver adapter.

    ``audit`` is an async callable taking an AuditEvent (the chain writer).
    The adapter returns approvals; we validate every one here regardless of what
    the adapter did, then issue the grant.
    """
    try:
        approvals = await approver.ask(hold)
    except Exception as e:  # adapter failure is a rejection, never an allow
        hold.status = HoldStatus.REJECTED
        hold.closed_at = utcnow()
        await store.update_hold(hold)
        await audit(AuditEvent(kind="approval", at=utcnow(), source="regent-pds", tool=hold.call.tool,
                               user=hold.call.principal.user, agent=hold.call.principal.agent,
                               rule_id=hold.rule_id, pack=hold.pack, verdict="reject", hold_id=hold.id,
                               payload={"error": f"approver adapter failed: {e}"}))
        return hold

    for a in approvals:
        if hold.status is not HoldStatus.PENDING:
            break
        try:
            apply_approval(hold, a, approver_roles=tuple(getattr(a, "roles", ()) or ()))
            await audit(AuditEvent(kind="approval", at=a.at, source="regent-pds", tool=hold.call.tool,
                                   user=hold.call.principal.user, agent=hold.call.principal.agent,
                                   rule_id=hold.rule_id, pack=hold.pack, verdict=a.decision, hold_id=hold.id,
                                   payload={"approver": a.approver, "attestation_accepted": a.attestation_accepted,
                                            "attestation_text": a.attestation_text, "comment": a.comment,
                                            "workflow": hold.approval.workflow,
                                            "approvals": f"{hold.approvals_granted}/{hold.required_approvals}"}))
        except WorkflowError as e:
            await audit(AuditEvent(kind="approval", at=utcnow(), source="regent-pds", tool=hold.call.tool,
                                   user=hold.call.principal.user, rule_id=hold.rule_id, pack=hold.pack,
                                   verdict="invalid", hold_id=hold.id,
                                   payload={"approver": a.approver, "rejected_because": str(e)}))

    if hold.status is HoldStatus.PENDING:
        expire_if_due(hold, hold.opened_at + hold.approval.sla + timedelta(seconds=1))
        await audit(AuditEvent(kind="hold_expired", at=utcnow(), source="regent-pds", tool=hold.call.tool,
                               user=hold.call.principal.user, rule_id=hold.rule_id, pack=hold.pack,
                               verdict="expired", hold_id=hold.id,
                               payload={"sla_s": hold.approval.sla.total_seconds(),
                                        "on_sla_expiry": hold.approval.on_sla_expiry,
                                        "call_id": hold.call.call_id, "args": hold.call.args}))

    await store.update_hold(hold)
    if hold.status is HoldStatus.APPROVED:
        grant = issue_grant(hold)
        await store.put_grant(grant)
        await audit(AuditEvent(kind="grant_issued", at=grant.issued_at, source="regent-pds", tool=hold.call.tool,
                               user=hold.call.principal.user, agent=hold.call.principal.agent,
                               rule_id=hold.rule_id, pack=hold.pack, verdict="allow", hold_id=hold.id,
                               grant_id=grant.id,
                               payload={"expires_at": grant.expires_at.isoformat(), "approvers": list(grant.approvers),
                                        "fingerprint": grant.fingerprint}))
    return hold
