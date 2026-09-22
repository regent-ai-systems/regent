"""Inbox approver: the out-of-band pattern every real approver shares.

A hold is announced through zero or more *notifiers* (CLI print, Slack, Teams,
webhook). Approvals arrive later through the PDS admin API (``regent approve``,
a Slack button callback, a Teams action) and are dropped into this inbox. The
workflow in core/workflow.py validates them; this class only transports.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Awaitable, Callable, Protocol

from regent.core.models import Approval, Hold, HoldStatus, utcnow


class Notifier(Protocol):
    name: str

    async def notify(self, hold: Hold) -> None: ...


class InboxApprover:
    name = "inbox"

    def __init__(self, notifiers: list[Notifier] | None = None, poll_s: float = 0.2):
        self.notifiers = notifiers or []
        self.poll_s = poll_s
        self._queues: dict[str, asyncio.Queue[Approval]] = {}
        self._holds: dict[str, Hold] = {}

    def open_holds(self) -> list[Hold]:
        return [h for h in self._holds.values() if h.status is HoldStatus.PENDING]

    async def submit(self, hold_id: str, approval: Approval) -> bool:
        q = self._queues.get(hold_id)
        if q is None:
            return False
        await q.put(approval)
        return True

    async def ask(self, hold: Hold) -> list[Approval]:
        q: asyncio.Queue[Approval] = asyncio.Queue()
        self._queues[hold.id] = q
        self._holds[hold.id] = hold
        for n in self.notifiers:
            try:
                await n.notify(hold)
            except Exception as e:  # a broken notifier must not block the workflow
                print(f"[regent] notifier {n.name} failed: {e}")
        deadline = hold.opened_at + hold.approval.sla
        collected: list[Approval] = []
        try:
            # Collect until the workflow would be resolved. We can't see the workflow's
            # verdict from here, so we stop at required_approvals approves or one reject.
            approves = 0
            while utcnow() < deadline:
                remaining = (deadline - utcnow()).total_seconds()
                try:
                    a = await asyncio.wait_for(q.get(), timeout=min(self.poll_s, max(remaining, 0.01)))
                except asyncio.TimeoutError:
                    continue
                collected.append(a)
                if a.decision == "reject":
                    break
                if a.decision == "approve" and a.attestation_accepted and a.approver != hold.call.principal.user:
                    approves += 1
                if approves >= hold.required_approvals:
                    break
            return collected
        finally:
            self._queues.pop(hold.id, None)


class PrintNotifier:
    """Prints the hold to stdout with the exact command that resolves it."""

    name = "print"

    async def notify(self, hold: Hold) -> None:
        a = hold.approval
        print(f"\n[regent] HOLD {hold.id}  tool={hold.call.tool}  user={hold.call.principal.user}  "
              f"rule={hold.rule_id}  workflow={a.workflow}  approvers={list(a.approvers)}")
        print(f"[regent]   args={hold.call.args}")
        if a.attest:
            print(f"[regent]   attestation: \"{a.attest}\"")
        print(f"[regent]   approve:  regent approve {hold.id} --as <approver> --role <role> --attest")
        print(f"[regent]   reject:   regent approve {hold.id} --as <approver> --reject\n")


class AutoApprover:
    """Approves (or rejects) immediately. Demos and tests only."""

    name = "auto"

    def __init__(self, approvers: tuple[str, ...] = ("auto-approver",), roles: tuple[str, ...] = (),
                 decision: str = "approve", accept_attestation: bool = True, delay: timedelta = timedelta(0)):
        self.approvers = approvers
        self.roles = roles
        self.decision = decision
        self.accept = accept_attestation
        self.delay = delay

    async def ask(self, hold: Hold) -> list[Approval]:
        if self.delay:
            await asyncio.sleep(self.delay.total_seconds())
        out = []
        for name in self.approvers[: hold.required_approvals]:
            a = Approval(approver=name, decision=self.decision, attestation_accepted=self.accept,
                         attestation_text=None, comment="auto")
            a.roles = self.roles  # type: ignore[attr-defined]
            out.append(a)
        return out


class CallbackApprover:
    """Adapter for embedding: call ``fn(hold)`` to get approvals (AGT plugin, tests)."""

    name = "callback"

    def __init__(self, fn: Callable[[Hold], Awaitable[list[Approval]]]):
        self.fn = fn

    async def ask(self, hold: Hold) -> list[Approval]:
        return await self.fn(hold)
