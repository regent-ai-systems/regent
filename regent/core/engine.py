"""The Policy Decision Service core loop.

    rule = packs.match(call)
    if rule.denies(call):            deny
    if rule.holds(call):
        if grant valid for call:     allow (consume grant)
        else open hold, run workflow off the hot path, return hold
    allow

Everything is recorded on the chain. Deny by default: no rule, no allow.
"""
from __future__ import annotations

import asyncio
from typing import Any

from regent.core.chain import Chain
from regent.core.match import Matcher, compile_expression
from regent.core.models import (AuditEvent, Decision, Hold, Pack, ToolCall, new_id, utcnow)
from regent.core.ports import Approver, Store
from regent.core.workflow import run_workflow


class Engine:
    def __init__(self, packs: list[Pack], store: Store, approver: Approver, retry_after_s: int = 5):
        self.packs = packs
        self.store = store
        self.approver = approver
        self.matcher = Matcher(packs)
        self.chain = Chain(store, packs)
        self.retry_after_s = retry_after_s
        self._tasks: set[asyncio.Task[Any]] = set()

    async def audit(self, event: AuditEvent) -> None:
        await self.chain.append(event)

    async def _record(self, call: ToolCall, d: Decision, extra: dict[str, Any] | None = None) -> Decision:
        await self.audit(AuditEvent(kind="decision", at=d.at, source="regent-pds", tool=call.tool,
                                    user=call.principal.user, agent=call.principal.agent, rule_id=d.rule_id,
                                    pack=d.pack, verdict=d.verdict.value, hold_id=d.hold_id, grant_id=d.grant_id,
                                    payload={"call_id": call.call_id, "reason": d.reason, "args": call.args,
                                             "session_id": call.session_id, **(extra or {})}))
        return d

    async def decide(self, call: ToolCall) -> Decision:
        result = self.matcher.evaluate(call)
        if result is None:
            return await self._record(call, Decision.deny("no rule governs this tool (deny by default)", call=call),
                                      {"coverage_gap": True})
        verdict, pack, rule = result

        if verdict == "deny":
            fired = rule.deny_if and compile_expression(rule.deny_if).eval(call, pack.firm)
            why = "deny_if matched" if fired else "allow_if not satisfied"
            return await self._record(call, Decision.deny(f"{rule.id}: {why}"
                                                          + (" (no override)" if rule.no_override and fired else ""), rule, pack, call))

        if verdict == "hold":
            if rule.no_override or rule.approval is None:
                return await self._record(call, Decision.deny(f"{rule.id}: hold requested but rule has no approval path",
                                                              rule, pack, call))
            grant = await self.store.grant_for(call.fingerprint(), call.grant_token)
            if grant and grant.valid_at():
                if grant.single_use:
                    await self.store.consume_grant(grant.id)
                    await self.audit(AuditEvent(kind="grant_consumed", at=utcnow(), source="regent-pds",
                                                tool=call.tool, user=call.principal.user, agent=call.principal.agent,
                                                rule_id=rule.id, pack=pack.name, verdict="allow",
                                                hold_id=grant.hold_id, grant_id=grant.id,
                                                payload={"approvers": list(grant.approvers)}))
                return await self._record(call, Decision.allow(f"{rule.id}: approved via {grant.hold_id}", rule, pack,
                                                               call, grant_id=grant.id))
            hold = Hold(id=new_id("hold"), call=call, rule_id=rule.id, pack=pack.name, approval=rule.approval)
            await self.store.open_hold(hold)
            await self.audit(AuditEvent(kind="hold_opened", at=hold.opened_at, source="regent-pds", tool=call.tool,
                                        user=call.principal.user, agent=call.principal.agent, rule_id=rule.id,
                                        pack=pack.name, verdict="hold", hold_id=hold.id,
                                        payload={"workflow": rule.approval.workflow,
                                                 "approvers": list(rule.approval.approvers),
                                                 "attest": rule.approval.attest, "args": call.args,
                                                 "grant_ttl_s": rule.approval.grant_ttl.total_seconds()}))
            task = asyncio.create_task(run_workflow(hold, self.approver, self.store, self.audit))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
            return await self._record(call, Decision.hold(hold.id, rule, pack, call, self.retry_after_s))

        return await self._record(call, Decision.allow(f"{rule.id}: allow_if matched", rule, pack, call))

    async def drain(self) -> None:
        """Wait for in-flight workflows (tests, graceful shutdown)."""
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    async def record_policies(self, actor: str = "regent") -> None:
        for p in self.packs:
            await self.store.record_policy(p, actor)
            await self.audit(AuditEvent(kind="policy_change", at=utcnow(), source="regent-pds", pack=p.name,
                                        payload={"version": p.version, "rules": [r.id for r in p.rules],
                                                 "source_hash": p.source_hash, "actor": actor}))
