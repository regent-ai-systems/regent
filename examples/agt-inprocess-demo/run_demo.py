"""In-process demo: Regent as a guard inside a Python agent host (the AGT plugin path).

    python examples/agt-inprocess-demo/run_demo.py

No gateway, no network. The same RIA pack, the same hold/grant/chain semantics,
driven through RegentGuard.check(). The approver here is a callback that a real
host would wire to AGT's ``require_approval`` bridge or to a Slack app.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from regent.approvers.inbox import CallbackApprover  # noqa: E402
from regent.core.chain import verify  # noqa: E402
from regent.core.models import Approval, Hold  # noqa: E402
from regent.runtimes.agt_plugin import RegentGuard  # noqa: E402


async def two_principals_approve(hold: Hold) -> list[Approval]:
    print(f"  [approver] hold {hold.id}: {hold.call.tool} {hold.call.args} needs {hold.approval.workflow}")
    print(f"  [approver] attestation: {hold.approval.attest}")
    out = []
    for who in ("maria.cco", "raj.supervisor")[: hold.required_approvals]:
        a = Approval(approver=who, decision="approve", attestation_accepted=True, attestation_text=None)
        a.roles = ("trading_supervisor",)  # type: ignore[attr-defined]
        out.append(a)
    return out


async def main() -> None:
    guard = RegentGuard.from_packs([str(ROOT / "packs" / "ria")], approver=CallbackApprover(two_principals_approve),
                                   firm=str(ROOT / "packs" / "ria" / "firm.example.yaml"))
    claims = {"assigned_accounts": ["ACC-1"]}
    memo = {"order_terms": {"side": "buy", "quantity": 10, "order_type": "market", "tif": "day"}, "discretionary": True,
            "recommended_by": "model:core-60-40", "placed_by": "agt-agent on behalf of agent7", "executing_broker": "CUSTODIAN-BD"}

    async def check(label: str, tool: str, args: dict) -> None:
        d = await guard.check(tool=tool, args=args, user="agent7", roles=["trader"], claims=claims)
        print(f"{label:36s} → {d.verdict.value:5s} {d.rule_id or ''}  {d.reason}")

    await check("routine trade", "custodian.place_trade", {**memo, "notional_usd": 1000, "account": "ACC-1", "security_id": "VTI"})
    await check("large trade (hold)", "custodian.place_trade", {**memo, "notional_usd": 500000, "account": "ACC-1", "security_id": "VTI"})
    await guard.engine.drain()  # approvals run off the hot path; wait for them here
    await check("large trade retry (grant)", "custodian.place_trade", {**memo, "notional_usd": 500000, "account": "ACC-1", "security_id": "VTI"})
    await check("non-discretionary, no instruction", "custodian.place_trade",
                {**memo, "discretionary": False, "notional_usd": 1000, "account": "ACC-1", "security_id": "VTI"})
    await check("email with account number", "email.send", {"to": ["c@x.com"], "body": "acct 12345678 is overdrawn", "archived": True})
    await check("record deletion", "crm.delete_contact", {"contact_id": "C1"})
    await check("ungoverned tool", "crm.get_contact", {"contact_id": "C1"})
    res = verify(await guard.engine.store.entries())
    print(f"chain: {'INTACT' if res.ok else 'BROKEN'} · {res.entries} entries")


if __name__ == "__main__":
    asyncio.run(main())
