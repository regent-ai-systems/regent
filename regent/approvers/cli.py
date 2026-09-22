"""Interactive terminal approver for the stdio shim / single-process demos.

For the PDS server, holds are resolved out-of-band with ``regent approve``
(see approvers/inbox.py). This adapter blocks on stdin instead.
"""
from __future__ import annotations

import asyncio

from regent.core.models import Approval, Hold


class CLIApprover:
    name = "cli"

    def __init__(self, default_roles: tuple[str, ...] = ()):
        self.default_roles = default_roles

    async def ask(self, hold: Hold) -> list[Approval]:
        a = hold.approval
        print(f"\n=== APPROVAL REQUIRED [{hold.id}] ===")
        print(f"tool: {hold.call.tool}\nrequester: {hold.call.principal.user}\nargs: {hold.call.args}")
        print(f"rule: {hold.rule_id}  workflow: {a.workflow}  approvers: {list(a.approvers)}")
        approvals: list[Approval] = []
        for i in range(hold.required_approvals):
            who = (await asyncio.to_thread(input, f"approver #{i + 1} username: ")).strip()
            roles = (await asyncio.to_thread(input, f"roles for {who} (comma-separated) [{','.join(self.default_roles)}]: ")).strip()
            roles_t = tuple(r.strip() for r in roles.split(",") if r.strip()) or self.default_roles
            accepted = True
            if a.attest:
                ans = (await asyncio.to_thread(input, f"attest: \"{a.attest}\"  [y/N]: ")).strip().lower()
                accepted = ans == "y"
            dec = (await asyncio.to_thread(input, "approve? [y/N]: ")).strip().lower()
            ap = Approval(approver=who, decision="approve" if dec == "y" else "reject", attestation_accepted=accepted,
                          attestation_text=None)
            ap.roles = roles_t  # type: ignore[attr-defined]
            approvals.append(ap)
            if ap.decision == "reject":
                break
        return approvals
