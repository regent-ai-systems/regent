"""In-process runtime for the Microsoft Agent Governance Toolkit (and any Python host).

AGT lets a policy hook run before a tool executes. This module exposes Regent
as a plain async callable with AGT's shape so the same packs, holds, grants
and chain apply without a network hop:

    from regent.runtimes.agt_plugin import RegentGuard
    guard = RegentGuard.from_packs(["packs/ria"], approver=my_approver)
    verdict = await guard.check(tool="custodian.place_trade", args={...}, user="agent-7", roles=["trader"])
    if verdict.verdict != "allow": ...

The AGT-native adapter (registering as a ``PolicyPlugin`` with its
``require_approval`` bridge) is the weeks-2–4 item; it wraps ``check``. The
Cedar compiler already emits the cheap rules for AGT's engine.
"""
from __future__ import annotations

from typing import Any

from regent.core.engine import Engine
from regent.core.models import Decision, Principal, ToolCall
from regent.core.packs import load_packs
from regent.core.ports import Approver, Store


class RegentGuard:
    name = "agt_plugin"

    def __init__(self, engine: Engine):
        self.engine = engine

    @classmethod
    def from_packs(cls, pack_paths: list[str], approver: Approver, store: Store | None = None,
                   firm: str | dict | None = None) -> "RegentGuard":
        from regent.stores.memory import MemoryStore
        return cls(Engine(load_packs(pack_paths, firm), store or MemoryStore(), approver))

    async def check(self, tool: str, args: dict[str, Any], user: str, agent: str = "agt-agent",
                    roles: list[str] | None = None, claims: dict[str, Any] | None = None,
                    grant_token: str | None = None) -> Decision:
        call = ToolCall(tool=tool, args=args, grant_token=grant_token,
                        principal=Principal(user=user, agent=agent, roles=tuple(roles or ()), claims=claims or {}))
        return await self.engine.decide(call)

    async def serve(self, decide=None) -> None:  # Runtime protocol; nothing to serve in-process
        return None
