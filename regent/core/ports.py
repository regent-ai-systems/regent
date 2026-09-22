"""Hexagonal ports. Adapters live in runtimes/, sources/, approvers/, stores/.

The core imports nothing from those packages; they import the core.
"""
from __future__ import annotations

from typing import Any, AsyncIterator, Awaitable, Callable, Protocol, runtime_checkable

from regent.core.models import (Approval, AuditEvent, ChainedEntry, Decision, Grant, Hold, Pack,
                                ToolCall)

Decider = Callable[[ToolCall], Awaitable[Decision]]


@runtime_checkable
class Runtime(Protocol):
    """Where enforcement happens: agentgateway ext_authz, AGT plugin, stdio shim."""

    name: str

    async def serve(self, decide: Decider) -> None: ...


@runtime_checkable
class Compiler(Protocol):
    """Emit a runtime's native policy dialect for the cheap rules of a pack."""

    dialect: str

    def compile(self, packs: list[Pack]) -> "CompiledPolicy": ...


class CompiledPolicy:
    def __init__(self, dialect: str, text: str, native_rule_ids: list[str], pds_rule_ids: list[str],
                 notes: list[str] | None = None):
        self.dialect = dialect
        self.text = text
        self.native_rule_ids = native_rule_ids  # enforced in the gateway, never reach Regent
        self.pds_rule_ids = pds_rule_ids  # need args or state: routed to the PDS
        self.notes = notes or []


@runtime_checkable
class AuditSource(Protocol):
    name: str

    def events(self) -> AsyncIterator[AuditEvent]: ...


@runtime_checkable
class Approver(Protocol):
    """Asks humans. Returns when the hold is resolved or the SLA expires."""

    name: str

    async def ask(self, hold: Hold) -> list[Approval]: ...


@runtime_checkable
class Store(Protocol):
    async def open_hold(self, hold: Hold) -> None: ...
    async def get_hold(self, hold_id: str) -> Hold | None: ...
    async def update_hold(self, hold: Hold) -> None: ...
    async def pending_holds(self) -> list[Hold]: ...
    async def put_grant(self, grant: Grant) -> None: ...
    async def grant_for(self, fingerprint: str, token: str | None = None) -> Grant | None: ...
    async def consume_grant(self, grant_id: str) -> None: ...
    async def grants(self, since: Any = None) -> list[Grant]: ...
    async def head(self) -> ChainedEntry | None: ...
    async def append(self, entry: ChainedEntry) -> None: ...
    async def entries(self, since: Any = None, until: Any = None) -> list[ChainedEntry]: ...
    async def record_policy(self, pack: Pack, actor: str) -> None: ...
    async def policy_history(self) -> list[dict[str, Any]]: ...
