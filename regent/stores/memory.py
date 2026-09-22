"""In-memory store for tests and the stdio shim's ephemeral mode."""
from __future__ import annotations

from typing import Any

from regent.core.models import ChainedEntry, Grant, Hold, HoldStatus, Pack, utcnow


class MemoryStore:
    def __init__(self) -> None:
        self.holds: dict[str, Hold] = {}
        self.grants_by_id: dict[str, Grant] = {}
        self.chain: list[ChainedEntry] = []
        self.policies: list[dict[str, Any]] = []

    async def open_hold(self, hold: Hold) -> None:
        self.holds[hold.id] = hold

    async def get_hold(self, hold_id: str) -> Hold | None:
        return self.holds.get(hold_id)

    async def update_hold(self, hold: Hold) -> None:
        self.holds[hold.id] = hold

    async def pending_holds(self) -> list[Hold]:
        return [h for h in self.holds.values() if h.status is HoldStatus.PENDING]

    async def put_grant(self, grant: Grant) -> None:
        self.grants_by_id[grant.id] = grant

    async def grant_for(self, fingerprint: str, token: str | None = None) -> Grant | None:
        cands = [g for g in self.grants_by_id.values() if g.fingerprint == fingerprint and g.valid_at()]
        if token:
            cands = [g for g in cands if g.token == token]
        return max(cands, key=lambda g: g.issued_at) if cands else None

    async def consume_grant(self, grant_id: str) -> None:
        self.grants_by_id[grant_id].consumed_at = utcnow()

    async def grants(self, since: Any = None) -> list[Grant]:
        return list(self.grants_by_id.values())

    async def head(self) -> ChainedEntry | None:
        return self.chain[-1] if self.chain else None

    async def append(self, entry: ChainedEntry) -> None:
        self.chain.append(entry)

    async def entries(self, since: Any = None, until: Any = None) -> list[ChainedEntry]:
        return list(self.chain)

    async def record_policy(self, pack: Pack, actor: str) -> None:
        self.policies.append({"at": utcnow().isoformat(), "pack": pack.name, "version": pack.version,
                              "source_hash": pack.source_hash, "actor": actor, "rules": [r.id for r in pack.rules]})

    async def policy_history(self) -> list[dict[str, Any]]:
        return list(self.policies)
