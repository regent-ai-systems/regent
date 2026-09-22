"""Hash chain over audit events and its verifier.

Each entry hashes (seq, prev_hash, redacted event, controls). ``verify`` walks
the chain and reports the first break. This is the open-source, single-writer
tamper-evidence layer; WORM (S3 Object Lock) and periodic anchoring are the
stores' job.
"""
from __future__ import annotations

from dataclasses import dataclass

from regent.core.models import AuditEvent, ChainedEntry, Pack
from regent.core.ports import Store
from regent.core.redact import redact


def controls_for(packs: list[Pack], pack_name: str | None, rule_id: str | None) -> tuple[str, ...]:
    if not rule_id:
        return ()
    for p in packs:
        if pack_name and p.name != pack_name:
            continue
        c = p.controls_for(rule_id)
        if c:
            return c
    return ()


def link(prev: ChainedEntry | None, event: AuditEvent, controls: tuple[str, ...]) -> ChainedEntry:
    event.payload = redact(event.payload)
    seq = 0 if prev is None else prev.seq + 1
    prev_hash = ChainedEntry.genesis_hash() if prev is None else prev.hash
    return ChainedEntry(seq=seq, prev_hash=prev_hash, event=event, controls=controls).seal()


class Chain:
    """Append-only writer bound to a store. Serialises appends."""

    def __init__(self, store: Store, packs: list[Pack]):
        self.store = store
        self.packs = packs
        self._head: ChainedEntry | None = None
        self._loaded = False

    async def _ensure(self) -> None:
        if not self._loaded:
            self._head = await self.store.head()
            self._loaded = True

    async def append(self, event: AuditEvent) -> ChainedEntry:
        await self._ensure()
        entry = link(self._head, event, controls_for(self.packs, event.pack, event.rule_id))
        await self.store.append(entry)
        self._head = entry
        return entry


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    first_bad_seq: int | None = None
    reason: str | None = None
    head_hash: str | None = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def verify(entries: list[ChainedEntry]) -> VerifyResult:
    prev_hash = ChainedEntry.genesis_hash()
    for i, e in enumerate(entries):
        if e.seq != i:
            return VerifyResult(False, len(entries), e.seq, f"sequence gap: expected {i} got {e.seq}")
        if e.prev_hash != prev_hash:
            return VerifyResult(False, len(entries), e.seq, "prev_hash does not match previous entry")
        if e.compute_hash() != e.hash:
            return VerifyResult(False, len(entries), e.seq, "entry hash does not match its content")
        prev_hash = e.hash
    return VerifyResult(True, len(entries), head_hash=prev_hash if entries else None)
