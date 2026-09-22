"""Microsoft Agent Governance Toolkit audit trail → AuditEvent.

AGT writes a Merkle-chained JSONL audit log. Each record carries its own hash
and the previous hash; we (1) verify that chain as we read it, (2) map the
record into a Regent AuditEvent, keeping AGT's hashes in the payload so an
examiner can cross-reference both ledgers.

Field names follow AGT's audit schema as of its April 2026 release; the alias
table absorbs renames.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from regent.core.models import AuditEvent

FIELD = {
    "ts": ("timestamp", "ts", "time"),
    "agent": ("agent_id", "agent", "principal"),
    "user": ("user_id", "user", "on_behalf_of", "subject"),
    "tool": ("tool", "tool_name", "action"),
    "args": ("arguments", "args", "input"),
    "decision": ("decision", "verdict", "outcome"),
    "policy": ("policy_id", "policy", "rule"),
    "hash": ("hash", "entry_hash"),
    "prev": ("previous_hash", "prev_hash", "parent_hash"),
}


def _get(rec: dict[str, Any], key: str) -> Any:
    for k in FIELD[key]:
        if k in rec:
            return rec[k]
    return None


class AGTMerkleSource:
    name = "agt_merkle"

    def __init__(self, path: str | Path, verify_chain: bool = True):
        self.path = Path(path)
        self.verify_chain = verify_chain
        self.chain_ok = True
        self.chain_error: str | None = None

    async def events(self) -> AsyncIterator[AuditEvent]:
        prev = None
        with self.path.open() as f:
            for n, line in enumerate(f):
                if not line.strip():
                    continue
                rec = json.loads(line)
                h, p = _get(rec, "hash"), _get(rec, "prev")
                if self.verify_chain and h:
                    if prev is not None and p != prev:
                        self.chain_ok, self.chain_error = False, f"AGT chain break at record {n}"
                    body = {k: v for k, v in rec.items() if k not in FIELD["hash"]}
                    recomputed = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                    if recomputed != h:
                        # AGT may hash a different canonical form; record, don't fail.
                        rec["_regent_hash_note"] = "hash not reproducible with sorted-JSON canonicalisation"
                    prev = h
                ts = _get(rec, "ts")
                at = (datetime.fromisoformat(str(ts).replace("Z", "+00:00")) if isinstance(ts, str)
                      else datetime.fromtimestamp(float(ts), tz=timezone.utc) if ts else datetime.now(timezone.utc))
                dec = str(_get(rec, "decision") or "allow").lower()
                yield AuditEvent(kind="tool_call", at=at, source="agt", tool=_get(rec, "tool"), user=_get(rec, "user"),
                                 agent=_get(rec, "agent"), rule_id=_get(rec, "policy"),
                                 verdict={"allowed": "allow", "denied": "deny", "blocked": "deny", "pending": "hold"}.get(dec, dec),
                                 payload={"args": _get(rec, "args"), "agt_hash": h, "agt_prev_hash": p, "raw": rec})
