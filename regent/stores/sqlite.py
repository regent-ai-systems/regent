"""SQLite store (dev). Single writer, append-only chain table.

Postgres and S3 Object Lock stores share this schema; they live in the same
package once the design partners need them (weeks 2–4).
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from regent.core.models import (Approval, ApprovalSpec, AuditEvent, ChainedEntry, Grant, Hold, HoldStatus, Pack,
                                Principal, ToolCall, utcnow)

SCHEMA = """
CREATE TABLE IF NOT EXISTS chain (
  seq INTEGER PRIMARY KEY, prev_hash TEXT NOT NULL, hash TEXT NOT NULL UNIQUE,
  at TEXT NOT NULL, controls TEXT NOT NULL, event TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS holds (
  id TEXT PRIMARY KEY, status TEXT NOT NULL, fingerprint TEXT NOT NULL, opened_at TEXT NOT NULL,
  closed_at TEXT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY, hold_id TEXT NOT NULL, fingerprint TEXT NOT NULL, token TEXT NOT NULL UNIQUE,
  user TEXT NOT NULL, issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, consumed_at TEXT, data TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS grants_fp ON grants(fingerprint);
CREATE TABLE IF NOT EXISTS policies (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, pack TEXT NOT NULL, version TEXT NOT NULL,
  source_hash TEXT, actor TEXT NOT NULL, rules TEXT NOT NULL);
"""


def _dt(s: str | None) -> datetime | None:
    return datetime.fromisoformat(s) if s else None


def _call_to_dict(c: ToolCall) -> dict[str, Any]:
    return {"tool": c.tool, "args": c.args, "call_id": c.call_id, "session_id": c.session_id,
            "grant_token": c.grant_token, "at": c.at.isoformat(),
            "principal": {"user": c.principal.user, "agent": c.principal.agent, "roles": list(c.principal.roles),
                          "claims": c.principal.claims}}


def _call_from_dict(d: dict[str, Any]) -> ToolCall:
    p = d["principal"]
    return ToolCall(tool=d["tool"], args=d["args"], call_id=d["call_id"], session_id=d.get("session_id"),
                    grant_token=d.get("grant_token"), at=_dt(d["at"]),
                    principal=Principal(user=p["user"], agent=p["agent"], roles=tuple(p["roles"]), claims=p["claims"]))


def hold_to_dict(h: Hold) -> dict[str, Any]:
    a = h.approval
    return {"id": h.id, "call": _call_to_dict(h.call), "rule_id": h.rule_id, "pack": h.pack, "status": h.status.value,
            "fingerprint": h.fingerprint, "opened_at": h.opened_at.isoformat(),
            "closed_at": h.closed_at.isoformat() if h.closed_at else None,
            "approval": {"workflow": a.workflow, "approvers": list(a.approvers), "attest": a.attest,
                         "grant_ttl_s": a.grant_ttl.total_seconds(), "escalate_to": list(a.escalate_to),
                         "sla_s": a.sla.total_seconds(), "sod": a.sod, "on_sla_expiry": a.on_sla_expiry},
            "approvals": [{**asdict(x), "at": x.at.isoformat()} for x in h.approvals]}


def hold_from_dict(d: dict[str, Any]) -> Hold:
    a = d["approval"]
    spec = ApprovalSpec(workflow=a["workflow"], approvers=tuple(a["approvers"]), attest=a["attest"],
                        grant_ttl=timedelta(seconds=a["grant_ttl_s"]), escalate_to=tuple(a["escalate_to"]),
                        sla=timedelta(seconds=a["sla_s"]), sod=a["sod"], on_sla_expiry=a.get("on_sla_expiry", "deny_and_log"))
    h = Hold(id=d["id"], call=_call_from_dict(d["call"]), rule_id=d["rule_id"], pack=d["pack"], approval=spec,
             status=HoldStatus(d["status"]), opened_at=_dt(d["opened_at"]), closed_at=_dt(d.get("closed_at")),
             fingerprint=d["fingerprint"])
    h.approvals = [Approval(approver=x["approver"], decision=x["decision"],
                            attestation_accepted=x["attestation_accepted"], attestation_text=x["attestation_text"],
                            at=_dt(x["at"]), comment=x.get("comment")) for x in d["approvals"]]
    return h


def _grant_row(g: Grant) -> dict[str, Any]:
    return {**asdict(g), "issued_at": g.issued_at.isoformat(), "expires_at": g.expires_at.isoformat(),
            "consumed_at": g.consumed_at.isoformat() if g.consumed_at else None, "approvers": list(g.approvers)}


def _grant_from(d: dict[str, Any]) -> Grant:
    return Grant(id=d["id"], hold_id=d["hold_id"], fingerprint=d["fingerprint"], user=d["user"], tool=d["tool"],
                 rule_id=d["rule_id"], pack=d["pack"], issued_at=_dt(d["issued_at"]), expires_at=_dt(d["expires_at"]),
                 approvers=tuple(d["approvers"]), token=d["token"], consumed_at=_dt(d.get("consumed_at")),
                 single_use=d.get("single_use", True))


def _event_from(d: dict[str, Any]) -> AuditEvent:
    return AuditEvent(kind=d["kind"], at=_dt(d["at"]), source=d["source"], tool=d.get("tool"), user=d.get("user"),
                      agent=d.get("agent"), rule_id=d.get("rule_id"), pack=d.get("pack"), verdict=d.get("verdict"),
                      hold_id=d.get("hold_id"), grant_id=d.get("grant_id"), payload=d.get("payload") or {},
                      event_id=d["event_id"])


def entry_from_dict(d: dict[str, Any]) -> ChainedEntry:
    return ChainedEntry(seq=d["seq"], prev_hash=d["prev_hash"], event=_event_from(d["event"]),
                        controls=tuple(d["controls"]), hash=d["hash"])


class SQLiteStore:
    def __init__(self, path: str | Path = "regent.db"):
        self.path = str(path)
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(SCHEMA)
        self._lock = asyncio.Lock()

    def close(self) -> None:
        self._db.close()

    # holds
    async def open_hold(self, hold: Hold) -> None:
        async with self._lock:
            self._db.execute("INSERT INTO holds VALUES (?,?,?,?,?,?)",
                             (hold.id, hold.status.value, hold.fingerprint, hold.opened_at.isoformat(), None,
                              json.dumps(hold_to_dict(hold))))

    async def get_hold(self, hold_id: str) -> Hold | None:
        row = self._db.execute("SELECT data FROM holds WHERE id=?", (hold_id,)).fetchone()
        return hold_from_dict(json.loads(row[0])) if row else None

    async def update_hold(self, hold: Hold) -> None:
        async with self._lock:
            self._db.execute("UPDATE holds SET status=?, closed_at=?, data=? WHERE id=?",
                             (hold.status.value, hold.closed_at.isoformat() if hold.closed_at else None,
                              json.dumps(hold_to_dict(hold)), hold.id))

    async def pending_holds(self) -> list[Hold]:
        rows = self._db.execute("SELECT data FROM holds WHERE status='pending' ORDER BY opened_at").fetchall()
        return [hold_from_dict(json.loads(r[0])) for r in rows]

    # grants
    async def put_grant(self, grant: Grant) -> None:
        async with self._lock:
            self._db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,?,?,?)",
                             (grant.id, grant.hold_id, grant.fingerprint, grant.token, grant.user,
                              grant.issued_at.isoformat(), grant.expires_at.isoformat(), None,
                              json.dumps(_grant_row(grant))))

    async def grant_for(self, fingerprint: str, token: str | None = None) -> Grant | None:
        now = utcnow().isoformat()
        if token:
            row = self._db.execute("SELECT data FROM grants WHERE token=? AND fingerprint=? AND consumed_at IS NULL "
                                   "AND expires_at > ?", (token, fingerprint, now)).fetchone()
        else:
            row = self._db.execute("SELECT data FROM grants WHERE fingerprint=? AND consumed_at IS NULL AND expires_at > ? "
                                   "ORDER BY issued_at DESC LIMIT 1", (fingerprint, now)).fetchone()
        return _grant_from(json.loads(row[0])) if row else None

    async def consume_grant(self, grant_id: str) -> None:
        async with self._lock:
            now = utcnow().isoformat()
            row = self._db.execute("SELECT data FROM grants WHERE id=?", (grant_id,)).fetchone()
            if row:
                d = json.loads(row[0])
                d["consumed_at"] = now
                self._db.execute("UPDATE grants SET consumed_at=?, data=? WHERE id=?", (now, json.dumps(d), grant_id))

    async def grants(self, since: Any = None) -> list[Grant]:
        rows = self._db.execute("SELECT data FROM grants ORDER BY issued_at").fetchall()
        return [_grant_from(json.loads(r[0])) for r in rows]

    # chain
    async def head(self) -> ChainedEntry | None:
        row = self._db.execute("SELECT seq, prev_hash, hash, controls, event FROM chain ORDER BY seq DESC LIMIT 1").fetchone()
        return self._row_to_entry(row) if row else None

    @staticmethod
    def _row_to_entry(row) -> ChainedEntry:
        seq, prev_hash, h, controls, event = row
        return ChainedEntry(seq=seq, prev_hash=prev_hash, event=_event_from(json.loads(event)),
                            controls=tuple(json.loads(controls)), hash=h)

    async def append(self, entry: ChainedEntry) -> None:
        async with self._lock:
            self._db.execute("INSERT INTO chain VALUES (?,?,?,?,?,?)",
                             (entry.seq, entry.prev_hash, entry.hash, entry.event.at.isoformat(),
                              json.dumps(list(entry.controls)), json.dumps(entry.event.to_dict())))

    async def entries(self, since: Any = None, until: Any = None) -> list[ChainedEntry]:
        rows = self._db.execute("SELECT seq, prev_hash, hash, controls, event FROM chain ORDER BY seq").fetchall()
        return [self._row_to_entry(r) for r in rows]

    # policies
    async def record_policy(self, pack: Pack, actor: str) -> None:
        async with self._lock:
            self._db.execute("INSERT INTO policies (at, pack, version, source_hash, actor, rules) VALUES (?,?,?,?,?,?)",
                             (utcnow().isoformat(), pack.name, pack.version, pack.source_hash, actor,
                              json.dumps([r.id for r in pack.rules])))

    async def policy_history(self) -> list[dict[str, Any]]:
        rows = self._db.execute("SELECT at, pack, version, source_hash, actor, rules FROM policies ORDER BY id").fetchall()
        return [{"at": r[0], "pack": r[1], "version": r[2], "source_hash": r[3], "actor": r[4], "rules": json.loads(r[5])}
                for r in rows]
