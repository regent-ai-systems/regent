"""Core data model. Everything the rest of Regent touches is defined here.

Design rules (from architecture v2):
- The core sees a normalised ToolCall and returns a Decision. Nothing else.
- Deny by default. A call that matches no rule is denied.
- ``no_override`` rules have no approval path.
- Every pack rule carries ``controls`` and ``examiner_asks``; the loader rejects
  packs that don't (tests enforce it too).
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for hashing. Sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------- principal / call


@dataclass(frozen=True)
class Principal:
    """Who is acting, and on whose behalf.

    ``agent`` is the workload identity (SPIFFE id, agentgateway apiKey name, ...).
    ``user`` is the human the agent acts for (JWT ``sub``).
    ``claims`` is the raw claim set so packs can reference arbitrary attributes
    (``principal.assigned_accounts``...).
    """

    user: str = "anonymous"
    agent: str = "unknown-agent"
    roles: tuple[str, ...] = ()
    claims: dict[str, Any] = field(default_factory=dict)

    def get(self, name: str, default: Any = None) -> Any:
        if name == "user":
            return self.user
        if name == "agent":
            return self.agent
        if name == "roles":
            return list(self.roles)
        return self.claims.get(name, default)


@dataclass(frozen=True)
class ToolCall:
    """A normalised MCP ``tools/call`` (or equivalent) as seen by the core."""

    tool: str  # fully qualified: "<target>.<tool>" e.g. "custodian.place_trade"
    args: dict[str, Any]
    principal: Principal
    call_id: str = field(default_factory=lambda: new_id("call"))
    session_id: str | None = None
    grant_token: str | None = None
    at: datetime = field(default_factory=utcnow)

    def fingerprint(self) -> str:
        """Stable hash of (tool, args, user). Grants are bound to this."""
        return sha256_hex(canonical_json({"tool": self.tool, "args": self.args, "user": self.principal.user}))


# --------------------------------------------------------------------------- rules / packs


class Verdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    HOLD = "hold"


@dataclass(frozen=True)
class ApprovalSpec:
    workflow: str = "single"  # single | four_eyes
    approvers: tuple[str, ...] = ()  # "role:supervising_principal", "user:alice"
    attest: str | None = None  # attestation text the approver must accept
    grant_ttl: timedelta = timedelta(minutes=10)
    escalate_to: tuple[str, ...] = ()
    sla: timedelta = timedelta(minutes=30)
    sod: bool = True  # separation of duties: requester may not approve own hold
    on_sla_expiry: str = "deny_and_log"  # what the firm does when nobody answers: cancel_and_log_trade_error, notify_adviser, ...


@dataclass(frozen=True)
class Rule:
    id: str
    tool: str  # exact name or glob ("custodian.*", "*")
    controls: tuple[str, ...]
    examiner_asks: str
    description: str = ""
    allow_if: str | None = None
    hold_if: str | None = None
    deny_if: str | None = None
    approval: ApprovalSpec | None = None
    no_override: bool = False
    priority: int = 100  # lower evaluates first within a pack

    @property
    def needs_args(self) -> bool:
        from regent.core.match import expression_uses_args

        return any(expression_uses_args(e) for e in (self.allow_if, self.hold_if, self.deny_if) if e)


@dataclass
class Pack:
    name: str  # "ria/v1"
    version: str
    rules: list[Rule]
    description: str = ""
    controls: dict[str, str] = field(default_factory=dict)  # control id -> citation text
    firm: dict[str, Any] = field(default_factory=dict)  # firm overlay: thresholds, lists, flags referenced as firm.<key>
    firm_keys_required: tuple[str, ...] = ()  # keys the overlay must supply (lint fails otherwise)
    exam_requests: list[dict[str, Any]] = field(default_factory=list)  # examiner request-list index
    source_path: str | None = None
    source_hash: str | None = None  # sha256 of the YAML that produced it

    def rule(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    def controls_for(self, rule_id: str) -> tuple[str, ...]:
        r = self.rule(rule_id)
        return r.controls if r else ()

    def examiner_question(self, rule_id: str) -> str | None:
        r = self.rule(rule_id)
        return r.examiner_asks if r else None


# --------------------------------------------------------------------------- decisions / holds / grants


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    rule_id: str | None
    pack: str | None
    reason: str
    hold_id: str | None = None
    grant_id: str | None = None
    retry_after_s: int | None = None
    call_id: str | None = None
    at: datetime = field(default_factory=utcnow)

    @staticmethod
    def deny(reason: str, rule: Rule | None = None, pack: Pack | None = None, call: ToolCall | None = None) -> "Decision":
        return Decision(Verdict.DENY, rule.id if rule else None, pack.name if pack else None, reason,
                        call_id=call.call_id if call else None)

    @staticmethod
    def allow(reason: str, rule: Rule, pack: Pack, call: ToolCall, grant_id: str | None = None) -> "Decision":
        return Decision(Verdict.ALLOW, rule.id, pack.name, reason, grant_id=grant_id, call_id=call.call_id)

    @staticmethod
    def hold(hold_id: str, rule: Rule, pack: Pack, call: ToolCall, retry_after_s: int = 5) -> "Decision":
        return Decision(Verdict.HOLD, rule.id, pack.name, "approval required", hold_id=hold_id,
                        retry_after_s=retry_after_s, call_id=call.call_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "rule_id": self.rule_id,
            "pack": self.pack,
            "reason": self.reason,
            "hold_id": self.hold_id,
            "grant_id": self.grant_id,
            "retry_after_s": self.retry_after_s,
            "call_id": self.call_id,
            "at": self.at.isoformat(),
        }


class HoldStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


@dataclass
class Approval:
    approver: str
    decision: str  # "approve" | "reject"
    attestation_accepted: bool
    attestation_text: str | None
    at: datetime = field(default_factory=utcnow)
    comment: str | None = None


@dataclass
class Hold:
    id: str
    call: ToolCall
    rule_id: str
    pack: str
    approval: ApprovalSpec
    status: HoldStatus = HoldStatus.PENDING
    approvals: list[Approval] = field(default_factory=list)
    opened_at: datetime = field(default_factory=utcnow)
    closed_at: datetime | None = None
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = self.call.fingerprint()

    @property
    def required_approvals(self) -> int:
        return 2 if self.approval.workflow == "four_eyes" else 1

    @property
    def approvals_granted(self) -> int:
        return sum(1 for a in self.approvals if a.decision == "approve")


@dataclass
class Grant:
    id: str
    hold_id: str
    fingerprint: str
    user: str
    tool: str
    rule_id: str
    pack: str
    issued_at: datetime
    expires_at: datetime
    approvers: tuple[str, ...]
    token: str = field(default_factory=lambda: secrets.token_urlsafe(24))
    consumed_at: datetime | None = None
    single_use: bool = True

    def valid_at(self, when: datetime | None = None) -> bool:
        when = when or utcnow()
        return self.consumed_at is None and self.issued_at <= when < self.expires_at


# --------------------------------------------------------------------------- audit


@dataclass
class AuditEvent:
    """Normalised audit event from any source (OTLP, AGT Merkle, JSONL, Regent itself)."""

    kind: str  # decision | hold_opened | approval | grant_issued | grant_consumed | tool_call | policy_change
    at: datetime
    source: str  # "agentgateway-otlp" | "regent-pds" | "agt" | "jsonl"
    tool: str | None = None
    user: str | None = None
    agent: str | None = None
    rule_id: str | None = None
    pack: str | None = None
    verdict: str | None = None
    hold_id: str | None = None
    grant_id: str | None = None
    payload: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: new_id("ev"))

    def to_dict(self) -> dict[str, Any]:
        d = {
            "event_id": self.event_id,
            "kind": self.kind,
            "at": self.at.isoformat(),
            "source": self.source,
            "tool": self.tool,
            "user": self.user,
            "agent": self.agent,
            "rule_id": self.rule_id,
            "pack": self.pack,
            "verdict": self.verdict,
            "hold_id": self.hold_id,
            "grant_id": self.grant_id,
            "payload": self.payload,
        }
        return d


@dataclass
class ChainedEntry:
    """One link of the hash chain: sha256(prev_hash || canonical(event) || controls)."""

    seq: int
    prev_hash: str
    event: AuditEvent
    controls: tuple[str, ...]
    hash: str = ""

    @staticmethod
    def genesis_hash() -> str:
        return "0" * 64

    def body(self) -> str:
        return canonical_json({"seq": self.seq, "prev": self.prev_hash, "event": self.event.to_dict(),
                               "controls": list(self.controls)})

    def compute_hash(self) -> str:
        return sha256_hex(self.body())

    def seal(self) -> "ChainedEntry":
        self.hash = self.compute_hash()
        return self

    def to_dict(self) -> dict[str, Any]:
        return {"seq": self.seq, "prev_hash": self.prev_hash, "hash": self.hash,
                "controls": list(self.controls), "event": self.event.to_dict()}
