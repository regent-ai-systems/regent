"""JSONL audit source: one event per line. Regent's own export format and the
lowest-common-denominator import (agentgateway access logs in JSON, custom
proxies, replay of an OTLP dump)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator

from regent.core.models import AuditEvent
from regent.sources.otel_otlp import parse_logs_json, parse_traces_json, pick


def _dt(v: Any) -> datetime:
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(v if v < 1e11 else v / 1e9, tz=timezone.utc)
    if isinstance(v, str):
        d = datetime.fromisoformat(v.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def line_to_events(obj: dict[str, Any]) -> list[AuditEvent]:
    if "resourceSpans" in obj:
        return parse_traces_json(obj)
    if "resourceLogs" in obj:
        return parse_logs_json(obj)
    if "kind" in obj and "at" in obj:  # Regent native
        return [AuditEvent(kind=obj["kind"], at=_dt(obj["at"]), source=obj.get("source", "jsonl"), tool=obj.get("tool"),
                           user=obj.get("user"), agent=obj.get("agent"), rule_id=obj.get("rule_id"), pack=obj.get("pack"),
                           verdict=obj.get("verdict"), hold_id=obj.get("hold_id"), grant_id=obj.get("grant_id"),
                           payload=obj.get("payload") or {}, event_id=obj.get("event_id") or AuditEvent.__dataclass_fields__["event_id"].default_factory())]
    # agentgateway access log line (flat JSON with mcp.* keys) or anything with a tool name
    flat = {k: v for k, v in obj.items()}
    tool = pick(flat, "tool") or flat.get("tool")
    if not tool:
        return []
    target = pick(flat, "target")
    return [AuditEvent(kind="tool_call", at=_dt(flat.get("time") or flat.get("timestamp") or flat.get("start")),
                       source="jsonl", tool=f"{target}.{tool}" if target and "." not in str(tool) else str(tool),
                       user=pick(flat, "user"), agent=pick(flat, "agent"), verdict=str(pick(flat, "verdict") or "allow"),
                       rule_id=pick(flat, "rule"), payload={"args": pick(flat, "args"), "raw": flat})]


class JSONLSource:
    name = "jsonl"

    def __init__(self, path: str | Path):
        self.path = Path(path)

    async def events(self) -> AsyncIterator[AuditEvent]:
        with self.path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for ev in line_to_events(obj):
                    yield ev
