"""Ingester: source events → redact → hash-chain → store, with control mapping."""
from __future__ import annotations

from regent.core.chain import Chain
from regent.core.match import Matcher
from regent.core.models import Pack, Principal, ToolCall
from regent.core.ports import AuditSource, Store


async def ingest(source: AuditSource, packs: list[Pack], store: Store, limit: int | None = None) -> int:
    chain = Chain(store, packs)
    matcher = Matcher(packs)
    n = 0
    async for ev in source.events():
        if ev.rule_id is None and ev.tool:
            # Attribute the gateway-side event to the rule that would have decided it: re-evaluate
            # when the arguments were logged, else fall back to the most specific governing rule.
            args = ev.payload.get("args")
            g = None
            if isinstance(args, dict):
                r = matcher.evaluate(ToolCall(tool=ev.tool, args=args, principal=Principal(user=ev.user or "anonymous",
                                                                                          agent=ev.agent or "unknown-agent")))
                if r:
                    g = (r[1], r[2])
                    ev.payload.setdefault("regent_reeval", r[0])
            g = g or matcher.governing(ev.tool)
            if g:
                ev.pack, ev.rule_id = g[0].name, g[1].id
            else:
                ev.payload["coverage_gap"] = True
        await chain.append(ev)
        n += 1
        if limit and n >= limit:
            break
    return n
