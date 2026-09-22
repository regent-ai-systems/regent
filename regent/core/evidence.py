"""Period evidence package: what a CCO hands the examiner.

Built from the chain, never from live state, so it can be regenerated for any
period and cross-checked with ``regent verify``. Sections mirror what an
examiner asks for: policies in force, supervision (holds/approvals), denials,
coverage gaps, chain integrity — each keyed to control IDs and the examiner
question that the rule answers.
"""
from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from regent.core.chain import verify
from regent.core.models import ChainedEntry, Pack


def _iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def build_evidence(entries: list[ChainedEntry], packs: list[Pack], period_start: datetime, period_end: datetime,
                   reachable_tools: list[str] | None = None, firm: str = "") -> dict[str, Any]:
    in_period = [e for e in entries if period_start <= e.event.at < period_end]
    integrity = verify(entries)

    # policies in force
    policies = []
    for p in packs:
        policies.append({"pack": p.name, "version": p.version, "source_hash": p.source_hash,
                         "rules": [{"id": r.id, "tool": r.tool, "controls": list(r.controls),
                                    "examiner_asks": r.examiner_asks, "no_override": r.no_override,
                                    "workflow": r.approval.workflow if r.approval else None} for r in p.rules]})
    policy_changes = [{"at": _iso(e.event.at), "pack": e.event.pack, **e.event.payload}
                      for e in in_period if e.event.kind == "policy_change"]

    # supervision: holds → approvals → grants → consumed
    holds: dict[str, dict[str, Any]] = {}
    for e in in_period:
        ev = e.event
        if not ev.hold_id:
            continue
        h = holds.setdefault(ev.hold_id, {"hold_id": ev.hold_id, "tool": ev.tool, "user": ev.user, "agent": ev.agent,
                                          "rule_id": ev.rule_id, "pack": ev.pack, "controls": list(e.controls),
                                          "opened_at": None, "approvals": [], "grant_id": None, "executed": False,
                                          "outcome": "pending", "resolution_s": None})
        if ev.kind == "hold_opened":
            h["opened_at"] = ev.at
            h["workflow"] = ev.payload.get("workflow")
            h["attest"] = ev.payload.get("attest")
        elif ev.kind == "approval":
            h["approvals"].append({"at": _iso(ev.at), "approver": ev.payload.get("approver"), "decision": ev.verdict,
                                   "attestation_accepted": ev.payload.get("attestation_accepted"),
                                   "rejected_because": ev.payload.get("rejected_because")})
            if ev.verdict == "reject":
                h["outcome"] = "rejected"
        elif ev.kind == "grant_issued":
            h["grant_id"] = ev.grant_id
            h["outcome"] = "approved"
            if h["opened_at"]:
                h["resolution_s"] = (ev.at - h["opened_at"]).total_seconds()
        elif ev.kind == "grant_consumed":
            h["executed"] = True
        elif ev.kind == "hold_expired":
            h["outcome"] = "expired"
    for h in holds.values():
        h["opened_at"] = _iso(h["opened_at"])

    resolved = [h["resolution_s"] for h in holds.values() if h["resolution_s"] is not None]
    unapproved_exec = [h for h in holds.values() if h["executed"] and h["outcome"] != "approved"]
    supervision = {
        "holds": len(holds),
        "approved": sum(1 for h in holds.values() if h["outcome"] == "approved"),
        "rejected": sum(1 for h in holds.values() if h["outcome"] == "rejected"),
        "expired": sum(1 for h in holds.values() if h["outcome"] == "expired"),
        "pending": sum(1 for h in holds.values() if h["outcome"] == "pending"),
        "executed_after_approval": sum(1 for h in holds.values() if h["executed"] and h["outcome"] == "approved"),
        "unapproved_executions": len(unapproved_exec),
        "median_resolution_s": statistics.median(resolved) if resolved else None,
        "p95_resolution_s": (sorted(resolved)[int(0.95 * (len(resolved) - 1))] if resolved else None),
        "invalid_approval_attempts": sum(1 for e in in_period if e.event.kind == "approval" and e.event.verdict == "invalid"),
        "detail": sorted(holds.values(), key=lambda h: h["opened_at"] or ""),
    }

    # decisions by rule / control
    decisions = [e for e in in_period if e.event.kind == "decision"]
    by_rule: dict[str, Counter[str]] = defaultdict(Counter)
    for e in decisions:
        by_rule[e.event.rule_id or "(no rule)"][e.event.verdict or "?"] += 1
    by_control: dict[str, Counter[str]] = defaultdict(Counter)
    for e in decisions:
        for c in e.controls:
            by_control[c][e.event.verdict or "?"] += 1
    denials = [{"at": _iso(e.event.at), "tool": e.event.tool, "user": e.event.user, "rule_id": e.event.rule_id,
                "controls": list(e.controls), "reason": e.event.payload.get("reason"),
                "args": e.event.payload.get("args")}
               for e in decisions if e.event.verdict == "deny"]
    no_override_blocks = [d for d in denials if d["reason"] and "no override" in d["reason"]]
    uncovered_calls = sorted({e.event.tool for e in decisions if e.event.payload.get("coverage_gap")})

    # coverage gaps: reachable tools with no rule + tools actually called with no rule
    gaps = list(uncovered_calls)
    if reachable_tools:
        from regent.core.match import Matcher
        gaps = sorted(set(gaps) | set(Matcher(packs).coverage_gaps(reachable_tools)))

    # trade blotter: order memoranda (204-2(a)(3)) reconstructed from allowed place_trade decisions
    blotter = []
    for e in decisions:
        ev = e.event
        if not (ev.tool or "").endswith(".place_trade") or ev.verdict != "allow":
            continue
        a = ev.payload.get("args") or {}
        terms = a.get("order_terms") if isinstance(a.get("order_terms"), dict) else {}
        blotter.append({"at": _iso(ev.at), "call_id": ev.payload.get("call_id"), "account": a.get("account"),
                        "security_id": a.get("security_id") or a.get("symbol"), "side": terms.get("side") or a.get("side"),
                        "quantity": terms.get("quantity") or a.get("quantity"), "order_type": terms.get("order_type"),
                        "limit_price": terms.get("limit_price"), "tif": terms.get("tif"), "notional_usd": a.get("notional_usd"),
                        "discretionary": a.get("discretionary"), "client_instruction_id": a.get("client_instruction_id"),
                        "recommended_by": a.get("recommended_by"), "placed_by": a.get("placed_by") or f"{ev.agent} on behalf of {ev.user}",
                        "executing_broker": a.get("executing_broker"), "capacity": a.get("capacity", "agency"),
                        "rule_id": ev.rule_id, "grant_id": ev.grant_id})
    memo_fields = ("discretionary", "recommended_by", "placed_by", "executing_broker", "side", "quantity")
    incomplete = [b["call_id"] for b in blotter if any(b.get(f) is None for f in memo_fields)]

    # examiner request-list index (what the SEC asks for on day one), from the pack
    request_index = []
    for p in packs:
        for item in p.exam_requests:
            rids = list(item.get("answered_by", []))
            act = Counter()
            for rid in rids:
                act.update(by_rule.get(rid, {}))
            request_index.append({"item": item.get("item"), "pack": p.name, "answered_by": rids,
                                  "evidence_sections": list(item.get("evidence_sections", [])), "activity": dict(act)})

    # examiner Q&A index
    qa = []
    for p in packs:
        for r in p.rules:
            qa.append({"question": r.examiner_asks, "answered_by": r.id, "pack": p.name, "controls": list(r.controls),
                       "activity": dict(by_rule.get(r.id, {}))})

    return {
        "regent_evidence_version": "0.1",
        "firm": firm,
        "generated_at": datetime.now().astimezone().isoformat(),
        "period": {"start": _iso(period_start), "end": _iso(period_end)},
        "chain_integrity": integrity.to_dict(),
        "totals": {"entries_in_period": len(in_period), "decisions": len(decisions),
                   "allowed": sum(1 for e in decisions if e.event.verdict == "allow"),
                   "denied": len(denials), "held": sum(1 for e in decisions if e.event.verdict == "hold")},
        "policies_in_force": policies,
        "policy_changes": policy_changes,
        "supervision": supervision,
        "data_protection": {"denials": len(denials), "no_override_blocks": len(no_override_blocks),
                            "overrides_possible_by_design": 0, "detail": denials},
        "activity_by_rule": {k: dict(v) for k, v in by_rule.items()},
        "activity_by_control": {k: dict(v) for k, v in by_control.items()},
        "coverage_gaps": gaps,
        "examiner_index": qa,
        "trade_blotter": {"orders": blotter, "incomplete_memoranda": incomplete},
        "exam_request_index": request_index,
        "firm_overlay": {p.name: p.firm for p in packs if p.firm},
    }


def _fmt_s(s: float | None) -> str:
    if s is None:
        return "n/a"
    m, sec = divmod(int(s), 60)
    return f"{m} m {sec:02d} s"


def render_markdown(ev: dict[str, Any]) -> str:
    L: list[str] = []
    p = ev["period"]
    L.append(f"# Compliance evidence package{(' — ' + ev['firm']) if ev['firm'] else ''}")
    L.append(f"Period {p['start']} → {p['end']} · generated {ev['generated_at']} · Regent evidence v{ev['regent_evidence_version']}\n")
    ci = ev["chain_integrity"]
    L.append("## 1. Audit chain integrity")
    L.append(f"- Entries verified: {ci['entries']} · **{'INTACT' if ci['ok'] else 'BROKEN at seq ' + str(ci['first_bad_seq']) + ': ' + str(ci['reason'])}**")
    if ci.get("head_hash"):
        L.append(f"- Head hash: `{ci['head_hash']}`")
    L.append("")
    L.append("## 2. Policies in force")
    for pk in ev["policies_in_force"]:
        L.append(f"### {pk['pack']} (v{pk['version']}) · source sha256 `{(pk['source_hash'] or '')[:16]}…`")
        L.append("| Rule | Tool | Controls | Workflow | Examiner asks |")
        L.append("|---|---|---|---|---|")
        for r in pk["rules"]:
            wf = "no override" if r["no_override"] else (r["workflow"] or "—")
            L.append(f"| {r['id']} | `{r['tool']}` | {', '.join(r['controls'])} | {wf} | {r['examiner_asks']} |")
        L.append("")
    if ev["policy_changes"]:
        L.append("Policy changes in period:")
        for c in ev["policy_changes"]:
            L.append(f"- {c['at']} · {c['pack']} v{c.get('version')} · by {c.get('actor')} · rules {', '.join(c.get('rules', []))}")
        L.append("")
    s = ev["supervision"]
    L.append("## 3. Supervision evidence (holds and approvals)")
    L.append(f"- Holds opened: **{s['holds']}** · approved {s['approved']} · rejected {s['rejected']} · expired {s['expired']} · pending {s['pending']}")
    L.append(f"- Executed after approval: {s['executed_after_approval']} · **Unapproved executions: {s['unapproved_executions']}**")
    L.append(f"- Median time to approval: {_fmt_s(s['median_resolution_s'])} · p95 {_fmt_s(s['p95_resolution_s'])}")
    L.append(f"- Invalid approval attempts blocked (SoD / duplicate / no attestation): {s['invalid_approval_attempts']}")
    if s["detail"]:
        L.append("")
        L.append("| Opened | Hold | Tool | Requester | Rule | Workflow | Approvers (attested) | Outcome | Executed |")
        L.append("|---|---|---|---|---|---|---|---|---|")
        for h in s["detail"]:
            appr = "; ".join(f"{a['approver']} ({'yes' if a['attestation_accepted'] else 'no'})"
                             for a in h["approvals"] if a["decision"] == "approve")
            L.append(f"| {h['opened_at']} | {h['hold_id']} | `{h['tool']}` | {h['user']} | {h['rule_id']} | {h.get('workflow')} | {appr or '—'} | {h['outcome']} | {'yes' if h['executed'] else 'no'} |")
    L.append("")
    d = ev["data_protection"]
    L.append("## 4. Denials and data-protection evidence")
    L.append(f"- Denials: **{d['denials']}** · of which non-overridable by design: {d['no_override_blocks']} · overrides possible: {d['overrides_possible_by_design']}")
    if d["detail"]:
        L.append("")
        L.append("| At | Tool | User | Rule | Controls | Reason |")
        L.append("|---|---|---|---|---|---|")
        for x in d["detail"]:
            L.append(f"| {x['at']} | `{x['tool']}` | {x['user']} | {x['rule_id'] or '—'} | {', '.join(x['controls'])} | {x['reason']} |")
    L.append("")
    L.append("## 5. Activity by control")
    L.append("| Control | allow | deny | hold |")
    L.append("|---|---|---|---|")
    for c, v in sorted(ev["activity_by_control"].items()):
        L.append(f"| {c} | {v.get('allow', 0)} | {v.get('deny', 0)} | {v.get('hold', 0)} |")
    L.append("")
    L.append("## 6. Coverage gaps")
    if ev["coverage_gaps"]:
        L.append("Tools reachable or called with **no governing rule** (deny-by-default applied, but this is the finding an examiner would write):")
        for g in ev["coverage_gaps"]:
            L.append(f"- `{g}`")
    else:
        L.append("None. Every reachable tool is governed by a rule.")
    L.append("")
    L.append("## 7. Examiner questions answered by rule")
    L.append("| Examiner asks | Answered by | Controls | Activity in period |")
    L.append("|---|---|---|---|")
    for q in ev["examiner_index"]:
        act = ", ".join(f"{k} {v}" for k, v in q["activity"].items()) or "none"
        L.append(f"| {q['question']} | {q['answered_by']} | {', '.join(q['controls'])} | {act} |")
    L.append("")
    tb = ev["trade_blotter"]
    L.append("## 8. Trade blotter — order memoranda (Rule 204-2(a)(3))")
    L.append(f"- Orders executed through the agent in period: **{len(tb['orders'])}** · memoranda missing a required field: **{len(tb['incomplete_memoranda'])}**")
    if tb["orders"]:
        L.append("")
        L.append("| Date of entry | Account | Security | Side | Qty | Type | Notional | Discretionary | Recommended by | Placed by | Executing broker | Capacity | Rule |")
        L.append("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
        for b in tb["orders"]:
            L.append(f"| {b['at']} | {b['account']} | {b['security_id']} | {b['side']} | {b['quantity']} | {b['order_type'] or '—'}"
                     f"{(' @ ' + str(b['limit_price'])) if b['limit_price'] else ''} | {b['notional_usd']} | "
                     f"{'yes' if b['discretionary'] else ('no · instr ' + str(b['client_instruction_id'])) if b['client_instruction_id'] else 'no'} | "
                     f"{b['recommended_by']} | {b['placed_by']} | {b['executing_broker']} | {b['capacity']} | {b['rule_id']} |")
    L.append("")
    if ev["exam_request_index"]:
        L.append("## 9. Examination request-list index")
        L.append("Typical day-one document requests, and where in this package each is answered.")
        L.append("")
        L.append("| Request | Answered by rules | Sections | Activity in period |")
        L.append("|---|---|---|---|")
        for r in ev["exam_request_index"]:
            act = ", ".join(f"{k} {v}" for k, v in r["activity"].items()) or "none"
            L.append(f"| {r['item']} | {', '.join(r['answered_by'])} | {'; '.join(r['evidence_sections'])} | {act} |")
        L.append("")
    if ev.get("firm_overlay"):
        L.append("## 10. Firm parameters in force")
        for pk, firm in ev["firm_overlay"].items():
            L.append(f"`{pk}`: " + ", ".join(f"{k} = {v}" for k, v in firm.items()))
        L.append("")
    return "\n".join(L)
