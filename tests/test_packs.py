"""Pack contract: every rule cites a control and an examiner question; expressions parse; loader rejects bad packs."""
from __future__ import annotations

import pytest

from regent.core.match import compile_expression

from regent.core.packs import PackError, load_pack_text, load_packs


@pytest.mark.parametrize("fixture", ["ria", "dev"])
def test_every_rule_has_controls_and_examiner_question(request, fixture):
    for pack in request.getfixturevalue(fixture):
        assert pack.rules, pack.name
        for r in pack.rules:
            assert r.controls and all(c.strip() for c in r.controls), r.id
            assert r.examiner_asks.strip().endswith("?") or len(r.examiner_asks) > 20, r.id
            for expr in (r.allow_if, r.hold_if, r.deny_if):
                if expr:
                    compile_expression(expr)


def test_controls_cited_are_defined(ria):
    pack = ria[0]
    for r in pack.rules:
        for c in r.controls:
            assert c in pack.controls, f"{r.id} cites undefined control {c}"


def test_loader_rejects_missing_controls():
    with pytest.raises(PackError, match="controls"):
        load_pack_text("pack: x/v1\nrules:\n- id: X-1\n  tool: a.b\n  allow_if: 'true'\n  examiner_asks: 'why?'\n")


def test_loader_rejects_missing_examiner_question():
    with pytest.raises(PackError, match="examiner_asks"):
        load_pack_text("pack: x/v1\nrules:\n- id: X-1\n  tool: a.b\n  allow_if: 'true'\n  controls: [C1]\n")


def test_loader_rejects_hold_without_approval():
    with pytest.raises(PackError, match="approval"):
        load_pack_text("pack: x/v1\nrules:\n- id: X-1\n  tool: a.b\n  hold_if: 'true'\n  controls: [C1]\n  examiner_asks: 'q?'\n")


def test_loader_rejects_no_override_with_approval():
    with pytest.raises(PackError, match="no_override"):
        load_pack_text("pack: x/v1\nrules:\n- id: X-1\n  tool: a.b\n  hold_if: 'true'\n  no_override: true\n"
                       "  approval: {workflow: single, approvers: [any]}\n  controls: [C1]\n  examiner_asks: 'q?'\n")


def test_loader_rejects_bad_expression():
    with pytest.raises(PackError, match="allow_if"):
        load_pack_text("pack: x/v1\nrules:\n- id: X-1\n  tool: a.b\n  allow_if: '__import__(\"os\")'\n  controls: [C1]\n  examiner_asks: 'q?'\n")


def test_loader_rejects_duplicate_ids():
    y = ("pack: x/v1\nrules:\n- id: X-1\n  tool: a.b\n  allow_if: 'true'\n  controls: [C1]\n  examiner_asks: 'q?'\n"
         "- id: X-1\n  tool: a.c\n  allow_if: 'true'\n  controls: [C1]\n  examiner_asks: 'q?'\n")
    with pytest.raises(PackError, match="duplicate"):
        load_pack_text(y)


def test_source_hash_changes_with_content(ria):
    p1 = load_pack_text("pack: x/v1\nrules:\n- id: X-1\n  tool: a.b\n  allow_if: 'true'\n  controls: [C1]\n  examiner_asks: 'q?'\n")
    p2 = load_pack_text("pack: x/v1\nrules:\n- id: X-1\n  tool: a.b\n  allow_if: 'false'\n  controls: [C1]\n  examiner_asks: 'q?'\n")
    assert p1.source_hash != p2.source_hash


def test_ria_pack_refuses_to_load_without_firm_overlay():
    from tests.conftest import ROOT
    with pytest.raises(PackError, match="firm overlay missing keys"):
        load_packs([ROOT / "packs" / "ria"])


def test_ria_pack_declares_no_dollar_defaults(ria):
    """Thresholds belong in the firm overlay: no rule expression may carry a numeric literal above 1
    (percentages, dollar amounts, day counts all come from firm.*)."""
    import ast
    for r in ria[0].rules:
        for expr in (r.allow_if, r.hold_if, r.deny_if):
            if not expr:
                continue
            nums = [n.value for n in ast.walk(compile_expression(expr).tree)
                    if isinstance(n, ast.Constant) and isinstance(n.value, (int, float)) and not isinstance(n.value, bool)]
            assert all(v <= 1 for v in nums), f"{r.id}: literal threshold {nums} should be a firm.* key"


def test_ria_pack_is_v0_2_and_has_request_index(ria):
    assert ria[0].version == "0.2.0"
    assert len(ria[0].exam_requests) >= 10
    ids = {r.id for r in ria[0].rules}
    for item in ria[0].exam_requests:
        assert set(item["answered_by"]) <= ids, item


def test_ria_roles_are_ria_roles_not_broker_dealer(ria):
    roles = {a.split(":")[1] for r in ria[0].rules if r.approval for a in r.approval.approvers if a.startswith("role:")}
    assert "supervising_principal" not in roles
    assert roles <= {"cco", "trading_supervisor", "operations_manager", "ciso", "marketing_reviewer"}
    assert not any(c.startswith("FINRA") for r in ria[0].rules for c in r.controls)


def test_every_ria_hold_has_on_sla_expiry(ria):
    for r in ria[0].rules:
        if r.approval:
            assert r.approval.on_sla_expiry in {"cancel_and_log_trade_error", "cancel_and_notify_adviser", "notify_adviser", "deny_and_log"}, r.id
