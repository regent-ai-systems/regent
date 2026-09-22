"""Expression language + deterministic matching. The RIA truth table lives here."""
from __future__ import annotations

import pytest

from regent.core.match import ExpressionError, Matcher, compile_expression, contains_pii, expression_uses_args


@pytest.mark.parametrize("text,kinds,expected", [
    ("SSN 123-45-6789", ["ssn"], True),
    ("SSN 123456789", ["ssn"], True),
    ("acct 12345678", ["account_number"], True),
    ("order 12345678", ["account_number"], False),
    ("card 4111 1111 1111 1111", ["credit_card"], True),   # Luhn-valid
    ("card 4111 1111 1111 1112", ["credit_card"], False),  # Luhn-invalid
    ("nothing here", None, False),
    (None, None, False),
])
def test_contains_pii(text, kinds, expected):
    assert contains_pii(text, kinds) is expected


def test_expression_rejects_unsafe():
    for bad in ["__import__('os')", "args.__class__", "open('x')", "lambda: 1", "[x for x in args]", "foo.bar"]:
        with pytest.raises(ExpressionError):
            compile_expression(bad)


def test_bare_identifiers_are_strings(mk):
    e = compile_expression("args.kind in [alpha, beta]")
    assert e.eval(mk("t.x", {"kind": "beta"}))
    assert not e.eval(mk("t.x", {"kind": "gamma"}))


def test_missing_args_and_claims(mk):
    assert not compile_expression("args.n > 5").eval(mk("t.x", {}))
    assert compile_expression("args.n <= 5").eval(mk("t.x", {}))  # -inf <= 5; use has() to be strict
    assert not compile_expression("has(args.n)").eval(mk("t.x", {}))
    assert compile_expression("not principal.nope").eval(mk("t.x", {}))


def test_firm_namespace_and_hypothetical_helper(mk):
    e = compile_expression("args.n > firm.limit or args.sec in firm.restricted")
    firm = {"limit": 10, "restricted": ["X"]}
    assert e.eval(mk("t.x", {"n": 11}), firm) and e.eval(mk("t.x", {"n": 1, "sec": "X"}), firm)
    assert not e.eval(mk("t.x", {"n": 1, "sec": "Y"}), firm)
    assert e.firm_keys == ("limit", "restricted")
    from regent.core.match import contains_hypothetical_performance as chp
    assert chp("our back-tested strategy") and chp("Projected returns of 8%") and not chp("quarterly review is Tuesday")


def test_uses_args():
    assert expression_uses_args("args.x > 1")
    assert not expression_uses_args("principal.roles")


from tests.conftest import EMAIL, TRADE  # noqa: E402

T = TRADE
XFER = {"account": "A1", "amount_usd": 5000, "destination": "X"}

RIA_TABLE = [
    # trading — routine flows, exceptions hold, breaches deny
    ("custodian.place_trade", T, "allow", "RIA-TRD-001"),
    ("custodian.place_trade", {**T, "notional_usd": 300000}, "hold", "RIA-TRD-001"),                      # firm.large_trade_threshold_usd
    ("custodian.place_trade", {**T, "security_id": "ACME"}, "hold", "RIA-TRD-001"),                       # restricted list
    ("custodian.place_trade", {**T, "model_deviation_pct": 7.5}, "hold", "RIA-TRD-001"),                  # > model_tolerance_pct 5
    ("custodian.place_trade", {**T, "post_trade_concentration_pct": 12}, "hold", "RIA-TRD-001"),         # > concentration_limit_pct 10
    ("custodian.place_trade", {**T, "account": "ACC-7001"}, "deny", "RIA-TRD-001"),                       # pending withdrawal but not assigned → deny
    ("custodian.place_trade", {**T, "is_first_trade_in_account": True}, "hold", "RIA-TRD-001"),
    ("custodian.place_trade", {**T, "account": "ZZ"}, "deny", "RIA-TRD-001"),                             # not an assigned account
    ("custodian.place_trade", {**T, "security_type": "options"}, "deny", "RIA-TRD-012"),
    ("custodian.place_trade", {**T, "security_type": "options", "account_options_approved": True}, "allow", "RIA-TRD-001"),
    ("custodian.place_trade", {**T, "capacity": "principal"}, "deny", "RIA-TRD-002"),
    ("custodian.place_trade", {**T, "capacity": "principal", "client_consent_id": "C1"}, "allow", "RIA-TRD-001"),
    ("custodian.place_trade", {**T, "capacity": "agency_cross"}, "deny", "RIA-TRD-002"),
    ("custodian.place_trade", {**T, "capacity": "agency_cross", "cross_confirmation_id": "X1"}, "allow", "RIA-TRD-001"),
    ("custodian.place_trade", {**T, "account_type": "employee"}, "deny", "RIA-ETH-003"),
    ("custodian.place_trade", {k: v for k, v in T.items() if k != "executing_broker"}, "deny", "RIA-REC-019"),  # incomplete memorandum
    # fee billing
    ("custodian.debit_fee", {"fee_bps": 100, "schedule_fee_bps": 100, "change_vs_prior_period_pct": 3}, "allow", "RIA-FEE-020"),
    ("custodian.debit_fee", {"fee_bps": 104, "schedule_fee_bps": 100, "change_vs_prior_period_pct": 3}, "hold", "RIA-FEE-020"),
    ("custodian.debit_fee", {"fee_bps": 100, "schedule_fee_bps": 100, "change_vs_prior_period_pct": -40}, "hold", "RIA-FEE-020"),
    # money movement tiers
    ("custodian.transfer_funds", {**XFER, "destination_type": "first_party", "transfer_type": "journal", "like_titled": True}, "allow", "RIA-CUS-018"),
    ("custodian.transfer_funds", {**XFER, "destination_type": "first_party", "transfer_type": "ach", "like_titled": True}, "allow", "RIA-CUS-018"),
    ("custodian.transfer_funds", {**XFER, "destination_type": "first_party", "transfer_type": "ach", "like_titled": False}, "deny", "RIA-CUS-018"),
    ("custodian.transfer_funds", {**XFER, "destination_type": "first_party", "transfer_type": "wire"}, "hold", "RIA-CUS-017"),
    ("custodian.transfer_funds", {**XFER, "destination_type": "third_party", "transfer_type": "wire"}, "deny", "RIA-CUS-004"),
    ("custodian.transfer_funds", {**XFER, "destination_type": "third_party", "transfer_type": "wire", "sloa_id": "S1"}, "deny", "RIA-CUS-004"),
    ("custodian.transfer_funds", {**XFER, "destination_type": "third_party", "transfer_type": "wire", "sloa_id": "S1",
                                  "sloa_all_seven_conditions_met": True}, "hold", "RIA-CUS-016"),
    ("custodian.transfer_funds", {**XFER, "destination_type": "first_party", "transfer_type": "journal", "like_titled": True,
                                  "instructions_changed_days_ago": 3}, "hold", "RIA-CUS-015"),
    ("custodian.transfer_funds", {**XFER, "destination_type": "first_party", "transfer_type": "journal", "like_titled": True,
                                  "instructions_changed_days_ago": 90}, "allow", "RIA-CUS-018"),
    # email
    ("email.send", {**EMAIL, "body": "SSN 123-45-6789"}, "deny", "RIA-DAT-005"),
    ("email.send", EMAIL, "allow", "RIA-COM-006"),
    ("email.send", {**EMAIL, "archived": False}, "deny", "RIA-COM-013"),
    ("email.send", {**EMAIL, "audience": "prospect"}, "allow", "RIA-COM-006"),                            # one-on-one prospect: not an advertisement
    ("email.send", {**EMAIL, "audience": "prospect", "body": "Our hypothetical back-tested returns were 14%."}, "hold", "RIA-COM-006"),
    ("email.send", {**EMAIL, "to": ["a@x.com", "b@x.com"]}, "allow", "RIA-COM-006"),                      # market commentary, no offer
    ("email.send", {**EMAIL, "to": ["a@x.com", "b@x.com"], "offers_services": True}, "hold", "RIA-COM-006"),
    ("email.send", {**EMAIL, "to": ["a@x.com", "b@x.com"], "contains_testimonial": True}, "hold", "RIA-COM-006"),
    ("email.send", {**EMAIL, "body": "Your statement for account 12345678 is attached."}, "deny", "RIA-DAT-014"),
    ("email.send", {**EMAIL, "body": "Your statement for account 12345678 is attached.", "recipient_is_email_of_record": True,
                    "channel": "portal"}, "allow", "RIA-COM-006"),
    ("email.send", {**EMAIL, "body": "Your statement for account 12345678 is attached.", "recipient_is_email_of_record": True,
                    "channel": "smtp"}, "deny", "RIA-DAT-014"),
    # records
    ("crm.export", {"segment": "all"}, "hold", "RIA-DAT-007"),
    ("crm.delete_contact", {}, "deny", "RIA-REC-009"),
    ("esign.void_envelope", {"envelope_status": "sent"}, "deny", "RIA-REC-010"),
    ("esign.void_envelope", {"envelope_status": "completed"}, "deny", "RIA-REC-010"),
    ("esign.void_envelope", {"envelope_status": "draft"}, "allow", "RIA-REC-010"),
    ("esign.send_envelope", {"template_id": "T1", "adv_delivery_receipt_id": "ADV-1"}, "allow", "RIA-REC-008"),
    ("esign.send_envelope", {"template_id": "T1"}, "hold", "RIA-REC-008"),                                 # ADV not delivered
    ("esign.send_envelope", {"template_id": "T9", "adv_delivery_receipt_id": "ADV-1"}, "hold", "RIA-REC-008"),
    ("docusign.void", {}, None, None),
    ("custodian.get_positions", {}, None, None),
]


@pytest.mark.parametrize("tool,args,verdict,rule", RIA_TABLE)
def test_ria_truth_table(ria, mk, tool, args, verdict, rule):
    r = Matcher(ria).evaluate(mk(tool, args))
    if verdict is None:
        assert r is None
    else:
        assert r is not None and (r[0], r[2].id) == (verdict, rule)


# ---- CCO review §6 item 1: discretionary-authority deny (RIA-TRD-011) ------------------------------

class TestDiscretionaryDeny:
    def test_non_discretionary_without_instruction_is_denied_no_override(self, ria, mk):
        r = Matcher(ria).evaluate(mk("custodian.place_trade", {**T, "discretionary": False}))
        assert (r[0], r[2].id) == ("deny", "RIA-TRD-011") and r[2].no_override

    def test_non_discretionary_with_client_instruction_flows(self, ria, mk):
        r = Matcher(ria).evaluate(mk("custodian.place_trade", {**T, "discretionary": False, "client_instruction_id": "CI-42"}))
        assert (r[0], r[2].id) == ("allow", "RIA-TRD-001")

    def test_missing_discretionary_flag_is_denied(self, ria, mk):
        # no flag at all: TRD-011 sees not None → deny before the memorandum-completeness rule
        r = Matcher(ria).evaluate(mk("custodian.place_trade", {k: v for k, v in T.items() if k != "discretionary"}))
        assert (r[0], r[2].id) == ("deny", "RIA-TRD-011")

    def test_discretionary_deny_wins_over_every_other_trade_rule(self, ria, mk):
        # a non-discretionary large restricted-list trade denies on authority, never holds
        r = Matcher(ria).evaluate(mk("custodian.place_trade", {**T, "discretionary": False, "notional_usd": 9e6, "security_id": "ACME"}))
        assert (r[0], r[2].id) == ("deny", "RIA-TRD-011")

    async def test_engine_gives_no_hold_id_and_records_no_override(self, ria, mk):
        from regent.approvers.inbox import AutoApprover
        from regent.core.engine import Engine
        from regent.stores.memory import MemoryStore
        eng = Engine(ria, MemoryStore(), AutoApprover())
        d = await eng.decide(mk("custodian.place_trade", {**T, "discretionary": False}))
        assert d.verdict.value == "deny" and d.hold_id is None and "no override" in d.reason and d.rule_id == "RIA-TRD-011"


# ---- CCO review §6 item 2: tiered money-movement holds --------------------------------------------

class TestTieredTransferHolds:
    FP_JOURNAL = {**XFER, "destination_type": "first_party", "transfer_type": "journal", "like_titled": True}
    FP_WIRE = {**XFER, "destination_type": "first_party", "transfer_type": "wire"}
    TP_OK = {**XFER, "destination_type": "third_party", "transfer_type": "wire", "sloa_id": "S1", "sloa_all_seven_conditions_met": True}

    def test_like_titled_journal_is_custody_free_and_flows(self, ria, mk):
        r = Matcher(ria).evaluate(mk("custodian.transfer_funds", self.FP_JOURNAL))
        assert (r[0], r[2].id) == ("allow", "RIA-CUS-018")

    def test_first_party_wire_single_ops_approval(self, ria, mk):
        r = Matcher(ria).evaluate(mk("custodian.transfer_funds", self.FP_WIRE))
        assert (r[0], r[2].id) == ("hold", "RIA-CUS-017")
        assert r[2].approval.workflow == "single" and r[2].approval.approvers == ("role:operations_manager",)
        assert r[2].approval.on_sla_expiry == "cancel_and_notify_adviser"

    def test_third_party_with_sloa_is_four_eyes_with_seven_conditions_attested(self, ria, mk):
        r = Matcher(ria).evaluate(mk("custodian.transfer_funds", self.TP_OK))
        assert (r[0], r[2].id) == ("hold", "RIA-CUS-016")
        a = r[2].approval
        assert a.workflow == "four_eyes" and set(a.approvers) == {"role:operations_manager", "role:cco"}
        assert all(f"({i})" in a.attest for i in range(1, 8))

    @pytest.mark.parametrize("bad", [{}, {"sloa_id": "S1"}, {"sloa_all_seven_conditions_met": True}])
    def test_third_party_without_full_sloa_is_custody_and_denied(self, ria, mk, bad):
        args = {**XFER, "destination_type": "third_party", "transfer_type": "wire", **bad}
        r = Matcher(ria).evaluate(mk("custodian.transfer_funds", args))
        assert (r[0], r[2].id) == ("deny", "RIA-CUS-004") and r[2].no_override
        assert "IAA-SLOA-NAL-2017" in r[2].controls

    @pytest.mark.parametrize("base", [FP_JOURNAL, FP_WIRE, TP_OK])
    def test_recent_instruction_change_holds_every_tier(self, ria, mk, base):
        r = Matcher(ria).evaluate(mk("custodian.transfer_funds", {**base, "instructions_changed_days_ago": 10}))
        assert (r[0], r[2].id) == ("hold", "RIA-CUS-015") and "SEC-RegS-ID-248.201" in r[2].controls

    def test_lookback_comes_from_the_firm_overlay(self, ria, mk):
        assert ria[0].firm["instruction_change_lookback_days"] == 30
        r = Matcher(ria).evaluate(mk("custodian.transfer_funds", {**self.FP_JOURNAL, "instructions_changed_days_ago": 31}))
        assert (r[0], r[2].id) == ("allow", "RIA-CUS-018")

    def test_unclassified_transfer_is_denied(self, ria, mk):
        r = Matcher(ria).evaluate(mk("custodian.transfer_funds", {**XFER, "destination_type": "first_party", "transfer_type": "check"}))
        assert (r[0], r[2].id) == ("deny", "RIA-CUS-018")


# ---- CCO review §6 item 3: Marketing Rule — one-on-one prospect email is not an advertisement -------

class TestMarketingRuleDefinition:
    def test_one_on_one_prospect_email_is_allowed(self, ria, mk):
        r = Matcher(ria).evaluate(mk("email.send", {**EMAIL, "audience": "prospect", "offers_services": True}))
        assert (r[0], r[2].id) == ("allow", "RIA-COM-006")

    def test_one_on_one_with_hypothetical_performance_is_still_an_advertisement(self, ria, mk):
        r = Matcher(ria).evaluate(mk("email.send", {**EMAIL, "audience": "prospect",
                                                    "body": "Based on projected returns of 9% the plan reaches $2M."}))
        assert (r[0], r[2].id) == ("hold", "RIA-COM-006")

    def test_multi_recipient_offer_is_an_advertisement(self, ria, mk):
        r = Matcher(ria).evaluate(mk("email.send", {**EMAIL, "to": ["a@x.com", "b@x.com"], "offers_services": True}))
        assert (r[0], r[2].id) == ("hold", "RIA-COM-006") and "SEC-204-2(a)(11)" in r[2].controls

    def test_multi_recipient_commentary_without_offer_is_correspondence(self, ria, mk):
        r = Matcher(ria).evaluate(mk("email.send", {**EMAIL, "to": ["a@x.com", "b@x.com"]}))
        assert (r[0], r[2].id) == ("allow", "RIA-COM-006")

    def test_control_text_reflects_2020_amendment(self, ria):
        assert "10+" not in ria[0].controls["SEC-204-2(a)(11)"] and "each advertisement" in ria[0].controls["SEC-204-2(a)(11)"]


def test_dev_default_table(dev, mk):
    m = Matcher(dev)
    assert m.evaluate(mk("fs.read_file", {"path": "/tmp/a.txt"}))[0] == "allow"
    assert m.evaluate(mk("fs.read_file", {"path": "/tmp/a.env"}))[0] == "deny"
    assert m.evaluate(mk("fs.write_file", {"path": "/tmp/a.txt"}))[0] == "hold"
    assert m.evaluate(mk("fs.write_file", {"path": "/etc/passwd"}))[0] == "deny"
    assert m.evaluate(mk("github.get_issue", {}))[0] == "allow"
    assert m.evaluate(mk("github.push_files", {"branch": "main"}))[0] == "deny"
    assert m.evaluate(mk("github.push_files", {"branch": "feat"}))[0] == "hold"
    assert m.evaluate(mk("github.delete_branch", {}))[2].id == "DEV-GH-007"
    assert m.evaluate(mk("github.fork_repository", {})) is None
