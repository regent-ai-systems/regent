# Writing packs

A pack is YAML a compliance officer can read and Regent can compile. One file or a directory of files sharing a `pack:` name.

```yaml
pack: ria/v1                 # <vertical>/<major>
version: "0.1.0"
description: …
controls:                    # control id → citation (shown in evidence)
  SEC-206(4)-7: "Advisers Act Rule 206(4)-7 — … (17 CFR 275.206(4)-7)"
rules:
  - id: RIA-TRD-001          # stable, never reused
    tool: custodian.place_trade      # <target>.<tool>; globs allowed: custodian.*, *.delete*
    priority: 50             # lower evaluates first among rules with equally specific tool patterns (default 100)
    allow_if: …
    hold_if: …
    deny_if: …
    no_override: true        # deny-only rules with no approval path, ever
    approval:
      workflow: single | four_eyes
      approvers: [role:trading_supervisor, user:maria, any]
      attest: "text the approver must accept"
      grant_ttl: 10m
      sla: 4h
      sod: true              # requester may not approve own hold (default true)
      on_sla_expiry: cancel_and_log_trade_error   # recorded on the chain when nobody answers
    controls: [SEC-206(4)-7]           # required
    examiner_asks: "…?"                # required
firm_overlay_required: [large_trade_threshold_usd]   # keys the overlay must supply even if no rule references them yet
exam_requests:                          # examiner request-list index, printed as evidence §9
  - item: "Trade blotter / order memoranda (204-2(a)(3))"
    answered_by: [RIA-REC-019, RIA-TRD-001]
    evidence_sections: ["8. Trade blotter"]
```

### Firm overlay

Thresholds, lists and flags never live in a pack. Rules reference `firm.<key>`; the values come from a YAML overlay with a top-level `firm:` mapping — `firm.yaml` beside the pack (git-ignored), or `--firm-overlay <file>`. The loader (and `regent lint`) refuse to run when any referenced or `firm_overlay_required` key is missing. Compilers inline the overlay values as constants, so the emitted CEL/Cedar/Rego is deployment-specific. Overlay values are printed in evidence §10 so the examiner sees the parameters that were in force.

## Evaluation

For a call, candidates are all rules whose `tool` pattern matches, ordered by pattern specificity (more literal characters first), then `priority`, then pack order, then file order. For each candidate, in order:

1. `deny_if` true → **deny** (stop)
2. `hold_if` true → **hold** (stop; or **allow** if a valid grant exists for this exact call)
3. `allow_if` present: true → **allow**; false → **deny** (stop)
4. no `allow_if`: fall through to the next candidate

If nothing decided: **allow** if some candidate was a hold-only rule whose threshold was not met (e.g. a trade below the hold amount), else **deny** (no rule → deny by default).

Consequences worth knowing: a deny-only rule (`RIA-REC-009`) never allows anything by itself; a rule with `allow_if` is the last word for its tool, so give deny-only rules a lower `priority` number so they run first.

## Expression language

A small subset of Python expression syntax, parsed and evaluated with a whitelist (no attribute access except on `args` / `principal` / `call`, no calls except the helpers, no comprehensions, no private names).

| Namespace | Meaning |
|---|---|
| `args.<name>` | tool-call argument; missing → `None` (numeric comparisons treat it as −∞; use `has(args.x)` to be strict) |
| `principal.user`, `.agent`, `.roles`, `.<claim>` | identity; claims come from the JWT the gateway validated |
| `firm.<key>` | the firm overlay (constants per deployment) |
| `call.tool`, `call.session_id` | the call itself |
| bare identifier | a string literal, so `args.side in [buy, sell]` reads naturally |

Helpers: `contains_pii(text, [ssn, account_number, credit_card, routing_number, dob, email, phone, npi, mrn])`, `contains_hypothetical_performance(text)`, `has(x)`, `len`, `lower`, `upper`, `startswith`, `endswith`, `matches(text, regex)`, `any_in(list, list)`, `hour_utc()`, `weekday_utc()`, `abs`, `min`, `max`, `str`, `int`, `float`. Operators: `and or not in`, comparisons, `+ - * / %`, `x if c else y`.

## What compiles where

| Rule shape | agentgateway CEL | Cedar (AGT) | Rego (OPA) |
|---|---|---|---|
| tool + `principal.*` only, no hold | native | native | native |
| references `args` | tool-level allow; **PDS decides** (gateway cannot see arguments at authz time) | native (`context.args`) | native (`input.args`) |
| `hold_if` / approval | PDS | `permit … when context.grant == true` for the retry; PDS opens the hold | `hold[...]`/`allow[...]` with `input.grant`; PDS opens the hold |
| `contains_pii()` | PDS | PDS | `regent_pii()` helper emitted |
| glob tools | `matches()` | needs an Action group (PDS meanwhile) | `glob.match` |

`regent compile` prints which rules went native and which are routed to the PDS, with the reason.

## Testing a pack

```bash
regent lint packs/mine
regent decide custodian.place_trade --pack packs/mine --args '{"notional_usd": 9000, "account": "A1"}' \
    --claim assigned_accounts='["A1"]' --role trader
```

Add a truth table to `tests/` like `tests/test_match.py::RIA_TABLE` — the rows are the CCO's acceptance criteria.

## Conventions

* Rule id: `<PACK>-<AREA>-<nnn>`; areas so far: TRD trading, CUS custody, DAT data protection, COM communications, REC records, ETH code of ethics, FS/GH for dev tools.
* One control id per regulation paragraph, cited to the CFR/rule text, never to a blog.
* `examiner_asks` is the question as the examiner would put it in a document request letter. If you cannot write that sentence, the rule does not belong in the pack.
* Thresholds (dollar amounts, percentages, day counts) are `firm.*` keys; a test fails if a rule expression carries a numeric literal above 1.
* Areas so far in the RIA pack: TRD trading, ETH code of ethics, REC records, FEE billing, CUS custody/money movement, DAT data protection, COM communications.
