# RIA pack v0.1 — simulated CCO review

**Reviewer stance:** written as the Chief Compliance Officer of a ~$1.5B AUM,
40-person SEC-registered adviser (not dual-registered), who has sat through two
SEC exams and is being asked whether this pack could become part of the firm's
written policies under Rule 206(4)-7.

**Disclaimer:** this is a model-generated review with citations checked against
the current CFR text and the SEC's 2026 examination priorities. It is not a
licensed practitioner's review and does not replace one. It removes the errors
a real CCO would find in the first ten minutes, so that the real CCO's hour
goes to judgment calls rather than corrections.

**Verdict:** the structure is right and unusual — rules that cite the CFR and
state the exam question are exactly how I'd want an AI control documented.
But three rules encode a misreading of the regulation, the trade threshold
would make the product unusable at any real firm, the ledger does not yet
capture the fields Rule 204-2(a)(3) requires for an order memorandum, and the
two biggest exam-risk areas for agent trading (discretionary authority and
restricted lists) are missing. Not adoptable as v0.1; adoptable as v0.2 with
the changes below.

---

## 1. Rule-by-rule

### RIA-TRD-001 · agent trades — **REWRITE**

**Problem 1 — the threshold.** A $5,000 hold with four-eyes approval per trade
is unworkable. A rebalance across 300 households generates 2,000+ orders, most
above $5,000. Nobody supervises trades one-by-one; supervision is by exception
and by blotter review. A CCO reading this would conclude the author has never
seen a trade blotter.

**Problem 2 — wrong trigger.** Notional size is not what an examiner cares
about. The exam questions are: was the adviser authorised to trade this
account (discretionary vs non-discretionary)? Was the trade within the client's
mandate (IPS, model, restrictions)? Was the security on a restricted list? Was
the allocation fair across accounts? Was best execution considered?

**Rewrite as exception-based holds:**

```yaml
- id: RIA-TRD-001
  tool: custodian.place_trade
  deny_if: not args.discretionary and not has(args.client_instruction_id)
      # non-discretionary account, no documented client instruction → never
  no_override_deny: true
  hold_if: >
      args.security_id in firm.restricted_list
      or args.model_deviation_pct > firm.model_tolerance_pct
      or args.post_trade_concentration_pct > firm.concentration_limit_pct
      or args.account in firm.accounts_with_pending_withdrawal
      or args.is_first_trade_in_account
      or args.notional_usd > firm.large_trade_threshold      # firm sets; $250k–$1M typical
  approval:
    workflow: single            # four-eyes is overkill for a trade exception; keep for money movement
    approvers: [role:trading_supervisor, role:cco]
    grant_ttl: 10m
    sla: 30m                    # a 4h hold on a market order is a trade error waiting to happen
    on_sla_expiry: cancel_and_log_trade_error
  controls: [SEC-206(4)-7, SEC-204-2(a)(3), SEC-204A(insider), FIDUCIARY-2019-INTERP]
  examiner_asks: >
      How does the firm ensure agent-initiated orders are placed only in accounts
      where it has discretionary authority, within each client's mandate, and not
      in restricted securities — and where is the order memorandum for each?
```

**Problem 3 — options gate.** `principal.options_approved` is an attribute of
the client account, not the adviser principal. Move to `args.account_options_level`.

**Problem 4 — role name.** "Supervising principal" is a broker-dealer term
(Series 24). At an RIA it's "trading supervisor", "CIO", or "CCO".

### RIA-TRD-002 · principal / agency-cross — **KEEP, refine**

Correct in substance. Two refinements: (a) agency-cross transactions have their
own rule, 206(3)-2, which permits blanket prospective consent plus per-trade
written confirmation — so `client_consent_id` for an agency cross may be a
standing consent, and the rule should require the post-trade confirmation
record instead; (b) for a pure RIA that never trades as principal, this rule
will fire zero times — fine, but say so in the description so an examiner
doesn't read it as evidence of principal trading. Add control
`SEC-206(3)-2`.

### RIA-ETH-003 · access-person trades — **FIX the citation claim**

Rule 204A-1 **requires** pre-clearance only for IPOs and limited offerings
(204A-1(c)). General pre-clearance of personal trades is a firm-policy choice,
which most firms make. The description "need code-of-ethics pre-clearance"
overstates the rule; write "pre-clearance as required by the firm's Code of
Ethics; 204A-1(c) mandates it for IPOs and limited offerings". Also: an agent
that trades in an access person's account is itself an oddity a CCO would ask
about — most firms would simply `deny` here and route personal trades through
the Code of Ethics system, not through the client-trading agent. Recommend
`deny_if: true, no_override: true` as the default and let a firm relax it.

### RIA-CUS-004 · money movement — **FIX, tier it**

`hold_if: "true"` with four-eyes CCO approval on every transfer means the CCO
approves every client's monthly distribution. Tier it:

- **First-party, like-titled journal/ACH at the same custodian** (client to
  their own account): allow with an ops-principal single approval or none;
  these are custody-free per the 2017 IAA no-action letter.
- **First-party wire to another institution**: hold, single approval; the
  destination must match the client's original written authorisation.
- **Third-party**: hold, four-eyes, and the SLOA must satisfy all **seven**
  no-action conditions — the attestation should name them (client-signed
  instruction naming the third party; adviser cannot change payee details;
  custodian verifies and notifies; client can revoke; adviser records that
  payee is not a related party; custodian sends initial and annual notices).
  If any condition fails the firm has custody and owes a surprise exam — that is
  the exam question, so put it in `examiner_asks`.
- **Any transfer where payee/instructions changed in the last 30 days**: hold
  regardless — that is the Reg S-ID red flag (17 CFR 248.201, Appendix A) and
  the #1 wire-fraud pattern.

Add control `IAA-SLOA-NAL-2017`.

### RIA-DAT-005 · NPI in email — **FIX, over-broad**

Blocking `account_number` and `dob` unconditionally will block the firm from
sending a client their own statement or a form that needs their DOB. NPI to
the **account holder** over a **secure or encrypted channel** is normal
business. Rewrite: deny SSN always; deny account number / DOB when the
recipient is not a verified email of record for that account, or when the
channel is not the firm's secure-delivery method. Keep `no_override` for SSN
only. Add control `SEC-RegS-P-248.30(a)(2)` (service-provider/secure handling)
since the 2024 amendments are now in force for all advisers (Dec 3, 2025 for
larger, June 3, 2026 for smaller entities).

### RIA-COM-006 · marketing rule — **FIX, misreads the definition**

Under 206(4)-1(e)(1), an advertisement is a communication **to more than one
person** that offers advisory services (or new services to current clients).
One-on-one communications are **excluded** unless they contain hypothetical
performance. So `args.audience == prospect` with a single recipient is *not*
an advertisement, and a multi-recipient market commentary to existing clients
that offers no service arguably isn't either. Rewrite triggers:

- hold if `len(args.to) > 1 and args.offers_services` (or contains
  performance/testimonial/third-party rating content), or
- hold if `contains_hypothetical_performance(args.body)` regardless of
  recipient count.

Also fix the controls text: 204-2(a)(11) after the 2020 amendment is "a copy
of each advertisement the adviser disseminates" — the "10+ persons" language
in the pack's `controls:` block describes the *old* rule and would be caught
by any CCO. Keep `SEC-204-2(a)(7)` (correspondence retention) as the control
for one-to-one client emails — that is the retention obligation that actually
covers them, and it is the one the SEC's off-channel-communications sweep
enforces.

### RIA-DAT-007 · bulk export — **KEEP**

Correct. Add: log destination and row count into the ledger entry so the
evidence package can answer "to where, and how many records" — Reg S-P's 2024
service-provider oversight provision (248.30(a)(5)) is where an examiner will
take this.

### RIA-REC-008 · agreements on approved templates — **KEEP, add ADV delivery**

Fine. Pair it with a missing rule: Rule 204-3 requires delivery of Form ADV
Part 2 (and Part 3/CRS for retail) at or before signing. Add
`hold_if: not has(args.adv_delivery_receipt_id)` on the same tool.

### RIA-REC-009 / -010 · no deletes, no voids — **KEEP**

Exactly right and the kind of control an examiner likes. One nuance: voiding
an *unsent* draft envelope is not a record change; scope -010 to envelopes with
status `sent` or `completed`.

---

## 2. Missing rules, ranked by how likely an examiner asks

| # | Gap | Why it matters | Sketch |
|---|---|---|---|
| M1 | **Discretionary authority** | Trading a non-discretionary account without instruction is a §206 fiduciary breach and a top deficiency. An *agent* doing it is the headline case. | In TRD-001 rewrite above |
| M2 | **Restricted / watch list** | §204A requires policies against misuse of MNPI; the restricted list is how firms evidence it | `hold_if args.security_id in firm.restricted_list` |
| M3 | **Aggregation & allocation fairness** | Block trades allocated after the fact favouring some accounts is a classic enforcement case | `custodian.allocate_block`: deny if allocation deviates from pre-trade allocation memo without approval |
| M4 | **Best execution** | 2026 priorities name it; an agent that always routes to one venue needs a documented reason | quarterly evidence item, not a per-trade rule: ledger must capture venue |
| M5 | **Fee billing** | Fee-calculation errors are the most common exam finding; fee deduction is custody | `custodian.debit_fee`: hold if fee differs from schedule by >X bps or from prior period by >Y% |
| M6 | **Form ADV / CRS delivery** | 204-3; retail advisers | With REC-008 |
| M7 | **Agent communications retention** | 204-2(a)(7) plus the off-channel sweep; every `email.send` and any chat the agent uses must be captured | `allow_if args.archived == true` on all outbound comms tools |
| M8 | **Reg S-P incident response** | 2024 amendments require an incident response program and 30-day customer notice; agents touching breach data need a hold | `*.notify_customers`, `*.access_incident_data`: hold to CCO/CISO |
| M9 | **AI use consistent with disclosures** | 2026 priorities: controls must match what the ADV says about AI. Not a tool rule — an evidence item: pack version vs ADV text | Evidence §2 should print the ADV Item 8 excerpt the firm supplied |
| M10 | **Political contributions (206(4)-5)** | Only if an agent touches payments/expense tools | `payments.*` to government-affiliated payees: hold |

## 3. Data the ledger must capture (204-2(a)(3))

The order memorandum must show: terms and conditions; who recommended; who
placed; account; date of entry; executing broker/dealer; **whether the order
was discretionary**. The current `place_trade` args carry notional, account,
security_type, capacity. Add and require: `discretionary: bool`,
`recommended_by`, `placed_by` (the agent identity plus on-behalf-of user),
`executing_broker`, `order_terms` (side, qty, limit/market, TIF). Without
these the evidence package cannot substitute for a blotter, and the blotter is
the first thing an examiner asks for.

## 4. What the SEC actually asks for on day one

The initial document request list for an adviser exam typically includes:
compliance manual and annual review; Code of Ethics and access-person list;
trade blotter; allocation and best-execution reviews; custody records, SLOAs,
surprise-exam reports; advertising file; client agreements and ADV delivery
records; cybersecurity / Reg S-P program and incident log; vendor list;
business continuity plan; and — as of 2026 — policies on AI and automated
tools and evidence they operate as disclosed.

The evidence package already answers several of these. Map its sections to
this list explicitly (a "request list index"), and it becomes the artifact the
CCO hands over on day one. That is the sale.

## 5. Vocabulary and framing

- Drop FINRA 3110/4511 from a pure-RIA pack or gate them behind
  `firm.dual_registrant: true`; an SEC examiner will not ask, and their
  presence signals the pack was written generically.
- Replace "supervising principal" with RIA roles: `cco`, `trading_supervisor`,
  `operations_manager`, `ciso`, `marketing_reviewer`.
- Every hold needs an `on_sla_expiry` behaviour. For trades: cancel and log a
  trade error. For money movement: cancel and notify the client's adviser.
- Thresholds belong in a `firm:` overlay file, never in the pack; the pack
  ships with *no* dollar defaults and the lint fails if the overlay is missing.

## 6. Priority list for v0.2

1. Rewrite TRD-001 as exception-based; add discretionary-authority deny (M1) and restricted list (M2).
2. Tier CUS-004 (first-party / wire / third-party) and encode the seven SLOA conditions.
3. Fix COM-006 to the actual advertisement definition; fix the 204-2(a)(11) control text.
4. Narrow DAT-005 to recipient-of-record and channel.
5. Add required order-memorandum fields to the `place_trade` schema and ledger.
6. Add M5 fee billing and M7 communications retention.
7. Move thresholds to a firm overlay; add `on_sla_expiry`.
8. Add the exam request-list index to the evidence package.

Estimated effort: 3–4 days of pack and schema work, plus the evidence index.
After this, a real CCO's review becomes a judgment review — which items to
tighten for their firm — rather than a correction exercise.

## Sources checked

17 CFR 275.204-2 (LII, current text) · 17 CFR 275.206(4)-1 (eCFR) · SEC IA-5653
Marketing Rule adopting release · IAA SLOA no-action letter (Feb 21, 2017) and
Kitces / Core Compliance summaries · Reg S-P 2024 amendments and compliance
dates (Proskauer, Sidley, Holland & Knight) · SEC Division of Examinations 2026
priorities (Dorsey, Goodwin, Plante Moran summaries).
