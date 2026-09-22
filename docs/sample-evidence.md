# Compliance evidence package — Demo Capital Advisors LLC
Period 2026-06-20T22:41:34.068109+00:00 → 2026-09-18T22:41:35.068109+00:00 · generated 2026-09-18T17:41:34.070462-05:00 · Regent evidence v0.1

## 1. Audit chain integrity
- Entries verified: 35 · **INTACT**
- Head hash: `7edd2d2106315fd89088809b66461c21650e724f9a4f74c92c73a849f846ffb4`

## 2. Policies in force
### ria/v1 (v0.2.0) · source sha256 `b51f20b38e8400c3…`
| Rule | Tool | Controls | Workflow | Examiner asks |
|---|---|---|---|---|
| RIA-TRD-011 | `custodian.place_trade` | FIDUCIARY-2019-INTERP, SEC-206(4)-7, SEC-204-2(a)(3) | no override | How does the firm ensure agent-initiated orders are placed only in accounts where it holds discretionary authority or has a documented client instruction? |
| RIA-TRD-002 | `custodian.place_trade` | SEC-206(3), SEC-206(3)-2, SEC-204-2(a)(7) | no override | How do you prevent principal or agency-cross trades from being executed without the consent and confirmation records the rule requires? |
| RIA-ETH-003 | `custodian.place_trade` | SEC-204A-1, SEC-206(4)-7 | no override | Can the client-trading agent transact in access-person or proprietary accounts, and how are those trades pre-cleared and reported under the Code of Ethics? |
| RIA-TRD-012 | `custodian.place_trade` | SEC-206(4)-7, FIDUCIARY-2019-INTERP | — | How do you prevent options or margin transactions in accounts the client has not been approved for? |
| RIA-REC-019 | `custodian.place_trade` | SEC-204-2(a)(3), SEC-204-2(e) | — | Produce the order memorandum for each agent-initiated order, showing who recommended, who placed, the executing broker and whether the order was discretionary. |
| RIA-TRD-001 | `custodian.place_trade` | SEC-206(4)-7, SEC-204-2(a)(3), SEC-204A, FIDUCIARY-2019-INTERP | single | How are agent-initiated orders supervised for mandate, restricted-list and concentration exceptions, and where is the record of each exception review? |
| RIA-FEE-020 | `custodian.debit_fee` | SEC-206(4)-2, SEC-206(4)-7, SEC-204-2(a)(2) | single | How are advisory fees calculated and reconciled to client agreements before being deducted, and who reviews exceptions? |
| RIA-CUS-004 | `custodian.transfer_funds` | SEC-206(4)-2, IAA-SLOA-NAL-2017 | no override | For each third-party transfer an agent initiated, show the standing letter of authorization and that all seven no-action conditions were met — or the surprise examination that covers it. |
| RIA-CUS-015 | `custodian.transfer_funds` | SEC-RegS-ID-248.201, SEC-206(4)-2, SEC-204-2(a)(7) | four_eyes | What is your red-flags procedure for transfers where the payee or instructions changed recently, and how is call-back verification evidenced? |
| RIA-CUS-016 | `custodian.transfer_funds` | SEC-206(4)-2, IAA-SLOA-NAL-2017, SEC-RegS-ID-248.201 | four_eyes | How does the firm ensure each third-party disbursement stays within the SLOA no-action conditions, and who attests to that per transfer? |
| RIA-CUS-017 | `custodian.transfer_funds` | SEC-206(4)-2, SEC-204-2(a)(7) | single | How are first-party wires to outside institutions matched to the client's written authorization? |
| RIA-CUS-018 | `custodian.transfer_funds` | SEC-206(4)-2, IAA-SLOA-NAL-2017 | — | Which agent-initiated money movements does the firm treat as custody-free, and on what basis? |
| RIA-DAT-005 | `email.send` | SEC-RegS-P-248.30, GLBA-501(b) | no override | What prevents Social Security numbers from leaving the firm through automated channels, and can anyone override it? |
| RIA-DAT-014 | `email.send` | SEC-RegS-P-248.30(a)(2), GLBA-501(b) | — | Under what conditions may nonpublic personal information be sent by automated email, and how is the recipient verified against the account's email of record? |
| RIA-COM-013 | `email.send` | SEC-204-2(a)(7), SEC-204-2(e) | — | Are all agent-sent communications captured in the firm's books-and-records archive, and how would an unarchived message be prevented? |
| RIA-COM-006 | `email.send` | SEC-206(4)-1, SEC-204-2(a)(11), SEC-204-2(a)(7) | single | How does the firm identify which agent-drafted communications are advertisements under Rule 206(4)-1, and how are those reviewed and retained? |
| RIA-DAT-007 | `crm.export` | SEC-RegS-P-248.30, SEC-RegS-P-248.30(a)(5), GLBA-501(b) | single | Who authorised each bulk export of client data by automated systems, to which service provider, and how many records? |
| RIA-REC-008 | `esign.send_envelope` | SEC-204-2(a)(10), SEC-204-3, SEC-204-2(a)(14), SEC-206(4)-7 | single | How do you ensure agents send only approved client agreements with the brochure delivered, and where are executed copies and delivery records retained? |
| RIA-REC-009 | `*.delete*` | SEC-204-2(e) | no override | Can an automated agent delete or alter required records, and how would you know? |
| RIA-REC-010 | `esign.void_envelope` | SEC-204-2(e), SEC-204-2(a)(10) | — | Can an automated agent void executed or in-flight client agreements? |

Policy changes in period:
- 2026-09-18T22:41:22.251582+00:00 · ria/v1 v0.2.0 · by regent serve · rules RIA-TRD-011, RIA-TRD-002, RIA-ETH-003, RIA-TRD-012, RIA-REC-019, RIA-TRD-001, RIA-FEE-020, RIA-CUS-004, RIA-CUS-015, RIA-CUS-016, RIA-CUS-017, RIA-CUS-018, RIA-DAT-005, RIA-DAT-014, RIA-COM-013, RIA-COM-006, RIA-DAT-007, RIA-REC-008, RIA-REC-009, RIA-REC-010

## 3. Supervision evidence (holds and approvals)
- Holds opened: **7** · approved 1 · rejected 0 · expired 0 · pending 6
- Executed after approval: 1 · **Unapproved executions: 0**
- Median time to approval: 0 m 02 s · p95 0 m 02 s
- Invalid approval attempts blocked (SoD / duplicate / no attestation): 1

| Opened | Hold | Tool | Requester | Rule | Workflow | Approvers (attested) | Outcome | Executed |
|---|---|---|---|---|---|---|---|---|
| 2026-09-18T22:41:25.810516+00:00 | hold_47435e2ea12666b7 | `custodian.place_trade` | agent7 | RIA-TRD-001 | single | maria.cco (yes) | approved | yes |
| 2026-09-18T22:41:28.790845+00:00 | hold_7006ad0f75a05dc0 | `custodian.place_trade` | agent7 | RIA-TRD-001 | single | — | pending | no |
| 2026-09-18T22:41:28.794974+00:00 | hold_1ad2bf180a51f3a7 | `custodian.place_trade` | agent7 | RIA-TRD-001 | single | — | pending | no |
| 2026-09-18T22:41:28.825859+00:00 | hold_e358cbb0b28605e1 | `custodian.transfer_funds` | agent7 | RIA-CUS-017 | single | — | pending | no |
| 2026-09-18T22:41:28.830221+00:00 | hold_7a377c3a3d8a14f8 | `custodian.transfer_funds` | agent7 | RIA-CUS-016 | four_eyes | — | pending | no |
| 2026-09-18T22:41:28.838979+00:00 | hold_5a1409c0e601934e | `custodian.transfer_funds` | agent7 | RIA-CUS-015 | four_eyes | — | pending | no |
| 2026-09-18T22:41:28.860333+00:00 | hold_b273aa5671d26c52 | `email.send` | agent7 | RIA-COM-006 | single | — | pending | no |

## 4. Denials and data-protection evidence
- Denials: **10** · of which non-overridable by design: 5 · overrides possible: 0

| At | Tool | User | Rule | Controls | Reason |
|---|---|---|---|---|---|
| 2026-09-18T22:41:28.798917+00:00 | `custodian.place_trade` | agent7 | RIA-TRD-011 | FIDUCIARY-2019-INTERP, SEC-206(4)-7, SEC-204-2(a)(3) | RIA-TRD-011: deny_if matched (no override) |
| 2026-09-18T22:41:28.807888+00:00 | `custodian.place_trade` | agent7 | RIA-REC-019 | SEC-204-2(a)(3), SEC-204-2(e) | RIA-REC-019: deny_if matched |
| 2026-09-18T22:41:28.811076+00:00 | `custodian.place_trade` | agent7 | RIA-TRD-012 | SEC-206(4)-7, FIDUCIARY-2019-INTERP | RIA-TRD-012: deny_if matched |
| 2026-09-18T22:41:28.816239+00:00 | `custodian.place_trade` | agent7 | RIA-TRD-002 | SEC-206(3), SEC-206(3)-2, SEC-204-2(a)(7) | RIA-TRD-002: deny_if matched (no override) |
| 2026-09-18T22:41:28.835335+00:00 | `custodian.transfer_funds` | agent7 | RIA-CUS-004 | SEC-206(4)-2, IAA-SLOA-NAL-2017 | RIA-CUS-004: deny_if matched (no override) |
| 2026-09-18T22:41:28.843413+00:00 | `email.send` | agent7 | RIA-DAT-005 | SEC-RegS-P-248.30, GLBA-501(b) | RIA-DAT-005: deny_if matched (no override) |
| 2026-09-18T22:41:28.865131+00:00 | `email.send` | agent7 | RIA-DAT-014 | SEC-RegS-P-248.30(a)(2), GLBA-501(b) | RIA-DAT-014: deny_if matched |
| 2026-09-18T22:41:28.868662+00:00 | `email.send` | agent7 | RIA-COM-013 | SEC-204-2(a)(7), SEC-204-2(e) | RIA-COM-013: deny_if matched |
| 2026-09-18T22:41:28.871964+00:00 | `crm.delete_contact` | agent7 | RIA-REC-009 | SEC-204-2(e) | RIA-REC-009: deny_if matched (no override) |
| 2026-09-18T22:41:28.875890+00:00 | `custodian.get_positions` | agent7 | — |  | no rule governs this tool (deny by default) |

## 5. Activity by control
| Control | allow | deny | hold |
|---|---|---|---|
| FIDUCIARY-2019-INTERP | 3 | 2 | 3 |
| GLBA-501(b) | 0 | 2 | 0 |
| IAA-SLOA-NAL-2017 | 1 | 1 | 1 |
| SEC-204-2(a)(11) | 2 | 0 | 1 |
| SEC-204-2(a)(3) | 3 | 2 | 3 |
| SEC-204-2(a)(7) | 2 | 2 | 3 |
| SEC-204-2(e) | 0 | 3 | 0 |
| SEC-204A | 3 | 0 | 3 |
| SEC-206(3) | 0 | 1 | 0 |
| SEC-206(3)-2 | 0 | 1 | 0 |
| SEC-206(4)-1 | 2 | 0 | 1 |
| SEC-206(4)-2 | 1 | 1 | 3 |
| SEC-206(4)-7 | 3 | 2 | 3 |
| SEC-RegS-ID-248.201 | 0 | 0 | 2 |
| SEC-RegS-P-248.30 | 0 | 1 | 0 |
| SEC-RegS-P-248.30(a)(2) | 0 | 1 | 0 |

## 6. Coverage gaps
Tools reachable or called with **no governing rule** (deny-by-default applied, but this is the finding an examiner would write):
- `crm.get_contact`
- `custodian.get_positions`

## 7. Examiner questions answered by rule
| Examiner asks | Answered by | Controls | Activity in period |
|---|---|---|---|
| How does the firm ensure agent-initiated orders are placed only in accounts where it holds discretionary authority or has a documented client instruction? | RIA-TRD-011 | FIDUCIARY-2019-INTERP, SEC-206(4)-7, SEC-204-2(a)(3) | deny 1 |
| How do you prevent principal or agency-cross trades from being executed without the consent and confirmation records the rule requires? | RIA-TRD-002 | SEC-206(3), SEC-206(3)-2, SEC-204-2(a)(7) | deny 1 |
| Can the client-trading agent transact in access-person or proprietary accounts, and how are those trades pre-cleared and reported under the Code of Ethics? | RIA-ETH-003 | SEC-204A-1, SEC-206(4)-7 | none |
| How do you prevent options or margin transactions in accounts the client has not been approved for? | RIA-TRD-012 | SEC-206(4)-7, FIDUCIARY-2019-INTERP | deny 1 |
| Produce the order memorandum for each agent-initiated order, showing who recommended, who placed, the executing broker and whether the order was discretionary. | RIA-REC-019 | SEC-204-2(a)(3), SEC-204-2(e) | deny 1 |
| How are agent-initiated orders supervised for mandate, restricted-list and concentration exceptions, and where is the record of each exception review? | RIA-TRD-001 | SEC-206(4)-7, SEC-204-2(a)(3), SEC-204A, FIDUCIARY-2019-INTERP | allow 3, hold 3 |
| How are advisory fees calculated and reconciled to client agreements before being deducted, and who reviews exceptions? | RIA-FEE-020 | SEC-206(4)-2, SEC-206(4)-7, SEC-204-2(a)(2) | none |
| For each third-party transfer an agent initiated, show the standing letter of authorization and that all seven no-action conditions were met — or the surprise examination that covers it. | RIA-CUS-004 | SEC-206(4)-2, IAA-SLOA-NAL-2017 | deny 1 |
| What is your red-flags procedure for transfers where the payee or instructions changed recently, and how is call-back verification evidenced? | RIA-CUS-015 | SEC-RegS-ID-248.201, SEC-206(4)-2, SEC-204-2(a)(7) | hold 1 |
| How does the firm ensure each third-party disbursement stays within the SLOA no-action conditions, and who attests to that per transfer? | RIA-CUS-016 | SEC-206(4)-2, IAA-SLOA-NAL-2017, SEC-RegS-ID-248.201 | hold 1 |
| How are first-party wires to outside institutions matched to the client's written authorization? | RIA-CUS-017 | SEC-206(4)-2, SEC-204-2(a)(7) | hold 1 |
| Which agent-initiated money movements does the firm treat as custody-free, and on what basis? | RIA-CUS-018 | SEC-206(4)-2, IAA-SLOA-NAL-2017 | allow 1 |
| What prevents Social Security numbers from leaving the firm through automated channels, and can anyone override it? | RIA-DAT-005 | SEC-RegS-P-248.30, GLBA-501(b) | deny 1 |
| Under what conditions may nonpublic personal information be sent by automated email, and how is the recipient verified against the account's email of record? | RIA-DAT-014 | SEC-RegS-P-248.30(a)(2), GLBA-501(b) | deny 1 |
| Are all agent-sent communications captured in the firm's books-and-records archive, and how would an unarchived message be prevented? | RIA-COM-013 | SEC-204-2(a)(7), SEC-204-2(e) | deny 1 |
| How does the firm identify which agent-drafted communications are advertisements under Rule 206(4)-1, and how are those reviewed and retained? | RIA-COM-006 | SEC-206(4)-1, SEC-204-2(a)(11), SEC-204-2(a)(7) | allow 2, hold 1 |
| Who authorised each bulk export of client data by automated systems, to which service provider, and how many records? | RIA-DAT-007 | SEC-RegS-P-248.30, SEC-RegS-P-248.30(a)(5), GLBA-501(b) | none |
| How do you ensure agents send only approved client agreements with the brochure delivered, and where are executed copies and delivery records retained? | RIA-REC-008 | SEC-204-2(a)(10), SEC-204-3, SEC-204-2(a)(14), SEC-206(4)-7 | none |
| Can an automated agent delete or alter required records, and how would you know? | RIA-REC-009 | SEC-204-2(e) | deny 1 |
| Can an automated agent void executed or in-flight client agreements? | RIA-REC-010 | SEC-204-2(e), SEC-204-2(a)(10) | none |

## 8. Trade blotter — order memoranda (Rule 204-2(a)(3))
- Orders executed through the agent in period: **3** · memoranda missing a required field: **0**

| Date of entry | Account | Security | Side | Qty | Type | Notional | Discretionary | Recommended by | Placed by | Executing broker | Capacity | Rule |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2026-09-18T22:41:25.803282+00:00 | ACC-1001 | VTI | buy | 40 | market | 12000 | yes | model:core-60-40 | portfolio-assistant on behalf of agent7 | CUSTODIAN-BD | agency | RIA-TRD-001 |
| 2026-09-18T22:41:28.784202+00:00 | ACC-1001 | VTI | buy | 1300 | market | 400000 | yes | model:core-60-40 | portfolio-assistant on behalf of agent7 | CUSTODIAN-BD | agency | RIA-TRD-001 |
| 2026-09-18T22:41:28.801803+00:00 | ACC-1001 | VTI | buy | 40 | market | 12000 | no · instr CI-42 | model:core-60-40 | portfolio-assistant on behalf of agent7 | CUSTODIAN-BD | agency | RIA-TRD-001 |

## 9. Examination request-list index
Typical day-one document requests, and where in this package each is answered.

| Request | Answered by rules | Sections | Activity in period |
|---|---|---|---|
| Compliance manual and most recent annual review (206(4)-7) | RIA-TRD-001, RIA-TRD-011, RIA-FEE-020 | 2. Policies in force; Policy changes in period | allow 3, hold 3, deny 1 |
| Trade blotter / order memoranda (204-2(a)(3)) | RIA-REC-019, RIA-TRD-001, RIA-TRD-011 | 3. Supervision evidence; 8. Trade blotter | deny 2, allow 3, hold 3 |
| Discretionary authority records and client instructions | RIA-TRD-011 | 4. Denials; 8. Trade blotter | deny 1 |
| Restricted / watch list and Code of Ethics records (204A, 204A-1) | RIA-TRD-001, RIA-ETH-003 | 3. Supervision evidence; 4. Denials | allow 3, hold 3 |
| Principal and agency-cross transaction consents (206(3), 206(3)-2) | RIA-TRD-002 | 4. Denials | deny 1 |
| Custody records, SLOAs, surprise-examination reports (206(4)-2) | RIA-CUS-004, RIA-CUS-015, RIA-CUS-016, RIA-CUS-017, RIA-CUS-018 | 3. Supervision evidence; 4. Denials | deny 1, hold 3, allow 1 |
| Fee billing calculations and reconciliations | RIA-FEE-020 | 3. Supervision evidence | none |
| Advertising file and marketing review records (206(4)-1, 204-2(a)(11)) | RIA-COM-006 | 3. Supervision evidence | allow 2, hold 1 |
| Client agreements and Form ADV / relationship-summary delivery records (204-2(a)(10), 204-3) | RIA-REC-008 | 3. Supervision evidence | none |
| Reg S-P safeguards program, service-provider oversight and incident log | RIA-DAT-005, RIA-DAT-014, RIA-DAT-007 | 4. Denials; 3. Supervision evidence | deny 2 |
| Electronic communications retention and off-channel review (204-2(a)(7)) | RIA-COM-013, RIA-COM-006 | 4. Denials | deny 1, allow 2, hold 1 |
| Policies on AI and automated tools, and evidence they operate as disclosed in Form ADV | RIA-TRD-001, RIA-TRD-011, RIA-REC-019 | 1. Audit chain integrity; 2. Policies in force; 6. Coverage gaps | allow 3, hold 3, deny 2 |

## 10. Firm parameters in force
`ria/v1`: large_trade_threshold_usd = 250000, model_tolerance_pct = 5.0, concentration_limit_pct = 10.0, restricted_list = ['ACME', 'BIGCO', 'CUSIP-000000000'], accounts_with_pending_withdrawal = ['ACC-7001'], fee_tolerance_bps = 2, fee_period_change_pct = 25.0, instruction_change_lookback_days = 30, secure_channels = ['portal', 'encrypted_email'], dual_registrant = False
