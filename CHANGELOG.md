# Changelog

All notable changes to Regent are recorded here. Format follows
Keep a Changelog; versions follow SemVer. Pre-1.0: minor versions may break.

## [Unreleased]

### Planned (v0.2)
- RIA pack v0.2 per `docs/RIA-CCO-REVIEW.md`: exception-based trade holds,
  discretionary-authority deny, tiered money-movement holds with SLOA
  conditions, Marketing Rule definition fix, narrowed NPI rule.
- Order-memorandum fields (204-2(a)(3)) required on `custodian.place_trade`.
- Firm overlay for thresholds; `on_sla_expiry` behaviour on holds.

## [0.1.0] — 2026-09-18

### Added
- Policy Decision Service: deny-by-default engine, `allow / deny / hold`,
  single-use time-boxed grants, `no_override` rules.
- Workflows: single, four-eyes, separation of duties, attestation, SLA.
- Runtimes: agentgateway `ext_authz` (gRPC + HTTP, verified against
  agentgateway v1.5.0), in-process `RegentGuard`, stdio shim.
- Compilers: pack → CEL (agentgateway), Cedar, Rego.
- Audit: OTLP/JSONL/AGT-Merkle sources, SHA-256 hash chain, redaction,
  `regent verify`.
- Evidence: `regent evidence` — policies in force, supervision, denials,
  activity by control, coverage gaps, examiner request index.
- Packs: `dev_default` (13 rules), `ria` v0.1 (10 rules, CFR-cited).
- CLI: `serve compile ingest evidence verify approve decide shim lint`.
- CI: pytest (3.11/3.12), ruff, DCO check, gitleaks.
