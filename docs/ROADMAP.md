# Roadmap (public)

Feature milestones only. Order may change based on what design partners need.

## v0.2 — pack correctness
- RIA pack rewritten per `docs/RIA-CCO-REVIEW.md`; practitioner review sought.
- Order-memorandum fields captured on trades; firm overlay for thresholds.
- Hold expiry behaviours (`cancel_and_log`, `notify`).

## v0.3 — usable approvals and storage
- Slack interactive approvals (Block Kit, attestation modal); Teams cards.
- Postgres store; S3 Object Lock sink for the chain; nightly export.
- Ed25519 signatures on ledger entries; `verify` checks chain + signatures.
- `deploy/docker-compose.yml` and a Helm chart.

## v0.4 — evidence depth
- PDF evidence export with signed hash.
- Cross-map of vertical controls to NIST AI RMF, EU AI Act Art. 12/14,
  SOC 2 CC6/CC7, OWASP Agentic Top 10.
- Exam request-list index in the evidence package.

## v0.5 — second vertical and AGT plugin
- Broker-dealer pack (FINRA 3110/3120/4511/2210, Reg BI) with SME review.
- Native Agent Governance Toolkit plugin registration; contract tests.
- OTLP ingest load-tested at 1k events/s.

## Later
- Hosted control plane (multi-tenant, OIDC SSO, RBAC, fleet policy push).
- HIPAA-practice and PCI-ops packs.
- Third-party security assessment before any 1.0.
