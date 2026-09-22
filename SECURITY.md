# Security Policy

Regent sits in the authorization path of AI agents. We treat every security
report as a priority.

## Supported versions

| Version | Supported |
|---|---|
| `main` and the latest tagged release | yes |
| anything older | no — upgrade |

Pre-1.0: no backports. Fixes land on `main` and the next tag.

## Reporting a vulnerability

- Use GitHub's **private vulnerability reporting** on this repository
  (Security tab → Report a vulnerability). A security@ mailbox will be added
  once the project domain is live.
- Do **not** open a public issue for a suspected vulnerability.
- Include: affected version/commit, runtime (agentgateway / AGT plugin / shim),
  reproduction steps, and impact (policy bypass, approval bypass, ledger
  tampering, secret exposure, denial of service).

We acknowledge within **2 business days**, give a severity assessment within
**5 business days**, and aim to ship a fix for critical issues (policy or
approval bypass, ledger integrity) within **14 days**. We will credit reporters
in the release notes unless asked not to.

## What counts as in scope

- Any way a tool call reaches a target without the policy decision the pack
  specifies (bypass).
- Any way a `hold` is converted to `allow` without a valid approval or grant.
- Ledger integrity: forging, reordering, or deleting entries without breaking
  the hash chain or `regent verify`.
- Redaction failures that write secrets or PII into the ledger.
- Compiler bugs that emit CEL/Cedar weaker than the pack.
- Dependency vulnerabilities with a demonstrated path through Regent.

Out of scope: issues in agentgateway or the Agent Governance Toolkit themselves
(report upstream), and social-engineering of approvers.

## Design commitments

- Deny by default. An unmatched call is denied, never allowed.
- Fail closed. If the PDS is unreachable, the runtime must deny (documented per
  runtime).
- No custom cryptography. Hash chaining uses SHA-256; signatures use Ed25519
  from a maintained library.
- Secrets never enter the repository. `gitleaks` runs in pre-commit and CI.
- No customer data in any repository, issue, or CI log.
