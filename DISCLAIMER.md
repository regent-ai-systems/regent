# Disclaimer

**Regent is software, not legal, compliance, or regulatory advice.**

1. **Policy packs are engineering artifacts.** A pack maps enforcement rules to
   control identifiers (for example FINRA 3110, SEC Rule 206(4)-7, Regulation S-P,
   HIPAA §164.312). Those mappings reflect the maintainers' reading of public
   rule text. They are not a legal opinion, are not reviewed by counsel unless a
   pack says so explicitly, and may be incomplete or out of date. Your
   obligations are determined by the regulator, your counsel, and your own
   compliance program — not by this project.

2. **Evidence packages are records, not attestations.** `regent evidence`
   assembles what the system observed. It does not certify that a firm is
   compliant with anything. An examiner, auditor, or regulator may reach a
   different conclusion from the same records.

3. **Enforcement is only as good as its placement.** Regent enforces policy only
   on tool calls that actually pass through a runtime it is attached to
   (agentgateway, the Agent Governance Toolkit plugin, or the stdio shim).
   Traffic that bypasses that runtime is not governed, not logged, and not in
   any evidence package.

4. **No warranty.** The software is provided "AS IS" under the Apache License,
   Version 2.0, without warranties or conditions of any kind. See LICENSE.

5. **Not a substitute for supervision.** Human-approval workflows in Regent are
   controls that a firm's supervisory system may rely on; they are not
   themselves a supervisory system, and configuring them does not discharge any
   person's regulatory supervisory obligations.

6. **Security.** Report vulnerabilities per SECURITY.md. Do not run pre-1.0
   releases in production without your own security review.

If you need a compliance opinion, engage counsel or a qualified compliance
consultant. Regent AI Systems LLC offers no such service unless separately
agreed in writing.
