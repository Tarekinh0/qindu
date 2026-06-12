---
description: Revue CISO du diff courant.
agent: qindu-ciso
subtask: true
---

# /qindu-ciso-review

CISO security review of the current diff. Verifies security properties and ADR compliance.

## Mandatory Context
- `@docs/decisions/README.md`
- `@ARCHITECTURE.md`
- `@AGENTS.md`

## Workflow

1. Show `git diff --stat`.
2. Show `git diff`.
3. Analyze the diff for security:
   - **TLS**: Any changes to TLS interception, certificate generation, or CA management?
   - **Crypto**: Any new cryptographic operations? Correct algorithms and key sizes?
   - **PII handling**: Is PII properly tokenized before egress? Vault encryption?
   - **Memory**: Any risk of PII being written to disk or swap?
   - **Input validation**: New parsers or protocol handlers? Fuzzing needed?
   - **Dependencies**: New Go modules? Known vulnerabilities?
   - **CI/CD**: Changes to workflows? Secrets exposure?
   - **Proxy surface**: Any new network listeners or endpoints?
4. Produce a short threat model if the change touches critical surfaces.
5. Identify unmet security requirements or missing tests.
6. Produce verdict: **PASS** or **BLOCKED** only.
