---
description: Revue DPO/RGPD du diff courant.
agent: qindu-dpo
subtask: true
---

# /qindu-dpo-review

DPO privacy review of the current diff. Verifies GDPR compliance and PII handling.

## Mandatory Context
- `@docs/decisions/README.md`
- `@ARCHITECTURE.md`
- `@AGENTS.md`

## Workflow

1. Show `git diff --stat`.
2. Show `git diff`.
3. Analyze the diff for privacy concerns:
   - **Logs**: Any PII in log messages? Are logs structured to avoid PII leakage?
   - **Persistent identifiers**: Any user IDs, device IDs, session IDs?
   - **Cookies / tracking**: Any analytics, telemetry, tracking mechanisms?
   - **AI payloads**: What data is sent to external AI services? Is it properly tokenized?
   - **Test data**: Any real PII in test fixtures?
   - **Error messages**: Could error output contain PII?
   - **Retention**: Any new data stored? With what TTL?
   - **DPIA / PIA**: Does this change require updating the Data Protection Impact Assessment?
4. Produce verdict: **PASS** or **BLOCKED** only.
5. If BLOCKED, list the specific blocking points with references to GDPR articles or Qindu privacy ADRs.
