---
description: Test d'intégration VM QEMU + API (tokenisation, vault, réhydratation, logs).
agent: qindu-qemu-tester
---

# /qindu-qemu-test

Triggers end-to-end integration testing on the Windows QEMU VM. Validates installation, service, proxy, TLS, story compliance, and from QINDU-0009 onward the full enforce pipeline with real AI provider calls.

## Mandatory Context
- Story `story.md` dans le dossier de sprint courant
- `@AGENTS.md`
- API key from `.ssh/openai.key` (for API integration tests)

## Workflow

### Phase 1: QEMU VM Testing

1. Identifier le sprint actif (`docs/implementation/sprints/QINDU-XXXX/`).
2. Lire `story.md`.
3. Connecter à la VM Windows via SSH (`192.168.122.4:2222`, user `opencode-admin`).
4. Nettoyer l'état précédent (désinstaller si installé).
5. Déployer le MSI et installer. WiX builds on the VM at `C:\Program Files (x86)\WiX Toolset v3\`.
6. Smoke tests : `/health`, `/proxy.pac`, service start/stop, écoute du port, logs.
7. Tests spécifiques à la story (MITM, PII detection, tokenization, rehydration, etc.).
8. Tests de bord : graceful shutdown, restart, uninstall propre.

### Phase 2: API Integration (from QINDU-0009 onward)

9. Send real prompts with PII through the proxy to an AI provider using the API key from `.ssh/openai.key`.
10. Verify tokenization: PII replaced with tokens in the outbound request body.
11. Verify vault persistence: token→value mapping stored and retrievable.
12. Verify rehydration: tokens replaced with original PII values in the AI response.
13. Verify log sanitization: zero PII values in any log output (agent.log, stdout, stderr).
14. Verify round-trip integrity: the full enforce pipeline works end-to-end without data loss.

### Report

15. Produire `qemu-test-report.md` avec verdict **PASS** ou **BLOCKED**.
