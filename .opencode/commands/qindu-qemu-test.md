---
description: Test d'intégration sur VM Windows QEMU.
agent: qindu-qemu-tester
---

# /qindu-qemu-test

Déclenche le test d'intégration sur la VM Windows QEMU. Valide l'installation, le service, le proxy, TLS et la conformité à la story.

## Mandatory Context
- Story `story.md` dans le dossier de sprint courant
- `@AGENTS.md`

## Workflow

1. Identifier le sprint actif (`docs/implementation/sprints/QINDU-XXXX/`).
2. Lire `story.md` et les artefacts de sprint (revues, dev-notes).
3. Connecter à la VM Windows via SSH (`192.168.122.4:2222`, user `opencode-admin`).
4. Nettoyer l'état précédent (désinstaller si installé).
5. Déployer le MSI et installer.
6. Smoke tests : `/health`, `/proxy.pac`, service start/stop, écoute du port, logs.
7. Tests spécifiques à la story (MITM, PII detection, tokenization, rehydration, etc.).
8. Tests de bord : graceful shutdown, restart, uninstall propre.
9. Produire `qemu-test-report.md` avec verdict **PASS** ou **BLOCKED**.
