# Qindu V1 — Risk Register (Human-Readable Mirror)

> **Source of truth**: `docs/implementation/backlog/qindu-v1-backlog.yaml` (`risks:` block)
> **Last synced**: 2026-07-06 (R-001 through R-033, QINDU-0009 closure)
> **Sync rule**: This file MUST be updated whenever the YAML `risks:` block changes.

| ID | Title | Severity | Affects | Status | Resolution |
|----|-------|----------|---------|--------|------------|
| R-001 | MSI non signé — SmartScreen warning | 🟢 LOW | QINDU-0002 | Accepted | Certificat OV/EV requis pour release publique |
| R-002 | Faux négatifs hex hashes | 🟢 LOW | QINDU-0005, 0006, 0009 | Accepted | Longueurs connues (32, 40, 64, 128 hex) exclues |
| R-003 | Évasion Unicode (confusables) | 🟡 MEDIUM | QINDU-0005 | Accepted | PII avec confusables non-ASCII contourne les regex |
| R-004 | Évasion par chunking | 🟡 MEDIUM | QINDU-0007, 0009, 0010 | Accepted | Résolu dans QINDU-0010 (sliding buffer SSE) |
| R-005 | Core dump exposure PII | 🟢 LOW | QINDU-0005, 0009 | Accepted | Valeurs PII en mémoire. Limitation runtime Go |
| R-006 | Certificat signature code absent | 🟡 MEDIUM | QINDU-0002, 0004 | Accepted | Certificat OV/EV requis avant release publique |
| R-007 | Pas de fuzzing ni benchmarks | 🟢 LOW | QINDU-0005, 0006 | Accepted | Différé à sprint futur dédié |
| R-008 | DPAPI sans couverture de tests unitaires | 🟢 LOW | QINDU-0001, 0008 | Accepted | DPAPI nécessite Windows. Tests manuels ou VM |
| R-009 | Adapter avant enforce — ordre non conventionnel | 🟢 LOW | QINDU-0011 | **Resolved** ✅ | QINDU-0011 livré avant QINDU-0009. Architecture provider-agnostic validée end-to-end |
| R-010 | vault.key non shreddé après PurgeAll | 🟡 MEDIUM | QINDU-0008 | Accepted | Opération 'purge all + shred key' sprint DPO futur |
| R-011 | /tmp CA fallback sur Unix — clé CA exposée | 🟡 MEDIUM | QINDU-0018, 0019 | Accepted | DOIT être retiré dans QINDU-0018 (reject startup) |
| R-012 | Pas de rotation/retention des logs fichier | 🟡 MEDIUM | QINDU-0007 | Accepted | Rotation à ajouter dans sprint maintenance ou QINDU-0020 |
| R-013 | Overflow canal async → perte silencieuse mappings PII | 🟢 LOW | QINDU-0009 | Accepted | Test overflow WARN à ajouter dans QINDU-0009 |
| R-014 | MSI orphaned registration — installation interrompue | 🟡 MEDIUM | QINDU-0002 | **Resolved** ✅ | Résolu QINDU-0009. Cross-compil pur x64 + WiX Toolset v3.14.1 élimine erreur 1920 |
| R-015 | Permissions fichier log 0644 au lieu de 0600 | 🟢 LOW | QINDU-0007 | Accepted | Correction triviale dans sprint maintenance futur |
| R-016 | CA absente du Windows trust store — regression QINDU-0004 | 🟡 MEDIUM | QINDU-0002 | Accepted | Correction dans HOTFIX ou sprint maintenance futur |
| R-017 | valueToToken — clés PII sur heap Go standard | 🟡 MEDIUM | QINDU-0006, 0009 | Accepted | Dedup par hash pour éviter PII comme clé. 4× reviewers |
| R-018 | Memory locking CI — happy path non testable Linux | 🟡 MEDIUM | QINDU-0006 | Accepted | CI manque CAP_IPC_LOCK. VM QEMU seule vérification |
| R-019 | MemoryStore.Close() — fuite arena (VirtualFree/Munmap) | 🟡 MEDIUM | QINDU-0006 | Accepted | ~4 MiB VAS fuité. Acceptable pour vault process-lifetime |
| R-020 | Prefix DB staleness — 70 patterns compilés | 🟢 LOW | QINDU-0005 | Accepted | Entropy recognizer fournit mitigation partielle |
| R-021 | SR-13 non implémenté — TLS SNI host absent des logs | 🟡 MEDIUM | QINDU-0007 | Accepted | Aucun sprint assigné. Accepté V1 |
| R-022 | NAME false positives — stop-word list limitée à 26 mots | 🟢 LOW | QINDU-0005 | Accepted | Confiance plafonnée à 0.70 |
| R-023 | IBAN et IP_ADDRESS non détectés par le moteur PII | 🟢 LOW | QINDU-0005, 0011, 0009 | Accepted | Gap à combler dans sprint amélioration moteur PII |
| R-024 | Config override bool fields silently ignored | 🟡 MEDIUM | QINDU-0002 | **Resolved** ✅ | Résolu QINDU-0009. PIILogging/CertCacheEnabled → *bool, FailMode → *string |
| R-025 | MSI upgrade certutil -addstore duplicate CN bloque install | 🟡 MEDIUM | QINDU-0002 | **Resolved** ✅ | Résolu QINDU-0009. Même CA CN fonctionne à travers réinstallations. Vérifié QEMU. |
| R-026 | MITM upstream dial sans timeout — goroutine leak | 🟡 MEDIUM | QINDU-0001 | Accepted | Graceful shutdown 30s nettoie au pire cas |
| R-027 | Pas de génération SBOM/SPDX dans le CI | 🟡 MEDIUM | QINDU-0004 | Accepted | go mod verify = intégrité partielle. Accepté V1 |
| R-028 | Pas d'attestation SLSA build provenance | 🟡 MEDIUM | QINDU-0004 | Accepted | Impossible de prouver le build chain. Accepté V1 |
| R-029 | pii_logging: false config flag is dead code | 🟡 MEDIUM | QINDU-0001, 0005 | Accepted | Aucun middleware de redaction n'existe. Accepté V1 |
| R-030 | Binaire agent.exe tracké dans Git | 🟡 MEDIUM | QINDU-0002, 0008 | Accepted | CI rebuild depuis source. Retirer du tracking ou vérifier |
| R-031 | Pas de cleanup per-user vault.db à la désinstallation MSI | 🟡 MEDIUM | QINDU-0008, 0009 | Accepted | MSI SYSTEM ne peut pas énumérer profils utilisateurs |
| R-032 | Logs/ non pré-créé par WiX — ACL gap + 0755 | 🟡 MEDIUM | QINDU-0008 | Accepted | Go MkdirAll(0755). WiX devrait pré-créer avec bonnes ACLs |
| R-033 | SeImpersonatePrivilege révoqué par GPO → deny all | 🟡 MEDIUM | QINDU-0008, 0009 | Accepted | Ajouter WARNING au startup si privilège absent |
| R-034 | Logging stderr en mode service Windows → pas de agent.log | 🟡 MEDIUM | QINDU-0008 | Accepted | output: 'file' requis en mode service. Défaut MSI à corriger. QINDU-0009 NB-1. |
| R-035 | Policies Chrome/Edge registry non nettoyées à la désinstallation | 🟡 MEDIUM | QINDU-0002 | Accepted | ProxyMode/ProxyPacUrl/QuicAllowed persistent. Bug WiX possible. QINDU-0009 NB-3. |

## Risk Severity Distribution

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 0 |
| 🟡 MEDIUM | 22 |
| 🟢 LOW | 11 |

## Orphaned Risks (Accepted but no resolving sprint assigned)

| ID | Title | Notes |
|----|-------|-------|
| R-021 | TLS SNI host absent des logs | Aucun sprint assigné. SHOULD requirement CISO |
| R-015 | Log permissions 0644 | Sprint maintenance non planifié |
| R-016 | CA trust store regression | HOTFIX non planifié |
| R-034 | stderr en mode service → pas de agent.log | Défaut MSI à corriger |
| R-035 | Policies Chrome/Edge non nettoyées à désinstall | Bug WiX possible, sprint non planifié |
