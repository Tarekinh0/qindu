# Qindu V1 Roadmap

## Phases

### Phase 1: Fondation Proxy (Sprints QINDU-0001 → QINDU-0004)

```
QINDU-0001: Proxy TLS local sélectif
  ├── HTTP CONNECT MITM/Tunnel
  ├── Certificats lazy (CA ECDSA P-256 + feuilles wildcard)
  ├── PAC dynamique + /health
  ├── Logs slog JSON sans PII
  ├── Graceful shutdown 30s
  ├── Service Windows (binaire unique)
  ├── Tests testcontainers-go
  └── CI GitHub Actions (cross-compilation)
QINDU-0002: Installer Windows + Service (inclut désinstallation)
QINDU-0004: CI/CD Pipeline
```

### 🔧 Hotfixes

- **QINDU-HOTFIX-001**: MSI installer + TLS CRL fixes (6 bugs, 149 tests) ✅
- **QINDU-HOTFIX-002**: Fix 50 golangci-lint issues (0 behavioural changes, 253 tests) ✅

### Phase 2: Moteur PII (Sprints QINDU-0005 → QINDU-0007)

```
QINDU-0005: Moteur PII Go-native (recognizers)
QINDU-0006: Tokenisation
QINDU-0007: Mode Monitor
```

### Phase 3: Vault (Sprint QINDU-0008)

```
QINDU-0008: Vault local chiffré       ← DONE ✅
```

### Phase 4: Enforce Pipeline (Sprints QINDU-0009 → QINDU-0013)

```
QINDU-0011: Adapter ChatGPT web       ← READY (next sprint)
QINDU-0009: Mode Enforce + Réhydratation non-streaming
QINDU-0010: Réhydratation streaming (SSE)
QINDU-0012: Adapter Claude web
QINDU-0013: Gestion historique conversations
```

**Note**: Provider adapters (0011, 0012) come BEFORE enforce mode (0009).
The adapter defines which fields are user text vs metadata, so the enforce
pipeline can surgically tokenize only the right fields. Without adapters,
enforce mode would blindly scan everything, producing false positives on
ChatGPT internal tokens (JWT, hex hashes, etc.).

### Phase 5: Extension (Sprints QINDU-0014 → QINDU-0017)

```
QINDU-0014: Adapter Gemini web
QINDU-0015: Page d'erreur locale (fail-closed)
QINDU-0016: Tray icon Windows
QINDU-0017: Endpoint rewriting (redirection provider → custom)
```

### Phase 6: UI & Metrics (Sprints QINDU-0020)

```
QINDU-0020: Fenêtre de configuration + métriques
```

### Phase 7: Cross-Platform Hardening (Sprints QINDU-0018 → QINDU-0021)

```
QINDU-0018: Linux hardening — crypto & safety
QINDU-0019: macOS hardening — Keychain trust, launchd, Homebrew
QINDU-0021: Linux packaging — systemd + .deb/.rpm
```

## Macro Dependency Chain

```
QINDU-0001 (Proxy)
  ├── QINDU-0002 (Installer + Désinstallation)
  ├── QINDU-0004 (CI/CD)
  ├── QINDU-0005 (Moteur PII)
  │     ├── QINDU-0006 (Tokenisation)
  │     │     └── QINDU-0008 (Vault) ✅ DONE
  │     └── QINDU-0007 (Mode Monitor)
  ├── QINDU-0011 (ChatGPT adapter) ← next sprint
  │     └── QINDU-0009 (Mode Enforce) ← depends on 0007 + 0008 + 0011
  │           └── QINDU-0010 (Rehyd streaming SSE)
  │                 ├── QINDU-0012 (Claude adapter)
  │                 └── QINDU-0014 (Gemini adapter)
  ├── QINDU-0013 (Historique) ← depends on 0009 + 0011 + 0012
  ├── QINDU-0015 (Fail-closed page)
  ├── QINDU-0016 (Tray icon)
  │     └── QINDU-0020 (Config window + metrics) ← depends on 0009 + 0016
  ├── QINDU-0017 (Endpoint rewriting)
  ├── QINDU-0018 (Linux hardening — crypto)
  │     └── QINDU-0021 (Linux packaging — systemd, .deb/.rpm)
  └── QINDU-0019 (macOS hardening) ← depends on 0018 (same crypto patterns)
```

## Blockers

_None currently._

## Key Milestones

1. **M0 - Proxy fonctionnel**: QINDU-0001 done → le proxy tourne, CONNECT, MITM, PAC, logs
2. **M1 - Installable**: QINDU-0002 + QINDU-0004 done → installation/désinstallation Windows complète, CI verte (0 issues golangci-lint, 5/5 packages test pass)
3. **M2 - PII Ready**: QINDU-0005 + QINDU-0006 + QINDU-0007 done → détection et tokenisation fonctionnelles, mode monitor avec path whitelisting + per-message logging + MSI uninstall clean
4. **M3 - MVP Privacy**: QINDU-0008 + QINDU-0011 + QINDU-0009 + QINDU-0010 done → flux complet tokenisation → réhydratation, ChatGPT fonctionnel
5. **M4 - Multi-Provider V1**: QINDU-0012 + QINDU-0013 + QINDU-0014 done → ChatGPT, Claude, Gemini supportés avec historique
6. **M5 - Multi-platform**: QINDU-0018 + QINDU-0019 + QINDU-0021 done → Linux et macOS pleinement supportés avec chiffrement CA, packaging natif, trust stores
