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

### Phase 3: Vault & Réhydratation (Sprints QINDU-0008 → QINDU-0010)

```
QINDU-0008: Vault local chiffré       ← READY
QINDU-0009: Mode Enforce + Réhydratation non-streaming
QINDU-0010: Réhydratation streaming (SSE)
```

### Phase 4: Providers (Sprints QINDU-0011 → QINDU-0013)

```
QINDU-0011: Adapter ChatGPT web
QINDU-0012: Adapter Claude web
QINDU-0013: Gestion historique conversations
```

### Phase 5: Extension (Sprints QINDU-0014 → QINDU-0016)

```
QINDU-0014: Adapter Gemini web
QINDU-0015: Page d'erreur locale (fail-closed)
QINDU-0016: Interface utilisateur locale (tray icon + fenêtre config + métriques)
QINDU-0017: Endpoint rewriting (redirection provider → custom)
```

## Macro Dependency Chain

```
QINDU-0001 (Proxy)
  ├── QINDU-0002 (Installer + Désinstallation)
  ├── QINDU-0004 (CI/CD)
  ├── QINDU-0005 (Moteur PII)
  │     ├── QINDU-0006 (Tokenisation)
  │     │     └── QINDU-0008 (Vault)
  │     └── QINDU-0007 (Mode Monitor)
  └── QINDU-0009 (Mode Enforce) ← needs QINDU-0007 + QINDU-0008
        └── QINDU-0010 (Rehyd streaming)
              ├── QINDU-0011 (ChatGPT)
              ├── QINDU-0012 (Claude)
              ├── QINDU-0013 (Historique) ← depends on QINDU-0011 + QINDU-0012
              └── QINDU-0014 (Gemini)
  ├── QINDU-0015 (Fail-closed page)
  ├── QINDU-0016 (Tray icon)
  └── QINDU-0017 (Endpoint rewriting)
```

## Blockers

_None currently._

## Key Milestones

1. **M0 - Proxy fonctionnel**: QINDU-0001 done → le proxy tourne, CONNECT, MITM, PAC, logs
2. **M1 - Installable**: QINDU-0002 + QINDU-0004 done → installation/désinstallation Windows complète, CI verte (0 issues golangci-lint, 5/5 packages test pass)
3. **M2 - PII Ready**: QINDU-0005 + QINDU-0006 + QINDU-0007 done → détection et tokenisation fonctionnelles, mode monitor avec path whitelisting + per-message logging + MSI uninstall clean
4. **M3 - MVP Privacy**: QINDU-0008 + QINDU-0009 + QINDU-0010 done → flux complet tokenisation → réhydratation
5. **M4 - V1 Complete**: QINDU-0011 + QINDU-0012 + QINDU-0013 done → ChatGPT et Claude supportés
