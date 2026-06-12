# ADR-006: Service Windows - binaire unique, auto-détection

- **Status**: Accepted
- **Date**: 2026-06-12

## Context

L'agent doit tourner comme service Windows en production, mais être lançable en console pour le développement. Nous devons choisir entre:
1. Deux points d'entrée séparés (binaires distincts)
2. Un seul binaire avec auto-détection du contexte

## Decision

- **Binaire unique** `cmd/agent/main.go` → `agent.exe`
- **Auto-détection** via `svc.IsAnInteractiveSession()`:
  - Lancé par le SCM → mode service (`svc.Run()`)
  - Lancé depuis un terminal → mode console (foreground)
- **Package**: `golang.org/x/sys/windows/svc`
- **Graceful shutdown**: le handler service écoute `svc.Stop` et déclenche un `http.Server.Shutdown(ctx)` avec timeout 30s

## Consequences

**Devient plus facile**:
- Un seul `go build`, un seul binaire à distribuer
- Développement: `go run .` → mode console immédiat
- Déploiement: `sc create QinduAgent binPath="C:\...\agent.exe"` → mode service

**Devient plus difficile**:
- Dépendance à l'API Windows (`golang.org/x/sys/windows`) → cross-compilation depuis Linux possible mais tests uniquement sur Windows
- Tests unitaires du handler service nécessitent des mocks
