# ADR-001: Module Go et structure du projet

- **Status**: Accepted
- **Date**: 2026-06-12

## Context

Le projet Qindu est un projet Go greenfield. Nous devons choisir le nom du module Go et la structure de répertoires qui guidera tout le développement V1.

Le module doit être compatible avec le repository GitHub privé existant (`github.com/Tarekinh0/qindu`) et permettre la distribution de binaires autonomes.

## Decision

- **Module Go**: `github.com/Tarekinh0/qindu`
- **Binaires**: `cmd/agent/` → `agent.exe`, `cmd/installer-helper/` → `installer-helper.exe`
- **Logique métier**: `internal/` - packages internes non exportables
- **Structure**: organisée par domaine fonctionnel (`proxy/`, `tls/`, `policy/`, `pii/`, `vault/`, etc.)
- **Tests**: `tests/unit/` et `tests/integration/` (hors `internal/` pour les tests d'intégration)

## Consequences

**Devient plus facile**:
- Distribution single-binary pour Windows
- Développement modulaire avec interfaces claires entre packages
- CI cross-compilation simple (`GOOS=windows GOARCH=amd64 go build`)

**Devient plus difficile**:
- Renommage du module si le repository change de propriétaire (nécessite `go mod edit`)
- Partage de code hors Qindu (tout est dans `internal/`)
