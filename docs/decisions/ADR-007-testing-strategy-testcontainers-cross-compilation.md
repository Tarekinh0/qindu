# ADR-007: Stratégie de tests - testcontainers-go et cross-compilation

- **Status**: Accepted
- **Date**: 2026-06-12

## Context

Le proxy MITM doit être testé avec de vrais serveurs HTTPS, du vrai HTTP/2, du vrai TLS. Les mocks `httptest` ne capturent pas les subtilités du multiplexing H2, des timeouts réseau, ou du comportement ALPN.

Nous devons aussi décider de la CI: tests sur Windows natif ou cross-compilation.

## Decision

- **Tests d'intégration**: `testcontainers-go` avec Docker pour lancer des serveurs HTTPS conteneurisés
  - Serveurs HTTP/1.1 et HTTP/2 avec vrais certificats
  - Simulation de streaming SSE
  - Timeouts réseau et graceful shutdown
- **CI**: GitHub Actions sur `ubuntu-latest`
  - Go 1.22 et 1.23 dans la matrice
  - `go test ./...`, `go vet ./...`
  - Cross-compilation: `GOOS=windows GOARCH=amd64 go build`
- **Tests Windows-spécifiques**: interfaces mockées en CI, tests manuels sur Windows pour DPAPI/trust store/service

## Consequences

**Devient plus facile**:
- Tests d'intégration réalistes et déterministes
- CI rapide et économique (runner Linux)
- Pas de runner Windows requis en CI

**Devient plus difficile**:
- Docker requis en CI et en développement local
- Les tests Windows-spécifiques ne sont pas automatisés en CI
