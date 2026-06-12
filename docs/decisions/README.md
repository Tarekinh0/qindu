# Architecture Decision Records (ADR)

This directory contains Architecture Decision Records for the Qindu project.

## What is an ADR?

An Architecture Decision Record captures a significant architectural decision along with its context and consequences.

## Format

Each ADR follows the format:
- **Title**: Short noun phrase
- **Status**: Proposed, Accepted, Deprecated, Superseded
- **Context**: What is the issue we're addressing?
- **Decision**: What is the change we're proposing and/or doing?
- **Consequences**: What becomes easier or more difficult because of this decision?

## ADR Index

| ID | Title | Domain | Status |
|----|-------|--------|--------|
| ADR-001 | Module Go et structure du projet | Go, Structure | Accepted |
| ADR-002 | Architecture du proxy : CONNECT MITM + Interceptor | Proxy, HTTP | Accepted |
| ADR-003 | Stratégie de gestion TLS : CA unique, certs lazy, SAN wildcard | TLS, Crypto | Accepted |
| ADR-004 | Pipeline de données : interface Interceptor | Proxy, Extensibilité | Accepted |
| ADR-005 | Configuration statique et génération PAC dynamique | Config, PAC | Accepted |
| ADR-006 | Service Windows : binaire unique, auto-détection | Windows, Packaging | Accepted |
| ADR-007 | Stratégie de tests : testcontainers-go, cross-compilation | Tests, CI | Accepted |
| ADR-008 | Journalisation structurée : slog JSON sans PII | Logging, Privacy | Accepted |
| ADR-009 | Modèle de concurrence du proxy | Proxy, Performance | Accepted |
| ADR-010 | Validation TLS upstream et compatibilité proxies entreprise | TLS, Sécurité | Accepted |

All agents must respect accepted ADRs.

### ADR Status Lifecycle

```text
Proposed  → Under discussion, not yet binding
Accepted  → Binding on all agents and future decisions
Deprecated → No longer applicable (superseded by another ADR)
Superseded → Replaced by a newer ADR on the same topic
```
