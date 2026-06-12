# ADR-009: Modèle de concurrence du proxy

- **Status**: Accepted
- **Date**: 2026-06-12

## Context

Le proxy doit gérer plusieurs connexions CONNECT simultanées. Chaque connexion peut durer longtemps (streaming SSE, keep-alive HTTP/2). Go rend la concurrence naturelle, mais nous devons choisir un modèle clair.

## Decision

- **Une goroutine par connexion CONNECT entrante**
- **Deux goroutines par connexion MITM**: une par direction (navigateur→proxy→upstream et upstream→proxy→navigateur)
- **`io.CopyBuffer`** avec buffer 32KB pour le forwarding
- **Ressources partagées**:
  - Cache de certificats: `sync.RWMutex`
  - Compteurs: `sync/atomic`
- **Pas de pool de workers**: le nombre de connexions simultanées est faible (~10 max sur localhost)
- **Cancellation**: `context.Context` propagé depuis la connexion HTTP

## Consequences

**Devient plus facile**:
- Modèle Go idiomatique, testé en production (Caddy, Traefik, goproxy)
- Code simple: une fonction par connexion, pas de file d'attente
- Débugging: stack trace par connexion

**Devient plus difficile**:
- Pas de limite de connexions intégrée (mais localhost + faible volume → non problématique)
- Pas de prioritisation des connexions
