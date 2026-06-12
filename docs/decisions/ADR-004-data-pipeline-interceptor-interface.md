# ADR-004: Pipeline de données - interface Interceptor

- **Status**: Accepted
- **Date**: 2026-06-12

## Context

Le proxy doit forwarder des requêtes HTTP et des réponses (y compris streaming SSE). Dans les sprints futurs, ces flux devront être inspectés et modifiés par le moteur PII (tokenisation des requêtes, réhydratation des réponses).

Nous devons définir une architecture extensible qui:
1. Permet le forwarding transparent en V1 (QINDU-0001)
2. Permet l'ajout de l'inspection PII sans refacto du proxy
3. Préserve les métadonnées HTTP (headers, Content-Type, URL)
4. Supporte le streaming (pas de buffering complet obligatoire)

## Decision

- **Interface `Interceptor`** avec deux méthodes:
  - `InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error)`
  - `InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error)`
- **QINDU-0001**: implémentation `NoOpInterceptor` retournant les flux inchangés
- **Futur**: `PIIInterceptor` wrappant les readers pour tokenisation/réhydratation
- Le proxy reste maître du `io.Copy` et du cycle de vie des connexions

## Consequences

**Devient plus facile**:
- Ajout de l'inspection PII = implémenter une nouvelle struct, zéro changement dans le proxy
- Accès aux métadonnées HTTP pour décider du traitement (Content-Type, path, provider)
- Compatible SSE: le reader wrappé peut maintenir un buffer glissant
- Provider injectable dans l'interceptor

**Devient plus difficile**:
- Debugging: un bug dans l'interceptor peut corrompre le flux
- Performance: chaque wrapper ajoute une couche d'indirection (négligeable)
