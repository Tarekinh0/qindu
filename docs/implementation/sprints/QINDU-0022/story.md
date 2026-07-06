# QINDU-0022 — Debug Flow Inspector

**Sprint**: Endpoint de debug pour visualiser ingress/egress du pipeline enforce
**Status**: In progress
**Go version**: 1.26

## Motivation

Le pipeline enforce tokenise le PII avant egress et réhydrate avant de répondre au browser. Les logs confirment `tokenized_count: 1` mais l'opérateur ne peut jamais **voir** le corps réel qui sort de la machine. On veut un moyen visuel, côte-à-côte, de comparer ce que le browser envoie (PII en clair) et ce que Qindu forward à l'upstream (tokens).

## Feature

### B — Endpoint GET /debug/flow

Un endpoint HTTP local-only qui expose un ring buffer en mémoire capturant les N dernières paires requête→réponse.

**Réponse JSON** :
```json
{
  "entries": [
    {
      "id": 1,
      "timestamp": "2026-07-06T15:04:05Z",
      "host": "api.openai.com",
      "method": "POST",
      "path": "/v1/chat/completions",
      "ingress_body": "{\"messages\":[{\"role\":\"user\",\"content\":\"Hello alice@corp.com\"}]}",
      "egress_body": "{\"messages\":[{\"role\":\"user\",\"content\":\"Hello <<EMAIL_1>>\"}]}",
      "entity_summary": {"EMAIL": 1},
      "body_bytes_in": 72,
      "body_bytes_out": 62
    }
  ],
  "buffer_size": 50,
  "entries_count": 1
}
```

**Contraintes** :
- Ring buffer de 50 entrées max (FIFO, éviction du plus ancien)
- Endpoint accessible uniquement sur `127.0.0.1` (localhost)
- Contenu limité aux N derniers flux — pas de persistance disque
- Flag de config `debug.flow_inspector: true` (défaut: `false`)
- WARNING au startup quand activé : `"FLOW INSPECTOR ENABLED — request bodies held in memory. Disable in production."`

### C — Log événement structuré DEBUG

Un log JSON émis à chaque transformation enforce, niveau DEBUG :

```json
{
  "event": "enforce_transform",
  "host": "api.openai.com",
  "path": "/v1/chat/completions",
  "detected_count": 3,
  "entity_summary": {"EMAIL": 1, "NAME": 2},
  "body_bytes_in": 847,
  "body_bytes_out": 812,
  "pii_values_logged": false
}
```

Émis dans `EnforceInterceptor.InterceptRequest()` (pas `scanBody` — on veut le résumé post-transformation). Optionnel : aussi sur `InterceptResponse()` avec `rehydration_count`.

## Architecture

### Nouveaux fichiers

| File | Purpose |
|------|---------|
| `internal/interceptor/debug.go` | `FlowRing`, `DebugInterceptor`, handler HTTP |

### Modifications existantes

| File | Change |
|------|--------|
| `internal/proxy/proxy.go` | Créer `FlowRing` si config activée ; handler `/debug/flow` dans `handleHTTP` ; passer ref à `NewProxy` |
| `internal/proxy/mitm.go` | Wrapper `DebugInterceptor` autour de `p.interceptor` en mode enforce |
| `internal/policy/config.go` | Nouveau bloc `debug:` avec `flow_inspector: *bool` |

### Design décisions

- **DD-1** — `DebugInterceptor` implémente `Interceptor`, wrap l'interceptor réel. Zéro impact sur `handleMITM` ou `forwardHTTPRoundTrip`.
- **DD-2** — `FlowRing` est un buffer circulaire thread-safe (`sync.Mutex`, pas `sync.RWMutex` — le handler lit et l'interceptor écrit, contention faible).
- **DD-3** — Le ring buffer stocke les corps en clair (PII). C'est accepté par le DPO (l'humain) car : flag désactivé par défaut, localhost only, mémoire uniquement, 50 entrées max.
- **DD-4** — `entity_summary` utilise les types d'entités détectés (`EMAIL`, `PHONE`, `NAME`, etc.) avec compteurs. Pas de valeurs PII.
- **DD-5** — L'événement `enforce_transform` est émis au niveau DEBUG. En production (INFO), zéro impact sur les logs.

## Acceptance Criteria

| AC | Description |
|----|-------------|
| AC-1 | `debug.flow_inspector: false` → pas de `/debug/flow`, pas de ring buffer, overhead zéro |
| AC-2 | `debug.flow_inspector: true` → endpoint `/debug/flow` répond sur `127.0.0.1` uniquement |
| AC-3 | Ring buffer capture ingress (pre-tokenization) et egress (post-tokenization) pour les 50 dernières requêtes |
| AC-4 | Éviction FIFO : la 51ème entrée supprime la plus ancienne |
| AC-5 | Événement `enforce_transform` émis à chaque transformation, niveau DEBUG |
| AC-6 | `pii_values_logged: false` sur l'événement de log — compteurs et types uniquement, jamais de valeurs |
| AC-7 | WARNING explicite au startup quand `flow_inspector: true` |
| AC-8 | Aucune persistance disque — redémarrage vide le buffer |
| AC-9 | Tests : ring buffer (concurrence, éviction, taille), DebugInterceptor (wrap, pass-through), handler HTTP (localhost only, JSON valide) |
| AC-10 | Zéro régression : tous les tests existants passent |
