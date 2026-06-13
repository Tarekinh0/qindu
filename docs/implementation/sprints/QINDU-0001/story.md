# QINDU-0001: Proxy TLS local sélectif - Fondation

**Status**: IN_PROGRESS
**Phase**: 1 - Fondation Proxy
**Sprint**: QINDU-0001

## Résumé

Implémenter le proxy TLS local qui est le squelette de tout Qindu. Le proxy écoute sur `127.0.0.1:8787`, accepte les connexions CONNECT du navigateur, fait du MITM TLS pour les domaines IA configurés, tunnel les autres domaines sans décryptage, sert la PAC et le health check, logge en JSON structuré sans PII, et s'arrête gracieusement.

C'est la fondation sur laquelle tout le reste (PII, tokenisation, vault, réhydratation) sera construit.

## Scope

### Inclus

1. **Module Go initialisé** (`github.com/Tarekinh0/qindu`, `cmd/agent/main.go`)
2. **Serveur HTTP unique** sur `127.0.0.1:8787` gérant :
   - `CONNECT` → handler MITM avec Hijacker
   - `GET /proxy.pac` → génération dynamique de la PAC
   - `GET /health` → statut minimal (up/down, version, uptime)
3. **DomainRouter** : route `MITM` pour les domaines IA configurés, `Tunnel` pour tout le reste
4. **Tunnel aveugle** : `io.Copy` sans décryptage pour les domaines non-IA
5. **MITM TLS** :
   - Génération CA racine ECDSA P-256, stockée sur disque chiffré DPAPI (`%PROGRAMDATA%\Qindu\ca.key`, chiffrée) dès QINDU-0001. En CI/tests Linux, la CA est en mémoire uniquement (DPAPI non disponible). La clé n'est jamais loggée.
   - Génération lazy de certificats feuilles (SAN: domaine + wildcard)
   - Cache mémoire `map[string]*tls.Certificate` avec `sync.RWMutex`
   - Validation upstream via trust store Windows (`x509.SystemCertPool`)
6. **Interface Interceptor** :
   - Définition de l'interface `Interceptor` (InterceptRequest, InterceptResponse)
   - Implémentation `NoOpInterceptor` (forwarding transparent)
   - Branché dans le pipeline de forwarding
7. **Pipeline de données** :
   - Requête: CONNECT → TLS handshake → lecture requête HTTP → Interceptor → forward upstream
   - Réponse: lecture réponse upstream → Interceptor → forward navigateur
   - Streaming avec `io.CopyBuffer` (buffer 32KB)
8. **PAC dynamique** : générée à chaque requête `/proxy.pac` depuis la config YAML
9. **Logging structuré** :
   - `log/slog` format JSON
   - Chaque CONNECT logge: timestamp, host, status, duration_ms, bytes_in, bytes_out
   - Aucun contenu de requête/réponse, aucun header sensible
10. **Configuration YAML** : `configs/default.yaml` lu au démarrage (pas de hot-reload)
11. **Service Windows** : binaire unique avec auto-détection console/service (`svc.IsAnInteractiveSession`)
12. **Graceful shutdown** : `http.Server.Shutdown(ctx)` avec timeout 30s
13. **Tests** :
    - Tests unitaires: DomainRouter, génération PAC, parsing config, génération certificats
    - Tests d'intégration (testcontainers-go): CONNECT end-to-end, MITM TLS, HTTP/2, bypass domaines non-IA, graceful shutdown, 502 Bad Gateway
14. **CI GitHub Actions** : `ubuntu-latest`, Go 1.22+1.23, `go vet`, `go test`, cross-compilation `GOOS=windows`

### Exclu (futurs sprints)

- ❌ Détection PII / recognizers
- ❌ Tokenisation / réhydratation
- ❌ Vault local
- ❌ Mode monitor / enforce
- ❌ Installer Windows / MSI
- ❌ Configuration automatique navigateur (policies Chrome/Edge)
- ❌ Adapters providers (ChatGPT, Claude)
- ❌ Endpoints admin protégés
- ❌ Tray icon / UI
- ❌ Page d'erreur fail-closed
- ❌ Hot-reload de la configuration

## Architecture cible pour ce sprint

```
cmd/agent/main.go
  └── internal/
        ├── proxy/
        │   ├── proxy.go          # Serveur HTTP + dispatch CONNECT/GET
        │   ├── connect.go        # Gestion tunnel CONNECT (MITM vs aveugle)
        │   ├── mitm.go           # Établissement double connexion TLS
        │   ├── forward.go        # Pipeline io.Copy + Interceptor
        │   ├── interceptor.go    # Interface + NoOpInterceptor
        │   └── graceful.go       # Graceful shutdown
        ├── tls/
        │   ├── ca.go             # Génération CA (ECDSA P-256)
        │   ├── cert_cache.go     # Cache lazy + RWMutex
        │   └── cert.go           # Génération certificat feuille (SAN wildcard)
        ├── policy/
        │   ├── config.go         # Chargement YAML
        │   ├── pac.go            # Génération PAC dynamique
        │   └── domain_router.go  # DomainRouter (MITM vs Tunnel)
        ├── logging/
        │   └── logger.go         # slog JSON
        └── service/
            ├── windows_service.go # Handler service Windows
            └── health.go         # Endpoint /health
```

## ADRs applicables

| ADR | Titre | Pertinence |
|-----|-------|-----------|
| ADR-001 | Module Go et structure du projet | Structure du code |
| ADR-002 | Architecture proxy CONNECT MITM + Interceptor | Design du proxy |
| ADR-003 | Stratégie TLS (CA unique, certs lazy, SAN wildcard) | Gestion TLS |
| ADR-004 | Pipeline de données (interface Interceptor) | Forwarding extensible |
| ADR-005 | Configuration statique et génération PAC dynamique | Config + PAC |
| ADR-006 | Service Windows (binaire unique, auto-détection) | Intégration Windows |
| ADR-007 | Stratégie de tests (testcontainers-go, cross-compilation) | Tests + CI |
| ADR-008 | Journalisation structurée (slog JSON sans PII) | Logging |
| ADR-009 | Modèle de concurrence du proxy | Goroutines |
| ADR-010 | Validation TLS upstream (trust store, compatibilité) | TLS upstream |

## Configuration de référence

```yaml
agent:
  listen_addr: "127.0.0.1"
  listen_port: 8787
  mode: "enforce"           # monitor | enforce (valeur du sprint 0001, ignorée)
  fail_mode: "fail_open"    # fail_open | fail_closed

tls:
  ca_name: "Qindu AI Privacy CA"
  ca_validity_years: 10
  ca_key_algorithm: "ECDSA_P256"
  cert_cache_enabled: true
  upstream_validation: "system"

providers:
  chatgpt:
    enabled: true
    domains:
      - "chatgpt.com"
  claude:
    enabled: true
    domains:
      - "claude.ai"

logging:
  level: "info"
  format: "json"
  pii_logging: false
```

## Critères d'acceptation

1. **Démarrage**: `go run ./cmd/agent/` lance le proxy en mode console. Les logs démarrage apparaissent en JSON.
2. **CONNECT MITM**: `curl -x http://127.0.0.1:8787 https://chatgpt.com/` établit un tunnel MITM, forwarde la requête, renvoie la réponse.
3. **CONNECT Tunnel**: `curl -x http://127.0.0.1:8787 https://example.com/` établit un tunnel aveugle (pas de décryptage).
4. **PAC**: `curl http://127.0.0.1:8787/proxy.pac` retourne un script JavaScript valide listant les domaines IA configurés.
5. **Health**: `curl http://127.0.0.1:8787/health` retourne `{"status":"up","version":"0.1.0"}`.
6. **Logs**: Chaque requête produit un log JSON avec `host`, `status`, `duration_ms`, `bytes_in`, `bytes_out`. Aucune PII, aucun header sensible.
7. **Graceful shutdown**: Ctrl+C → le proxy attend les connexions en cours (max 30s) puis s'arrête proprement.
8. **502 Bad Gateway**: Si l'upstream est injoignable, le proxy renvoie 502 (pas de crash).
9. **Certificats**: Le premier CONNECT vers `chatgpt.com` génère un certificat. Les CONNECTS suivants réutilisent le certificat caché.
10. **Tests verts**: `go test ./...` passe (unitaires + intégration). `go vet ./...` sans erreur.

## Contraintes de sécurité

- Le proxy bind **exclusivement** sur `127.0.0.1` (et `::1`), jamais `0.0.0.0`
- La clé privée de la CA n'est jamais loggée
- Les logs ne contiennent ni headers HTTP ni corps de requête/réponse
- Le NoOpInterceptor ne modifie pas les données
- `InsecureSkipVerify` n'est pas activé par défaut

## Notes pour l'implémentation

- Utiliser `net/http` standard avec `http.Hijacker` pour les CONNECT
- Utiliser `crypto/tls` pour la génération de certificats
- Utiliser `golang.org/x/sys/windows/svc` pour le service Windows
- Utiliser `testcontainers-go` avec une image `nginx:alpine` ou `httpbin` pour les tests d'intégration
- La structure de dossiers doit correspondre exactement au plan défini dans ADR-001
- Les packages `_windows.go` doivent avoir un équivalent `_other.go` (stub) pour la cross-compilation

## Dépendances Go prévues

```
github.com/Tarekinh0/qindu
golang.org/x/sys/windows/svc
gopkg.in/yaml.v3
testcontainers-go (tests uniquement)
```
