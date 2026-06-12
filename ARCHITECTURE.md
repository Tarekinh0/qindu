# Qindu V1 Architecture

## 1. Ce qu'on construit

Qindu est un proxy local Windows qui s'intercale entre le navigateur et les services IA web (ChatGPT, Claude, Gemini). Il detecte les donnees sensibles dans les prompts, les remplace par des tokens avant qu'elles quittent la machine, et restaure les reponses avant affichage.

Principe :

```
Utilisateur tape "Resume ce ticket de Jane Doe, jane@example.com"
    → Qindu envoie "Resume ce ticket de <<PII_PERSON_0001>>, <<PII_EMAIL_0002>>"
    → Le fournisseur IA voit les tokens, jamais les vraies donnees
    → Qindu rehydrate la reponse et affiche les vraies valeurs
```

Le produit ne modifie pas l'interface web, ne necessite pas d'extension navigateur, et n'intercepte que les domaines IA. Le reste du trafic (banque, sante, SSO, mail) passe en direct.

## 2. Perimetre

### V1

- Windows 10/11
- Chrome, Edge
- Proxy TLS local selectif (HTTP/1.1 + HTTP/2)
- CA racine unique ECDSA P-256, certificats feuilles lazy
- PAC dynamique servie par le proxy
- QUIC desactive via policies navigateur
- MITM sur domaines IA, tunnel aveugle sur le reste
- Pipeline Interceptor (NoOp en QINDU-0001, PII ensuite)
- Moteur PII Go-native (regex, validateurs, contexte)
- Tokenisation reversible (format `<<PII_TYPE_ID>>`)
- Vault local chiffre DPAPI
- Rehydratation streaming et non-streaming
- Modes monitor et enforce
- Logs slog JSON sans PII
- Graceful shutdown 30s
- Service Windows installe via MSI

### Hors V1

Kernel drivers, autres navigateurs/OS, extension obligatoire, SDK, console entreprise, fleet management, inspection trafic complet, PDF/images.

## 3. Stack technique

| Choix | Pourquoi |
|-------|----------|
| Go | Binaire unique, pas de runtime, TLS/HTTP natif |
| Module `github.com/Tarekinh0/qindu` | Repo GitHub existant |
| Binaire `cmd/agent/` | Point d'entree unique (console + service) |
| ECDSA P-256 | CA et certs feuilles, rapide, universel |
| DPAPI | Chiffrement vault et cle CA, lie a la machine |
| YAML | Config statique, source unique de verite |
| slog JSON | Logs structures, stdlib Go 1.21+ |
| testcontainers-go | Tests integration avec vrais serveurs HTTPS |
| GitHub Actions ubuntu-latest | Cross-compilation `GOOS=windows` |

Concurrence : une goroutine par connexion CONNECT. Cache certificats protege par `sync.RWMutex`.

## 4. Arborescence

```
cmd/agent/main.go                    Point d'entree

internal/
  proxy/proxy.go                     Serveur HTTP (CONNECT + GET)
  proxy/connect.go                   Tunnel CONNECT (MITM vs aveugle)
  proxy/mitm.go                      Double handshake TLS
  proxy/forward.go                   io.Copy + Interceptor
  proxy/interceptor.go               Interface + NoOp
  proxy/graceful.go                  Shutdown 30s

  tls/ca.go                          Generation CA ECDSA P-256
  tls/cert_cache.go                  Cache memoire + RWMutex
  tls/cert.go                        Certificats feuilles (SAN wildcard)
  tls/truststore_windows.go          Trust store Windows

  policy/config.go                   Chargement YAML
  policy/pac.go                      Generation PAC dynamique
  policy/domain_router.go            MITM vs Tunnel

  providers/provider.go              Interface adapter
  providers/chatgpt/                 ChatGPT web
  providers/claude/                  Claude web

  pii/analyzer.go                    Moteur detection
  pii/recognizer.go                  Interface Recognizer
  pii/recognizers/*.go               Email, phone, IBAN, CB, JWT, API key

  tokenize/tokenizer.go              PII -> token
  tokenize/detokenizer.go            Token -> PII
  tokenize/stream_rehydrator.go      Buffer glissant SSE

  vault/vault.go                     Interface vault
  vault/crypto_windows.go            Chiffrement DPAPI

  logging/logger.go                  slog JSON
  service/windows_service.go         Handler service Windows
```

## 5. Fonctionnement du proxy

```
Browser ──▶ http://127.0.0.1:8787/proxy.pac
              La PAC renvoie les domaines IA vers le proxy,
              tout le reste en DIRECT.

Browser ──▶ CONNECT chatgpt.com:443 ──▶ Proxy Qindu
              │
              ├── Domaine non-IA → io.Copy aveugle (pas de decryptage)
              │
              └── Domaine IA → MITM :
                    ├── TLS handshake avec certificat Qindu (navigateur)
                    ├── TLS handshake vers upstream (trust store Windows)
                    ├── Lecture requete HTTP
                    ├── Interceptor.InterceptRequest() (NoOp en 0001)
                    ├── Forward upstream
                    ├── Lecture reponse HTTP
                    ├── Interceptor.InterceptResponse() (NoOp en 0001)
                    └── Forward navigateur

Browser ──▶ GET /health    → {"status":"up","version":"0.1.0"}
Browser ──▶ GET /proxy.pac → script PAC genere depuis le YAML
```

L'Interceptor est une interface Go qui permet d'ajouter la detection PII plus tard sans toucher au proxy :

```go
type Interceptor interface {
    InterceptRequest(req *http.Request) (*http.Request, io.ReadCloser, error)
    InterceptResponse(resp *http.Response) (*http.Response, io.ReadCloser, error)
}
```

Le proxy bind sur `127.0.0.1:8787`. Pas d'exposition reseau. Une regle firewall Windows (posee par l'installer) renforce la restriction au loopback.

## 6. Gestion TLS

### CA racine

Une seule CA ECDSA P-256 par machine, valide 10 ans. Cle privee dans `%PROGRAMDATA%\Qindu\ca.key`, chiffree DPAPI, ACL SYSTEM + Administrateurs. Installee dans le trust store machine Windows. Supprimee a la desinstallation.

### Certificats feuilles

Generes a la volee au premier CONNECT vers un domaine IA. Stockes en memoire (`map[string]*tls.Certificate` + `sync.RWMutex`), pas de persistence disque. Chaque certificat couvre le domaine et ses sous-domaines (SAN: `DNS:domaine.com` + `DNS:*.domaine.com`).

### Validation upstream

Le proxy valide le certificat du serveur IA via le trust store Windows (`x509.SystemCertPool`). Les proxies d'entreprise legitimes (Zscaler, Netskope, Palo Alto) sont acceptes si leur CA est dans le trust store. Echec de validation = 502 Bad Gateway. Pas de `InsecureSkipVerify` par defaut.

### QUIC

Desactive via les policies Chrome/Edge (`QuicAllowed = 0`). Pas de blocage actif au niveau proxy. Si QUIC passe malgre les policies, le trafic bypass Qindu. Limite assumee.

## 7. Configuration

Fichier YAML lu au demarrage, pas de rechargement a chaud.

```yaml
agent:
  listen_addr: "127.0.0.1"
  listen_port: 8787
  mode: "enforce"
  fail_mode: "fail_open"

tls:
  ca_name: "Qindu AI Privacy CA"
  ca_validity_years: 10
  ca_key_algorithm: "ECDSA_P256"
  upstream_validation: "system"

providers:
  chatgpt:
    enabled: true
    domains: ["chatgpt.com"]
  claude:
    enabled: true
    domains: ["claude.ai"]

pii:
  entities: [EMAIL, PHONE, IBAN, CREDIT_CARD, API_KEY, JWT]
  min_score: 0.7

vault:
  ttl_hours: 168
  encryption: "dpapi"

logging:
  level: "info"
  format: "json"
```

La PAC est servie sur `http://127.0.0.1:8787/proxy.pac`, generee dynamiquement depuis la section `providers` du YAML. Pas de fichier PAC separe a synchroniser.

Modes de defaillance : `fail-open` (defaut) laisse passer le trafic si l'agent est down. `fail-closed` bloque les domaines IA.

## 8. Pipeline PII (sprints futurs)

Les sections suivantes decrivent le comportement cible apres QINDU-0001.

### Detection

Moteur Go-native base sur regex, validateurs (Luhn, IBAN), checksums, mots de contexte, et score de confiance. Types detectes : emails, telephones, IP, URLs sensibles, cles API, JWT, IBAN, cartes bancaires, identifiants internes configurables. Chevauchements resolus par : couverture la plus longue, score le plus eleve, priorite d'entite.

### Tokenisation

Format `<<PII_TYPE_ID>>` (ex: `<<PII_EMAIL_0001>>`). Tokens stables dans une conversation, detectables en streaming, sans valeur sensible. Meme valeur = meme token dans une meme conversation.

### Vault

Mapping `token → valeur` chiffre DPAPI, persistant, scope par provider et conversation. TTL configurable (24h, 7j, infini). Jamais logge. Supprimable manuellement.

### Rehydratation

Non-streaming : remplacement des tokens dans le corps complet.
Streaming : buffer glissant de quelques KB pour reconstituer les tokens coupes entre chunks SSE. Si un token est partiel ou corrompu, il reste visible (pas d'invention de valeur).

### Tokens modifies par le modele

Le LLM peut alterer les tokens : `<<PII_PERSON_0001>>` (exact), `PII_PERSON_0001` (fallback sans chevrons), `<<PII_PERSON_0001>>'s` (ponctuation ignoree). Les formes trop eloignees restent visibles.

### Modes

Monitor : detection sans modification. Enforce : tokenisation avant envoi + blocage possible.

## 9. Logging

slog JSON. Chaque requete logge `host, status, duration_ms, bytes_in, bytes_out`. En mode PII : `entities[], entity_count, mode, latency_ms, pii_values_logged: false`.

Interdit dans les logs : prompts, reponses, valeurs PII, mappings token/valeur, headers (Authorization, Cookie), tokens de session, IP (toujours 127.0.0.1).

## 10. Securite

- **Least decrypt** : MITM uniquement sur domaines IA
- **Local-first** : tout le traitement sur la machine, zero cloud
- **Pas de PII** dans les logs, memoire non protegee, crash dumps
- **Graceful shutdown** 30s
- **Endpoints** : `/proxy.pac` public, `/health` statut minimal, `/admin` desactive, `/debug` desactive en production
- **Pas de telemetrie**

Surfaces sensibles : cle privee CA (DPAPI, ACL), vault (DPAPI), config YAML (permissions), port proxy (127.0.0.1, firewall loopback).

## 11. Installation (sprint separe, QINDU-0002+)

L'installer MSI cree le service Windows, genere la CA, l'installe dans le trust store, configure les policies Chrome/Edge (URL PAC + QUIC desactive), pose la regle firewall, et demarre le service.

La desinstallation arrete le service, supprime les policies, la CA du trust store, la cle CA, les fichiers, et la regle firewall. Le vault est conserve ou supprime selon le choix de l'utilisateur.

En developpement, le proxy tourne en mode console (`go run ./cmd/agent`). Le meme binaire detecte automatiquement s'il est lance par le SCM Windows ou en interactif.

## 12. Tests

**Unitaires** : recognizers, validateurs, overlaps, tokenisation, stream rehydrator, vault, redaction logs, generation certificats, DomainRouter, generation PAC, parsing YAML.

**Integration** (testcontainers-go + Docker) : CONNECT end-to-end, TLS MITM, HTTP/1.1 et HTTP/2, SSE avec tokens coupes, PAC routing, bypass domaines non-IA, graceful shutdown, 502 Bad Gateway.

**Securite** : bind 127.0.0.1 verifie, permissions fichiers, vault chiffre illisible sans DPAPI, absence de PII dans logs/erreurs/crash dumps, tokens inconnus non modifies.

Les parties Windows-specifiques (DPAPI, trust store, service) sont mockees en CI et testees manuellement sur Windows.

## 13. CI/CD

GitHub Actions sur `ubuntu-latest`, Go 1.22 et 1.23. `go vet`, `go test`, cross-compilation `GOOS=windows GOARCH=amd64`. Docker requis pour les tests integration.

Le packaging MSI, la signature de code et la provenance SLSA viendront dans un sprint dedie.

## 14. Performances

- Latence ajoutee sur prompt court : < 300ms (cible 50-150ms)
- Rehydratation streaming : quelques ms par chunk
- Memoire : < 100 MB
- Le proxy ne bufférise pas les reponses completes, n'analyse pas les assets (JS, CSS, images), et ne demarre pas de moteur externe par requete.

## 15. Maintenance et limites

Le code fournisseur est isole dans `internal/providers/`. Un changement d'API ChatGPT ne touche pas le proxy ou le moteur PII.

Limites assumées : faux negatifs sur noms et adresses, tokens alteres par le modele, historique non rehydratable si vault expire, contournement possible par admin local, bypass QUIC si policies non appliquees.

## 16. Apres V1

macOS, Firefox, Gemini/Copilot/Perplexity, moteur NER local (ONNX), fichiers texte/PDF, console entreprise, fleet management, SIEM export, proxy transparent OS, anti-bypass renforce.

## 17. Resume des decisions

```
Langage          Go
Module           github.com/Tarekinh0/qindu
Binaire          cmd/agent/ → agent.exe
Cible            Windows, Chrome, Edge
Interception     Proxy TLS selectif (MITM IA, tunnel aveugle reste)
Routage          PAC dynamique depuis YAML
TLS CA           ECDSA P-256 unique, 10 ans, cle DPAPI
TLS certs        Lazy generation, cache memoire, SAN wildcard
TLS upstream     Validation trust store Windows
QUIC             Desactive via policies navigateur
Pipeline         Interface Interceptor (NoOp → PII)
HTTP             HTTP/1.1 + HTTP/2, meme port CONNECT + endpoints
Config           YAML statique, pas de hot-reload
Logs             slog JSON, zero PII
Port             127.0.0.1:8787, firewall loopback
Arret            Graceful shutdown 30s
Service          Binaire unique console/service
Tests            testcontainers-go, cross-compilation CI
Licence          AGPL-3.0 + dual licensing
```

## 18. Architecture Decision Records

Les 10 ADRs sont dans `docs/decisions/`. Statut : Accepted.

| ID | Titre |
|----|-------|
| ADR-001 | Module Go et structure du projet |
| ADR-002 | Architecture proxy CONNECT MITM + Interceptor |
| ADR-003 | Strategie TLS (CA unique, certs lazy, SAN wildcard) |
| ADR-004 | Pipeline de donnees (interface Interceptor) |
| ADR-005 | Configuration statique et generation PAC dynamique |
| ADR-006 | Service Windows (binaire unique, auto-detection) |
| ADR-007 | Strategie de tests (testcontainers-go, cross-compilation) |
| ADR-008 | Journalisation structuree (slog JSON sans PII) |
| ADR-009 | Modele de concurrence du proxy |
| ADR-010 | Validation TLS upstream et compatibilite proxies entreprise |
