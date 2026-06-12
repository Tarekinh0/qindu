# ADR-003: Stratégie TLS - CA unique, certificats lazy, SAN wildcard

- **Status**: Accepted
- **Date**: 2026-06-12

## Context

Le proxy MITM nécessite une CA locale pour signer des certificats à la volée. Nous devons choisir:
1. Le nombre de CA (une par machine vs une par fournisseur)
2. L'algorithme cryptographique
3. La stratégie de génération et cache des certificats feuilles
4. Les Subject Alternative Names (SAN)

## Decision

- **CA**: une seule CA racine ECDSA P-256 par machine, validité 10 ans
- **Clé CA**: stockée dans `%PROGRAMDATA%\Qindu\ca.key`, chiffrée via DPAPI, ACL restrictives
- **Certificats feuilles**:
  - Génération lazy au premier CONNECT
  - Cache mémoire `map[string]*tls.Certificate` protégé par `sync.RWMutex`
  - Algorithme ECDSA P-256
  - SAN: `DNS:domaine.com` + `DNS:*.domaine.com`
- **Pas de persistence disque** pour les certificats feuilles (régénérés au redémarrage)
- **Validation upstream**: via trust store Windows (`x509.SystemCertPool`)

## Consequences

**Devient plus facile**:
- Compatible avec les proxies entreprise (Zscaler et al.) sans config spéciale
- Génération ultrarapide (ECDSA P-256 < 1ms)
- Wildcard évite les erreurs sur les sous-domaines CDN

**Devient plus difficile**:
- Rotation de CA nécessite une réinstallation complète
- Pas d'isolation par provider (une CA compromise = tous les domaines compromis - acceptable car localhost)
