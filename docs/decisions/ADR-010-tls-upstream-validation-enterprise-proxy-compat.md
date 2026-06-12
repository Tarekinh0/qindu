# ADR-010: Validation TLS upstream et compatibilité proxies entreprise

- **Status**: Accepted
- **Date**: 2026-06-12

## Context

Le proxy Qindu établit une connexion TLS vers le serveur IA upstream. Dans un environnement entreprise, un autre proxy (Zscaler, Netskope, Palo Alto) peut déjà faire du MITM entre Qindu et le serveur IA. Ces proxies entreprise installent leur propre CA dans le trust store Windows.

Nous devons décider comment Qindu valide le certificat upstream, et s'il doit faire confiance aux CA du trust store système.

## Decision

- **Validation standard**: `x509.SystemCertPool` (trust store Windows)
- **Pas de `InsecureSkipVerify`** par défaut
- **Option configurable** `tls.upstream_validation: "system" | "insecure"` - mais `insecure` non documenté comme usage standard
- **Comportement**: si le certificat upstream est invalide (auto-signé sans CA dans le trust store, expiré, hostname mismatch) → **502 Bad Gateway**
- **Pas de pinning** de certificat en V1

## Consequences

**Devient plus facile**:
- Zéro configuration pour les utilisateurs derrière un proxy entreprise légitime
- Détection automatique des MITM malveillants
- Comportement cohérent avec le navigateur

**Devient plus difficile**:
- Certains environnements de test ou proxys maison sans CA installée nécessiteront le flag `insecure`
- Pas de protection contre une CA entreprise compromise (mais c'est une menace acceptée: si la CA entreprise est compromise, tout le poste l'est)
