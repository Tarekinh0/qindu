# ADR-005: Configuration statique et génération PAC dynamique

- **Status**: Accepted
- **Date**: 2026-06-12

## Context

Le proxy a besoin de configuration (port, domaines IA, mode, etc.) et doit servir un fichier PAC au navigateur pour le routage. Nous devons décider:
1. Format et cycle de vie de la configuration
2. Comment la PAC est générée et servie

## Decision

- **Configuration**: fichier YAML statique (`configs/default.yaml`), lu au démarrage uniquement
- **Pas de rechargement à chaud** en V1 - modification = redémarrage du service
- **PAC**: générée dynamiquement à chaque requête `/proxy.pac` depuis la config YAML
- **Source unique de vérité**: la config YAML - pas de fichier PAC séparé à synchroniser
- **Port par défaut**: 8787, configurable

## Consequences

**Devient plus facile**:
- Développement: un seul fichier à éditer
- Pas de désynchronisation config ↔ PAC
- Pas de complexité de hot-reload

**Devient plus difficile**:
- Changement de config en production nécessite un redémarrage
- Pas de rollback à chaud
