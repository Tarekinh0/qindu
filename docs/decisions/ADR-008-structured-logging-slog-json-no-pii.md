# ADR-008: Journalisation structurée - slog JSON sans PII

- **Status**: Accepted
- **Date**: 2026-06-12

## Context

Les logs sont essentiels pour le debugging du proxy, mais ne doivent jamais contenir de PII. L'ARCHITECTURE.md liste exhaustivement ce qui est interdit dans les logs (prompts, réponses, valeurs PII, headers sensibles, cookies, tokens de session, IP).

Nous devons choisir une bibliothèque de logging et un format.

## Decision

- **Bibliothèque**: `log/slog` (standard Go 1.21+)
- **Format**: JSON structuré
- **Niveaux**: DEBUG, INFO, WARN, ERROR
- **Métriques loggées**: timestamp, niveau, message, host (domaine cible), statut HTTP, durée, bytes in/out, provider, entités détectées (nom, pas valeur), mode, latence
- **Garantie**: flag `pii_values_logged: false` dans chaque log PII
- **Redaction**: package `internal/logging/redaction.go` pour valider l'absence de PII dans les messages

## Consequences

**Devient plus facile**:
- Parsing automatique (jq, Loki, ELK)
- Zero dépendance externe (stdlib)
- Audit de conformité: le flag `pii_values_logged` est vérifiable

**Devient plus difficile**:
- Développement: les logs JSON sont moins lisibles en console que du texte
- Risque: un développeur pourrait logger une valeur PII par erreur - la redaction.go doit servir de garde-fou
