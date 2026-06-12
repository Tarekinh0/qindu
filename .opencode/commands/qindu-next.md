---
description: Lit le backlog canonique, trouve le prochain item READY, crée le dossier de sprint, et lance l'Orchestrateur.
agent: qindu-orchestrator
---

# /qindu-next

Reads the canonical backlog and roadmap, finds the next READY item, creates the sprint folder, and launches the sprint.

## Workflow

1. Read `@docs/implementation/backlog/qindu-v1-backlog.yaml`.
2. Read `@docs/implementation/backlog/qindu-v1-roadmap.md`.
3. Find the next item with status `READY` (dependencies OK, human inputs provided).
4. If no item is READY:
   - Explain why (blocking dependencies, missing human inputs).
   - Show the list of WAITING_INPUT and BLOCKED items with reasons.
   - Stop.
5. If an item is READY:
   - Extract its ID.
   - Create sprint folder `docs/implementation/sprints/<ID>/`.
   - Launch `/qindu-sprint <ID>`.
