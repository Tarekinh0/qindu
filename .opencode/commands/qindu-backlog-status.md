---
description: Affiche l'état macro du projet (items bloqués, inputs manquants, prochain item).
agent: qindu-orchestrator
---

# /qindu-backlog-status

Displays the macro status of the Qindu project.

## Workflow

1. Read `@docs/implementation/backlog/qindu-v1-backlog.yaml`.
2. Read `@docs/implementation/backlog/qindu-v1-roadmap.md`.
3. Generate a macro status report:
   - **Next READY item**: The next item that can be started.
   - **BLOCKED items**: List of BLOCKED items with reasons (dependencies, missing inputs).
   - **WAITING_INPUT items**: Items waiting for human decisions or inputs.
   - **IN_PROGRESS items**: Currently active sprints.
   - **DONE items**: Completed items.
4. Summarize progress against the roadmap phases.
5. Highlight any stalled or at-risk items.

Use the risk register to flag critical risks.
