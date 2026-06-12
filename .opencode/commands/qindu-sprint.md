---
description: Lance un cycle complet de story Qindu avec DPO, CISO, DevSecOps, QA et Release.
agent: qindu-orchestrator
---

# /qindu-sprint

Start a full sprint cycle for a Qindu backlog item.

## Usage
```
/qindu-sprint <ID>
```
Example: `/qindu-sprint QINDU-001`

## Mandatory Context
- `@docs/implementation/backlog/qindu-v1-backlog.yaml`
- `@ARCHITECTURE.md`
- `@docs/decisions/README.md`
- `@AGENTS.md`

First, show current git status (`git status`).

## Workflow (14 steps)

1. Extract the item with ID `<ID>` from `qindu-v1-backlog.yaml`.
2. Create the sprint folder: `docs/implementation/sprints/<ID>/`.
3. Write `story.md` in the sprint folder (use `@docs/implementation/templates/story.md`).
4. Invoke **qindu-dpo** to produce `dpo-requirements.md` in the sprint folder.
5. Invoke **qindu-ciso** to produce `ciso-requirements.md` in the sprint folder.
   - If either DPO or CISO returns BLOCKED, produce `closure.md` with verdict BLOCKED and stop.
6. Invoke **qindu-devsecops** to implement the story (code + tests) and write `dev-notes.md`.
7. Invoke **qindu-ciso** to produce `ciso-review.md` (max 2 retry loops if BLOCKED).
8. Invoke **qindu-dpo** to produce `dpo-review.md` (max 2 retry loops if BLOCKED).
9. Invoke **qindu-qa** to produce `qa-review.md`.
10. If CI/CD, build, packaging, or release artifacts are affected, invoke **qindu-release** for `release-review.md`.
11. Produce `closure.md` with final verdict: PASS or BLOCKED.
12. If PASS, update the backlog YAML: set `status: DONE`, record `last_sprint_folder` and evidence.
13. If BLOCKED, update the backlog YAML: set `status: BLOCKED` and record `blocked_reason`.
14. Display the final verdict and summary.

Never modify ADRs to make a story pass.
