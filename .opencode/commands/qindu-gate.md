---
description: Gate final avant merge local.
agent: qindu-orchestrator
---

# /qindu-gate

Final gate before merging changes locally. Validates the current diff against all governance rules.

## Mandatory Context
- `@AGENTS.md`
- `@docs/decisions/README.md`
- `@ARCHITECTURE.md`

## Workflow

1. Show `git status`.
2. Show `git diff --stat`.
3. Show `git diff`.
4. Invoke reviews in parallel (or sequentially as needed):
   - **qindu-ciso** → produces `ciso-review.md` in a temporary gate context.
   - **qindu-dpo** → produces `dpo-review.md`.
   - **qindu-qa** → produces `qa-review.md`.
5. If CI/CD workflows or release artifacts are affected:
   - **qindu-release** → produces `release-review.md`.
6. Read all review files.
7. Produce final verdict:
   - **PASS**: All reviews are green.
   - **BLOCKED**: List all blocking points from each review.

The gate must not be bypassed. If any review is BLOCKED, the changes must not be merged.
