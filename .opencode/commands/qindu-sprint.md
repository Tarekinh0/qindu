---
description: Lance un cycle complet de story Qindu — grill-me → DPO/CISO → DevSecOps → Peer → CISO/DPO → QA/Release → QEMU → Closure.
agent: qindu-orchestrator
---

# /qindu-sprint

Start a full sprint cycle for a Qindu backlog item.

## Usage
```
/qindu-sprint <ID>
```
Example: `/qindu-sprint QINDU-0009`

## Mandatory Context
- `@AGENTS.md`
- `@docs/implementation/backlog/qindu-v1-backlog.yaml`
- `@docs/implementation/backlog/qindu-v1-roadmap.md`
- `@docs/decisions/README.md`

First, show current git status (`git status`).

## Workflow (8 steps — strictly sequential per AGENTS.md)

1. **Story Init**: Orchestrator uses the **grill-me** skill to interview the human about design choices, tradeoffs, and boundaries. Then writes `story.md` in `docs/implementation/sprints/<ID>/`.

2. **Design**: 
   - Invoke `qindu-dpo` → `dpo-requirements.md`
   - Invoke `qindu-ciso` → `ciso-requirements.md`
   - If either returns BLOCKED, produce `closure.md` with verdict BLOCKED and stop. Orchestrator may negotiate using cross-sprint context only.

3. **Implementation**: Invoke `qindu-devsecops` with `story.md` + `dpo-requirements.md` + `ciso-requirements.md` + git diff. Writes code, tests, and `dev-notes.md`. Orchestrator provides zero code guidance.

4. **Peer Review**: Invoke `qindu-peer-reviewer` with `story.md` + git diff only (blank-slate). No `dev-notes.md`, no requirements docs. If REJECT or FIX_AND_RESUBMIT, return to step 3. Loop 3→4 until MERGE_READY.

5. **Security & Privacy Review**:
   - Invoke `qindu-ciso` → `ciso-review.md` (story.md + git diff only)
   - Invoke `qindu-dpo` → `dpo-review.md` (story.md + git diff only)
   - If BLOCKED by either, return to step 3. Orchestrator may negotiate using cross-sprint context only — never code.

6. **Quality & Release Validation**:
   - Invoke `qindu-qa` → `qa-review.md` (story.md + git diff only)
   - Invoke `qindu-release` → `release-review.md` if CI/CD, build, packaging, or release artifacts are affected (story.md + git diff only)
   - If BLOCKED by either, return to step 3.

7. **VM & API Integration Test**: Invoke `qindu-qemu-tester` with `story.md` + MSI artifact + test instructions. Deploys MSI to Windows QEMU VM. From QINDU-0009 onward, also validates the full enforce pipeline with real AI provider calls (API key from `.ssh/openai.key`). Writes `qemu-test-report.md`. If BLOCKED, returns to step 3 and re-enters the full pipeline (steps 3→4→5→6→7).

8. **Closure**: Read all verdicts. If ALL gates say PASS (or MERGE_READY), produce `closure.md` — a summary, not a judgment. Update the risk register and backlog:
   - If PASS: set `status: DONE`, record `last_sprint_folder` and evidence
   - If BLOCKED: set `status: BLOCKED` and record `blocked_reason`
   - Extract findings, cross-reference risks, add new risks (MEDIUM+ or 2+ reviewers), sync `qindu-risk-register.md`

## Reviewer Input Contract

Every reviewer receives exactly: `story.md` + git diff. Nothing else. No `dev-notes.md`, no code excerpts, no orchestration hints. (Peer Reviewer also receives existing `qemu-test-report.md` on fix iterations.)

## Finding Resolution Rule

Every finding MUST be either fixed by DevSecOps or explicitly accepted by the reviewer who raised it. Orchestrator cannot accept on a reviewer's behalf — regardless of severity.

Never modify ADRs to make a story pass.
