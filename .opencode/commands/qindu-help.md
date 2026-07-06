---
description: Liste les commandes disponibles et explique brièvement le workflow Qindu.
agent: qindu-orchestrator
---

# /qindu-help

Displays all available Qindu commands and explains the governance workflow.

## Available Commands

| Command | Description |
|---------|-------------|
| `/qindu-next` | Find the next READY backlog item and launch a sprint |
| `/qindu-sprint <ID>` | Start a full sprint cycle (grill-me → Design → DevSecOps → Peer → CISO/DPO → QA/Release → QEMU → Closure) |
| `/qindu-backlog-status` | Show macro project status with risk reconciliation |
| `/qindu-backlog-refine` | Refine the backlog (YAML, roadmap, risks) |
| `/qindu-gate` | Final validation gate before merging changes |
| `/qindu-help` | Show this help |

## Governance Workflow

Qindu uses a strict multi-agent model with a document-clerk orchestrator:

1. **Backlog refinement**: Items are drafted and refined in the canonical backlog.
2. **Status check**: Use `/qindu-backlog-status` to see what's next.
3. **Launch sprint**: `/qindu-next` finds the next READY item and starts the sprint.
4. **Sprint execution** (8 steps via `/qindu-sprint`):
   - Grill-me interview (human design choices)
   - DPO + CISO write requirements
   - DevSecOps implements with tests
   - Peer Reviewer blank-slate code review (loop until MERGE_READY)
   - CISO + DPO security & privacy review
   - QA + Release quality & supply chain validation
   - QEMU + API integration test (real prompts through proxy)
   - Orchestrator writes closure (summary, not judgment)
5. **Final validation**: `/qindu-gate` ensures nothing was missed before merging.

## Finding Resolution Rule

Every finding MUST be fixed or explicitly accepted by the reviewer who raised it. Orchestrator cannot override verdicts — regardless of severity.

## Project

Qindu is a local AI Privacy Proxy that sits between the browser and web-based AI services, tokenizing PII before it leaves the machine and rehydrating AI responses locally.

- Language: Go
- Platform: Windows
- Key concerns: TLS interception, PII detection, vault encryption (DPAPI), browser integration
