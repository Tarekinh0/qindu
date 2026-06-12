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
| `/qindu-sprint <ID>` | Start a full sprint cycle (Orchestrator → DPO/CISO → DevSecOps → Reviews) |
| `/qindu-backlog-status` | Show macro project status (blocked items, next item, progress) |
| `/qindu-backlog-refine` | Refine the backlog (YAML, roadmap, risks) |
| `/qindu-gate` | Final validation gate before merging changes |
| `/qindu-help` | Show this help |

## Governance Workflow

Qindu uses a strict multi-agent model:

1. **Backlog refinement**: Items are drafted and refined in the canonical backlog.
2. **Status check**: Use `/qindu-backlog-status` to see what's next.
3. **Launch sprint**: `/qindu-next` finds the next READY item and starts the sprint.
4. **Sprint execution** (automatic via `/qindu-sprint`):
   - Orchestrator creates the story
   - DPO writes privacy requirements
   - CISO writes security requirements
   - DevSecOps implements with tests
   - CISO reviews the implementation
   - DPO reviews the implementation
   - QA validates tests and quality
   - Release validates CI/CD (if applicable)
   - Orchestrator produces closure
5. **Final validation**: `/qindu-gate` ensures nothing was missed before merging.

## Project

Qindu is a local AI Privacy Proxy that sits between the browser and web-based AI services, tokenizing PII before it leaves the machine and rehydrating AI responses locally.

- Language: Go
- Platform: Windows
- Key concerns: TLS interception, PII detection, vault encryption (DPAPI), browser integration
