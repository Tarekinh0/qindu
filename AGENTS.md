# Qindu agent rules

Qindu is a local AI Privacy Proxy that sits between the browser and web-based AI services, tokenizing PII before it leaves the machine and rehydrating AI responses locally.

Non-negotiable rules:
- Do not weaken the Architecture Decision Records in the `docs/decisions/` folder.
- Do not introduce user accounts, telemetry, analytics, tracking, or persistent user identifiers.
- PII must never be logged, stored unencrypted, or sent to external services in clear text.
- The vault (PII token store) must be encrypted at rest via DPAPI and only accessible locally.
- Decrypted PII and intercepted traffic must only exist in memory-backed storage.
- No feature is complete without privacy, security, and regression tests.
- Any change affecting TLS interception, cryptography, PII detection, vault, logging, or CI/CD must go through DPO and CISO review.

ADR anchors:
- ADRs will be created in `docs/decisions/` as the project evolves. Each ADR must be respected by all agents.

Never commit secrets, production credentials, private keys, CA private keys, real user PII, or real browser traffic samples.

## Qindu Backlog Governance

Before taking any action, all agents MUST read the canonical backlog and roadmap to understand the current context and priorities. The source of truth is located at:
- `docs/implementation/backlog/qindu-v1-backlog.yaml`
- `docs/implementation/backlog/qindu-v1-roadmap.md`

## Multi-Agent Governance

Qindu uses a strict multi-agent governance model to ensure security, privacy, and quality.

### Agents
- **qindu-orchestrator**: Primary agent and arbiter. Manages the sprint lifecycle, creates stories, coordinates other agents, and resolves conflicts or rejections.
- **qindu-dpo**: Reviewer. Ensures GDPR compliance, privacy by design, PII minimization, and data protection principles. Cannot modify code.
- **qindu-ciso**: Reviewer. Ensures security, threat modeling, TLS/CA hardening, and compliance with ADRs. Cannot modify code.
- **qindu-devsecops**: Implementer. Writes Go code, tests, and CI/CD workflows. Cannot modify ADRs.
- **qindu-qa**: Reviewer. Verifies tests, PII detection accuracy, edge cases, and quality. Cannot modify code.
- **qindu-release**: Reviewer. Verifies CI/CD, MSI packaging, code signing, and supply chain security. Cannot modify code.
- **qindu-peer-reviewer**: Senior Go dev. Merciless code review against Clean Code, SOLID, Go Proverbs, Pragmatic Programmer, DDD, Effective Go, Code Complete. Produces structured scorecards with blocking bugs, design flaws, and maintainability grades. Invoked after DevSecOps delivers `dev-notes.md`, before CISO/DPO review gates. Cannot modify code.

### Strict Sequential Workflow

The workflow is strictly sequential and file-based within the sprint folder (`docs/implementation/sprints/QINDU-XXXX/`):

1. **Sprint Initialization**: `qindu-orchestrator` creates the sprint folder and writes `story.md`.
2. **Design**:
   - `qindu-dpo` writes `dpo-requirements.md`.
   - `qindu-ciso` writes `ciso-requirements.md`.
   - *If blocked, the sprint stops and `qindu-orchestrator` arbitrates.*
3. **Implementation**: `qindu-devsecops` implements the story (code, tests) and writes `dev-notes.md` (factual, technical).
4. **Peer Review**: `qindu-peer-reviewer` reviews the implementation against Clean Code, SOLID, Go Proverbs, and other design standards. Produces `peer-review.md` with scorecard, critical findings, and verdict. If REJECT or FIX_AND_RESUBMIT with critical bugs, the sprint returns to step 3 for fixes.

   **Blank-slate rule**: After each DevSecOps fix cycle, the peer reviewer MUST be invoked as a fresh, independent session. The peer reviewer receives ONLY `story.md` + source code — no `dev-notes.md`, no `dpo-requirements.md`, no `ciso-requirements.md`, no prior `peer-review.md`. This eliminates confirmation bias from previous reviewers. Loop step 3→4 indefinitely until MERGE_READY is achieved.
5. **Review**:
   - `qindu-ciso` verifies the implementation and writes `ciso-review.md`.
   - `qindu-dpo` verifies the implementation and writes `dpo-review.md`.
6. **Validation**:
   - `qindu-qa` verifies tests, PII accuracy, and edge cases, then writes `qa-review.md`.
   - `qindu-release` verifies CI/CD and supply chain, then writes `release-review.md`.
7. **Closure**: `qindu-orchestrator` reviews all artifacts, resolves any remaining conflicts, and produces `closure.md` with the final verdict.

### Commands
- `/qindu-sprint`: Starts a full sprint cycle.
- `/qindu-gate`: Final gate before merging.
