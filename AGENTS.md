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
- **qindu-qemu-tester**: Reviewer. Validates on real Windows QEMU VM — install, uninstall, service, proxy, TLS, and story compliance via SSH. Cannot modify code.

### Strict Sequential Workflow

The workflow is strictly sequential and file-based within the sprint folder (`docs/implementation/sprints/QINDU-XXXX/`):

1. **Sprint Initialization**: `qindu-orchestrator` creates the sprint folder and writes `story.md`.
2. **Design**:
   - `qindu-dpo` writes `dpo-requirements.md`.
   - `qindu-ciso` writes `ciso-requirements.md`.
   - *If blocked, the sprint stops and `qindu-orchestrator` arbitrates.*
3. **Implementation**: `qindu-devsecops` implements the story (code, tests) and writes `dev-notes.md` (factual, technical).
4. **Peer Review**: `qindu-peer-reviewer` reviews the implementation against Clean Code, SOLID, Go Proverbs, and other design standards. Produces `peer-review.md` with scorecard, critical findings, and verdict. If REJECT or FIX_AND_RESUBMIT with critical bugs, the sprint returns to step 3 for fixes.

   **Blank-slate rule**: After each DevSecOps fix cycle, the peer reviewer MUST be invoked as a fresh, independent session. The peer reviewer receives ONLY `story.md` + source code + existing `qemu-test-report.md` (factual VM findings from prior iterations) — no `dev-notes.md`, no `dpo-requirements.md`, no `ciso-requirements.md`, no prior `peer-review.md`. This eliminates confirmation bias from previous reviewers. Loop step 3→4 indefinitely until MERGE_READY is achieved.
5. **Review**:
   - `qindu-ciso` verifies the implementation and writes `ciso-review.md`.
   - `qindu-dpo` verifies the implementation and writes `dpo-review.md`.
   - *On fix iterations (step 7→3→4→5), reviewers MUST also read `qemu-test-report.md` from the prior cycle.*
6. **Validation**:
    - `qindu-qa` verifies tests, PII accuracy, and edge cases, then writes `qa-review.md`.
    - `qindu-release` verifies CI/CD and supply chain, then writes `release-review.md`.
    - *On fix iterations (step 7→3→4→5→6), validators MUST also read `qemu-test-report.md` from the prior cycle.*
7. **VM Integration Test**: `qindu-qemu-tester` deploys the MSI to the Windows QEMU VM, runs smoke tests, edge cases, and uninstall verification, then writes `qemu-test-report.md` with verdict PASS or BLOCKED.
    - *If BLOCKED, the sprint returns to step 3 for fixes and re-enters the full pipeline (steps 3→4→5→6→7) with the qemu-test-report fed to all downstream reviewers and validators.*
8. **Closure**: `qindu-orchestrator` reviews all artifacts, resolves any remaining conflicts, and produces `closure.md` with the final verdict.

### Commands
- `/qindu-sprint`: Starts a full sprint cycle.
- `/qindu-gate`: Final gate before merging.
- `/qindu-backlog-status`: Displays macro status of the project, including risk register reconciliation. See Backlog Governance above.

## Risk Register Governance

The canonical risk register is `docs/implementation/backlog/qindu-v1-backlog.yaml` (`risks:` block). The file `docs/implementation/backlog/qindu-risk-register.md` is a human-readable mirror — it MUST be kept in sync with the YAML.

### Risk Reconciliation (per sprint closure)

At sprint closure (`closure.md`), the orchestrator MUST:

1. **Extract every finding** from all review documents (peer-review, ciso-review, dpo-review, qa-review, release-review) that:
   - Was accepted for V1 but not fixed
   - Was deferred to a future sprint
   - Was documented as a residual risk or known limitation
2. **Cross-reference** each finding against the existing risk register (R-001 through R-XXX).
3. **Add new risks** to `qindu-v1-backlog.yaml` for any finding that is:
   - MEDIUM severity or higher, OR
   - Documented by 2+ independent reviewers, OR
   - Represents a PII exposure, crypto weakness, TLS vulnerability, or supply chain gap
4. **Add `inherited_from_XXXX`** entries to affected future sprint entries in the backlog.
5. **Update `risks_resolved`** on future sprint entries when a sprint is specifically designed to resolve a tracked risk.
6. **Update `qindu-risk-register.md`** to mirror the YAML.

### During `/qindu-backlog-status`

The orchestrator MUST include a **Risk Reconciliation** section that flags:
- Risks accepted but never assigned to a resolving sprint (orphaned risks)
- Risks deferred to sprints that have been completed but were not addressed
- Risks present in closure documents but absent from the central register

This prevents the register from drifting out of sync with the actual review artifacts.
