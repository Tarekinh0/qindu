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

#### qindu-orchestrator — Document Router & Clerk

The orchestrator is a **document clerk**, not an arbiter. Three responsibilities:

1. **Route**: Pass artifacts between agents in the correct sequential order. Ensure the right agent receives the right files at the right time.
2. **Contextualize**: When a reviewer raises a concern, the orchestrator may provide **cross-sprint context** (ADRs, previous closures, risk register) to help the reviewer understand the broader picture. He never provides code opinions, code excerpts, or hints about what the code does.
3. **Close**: When all gates report their final verdict, the orchestrator reads every verdict and writes `closure.md` — a summary of what happened, not a judgment. If any gate says BLOCKED, the sprint stays open.

**Hard constraints**:
- Never reads source code. Never opens `.go` files.
- Never provides code excerpts, line numbers, or file paths to reviewers or DevSecOps.
- Cannot override, soften, or "accept on behalf of" any reviewer's verdict.
- Cannot decide that a MEDIUM finding is "acceptable for V1" — only the reviewer who raised it can accept it.
- At sprint start, uses the **grill-me** skill to interview the human about design choices before writing `story.md`.

#### qindu-dpo — Privacy Reviewer

Absolute veto on privacy. Ensures GDPR compliance, privacy by design, PII minimization, and data protection principles. Cannot modify code.

Receives: `story.md` + git diff. Nothing else.

#### qindu-ciso — Security Reviewer

Absolute veto on security. Ensures threat modeling, TLS/CA hardening, and compliance with ADRs. Cannot modify code.

Receives: `story.md` + git diff. Nothing else.

#### qindu-devsecops — Pure Executor

Writes Go code, tests, and CI/CD workflows. Cannot modify ADRs.

Reads reviews and the git diff independently. Implements exactly what reviewers demand. Fixes every finding unless the reviewer explicitly marks it as accepted. No negotiation power with reviewers — his job is to execute, not argue.

#### qindu-qa — Quality Reviewer

Absolute veto on quality. Verifies tests, PII detection accuracy, edge cases, and invariants. Cannot modify code.

Receives: `story.md` + git diff. Nothing else.

#### qindu-release — Release Reviewer

Absolute veto on supply chain. Verifies CI/CD, MSI packaging, code signing, and provenance. Cannot modify code.

Receives: `story.md` + git diff. Nothing else.

#### qindu-peer-reviewer — Senior Go Reviewer

Merciless code review against Clean Code, SOLID, Go Proverbs, Pragmatic Programmer, DDD, Effective Go, Code Complete. Produces structured scorecards with blocking bugs, design flaws, and maintainability grades. Invoked after DevSecOps delivers `dev-notes.md`, before CISO/DPO review gates. Cannot modify code.

Receives: `story.md` + git diff. Nothing else.

**Blank-slate rule**: Invoked as a fresh, independent session each time. Receives ONLY `story.md` + git diff + existing `qemu-test-report.md` (factual VM findings from prior iterations). No `dev-notes.md`, no `dpo-requirements.md`, no `ciso-requirements.md`, no prior `peer-review.md`.

#### qindu-qemu-tester — VM & API Integration Reviewer

Validates Qindu end-to-end: deploys the MSI to the Windows QEMU VM and tests the full proxy pipeline with real API calls. Cannot modify code.

Two validation modes:

1. **QEMU VM**: Install, uninstall, service, proxy, TLS trust store, PAC, firewall, story compliance — via SSH.
2. **API Integration** (from QINDU-0009 onward): Sends real prompts through the proxy to AI providers, verifying:
   - Tokenization: PII replaced with tokens in outbound request
   - Vault: token→value mapping persisted and retrievable
   - Rehydration: tokens replaced with original PII in response
   - Log sanitization: zero PII values in any log output
   - Round-trip: the full enforce pipeline works end-to-end

Receives: `story.md` + MSI artifact + test instructions. API key from `.ssh/openai.key`. Nothing else.

WiX builds are performed on the QEMU VM using the WiX Toolset installed at `C:\Program Files (x86)\WiX Toolset v3\`.

---

### Strict Sequential Workflow

The workflow is strictly sequential and file-based within the sprint folder (`docs/implementation/sprints/QINDU-XXXX/`):

1. **Story Initialization**:
   - Orchestrator uses the **grill-me** skill to interview the human about design choices, tradeoffs, and boundaries.
   - Orchestrator writes `story.md` based on the interview.

2. **Design**:
   - `qindu-dpo` receives `story.md` + git diff, writes `dpo-requirements.md`.
   - `qindu-ciso` receives `story.md` + git diff, writes `ciso-requirements.md`.
   - *If either says BLOCKED, the sprint stops and the orchestrator negotiates using cross-sprint context only.*

3. **Implementation**:
   - `qindu-devsecops` receives `story.md` + `dpo-requirements.md` + `ciso-requirements.md` + git diff.
   - Implements the story (code, tests) and writes `dev-notes.md` (factual, technical).
   - DevSecOps reads the code himself — the orchestrator provides zero code guidance.

4. **Peer Review**:
   - `qindu-peer-reviewer` receives `story.md` + git diff only (blank-slate).
   - If REJECT or FIX_AND_RESUBMIT, the sprint returns to step 3.
   - Loop 3→4 until MERGE_READY.

5. **Security & Privacy Review**:
   - `qindu-ciso` receives `story.md` + git diff only, writes `ciso-review.md`.
   - `qindu-dpo` receives `story.md` + git diff only, writes `dpo-review.md`.
   - If BLOCKED by either, the sprint returns to step 3. Orchestrator may negotiate using cross-sprint context only — never code.
   - On fix iterations, reviewers also read `qemu-test-report.md` from the prior cycle.

6. **Quality & Release Validation**:
   - `qindu-qa` receives `story.md` + git diff only, writes `qa-review.md`.
   - `qindu-release` receives `story.md` + git diff only, writes `release-review.md`.
   - If BLOCKED by either, the sprint returns to step 3.
   - On fix iterations, validators also read `qemu-test-report.md` from the prior cycle.

7. **VM & API Integration Test**:
   - `qindu-qemu-tester` deploys the MSI to the Windows QEMU VM, runs smoke tests, edge cases, and uninstall verification.
   - **From QINDU-0009 onward**: Also validates the full enforce pipeline with real AI provider calls (tokenization, vault persistence, rehydration, log sanitization).
   - Writes `qemu-test-report.md` with verdict PASS or BLOCKED.
   - Uses API key from `.ssh/openai.key` for provider calls.
   - If BLOCKED, returns to step 3 and re-enters the full pipeline (steps 3→4→5→6→7).

8. **Closure**:
   - Orchestrator reads all verdicts from all agents.
   - If ALL gates say PASS (or equivalent), writes `closure.md` summarizing what happened — verdicts, changes, findings, risks. Not a judgment call.
   - If ANY gate says BLOCKED, the sprint stays open.
   - Updates the risk register and backlog with all findings accepted or deferred by reviewers.

### Reviewer Input Contract

Every reviewer (DPO, CISO, Peer, QA, Release, QEMU) receives exactly:
- `story.md` — the sprint specification
- Git diff — the code to judge
- `qemu-test-report.md` — only on fix iteration cycles (factual VM findings)
- `backlog.yaml` + `roadmap.md` — project context (always available)

Nothing else. No `dev-notes.md`. No code excerpts. No orchestration hints. No "here's what to look at." Reviewers reach their own conclusions independently.

### Finding Resolution Rule

Every finding raised by any reviewer MUST be either:
- **Fixed** by DevSecOps in a subsequent fix cycle, OR
- **Explicitly accepted** by the reviewer who raised it (with documented rationale)

The orchestrator cannot accept a finding on behalf of a reviewer. MEDIUM, LOW — makes no difference. Only the reviewer can accept their own findings.

---

### Commands
- `/qindu-sprint`: Starts a full sprint cycle (steps 1→8).
- `/qindu-gate`: Final gate before merging.
- `/qindu-backlog-status`: Displays macro status of the project, including risk register reconciliation. See Backlog Governance above.

## Risk Register Governance

The canonical risk register is `docs/implementation/backlog/qindu-v1-backlog.yaml` (`risks:` block). The file `docs/implementation/backlog/qindu-risk-register.md` is a human-readable mirror — it MUST be kept in sync with the YAML.

### Risk Reconciliation (per sprint closure)

At sprint closure (`closure.md`), the orchestrator MUST:

1. **Extract every finding** from all review documents (peer-review, ciso-review, dpo-review, qa-review, release-review) that:
   - Was explicitly accepted by the reviewer but not fixed
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
