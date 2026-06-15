# Peer Review — QINDU-0004: CI/CD Pipeline Enhancement

**Reviewer**: qindu-peer-reviewer (senior Go developer, 15+ years distributed systems)
**Date**: 2026-06-15
**Files Reviewed**: `.github/workflows/ci.yml` (246 lines), `.golangci.yml` (44 lines)
**Context**: `docs/implementation/sprints/QINDU-0004/story.md`, `go.mod` (Go 1.26), `ARCHITECTURE.md`
**Rule**: Blank-slate review — independent, evidence-based, no reference to prior reviews.

---

## 1. Scorecard

| Dimension       | Score | Justification |
|-----------------|-------|---------------|
| Correctness     | 9/10  | YAML is structurally valid. All 5 actions are SHA-pinned to 40-character commits with version comments. Job dependency chain (`needs: [test, validate-wix]` → `build-msi`) is logically sound. `if: always()` on coverage upload paired with `if-no-files-found: warn` handles the edge case where tests don't produce `coverage.out`. One correctness gap: the story explicitly requires the `gosimple` linter, but `.golangci.yml` omits it without documenting why. |
| Design          | 9/10  | Five cleanly separated jobs (`golangci-lint`, `test`, `format`, `validate-wix`, `build-msi`) with parallel execution where appropriate. `concurrency` group at workflow level cancels redundant in-flight runs. `permissions: contents: read` applies defense-in-depth at the workflow root. Cross-compilation checks (`go build -v ./...`) are cleanly separated from the artifact build (`go build -o agent.exe ./cmd/agent/`). No matrix-strategy over-engineering for a single-version CI. |
| Security        | 10/10 | No secrets exposed in uncommented code. Code-signing placeholder is fully commented out with clear `secrets.*` references for future use. All actions are commit-SHA-pinned. `permissions: contents: read` at workflow root — no job escalates. No `pull_request_target` event. Artifact names (`agent-windows-amd64`, `coverage-report`, `Qindu-Installer-x64.msi`) leak no PII, no version-information exposure. |
| Maintainability | 9/10  | Consistent step naming and action version comments. The code-signing placeholder includes detailed documentation of required secrets (`CODE_SIGNING_CERTIFICATE`, `CODE_SIGNING_PASSWORD`). Both cross-compilation strategy and certutil format inconsistency are explicitly commented. `.golangci.yml` uses `default: none` with explicit opt-in only — future linter additions are auditable. One minor inconsistency: `sha256sum` format (Linux, `test` job) vs `certutil` format (Windows, `build-msi` job) produces different checksum output structures. |
| **Overall**     | **9.3/10** | Production-grade CI pipeline with one documentation gap to close. |

---

## 2. Critical Findings 🔴

**None.** No bugs, panics, security holes, data-loss risks, race conditions, or build breakers were found in any reviewed file.

---

## 3. Design Flaws 🟡

### PR-001 — Missing `gosimple` Linter Per Story Requirements (HIGH — Requirements Gap)

- **File**: `.golangci.yml`, line 14–21
- **Category**: Coverage / Requirements Compliance
- **Problem**: The sprint story (§ "Notes") explicitly specifies the linter set: *"enable govet, staticcheck, errcheck, gosimple, unused, ineffassign, unconvert, misspell."* The `.golangci.yml` enables 7 of these 8 — `gosimple` is absent. The story lists 8 linters; the config has 7.

  The likely reason is that golangci-lint v2 removed `gosimple` as a standalone linter name — its simplification checks (`S1xxx`) are now subsumed under `staticcheck`. However, this rationale is **not documented** in the configuration file or in any comment. A reader cross-referencing the story with the config will observe a gap with no explanation, creating a compliance audit finding.

  Additionally, the story also lists `unused` which, like `gosimple`, was historically part of staticcheck — yet `unused` IS explicitly listed in the config. This inconsistency in treatment (listing `unused` but not `gosimple`) compounds the confusion.

- **Fix**: Add a comment to `.golangci.yml` documenting that `gosimple` checks (`S1xxx` simplification rules from staticcheck) are covered by the `staticcheck` linter in golangci-lint v2 and no longer exist as a separate linter. Suggested addition after line 6:

  ```yaml
  # Note: `gosimple` (S1xxx simplification checks) is not listed separately
  # because golangci-lint v2 merged it into `staticcheck`. The `staticcheck`
  # linter below covers SA, S, QF, and U checks from staticcheck.
  ```

  Then verify by running `golangci-lint run --enable=staticcheck --print-issued-lines=false ./... 2>&1 | grep -c '(S1'` to confirm S1xxx checks are actually emitted. If they are not, investigate whether an explicit `staticcheck` checks configuration is needed.

### PR-002 — Checksum Format Inconsistency Between Jobs (LOW — Non-Blocking)

- **File**: `.github/workflows/ci.yml`, lines 93–95 (`test` job), lines 234–238 (`build-msi` job)
- **Category**: Inconsistency / Consumer Experience
- **Problem**: The `test` job uses `sha256sum agent.exe > agent.exe.sha256` which produces the standard GNU format: `<hex_hash>  agent.exe\n`. The `build-msi` job uses `certutil -hashfile Qindu-Installer-x64.msi SHA256 > Qindu-Installer-x64.msi.sha256` which produces a multi-line Windows format:

  ```
  SHA256 hash of Qindu-Installer-x64.msi:
  <hex_hash>
  CertUtil: -hashfile command completed successfully.
  ```

  Different checksum file formats from the same CI pipeline create unnecessary friction for downstream consumers (automated downloaders, verification scripts, release-pipeline integrations). The workflow itself acknowledges this with a comment (line 232: *"This is a known inconsistency — see dev-notes fix cycle 2."*), which is a code smell — comments that say "we know this is inconsistent but haven't fixed it" belong in a tracking issue, not committed source.

- **Fix**: Standardize on the `sha256sum` format. On the Windows runner, replace the `certutil` step with a PowerShell equivalent that produces the same format:

  ```yaml
  - name: Generate SHA256 checksum
    shell: pwsh
    working-directory: installer/wix
    run: |
      $hash = (Get-FileHash -Algorithm SHA256 Qindu-Installer-x64.msi).Hash.ToLower()
      "$hash  Qindu-Installer-x64.msi" | Out-File -Encoding ASCII Qindu-Installer-x64.msi.sha256
  ```

  `Get-FileHash` is available on all `windows-latest` runner images by default. If there's a reason `certutil` must be used, document it in a single-sentence rationale and link to a tracking issue for resolution.

---

## 4. Nitpicks 🟢

### NP-001 — `golangci-lint` Job Name Ambiguity
- **File**: `.github/workflows/ci.yml`, line 20 (`name: Lint`)
- **Issue**: The job display name `Lint` is ambiguous. If Qindu eventually adds ESLint, shellcheck, or markdownlint, "Lint" won't distinguish them. `Go Lint` or simply matching the job key (`golangci-lint`) would be clearer in the GitHub Actions UI. Not blocking — Qindu V1 is pure Go.

### NP-002 — `go mod verify` Missing in `golangci-lint` Job
- **File**: `.github/workflows/ci.yml`, lines 19–44
- **Issue**: The `test` job runs `go mod verify` (line 68), but the `golangci-lint` job does not. The `golangci-lint-action` internally runs `go mod download` which validates `go.sum` entries for downloaded modules, but it does not run the full `go mod verify` (which checks ALL entries in `go.sum` against the module cache). In a supply-chain-conscious pipeline, both jobs should verify module integrity independently. Adding `go mod verify` before the cache step in `golangci-lint` costs ~1 second and closes this gap.

### NP-003 — No `timeout-minutes` on `build-msi` Job
- **File**: `.github/workflows/ci.yml`, line 162
- **Issue**: The `build-msi` job runs on `windows-latest` (slower startup), installs WiX via Chocolatey (network-dependent), and runs `go test -race` on Windows (slower than Linux). While GitHub's default 360-minute timeout won't be hit in practice, an explicit `timeout-minutes: 20` is a defensive practice that catches hung Chocolatey installs or stuck processes faster than the default. The other jobs (lint, test, format, validate-wix) complete in <5 minutes and don't need explicit timeouts.

### NP-004 — Double `./cmd/agent/` Compilation for windows/amd64
- **File**: `.github/workflows/ci.yml`, lines 80–91
- **Issue**: The `test` job compiles `./cmd/agent/` twice for windows/amd64: once inside `go build -v ./...` (line 81, which builds all packages including `cmd/agent/`), and once explicitly via `go build -o agent.exe ./cmd/agent/` (line 91, the artifact build). For a project with ~20 packages, the wasted compilation is negligible (~1 second). The result is clean from a correctness standpoint (named output binary vs mass-compile check). The comments already explain the rationale. Not worth optimizing, but worth noting.

### NP-005 — Code-Signing Placeholder Signs Only `agent.exe`, Not MSI
- **File**: `.github/workflows/ci.yml`, lines 213–229
- **Issue**: The commented-out `Sign agent.exe` step targets only the raw binary. In a production code-signing workflow, the MSI installer (`Qindu-Installer-x64.msi`) should also be signed. The placeholder comment mentions `docs/signing.md` for "full setup instructions" — as long as that (future) document covers MSI signing, this is fine. Adding a one-line comment `# MSI signing (see docs/signing.md)` next to the agent.exe sign step would prevent a future implementer from stopping at binary signing and missing the MSI.

---

## 5. Concurrency, Caching, and Resilience Verification

Per Qindu-specific review standards, the following were explicitly checked:

| Check | Result | Evidence |
|-------|--------|----------|
| Concurrency group present | ✅ | `.github/workflows/ci.yml:6` — `group: ${{ github.workflow }}-${{ github.ref }}` with `cancel-in-progress: true` |
| Module cache in `golangci-lint` job | ✅ | `.github/workflows/ci.yml:31-39` — full `actions/cache@v4` with `~/go/pkg/mod` and `~/.cache/go-build` |
| Module cache in `test` job | ✅ | `.github/workflows/ci.yml:58-66` — identical cache key strategy |
| No matrix-strategy over-engineering | ✅ | Zero occurrences of `strategy:` or `matrix:` anywhere in `ci.yml` |
| No `pull_request_target` event | ✅ | Events: `push`, `pull_request`, `workflow_dispatch` only |
| No plaintext secrets in workflow | ✅ | All secrets referenced via `${{ secrets.* }}` syntax |
| No PII in artifact names | ✅ | Artifacts: `agent-windows-amd64`, `coverage-report`, `Qindu-Installer-x64.msi` |

---

## 6. Acceptance Criteria Checklist

| # | Criterion | Status | Evidence |
|---|-----------|--------|----------|
| 1 | `.golangci.yml` exists at repo root with minimal, pragmatic configuration | ✅ PASS | 44 lines, `default: none`, 7 linters + comment scaffolding |
| 2 | `golangci-lint` runs as separate job in `ci.yml` | ✅ PASS | Job `golangci-lint` (line 19), no `needs:` dependency |
| 3 | Coverage: `go test -race -coverprofile=coverage.out ./...`, upload artifact | ✅ PASS | Line 75: `-coverprofile=coverage.out`, line 104: upload with `if: always()` |
| 4 | Standalone `agent.exe` artifact uploaded | ✅ PASS | Lines 91–100: build + SHA256 + `upload-artifact` as `agent-windows-amd64` |
| 5 | Commented-out code-signing placeholder with documented secrets | ✅ PASS | Lines 213–229: `CODE_SIGNING_CERTIFICATE`, `CODE_SIGNING_PASSWORD` documented |
| 6 | All existing jobs preserved (`test`, `format`, `validate-wix`, `build-msi`) | ✅ PASS | All four jobs intact with their original steps |
| 7 | No PII in CI logs | ✅ PASS | Workflow YAML contains no user data, email addresses, or identifiable strings |
| 8 | No secrets committed to repository | ✅ PASS | No hardcoded credentials, tokens, or keys in any reviewed file |

All 8 acceptance criteria are met. Criterion 1 has a minor documentation gap (PR-001) that does not affect functionality.

---

## 7. Verdict

### **MERGE_READY** ✅

No critical findings. The implementation delivers all eight acceptance criteria with production-grade engineering discipline: SHA-pinned actions, minimal permissions, concurrency-aware pipeline management, graceful edge-case handling (`if-no-files-found: warn`), and clean job separation.

**One required post-merge action**: Address **PR-001** (document `gosimple` coverage by `staticcheck`) with a follow-up commit before the CISO review gate. The fix is a 3-line comment addition to `.golangci.yml` — no structural changes needed. This ensures the config file self-documents its relationship to the story requirements, preventing audit confusion.

**Remaining items (PR-002, NP-001 through NP-005)** are non-blocking quality-of-life improvements. The most impactful are:
- **NP-003** (`timeout-minutes` on `build-msi`): cheap defensive addition
- **NP-002** (`go mod verify` in lint job): closes a supply-chain verification gap

Neither blocks merge. Both can be addressed in a follow-up refinement sprint.

---

*End of peer review. 0 critical findings. 2 design flaws (1 HIGH documentation gap, 1 LOW inconsistency). 5 nitpicks. 0 security issues. 8/8 acceptance criteria met.*

*Reviewed against Clean Code, Pragmatic Programmer, SOLID, Go Proverbs, Effective Go, Code Complete, and Qindu-specific security checks.*
