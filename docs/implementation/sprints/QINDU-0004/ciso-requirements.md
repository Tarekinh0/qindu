# CISO Requirements — QINDU-0004: CI/CD Pipeline Enhancement

## 1. Attack Surface Assessment

### 1.1 New Attack Surface

| Surface | Description | Risk Level |
|---------|-------------|------------|
| **golangci-lint installation** | New binary installed on CI runner. Supply chain risk if pulled from unofficial source or unpinned. | Medium |
| **Workflow artifact: `coverage.out`** | New artifact uploaded. Could leak source paths, environment variables, or test fixture data if not sanitized. | Low |
| **Workflow artifact: `agent.exe`** | New standalone binary artifact. Integrity risk if not checksummed. | Low |
| **Code-signing placeholder** | Commented-out YAML step referencing `secrets.*`. Risk of accidental exposure of secret naming conventions. | Very Low |
| **`.golangci.yml` config file** | New file at repo root. Low risk, but configuration must not weaken build security (e.g., disabling critical checks). | Very Low |

### 1.2 Modified Attack Surface

| Surface | Description | Risk Level |
|---------|-------------|------------|
| **`test` job** | Adds `-coverprofile=coverage.out` flag. `go test` output must remain PII-free. | Low |
| **`build-msi` job** | Code-signing placeholder added (commented out). No runtime change. | Very Low |

### 1.3 Pre-existing Attack Surface (Reviewed for Regression)

| Surface | Status | Risk |
|---------|--------|------|
| **`pull_request` trigger** | Uses `pull_request` (safe for forks) — NOT `pull_request_target`. | Safe |
| **Action references** | All `@v4`/`@v5` tags — mutable, unpinned. **Existing supply chain debt.** | Medium |
| **`permissions` block** | Absent. GITHUB_TOKEN defaults to `write-all` for the workflow scope. **Over-privileged.** | Medium |
| **`apt-get install` (validate-wix)** | Installs `libxml2-utils` unpinned. Canonical repo compromise is a tail risk. | Low |
| **`choco install` (build-msi)** | Installs `wixtoolset@3.14.1` pinned to version. Acceptable. | Low |
| **Secrets usage** | None currently in use. No secret leakage surface. | Safe |
| **Artifact checksums** | Existing MSI upload includes SHA256. Good. | Safe |

---

## 2. Protected Assets

| Asset | Location | Protection Requirement |
|-------|----------|------------------------|
| **CI runner integrity** | GitHub-hosted ephemeral runner | Pin all third-party actions to SHA digests; verify golangci-lint provenance |
| **GITHUB_TOKEN** | Auto-injected by Actions | Restrict via `permissions:` block to `contents: read` |
| **Code-signing secrets (future)** | `${{ secrets.CODE_SIGNING_* }}` | Must never be echoed, logged, or embedded in artifacts. Placeholder must reference by name only. |
| **Artifact integrity** | `coverage.out`, `agent.exe`, MSI | All binary/executable artifacts must have checksums |
| **Repo source code** | `github.com/Tarekinh0/qindu` (public) | Fork PRs must not execute with elevated privileges |
| **Go module supply chain** | `go.sum`, cached modules | `go mod verify` already enforced; golangci-lint must not bypass this |

---

## 3. Threat Model (STRIDE-per-element)

### 3.1 Workflow Trigger — Spoofing / Elevation of Privilege

- **Threat**: Fork PR uses `pull_request_target` to execute in base repo context with secrets access.
- **Status**: **Mitigated.** The workflow uses `pull_request:` (not `pull_request_target`). PR code runs in the forked context with read-only GITHUB_TOKEN scoped to the fork. No secrets are accessible from fork PRs.
- **Requirement**: Do NOT change to `pull_request_target`. Lock this.

### 3.2 Third-Party Actions — Tampering / Supply Chain

- **Threat**: Attacker compromises `actions/checkout@v4` repo and publishes malicious code under the mutable `v4` tag. All downstream CI runs execute attacker code with GITHUB_TOKEN.
- **Status**: **Vulnerable.** All four actions (`checkout@v4`, `setup-go@v5`, `cache@v4`, `upload-artifact@v4`) use mutable version tags.
- **Requirement**: Pin all GitHub Actions to immutable commit SHA digests.

### 3.3 golangci-lint Installation — Tampering / Supply Chain

- **Threat**: Installing golangci-lint from an unofficial source or without version pinning could inject a backdoored linter binary into the CI pipeline.
- **Status**: **Design stage — not yet implemented.**
- **Requirement**: Use the official `golangci/golangci-lint-action` (pinned to SHA) OR download the binary from the official GitHub release with version pin and SHA256 verification. Never pipe `curl | bash`.

### 3.4 Artifact Upload — Tampering

- **Threat**: Attacker with write access to the repo repo could replace a release artifact with a backdoored `agent.exe` post-build. Without checksums, downstream consumers cannot verify integrity.
- **Status**: **Partially mitigated.** MSI upload includes SHA256 checksum. The new `agent.exe` upload in the story scope does not specify checksum generation.
- **Requirement**: Generate SHA256 checksum for `agent.exe` artifact, same as the existing MSI pattern.

### 3.5 Code-Signing Placeholder — Information Disclosure

- **Threat**: Commented-out YAML could reveal:
  - The exact secret names (enables targeted credential harvesting attacks)
  - Example signing parameters that imply infrastructure details
  - Tooling names/versions that enable supply chain targeting
- **Status**: **Design stage — low risk.** The story explicitly requires "references GitHub secrets."
- **Requirement**: Reference `${{ secrets.CODE_SIGNING_* }}` generically. Do NOT document real secret names in comments. Use placeholder text like `# Uncomment and configure when signing certificate is available. Set secrets: CODE_SIGNING_CERTIFICATE, CODE_SIGNING_PASSWORD in repository settings.`

### 3.6 Over-Privileged GITHUB_TOKEN — Elevation of Privilege

- **Threat**: Without a `permissions:` block, the workflow's GITHUB_TOKEN defaults to `write-all` (contents: write, issues: write, pull-requests: write, etc.). A compromised action or injected step could push malicious commits, modify releases, or tamper with issues.
- **Status**: **Vulnerable.** No `permissions:` block exists in the current workflow.
- **Requirement**: Add a top-level `permissions:` block with `contents: read` (minimum required for checkout and artifact upload). The `actions/upload-artifact@v4` requires `contents: read` plus `actions: write` (to upload artifacts). Use the most restrictive scope possible.

### 3.7 CI Log Emission — Information Disclosure

- **Threat**: Logs from `go test`, `golangci-lint`, or build steps could contain PII (developer home paths, environment variables, test fixture data).
- **Status**: **DPO-reviewed.** Acceptance criteria mandate PII-free logs.
- **Requirement**: Enforce. Coverage report (`coverage.out`) must contain only relative module paths. No `/home/` or `/Users/` prefixes. No environment variables.

### 3.8 `apt-get install` — Supply Chain

- **Threat**: The `validate-wix` job runs `sudo apt-get update && sudo apt-get install -y libxml2-utils` on every run. A compromised Ubuntu package mirror could inject malicious XML processing tools.
- **Status**: **Accepted residual risk.** Canonical package repository compromise is a tail-risk event. The package (`libxml2-utils`) is well-known.
- **Requirement**: Monitor but do not block. Consider pinning to a specific package version in the future.

### 3.9 `choco install wix` — Supply Chain

- **Threat**: `choco install wixtoolset --version=3.14.1` pulls from Chocolatey community feed. Community packages can be compromised.
- **Status**: **Existing — not new in this sprint.** Version is pinned (`3.14.1`), which is acceptable.
- **Requirement**: No change needed in this sprint. Existing mitigation is adequate.

---

## 4. Blocking Security Requirements

The following requirements **MUST** be satisfied. Any violation is a blocking issue:

### 4.1 Pin All GitHub Actions to Commit SHA Digests

**Severity: BLOCKING**

All `uses:` directives must reference full-length commit SHA digests, not version tags.

| Action | Current | Required |
|--------|---------|----------|
| `actions/checkout` | `@v4` | `@<commit-sha>` — latest v4.x commit |
| `actions/setup-go` | `@v5` | `@<commit-sha>` — latest v5.x commit |
| `actions/cache` | `@v4` | `@<commit-sha>` — latest v4.x commit |
| `actions/upload-artifact` | `@v4` | `@<commit-sha>` — latest v4.x commit |

Rationale: OWASP CI/CD Security Cheat Sheet §Actions, SLSA Level 3 supply chain integrity. Mutable tags (`@v4`, `@v5`) allow an attacker who compromises the action repository to backdoor all downstream CI runs without changing the workflow file.

**Exception**: If the `golangci/golangci-lint-action` is used, it must also be pinned to a commit SHA.

### 4.2 Add Least-Privilege `permissions:` Block

**Severity: BLOCKING**

Add at the **top level** of the workflow:

```yaml
permissions:
  contents: read
```

Job-specific overrides if needed (e.g., `actions: write` for artifact upload). The principle: start with zero, grant only what's needed.

Rationale: Without this, GITHUB_TOKEN defaults to `write-all`. A single compromised action can push commits, modify releases, or delete artifacts. OWASP ASVS V14.2.2.

### 4.3 Pin golangci-lint Version

**Severity: BLOCKING**

The golangci-lint binary or action must be pinned to a specific version (e.g., `v2.7.x` matching the Go 1.26 toolchain). Do NOT use `latest`.

Two acceptable approaches:

**Option A (preferred)**: Use the official `golangci/golangci-lint-action` pinned to SHA, with a pinned version argument:
```yaml
- uses: golangci/golangci-lint-action@<sha>
  with:
    version: v2.7.2
```

**Option B**: Download the binary directly from the official GitHub release with SHA256 verification:
```yaml
- run: |
    curl -sSfL https://github.com/golangci/golangci-lint/releases/download/v2.7.2/golangci-lint-2.7.2-linux-amd64.tar.gz -o golangci-lint.tar.gz
    echo "<sha256-checksum> golangci-lint.tar.gz" | sha256sum -c
    tar -xzf golangci-lint.tar.gz
    ./golangci-lint-2.7.2-linux-amd64/golangci-lint run ./...
```

**Forbidden**: `curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh` — pipe-to-shell is a supply chain anti-pattern.

### 4.4 Generate `agent.exe` SHA256 Checksum

**Severity: BLOCKING**

The standalone `agent.exe` artifact upload must include a SHA256 checksum, matching the existing pattern in the `build-msi` job. Use `certutil` on Windows or `sha256sum` on Linux:

```yaml
- name: Generate SHA256 checksum for agent.exe
  run: sha256sum agent.exe > agent.exe.sha256
```

Both `agent.exe` and `agent.exe.sha256` must be uploaded together as a single artifact or as paired artifacts.

### 4.5 Code-Signing Placeholder Safety

**Severity: NON-BLOCKING (but must comply)**

The commented-out placeholder must:
1. Use generic placeholder names for secrets (e.g., `${{ secrets.CODE_SIGNING_CERTIFICATE }}`, not revealing the actual secret naming convention)
2. Contain no example certificate data, PEM blocks, or base64-encoded blobs
3. Include a comment explaining that the block is intentionally disabled and what secrets are needed
4. Be syntactically valid YAML (commented) so it does not break the workflow parser

Example acceptable form:
```yaml
# ─── Code Signing (Future) ─────────────────────────────────────────
# Uncomment this step when an EV Code Signing Certificate is available.
# Required repository secrets:
#   - CODE_SIGNING_CERTIFICATE (base64-encoded PFX)
#   - CODE_SIGNING_PASSWORD
# See docs/signing.md for setup instructions.
#
# - name: Sign agent.exe
#   run: |
#     signtool sign /fd SHA256 /f certificate.pfx /p $env:CODE_SIGNING_PASSWORD agent.exe
#   env:
#     CODE_SIGNING_CERTIFICATE: ${{ secrets.CODE_SIGNING_CERTIFICATE }}
#     CODE_SIGNING_PASSWORD: ${{ secrets.CODE_SIGNING_PASSWORD }}
```

### 4.6 No Secrets in CI Logs, Coverage Reports, or Artifacts

**Severity: BLOCKING**

Must verify:
- `golangci-lint` output does not echo source code containing PII or secrets
- `go test -coverprofile` output does not contain absolute paths or environment variables
- `coverage.out` artifact contains only relative module-import paths
- Build logs do not leak GITHUB_TOKEN, signing secrets, or API keys
- `go vet` output does not include file contents that might contain secrets

### 4.7 Preserve `pull_request` Trigger (Never Use `pull_request_target`)

**Severity: BLOCKING**

The workflow currently uses `pull_request:` — this is safe. Under no circumstances should this be changed to `pull_request_target`. The current configuration ensures fork PRs execute in the forked context without access to the base repository's secrets.

### 4.8 `.golangci.yml` Must Not Disable Security-Critical Checks

**Severity: BLOCKING**

The `.golangci.yml` configuration must enable at minimum:
- `govet` — Go's built-in suspicious construct detector
- `staticcheck` — static analysis (SAxxxx checks)
- `errcheck` — unchecked error returns
- `ineffassign` — ineffectual assignments

It must NOT disable `gosec` or equivalent security-oriented linters if present. The configuration should be explicitly minimal and documented (no "magic" exclusions without comments).

---

## 5. ADR Compliance Check

### ADR-007: Testing Strategy

| Provision | Status | Notes |
|-----------|--------|-------|
| CI on `ubuntu-latest` | ✅ Compliant | All jobs (except `build-msi`) use `ubuntu-latest` |
| `go test ./...`, `go vet ./...` | ✅ Compliant | `test` job includes both |
| Cross-compilation `GOOS=windows` | ✅ Compliant | Both `amd64` and `arm64` cross-compiled |
| Go version matrix | ⚠️ Deviation | ADR specifies 1.22/1.23; `go.mod`/workflow uses 1.26. Story explicitly acknowledges this and does not modify the ADR. |
| Docker for testcontainers | ✅ Compliant | `ubuntu-latest` provides Docker; `test` job runs integration tests |

**Verdict**: No regression. The Go version deviation is a pre-existing divergence from the ADR, not introduced by this sprint.

### ADR-010: TLS Upstream Validation

| Provision | Status | Notes |
|-----------|--------|-------|
| No bypass of TLS checks in CI | ✅ Compliant | CI does not override TLS verification; standard `x509.SystemCertPool` behavior in tests |
| No `InsecureSkipVerify` in CI | ✅ Compliant | Tests use real certificates via testcontainers |

**Verdict**: No impact.

### Other ADRs

- **ADR-008 (Structured Logging)**: No CI-specific provisions. Coverage/lint output is machine-readable, not PII-structured. ✅ Compliant.
- **ADR-004 (Data Pipeline)**: Not directly relevant to CI. ✅ N/A.
- **ADR-003 (TLS Strategy)**: Not directly relevant to CI. ✅ N/A.

---

## 6. Mandatory Security Tests

For the CISO Review phase (`ciso-review.md`), the following must be verified:

### T1: Action SHA Pinning
- [ ] Run `git diff` and confirm all `uses:` directives in `.github/workflows/ci.yml` reference commit SHA digests (40-char hex), not version tags (`@v4`, `@v5`)
- [ ] Verify the SHA is the latest commit on the respective major version tag at time of implementation

### T2: Least-Privilege Permissions
- [ ] Confirm `permissions:` block exists at workflow top level
- [ ] Confirm `contents: read` is the only permission (or the minimal set)
- [ ] Verify no `id-token: write` or other write permissions unless explicitly justified

### T3: Trigger Safety
- [ ] Confirm workflow uses `pull_request:` (not `pull_request_target`)
- [ ] No `schedule:` trigger with write permissions
- [ ] Fork PR execution verified via a test PR from a fork (manual)

### T4: golangci-lint Provenance
- [ ] Confirm golangci-lint is either (a) installed via the official action pinned to SHA with a pinned version, or (b) downloaded with SHA256 checksum verification
- [ ] No `| sh`, `| bash`, or other pipe-to-shell patterns

### T5: Artifact Integrity
- [ ] Confirm `agent.exe` upload includes `agent.exe.sha256` (or equivalent checksum)
- [ ] Download both artifacts from a CI run and verify SHA256 matches

### T6: Code-Signing Placeholder Audit
- [ ] Grep the workflow file for any hardcoded base64 strings, PEM blocks, or certificate data
- [ ] Confirm placeholder is syntactically commented out and does not execute
- [ ] Confirm secret references use `${{ secrets.* }}` syntax without hardcoded values

### T7: CI Log PII Audit
- [ ] Inspect a real CI run's raw logs for: email addresses, phone numbers, home directory paths (`/home/<username>`), GITHUB_TOKEN values, API keys
- [ ] Download `coverage.out` artifact and verify all file paths are relative module paths (no `/home/tarek/`, `/Users/`, `C:\Users\`)
- [ ] Verify `golangci-lint` output does not echo source code containing secrets or test fixture data

### T8: `.golangci.yml` Configuration Audit
- [ ] Confirm `govet`, `staticcheck`, `errcheck` are enabled
- [ ] Confirm no security-critical linter (`gosec` or equivalent) is explicitly disabled
- [ ] Confirm linter configuration does not suppress warnings on security-sensitive patterns (e.g., TLS, crypto, file permissions)

### T9: Workflow Syntax Validation
- [ ] Run the workflow through `actionlint` or GitHub's workflow parser to confirm no YAML syntax errors
- [ ] Confirm the new `golangci-lint` job runs independently and does not block existing jobs via unexpected `needs:` dependencies

### T10: No Regression on Existing Jobs
- [ ] All 4 existing jobs (`test`, `format`, `validate-wix`, `build-msi`) pass unchanged
- [ ] `go vet` still runs and catches violations
- [ ] `go test -race` still runs with race detector enabled
- [ ] Cross-compilation for `windows/amd64` and `windows/arm64` still succeeds

---

## 7. Residual Risks

The following risks are accepted (not blocked) but documented for awareness:

| Risk | Reason for Acceptance | Mitigation |
|------|----------------------|------------|
| `apt-get install` pulls from Canonical mirrors without pinned version | Canonical repo compromise is a tail-risk event. `libxml2-utils` is a well-known, widely-used package. | Future: pin to specific version with `apt-get install libxml2-utils=2.12.x` |
| `choco install wixtoolset` from community feed | Version is pinned (`3.14.1`). Chocolatey community feed is the standard WiX distribution channel. | Monitor periodically; consider official WiX releases directly in the future |
| `windows-latest` / `ubuntu-latest` mutable runner images | GitHub-hosted runner images are updated continuously; `latest` can introduce breaking changes. Standard practice for open-source CI. | Pin to specific runner versions (`ubuntu-24.04`, `windows-2022`) if stability issues arise |
| Coverage report may contain source paths that reveal developer machine names or directory structures | Go's coverage tool uses module-relative paths. Test suites run in containerized CI with no personal directories. | Verify in T7 |
| No SLSA provenance attestation for artifacts | V1 goal is build verification, not release. SLSA provenance is a V2+ concern. | Document as a future enhancement |
| Go 1.26 used instead of ADR-007's specified 1.22/1.23 matrix | Pre-existing divergence. ADR-007 was written before Go 1.26 was the project's chosen version. | Update ADR-007 in a future sprint to reflect actual version policy |

---

## 8. Verdict

### PASS — With Requirements

No blocking architectural or privacy security concerns exist for QINDU-0004. The sprint is purely CI infrastructure enhancement with no PII processing surface, no new network exposure, and no modification to the proxy's TLS interception or data pipeline.

**However**, the existing CI workflow has pre-existing supply chain debt (unpinned actions, missing permissions block) that **must** be remediated as part of this sprint. The following are blocking implementation requirements:

1. **Pin all 4 existing actions and any new actions to commit SHA digests** (§4.1)
2. **Add `permissions: contents: read` block** (§4.2)
3. **Pin golangci-lint to a specific version** (§4.3)
4. **Generate SHA256 checksum for `agent.exe` artifact** (§4.4)
5. **Ensure code-signing placeholder is safe** (§4.5)
6. **Enable security-critical linters in `.golangci.yml`** (§4.8)

These requirements must be verified during the CISO Review phase using the test checklist in §6.

---

## 9. References

| Reference | Title | Applicability |
|-----------|-------|---------------|
| OWASP ASVS V14.2.2 | Verify CI/CD pipeline permissions are least-privilege | §4.2 |
| OWASP CI/CD Security Cheat Sheet | Action pinning, trigger security | §4.1, §4.7 |
| SLSA v1.0 (Level 3) | Non-falsifiable provenance, pinned dependencies | §4.1, §4.3 |
| ADR-007 | Testing strategy: testcontainers, cross-compilation, CI on ubuntu-latest | §5 |
| ADR-008 | Structured logging: slog, JSON, no PII in logs | §4.6, §T7 |
| GitHub Security Lab | Preventing pwn requests (pull_request_target risks) | §4.7 |
| Qindu V1 Backlog | QINDU-0004: forbidden items (PII in logs, secrets in repo) | §4.6 |
