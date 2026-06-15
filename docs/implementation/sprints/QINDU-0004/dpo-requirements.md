# DPO Requirements — QINDU-0004: CI/CD Pipeline Enhancement

## 1. Applicability

This sprint is **not triggered by GDPR or personal data processing**. QINDU-0004 enhances the GitHub Actions CI/CD pipeline — it deals exclusively with CI workflow configuration (`.github/workflows/ci.yml`), linter configuration (`.golangci.yml`), test coverage generation (`coverage.out`), and build artifact uploads (`agent.exe`).

No PII detection, tokenization, vault encryption, rehydration, or user data processing is involved. The pipeline runs on ephemeral GitHub-hosted runners (`ubuntu-latest`, `windows-latest` for MSI) and produces only machine-generated artifacts (compiled binaries, coverage profiles, linter output).

## 2. Data Protection Requirements

Although this sprint does not itself process personal data, the following privacy-by-design constraints apply to prevent future leakage:

### 2.1 CI Logs Must Be PII-Free
- **Requirement**: CI job output (golangci-lint logs, `go test` output, `go vet` output, build steps) must not emit personal data.
- **Why**: CI logs are persistent and potentially visible to contributors. Any PII emitted today (e.g., from test fixtures, file paths containing usernames, or leaked environment variables) would constitute a breach.
- **Enforcement**: Acceptance criterion #7 of the story already mandates this. The `test` job's coverage generation (`coverage.out`) must be inspected to ensure it contains only source-file relative paths and coverage counters — no usernames, home directory paths, or environment variable values.

### 2.2 No Secrets in Repository
- **Requirement**: No secrets, tokens, API keys, certificates, or signing keys may be committed to the repository in any form — source code, YAML configuration, comments, or workflow artifacts.
- **Enforcement**: Acceptance criterion #8 of the story already mandates this. The code-signing placeholder (commented-out step in `build-msi`) must reference GitHub Secrets by name only (e.g., `${{ secrets.CODE_SIGNING_CERTIFICATE }}`) — never by value. Comments must not contain example certificate data.

### 2.3 Test Fixtures Must Remain PII-Free
- **Requirement**: Existing unit and integration tests (including testcontainers-go integration tests) must not use real PII in test fixtures. The coverage report (`coverage.out`) is a workflow artifact and must not become a vector for PII leakage.
- **Enforcement**: This is a standing requirement from ADR-004 and the backlog. This sprint does not introduce new test fixtures, so the risk is limited to verifying that the existing test suite (122 tests from QINDU-0001, 148 from QINDU-0002) remains PII-free in its CI output.

### 2.4 Artifact Access Control
- **Requirement**: Workflow artifacts (`coverage.out`, `agent.exe`) are stored on GitHub and inherit the repository's visibility. For a public repository, these artifacts are publicly downloadable. They must contain no personal data.
- **Enforcement**: `coverage.out` contains only code coverage data — source file names and line hit counts. `agent.exe` is a compiled Go binary. Neither constitutes personal data.

## 3. Forbidden Items

The following are explicitly forbidden in this sprint:

| # | Forbidden | Rationale |
|---|-----------|-----------|
| 1 | PII in CI logs, coverage output, or linter output | Backlog constraint; GDPR art. 5(1)(c) data minimization |
| 2 | Secrets committed to the repository in any form | Backlog constraint; security hygiene |
| 3 | External coverage services (Codecov, Coveralls, etc.) | Transmits data to third parties; unnecessary for V1 per story scope |
| 4 | Real user data in test fixtures | Standing ADR-004 requirement |
| 5 | Username/home-directory paths in CI output | Potentially identifies developers; path-independent builds required |
| 6 | Analytics, telemetry, or tracking in CI pipeline | Qindu project constraint: no tracking of any kind |

## 4. Risk Assessment

### Rights and Freedoms Risks: **Negligible**

This sprint does not process personal data. It is CI infrastructure. The residual risks are:

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| PII from test fixtures leaks into coverage report | Very Low | Medium | Existing test suite is PII-free; no new fixtures introduced |
| Secrets accidentally committed in placeholder comments | Low | High | Code review; acceptance criterion #8 |
| CI logs contain developer usernames or paths | Low | Low | Go modules use canonical import paths; CI runs in containerized runner |

### Blocking Points: **None**

No blocking data protection concerns exist for this sprint. The story's scope is purely CI infrastructure with no PII processing surface.

## 5. Required Privacy Tests

For the Review phase, verify:

1. **PII-free CI logs**: Trigger a CI run and inspect all job logs (`golangci-lint`, `test`, `format`, `validate-wix`, `build-msi`). Confirm no email addresses, phone numbers, names, API keys, tokens, or home directory paths appear.
2. **PII-free coverage report**: Download the `coverage.out` artifact and inspect it. Confirm it contains only Go source file paths (relative, module-based) and coverage counters — no personal data.
3. **Secrets audit**: Run `git diff` for the sprint branch and confirm no secrets, tokens, or certificate data appear in any committed file (YAML, Go, comments).
4. **Code-signing placeholder**: Verify the commented-out step references `${{ secrets.* }}` by variable name only, contains no example certificate data, and does not execute.
5. **No external services**: Verify the CI workflow does not invoke Codecov, Coveralls, or any third-party coverage/analytics service.

## 6. Verdict

**PASS** — No blocking data protection concerns.

This sprint is CI infrastructure only. It processes no personal data, introduces no PII detection/tokenization/vault components, and has no user-facing surface. The existing backlog constraints ("PII in CI logs" forbidden, "secrets in repo" forbidden) are already embedded in the acceptance criteria. Proceed to implementation.
