# Story: CI/CD Pipeline — Enhancement

## Objective

Enhance the existing GitHub Actions CI/CD pipeline (`.github/workflows/ci.yml`) with golangci-lint, test coverage reporting, a standalone `agent.exe` build artifact, and a code-signing placeholder for future use.

## Context

A CI workflow already exists with 4 jobs (`test`, `format`, `validate-wix`, `build-msi`) covering `go vet`, `go test -race`, cross-compilation (`GOOS=windows` for amd64 and arm64), `go fmt` checks, WiX XML validation, and MSI packaging (on tags/manual dispatch). The acceptance criteria from the backlog ("go vet, go test, cross-compilation GOOS=windows sur ubuntu-latest") is already met.

This sprint enhances — not replaces — the existing pipeline.

## Scope

### Additions
- [ ] **`.golangci.yml`** configuration file at repo root with a minimal, pragmatic linter set
- [ ] **`golangci-lint` job** in `ci.yml` — separate from `test`, runs in parallel, fails independently
- [ ] **Test coverage generation** in `test` job — `go test -race -coverprofile=coverage.out ./...`, upload `coverage.out` as a workflow artifact
- [ ] **Standalone `agent.exe` artifact** — upload the cross-compiled Windows binary as a workflow artifact (in addition to the existing MSI artifact in the `build-msi` job)
- [ ] **Code-signing placeholder** — a commented-out step in the `build-msi` job showing where code signing will be integrated when a signing certificate is available (references GitHub secrets)

### Preserved (untouched logic)
- [ ] `test` job: `go mod verify`, `go vet`, `go test -race`, cross-compile for windows/amd64 and windows/arm64
- [ ] `format` job: `go fmt` diff check
- [ ] `validate-wix` job: XML well-formedness and include references
- [ ] `build-msi` job: Windows runner, builds `agent.exe`, MSI packaging, uploads MSI artifact (triggered on tags or `workflow_dispatch`)
- [ ] All triggers: `push` to `main`, `pull_request` to `main`, tags `v*`, `workflow_dispatch`
- [ ] Go version: `1.26` (single version, matches `go.mod`)
- [ ] Module caching via `actions/cache@v4`

## Out of Scope

- Automatic deployment (CD) — V1 is build verification only
- Actual code signing — no signing certificate available yet
- Coverage gate/threshold enforcement — coverage is informational only
- Test matrix with multiple Go versions — single Go 1.26
- Modifying or removing the existing `build-msi` job logic
- Changes to WiX sources or MSI packaging
- Adding external coverage services (Codecov, Coveralls, etc.)

## Impacted ADRs

| ADR | Relevance |
|-----|-----------|
| ADR-007 | Testing strategy: testcontainers-go, cross-compilation, CI on ubuntu-latest. **N.B.** ADR-007 specifies Go 1.22/1.23 matrix, but `go.mod` and prior sprints use Go 1.26. This sprint uses Go 1.26. The ADR is not modified. |

## Acceptance Criteria

1. `.golangci.yml` exists at repo root with a minimal, pragmatic configuration
2. `golangci-lint` runs as a separate job in `ci.yml`, prior to or parallel with `test`
3. `go test -race -coverprofile=coverage.out ./...` generates a coverage report; `coverage.out` is uploaded as a workflow artifact
4. Cross-compiled `agent.exe` (windows/amd64) is uploaded as a standalone workflow artifact in addition to the existing MSI artifact
5. A commented-out code-signing step exists in `build-msi` with clear documentation of the required secrets
6. All existing jobs continue to pass: `go vet`, `go test -race`, cross-compilation, `go fmt`, WiX validation
7. No PII appears in CI logs
8. No secrets committed to the repository

## Expected Tests

- Manual verification: push a branch, open a PR, confirm all jobs pass on GitHub Actions
- Verify `coverage.out` artifact is downloadable and contains valid coverage data
- Verify `agent.exe` artifact is downloadable and is a valid Windows PE binary
- Verify `golangci-lint` catches a deliberate linting violation (e.g., in a test commit)
- Verify code-signing placeholder does not run (commented out) and does not break the workflow

## Notes

- The existing CI was built during QINDU-0001/QINDU-0002 and is functional. This sprint is additive only.
- `golangci-lint` configuration should be pragmatic: enable `govet`, `staticcheck`, `errcheck`, `gosimple`, `unused`, `ineffassign`, `unconvert`, `misspell`. Do not enable opinionated or noisy linters that would block development.
- The coverage report is uploaded as a raw artifact; no external service integration.
- Docker is required on the runner for `testcontainers-go` integration tests; `ubuntu-latest` provides this by default.
