# Release Review — QINDU-0009 (Mode Enforce + Réhydratation)

**Reviewer**: qindu-release  
**Date**: 2026-07-06  
**Verdict**: **PASS** ✅

---

## 1. Checklist Summary

| Check | Status | Notes |
|-------|--------|-------|
| Build integrity (`go build ./...`) | ✅ PASS | Linux native build clean |
| Cross-compilation (`GOOS=windows GOARCH=amd64`) | ✅ PASS | Windows amd64 cross-compile clean |
| Cross-compilation (`GOOS=windows GOARCH=arm64`) | ✅ PASS | Windows arm64 cross-compile clean |
| All tests (`go test -race ./...`) | ✅ PASS | 18 packages, zero failures |
| go.sum integrity (`go mod verify`) | ✅ PASS | All modules verified |
| No new external dependencies | ✅ PASS | `go.mod` unchanged — same 3 direct deps (bbolt, x/sys, yaml.v3) |
| MSI packaging unaffected | ✅ PASS | No changes to `installer/wix/*.wxs` |
| Binary size increase reasonable | ✅ PASS | Linux: 11 MB, Windows: 12 MB — typical Go binary |
| No secrets or credentials | ✅ PASS | Zero findings after thorough scan |
| No CA private keys exposed | ✅ PASS | No PEM material in any changed file |
| No PII in test fixtures | ✅ PASS | All test data uses `@example.com` (RFC 6761) and synthetic phone numbers |
| CI pipeline not broken | ✅ PASS | CI workflow compatible — same dependencies, same Go version |

---

## 2. Detailed Findings

### 2.1 Build Integrity

Both native Linux and cross-compiled Windows builds succeed cleanly:

```
$ go build ./...                          # PASS
$ GOOS=windows GOARCH=amd64 go build ./... # PASS
$ GOOS=windows GOARCH=arm64 go build ./...  # PASS
```

The new files (`enforce.go`, `enforce_sse.go`, `segments.go`, `conversation.go`) and their test companions compile without errors or warnings.

### 2.2 Test Suite

All 18 packages pass with race detector:

```
ok  github.com/Tarekinh0/qindu/internal/interceptor  0.231s
ok  github.com/Tarekinh0/qindu/internal/policy        0.006s
ok  github.com/Tarekinh0/qindu/internal/proxy         2.815s
ok  github.com/Tarekinh0/qindu/internal/tokenize      (cached)
ok  github.com/Tarekinh0/qindu/internal/vault         18.508s
```

Notable: the new vault async channel overflow test (`TestAsyncChannelOverflowWarn`) exercises the R-013 backpressure scenario and passes correctly. Longest test (`vault`) at ~18s is within normal bounds for the bbolt-backed vault.

### 2.3 Dependencies & Supply Chain

**go.mod — unchanged**. The diff modifies zero lines in `go.mod`:

```
require (
    go.etcd.io/bbolt v1.5.0
    golang.org/x/sys v0.46.0
    gopkg.in/yaml.v3 v3.0.1
)
```

**go.sum — unchanged**. All checksums verified by `go mod verify`. No new indirect dependencies introduced. The `encode_sse.go` file uses only standard library packages (`bufio`, `bytes`, `fmt`, `io`, `log/slog`, `strings`, `unicode/utf8`).

### 2.4 Secrets & Credentials

**Zero findings**. A comprehensive grep for API keys, passwords, PEM blocks, GitHub tokens, and credential patterns across all changed files found:

- `github_pat_` and `ghp_` patterns appear **only** in `internal/pii/secret_prefix.go` — these are PII detection regex patterns, not actual credentials.
- `PRIVATE KEY` and similar strings appear **only** in PII detection code, test verification strings (ensuring secrets are NOT leaked), and the CA test helper.
- No hardcoded API keys, tokens, passwords, or certificate material in any changed file.

### 2.5 CI/CD Pipeline Analysis

The existing CI workflow at `.github/workflows/ci.yml` runs:

| Job | What it validates | Impact of QINDU-0009 |
|-----|-------------------|---------------------|
| **Lint** | golangci-lint v2.7.2 on `./...` | New code passes lint rules (govet, staticcheck, errcheck, unused, ineffassign, unconvert, misspell) |
| **Test & Build** | `go test -race`, cross-compile win/amd64 + win/arm64, build agent.exe | All new packages included in `./...` |
| **Format** | `go fmt` + git diff check | Consistent with existing formatting |
| **Validate WiX** | XML well-formedness + include resolution | No WiX changes — unaffected |
| **Build MSI** | Windows runner, WiX Toolset 3.14.1 | No WiX changes — unaffected |

The CI uses pinned GitHub Actions by commit SHA (v4.2.2, v5.4.0, v4.2.3, v7). No new actions introduced.

### 2.6 MSI Packaging

The WiX installer source at `installer/wix/qindu.wxs` and its includes (`service.wxs`, `files.wxs`, `cleanup.wxs`, `ca-trust.wxs`, `firewall.wxs`, `dialogs.wxs`, `registry-*.wxs`) are **unchanged** by this sprint. The MSI build in CI is triggered on tag push and `workflow_dispatch` only.

### 2.7 Binary Size

| Target | Size |
|--------|------|
| Linux amd64 (`agent`) | 11 MB |
| Windows amd64 (`agent.exe`) | 12 MB |

These are standard Go binary sizes for an application with PII engine (9 recognizers), TLS interception, vault (bbolt + crypto), and network proxy. No significant increase attributable to this sprint — the enforce pipeline adds no new CGo or embedded assets, only Go code.

### 2.8 Code Signing

Code signing (Authenticode) is **not yet implemented**. The CI contains a commented-out signing step with full documentation referencing `docs/signing.md`. This is appropriate for pre-1.0 development:

```yaml
# ─── Code Signing (Future) ─────────────────────────────────────────
# Uncomment and configure this step when an EV Code Signing
# Certificate is available.
```

**Finding R-034**: Code signing not implemented. Track as a pre-release requirement. Not a sprint-level blocker.

### 2.9 SBOM & Provenance

SBOM generation (SPDX/CycloneDX) and SLSA provenance attestation are **not present** in the CI pipeline. The CI does generate SHA256 checksums for `agent.exe` and `Qindu-Installer-x64.msi` artifacts, which provides basic integrity verification.

**Finding R-035**: SBOM generation and SLSA provenance not implemented. Track as pre-release requirements for V1.0. Not a sprint-level blocker since Qindu is in active development with no tagged production release.

---

## 3. Architecture Compliance

The sprint respects all applicable ADR anchors:

- **ADR-002** (CONNECT MITM): `handleMITM` extended with vault wiring, no changes to TLS interception flow.
- **ADR-004** (Interceptor interface): New `EnforceInterceptor` implements the same `Interceptor` interface — no breaking changes.
- **ADR-008** (slog JSON sans PII): All log entries include `pii_values_logged: false`. The sliding buffer is zeroed on close (`emitAndCleanup`). No PII values in any log format.

Config fix R-024 (`*bool` for `PIILogging`, `CertCacheEnabled`; `*string` for `FailMode`) is backward-compatible — existing YAML files parse correctly, nil-safe accessors provide defaults.

---

## 4. Inherited Risk Status

| Risk | Sourced from | This sprint |
|------|-------------|-------------|
| R-013 (async channel overflow) | QINDU-0008 | **Tested**: `TestAsyncChannelOverflowWarn` verifies WARN emission without PII leakage |
| R-024 (config bool ambiguity) | QINDU-0008 | **Fixed**: `*bool`/`*string` pointers with nil-safe accessors |
| R-033 (SeImpersonatePrivilege) | QINDU-0008 | **Warned**: Startup WARN if enforce mode on Windows |
| R-004 (chunk evasion) | QINDU-0007 | **Mitigated** for responses: 4KB sliding buffer in SSE rehydration. Request chunk evasion still accepted. |
| R-005 (core dump PII) | QINDU-0007 | Accepted — Go runtime limitation (unchanged) |
| R-017 (valueToToken heap) | QINDU-0006 | Accepted — documented trade-off (unchanged) |
| R-023 (IBAN/IP not detected) | QINDU-0005 | Accepted — engine gap (unchanged) |
| R-031 (vault not cleaned on uninstall) | QINDU-0008 | Accepted — MSI limitation (unchanged) |

---

## 5. Verdict

**PASS** ✅

The QINDU-0009 sprint is release-ready from a supply chain perspective. All builds succeed, all tests pass, no new dependencies, no secrets exposed, no CI regressions, and MSI packaging is unaffected. The two pre-release concerns identified (code signing, SBOM/provenance) are documented as R-034 and R-035 for tracking and do not block this sprint.

---

*End of release review.*
