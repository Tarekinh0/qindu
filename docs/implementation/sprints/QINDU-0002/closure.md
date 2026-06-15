# Closure — QINDU-0002: Installer Windows + Service

**Date**: 2026-06-15
**Orchestrator**: qindu-orchestrator
**Final Verdict**: ✅ **PASS**

---

## Sprint Summary

Produced a complete MSI installer (WiX Toolset) that deploys the Qindu agent as a Windows service under LocalService, generates and installs the CA root certificate with Name Constraints into the machine trust store, configures Chrome/Edge browser policies (PAC URL + QUIC disabled), sets up explicit firewall loopback rules, and provides clean uninstall with user choice on data deletion. The CA generation subcommand (`ca-init`) was added to the single agent binary, with Name Constraints by default and an opt-in unsafe mode gated behind interactive confirmation.

---

## Gate Results

| # | Gate | Agent | Verdict | Artifact |
|---|------|-------|---------|----------|
| 1 | Init | orchestrator | ✅ | `story.md` |
| 2a | Design (Privacy) | qindu-dpo | PROCEED_WITH_CAVEATS | `dpo-requirements.md` |
| 2b | Design (Security) | qindu-ciso | PROCEED_WITH_CAVEATS | `ciso-requirements.md` |
| 3 | Implementation | qindu-devsecops | ✅ (7 rounds, 30+ bugs fixed) | 18+ files, `dev-notes.md` |
| 4 | Peer Review | qindu-peer-reviewer | MERGE_READY (4.1/5), 6 rounds | `peer-review.md` |
| 5a | CISO Review | qindu-ciso | PASS (18/18 SR-INSTALLER, 10/10 SR continuity) | `ciso-review.md` |
| 5b | DPO Review | qindu-dpo | PASS (12/12 R) | `dpo-review.md` |
| 6a | QA Validation | qindu-qa | PASS (148 tests, 15/15 AC, 20/20 CISO, 18/18 DPO) | `qa-review.md` |
| 6b | Release Validation | qindu-release | PASS | `release-review.md` |
| 7 | Closure | orchestrator | PASS | `closure.md` |

---

## Process Improvements Applied During Sprint

This sprint drove significant improvements to the Qindu multi-agent governance workflow:

1. **Blank-slate peer review rule** — After each DevSecOps fix cycle, the peer reviewer is invoked as a fresh, independent session receiving only `story.md` + source code. This eliminates confirmation bias and consistently finds bugs that "informed" reviewers miss. Codified in `AGENTS.md` step 4.

2. **WiX CI validation** — A new `validate-wix` job checks XML well-formedness and include references on every push. Prevents MSI build breakers from reaching the `windows-latest` runner.

3. **Ruthless re-verification** — Peer reviewers are challenged on findings to eliminate false positives (e.g., regex false positive, `%w` on `syscall.Errno`).

4. **Cross-sprint scope vigilance** — Blank-slate reviewers found legitimate bugs in QINDU-0001 code (keep-alive bufio.Reader data corruption). These were fixed rather than deferred.

---

## Deliverables

| Artifact | Description |
|----------|-------------|
| `cmd/agent/main.go` | Added `ca-init` subcommand with Name Constraints, `--unsafe` mode, config path resolution |
| `cmd/agent/proxy.go` | Proxy runtime code (extracted from main.go for SRP) |
| `cmd/agent/ca_init_test.go` | 20 tests covering CA generation, constraints, unsafe mode, path resolution |
| `internal/tls/ca.go` | Name Constraints support in GenerateCA (`permittedDNSDomains` parameter) |
| `internal/tls/ca_helper.go` | Comma-ok type assertion fix (SEC-F4) |
| `internal/tls/cert_cache.go` | TTL expiration check in Get() and GetOrCreate() |
| `internal/policy/config.go` | MergeFileOverride with field-level provider map merging |
| `internal/proxy/forward.go` | Buffered reader reuse for keep-alive correctness |
| `internal/proxy/mitm.go` | Accurate lastStatus in connection logs |
| `internal/constants/constants.go` | Shared GracefulShutdownTimeout constant |
| `installer/wix/` | 11 files: main entry + 8 includes + locale + license |
| `.github/workflows/ci.yml` | Added `validate-wix` and `build-msi` jobs |
| `AGENTS.md` | Blank-slate peer review rule codified |

---

## Metrics

| Metric | Value |
|--------|-------|
| Tests passing | 148 (with `-race`) |
| Peer review rounds | 6 |
| DevSecOps fix rounds | 7 |
| Blocking bugs found & fixed | 30+ |
| False positives caught (reviewer errors corrected) | 3 |
| CISO SR-INSTALLER satisfied | 18/18 |
| DPO requirements satisfied | 12/12 |
| Acceptance criteria met | 15/15 |
| Go version | 1.26 |
| Cross-compilation | GOOS=windows GOARCH=amd64 ✅ |

---

## Known Caveats (Non-Blocking)

- MSI is unsigned — SmartScreen shows warning on download (accepted for V1 dev)
- Windows VM integration testing is manual (not automated in CI)
- DPAPI code has no unit test coverage (requires Windows)
- `CertCache` TTL eviction is lazy (entries linger until size-triggered eviction or reuse)
- Config override boolean fields (`CertCacheEnabled`, `PIILogging`) cannot be set to `false` via override (yaml.v3 limitation with zero values)

---

## Verdict

**PASS.** The sprint delivers all 15 acceptance criteria with production-grade Go code (4.1/5 peer review score), comprehensive tests (148 passing with `-race`), and a well-structured WiX MSI installer. All 18 CISO security requirements and 12 DPO privacy requirements are satisfied. The sprint advanced to Windows MSI packaging and is ready for the next phase (QINDU-0004 CI/CD Pipeline, QINDU-0005 PII Engine).
