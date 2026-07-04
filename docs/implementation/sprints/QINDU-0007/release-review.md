# Release Review — Sprint QINDU-0007 (Re-Verification After Fix Cycle)

**Reviewer**: Qindu Release Manager (Release & Supply-Chain Security)
**Sprint**: QINDU-0007 — Mode Monitor (détection sans modification)
**Date**: 2026-07-04
**Previous review**: PASS (2026-07-04)
**Trigger**: QEMU-triggered fix cycle — file logging, `--console` flag, default config changes

---

## Verdict

### ✅ PASS

All release gates remain green after the fix cycle. Zero new external dependencies. `go.sum` integrity verified. All test suites pass with the race detector. The MSI installer is unaffected structurally — all new Go packages compile into `agent.exe`. The three QEMU-reported operational issues (log persistence, SSH service-mode detection, enforce-mode default blocking MSI install) are resolved without introducing supply-chain regressions. No secrets, CA keys, or PII values in any source file or build artifact.

---

## 1. Fix Cycle Change Summary

### Modified files (15 files, +373/−33 lines)

| File | Change | Supply-Chain Impact |
|------|--------|---------------------|
| `internal/logging/logger.go` | File-based log output via `InitLogger` returning `io.Closer`; `resolveLogWriter`, `openLogFile`, `defaultLogDir` helpers; `multiWriteCloser` and `nopCloser` types | ✅ Safe — stdlib-only (`io`, `os`, `path/filepath`, `runtime`, `errors`, `fmt`). No new imports. |
| `internal/logging/logger_test.go` | 3 new tests (`FileOutput`, `BothOutput`, `Fallback`) + signature updates for all 5 existing test call sites | ✅ Safe — test-only. Uses `os.ReadFile`, `json.Valid`, `filepath.Join`. |
| `internal/policy/config.go` | `agent.mode` validation (`transparent`/`monitor`/`enforce`); `logging.output` validation (`stderr`/`file`/`both`/`""`); `Output` and `LogDir` fields on `LoggingConfig`; `DefaultConfig()` mode changed to `"monitor"`; `MergeFileOverride` extended for new fields | ✅ Safe — stdlib-only. No new imports. |
| `internal/policy/config_test.go` | `TestValidate_AgentMode` (6 cases); updated `TestMergeFileOverride_AgentFieldMerged` to use valid modes | ✅ Safe — test-only. |
| `internal/proxy/proxy.go` | `NewProxy` returns `(*Proxy, error)`; `selectInterceptor` creates engine lazily for `"monitor"` mode; imports `interceptor` and `pii` packages | ✅ Safe — internal package imports only. |
| `internal/proxy/proxy_integration_test.go` | Adapted to `NewProxy` error return (one call site) | ✅ Safe — test-only. |
| `cmd/agent/main.go` | `--console` flag + `QINDU_CONSOLE` env var | ✅ Safe — `flag` + `os` stdlib. |
| `cmd/agent/proxy.go` | `runProxy` and `startProxy` accept `forceConsole`; `InitLogger` closer deferred; `NewProxy` error handling | ✅ Safe — stdlib-only. |
| `configs/default.yaml` | `mode: "monitor"`, `pii_logging: true`, `output: "stderr"`, `log_dir: ""` | ✅ Safe — config change only. |
| `installer/wix/configs/default.yaml` | Same changes (MSI copy) | ✅ Safe — identical to `configs/default.yaml`. |
| `installer/wix/includes/files.wxs` | Binary name: `qindu-agent.exe` → `agent.exe` | ✅ Safe — matches actual Go build output. |
| `installer/wix/locale/en-us.wxl` | Unicode em-dashes/bullets → ASCII (`—` → `--`, `•` → `*`) | ✅ Safe — Windows-1252 code page compatibility. |
| `internal/pii/engine.go` | `MaxInputLen() int` accessor (read-only) | ✅ Safe — backward-compatible, no behavioral change. |
| `internal/proxy/proxy_test.go` | NEW: 5 mode-selection tests (enforce-fatal, transparent, monitor, default-valid, start-time) | ✅ Safe — test-only, internal imports. |
| `installer/wix/agent.exe` | Binary artifact rebuilt (10.9 MB → 10.9 MB) | ✅ Safe — same dependency set. |

### Created files (no MSI packaging impact)

| File | Lines | Purpose |
|------|------:|---------|
| `internal/interceptor/monitor.go` | ~424 | `MonitorInterceptor` — PII detection, zero-PII logs, byte-identical forwarding |
| `internal/interceptor/sse.go` | ~325 | `SSEFrameReader` — per-frame SSE PII detection |
| `internal/interceptor/monitor_test.go` | ~882 | 28 unit tests, race-clean |
| `internal/interceptor/sse_test.go` | ~597 | 11 SSE unit tests, race-clean |

All new files are Go internal packages compiled into `agent.exe`. No new files to add to the MSI WiX config — the `files.wxs` references only `agent.exe` (the compiled binary), `configs\default.yaml`, and runtime directories.

---

## 2. Dependency & Supply-Chain Analysis

### go.mod / go.sum

| Check | Status | Detail |
|-------|:------:|--------|
| `go.mod` changed | ✅ No | Identical to baseline — no new `require`, `replace`, or `exclude` directives |
| `go.sum` changed | ✅ No | Identical to baseline. All module hashes verified. |
| `go mod verify` | ✅ PASS | `all modules verified` |
| `go mod tidy` | ✅ CLEAN | No changes produced. Module graph is consistent. |
| `go mod graph` | ✅ STABLE | Only existing dependencies: `golang.org/x/sys`, `gopkg.in/yaml.v3`, `gopkg.in/check.v1`, `github.com/kr/pretty`, `github.com/rogpeppe/go-internal` |

### Dependency inventory (unchanged)

```
github.com/Tarekinh0/qindu
├── golang.org/x/sys@v0.46.0       (Windows service APIs)
├── gopkg.in/yaml.v3@v3.0.1         (config parsing)
├── gopkg.in/check.v1@v1.0.0        (test framework, indirect)
├── github.com/kr/pretty@v0.3.1     (test helper, indirect)
└── github.com/rogpeppe/go-internal@v1.14.1 (test helper, indirect)
```

All indirect dependencies are test-only (`check.v1`, `kr/pretty`, `rogpeppe/go-internal`). The two production dependencies (`x/sys`, `yaml.v3`) are unchanged from baseline.

### Interceptor package dependencies

The `internal/interceptor/` package depends exclusively on:
- Go standard library: `bytes`, `fmt`, `io`, `log/slog`, `mime`, `net/http`, `strings`, `unicode/utf8`, `bufio`, `time`
- Internal packages: `github.com/Tarekinh0/qindu/internal/pii`

Zero third-party imports. Zero CGo dependencies (`CGO_ENABLED=0`). Fully cross-compilable.

---

## 3. Build Verification

### Native build (linux/amd64)

```
$ go build ./...
→ No output = clean
```

### Cross-compilation (windows/amd64)

```
$ GOOS=windows GOARCH=amd64 go build -o /tmp/qindu-agent-0007.exe ./cmd/agent/
→ No output = clean

$ file /tmp/qindu-agent-0007.exe
PE32+ executable for MS Windows 6.01 (console), x86-64, 16 sections
```

### go vet

```
$ go vet ./...
→ No output = clean (all packages)
```

### Binary attribution

```
$ go version -m /tmp/qindu-agent-0007.exe
go1.26.3
path  github.com/Tarekinh0/qindu/cmd/agent
dep   golang.org/x/sys   v0.46.0
dep   gopkg.in/yaml.v3   v3.0.1
build CGO_ENABLED=0
build GOOS=windows
build GOARCH=amd64
build vcs=git
build vcs.modified=true
```

No unexpected modules in the binary. `CGO_ENABLED=0` confirmed — pure Go, no native linking.

---

## 4. Test Suite

```
$ go test -race -count=1 ./...
ok   github.com/Tarekinh0/qindu/cmd/agent           1.033s
?    github.com/Tarekinh0/qindu/internal/constants   [no test files]
ok   github.com/Tarekinh0/qindu/internal/interceptor 1.474s
ok   github.com/Tarekinh0/qindu/internal/logging     1.019s
ok   github.com/Tarekinh0/qindu/internal/pii         1.446s
ok   github.com/Tarekinh0/qindu/internal/policy      1.029s
ok   github.com/Tarekinh0/qindu/internal/proxy       3.934s
?    github.com/Tarekinh0/qindu/internal/service      [no test files]
ok   github.com/Tarekinh0/qindu/internal/tls         1.308s
ok   github.com/Tarekinh0/qindu/internal/tokenize    1.549s
```

- **10 packages** (8 with tests, 2 without), **0 failures**, **0 data races**
- Coverage (key packages): interceptor 85.3%, logging 78.4%, policy 76.0%, proxy 59.3%
- New logging tests: `TestInitLogger_FileOutput`, `TestInitLogger_BothOutput`, `TestInitLogger_FileOutputFallback` — all pass
- New proxy tests: `TestNewProxy_EnforceModeFatal`, `TestNewProxy_TransparentMode`, `TestNewProxy_MonitorMode`, `TestNewProxy_DefaultConfigIsValid`, `TestNewProxy_StartTimeIsSet` — all pass
- New policy tests: `TestValidate_AgentMode` (6 cases) — all pass

---

## 5. MSI Installer Impact Assessment

### Files changed

| File | Change | Packaging Impact |
|------|--------|------------------|
| `installer/wix/includes/files.wxs` | Binary name: `qindu-agent.exe` → `agent.exe` | ✅ Fix — matches actual Go build output name |
| `installer/wix/locale/en-us.wxl` | Unicode → ASCII in display strings | ✅ Fix — Windows-1252 code page compatibility (fixes `light.exe` error `LGHT0311`) |
| `installer/wix/configs/default.yaml` | Mode, `pii_logging`, `output`, `log_dir` | ✅ Config update — shipped YAML now matches operational defaults |
| `installer/wix/qindu.wxs` | **Unchanged** | ✅ No structural MSI changes needed |
| Other includes (`*.wxs`) | **Unchanged** | ✅ No new components, directories, or files to package |

### New files requiring MSI packaging?

**None.** The `internal/interceptor/` and `internal/logging/` packages compile into `agent.exe`. The MSI ships only:
- `agent.exe` (compiled binary — includes all interceptor/logging code)
- `configs/default.yaml` (shipped config)
- Runtime directories (`ProgramData\Qindu\` with restricted ACL)

The `files.wxs` change (`qindu-agent.exe` → `agent.exe`) was already performed by the QEMU tester and is included in this working tree. No further MSI changes are needed.

### Config file sync

```
$ diff configs/default.yaml installer/wix/configs/default.yaml
→ No output = identical
```

Both shipped config sources are byte-identical. No divergence risk for this sprint.

---

## 6. Breaking Change Audit

### `NewProxy` signature change: `*Proxy` → `(*Proxy, error)`

| Call site | Status |
|-----------|--------|
| `cmd/agent/proxy.go:55` | ✅ Updated — `err` handling with `logger.Error` + exit code 1 |
| `internal/proxy/proxy_integration_test.go:90` | ✅ Updated — `t.Fatalf` on error |
| `internal/proxy/proxy_test.go` (new) | ✅ All 5 tests handle error return correctly |

All call sites are internal. No external consumers. Fully propagated and tested.

### `InitLogger` signature change: `*slog.Logger` → `(*slog.Logger, io.Closer)`

| Call site | Status |
|-----------|--------|
| `cmd/agent/proxy.go:41` | ✅ Updated — `defer logCloser.Close()` captures closer |
| `internal/logging/logger_test.go` (5 tests) | ✅ Updated — all call `defer closer.Close()` |

The `io.Closer` is always non-nil (stderr path returns `nopCloser{os.Stderr}`). Safe to defer unconditionally.

### `DefaultConfig().Agent.Mode`: `"enforce"` → `"monitor"`

| Impact | Status |
|--------|--------|
| `TestNewProxy_DefaultConfigIsEnforce` | ✅ Renamed to `TestNewProxy_DefaultConfigIsValid` — now asserts proxy creates successfully with monitor mode |
| All other default-config callers | ✅ Monitor mode is the correct operational default. No upstream callers depend on `"enforce"` — that mode would have failed at startup per AC #11 |

---

## 7. Supply Chain Security

| Concern | Previous Status | After Fix Cycle | Delta |
|---------|:------:|:------:|-------|
| **New third-party dependencies** | ✅ None | ✅ None | No change |
| **go.sum integrity** | ✅ PASS | ✅ PASS | No change — `go.sum` unchanged |
| **Vendored dependencies** | ⚠️ Not vendored | ⚠️ Not vendored | No change |
| **Binary reproducibility** | ⚠️ Not verified | ⚠️ Not verified | No change — `-trimpath` not configured |
| **SBOM generation** | ⚠️ Not implemented | ⚠️ Not implemented | No change |
| **Code signing** | ⚠️ Not implemented | ⚠️ Not implemented | No change |
| **SLSA provenance** | ⚠️ Not implemented | ⚠️ Not implemented | No change |
| **Secrets in code** | ✅ None | ✅ None | No change — diff audit confirms zero secrets |
| **CA keys in artifacts** | ✅ None | ✅ None | No change — CA generation is runtime-only |
| **PII in test fixtures** | ✅ Synthetic only | ✅ Synthetic only | All new test data uses IANA-reserved domains, NANP fiction numbers, PCI test cards |

### New supply-chain observation: log file permissions

The `openLogFile` function creates log files with `0644` permissions (world-readable). While this is not a supply-chain concern (it is a runtime behavior), it is noted here because it affects the security posture of the release artifact. CISO (F-1) and DPO (APC-6, APC-7) have flagged this as a non-blocking recommendation for `0600` / `0700` permissions. Does not block release.

---

## 8. CI/CD Pipeline Assessment (Unchanged)

There remains **no CI/CD pipeline** defined in the repository:
- No `.github/workflows/` directory
- No `Makefile` or build automation
- No CI configuration files

The `.golangci.yml` configuration exists but is not invoked automatically.

**Pre-existing gap** — not introduced or regressed by this sprint. Tracked separately for supply-chain hardening.

---

## 9. ADR Compliance

| ADR | Impact | Status |
|-----|--------|--------|
| **ADR-003** (loopback binding) | Unchanged — binds `127.0.0.1` only | ✅ Compliant |
| **ADR-004** (Interceptor interface) | `MonitorInterceptor` implements the interface without modifying it | ✅ Compliant |
| **ADR-008** (structured logging) | Detection logs use `slog.JSONHandler`. `pii_values_logged: false` enforced. File output uses same handler — no structural change. | ✅ Compliant |
| **ADR-002** (local CA) | Unchanged — TLS interception untouched | ✅ Compliant |

---

## 10. Gate Review Status

| Gate | Reviewer | Verdict | Date |
|------|----------|---------|------|
| Peer Review | qindu-peer-reviewer | **MERGE_READY** | 2026-07-04 |
| Security Review | qindu-ciso | **PASS** | 2026-07-04 |
| Privacy Review | qindu-dpo | **PASS** | 2026-07-04 |
| Quality Assurance | qindu-qa | **PASS** | 2026-07-04 |
| QEMU VM Test | qindu-qemu-tester | **PASS** | 2026-07-04 |
| **Release Review** | **qindu-release** | **✅ PASS** | **2026-07-04** |

All gates are green. No blocking findings across any review domain.

---

## 11. Pre-Existing Gaps (not introduced or regressed)

The following supply-chain and CI/CD gaps exist in the repository baseline and are unchanged by this sprint:

1. **No CI/CD pipeline** — no automated build, test, lint, or release workflow
2. **No Authenticode code signing** — `agent.exe` and the MSI installer are unsigned
3. **No SBOM generation** — no SPDX or CycloneDX SBOM produced
4. **No SLSA provenance** — no build provenance attestations generated
5. **No vendoring** — dependencies fetched from module proxy at build time
6. **No binary reproducibility measures** — no `-trimpath`, no `-buildvcs=false`
7. **Log file permissions `0644`** — tracked as CISO F-1 / DPO APC-9 (non-blocking)
8. **No log rotation** — tracked as DPO-R10 / APC-6 (non-blocking, deferred to QINDU-0016)

---

## 12. Checklist

| Gate | Status | Evidence |
|------|:------:|----------|
| **CI/CD workflows** | ⚠️ N/A | No `.github/workflows/` exists. Pre-existing gap. |
| **Test results** | ✅ PASS | 10 packages, 0 failures, 0 data races (`go test -race ./...`) |
| **Dependencies** | ✅ PASS | Zero new dependencies. `go.mod` and `go.sum` unchanged. |
| **SBOM** | ⚠️ N/A | Not implemented. Pre-existing gap. |
| **Code signing** | ⚠️ N/A | Not implemented. Pre-existing gap. |
| **Provenance** | ⚠️ N/A | Not implemented. Pre-existing gap. |
| **go.sum integrity** | ✅ PASS | `go mod verify` — all modules verified. `go mod tidy` — clean. |
| **Build (linux/amd64)** | ✅ PASS | `go build ./...` — clean |
| **Build (windows/amd64)** | ✅ PASS | `GOOS=windows GOARCH=amd64 go build ./cmd/agent/` — valid PE32+ |
| **go vet** | ✅ PASS | `go vet ./...` — clean across all packages |
| **MSI installer** | ✅ PASS | No structural changes needed. `files.wxs` binary name fix applied. Config YAML in sync. |
| **Secrets in code** | ✅ PASS | Zero secrets, CA keys, API tokens, or PII values in any source file or diff |
| **Breaking changes** | ✅ RESOLVED | `NewProxy` → error return (all 3 callers updated). `InitLogger` → `io.Closer` (all 6 callers updated). `DefaultConfig().Mode` → `"monitor"` (1 test renamed). |

---

## 13. Conclusion

The QINDU-0007 fix cycle is **release-ready** from a build, packaging, and supply-chain perspective:

- ✅ Compiles cleanly for the target platform (Windows amd64)
- ✅ Zero new external dependencies — `go.mod` and `go.sum` unchanged from baseline
- ✅ `go.sum` integrity verified (`go mod verify`)
- ✅ `go vet` clean
- ✅ All tests pass with race detector (10 packages, 0 failures, 0 races)
- ✅ Breaking changes (`NewProxy`, `InitLogger`, `DefaultConfig().Mode`) fully propagated to all callers
- ✅ MSI installer structurally unaffected — only config file and encoding fixes
- ✅ No secrets, CA keys, or PII in code or build artifacts
- ✅ All gates green: Peer MERGE_READY, CISO PASS, DPO PASS, QA PASS, QEMU PASS

The 8 pre-existing CI/CD and supply-chain gaps (no CI pipeline, no code signing, no SBOM, no provenance, no vendoring, no binary reproducibility, log file permissions `0644`, no log rotation) are noted for tracking but were not introduced or regressed by this sprint and do not block the merge.

**Verdict: PASS**
