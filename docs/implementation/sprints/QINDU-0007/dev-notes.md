# QINDU-0007 Dev Notes — Mode Monitor (Fix Round 2)

**Author**: Qindu DevSecOps
**Date**: 2026-07-04
**Status**: IMPLEMENTED — QEMU report fixes applied

---

## 1. Fix Round 2 — QEMU Report Remediation

**Trigger**: QEMU test report verdict **PASS** with one blocking operational limitation: log persistence to disk is missing. Three additional findings (F-1, F-2, F-3) addressed.

---

### CHANGE 1: Log persistence to disk (BLOCKING — Section 4)

**Problem**: `InitLogger` hardcoded `os.Stderr` as the sole log output. When running as a Windows service (`NT AUTHORITY\LocalService`), `os.Stderr` is discarded by the SCM. This makes all logs — startup messages, connection metadata, and most critically, PII detection entries — invisible during service operation.

**Fix**: Added configurable log output destination to `InitLogger` and `LoggingConfig`.

#### Files modified

| File | Change |
|---|---|
| `internal/policy/config.go` | Added `Output string` (`"stderr"`, `"file"`, `"both"`) and `LogDir string` fields to `LoggingConfig`. Updated `DefaultConfig()` with safe defaults (`"stderr"`, `""`). Updated `MergeFileOverride()` to merge new fields. |
| `internal/logging/logger.go` | Changed `InitLogger(level, format string)` → `InitLogger(level, format, output, logDir string)`. Added `resolveLogWriter()`, `openLogFile()`, and `defaultLogDir()` helpers. File output creates `agent.log` with append mode in the configured directory (auto-creates it via `MkdirAll`). Falls back to stderr on failure with a diagnostic warning. `"both"` mode uses `io.MultiWriter(os.Stderr, file)`. |
| `internal/logging/logger_test.go` | Updated all 3 existing tests for new signature. Added 3 new tests: `TestInitLogger_FileOutput` (JSON in file), `TestInitLogger_BothOutput` (file + stderr), `TestInitLogger_FileOutputFallback` (graceful fallback). Added `os` import. |
| `cmd/agent/proxy.go` | Passes `cfg.Logging.Output` and `cfg.Logging.LogDir` to `InitLogger`. |
| `configs/default.yaml` | Added `output: "stderr"` and `log_dir: ""` comments. |
| `installer/wix/configs/default.yaml` | Same additions. |

#### Design decisions

- **`os.O_APPEND` mode**: Log file grows indefinitely; no rotation yet (DPO-R10: deferred). Open file handle lives for process lifetime (closed by OS on exit).
- **`defaultLogDir()`**: On Windows → `%PROGRAMDATA%\Qindu\logs`; on other → `$HOME/.qindu/logs` or `$TMPDIR/qindu-logs`.
- **Empty `output` falls back to stderr**: Backward-compatible with configs created before this change.
- **No auto-detection of service mode for output**: The config explicitly controls output destination. Users who want file logging in service mode set `output: "file"` in config. This keeps the logging layer unaware of the service/console distinction.

#### How to enable file output for service mode

```yaml
# In %PROGRAMFILES%\Qindu\configs\default.yaml (or override at %PROGRAMDATA%\Qindu\config.yaml):
logging:
  output: "file"          # or "both" for stderr + file
  log_dir: ""              # auto-detect: C:\ProgramData\Qindu\logs
```

---

### CHANGE 2: SSH session detected as service mode (F-1 — MEDIUM)

**Problem**: `svc.IsAnInteractiveSession()` returns `false` for SSH sessions, causing the agent to try `svc.Run()` and fail with "The service process could not connect to the service controller." This blocks debugging and testing via SSH.

**Fix**: Added `--console` flag and `QINDU_CONSOLE=1` env var to force console mode.

#### Files modified

| File | Change |
|---|---|
| `cmd/agent/main.go` | Added `--console` flag (`flag.Bool`). Added `os.Getenv("QINDU_CONSOLE") == "1"` check. Combined into `forceConsole bool` passed to `runProxy()`. |
| `cmd/agent/proxy.go` | `runProxy()` accepts `forceConsole bool`. `startProxy()` accepts `forceConsole bool`. When `forceConsole` is true, service detection is bypassed and console mode runs directly (logs "running in console mode (forced)"). |

#### Usage

```powershell
# Via SSH:
$env:QINDU_CONSOLE = "1"
& "C:\Program Files\Qindu\agent.exe" -config "C:\Program Files\Qindu\configs\default.yaml"

# Or with flag:
& "C:\Program Files\Qindu\agent.exe" --console
```

---

### CHANGE 3: `configs/default.yaml` mode default (F-3 — HIGH)

**Problem**: Both `configs/default.yaml` and `installer/wix/configs/default.yaml` shipped with `mode: "enforce"`. Since enforce mode is not implemented (QINDU-0009), the agent returns a fatal error from `NewProxy`, which causes the MSI service auto-start to fail, which triggers a full MSI rollback.

**Fix**: Changed `mode: "enforce"` → `mode: "monitor"` and `pii_logging: false` → `pii_logging: true` in both config files. Also updated comments to list all three valid modes.

#### Files modified

| File | Change |
|---|---|
| `configs/default.yaml` | `mode: "monitor"`, `pii_logging: true`, added `output: "stderr"` and `log_dir: ""` with comments. |
| `installer/wix/configs/default.yaml` | Same changes (MSI shipped copy). |

#### Note

`DefaultConfig()` in `internal/policy/config.go` retains `Mode: "enforce"` per story specification (forward compatibility for QINDU-0009). The YAML default is what gets shipped; the `DefaultConfig()` function is for programmatic use.

---

### CHANGE 4: CA trust store (Section 2 — noted, not fixed)

The QEMU report notes that `certutil -store Root "Qindu AI Privacy CA"` returns `NTE_NOT_FOUND`. CA files exist at `C:\ProgramData\Qindu\` but are not in the Windows trust store. This is a pre-existing infrastructure issue from the installer (QINDU-0004), not a QINDU-0007 regression. The CA cert installation sequence may have been rolled back by a previous failed MSI install. This must be verified by the installer sprint; it does not block QINDU-0007's functional correctness.

---

## 2. Complete File Summary

### Created (prior rounds)

| File | Lines | Purpose |
|---|---|---|
| `internal/interceptor/monitor.go` | ~424 | MonitorInterceptor implementation |
| `internal/interceptor/sse.go` | ~325 | SSE frame reader |
| `internal/interceptor/monitor_test.go` | ~882 | 28 unit tests |
| `internal/interceptor/sse_test.go` | ~597 | 11 unit tests |

### Modified (all rounds)

| File | Round 1 | Round 2 | Round 3 | Summary |
|---|---|---|---|---|
| `internal/proxy/proxy.go` | ✅ | — | ✅ | Interceptor selection, engine creation moved to selectInterceptor |
| `internal/policy/config.go` | ✅ | ✅ (output/log_dir) | ✅ (mode+validation) | Mode default changed to "monitor"; logging.output validated |
| `internal/policy/config_test.go` | ✅ | — | — | 6 AgentMode validation cases |
| `internal/logging/logger.go` | — | ✅ | ✅ (closer) | File output + multiWriteCloser + InitLogger returns closer |
| `internal/logging/logger_test.go` | — | ✅ | ✅ (filepath.Join) | Test signature updates + filepath.Join fixes |
| `internal/pii/engine.go` | — | — | ✅ (MaxInputLen) | Added MaxInputLen() accessor |
| `internal/interceptor/monitor.go` | — | — | ✅ | Removed redundant maxInputLen param from constructor |
| `internal/interceptor/monitor_test.go` | — | — | ✅ | Updated 22 call sites for 3-arg constructor |
| `internal/proxy/proxy_test.go` | — | — | ✅ | DefaultConfig test repurposed for monitor mode |
| `cmd/agent/proxy.go` | — | ✅ | ✅ (closer) | Logging config pass-through + defer closer.Close() |
| `cmd/agent/main.go` | — | ✅ | — | --console flag + QINDU_CONSOLE env var |
| `configs/default.yaml` | — | ✅ | — | mode=monitor, pii_logging=true, output/log_dir |
| `installer/wix/configs/default.yaml` | — | ✅ | — | Same as above (MSI shipped copy) |

---

## 3. Test Results (Fix Round 3)

```
$ go build ./...  → PASS
$ go vet ./...    → PASS
$ go test -race -count=1 ./...
ok  	github.com/Tarekinh0/qindu/cmd/agent	1.066s
?   	github.com/Tarekinh0/qindu/internal/constants	[no test files]
ok  	github.com/Tarekinh0/qindu/internal/interceptor	1.728s
ok  	github.com/Tarekinh0/qindu/internal/logging	1.031s
ok  	github.com/Tarekinh0/qindu/internal/pii	1.695s
ok  	github.com/Tarekinh0/qindu/internal/policy	1.056s
ok  	github.com/Tarekinh0/qindu/internal/proxy	3.999s
?   	github.com/Tarekinh0/qindu/internal/service	[no test files]
ok  	github.com/Tarekinh0/qindu/internal/tls	1.859s
ok  	github.com/Tarekinh0/qindu/internal/tokenize	1.789s
```

- 10 packages PASS, 0 failures, 0 data races
- All existing tests updated for new `InitLogger` and `NewMonitorInterceptor` signatures
- Logging tests: 8 tests (3 original + 3 file/both + connection + NoPII)
- Monitor tests: 28 unit tests updated for 3-arg constructor
- Proxy tests: `TestNewProxy_DefaultConfigIsValid` replaces `TestNewProxy_DefaultConfigIsEnforce`
- Policy tests: `TestValidate_AgentMode` unchanged; `logging.output` validation covered by default config validation

---

## 4. How to Verify File Logging (QEMU Re-Test)

1. **Edit the shipped config** to use file output:
   ```yaml
   # C:\Program Files\Qindu\configs\default.yaml
   logging:
     output: "file"
     log_dir: ""   # defaults to C:\ProgramData\Qindu\logs
   ```

2. **Restart the QinduAgent service**:
   ```powershell
   Restart-Service QinduAgent
   ```

3. **Verify log file exists and contains startup entries**:
   ```powershell
   Get-Content "C:\ProgramData\Qindu\logs\agent.log"
   ```
   Expected: JSON lines including `"Monitor mode active..."` with `"pii_logging":true`.

4. **Send synthetic PII through the proxy** (AC #12–#14):
   ```powershell
   curl -x http://127.0.0.1:8787 -k -X POST \
     -d '{"prompt":"My email is test@example.com and phone +1-555-0123"}' \
     -H "Content-Type: application/json" \
     https://chatgpt.com/api/test
   ```

5. **Verify detection log entry in the log file**:
   ```powershell
   Select-String -Path "C:\ProgramData\Qindu\logs\agent.log" -Pattern "pii_detected"
   ```
   Expected: JSON entry with `"entity_count":2`, `"entity_summary":{"EMAIL":1,"PHONE":1}`, `"pii_values_logged":false`.

6. **Toggle to transparent mode** (AC #16):
   - Edit config: `mode: "transparent"`
   - Restart service
   - Send same prompt
   - Verify log file has **zero** `pii_detected` entries (connection logs only)
   - Revert to `mode: "monitor"`, restart, verify entries return

7. **Test --console mode** (F-1 fix):
   ```powershell
   Stop-Service QinduAgent
   $env:QINDU_CONSOLE = "1"
   & "C:\Program Files\Qindu\agent.exe" --console
   ```
   Expected: service detection bypassed, runs in foreground, logs to stderr.

---

## 5. Remaining Gaps

| Gap | Severity | Notes |
|---|---|---|
| **Log rotation** | MEDIUM | File grows indefinitely in append mode. DPO-R10 recommends 7–30 day retention. Not blocking — deferred. |
| **`pii_logging` pointer fix** | MEDIUM | DPO-R12 / QINDU-0002 PR-104: `PIILogging bool` zero-value problem means override file `pii_logging: true` is indistinguishable from absent. Tracked for QINDU-0009. |
| **F-2: MSI uninstall orphaned registration** | LOW | Documentation issue — `sc delete` breaks MSI uninstall. The correct uninstall path is `msiexec /x`. No code fix needed for QINDU-0007. |
| **CA trust store not populated** | MEDIUM | Pre-existing from QINDU-0004 installer. CA files exist at `C:\ProgramData\Qindu\` but trust store entry may be missing. Must be fixed in installer sprint; does not block QINDU-0007 functionality (proxy can still generate leaf certs). |
| **SSE timeout on stalled connections** | LOW | Known limitation from Round 1: if upstream completely stalls (zero bytes), Go's blocking `Read` never returns and the 30s timeout cannot fire. `net.Conn` read deadline should handle this at transport layer. |

---

## 6. Fix Round 3 — Peer Review Remediation (PR-001 to PR-102)

**Trigger**: Peer review verdict `FIX_AND_RESUBMIT` with 2 blocking findings and 5 non-blocking recommendations. All findings fixed.

### PR-001 🔴 Log file handle never closed — FIXED

**Files**: `internal/logging/logger.go`, `internal/logging/logger_test.go`, `cmd/agent/proxy.go`

- Added `nopCloser` type (no-op `Close()` for stderr).
- Added `multiWriteCloser` struct that wraps `io.MultiWriter` composition with an `[]io.Closer` slice, using `errors.Join` for batched close.
- Changed `resolveLogWriter` return type from `io.Writer` to `(io.Writer, io.Closer)`. The `"file"` case returns the `*os.File` directly as both writer and closer. The `"both"` case returns a `multiWriteCloser` holding the file closer.
- Changed `InitLogger` return type from `*slog.Logger` to `(*slog.Logger, io.Closer)`. The caller is responsible for `defer closer.Close()`.
- Updated `cmd/agent/proxy.go` to capture and defer the closer.
- Updated all 5 test call sites in `logger_test.go`.

### PR-002 🟡 DefaultConfig() mode vs YAML inconsistency — FIXED

**Files**: `internal/policy/config.go`, `internal/proxy/proxy_test.go`

- Changed `DefaultConfig().Agent.Mode` from `"enforce"` to `"monitor"` — matching `configs/default.yaml`.
- Renamed `TestNewProxy_DefaultConfigIsEnforce` → `TestNewProxy_DefaultConfigIsValid`, now asserting the default config creates a valid proxy instance (monitor mode).

### PR-003 🟡 No validation of `logging.output` — FIXED

**File**: `internal/policy/config.go`

- Added `logging.output` validation in `Config.Validate()`: accepts `"stderr"`, `"file"`, `"both"`, or `""`; rejects anything else with a descriptive error.

### PR-005 🟢 `filepath.Join` in tests — FIXED

**File**: `internal/logging/logger_test.go`

- Replaced `tmpDir + "/agent.log"` with `filepath.Join(tmpDir, "agent.log")` in `TestInitLogger_FileOutput` and `TestInitLogger_BothOutput`.
- Added `"path/filepath"` import.

### PR-100 🟡 Engine creation deferred — FIXED

**Files**: `internal/proxy/proxy.go`, `internal/proxy/proxy_test.go`

- Moved engine creation from `NewProxy` into `selectInterceptor`, only creating the `pii.Engine` with all 9 recognizers for `"monitor"` mode.
- `selectInterceptor` no longer takes `*pii.Engine` parameter — it creates one itself when needed.
- In `"transparent"` mode, no engine is created at all (zero cost for unused features).
- `NewProxy` signature unchanged; engine is now created lazily.

### PR-102 🟡 Removed redundant `maxInputLen` parameter — FIXED

**Files**: `internal/pii/engine.go`, `internal/interceptor/monitor.go`, `internal/interceptor/monitor_test.go`, `internal/proxy/proxy.go`

- Added `MaxInputLen() int` method to `pii.Engine` exposing the already-present `maxInputLen` field.
- Removed `maxInputLen int` parameter from `NewMonitorInterceptor` — the value is now read from `engine.MaxInputLen()`.
- Updated `selectInterceptor` in proxy.go: call is `NewMonitorInterceptor(engine, cfg.Logging.PIILogging, logger)`.
- Updated all 22 test call sites in `monitor_test.go`:
  - Standard tests: dropped the `pii.DefaultMaxInputBytes` argument.
  - Oversize tests (`OversizeBodyWithClosingReader`, `OversizeBodyCloseIsPropagated`): now create a small engine (`pii.NewEngine(100, ...)`) instead of passing a mismatched limit.

---

## 7. Unchanged per Sprint Constraints

- `internal/pii/` — `MaxInputLen()` added as a read-only accessor; no behavioral change
- `Interceptor` interface — unchanged
- `NoOpInterceptor` — unchanged
- `forward.go` — unchanged
- ADRs — unchanged
- `story.md`, `dpo-requirements.md`, `ciso-requirements.md` — unchanged (not for DevSecOps)
