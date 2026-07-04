# QINDU-0007 Dev Notes — Mode Monitor (Fix Round 3: Path Filtering & Per-Message Logging)

**Author**: Qindu DevSecOps
**Date**: 2026-07-04
**Status**: IMPLEMENTED — Bug 1 (path filtering) and Bug 2 (per-message logging) fixed

---

## 1. Fix Round 3 — Critical Production Bugs

**Trigger**: Two critical bugs making monitor mode useless in production:
- **Bug 1**: No path filtering — telemetry noise drowns out signal
- **Bug 2**: Per-detection logging — can't tell signal from noise

---

### CHANGE 1: Path-based scan filtering (Bug 1)

**Problem**: The interceptor scanned ALL HTTP paths, including ChatGPT telemetry (`/ces/v1/t`, `/ces/statsc/flush`, etc.), producing Luhn false positives on analytics payloads and entropy false positives on base64 session tokens.

**Fix**: Added whitelist-based path filtering. Only conversation endpoints are scanned.

#### Implementation

- Added `MonitorConfig` struct with `ScanPaths []string` to `AgentConfig` in `internal/policy/config.go`
- Default scan paths: `/conversation`, `/v1/messages`, `/chat/completions`, `generateContent`, `/chat/`
- Case-insensitive substring matching via `strings.Contains` with `strings.ToLower`
- Paths not matching the whitelist are skipped entirely — no scan, no log entry
- Validation: empty scan paths get populated with defaults; empty values in the list are rejected
- `MergeFileOverride` merges `MonitorConfig.ScanPaths` (full replacement when present)

#### Files modified

| File | Change |
|---|---|
| `internal/policy/config.go` | Added `MonitorConfig` struct, `defaultMonitorScanPaths()`, populated `DefaultConfig()`, added validation in `Validate()`, added merge in `MergeFileOverride()` |
| `internal/interceptor/monitor.go` | Added `scanPaths` field to `MonitorInterceptor`, `shouldScanPath()` method, path check at top of `InterceptRequest` and `InterceptResponse`, updated `NewMonitorInterceptor` signature |
| `internal/proxy/proxy.go` | Updated `selectInterceptor` to pass `cfg.Agent.Monitor.ScanPaths` to `NewMonitorInterceptor` (minimal change: one line) |
| `configs/default.yaml` | Added `agent.monitor.scan_paths` section |
| `installer/wix/configs/default.yaml` | Same |

---

### CHANGE 2: Per-message aggregated logging (Bug 2)

**Problem**: Each PII entity produced its own `pii_detected` log line. A single request generated dozens of lines for entropy false positives. Users couldn't find the one meaningful detection.

**Fix**: Changed log format from per-detection `pii_detected` to per-message `monitor_scan`. Every scanned message produces exactly ONE log entry.

#### New log format

```json
// PII found:
{"msg":"monitor_scan","direction":"request","result":"pii_found","entity_count":2,"entity_summary":{"EMAIL":1,"PHONE":1},"bytes_analyzed":1355,"pii_values_logged":false,"host":"api.openai.com","method":"POST","path":"/v1/chat/completions"}

// Clean (no PII):
{"msg":"monitor_scan","direction":"request","result":"clean","bytes_analyzed":452,"pii_values_logged":false,"host":"api.openai.com","method":"POST","path":"/v1/chat/completions"}
```

Key changes:
- `msg` field is `"monitor_scan"` (not `"pii_detected"`)
- `result` field: `"clean"` or `"pii_found"` — instant signal-to-noise
- `entity_count` and `entity_summary` only present when `result: "pii_found"`
- **Every** scanned message produces a log entry — even clean ones — so users can see traffic is being inspected
- No per-entity list (`entities` array removed) — `entity_summary` count map is sufficient
- `pii_values_logged` always `false`

#### SSE responses

- Frame-by-frame detection continues (for correctness)
- Detection results are **accumulated** across all frames of a single response stream
- When the stream ends (`io.EOF` or `data: [DONE]` marker), ONE aggregated `monitor_scan` is emitted
- Frames are still forwarded immediately (no buffering for forwarding, only accumulate for the log)
- `sse_frame: true` included in the aggregated entry

#### `pii_logging` flag behavior

| Setting | Engine runs? | Log emitted? | entity_summary? |
|---|---|---|---|
| `true` | Yes | Yes | Yes (when pii_found) |
| `false` | Yes | Yes | No (privacy) |

Previously (PR-103), `pii_logging: false` skipped the engine call entirely. Now the engine always runs when the path matches, but `entity_summary` is suppressed when `pii_logging: false`. This ensures users can see "traffic was scanned" without leaking entity type details.

#### Implementation (interceptor)

- Removed `logDetection()`, `buildLogEntry()`, `buildEntityLogArgs()`
- Added `logMonitorScan()` — one call per message, produces `monitor_scan` entry
- Added `buildEntitySummary()` — shared helper for entity type counting
- `InterceptRequest`/`InterceptResponse`: engine always runs when path matches; always call `logMonitorScan`

#### Implementation (SSE)

- Added aggregated fields to `SSEFrameReader`: `aggregatedSummary`, `aggregatedCount`, `totalBytesAnalyzed`, `monitorScanEmitted`, `doneMarkerSeen`
- `detectFrame()`: accumulates entity types instead of logging
- `emitAggregatedMonitorScan()`: emits one `monitor_scan` at stream end
- Triggered on `io.EOF` in `Read()` or when `data: [DONE]` marker is detected
- Guard with `monitorScanEmitted` flag to prevent double emission

#### Files modified

| File | Change |
|---|---|
| `internal/interceptor/monitor.go` | Replaced `logDetection`/`buildLogEntry`/`buildEntityLogArgs` with `logMonitorScan` and `buildEntitySummary`. Updated both intercept methods to always scan and log. |
| `internal/interceptor/sse.go` | Added aggregation fields to `SSEFrameReader`, rewrote `detectFrame` to accumulate, added `emitAggregatedMonitorScan`, added `[DONE]` marker detection |
| `internal/interceptor/monitor_test.go` | Updated all 28+ tests for new `monitor_scan` format and `NewMonitorInterceptor` 4-arg signature. Added tests: path filtering, clean-path logging, `pii_logging=false` behavior, `buildEntitySummary`, path substring matching |
| `internal/interceptor/sse_test.go` | Updated all 11+ SSE tests for aggregated logging. Added tests: `[DONE]` marker termination, clean SSE stream aggregation |

---

## 2. Complete File Summary

### Modified (this round)

| File | Lines | Summary |
|---|---|---|
| `internal/policy/config.go` | ~314 | `MonitorConfig` struct, `defaultMonitorScanPaths()`, validation, merge |
| `internal/interceptor/monitor.go` | ~499 | `scanPaths` field, `shouldScanPath()`, `logMonitorScan()`, per-message logging |
| `internal/interceptor/sse.go` | ~390 | Aggregation fields, `emitAggregatedMonitorScan()`, `[DONE]` handling |
| `internal/interceptor/monitor_test.go` | ~767 | 32+ tests updated, new path filtering + log format tests |
| `internal/interceptor/sse_test.go` | ~527 | 13+ tests updated, aggregated logging + `[DONE]` tests |
| `internal/proxy/proxy.go` | +1 line | Pass `ScanPaths` to `NewMonitorInterceptor` |
| `configs/default.yaml` | ~35 | Added `agent.monitor.scan_paths` |
| `installer/wix/configs/default.yaml` | ~39 | Same |

---

## 3. Test Results

```
$ go build ./...  → PASS
$ go vet ./...    → PASS
$ go test -count=1 ./...
ok  	github.com/Tarekinh0/qindu/cmd/agent	0.014s
?   	github.com/Tarekinh0/qindu/internal/constants	[no test files]
ok  	github.com/Tarekinh0/qindu/internal/interceptor	0.182s
ok  	github.com/Tarekinh0/qindu/internal/logging	(cached)
ok  	github.com/Tarekinh0/qindu/internal/pii	(cached)
ok  	github.com/Tarekinh0/qindu/internal/policy	0.011s
ok  	github.com/Tarekinh0/qindu/internal/proxy	2.807s
?   	github.com/Tarekinh0/qindu/internal/service	[no test files]
ok  	github.com/Tarekinh0/qindu/internal/tls	(cached)
ok  	github.com/Tarekinh0/qindu/internal/tokenize	(cached)
```

- 10 packages PASS, 0 failures
- Interceptor: 50+ tests pass (including new path filtering and aggregated log tests)
- Policy: all config tests pass (including scan path defaults and validation)

### New tests added

| Test | Covers |
|---|---|
| `TestShouldScanPath` (13 subtests) | Path filtering: conversation, claude, openai, gemini, copilot match; telemetry, health, sentinel skip; case-insensitive |
| `TestMonitorInterceptor_InterceptRequest_PathFilterSkip` | Telemetry path `/ces/statsc/flush` skipped |
| `TestMonitorInterceptor_ResponsePathFilterSkip` | Telemetry path skipped on response |
| `TestMonitorInterceptor_InterceptRequest_NoPII_CleanLog` | Clean message produces `monitor_scan` with `result: "clean"` |
| `TestMonitorInterceptor_InterceptRequest_PathFilterSubstringMatch` | Custom scan path matching |
| `TestBuildEntitySummary` | Entity summary aggregation helper |
| `TestSSEFrameReader_DoneMarkerTermination` | `[DONE]` marker triggers aggregated emission |
| `TestSSEFrameReader_AggregatedSummaryForClean` | Clean SSE stream produces clean `monitor_scan` |

---

## 4. Design Decisions

1. **Substring matching, not path prefix matching**: `strings.Contains` with case-insensitive comparison. This catches conversation paths wherever they appear in the URL hierarchy (e.g., `/backend-anon/conversation`, `/v1/chat/completions`). The Gemini `generateContent` scan path deliberately omits the leading `/` to match both `:generateContent` (Gemini API) and `/generateContent` paths.

2. **Path check before content-type check**: For `InterceptResponse`, the path whitelist check runs before `classifyContentType`. This avoids wasting cycles on content-type parsing for telemetry paths that will be skipped anyway.

3. **Default scan paths in two places**: Both `internal/policy/config.go` (`defaultMonitorScanPaths`) and `internal/interceptor/monitor.go` (`defaultScanPaths`) have the same default list. The policy version applies during config loading/validation; the interceptor version is a fallback when `nil` or empty scan paths are passed programmatically. This is intentional — the YAML config is the primary source of truth, but the interceptor defensively falls back to known-good defaults.

4. **Engine always runs when path matches**: Previously, `pii_logging: false` skipped the engine call (PR-103). With the new log format, the engine must run to populate `result` (`"clean"` vs `"pii_found"`) and `entity_count`. The `pii_logging` flag now controls only whether `entity_summary` is included in the log entry.

5. **proxy.go minimal change**: Added one line passing `cfg.Agent.Monitor.ScanPaths` to `NewMonitorInterceptor`. The `Interceptor` interface remains unchanged — `InterceptRequest` and `InterceptResponse` signatures are identical.

---

## 5. Remaining Gaps

| Gap | Severity | Notes |
|---|---|---|
| **Log rotation** | MEDIUM | File grows indefinitely in append mode. DPO-R10 recommends 7–30 day retention. |
| **`pii_logging` pointer fix** | MEDIUM | DPO-R12 / QINDU-0002 PR-104: `PIILogging bool` zero-value problem. Tracked for QINDU-0009. |
| **SSE timeout on stalled connections** | LOW | Known limitation: if upstream completely stalls, Go's blocking `Read` never returns. |
| **CA trust store not populated** | MEDIUM | Pre-existing from QINDU-0004 installer. |
| **No scan_paths for non-chat providers** | LOW | Current whitelist covers major providers. Users can extend via config. |

---

## 6. Unchanged per Sprint Constraints

- `Interceptor` interface — unchanged
- `NoOpInterceptor` — unchanged
- `forward.go` — unchanged
- PII engine and recognizers — unchanged
- `pii_values_logged` always `false` — unchanged
- ADRs — unchanged
