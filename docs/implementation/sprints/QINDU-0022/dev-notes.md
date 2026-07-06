# QINDU-0022 — Dev Notes

## Peer Review Fix Iteration — HIGH Findings (PR-001 through PR-004)

### PR-001 — EnforceInterceptor ShouldProcess contract violation (nil-plugin mode)
- **Problem**: `matchRequestPath` returned `false` when `plugin == nil`, but `InterceptRequest` still processed bodies (path guard checks `e.plugin != nil` before skipping). `ShouldProcess` returned `false` for nil-plugin mode, causing `DebugInterceptor` to skip buffering — but the inner interceptor still tokenized, producing zero FlowRing entries silently.
- **Fix**: Changed `matchRequestPath` to return `true` when `plugin == nil` (full-body fallback processes all paths). `ShouldProcess` now truthfully reflects behavior.
- **Files**: `internal/interceptor/enforce.go:379-385`
- **Tests**: `TestEnforceInterceptor_ShouldProcess_NilPlugin`, `TestEnforceInterceptor_ShouldProcess_WithPlugin`

### PR-002 — Unbounded response body buffering in EnforceInterceptor
- **Problem**: Both `InterceptRequest` and `InterceptResponse` (ctAnalyze path) used bare `io.ReadAll(resp.Body)` with no size cap. A 10MB body consumed 10MB memory before `scanBody`'s `LimitReader` was even reached.
- **Fix**: Added `maxBodyReadMargin = 1024` constant. Applied `io.LimitReader(req.Body, int64(e.maxInputLen+maxBodyReadMargin))` to all body pre-reads in both `InterceptRequest` and `InterceptResponse`.
- **Files**: `internal/interceptor/enforce.go:17, 106, 288`
- **Tests**: `TestEnforceInterceptor_BodyPreReadCap`

### PR-003 — TOCTOU race in FlowHandler between Snapshot() and Len()
- **Problem**: `FlowHandler` called `ring.Snapshot()` (acquires lock, captures entries, releases) then separately called `ring.Len()` (acquires lock again). Another goroutine could `Record()` in between, making `entries_count` inconsistent with `entries`.
- **Fix**: Derive `EntriesCount` from `len(entries)` — the snapshot length, not a separate `ring.Len()` call.
- **Files**: `internal/interceptor/debug.go:147`
- **Tests**: `TestFlowHandler_EntriesCountFromSnapshot`, `TestFlowHandler_TokenRaceImmunity`

### PR-004 — No per-entry body size cap in FlowRing
- **Problem**: `FlowRing.Record` stored full body strings. A single 5MB request would consume 10MB+ (ingress + egress). 50 entries × 5MB = 500MB.
- **Fix**: Added `maxDebugBodyLen = 64 * 1024` constant and `truncateDebugBody()` function. Bodies exceeding 64KB are truncated with `...[truncated]` suffix. `BodyBytesIn`/`BodyBytesOut` capture original sizes so operator sees true byte count.
- **Files**: `internal/interceptor/debug.go:16-19, 66-75, 174-180`
- **Tests**: `TestTruncateDebugBody_UnderLimit`, `TestTruncateDebugBody_AtLimit`, `TestTruncateDebugBody_OverLimit`, `TestFlowRing_Record_TruncatesOversizeBody`, `TestFlowRing_Record_SmallBodyUnchanged`

---

## Fix — DebugInterceptor ShouldProcess Guard (Flow Inspector Sentinel Bug)

### Bug Description (Fix #2)

The `DebugInterceptor` read and recorded ALL request bodies in the FlowRing — including non-conversation endpoints like `/backend-anon/sentinel/chat-requirements/finalize`. This happened because `InterceptRequest` always read the body before calling the inner interceptor. If the inner interceptor's path guard skipped the endpoint, the body had already been consumed and recorded.

- **Observed**: sentinel challenge payloads (encrypted anti-bot challenges) captured in `/debug/flow` output
- **Impact**: sentinel payloads buffered in memory (via `FlowRing.Record`), polluting the debug inspector with uninteresting pass-through entries
- **Root cause**: `DebugInterceptor.InterceptRequest` read the body eagerly (line 260 `io.ReadAll(req.Body)`) before delegating to the inner interceptor. The inner's path guard ran too late — the body was already consumed.

### Fix

Added `ShouldProcess(host, method, path string) bool` to the `Interceptor` interface. The `DebugInterceptor` calls `ShouldProcess` BEFORE reading the body. If the inner interceptor would skip this path, `DebugInterceptor` delegates directly without any body buffering or FlowRing recording.

### Files Changed

| File | Change |
|------|--------|
| `internal/proxy/interceptor.go` | Added `ShouldProcess(host, method, path string) bool` to `Interceptor` interface. Implemented on `NoOpInterceptor` (returns false). |
| `internal/proxy/proxy.go` | Implemented `ShouldProcess` on `providerDispatcher` — routes by host then delegates to selected interceptor. |
| `internal/interceptor/monitor.go` | Added `ShouldProcess` on `MonitorInterceptor` — delegates to `shouldScanPath`. |
| `internal/interceptor/provider_interceptor.go` | Added `ShouldProcess` on `ProviderInterceptor` — delegates to `matchPathSafe`. |
| `internal/interceptor/enforce.go` | Added `ShouldProcess` on `EnforceInterceptor` — delegates to `matchRequestPath`. |
| `internal/interceptor/debug.go` | Added `ShouldProcess` on `DebugInterceptor` (delegates to inner). Added `ShouldProcess` to `innerInterceptor` interface. Modified `InterceptRequest`: step 0 checks `ShouldProcess` before reading body; non-matching paths delegate directly to inner without buffering or recording. |
| `internal/interceptor/debug_test.go` | Added `ShouldProcess` to `stubInterceptor`, `errorInterceptor`. Added `pathAwareStub`. Added 4 new tests: `TestDebugInterceptor_SentinelNotRecorded` (sentinel → 0 entries), `TestDebugInterceptor_ConversationRecorded` (conversation → 1 entry), `TestDebugInterceptor_SentinelThenConversation` (interleaved sequence), `TestDebugInterceptor_ShouldProcessDelegates` (delegation correctness). |
| `internal/proxy/proxy_test.go` | Added `ShouldProcess` to `recordingInterceptor`. |

### How It Works

```
Old flow:
  DebugInterceptor.InterceptRequest
    → io.ReadAll(req.Body)              ← body ALWAYS consumed here
    → inner.InterceptRequest(req)       ← path guard runs too late
    → ring.Record(...)                  ← sentinel payload recorded!

New flow:
  DebugInterceptor.InterceptRequest
    → inner.ShouldProcess(host, method, path)  ← check BEFORE reading
    → if false: inner.InterceptRequest(req)    ← body passes through unread
    → if true:  io.ReadAll(req.Body)           ← only read when needed
                 inner.InterceptRequest(req)
                 ring.Record(...)              ← only recorded when processed
```

### QEMU Bug Fix — Path Guard in EnforceInterceptor

### Bug Description

The QEMU tester found two bugs in the `EnforceInterceptor`:

1. **`text_segments_filtered` flood**: Hundreds of WARN log entries `"dropped":1,"valid":0,"total":1` — every non-conversation request/response body was being treated as a full-body segment, and binary bodies failed `isValidText` (NUL bytes).

2. **`sentinel/chat-requirements/finalize` → 500**: The sentinel challenge endpoint was being processed with full-body PII scanning. The encrypted challenge payload triggered 71 false-positive SECRET detections, tokenization corrupted the payload (6353→1594 bytes), and the upstream returned 500.

### Root Cause

`EnforceInterceptor.InterceptRequest()` and `InterceptResponse()` lacked the path-matching guard that `ProviderInterceptor` already has:

```go
// ProviderInterceptor correctly skips non-matching paths:
if !p.matchPathSafe(req.Method, rawPath) {
    return req, req.Body, nil
}
```

The `EnforceInterceptor` only used the path match to decide whether to set an extractor — it never skipped the body scanning pipeline entirely. Non-conversation paths (sentinel/challenge, telemetry, static assets) fell through to full-body scanning with `tokenize`/`rehydrate` callbacks active.

### Fix

Added path-matching guards to both `InterceptRequest` and `InterceptResponse`:

| File | Change |
|------|--------|
| `internal/interceptor/enforce.go` | Added path guard in `InterceptRequest` (after tokenizer check, before body pre-read). Added path guard in `InterceptResponse` (after nil-body check, before content-type switch). Updated flow documentation comments. |
| `internal/interceptor/enforce_test.go` | Added 4 new tests: `TestEnforceInterceptor_PathGuardRequestSkipsNonConversation`, `TestEnforceInterceptor_PathGuardRequestProcessesConversation`, `TestEnforceInterceptor_PathGuardResponseSkipsNonConversation`, `TestEnforceInterceptor_PathGuard_NilPlugin`. Added `pathGuardPlugin` mock. |

### How It Works

The guard checks: `e.plugin != nil && !e.matchRequestPath(method, path)`. If the plugin does not handle the path, the body passes through without any scanning, tokenization, rehydration, or log emission. Conversation paths continue to be processed normally.

When `plugin` is nil (no provider plugin, full-body fallback mode), the guard does not trigger because `e.plugin != nil` is false — all paths are scanned via full-body extraction.

---


| File | Change |
|------|--------|
| `internal/interceptor/debug.go` | **NEW** — `FlowRing`, `DebugInterceptor`, `FlowHandler`, `tokenSummary`, `knownDebugEntityTypes` |
| `internal/interceptor/debug_test.go` | **NEW** — 25+ test functions covering ring buffer, debug interceptor, handler, token summary |
| `internal/policy/config.go` | **Modified** — Added `DebugConfig` struct + `FlowInspectorValue()`, integration with `DefaultConfig` and `MergeFileOverride` |
| `internal/proxy/proxy.go` | **Modified** — FlowRing field on Proxy, creation + wrapping in NewProxy, `/debug/flow` handler + `isLocalhostRequest` helper |
| `internal/interceptor/enforce.go` | **Modified** — Pre-read body in `InterceptRequest` and `InterceptResponse`, emit `enforce_transform` DEBUG log with byte sizes and entity counts |

## Peer Review Fix Iteration — Modified Files

| File | Fix | Peer ID |
|------|-----|---------|
| `internal/interceptor/debug.go` | Removed `init()` with `panic()` and test logic (lines 334-363). Moved assertions to `debug_test.go`. | PR-001 |
| `internal/interceptor/debug_test.go` | Added `TestTokenPatternRegex_InitValidation` — mirrors the old `init()` assertions in test form. Added `"strconv"` import. | PR-001 |
| `internal/interceptor/enforce_sse.go` | Removed `break` in `Read()` for loop (lines 182-188). Changed dead-code `return 0, nil` to `return 0, io.ErrUnexpectedEOF` for defense-in-depth. The loop now naturally continues reading until data or error. | PR-002 |
| `internal/interceptor/enforce_sse_test.go` | Added `TestEnforceSSEReader_NoZeroNilReturn` with `chunkedReader` — validates io.Reader contract via 1-byte chunking through io.ReadAll. | PR-002 |
| `internal/proxy/proxy.go` | Added `providerByDomain map[string]string` + `providerSortedDomains []providerDomain` fields to `Proxy`. Added `buildProviderCache()` method called from `NewProxy`. Rewrote `resolveProviderForHost` to use cached data instead of O(n log n) per-request rebuild. Extracted `providerDomain` to package-level type. | PR-003 |
| `internal/proxy/proxy_test.go` | Updated `helperNewTestProxy` to call `buildProviderCache()`. Added `TestBuildProviderCache` (5 subtests): enabled providers populate cache, disabled excluded, empty domains excluded, no providers yields empty cache, sort order verified. | PR-003 |

## Technical Choices and Rationale

### PR-001: Remove `init()` with `panic`
- **Problem**: `init()` in `debug.go` ran test assertions at import time via `panic()`. If the regex or test cases ever changed, the binary would crash at startup — including in production.
- **Fix**: Deleted the entire `init()` function. Moved the three assertions (`<<EMAIL_1>>`, `<<PHONE_2>>`, `<<PRIVATE_KEY_99>>`) into `TestTokenPatternRegex_InitValidation` in `debug_test.go`. Also deleted the dead `nil` check on line 337 (`MustCompile` already panics on failure).
- **Impact**: No change to runtime behavior. Regex validation is now a test-time concern, not a startup panic risk.

### PR-002: Fix `(0, nil)` return in `EnforceSSEReader.Read()`
- **Problem**: The `for` loop in `Read()` had a `break` (line 188) that exited the loop when `outputBuf` was empty and `hasFrameData` was false after initial processing. This caused `Read()` to return `(0, nil)`, violating the `io.Reader` contract. Go's `io.Copy` treats `(0, nil)` as "retry immediately" → busy-loop at 100% CPU.
- **Fix**: Removed the `break` and surrounding conditional. The `for r.outputBuf.Len() == 0` loop now naturally continues when no output is available — it reads more from upstream until data or an error arrives. The dead-code path `return 0, nil` was changed to `return 0, io.ErrUnexpectedEOF` as a defense-in-depth guard.
- **Regression test**: `TestEnforceSSEReader_NoZeroNilReturn` sends an SSE frame in 1-byte chunks through `io.ReadAll` (which uses `io.Copy` internally). This validates the io.Reader contract under chunking patterns that would previously hit the `break`.

### PR-003: Cache `resolveProviderForHost` domain mapping
- **Problem**: `resolveProviderForHost` rebuilt the domain-to-provider map and sorted the domain list on every call — O(P×D + D log D) per HTTP request. Called from `handleMITM`'s keep-alive loop, so every request paid this cost.
- **Fix**: Added two fields to `Proxy`: `providerByDomain map[string]string` (exact-match cache) and `providerSortedDomains []providerDomain` (length-descending sorted slice for suffix matching). These are built once in `buildProviderCache()`, called from `NewProxy`. `resolveProviderForHost` now does a direct map lookup followed by linear scan of the pre-sorted slice. When the provider list is empty, resolution returns "unknown" immediately.
- **Regression test**: `TestBuildProviderCache` (5 subtests) validates that enabled providers populate the cache, disabled providers are excluded, empty domains are filtered, no providers yields an empty cache, and the sorted slice is correctly length-descending.
- **Backward compatibility**: `helperNewTestProxy` updated to call `buildProviderCache()` so existing `TestResolveProviderForHost` subtests continue to work.

### FlowRing Design (DD-2) — unchanged
- **`sync.Mutex`** instead of `sync.RWMutex`: contention is low (handler reads infrequently, interceptor writes occasionally). Mutex is simpler and avoids write-starvation risk with two readers (handler + interceptor through DebugInterceptor).
- **FIFO eviction**: uses slice copy `copy(fr.entries, fr.entries[1:])` — clean and safe. At 50 max entries, the cost is negligible.
- **Snapshot returns a copy**: prevents leaks from the ring buffer's internal state. The caller cannot mutate the buffer by mutating the returned slice.

### Circular Import Avoidance — unchanged
- `proxy` package imports `interceptor` package (for `EnforceInterceptor`, `MonitorInterceptor`, etc.).
- If `interceptor/debug.go` imported `proxy` (for the `Interceptor` interface), we'd have a cycle.
- **Solution**: defined a local `innerInterceptor` interface in `debug.go` with identical method signatures. Go's structural typing means any `proxy.Interceptor` automatically satisfies this interface. Zero overhead, zero cycle.

### DebugInterceptor Wrap Point — unchanged
- Wrapping happens in `NewProxy` after `selectInterceptor`. This means the `DebugInterceptor` wraps the final interceptor (providerDispatcher or direct EnforceInterceptor/MonitorInterceptor). No change needed in `mitm.go`.
- The story's table mentions `mitm.go` changes, but wrapping in `NewProxy` is architecturally cleaner and works for all modes (not just enforce).

## How to Test

### Peer Review Fix Tests
```bash
# PR-001: Regex validation moved to test
go test ./internal/interceptor/... -v -run "TestTokenPatternRegex_InitValidation"

# PR-002: SSE io.Reader contract (1-byte chunk test)
go test ./internal/interceptor/... -v -run "TestEnforceSSEReader_NoZeroNilReturn"

# PR-003: Provider cache tests
go test ./internal/proxy/... -v -run "TestBuildProviderCache|TestResolveProviderForHost"
```

### QEMU Bug Fix Tests
```bash
# Path guard tests for EnforceInterceptor
go test ./internal/interceptor/... -v -run "TestEnforceInterceptor_PathGuard"
```

### Unit Tests
```bash
go test ./internal/interceptor/... -v -run "TestFlowRing|TestTokenSummary|TestDebugInterceptor|TestFlowHandler"
go test -race ./internal/interceptor/... -run "TestFlowRing_Concurrency"
```

### Full Regression
```bash
go test ./...
go vet ./...
```

All existing tests pass with zero modifications to existing test logic.

## Gaps and Remaining Risks

1. **PII in memory**: The ring buffer stores raw PII in clear text (DD-3 accepted by DPO/human). While gated behind a disabled-by-default flag, any process with access to the host can read `/debug/flow` if the flag is mistakenly left enabled in production. The localhost guard helps but is not a security boundary on a compromised host.

2. **Ring buffer size**: Hard-coded at 50 entries. No configuration option to change. Sufficient for debugging but may be too small for high-traffic debugging scenarios.

3. **Body truncation**: Large bodies (exceeding `maxInputLen`) are handled by scanBody's oversize path, meaning they won't appear in the flow inspector because the DebugInterceptor pre-reads them. The enforce_transform log also won't capture the full byte count for oversized bodies.

4. **SSE response path**: The `InterceptResponse` enforce_transform log is only emitted for `ctAnalyze` (non-streaming JSON). SSE responses use a streaming reader and don't get the enforce_transform log. This is documented as "optional" in the story.

5. **No maximum body size for ring buffer**: The ring buffer entry bodies have no size limit. If a request body is very large (but within maxInputLen), it will be stored entirely in the ring buffer. This could consume significant memory with 50 large entries.

6. **No cleanup/eviction by age**: Entries are only evicted by FIFO when the buffer is full. Old entries persist indefinitely in memory until evicted or the proxy restarts (AC-8: no disk persistence, buffer cleared on restart).
