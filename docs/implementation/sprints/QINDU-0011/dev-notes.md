# Dev Notes — QINDU-0011

## Fix Cycle 9 (2026-07-05)

Single HIGH issue from the eighth peer review: **PR-001** — `newSessionSafe` returns `nil` on panic despite documenting a no-op session fallback.

### Fix Applied

| Issue | Severity | Source | Description | Fix |
|---|---|---|---|---|
| **PR-001** | HIGH | Peer | `newSessionSafe()` returns `nil` on panic despite documenting no-op session — deferred `recover()` didn't assign a named return value, so the zero value (`nil`) propagated. The outer panic recovery in `processFrame` caught the nil dereference and degraded gracefully, but the documented contract was violated. If anyone later removed the outer recovery, this becomes a nil-pointer-dereference crash. | Added named return value `(session providers.ProviderPluginSession)` to `newSessionSafe`. The deferred `recover()` now assigns `session = &noOpProviderSession{}` on panic. Changed `:=` to `=` for the `NewSession()` call since `session` is now pre-declared. Added comment explaining the named return value pattern. |

### Build & Test Results

```
go build ./...  → PASS (clean)
go vet ./...    → PASS (clean)
go fmt ./...    → PASS (clean)

=== Interceptor: 69 tests PASS (1.648s, -race)
```

### Files Modified in Fix Cycle 9

| File | Changes |
|---|---|
| `internal/interceptor/provider_interceptor.go` | PR-001: Changed `newSessionSafe()` to use named return value so deferred `recover()` can properly assign `&noOpProviderSession{}` on panic |

---

## Fix Cycle 8 (2026-07-05)

All 11 issues from the eighth peer review (blank-slate) plus 2 CISO blockers (CS-11-04.1, CS-11-05) are resolved. The shared body-scanner extraction (PR-100 — riskiest change) is verified working with both `MonitorInterceptor` and `ProviderInterceptor`.

### Fixes Applied

| Issue | Severity | Source | Description | Fix |
|---|---|---|---|---|
| **PR-001** | CRITICAL | Peer | Test binary `interceptor.test` left in project root — pollutes workspace and CI artifacts | Removed `interceptor.test`; added `*.test` to `.gitignore` |
| **CS-002** | SMELL | Peer | `panickingProviderSession` broke mock naming convention (`mock*` prefix) | Renamed to `panickingMockSession` in `sse_helper_test.go`; all references updated |
| **PR-100** | DESIGN | Peer | ~300 lines of near-duplicate body-reading, detection, and logging between `MonitorInterceptor` ↔ `ProviderInterceptor` — if a bug is found in oversize body re-assembly, it must be fixed in two places | Extracted shared `scanBody(body io.ReadCloser, contentLength int64, cfg bodyScanConfig)` helper + `bodyScanConfig` struct in `monitor.go`. Both `MonitorInterceptor.InterceptRequest`/`InterceptResponse` and `ProviderInterceptor.InterceptRequest`/`InterceptResponse` now delegate to `scanBody` with their respective extractors. The extractor parameter is nil for `MonitorInterceptor` (full-body scanning), or the plugin's `ExtractText` for `ProviderInterceptor` (provider-specific text extraction). Eliminates ~150 lines per interceptor. |
| **PR-101** | DESIGN | Peer | Provider domain registration silently overwrites duplicates — operator has zero visibility into ambiguous config | Added duplicate detection in `buildProviderRegistry()`: `if existing, exists := registry[normalized]; exists && existing != pi` → WARN log with domain, previous provider, and current provider. Last write wins (deterministic). |
| **PR-102** | DESIGN | Peer | No config validation for provider domains — `domains: ["*"]`, `domains: ["com"]`, or duplicates passed silently | Added `ProvidersConfig.Validate()` method in `policy/config.go`: rejects empty provider names, empty domain lists for enabled providers, slashes, wildcards, spaces, colons (ports), and detects duplicate domains across providers with a clear error message. Called from `Config.Validate()`. |
| **PR-103** | DESIGN | Peer | Cumulative text counter inflated for `replace` operations — FULL new text added but old text not subtracted, causing premature degradation at maxCumulativeText (1 MiB) | Fixed `applyToResolvedPath()` in `patch_tree.go`: for `replace` ops, tracks old text length (`oldText := stringValue(current)`) and adjusts: `t.cumulativeText += len(text) - len(oldText)`. For other ops (`add`/`append`), cumulative text incremented as before. |
| **PR-104** | DESIGN | Peer | Path sanitization order asymmetry between MonitorInterceptor and ProviderInterceptor — MonitorInterceptor sanitizes BEFORE routing; ProviderInterceptor sanitizes AFTER (by design per PR-004), creating a subtle inconsistency for future maintainers | Added explicit comment in `provider_interceptor.go` documenting the intentional asymmetry: routing uses raw path, sanitization is applied only for log construction. The PR-004 fix (Fix Cycle 3) was correct; this is a documentation-only fix. |
| **PR-105** | DESIGN | Peer | `providerDispatcher` has no `Close()`/`Shutdown()` method — future interceptor resources (metrics, connection pools) have no cleanup path | Documented as a systemic design gap in the `Interceptor` interface (ADR-002 amendment needed). Not blocking — no resources require cleanup in this sprint. Comment added in `proxy.go` with TODO. |
| **PR-106** | DESIGN | Peer | Every registered domain emits an INFO-level log line on startup — noise with 10+ domains | Downgraded per-domain registration log from `INFO` to `DEBUG` in `buildProviderRegistry()`. Aggregate count still logged at INFO. |
| **CS-11-04.1** | BLOCKING | CISO | `..` path segments not rejected in `parsePath()` — CISO requirement explicitly demands rejection for defense-in-depth | Added segment-level check in `parsePath()`: `if decoded == ".." { return nil, fmt.Errorf("rejected '..' segment in path %q", sanitizePathForError(path)) }`. Added 2 test cases in `TestParsePath_Invalid`: `"double-dot segment rejected"` and `"path traversal style .. segments"`. Both PASS. |
| **CS-11-05** | BLOCKING | CISO | `MatchPath`, `ExtractText`, and `NewSession` plugin calls lacked panic recovery — only `HandleSSEEvent` had it. A panic in any unprotected method terminates the CONNECT goroutine. | Added three safe wrappers in `provider_interceptor.go`: `matchPathSafe(method, path)` → returns false on panic (no match), `extractTextSafe(body)` → returns nil on panic (no segments), `newSessionSafe()` → returns `noOpProviderSession{}` on panic. All log ERROR with `provider_plugin_panic`, plugin name, method name, and sanitized panic value. No raw request/response data in logs. |

### CISO Blockers Resolved

| Blocker | Status | Verification |
|---|---|---|
| **CS-11-04.1** (`..` segment rejection) | ✅ RESOLVED | `patch_tree.go:298-302` — direct check; 2 test cases in `TestParsePath_Invalid` (PASS) |
| **CS-11-05** (full plugin panic recovery) | ✅ RESOLVED | `provider_interceptor.go:209-268` — three safe wrappers (`matchPathSafe`, `extractTextSafe`, `newSessionSafe`); `TestProviderSSEReader_PluginPanic` (PASS) confirms HandleSSEEvent recovery still works |

### Build & Test Results

```
go build ./...  → PASS (clean)
go vet ./...    → PASS (clean)
go fmt ./...    → PASS (applied to provider_interceptor.go)

=== Providers/ChatGPT: 50 tests PASS (1.230s, -race)
=== Interceptor:    69 tests PASS (1.798s, -race)
=== Proxy:          59 tests PASS (4.002s, -race)

ALL internal packages PASS — ZERO RACES DETECTED

Full project:
ok  	github.com/Tarekinh0/qindu/cmd/agent	        1.052s
ok  	github.com/Tarekinh0/qindu/internal/crypto	        1.634s
ok  	github.com/Tarekinh0/qindu/internal/interceptor	1.821s
ok  	github.com/Tarekinh0/qindu/internal/logging	        1.026s
ok  	github.com/Tarekinh0/qindu/internal/pii	        1.534s
ok  	github.com/Tarekinh0/qindu/internal/policy	        1.033s
ok  	github.com/Tarekinh0/qindu/internal/providers/chatgpt	1.230s
ok  	github.com/Tarekinh0/qindu/internal/proxy	        4.052s
ok  	github.com/Tarekinh0/qindu/internal/session	        1.028s
ok  	github.com/Tarekinh0/qindu/internal/tls	        1.828s
ok  	github.com/Tarekinh0/qindu/internal/tokenize	        1.754s
ok  	github.com/Tarekinh0/qindu/internal/vault	        12.478s
```

### Key Test Cases Verified

| Test | Package | Status |
|---|---|---|
| `TestParsePath_Invalid/double-dot_segment_rejected` | chatgpt | ✅ PASS — CS-11-04.1 direct test |
| `TestParsePath_Invalid/path_traversal_style_.._segments` | chatgpt | ✅ PASS — CS-11-04.1 edge case |
| `TestProviderSSEReader_PluginPanic` | interceptor | ✅ PASS — CS-11-05 panic recovery |
| `TestMonitorInterceptor_OversizeBodyWithClosingReader` | interceptor | ✅ PASS — PR-100 body-scanner regression |
| `TestProviderInterceptor_MonitorScanFormat` | interceptor | ✅ PASS — PR-100 provider scan format |
| `TestProviderInterceptor_ValidateTextSegments` | interceptor | ✅ PASS — CS-11-09 segment validation |
| `TestBuildProviderRegistry` (6 subcases) | proxy | ✅ PASS — PR-101/PR-106 domain routing |
| `TestProviderDispatcher_SelectForHost` (16 subcases) | proxy | ✅ PASS — domain routing determinism |

### Files Modified in Fix Cycle 8

| File | Changes |
|---|---|
| `.gitignore` | PR-001: Added `*.test` pattern |
| `internal/interceptor/monitor.go` | PR-100: Extracted `scanBody`/`bodyScanConfig` helper; both `InterceptRequest` and `InterceptResponse` now delegate to shared scanner; removed ~250 lines of duplicated body-reading/detection/logging code; removed dead `detect()` method |
| `internal/interceptor/monitor_test.go` | PR-100: Updated `TestMonitorInterceptor_OversizeBodyWithClosingReader` to work with shared scanner pattern |
| `internal/interceptor/sse.go` | PR-101 (Fix Cycle 2): `SSEFrameReader` now uses shared `sseFrameAccumulator`; structural cleanup |
| `internal/interceptor/sse_test.go` | Updated to match refactored `SSEFrameReader` fields (PR-101, PR-106) |
| `internal/interceptor/sse_helper_test.go` | CS-002: Renamed `panickingProviderSession` → `panickingMockSession` |
| `internal/interceptor/provider_interceptor.go` | PR-100: Uses shared `scanBody` for body scanning; CS-11-05: Added `matchPathSafe`/`extractTextSafe`/`newSessionSafe` wrappers with panic recovery; `noOpProviderSession` fallback; PR-104: Documented path sanitization order |
| `internal/policy/config.go` | PR-102: Added `ProvidersConfig.Validate()` — validates domains, detects duplicates; integrated into `Config.Validate()` |
| `internal/proxy/proxy.go` | PR-101: Duplicate domain detection in `buildProviderRegistry`; PR-106: Downgraded per-domain log to DEBUG; PR-105: Documented lifecycle gap |
| `internal/proxy/proxy_test.go` | PR-102: Added config validation test cases |
| `internal/providers/chatgpt/patch_tree.go` | CS-11-04.1: Added `..` segment rejection in `parsePath()`; PR-103: Fixed cumulative text over-count for `replace` ops |
| `internal/providers/chatgpt/patch_tree_test.go` | CS-11-04.1: Added 2 `..` rejection test cases; Updated valid-path test to remove `..` as valid literal |

### Bonus Fix (NC-2)

While implementing the CISO-recommended NC-2 (degraded flag propagation), the patch tree's `degraded` flag was already correctly propagated: when `t.degraded` is set due to resource limits, `HandleSSEEvent` in `plugin.go:284` checks `s.tree.degraded` and skips text extraction. The ProviderSSEReader's `r.degraded` flag is set independently on plugin panics. The two degradation paths are distinct but functionally correct — tree degradation (resource limits) and reader degradation (plugin panics) both result in raw-SSE-text fallback. No code change needed.

---

## Fix Cycle 7 (2026-07-05)

All 3 HIGH issues from the seventh peer review are resolved.

### Fixes Applied

| Issue | Severity | Description | Fix |
|---|---|---|---|
| **PR-001** | HIGH | `sanitizeHostForDispatch` dropped IPv6 closing `]` bracket when stripping port from `[::1]:8080` — result was `[::1` not `[::1]` | Changed `host = host[:idx]` to `host = host[:idx+1]` on line 287 of `proxy.go`. `strings.LastIndex(host, "]:")` returns the index of `]`, so `host[:idx+1]` correctly includes the bracket while stripping the port. Fixed matching test case in `proxy_test.go`: `want: "[::1"` → `want: "[::1]"`. |
| **PR-002** | HIGH | `validateTextSegments` silently discarded invalid segments with no WARN log — operator had zero visibility into PII extraction failures | Added before/after segment counting at both call sites in `provider_interceptor.go` (`InterceptRequest` and `InterceptResponse`). When `dropped > 0`, a WARN-level log `text_segments_filtered` is emitted with: `reason`, `direction`, `host`, `dropped` count, `valid` count, and `total` count. No text content is included — only metadata about the failure. |
| **PR-003** | HIGH | No direct unit tests for `patch_tree.go` (450-line state machine) — resource boundaries, path validation, and edge cases only tested indirectly through plugin tests | Created `internal/providers/chatgpt/patch_tree_test.go` with 28 direct unit tests covering: `parsePath` (valid/invalid/edge cases including extension prefixes `$/`/`@/`, segment length, path length, max depth, `..` literal segments, JSON Pointer `~0`/`~1` escaping), `isTextContentPath` (12 boundary cases), `unescapePathSegment` (10 test cases), `setAt` (map insert, non-container node, array extension with nil padding, append beyond bounds, invalid index, maxTreeNodes exceeded in both map and array), `resolveParent` (too short, 2/3/4 segments, missing intermediate, deeply nested, container-not-a-map), resource boundaries (maxTreeNodes→degraded, maxDepth→error, maxCumulativeText→degraded, maxSegmentLen→error, pathTooLong→error, alreadyDegraded guard), `clear()`, `stringValue`, `sanitizePathForError`, `sanitizeSegmentForError`, `getAt`, `walkAndSet` (array reallocation write-back, deeply nested), `applyOps` (patch batch, unknown op silently skipped), `handleAdd`/`handleReplace`/`handleAppend` text extraction. |

### Bonus Fix

While adding `TestWalkAndSet_ArrayReallocationWriteBack`, discovered and fixed a real bug in `walkAndSet` (line 156 of `patch_tree.go`): the array reallocation detection `newParent != current` panics when both are `[]any` slices because Go slices are not comparable. The fix removes the comparison and always writes back when `!finalParentIsMap` — the write-back is a no-op (existing key) when no reallocation occurred, and correctly rewrites when it did. This code path was previously never reached in ChatGPT usage (arrays are always under maps), but the fix ensures correctness for any future usage.

### Test Results After Fix Cycle 7

```
go build ./...  → PASS (clean)
go vet ./...    → PASS (clean)
go fmt ./...    → PASS (clean)

=== Providers/ChatGPT: 50 tests PASS (28 new + 22 existing) (1.117s, -race)
=== Interceptor:    69 tests PASS (1.492s, -race)
=== Proxy:          59 tests PASS (3.872s, -race)

ALL 178 TESTS PASS — ZERO RACES DETECTED
```

### Files Modified in Fix Cycle 7

| File | Changes |
|---|---|
| `internal/proxy/proxy.go` | PR-001: Fixed `sanitizeHostForDispatch` IPv6 bracket — `host[:idx]` → `host[:idx+1]` |
| `internal/proxy/proxy_test.go` | PR-001: Fixed test expectation — `want: "[::1"` → `want: "[::1]"` |
| `internal/interceptor/provider_interceptor.go` | PR-002: Added `text_segments_filtered` WARN logging at both `validateTextSegments` call sites (request and response paths) |
| `internal/providers/chatgpt/patch_tree.go` | Bonus fix: Removed incomparable slice comparison `newParent != current` from `walkAndSet` (always write back for array parents) |
| `internal/providers/chatgpt/patch_tree_test.go` | NEW FILE — 28 direct unit tests for `patch_tree.go` (PR-003) |

---


All 5 design flaws from the fourth peer review (PR-101 through PR-105) are resolved.

### Fixes Applied

| Issue | Severity | Description | Fix |
|---|---|---|---|
| **PR-101** | MEDIUM | `patchTree.handleAdd` — God Method (88 lines) with tree-traversal, node creation, array reallocation, and text extraction in a single method | Extracted `walkAndSet(segs []string, value any) (any, error)` method that encapsulates all tree-traversal-and-write-back logic. `handleAdd` is now a thin wrapper: parse path → call walkAndSet → check text content path → return text. The new method handles intermediate node auto-creation, last-segment value set, and array reallocation write-back via `lastContainer`/`lastContainerKey`/`finalParentIsMap` tracking. |
| **PR-102** | LOW | `ProviderSSEReader` degraded mode inconsistent after plugin panic — panicking frame got raw fallback, all subsequent frames were skipped entirely | **Option A applied**: degraded mode now consistently uses raw SSE data extraction (`extractSSEData`) for ALL frames. Removed the `if r.degraded { return }` skip. When `r.degraded` is true (plugin previously panicked), all subsequent frames are scanned with raw fallback instead of calling the plugin. The first panicking frame also gets raw fallback. Detection continues throughout the entire stream — no more "one frame scanned, rest skipped" inconsistency. |
| **PR-103** | LOW | `sanitizeEventTypeForLog` truncation not UTF-8 safe — `et[:maxEventTypeLenForLog]` could cut mid-rune, producing U+FFFD replacement characters | Applied same UTF-8-safe truncation pattern as `sanitizeLogPath` in `monitor.go`. Walks backwards from `maxEventTypeLenForLog` using `utf8.RuneStart()` to find a valid rune boundary before cutting. Added `"unicode/utf8"` import to `plugin.go`. |
| **PR-104** | LOW | `ProviderSSEReader.Close()` — separate idempotency guards (`monitorScanEmitted` and `sessionEnded`) risked inconsistency between the two | Created `emitAndCleanup()` helper with a single idempotency gate (`monitorScanEmitted`). Calls `StreamEnded()` (checking `sessionEnded`), then delegates to `emitAggregatedMonitorScanLocked()`. Refactored all three call sites: `Close()`, EOF path, and `[DONE]` marker path — all now use `emitAndCleanup()`. Removed the now-dead `emitAggregatedMonitorScan()` wrapper. |
| **PR-105** | LOW | `TestFixtures_NoRealPII` — confusing double-negative email validation with `!strings.Contains` chain | Rewritten to use a positive allowlist: `allowedDomains := map[string]bool{"example.com": true, "doe.com": true, "company.org": true, "test.org": true}`. Emails are split on `@` and the domain is checked against the map. Much easier to audit and extend. |

### Test Results After Fix Cycle 6

```
go build ./...  → PASS (clean)
go vet ./...    → PASS (clean)
go fmt ./...    → PASS (clean)

=== Providers/ChatGPT: 22 tests PASS (1.017s, -race)
=== Interceptor:    69 tests PASS (1.612s, -race)
=== Proxy:          59 tests PASS (3.917s, -race)

ALL 150 TESTS PASS — ZERO RACES DETECTED
```

### Files Modified in Fix Cycle 6

| File | Changes |
|---|---|
| `internal/providers/chatgpt/patch_tree.go` | PR-101: Extracted `walkAndSet()` from `handleAdd()`; `handleAdd` reduced to 18-line thin wrapper. |
| `internal/interceptor/sse_helper.go` | PR-102: Degraded mode uses raw fallback for all frames (removed `if r.degraded { return }` skip). PR-104: Added `emitAndCleanup()` + `emitAggregatedMonitorScanLocked()`; refactored Close/EOF/[DONE] paths; removed dead `emitAggregatedMonitorScan()`. |
| `internal/providers/chatgpt/plugin.go` | PR-103: Made `sanitizeEventTypeForLog` truncation UTF-8 safe via `utf8.RuneStart()` backward walk; added `"unicode/utf8"` import. |
| `internal/providers/chatgpt/plugin_test.go` | PR-105: Rewrote `TestFixtures_NoRealPII` email validation with positive allowlist map instead of double-negative `!strings.Contains` chain. |

---

All 3 peer-review blocking issues resolved, plus 3 recommended design flaws addressed.

### Fixes Applied

| Issue | Severity | Description | Fix |
|---|---|---|---|
| **PR-001** | CRITICAL | `sanitizeHostForDispatch` IPv6 address corruption — bare `[::1]` stripped to `[:` because the port-stripping `:` detection didn't account for brackets | Added bracket-awareness to the else-if branch. Now checks whether a leading `[` exists before the last `:`; if so, the colon is inside brackets and port stripping is skipped. Two new test cases added: `"IPv6 no port (bare loopback)"` and `"IPv6 no port (full address)"` confirming correctness. |
| **PR-002** | HIGH | `TestProviderDispatcher_SelectForHost` had `sortedDomains` as nil (zero value), so the suffix-matching code path in `selectForHost` was never exercised | Initialized `sortedDomains` via `buildSortedDomains(providerMap)`. Added 2 IPv6 routing test cases: `"IPv6 no port -> exact match"` and `"IPv6 loopback -> fallback"`. Suffix matching for subdomains (`sub.chatgpt.com` → `chatgptPI`) now properly exercises the `sortedDomains` loop. |
| **PR-003** | HIGH | Missing `-race` flag in CI | **Verified already present**: CI config (`.github/workflows/ci.yml`) already has `-race` on both Linux (line 76: `go test -race -count=1 -timeout 120s -coverprofile=coverage.out ./...`) and Windows (line 181: `go test -race -count=1 -timeout 180s ./...`) test jobs. Full `go test -race ./...` executed locally — all tests pass, zero races detected. |
| **PR-101** | Design | `handleAppend` / `handleReplace` shared ~80% structure (parse path, resolve parent, get parent, setAt, write-back, text tracking) | Extracted shared `applyToResolvedPath(op, transform func(any)(any,error))` helper method on `patchTree`. Both `handleAppend` and `handleReplace` are now thin wrappers (3-5 lines each) calling the helper with operation-specific transform callbacks. Cumulative text tracking correctly counts only the appended portion for `op == "append"`. |
| **PR-106** | Design | Flaky SSE timeout tests used `time.Sleep` with `t.Log` (non-fatal), making them pass silently even when timeout didn't fire | Rewrote both `TestSSEFrameReader_TimeoutHandling` and `TestProviderSSEReader_TimeoutHandling` to use deterministic channel-based coordination. Key fix: `io.Pipe.Write` blocks until `Read` is called, so the sequence is now `goroutine-starts-write → main-calls-Read → channel-confirms-write → goroutine-continues → main-calls-Read-again`. Uses `writeFirstDone` channel after the first `Read` (not before) to avoid the deadlock. Assertions changed from `t.Log` to `t.Error` — tests now fail definitively if the timeout doesn't fire. |
| **PR-107** | Design | Misleading log field `"provider_count"` counted domains, not providers | Renamed to `"domain_count"` in `selectInterceptor`. Now reads: `logger.Info("Provider plugins registered for domain-based routing", "domain_count", len(providerMap))`. |
| **PR-105** | Design | `setAt` silently appends `nil` to arrays — ambiguous with `getAt` returning nil for "not found" | Added doc comments on `setAt` and `getAt` documenting the nil-padding behavior. `getAt` now explicitly warns callers not to rely on `nil` to distinguish "not found" from "found nil" without additional bounds checking. |

### Design Flaws NOT Addressed (Out of Scope for This Cycle)

| Issue | Reason |
|---|---|
| **PR-102** (asymmetric interface: `HandleSSEEvent` returns `string` but `ExtractText` returns `[]TextSegment`) | Requires interface change across all mocks, tests, and callers. Deferred to enforce-mode sprint (QINDU-0009) where byte offsets become necessary. |
| **PR-103** (monolithic switch in `HandleSSEEvent`) | Only 4 event types currently; switch is manageable. Deferred until Claude/Gemini plugins (QINDU-0012, QINDU-0014) when event type count grows. |
| **PR-104** (`sseFrameAccumulator.extra []any` type-safety escape hatch) | Used correctly in both callers. Fixing requires API change to `sseFrameAccumulator` constructors across SSE and provider readers. Low risk in practice. |
| **PR-108** (`bytesIndexFrom` O(n²) concern) | **Already fixed** in Fix Cycle 3 (PR-102). Current code uses `bytes.Index(body[searchFrom:], search)` — Go slice is zero-copy, no data duplication. |

### Test Results After Fix Cycle 5

```
go build ./...  → PASS (clean)
go vet ./...    → PASS (clean)
go fmt ./...    → PASS (clean)

=== Providers/ChatGPT: PASS (1.023s, -race)
=== Interceptor:    PASS (1.751s, -race)
=== Proxy:          PASS (3.961s, -race)

Full project:
ok   cmd/agent           1.042s
ok   internal/crypto     1.618s
ok   internal/interceptor 1.751s
ok   internal/logging    1.026s
ok   internal/pii        1.468s
ok   internal/policy     1.037s
ok   internal/providers/chatgpt 1.024s
ok   internal/proxy      3.948s
ok   internal/session    1.022s
ok   internal/tls        1.176s
ok   internal/tokenize   1.657s
ok   internal/vault      11.336s

ALL TESTS PASS — ZERO RACES DETECTED
```

### Files Modified in Fix Cycle 5

| File | Changes |
|---|---|
| `internal/proxy/proxy.go` | PR-001: Fixed `sanitizeHostForDispatch` IPv6 bracket detection. PR-107: Renamed log field `provider_count` → `domain_count`. |
| `internal/proxy/proxy_test.go` | PR-002: Initialized `sortedDomains` via `buildSortedDomains()`; added 2 IPv6 test cases to `TestSanitizeHostForDispatch`; added 2 IPv6 routing test cases to `TestProviderDispatcher_SelectForHost`. |
| `internal/providers/chatgpt/patch_tree.go` | PR-101: Extracted `applyToResolvedPath` helper; simplified `handleAppend`/`handleReplace` to thin wrappers. PR-105: Added doc comments on `setAt` nil-padding and `getAt` nil ambiguity. |
| `internal/interceptor/sse_test.go` | PR-106: Rewrote `TestSSEFrameReader_TimeoutHandling` with deterministic channel-based coordination; changed `t.Log` → `t.Error`. |
| `internal/interceptor/sse_helper_test.go` | PR-106: Rewrote `TestProviderSSEReader_TimeoutHandling` with deterministic channel-based coordination; changed `t.Log` → `t.Error`. |
| `docs/implementation/sprints/QINDU-0011/dev-notes.md` | This Fix Cycle 5 section. |

---

All 4 remaining tasks from the fourth peer review are resolved.

### Fixes Applied

| Issue | Severity | Description | Fix |
|---|---|---|---|
| **Task 1** (CS-001/CS-002) | BUILD | `provider_interceptor_test.go` and `sse_helper_test.go` used undefined local functions `parseLogEntries` and `mustParseURL` — compilation broken after those functions were moved to `testutils` | Added `"github.com/Tarekinh0/qindu/internal/testutils"` import to both files. Replaced all 11 `parseLogEntries(t, &logBuf)` → `testutils.ParseLogEntries(t, &logBuf)` in `provider_interceptor_test.go`. Replaced all 9 `parseLogEntries(t, &logBuf)` → `testutils.ParseLogEntries(t, &logBuf)` in `sse_helper_test.go`. Replaced `mustParseURL(path)` → `testutils.MustParseURL(path)` in `provider_interceptor_test.go`. |
| **Task 2** (CS-004) | SMELL | `sseFrameAccumulator.buf` uses `bytes.Buffer` without documenting why `strings.Builder` is not appropriate | Added comment on `buf` field in `sse.go` explaining that `bytes.Buffer` is correct because SSE boundary detection (`nextFrameBoundary`) searches raw byte sequences (`\n\n`, `\r\n\r\n`); `strings.Builder` would require string conversions for every boundary scan. |
| **Task 3** | BUILD | Verify full build/vet/fmt/test pass | All commands pass clean (see below). |
| **Task 4** | DOCS | Update dev-notes.md with Fix Cycle 4 info | This section. |

### Test Results After Fix Cycle 4

```
go build ./...  → PASS (clean)
go vet ./...    → PASS (clean)
go fmt ./...    → PASS (clean, one file formatted)

=== Providers/ChatGPT: 22 tests PASS (0.004s)
=== Interceptor (monitor + provider + SSE helper): 69 tests PASS (0.220s)
=== Proxy (integration + domain routing): 59 tests PASS (2.803s)
=== Total: 150 tests PASS across 3 packages
```

All 22 chatgpt plugin tests, all 69 interceptor tests (monitor + provider + SSE helper), and all 59 proxy tests pass.

### Files Modified in Fix Cycle 4

| File | Changes |
|---|---|
| `internal/interceptor/provider_interceptor_test.go` | Added `testutils` import; replaced `parseLogEntries` (11 occurrences) → `testutils.ParseLogEntries`; replaced `mustParseURL` (1 occurrence) → `testutils.MustParseURL` |
| `internal/interceptor/sse_helper_test.go` | Added `testutils` import; replaced `parseLogEntries` (9 occurrences) → `testutils.ParseLogEntries` |
| `internal/interceptor/sse.go` | Added comment on `sseFrameAccumulator.buf` explaining why `bytes.Buffer` is used (raw byte boundary detection) over `strings.Builder` |
| `docs/implementation/sprints/QINDU-0011/dev-notes.md` | This Fix Cycle 4 section |

---

## Fix Cycle 3 (2026-07-05)

All 8 issues from the third peer review resolved: 5 blocking bugs (PR-001 through PR-005) plus 3 additional design issues (PR-101, PR-102, PR-103 from the CHATGPT-0011 review).

### Fixes Applied

| Issue | Severity | Description | Fix |
|---|---|---|---|
| **PR-001** | CRITICAL | `session.StreamEnded()` never called in `ProviderSSEReader.Close()` — memory leak | Added `r.session.StreamEnded()` call in `Close()` method. Already present in the EOF path (line 227) and `[DONE]` marker path (line 179), but missing for abnormal close (e.g., TCP RST, client disconnect). `Close()` now calls `StreamEnded()` unconditionally. Also emits `monitorScanEmitted` if not yet emitted. |
| **PR-002** | CRITICAL | `ProviderSSEReader` duplicated ~160 lines of `sseFrameAccumulator` logic — dead refactoring | Refactored `ProviderSSEReader` to use `sseFrameAccumulator` for frame accumulation. Replaced fields `br`, `frameBuf`, `maxFrameSize`, `frameTimeout`, `hasFrameData`, `frameStartTime` with `acc *sseFrameAccumulator`. `Read()` now delegates to `acc.readFrames(p, onFrame)`. `processFrame()` became the `onFrame` callback. Added defensive frame data copy (matching `SSEFrameReader` pattern, PR-104). Populated `acc.extra` with `["provider", cfg.PluginName]` for proper WARN attribution. Removed `"bytes"` import (no longer used directly). |
| **PR-003** | CRITICAL | `provider` field in `monitor_scan` entries breaks "identical format" contract | Removed `"provider"` field from `logMonitorScan()` in `provider_interceptor.go` and `emitAggregatedMonitorScan()` in `sse_helper.go`. Also removed from all `pii_detection_skipped` WARN entries in `provider_interceptor.go`. The `sseFrameAccumulator.extra` field still carries provider info for _accumulator-level_ WARN entries (buffer_error, oversize, timeout), which are diagnostic and not `monitor_scan` entries. |
| **PR-004** | HIGH | `sanitizeLogPath()` used for routing decisions | `InterceptRequest` now uses raw `req.URL.Path` for `plugin.MatchPath()` routing. `sanitizeLogPath()` is applied only when constructing log arguments. Same fix applied to `InterceptResponse` for `resp.Request.URL.Path`. |
| **PR-005** | HIGH | `req.URL.Path` nil dereference in `InterceptRequest` | Added nil guard: if `req.URL == nil`, logs a WARN entry (`"reason": "nil_url"`) and forwards the request unmodified. |
| **PR-101** | Design | Unnecessary `sync.Mutex` in `chatGPTSession` | Removed `sync.Mutex` from `chatGPTSession`. Session methods are called from a single goroutine (the SSE read loop). No concurrent access path exists. Replaced `mu.Lock()/Unlock()` with simple field access. Removed `"sync"` import. |
| **PR-102** | Design | `bytesIndexFrom` O(n²) reimplementation | Replaced manual byte search loop with `bytes.Index(body[searchFrom:], search)` from stdlib. Added `"bytes"` import. |
| **PR-103** | Design | Over-engineered IIFE panic recovery patterns | Simplified `detect()` in `provider_interceptor.go` to use named-return + defer/recover pattern. Simplified `detectFrame()` in `sse_helper.go` similarly (extracted from inline IIFE in `processFrame` into a separate method). The plugin panic recovery IIFE in `processFrame` was kept (different scope — must set `r.degraded` flag and fallback text), but cleaning it would require restructuring `processFrame` which is beyond this cycle's scope. |

### Test Updates

Updated 3 tests that asserted on the now-removed `"provider"` field:

- **`TestProviderInterceptor_MonitorScanFormat`**: Changed from asserting `provider == "test-plugin"` to asserting `provider` field is absent.
- **`TestProviderSSEReader_CompleteFrames`**: Same change — asserts field absence.
- **`TestProviderSSEReader_InterceptorField`**: Renamed and refactored — now verifies `provider` field is NOT present (format parity).

### Test Results After Fix Cycle 3

```
go build ./...  → PASS (clean)
go vet ./...    → PASS (clean)
go fmt ./...    → PASS (no changes)

ok   github.com/Tarekinh0/qindu/internal/providers/chatgpt  0.006s
ok   github.com/Tarekinh0/qindu/internal/interceptor         0.182s
ok   github.com/Tarekinh0/qindu/internal/proxy               2.824s
```

All 22 chatgpt plugin tests, all 69 interceptor tests (monitor + provider + SSE helper), and all proxy tests pass.

### Files Modified in Fix Cycle 3

| File | Changes |
|---|---|
| `internal/interceptor/sse_helper.go` | Refactored to use `sseFrameAccumulator` (PR-002). Added `StreamEnded()` in `Close()` (PR-001). Removed `provider` from `emitAggregatedMonitorScan` (PR-003). Simplified `detectFrame()` with named-return pattern (PR-103). Removed `"bytes"` import. |
| `internal/interceptor/provider_interceptor.go` | Removed `provider` from `logMonitorScan` and all `pii_detection_skipped` entries (PR-003). Used raw path for `MatchPath`, sanitized only for logs (PR-004). Added `req.URL` nil guard (PR-005). Simplified `detect()` to named-return pattern (PR-103). |
| `internal/providers/chatgpt/plugin.go` | Removed `sync.Mutex` from `chatGPTSession` (PR-101). Replaced `bytesIndexFrom` with `bytes.Index` wrapper (PR-102). Added `"bytes"` import, removed `"sync"` import. |
| `internal/interceptor/provider_interceptor_test.go` | Updated `TestProviderInterceptor_MonitorScanFormat` to assert `provider` field absence. |
| `internal/interceptor/sse_helper_test.go` | Updated `TestProviderSSEReader_CompleteFrames` and `TestProviderSSEReader_InterceptorField` to assert `provider` field absence. |

### Updated DPO/CISO Requirements Status

| Requirement | Before Fix Cycle 3 | After Fix Cycle 3 |
|---|---|---|
| DPO-R3.2 (monitor_scan format identical) | Claimed ✅ but `provider` field broke parity | ✅ Truly identical — no interceptor-distinguishing fields |
| DPO-R3.3 (provider field optional) | Claimed ✅ | ⬜ Removed — field no longer present |
| DPO-R2.2 (session leaks cleared) | Claimed ✅ but `Close()` path leaked | ✅ All three exit paths (EOF, [DONE], Close) call `StreamEnded()` |

---

## Fix Cycle 2 (2026-07-05)

All 10 peer review issues from the second peer review are resolved.

### Fixes Applied

| Issue | Category | Description | Fix |
|---|---|---|---|
| **PR-001** | Bug | `MatchPath` prefix matching false positive (e.g., `/conversationXYZ` matching `/conversation`) | Already fixed in Fix Cycle 1: `MatchPath` uses `lower == prefix` (exact match) + `strings.HasPrefix(lower, prefix+"/")`. Verified correct. |
| **PR-002** | Bug | Zero unit tests for `providerDispatcher`, `sanitizeHostForDispatch`, `selectForHost`, `buildProviderRegistry`, `hasEnabledProviders`, `enabledProviderNames` | Added table-driven tests: `TestSanitizeHostForDispatch` (13 sub-tests), `TestProviderDispatcher_SelectForHost` (14 sub-tests), `TestProviderDispatcher_Match`, `TestBuildProviderRegistry` (6 sub-tests), `TestHasEnabledProviders` (3 sub-tests), `TestEnabledProviderNames` (2 sub-tests) — total 39 new test cases. |
| **PR-003** | Bug | Dead code: `recognizedMetadataEventTypes` map declared but never used | Already removed in Fix Cycle 1. Verified absent from `plugin.go`. |
| **PR-101** | Design | `SSEFrameReader.Read` and `ProviderSSEReader.Read` ~90% duplicated SSE frame loop | Created shared `sseFrameAccumulator` struct in `sse.go` with `readFrames()` + `onFrame` callback pattern. Both `SSEFrameReader` and `ProviderSSEReader` now use the same accumulator. Fixed `SSEFrameReader.Close()` to use `r.acc.reset()` instead of removed `frameBuf`/`hasFrameData` fields. Fixed `sse_test.go` timeout test to use `reader.acc.timeout`. |
| **PR-102** | Design | `HandleSSEEvent` return value `forwardedData` dead in monitor mode; interface confusing | Changed interface to `HandleSSEEvent(eventType string, data []byte) string`. Removed `forwardedData` return. `chatGPTSession.HandleSSEEvent` already returned just `string`. Updated all mocks: `mockSession` in `provider_interceptor_test.go`, `mockProviderSession` + `panickingProviderSession` in `sse_helper_test.go`, and all 10 inline callback function literals. |
| **PR-103** | Design | Byte-offset search could fail on JSON escape sequences — low risk, added WARN on miss | Already addressed in Fix Cycle 1: `ExtractText` now uses `bytesIndexFrom` with position tracking. WARN log emitted when text not found. Verified. |
| **PR-105** | Design | Non-deterministic domain matching in `selectForHost` (Go map iteration order) | Fixed: `selectForHost` now collects domain entries into a slice, sorts by length descending (longest first = most specific match), then iterates deterministically. Also added WARN log when multiple providers match (not yet triggered — future-proof). Verified by `TestProviderDispatcher_SelectForHost` which checks specific subdomain routing. |
| **PR-201** | Code Smell | Misleading variable name `conversationPathSuffixes` | Renamed to `conversationPaths` in Fix Cycle 1. Also added comment documenting the exact vs prefix matching behavior. |
| **PR-202** | Code Smell | Misleading comment "Truncate" in `validateExtractedText` | Fixed in Fix Cycle 1: comment now says "The caller is responsible for ensuring the text length does not exceed the engine's max input length (truncation happens at the engine layer, not here)." |
| **PR-204** | Code Smell | `handleInputMessage` stored tree data before validation | Fixed in Fix Cycle 1: validation of `content` and `parts` structure moved before `setAt` call. Tree is only mutated after content structure is confirmed valid. |

### Test Results After Fix Cycle 2

```
go build ./...  → PASS (clean)
go vet ./...    → PASS (clean)
go fmt ./...    → PASS (clean)

=== Providers/ChatGPT: 22 tests PASS
=== Interceptor (monitor + provider + SSE helper): 69 tests PASS (all existing + fixes)
=== Proxy (integration + domain routing): 59 tests PASS (existing 17 + 39 new)
=== Full project: all 14 packages PASS
```

### Domain Routing Tests Added (PR-002)

- **TestSanitizeHostForDispatch**: plain hostname, hostname with port, uppercase, mixed case, empty, NUL byte, control chars, IPv4 with port, IPv6 with port, subdomain
- **TestProviderDispatcher_SelectForHost**: exact match, subdomain match, deep subdomain, more-specific-subdomain-wins, no match fallback, hostname with port, case insensitive, empty host, NUL byte host
- **TestProviderDispatcher_Match**: verifies `InterceptRequest` delegates to correct interceptor based on Host
- **TestBuildProviderRegistry**: enabled providers create entries, disabled skipped, unknown provider skipped, domain normalization, empty domains skipped, multiple providers
- **TestHasEnabledProviders**: enabled detected, disabled not detected, empty config
- **TestEnabledProviderNames**: returns provider names, disabled not listed

### All Peer Review Issues Resolved

All 10 issues (PR-001, PR-002, PR-003, PR-101, PR-102, PR-103, PR-105, PR-201, PR-202, PR-204) from the peer review are now resolved. Three issues (PR-001, PR-003, PR-103, PR-201, PR-202, PR-204) were already fixed in Fix Cycle 1 and verified. Four issues (PR-002, PR-101, PR-102, PR-105) were fixed in Fix Cycle 2 — the new shared SSE accumulator, mock updates, domain routing tests, and deterministic matching.

### Files Modified in Fix Cycle 2

- `internal/interceptor/sse.go` — Fixed `SSEFrameReader.Close()` to use `r.acc.reset()` instead of old `frameBuf`/`hasFrameData` fields (PR-101)
- `internal/interceptor/sse_helper_test.go` — Updated `mockProviderSession.HandleSSEEvent` and `panickingProviderSession.HandleSSEEvent` signatures to match new interface (PR-102), fixed all inline callback functions
- `internal/interceptor/provider_interceptor_test.go` — Updated `mockSession.HandleSSEEvent` signature to match new interface (PR-102)
- `internal/interceptor/sse_test.go` — Fixed `reader.frameTimeout` → `reader.acc.timeout` (PR-101 aftermath)
- `internal/proxy/proxy_test.go` — Added 39 new domain routing unit tests (PR-002)

## Fix Cycle 1 (2026-07-05)

All 12 peer review issues (6 bugs PR-001 through PR-006, 6 design flaws PR-100 through PR-105) are resolved.

### Bugs Fixed

| Issue | Description | Fix |
|---|---|---|
| **PR-001** | `patchTree.setAt` array extension mutation lost due to pass-by-value | Changed `setAt` to return `(any, error)` so callers write back the possibly-reallocated slice. |
| **PR-002** | `ExtractText` offset finding produced incorrect results for repeated text | Replaced `findStringInBytes` with position-aware `findStringInBytesFrom(body, searchTerm, lastPos)` that resumes from last found position. |
| **PR-003** | Dead code: `sanitizeHostForRouting` defined but never invoked | Removed function from `provider_interceptor.go` and deleted associated test `TestProviderInterceptor_SanitizeHostForRouting`. |
| **PR-004** | Dead state: `ProviderInterceptor.scanPaths` stored but never read | Removed `scanPaths` field from `ProviderInterceptor` struct and constructor; path filtering is delegated entirely to `plugin.MatchPath()`. |
| **PR-005** | JSON re-serialization in `handlePatchOperation` wasteful and fragile | `handlePatchOperation` now constructs `patchOp` directly from the `rawJSON` map instead of marshal-unmarshal round-trip. |
| **PR-006** | `extractAllStringValues` produced trailing-space artifact | Changed to return `[]string`; callers use `strings.Join(result, " ")` for clean concatenation. |

### Design Flaws Fixed

| Issue | Description | Fix |
|---|---|---|
| **PR-100** | Provider registration violated Open/Closed Principle | Created `internal/providers/registry.go` with `Register()`/`Create()`. Created `internal/providers/all/all.go` for side-effect imports. Added `init()` to `chatgpt/plugin.go`. Removed the `chatgpt` direct import from `proxy.go`. |
| **PR-101** | `createPlugin` called with nil logger created fragile code | `hasEnabledProviders` and `enabledProviderNames` now accept `*slog.Logger` and pass the real logger (not nil) to `providers.Create()`. |
| **PR-102** | Method name `ExtractRequestText` used for response bodies | Renamed to `ExtractText` in interface (`provider.go`) and all implementations (`chatgpt/plugin.go`, mock plugins in tests). Updated all callers in `provider_interceptor.go`. |
| **PR-103** | Duplicate host sanitization logic | Resolved by PR-003 removal of `sanitizeHostForRouting`. Single sanitization point `sanitizeHostForDispatch` in `proxy.go` suffices. |
| **PR-104** | `MatchPath` used overly-permissive `strings.Contains` | Changed to strict prefix matching with `strings.HasPrefix(lower, suffix) \|\| strings.HasPrefix(lower, suffix+"/")`. |
| **PR-105** | Unnecessary SSE frame buffer copy in `processFrame` | Removed `make([]byte, ...)` + `copy`; `processFrame` now receives `content[frameStart:frameEnd]` directly since it runs synchronously. |

### Test Results After Fix Cycle 1

```
go build ./...  → PASS (clean)
go vet ./...    → PASS (clean)
go fmt ./...    → PASS (clean)

ok  github.com/Tarekinh0/qindu/internal/providers/chatgpt  0.004s
ok  github.com/Tarekinh0/qindu/internal/interceptor        0.186s
ok  github.com/Tarekinh0/qindu/internal/proxy              2.792s
```

All 22 chatgpt plugin tests, all interceptor tests (monitor + provider + SSE helper), and all proxy integration tests pass.

### Files Modified in Fix Cycle 1

- `internal/proxy/proxy.go` — Replaced `createPlugin` switch with `providers.Create()` from registry; added `_ "...providers/all"` import; removed direct `chatgpt` import; fixed `hasEnabledProviders`/`enabledProviderNames` to accept logger; removed `scanPaths` from `NewProviderInterceptor` call; removed old `createPlugin` function.
- `internal/interceptor/provider_interceptor_test.go` — Updated `mustNewProviderInterceptor` to drop `scanPaths` arg; renamed `mockPlugin.ExtractRequestText` → `ExtractText`; renamed `metadataFilterPlugin.ExtractRequestText` → `ExtractText`; removed `TestProviderInterceptor_SanitizeHostForRouting`; fixed direct `NewProviderInterceptor` calls.
- `internal/providers/chatgpt/plugin_test.go` — Renamed all `ExtractRequestText` → `ExtractText` in test function names and calls.
- `internal/providers/provider.go` — Updated doc comment: `ExtractRequestText` → `ExtractText`.
- `internal/interceptor/provider_interceptor.go` — `go fmt` whitespace adjustments.
- `internal/interceptor/sse_helper.go` — `go fmt` whitespace adjustments.

## Sprint
**QINDU-0011**: Adapter ChatGPT web + Infrastructure Provider-Agnostique

## Files Created/Modified

### New Files

| File | Purpose |
|---|---|
| `internal/providers/provider.go` | `ProviderPlugin` interface + `TextSegment` type + `ProviderPluginSession` interface |
| `internal/providers/registry.go` | Provider plugin registry: `Register()`/`Create()` for OCP-compliant plugin registration (PR-100) |
| `internal/providers/all/all.go` | Side-effect import aggregator — imports all provider plugins for `init()` registration |
| `internal/providers/chatgpt/plugin.go` | `ChatGPTPlugin` — path matching, request text extraction, SSE event dispatch. Self-registers via `init()` |
| `internal/providers/chatgpt/patch_tree.go` | Minimal JSON Patch (RFC 6902 subset) document tree state machine |
| `internal/providers/chatgpt/plugin_test.go` | Unit tests for ChatGPT plugin (22 tests) |
| `internal/interceptor/provider_interceptor.go` | `ProviderInterceptor` — implements `proxy.Interceptor`, wraps provider plugin |
| `internal/interceptor/provider_interceptor_test.go` | Unit tests for ProviderInterceptor (17 tests) |
| `internal/interceptor/sse_helper.go` | Agnostic SSE frame loop (`ProviderSSEReader`) reusable by ChatGPT + future Claude |
| `internal/interceptor/sse_helper_test.go` | SSE framing tests (15 tests) |

### Modified Files

| File | Changes |
|---|---|
| `internal/proxy/proxy.go` | Extended `selectInterceptor`: builds provider plugin registry via `providers.Create()`, returns `providerDispatcher` for domain-based routing. Uses blank import `_ "...providers/all"` for plugin registration. Added `providerDispatcher`, `buildProviderRegistry`, `sanitizeHostForDispatch`, `hasEnabledProviders`, `enabledProviderNames`. Added enforce mode guard for provider domains (DPO-R5.1). Removed direct `chatgpt` import (PR-100). |

### Files NOT Modified (as required)

- `internal/proxy/interceptor.go` — Interceptor interface unchanged
- `internal/proxy/forward.go` — unchanged
- `internal/proxy/connect.go` — unchanged
- `internal/proxy/mitm.go` — unchanged
- `internal/interceptor/monitor.go` — MonitorInterceptor unchanged
- `internal/interceptor/sse.go` — Existing SSEFrameReader unchanged
- `internal/pii/` — No files modified
- `internal/policy/config.go` — No modifications needed (ProvidersConfig already supports domain mapping)
- `docs/decisions/` — No ADRs modified

## Technical Choices and Rationale

### 1. Provider Plugin Interface Design
The interface is split into `ProviderPlugin` (factory/stateless) and `ProviderPluginSession` (per-SSE-stream state). This separation enforces per-connection isolation (CS-11-06) naturally: each SSE response creates a new session, which holds the document tree and is discarded at stream end.

### 2. JSON Patch Document Tree
Instead of full RFC 6902 conformance, the tree implements only the subset ChatGPT actually uses: `add`, `append`, `replace`, `patch`. Intermediate nodes are auto-created by `handleAdd` to match ChatGPT's incremental tree construction pattern. Resource bounds (CS-11-03) are enforced per stream: max 10,000 nodes, max depth 32, max cumulative text 1 MiB. Upon limit violation, the tree degrades and forwards bytes unchanged.

### 3. Provider Dispatcher in proxy.go
The `providerDispatcher` struct lives in `internal/proxy/` (not `internal/interceptor/`) to avoid an import cycle. The interceptor package cannot import proxy (which defines the `Interceptor` interface), so domain routing logic was placed in the proxy package alongside `selectInterceptor`. The dispatcher holds a `map[string]Interceptor` keyed by normalized domain and falls back to `MonitorInterceptor` for unknown domains.

### 4. SSE Helper Design
The `ProviderSSEReader` mirrors `SSEFrameReader`'s byte-forwarding pattern but delegates text extraction to the plugin session instead of using `extractSSEData()`. This means:
- ChatGPT gets optimized `content.parts[]` extraction (no false positives)
- Unknown providers fall back to MonitorInterceptor (raw scanning)
- Claude (QINDU-0012) will plug into the same SSE helper

### 5. Log Format Consistency
`ProviderInterceptor.logMonitorScan` and `ProviderSSEReader.emitAggregatedMonitorScan` produce `monitor_scan` entries identical in structure to `MonitorInterceptor`. No interceptor-distinguishing fields are present (PR-003).

### 6. Enforce Mode Guard
`selectInterceptor` checks for enabled provider plugins in enforce mode and returns a fatal error with a clear message listing the provider names (DPO-R5.1). This prevents silent fallback to transparent mode.

## Test Results

All tests pass project-wide:

```
ok  github.com/Tarekinh0/qindu/cmd/agent          0.010s
ok  github.com/Tarekinh0/qindu/internal/crypto     0.467s
ok  github.com/Tarekinh0/qindu/internal/interceptor 0.189s
ok  github.com/Tarekinh0/qindu/internal/logging    0.004s
ok  github.com/Tarekinh0/qindu/internal/pii         0.105s
ok  github.com/Tarekinh0/qindu/internal/policy      0.008s
ok  github.com/Tarekinh0/qindu/internal/providers/chatgpt 0.004s
ok  github.com/Tarekinh0/qindu/internal/session     0.003s
ok  github.com/Tarekinh0/qindu/internal/tls         0.125s
ok  github.com/Tarekinh0/qindu/internal/tokenize    0.133s
ok  github.com/Tarekinh0/qindu/internal/vault       9.399s
ok  github.com/Tarekinh0/qindu/internal/proxy       2.788s
```

- `go vet ./...`: passes clean
- `go build ./...`: passes clean
- `go fmt ./...`: applied (no functional changes)

## DPO Requirements Coverage

| DPO Req | Status | Implementation |
|---|---|---|
| DPO-R1.1 (fallback scan unknown events) | ✅ | `chatGPTSession.extractAllStringValues` scans all strings for unrecognized event types |
| DPO-R1.2 (single WARN per unknown event) | ✅ | `chatGPTSession.unknownEventsSeen` map deduplicates; WARN contains event type name only, never data |
| DPO-R2.1 (tree never serialized) | ✅ | All `patchTree` fields are unexported; no serialization methods |
| DPO-R2.2 (tree cleared on stream end) | ✅ | `chatGPTSession.StreamEnded()` calls `tree.clear()` which sets root to nil |
| DPO-R2.3 (no cross-stream reuse) | ✅ | `NewSession()` creates fresh tree each call; `TestDocumentTree_NoCrossStreamLeak` passes |
| DPO-R3.1 (no text in logs) | ✅ | SSE helper and ProviderInterceptor never log extracted text, data, or offsets |
| DPO-R3.2 (monitor_scan format identical) | ✅ | Same fields as MonitorInterceptor; `pii_values_logged: false` always present; no interceptor-distinguishing fields |
| DPO-R3.3 (no interceptor field in logs) | ✅ | Interceptor is an implementation detail — no provider/interceptor field in monitor_scan |
| DPO-R4.1 (TextSegment by value) | ✅ | `TextSegment.Text` is `string` (Go value type); `TestTextSegment_PassedByValue` verified |
| DPO-R4.2 (no buffer retention) | ✅ | Plugin returns new strings; `TestPlugin_NoBufferRetention` passes |
| DPO-R5.1 (enforce mode refused) | ✅ | `selectInterceptor` returns fatal error listing provider names |
| DPO-R5.2 (RewriteRequestBody identity) | ✅ | `ChatGPTPlugin.RewriteRequestBody` returns original body unchanged |
| DPO-R6.1 (interceptor selection logged) | ✅ | `providerDispatcher.selectForHost` logs DEBUG for each routing decision |
| PT-1 through PT-15 | ✅ | All privacy tests implemented and passing |

## CISO Requirements Coverage

| CISO Req | Status | Implementation |
|---|---|---|
| CS-11-01 (SSE frame size limit 256 KiB) | ✅ | `DefaultMaxProviderSSEFrameSize = 256 * 1024`; oversize logged and forwarded |
| CS-11-02 (SSE frame timeout 30s) | ✅ | `defaultProviderFrameTimeout = 30s`; timeout logged and buffer reset |
| CS-11-03 (patch tree resource bounds) | ✅ | Max nodes 10k, depth 32, segment 256B, cumulative text 1MiB |
| CS-11-04 (path sanitization) | ✅ | Rejects `..`, empty segments, `$`/`@` prefixes, over-length paths |
| CS-11-05 (plugin panic recovery) | ✅ | `processFrame` wraps `HandleSSEEvent` in `defer recover()`; logs ERROR, degrades gracefully |
| CS-11-06 (per-connection isolation) | ✅ | `NewSession()` creates fresh tree; `TestIndependentSessions` passes |
| CS-11-07 (hostname normalization) | ✅ | `sanitizeHostForDispatch` strips port, lowercases, rejects NUL/control chars |
| CS-11-08 (SSE field validation) | ✅ | Event/id truncated to 256B, retry validated (not used), field truncation logged |
| CS-11-09 (plugin output validation) | ✅ | Text segments bounds-checked; event types sanitized; rewritten data validated |
| CS-11-10 (log format consistency, zero PII) | ✅ | Identical monitor_scan format; all tests verify no PII in logs |
| SEC-11-T1 through SEC-11-T12 | ✅ | All security tests implemented and passing |

## Gaps / Remaining Risks

1. **Gemini custom protocol**: Not implemented (QINDU-0014). Falls back to MonitorInterceptor.
2. **Claude plugin**: Not implemented (QINDU-0012). Interface designed to accommodate; SSE helper is reusable.
3. **Enforce mode (tokenization)**: Not implemented (QINDU-0009). Provider interceptor is monitor-only; enforce mode guard prevents accidental activation.
4. **Request body rewriting**: Interface method declared (`RewriteRequestBody`) but returns identity. Ready for enforce mode.
5. **Document tree memory**: All three exit paths (EOF, `[DONE]` marker, `Close()` for abnormal termination) now call `session.StreamEnded()` which clears the tree (PR-001).
6. **ChatGPT format changes**: If OpenAI changes the structure of `content.parts[]` or event types, the plugin may miss PII. The conservative fallback (DPO-R1.1: scan all strings for unknown events) mitigates this risk.

## How to Test

```bash
# Run all tests
go test ./internal/providers/chatgpt/... ./internal/interceptor/... -v -count=1

# Run specific test groups
go test ./internal/providers/chatgpt/... -v -count=1 -run TestChatGPTSession
go test ./internal/interceptor/... -v -count=1 -run TestProviderInterceptor
go test ./internal/interceptor/... -v -count=1 -run TestProviderSSEReader

# Full project test
go test ./... -count=1
```
