# Peer Review: QINDU-0011 — Adapter ChatGPT web + Infrastructure Provider-Agnostique

**Reviewer**: qindu-peer-reviewer (fresh session, blank slate)  
**Date**: 2026-07-05  
**Phase**: 4 — Enforce Pipeline  
**Files changed**: 10 (1312 insertions, 484 deletions)  
**New files**: 8 (`internal/providers/`, `internal/interceptor/provider_interceptor*.go`, `internal/interceptor/sse_helper*.go`)  
**Build**: ✅ pass  
**Vet**: ✅ pass  
**Tests (with `-race`)**: ✅ all pass  

---

## Section 1: Scorecard

| Framework | Score | Justification |
|-----------|-------|---------------|
| **Clean Code** | **8/10** | `emitMonitorScan` centralizes 4 duplicate log emission sites into 1. `scanBody` eliminates ~300 lines of duplication. `sseFrameAccumulator` shared between two SSE readers. `parseSSEFrame` is parse-only, no mutation. However: `isValidText` is misleadingly named (only checks NUL bytes), and `providerDispatcher.logger` is a dead field. |
| **Pragmatic Programmer** | **8/10** | Orthogonality is excellent — agnostic layer owns byte I/O, plugin owns JSON schema. Plugin isolation via `ProvidersConfig.Validate()` (domain slashes, wildcards, duplicates). Reversibility respected: `RewriteRequestBody` is declared but returns identity. Plugin factory pattern enables future providers without touching proxy.go. Deduction: `providers` registry lacks `IsRegistered` — forces `Create` for existence checks. |
| **SOLID** | **9/10** | **SRP**: Each struct has one reason to change. `ProviderPlugin` interface (3 methods + factory) focused on text extraction. `ProviderPluginSession` (2 methods) focused on per-stream state. **OCP**: Plugin registration via `init()` + `providers.Register` — adding a new provider requires zero changes to proxy.go. **ISP**: Interfaces are small — `ProviderPlugin` has 5 methods, `ProviderPluginSession` has 2. **DIP**: Proxy depends on `Interceptor` interface; `selectInterceptor` returns `providerDispatcher` behind it. Deduction: `providers.Create` leaks concrete instantiation through the registry. |
| **Go Proverbs** | **9/10** | Errors are values and always wrapped (`%w`). No panic in production paths (CS-11-05 panic recovery wraps all plugin calls). `defer` for cleanup is correct — `emitAndCleanup` is idempotent. `sync.RWMutex` on registry correctly used. Deduction: `slog.Logger` is passed as concrete `*slog.Logger` rather than interface — idiomatic per Go community convention but limits test mocking. |
| **Effective Go** | **9/10** | Idiomatic naming: `NewProviderInterceptor`, camelCase fields, no getters named `GetX`. Build tag correctness: `_ "internal/providers/all"` side-effect import is properly documented. No `init()` abuse — only plugin self-registration. Error handling consistent: `if err := ...; err != nil`. Deduction: `combinedReadCloser` embeds `io.Reader` by value but wraps `io.Closer` via method — uncommon pattern worth a comment. |
| **DDD** | **9/10** | Bounded contexts: `providers` package, `chatgpt` sub-package, `interceptor` package cleanly separated. Ubiquitous language: `ProviderPlugin`, `ProviderPluginSession`, `TextSegment`, `chatGPTSession`, `patchTree` — domain terms match the story. Aggregate root: `chatGPTSession` owns the `patchTree` document tree lifecycle. Value objects: `TextSegment` is copied by value. Deduction: `bodyScanConfig` is a parameter object, not a domain concept — purely mechanical. |
| **Code Complete** | **9/10** | Defensive programming strong: `matchPathSafe`, `extractTextSafe`, `newSessionSafe` all wrap plugin calls with recover. Config validation at startup: `ProvidersConfig.Validate()` catches bad domains. Path depth limits (`maxPathDepth = 32`), node count limits (`maxTreeNodes = 10000`), text limits (`maxCumulativeText = 1 MiB`). HTML entity encoding not needed (JSON is the transport). No global mutable state. Deduction: `patch_tree.go:setAt` uses `existing == nil` without comma-ok to distinguish "key not in map" from "key set to nil" — theoretical node-count double-increment. |

**Composite score**: **61/70** (87%) — Solid, production-quality code with minor naming/cosmetic issues.

---

## Section 2: Critical Findings 🔴

### PR-001: `patchTree.setAt` map nil-value double-counting (node exhaustion risk)

- **File**: `internal/providers/chatgpt/patch_tree.go:386-392`
- **Severity**: LOW (no practical impact on ChatGPT — documented for future maintainers)
- **Problem**: `setAt` for maps checks `existing == nil` to decide whether to increment `nodeCount`:

```go
case map[string]any:
    existing := p[seg]          // ← no comma-ok
    if existing == nil {         // ← conflates "not found" with "found nil"
        t.nodeCount++
```

In Go, `m["key"]` returns the zero value (`nil` for `any`) for both missing keys and keys explicitly set to `nil`. If a JSON Patch operation sets a map key to `nil` and a subsequent operation overwrites it with a non-nil value, `nodeCount` is incremented twice for the same logical node. This prematurely triggers `degraded` mode at `maxTreeNodes - 1` actual nodes instead of `maxTreeNodes`.

**Fix**: Use the comma-ok form to distinguish:

```go
case map[string]any:
    _, exists := p[seg]
    if !exists {
        t.nodeCount++
        if t.nodeCount > maxTreeNodes {
            return nil, fmt.Errorf("max node count %d exceeded", maxTreeNodes)
        }
    }
    p[seg] = value
    return p, nil
```

This is a true defect in the node counting logic but has **zero practical impact on ChatGPT** because the ChatGPT protocol never sets map values to `nil`. Flagged for correctness in the event this tree is reused for other providers.

---

## Section 3: Design Flaws 🟡

### PR-101: `providerDispatcher.logger` — dead field

- **Category**: Dead Code
- **File**: `internal/proxy/proxy.go:163`
- **Problem**: The `providerDispatcher` struct stores a `logger *slog.Logger` field that is never used in `InterceptRequest`, `InterceptResponse`, or `selectForHost`. It is set at construction time but reads zero times during dispatch.
- **Fix**: Remove the field. If future logging is needed at dispatch time, the `fallback` and `providers` already have their own loggers.

### PR-102: `isValidText` — misleading function name

- **Category**: Naming
- **File**: `internal/interceptor/provider_interceptor.go:292-303`
- **Problem**: `isValidText` suggests a general text validity check but only detects embedded NUL bytes (`s[i] == 0`). The function does not verify UTF-8 validity or check for other control characters. Since Go strings are guaranteed UTF-8, the NUL check is the only meaningful validation, but the name overpromises.
- **Fix**: Rename to `containsNUL` or `isNULFree`, and update the doc comment to be precise about what it validates. Alternatively, fold the NUL check directly into `validateTextSegments` since it's the only caller.

### PR-103: `providers` registry lacks `IsRegistered` — forces wasteful `Create` calls

- **Category**: Interface Segregation
- **File**: `internal/providers/registry.go`
- **Problem**: `hasEnabledProviders` and `enabledProviderNames` in `proxy.go` call `providers.Create(name, logger)` solely to check if a plugin exists. `Create` constructs a full plugin instance (allocates memory, sets up data structures) that is immediately discarded. This violates "don't pay for what you don't use."
- **Fix**: Add a lightweight lookup function:

```go
func IsRegistered(name string) bool {
    registryMu.RLock()
    _, ok := registry[name]
    registryMu.RUnlock()
    return ok
}
```

Then `hasEnabledProviders` and `enabledProviderNames` use `IsRegistered` instead of `Create`.

### PR-104: `chatGPTSession.HandleSSEEvent` — event type precedence ambiguity

- **Category**: Coupling / Silent Behavior
- **File**: `internal/providers/chatgpt/plugin.go:157-208`
- **Problem**: `HandleSSEEvent` receives `eventType` from the SSE `event:` line and `data` as raw bytes. The method then:
  1. Parses `data` as JSON
  2. If `eventType == ""`, extracts the `type` field from the JSON
  3. Checks for `PatchOp` (`"o"` field) before checking `eventType`
  
  This means a frame with `event: message_marker` AND a JSON `"o": "append"` would be processed as a patch operation (step 3 takes priority). The precedence order (patch ops → typed events → fallback) is correct per ChatGPT's protocol but is not documented in the function's godoc.
- **Fix**: Add a godoc comment explaining the precedence order and the rationale (patch ops are structural and must be processed first to maintain the document tree, while typed events are informational).

### PR-105: `validateEventType` silently truncates and strips — no indication to caller

- **Category**: Silent Data Corruption
- **File**: `internal/interceptor/sse_helper.go:377-392`
- **Problem**: `validateEventType` truncates event types longer than `maxSSEEventTypeLen` (128 bytes) and strips non-printable characters. The truncation is silent — no warning log, no indication that data was modified. If a future provider uses event types longer than 128 bytes, the interceptor silently corrupts them. The event type is only used for routing within the plugin (not forwarded), so current impact is low.
- **Fix**: When truncation occurs, emit a DEBUG-level log: `"sse_event_type_truncated"`. This gives operators visibility into data modification without being noisy.

### PR-106: `parseSSEFrame` does not validate `retry:` values despite parsing them

- **Category**: Input Validation
- **File**: `internal/interceptor/sse_helper.go:364-367`
- **Problem**: The SSE spec allows `retry:` lines that control reconnection behavior. The `parseSSEFrame` function explicitly mentions `retry:` and `id:` lines (lines 358-367) but only skips them — no validation of the numeric retry value against `maxRetryMs` (defined at line 34). The constant `maxRetryMs` is defined but never used.
- **Fix**: Either remove the unused `maxRetryMs` constant and the dead comment about `retry:` validation, or implement validation. The constant is dead code.

### PR-107: `combinedReadCloser` structural pattern — embedding `io.Reader` by value

- **Category**: Code Smell / Composability
- **File**: `internal/interceptor/monitor.go:26-34`
- **Problem**: `combinedReadCloser` embeds `io.Reader` by value and wraps `io.Closer` via explicit `Close()` method. This is correct but non-obvious. A reader who sees `type combinedReadCloser struct { io.Reader; closer io.Closer }` might expect it to implement `io.ReadCloser` through embedding, but it doesn't — `Close()` is a method, not an embedded interface. The name `combinedReadCloser` also implies it IS a `ReadCloser`, which it technically is.
- **Fix**: Add a 2-line comment explaining why the pattern is used (to allow a `MultiReader` to share a closer with the original body). No code change needed.

---

## Section 4: Excellence 🟢

### EX-001: `emitMonitorScan` — DRY consolidation of 4 identical log paths
**File**: `internal/interceptor/monitor.go:254-293`

Four call sites (`MonitorInterceptor.scanBody`, `SSEFrameReader.emitAggregatedMonitorScan`, `ProviderSSEReader.emitAggregatedMonitorScanLocked`, `ProviderInterceptor via scanBody`) all now converge on a single `emitMonitorScan(logger, MonitorScanArgs{...})`. The `MonitorScanArgs` struct uses Go zero-value semantics (`Status == 0` → omit) for clean log emission. This is textbook Clean Code refactoring.

### EX-002: `scanBody` — shared body scanner eliminates ~300 lines of near-identical code
**File**: `internal/interceptor/monitor.go:386-488`

The `bodyScanConfig` + `scanBody` pattern abstracts the entire body-read/detect/log/rewrite pipeline. `MonitorInterceptor` passes `extractor: nil` for full-body scanning; `ProviderInterceptor` passes `extractor: p.extractTextSafe` for targeted extraction. The `rewriter` callback is declared but returns identity in this sprint. This is the Strategy pattern done right in Go — no abstract classes, no factories, just function fields.

### EX-003: `patchTree` resource boundaries — defense-in-depth
**File**: `internal/providers/chatgpt/patch_tree.go:10-17`

Every resource-consuming operation has a hard limit:
- `maxTreeNodes = 10000` — prevents memory exhaustion from pathological JSON Patch
- `maxPathDepth = 32` — prevents deeply nested traversal
- `maxPathTotalLen = 512` — prevents large path strings
- `maxCumulativeText = 1 << 20` — 1 MiB text per stream
- JSON Pointer extension rejection (`$`, `@`) and `..` traversal blocking

When any limit is exceeded, `degraded = true` and subsequent operations are silently no-op'd. The tree does not crash — it gracefully degrades. This is textbook Code Complete defensive programming.

### EX-004: `parsePath` input validation — RFC 6901 subset with security hardening
**File**: `internal/providers/chatgpt/patch_tree.go:265-319`

The path parser validates:
- Leading `/` required (non-optional per RFC 6901)
- Path length bounded
- Segment length bounded
- Depth bounded
- Extension prefixes (`$/`, `@/`) rejected
- `..` segments rejected (even though JSON Pointer has no traversal semantics)
- Empty path segments rejected (`/foo//bar`)

The test coverage (`patch_tree_test.go`) includes 13 invalid-path test cases covering every rejection reason. This is rare quality in open-source Go code.

### EX-005: `sseFrameAccumulator` — shared frame accumulation eliminates 90% duplication
**File**: `internal/interceptor/sse.go:292-421`

The `sseFrameAccumulator` extracts the identical frame-buffering/boundary-detection/timeout logic from `SSEFrameReader` and `ProviderSSEReader`. `readFrames` uses a callback (`onFrame`) to let each reader process frames differently. The `extra` field (`[]any`) allows per-instance log attributes without modifying the accumulator. This is elegant composition.

### EX-006: `sanitizeHostForDispatch` — IPv6-aware port stripping
**File**: `internal/proxy/proxy.go:274-307`

The function correctly handles:
- `chatgpt.com:443` → `chatgpt.com`
- `[::1]:8080` → `[::1]`
- `[2001:db8::1]:443` → `[2001:db8::1]`
- Bare IPv6 `[::1]` → `[::1]`
- IPv6 without brackets `::1:8080` → `::1` (fallback behavior, unlikely in practice)

The test `TestSanitizeHostForDispatch` covers 15 cases including NUL injection, control characters, and multiple IPv6 variants. This is the kind of edge-case awareness that prevents production incidents.

### EX-007: `providers.Register` / `providers.Create` — plugin registry with OCP
**File**: `internal/providers/registry.go`

The `init()` + `Register` pattern enables adding a new provider (e.g., Claude in QINDU-0012) with:
1. Create the plugin package with `func init() { providers.Register("claude", ...) }`
2. Add `_ "internal/providers/claude"` to `internal/providers/all/all.go`
3. **Zero changes to proxy.go**

This is the Open/Closed Principle applied to plugin loading — the Go equivalent of ServiceLoader or DI container registration.

### EX-008: Test quality — `TestTestFixtures_NoRealPII`
**File**: `internal/providers/chatgpt/plugin_test.go:532-569`

A static analysis test that validates every email address in test fixtures uses only `example.com`, `doe.com`, `company.org`, or `test.org` domains. This prevents accidental inclusion of real PII. The test has a positive allowlist (`allowedDomains`) and fails on unknown domains. This is the kind of test that prevents CISO gate rejections.

---

## Section 5: Verdict

**MERGE_READY**

The implementation is production-quality. The architecture — agnostic SSE layer + provider-specific plugins — is cleanly separated with minimal coupling. The resource boundaries on the patch tree, the panic isolation on plugin calls, and the centralized log emission function demonstrate mature Go engineering.

The issues identified above (PR-001 through PR-107) are:
- **PR-001**: A theoretical node-counting bug with zero practical impact on ChatGPT. Can be fixed in QINDU-0012 when the patch tree is reviewed for Claude.
- **PR-101–PR-107**: Code quality improvements — dead field removal, better naming, missing validation, and documentation. None are blocking.

No PII leaks. No security vulnerabilities. No data loss paths. No goroutine leaks. All tests pass with `-race`.

### Acceptance Criteria Coverage

All 10 acceptance criteria from the story are covered by tests:

| AC | Description | Test |
|----|-------------|------|
| 1 | ChatGPT user message — PII detected | `TestChatGPTPlugin_PIIDetectionOnExtractedText` |
| 2 | ChatGPT response — text PII detected | `TestProviderInterceptor_SSEResponse` |
| 3 | ChatGPT metadata — JWT ignored | `TestChatGPTSession_MetadataEventsIgnored` |
| 4 | ChatGPT markers — ignored | `TestChatGPTSession_AppendNonTextPath` |
| 5 | Non-conversation paths bypassed | `TestProviderInterceptor_NonConversationPathBypassed` |
| 6 | Fallback to MonitorInterceptor | `TestProviderInterceptor_MonitorScanFormat` (format parity) |
| 7 | ProviderInterceptor + Monitor coexist | `TestProviderDispatcher_SelectForHost` |
| 8 | SSE helper correctness | `TestParseSSEFrame_EventAndData` (6 cases), `TestProviderSSEReader_CRLFBoundaries` |
| 9 | Patch tree — input_message init | `TestChatGPTSession_InputMessage_TextExtracted` |
| 10 | Patch tree — append | `TestChatGPTSession_AppendTextContent` |
