# CISO Security Review — QINDU-0011 (Re-verification)

- **Author**: Qindu CISO
- **Sprint**: Adapter ChatGPT web + Infrastructure Provider-Agnostique
- **Date**: 2026-07-05
- **Review type**: Re-verification after fixes for CS-11-04.1 and CS-11-05

---

## 1. Re-verification Summary

This re-verification targets the two blocking findings from the previous review:

| Blocker | Description | Previous Status | Current Fix |
|---|---|---|---|
| **CS-11-04.1** | `..` path segments not rejected in `parsePath()` | ❌ FAIL | ✅ FIXED — `patch_tree.go:298-303` |
| **CS-11-05** | `MatchPath`, `ExtractText`, `NewSession` lacked panic recovery | ❌ PARTIAL FAIL | ✅ FIXED — `provider_interceptor.go:212-264` |

All other CS-11-XX requirements are re-verified for regressions against the same source files.

---

## 2. CS-11-04.1 Fix Verification — `..` Path Segment Rejection: **PASS**

### Code location: `internal/providers/chatgpt/patch_tree.go:298-303`

```go
// Reject ".." segments — defense-in-depth (CS-11-04.1).
// JSON Pointer has no traversal semantics, but rejecting ".." prevents
// path-traversal-styled inputs from reaching downstream consumers.
if decoded == ".." {
    return nil, fmt.Errorf("rejected '..' segment in path %q", sanitizePathForError(path))
}
```

The check is placed at the correct location in `parsePath()`:
- **After** the `$`/`@` prefix check (line 294)
- **Before** the segment length and depth checks
- Returns a sanitized error with path truncated for safety

### Tests:

| Test | Location | Status |
|---|---|---|
| "double-dot segment rejected" — `/foo/..` → error | `patch_tree_test.go:112-115` | ✅ PASS |
| "path traversal style .. segments" — `/../../etc/passwd` → error | `patch_tree_test.go:117-119` | ✅ PASS |

Both tests verify the error message contains `"rejected '..' segment"`.

---

## 3. CS-11-05 Fix Verification — Full Plugin Panic Recovery: **PASS**

### Code location: `internal/interceptor/provider_interceptor.go`

Three new panic-safe wrapper methods have been added:

#### 3.1 `matchPathSafe()` (lines 212–224)

```go
func (p *ProviderInterceptor) matchPathSafe(method, path string) (matched bool) {
    defer func() {
        if r := recover(); r != nil {
            p.logger.Error("provider_plugin_panic",
                "plugin", p.plugin.Name(),
                "method", "MatchPath",
                "panic", fmt.Sprintf("%v", r),
            )
            matched = false
        }
    }()
    return p.plugin.MatchPath(method, path)
}
```

- Called from `InterceptRequest()` line 74 and `InterceptResponse()` line 125
- On panic: logs ERROR, returns `false` (no match → falls through to next interceptor / passthrough)

#### 3.2 `extractTextSafe()` (lines 229–241)

```go
func (p *ProviderInterceptor) extractTextSafe(body []byte) (segments []providers.TextSegment) {
    defer func() {
        if r := recover(); r != nil {
            p.logger.Error("provider_plugin_panic",
                "plugin", p.plugin.Name(),
                "method", "ExtractText",
                "panic", fmt.Sprintf("%v", r),
            )
            segments = nil
        }
    }()
    return p.plugin.ExtractText(body)
}
```

- Called from `InterceptRequest()` line 97 (via `bodyScanConfig.extractor`) and `InterceptResponse()` line 190
- On panic: logs ERROR, returns `nil` segments (no text extracted → body forwarded without scanning)

#### 3.3 `newSessionSafe()` (lines 247–263)

```go
func (p *ProviderInterceptor) newSessionSafe() (session providers.ProviderPluginSession) {
    defer func() {
        if r := recover(); r != nil {
            p.logger.Error("provider_plugin_panic",
                "plugin", p.plugin.Name(),
                "method", "NewSession",
                "panic", fmt.Sprintf("%v", r),
            )
            session = &noOpProviderSession{}
        }
    }()
    session = p.plugin.NewSession()
    if session == nil {
        session = &noOpProviderSession{}
    }
    return
}
```

- Called from `InterceptResponse()` line 159 (CT SSE branch)
- On panic: logs ERROR, returns `noOpProviderSession` (empty text, silent StreamEnded)
- Also guards against `nil` return from `NewSession()`

#### 3.4 `noOpProviderSession` (lines 265–269)

```go
type noOpProviderSession struct{}

func (s *noOpProviderSession) HandleSSEEvent(_ string, _ []byte) string { return "" }
func (s *noOpProviderSession) StreamEnded()                             {}
```

Safe fallback: returns empty text for all events, StreamEnded is a no-op.

#### 3.5 `HandleSSEEvent` panic recovery — pre-existing (lines 257–269 of `sse_helper.go`)

Already wrapped in the previous version. Unchanged. Sets `r.degraded = true` on panic, falls back to raw SSE extraction.

### Call-site coverage:

| Plugin method | Call site | Safe wrapper | Verified |
|---|---|---|---|
| `MatchPath` | `InterceptRequest():74` | `matchPathSafe()` | ✅ |
| `MatchPath` | `InterceptResponse():125` | `matchPathSafe()` | ✅ |
| `ExtractText` | `InterceptRequest():97` | `extractTextSafe()` | ✅ |
| `ExtractText` | `InterceptResponse():190` | `extractTextSafe()` | ✅ |
| `NewSession` | `InterceptResponse():159` | `newSessionSafe()` | ✅ |
| `HandleSSEEvent` | `sse_helper.go:268` | Inline `defer recover()` | ✅ |

**All plugin calls from the agnostic layer are now protected.** ✅

---

## 4. Per-Requirement Re-verification (CS-11-01 through CS-11-10)

### CS-11-01 — SSE Frame Size Limit: **PASS** (Unchanged)

| Check | Status |
|---|---|
| `DefaultMaxProviderSSEFrameSize = 256 KiB` | ✅ `sse_helper.go:18` |
| Oversize detection in `sseFrameAccumulator` | ✅ `sse.go:341-355` |
| Bytes forwarded on oversize | ✅ |
| Test `TestProviderSSEReader_OversizedFrame` | ✅ PASS |

### CS-11-02 — SSE Frame Timeout: **PASS** (Unchanged)

| Check | Status |
|---|---|
| Default 30s timeout | ✅ `sse_helper.go:21` |
| Timeout detection in `sseFrameAccumulator` | ✅ `sse.go:388-401` |
| Test `TestProviderSSEReader_TimeoutHandling` | ✅ PASS |

### CS-11-03 — JSON Patch Document Tree Resource Bounds: **PASS** (Unchanged)

| Limit | Code | Test |
|---|---|---|
| Max nodes: 10,000 | `patch_tree.go:12` → `setAt()` lines 386-388 | SEC-11-T3 ✅ |
| Max path depth: 32 | `patch_tree.go:13` → `parsePath()` lines 314-316 | SEC-11-T4 ✅ |
| Max path segment: 256 bytes | `patch_tree.go:14` → `parsePath()` lines 306-308 | ✅ |
| Max cumulative text: 1 MiB | `patch_tree.go:16` → `handleAdd()`, `applyToResolvedPath()` | SEC-11-T12 ✅ |

All violations trigger `t.degraded = true`. No regression.

### CS-11-04 — JSON Patch Path Sanitization: **PASS** (Previously FAIL for `..`)

| Rule | Code | Test | Status |
|---|---|---|---|
| 1. Reject `..` segments | ✅ `patch_tree.go:298-303` | `patch_tree_test.go:112-119` | ✅ PASS |
| 2. Reject empty path segments | ✅ `patch_tree.go:288-291` | (implicit in `TestParsePath_Invalid`) | ✅ PASS |
| 3. Reject `$`/`@` prefixes | ✅ `patch_tree.go:294-295` | `patch_tree_test.go:86-94` | ✅ PASS |
| 4. Max 512 bytes total length | ✅ `patch_tree.go:272-274` | `patch_tree_test.go:96-100` | ✅ PASS |

### CS-11-05 — Plugin Panic Recovery: **PASS** (Previously PARTIAL FAIL)

| Call site | Protected? | Status |
|---|---|---|
| `MatchPath` in request & response | ✅ `matchPathSafe()` | ✅ PASS |
| `ExtractText` in request & response | ✅ `extractTextSafe()` | ✅ PASS |
| `NewSession` in response | ✅ `newSessionSafe()` | ✅ PASS |
| `HandleSSEEvent` in SSE loop | ✅ Inline `defer recover()` | ✅ PASS |

Test `TestProviderSSEReader_PluginPanic` (SEC-11-T7) — PASS.

### CS-11-06 — Plugin Per-Connection Isolation: **PASS** (Unchanged)

| Check | Status |
|---|---|
| Fresh session per SSE stream via `newSessionSafe()` | ✅ `provider_interceptor.go:159` |
| No shared mutable state between `chatGPTSession` instances | ✅ |
| Session cleared on `StreamEnded()` | ✅ `plugin.go:212-218` |
| Test `TestProviderInterceptor_IndependentSessions` | ✅ PASS |

### CS-11-07 — Hostname Normalization for Domain Routing: **PASS** (Unchanged)

| Rule | Code | Test |
|---|---|---|
| Lowercase | `sanitizeHostForDispatch()` line 291 | ✅ |
| Strip port (IPv4, IPv6, bare IPv6) | Lines 293-304 | ✅ |
| Reject empty host | Line 277-279 | ✅ |
| Reject NUL/control chars | Lines 281-288 | ✅ |
| Exact + suffix match | `selectForHost()` lines 192-206 | ✅ |
| No duplicate domain logic | `DomainRouter` is single source of truth | ✅ |

### CS-11-08 — SSE Field Validation: **PASS** (Unchanged)

| Check | Status |
|---|---|
| `event:`/`id:` truncated to 256 bytes | ✅ `parseSSEFrame()` lines 339-344 |
| `retry:` not parsed — no timer injection vector | ✅ |

### CS-11-09 — Plugin Output Validation: **PASS** (Unchanged)

| Check | Code |
|---|---|
| Text segment bounds validation | ✅ `validateTextSegments()` lines 274-289 |
| Empty text / NUL byte filtering | ✅ `isValidText()` lines 292-302 |
| Event type ≤ 128 bytes, printable ASCII | ✅ `validateEventType()` lines 377-392 |
| Extracted text UTF-8 validation | ✅ `validateExtractedText()` lines 398-407 |

### CS-11-10 — Log Format Consistency and Zero PII Guarantee: **PASS** (Unchanged)

| Check | Status |
|---|---|
| Identical `monitor_scan` format as `MonitorInterceptor` | ✅ Uses `emitMonitorScan()` shared function |
| `pii_values_logged: false` | ✅ Verified |
| No raw PII in any log entry | ✅ `TestProviderInterceptor_ZeroPIIInAllLogs`, `TestProviderSSEReader_ZeroPIIInLogs` |
| Entity summary keys are types only | ✅ `isValidEntityType()` check |
| Sanitized error metadata | ✅ `sanitizePathForError()`, `sanitizeSegmentForError()`, `sanitizeEventTypeForLog()` |

---

## 5. Mandatory Security Tests Coverage

| Test ID | Requirement | Test Function | Status |
|---|---|---|---|
| SEC-11-T1 | CS-11-01 oversize frame | `TestProviderSSEReader_OversizedFrame` | ✅ PASS |
| SEC-11-T2 | CS-11-02 frame timeout | `TestProviderSSEReader_TimeoutHandling` | ✅ PASS |
| SEC-11-T3 | CS-11-03 max nodes 10,000 | `TestApplyOps_MaxTreeNodesDegradedMode` | ✅ PASS |
| SEC-11-T4 | CS-11-03 max path depth | `TestApplyOps_MaxDepthError` | ✅ PASS |
| SEC-11-T5 | CS-11-04 path traversal `..` | `TestParsePath_Invalid` — "path traversal style .. segments" | ✅ PASS |
| SEC-11-T6 | CS-11-04 extension prefix `$` | `TestParsePath_Invalid` — "extension prefix dollar-slash" | ✅ PASS |
| SEC-11-T7 | CS-11-05 plugin panic | `TestProviderSSEReader_PluginPanic` | ✅ PASS |
| SEC-11-T8 | CS-11-06 concurrent isolation | `TestProviderInterceptor_IndependentSessions` | ✅ PASS |
| SEC-11-T9 | CS-11-07 NUL byte host | `TestSanitizeHostForDispatch` — "NUL byte" | ✅ PASS |
| SEC-11-T10 | CS-11-09 invalid segment bounds | `TestProviderInterceptor_ValidateTextSegments` | ✅ PASS |
| SEC-11-T11 | CS-11-10 zero PII in logs | `TestProviderInterceptor_ZeroPIIInAllLogs`, `TestProviderSSEReader_ZeroPIIInLogs` | ✅ PASS |
| SEC-11-T12 | CS-11-03 max cumulative text | `TestApplyOps_MaxCumulativeTextDegradedMode` | ✅ PASS |

**All 12 mandatory security tests pass.** SEC-11-T5 (previously missing due to the `..` blocker) is now present and passes.

---

## 6. New Concerns

None. The fixes are minimal, targeted, and do not introduce new attack surface or complexity.

---

## 7. Residual Risk Assessment

No change from previous review. The four residual risks remain accepted:
- GPT model behavior change alters JSON Patch format (monitor mode only — worst case: missed PII detection)
- Gemini custom protocol not covered (out of scope)
- Plugin interface evolution risk (Claude/Gemini HAR confirmed coverage)
- Document tree memory retention after stream error (Go GC reclaims)

---

## 8. Test Results Summary

```
ok  	github.com/Tarekinh0/qindu/internal/interceptor	0.313s
ok  	github.com/Tarekinh0/qindu/internal/providers/chatgpt	0.040s
ok  	github.com/Tarekinh0/qindu/internal/proxy	2.827s
ok  	github.com/Tarekinh0/qindu/internal/policy	0.008s
go vet: CLEAN — zero warnings
```

All 82+ tests pass. Zero vet warnings. The codebase is clean.

---

## 9. Verdict

**VERDICT: PASS**

Both blocking findings from the previous review are resolved:

1. **CS-11-04.1 FIXED** — `parsePath()` now rejects `..` path segments at `patch_tree.go:298-303`, with comprehensive tests including `/../../etc/passwd`.

2. **CS-11-05 FIXED** — All plugin method calls (`MatchPath`, `ExtractText`, `NewSession`) are now wrapped in panic-safe wrappers (`matchPathSafe`, `extractTextSafe`, `newSessionSafe`) with proper fallback behavior and `noOpProviderSession` as a safe sentinel. `HandleSSEEvent` was already wrapped.

All 10 security requirements (CS-11-01 through CS-11-10) now **PASS**. All 12 mandatory security tests (SEC-11-T1 through SEC-11-T12) **PASS**. No regressions detected in the previously passing requirements.

The implementation maintains the privacy proxy model. TLS interception, the interceptor interface, structured logging, and the PII engine are untouched. The provider-agnostic architecture with plugin isolation remains sound.

---

**Report path**: `docs/implementation/sprints/QINDU-0011/ciso-review.md`
**Verdict**: **PASS**
