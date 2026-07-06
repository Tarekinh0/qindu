# QINDU-0022 Peer Review — Debug Flow Inspector

**Date**: 2026-07-06
**Reviewer**: qindu-peer-reviewer
**Reviewed against**: `story.md` AC-1 through AC-10, 4 prior HIGH fixes (PR-001 through PR-004), 7 design frameworks.

---

## Section 1: Scorecard

| Framework | Score | Justification |
|-----------|-------|---------------|
| **Clean Code** | 4/5 | Small functions, meaningful names, DRY across interceptors. Minor: dead `_ = closeErr` in `debug.go`; `FlowHandler` closure allocated per request unnecessarily. |
| **Pragmatic Programmer** | 4/5 | DebugInterceptor wrapping EnforceInterceptor is cleanly orthogonal. Reversible: `flow_inspector: false` = zero overhead. Minor: `isLocalhostRequest` comment mentions X-Forwarded-For but code only inspects RemoteAddr — comment is misleading (though behavior is correct since proxy binds loopback-only). |
| **SOLID** | 5/5 | SRP: `FlowRing` owns buffer lifecycle, `DebugInterceptor` owns recording, `EnforceInterceptor` owns transformation. OCP: `DebugInterceptor` wraps `innerInterceptor` interface without modifying `handleMITM` or `forwardHTTPRoundTrip`. ISP: `innerInterceptor` has exactly 3 methods. DIP: All interceptors depend on `Interceptor` interface. |
| **Go Proverbs** | 4/5 | Errors are values, always wrapped with `%w`. No panics in production paths. Minor: `newBody.Close()` errors silently discarded in `enforce.go:175,344` (in-memory readers, safe in practice). |
| **Effective Go** | 4/5 | Idiomatic camelCase, proper `defer` usage, `gofmt` compliant. Minor: `getCADir()` called without caching in test harness could be memoized; misleading comment in `isLocalhostRequest`. |
| **DDD** | 5/5 | `FlowRing`, `DebugInterceptor`, `FlowHandler` form a clear bounded context. Ubiquitous language: `ingress_body` / `egress_body` matches story vocabulary. `entity_summary` uses domain entity types (`EMAIL`, `PHONE`, etc.), never raw values. |
| **Code Complete** | 4/5 | Strong defensive programming: localhost-only via both bind address validation + defense-in-depth handler check. Config validated at startup. Minor: `sanitizeHostForDispatch` rune-scan is guaranteed constant-time but iterates every rune; `net.SplitHostPort` would be clearer for port stripping. |

---

## Section 2: Critical Findings 🔴

**None.** All four HIGH issues from the previous iteration are resolved:

| Issue | File | Status |
|-------|------|--------|
| **PR-001**: EnforceInterceptor.ShouldProcess nil-plugin returns true | `internal/interceptor/enforce.go:391-394` | ✅ `matchRequestPath` returns `true` when `e.plugin == nil`. DebugInterceptor correctly buffers full-body fallback bodies. Tested in `enforce_test.go:778-822`. |
| **PR-002**: `io.ReadAll` bounded with `maxBodyReadMargin` | `internal/interceptor/enforce.go:111-112, 289-290` | ✅ `io.LimitReader` caps at `maxInputLen + maxBodyReadMargin` (1024). `maxBodyReadMargin` is a well-named constant. Tested in `enforce_test.go:824-867`. |
| **PR-003**: FlowHandler TOCTOU race fixed | `internal/interceptor/debug.go:157-163` | ✅ `EntriesCount` derived from `len(entries)` (snapshot), not from separate `ring.Len()` call. Tested with concurrent reads/writes in `debug_test.go:880-968`. |
| **PR-004**: FlowRing per-entry 64KB cap | `internal/interceptor/debug.go:22, 71-81, 183-188` | ✅ `truncateDebugBody` caps at `maxDebugBodyLen=64KiB` with `[truncated]` suffix. `BodyBytesIn`/`BodyBytesOut` capture pre-truncation sizes. Tested in `debug_test.go:970-1053`. |

---

## Section 3: Design Flaws 🟡

### PR-101 — Dead code: `_ = closeErr` in `DebugInterceptor.InterceptRequest`
- **Category**: Clean Code / Readability
- **File**: `internal/interceptor/debug.go:319, 351`
- **Problem**: The statement `_ = closeErr` inside an `if closeErr := ...` block is a no-op. Go considers `closeErr` used in the `if` condition itself. The `_ = closeErr` adds visual noise with zero effect.
- **Fix**: Remove the `_ = closeErr` line. It compiles and runs correctly without it, and the compiler does not flag `closeErr` as unused since it appears in the condition. If a linter demands it, the linter rule should be adjusted, not the code.

### PR-102 — Misleading comment in `isLocalhostRequest`
- **Category**: Documentation / Correctness
- **File**: `internal/proxy/proxy.go:597`
- **Problem**: The godoc comment says "Checks both the RemoteAddr and the X-Forwarded-For header (for defense in depth)." The function only inspects `r.RemoteAddr`. The X-Forwarded-For header is never read. While the comment describes intended behavior (defense-in-depth), the actual code does not match. This could mislead a future maintainer.
- **Fix**: Either remove the X-Forwarded-For mention from the comment, or add the header check. Given that the proxy binds to `127.0.0.1` exclusively (validated at startup in `config.Validate()`), checking X-Forwarded-For is superfluous — remote connections are impossible. Remove it from the comment.

### PR-103 — Port stripping in `sanitizeHostForDispatch` could use `net.SplitHostPort`
- **Category**: Code Complete / Maintainability
- **File**: `internal/proxy/proxy.go:462-493`
- **Problem**: The manual IPv4/IPv6 bracket-aware port stripping is correct but complex (3 branches, bracket tracking, `strings.Contains` check to avoid stripping brackets from bare IPv6). `net.SplitHostPort` handles all these cases natively and is battle-tested in the standard library.
- **Fix**: Replace the manual port-stripping logic with `net.SplitHostPort`:

```go
func sanitizeHostForDispatch(host string) string {
    if host == "" {
        return ""
    }
    if strings.IndexByte(host, 0) >= 0 {
        return ""
    }
    for _, r := range host {
        if r < 32 || r > 126 {
            return ""
        }
    }
    clean, _, err := net.SplitHostPort(host)
    if err != nil {
        // No port, host is already clean.
        clean = host
    }
    return strings.ToLower(clean)
}
```

### PR-104 — `isLocalhostRequest` vs `net.SplitHostPort` for RemoteAddr
- **Category**: Code Complete / Maintainability
- **File**: `internal/proxy/proxy.go:599-613`
- **Problem**: The manual bracket-stripping logic (`TrimPrefix("[", ...)`, `TrimSuffix("]", ...`) + `LastIndexByte(':')` for port stripping duplicates what `net.SplitHostPort` does.
- **Fix**: Use `net.SplitHostPort` on `r.RemoteAddr`, then `net.ParseIP` on the resulting host.

### PR-105 — `FlowHandler` allocates a closure per request
- **Category**: Pragmatic Programmer / Performance
- **File**: `internal/proxy/proxy.go:590`
- **Problem**: `interceptor.FlowHandler(p.flowRing)(w, r)` calls `FlowHandler` every time `/debug/flow` is requested, creating a new closure. `FlowHandler` returns an `http.HandlerFunc`. Since the ring is already bound to the proxy struct, there's no need to re-create the handler function each time.
- **Fix**: Pre-create the handler in `NewProxy` and store it on the `Proxy` struct (or create it lazily on first access). This is a micro-optimization for a debug-only endpoint (<1 req/s expected), so priority is LOW.

---

## Section 4: Excellence 🟢

### 1. `DebugInterceptor` wrapping design (`internal/interceptor/debug.go:261-384`)
The `DebugInterceptor` wrapping pattern is textbook orthogonality:
- Defines a local `innerInterceptor` interface to avoid circular imports between the `interceptor` and `proxy` packages.
- The `ShouldProcess` guard (line 304-314) prevents sentinel/challenge payloads and telemetry from being buffered in memory — this is critical for the ChatGPT provider where sentinel endpoints contain encrypted payloads that produce false-positive PII detections.
- On inner-interceptor error, the egress body is still recorded as empty (line 338-344), so the operator can see what was attempted even when transformation fails.
- `InterceptResponse` delegates without recording (line 379-381), keeping the scope focused on request transformation per DD-1.
- Compile-time interface check at line 384: `var _ innerInterceptor = (*DebugInterceptor)(nil)`.

### 2. `tokenSummary` entity type filtering (`internal/interceptor/debug.go:190-240`)
The `tokenSummary` function demonstrates careful design:
- Uses a pre-compiled regex (`tokenPatternRegex`) rather than constructing one per call.
- Filters against `knownDebugEntityTypes` (a `map[string]bool`) to reject unknown token types and malformed patterns (`<<UNKNOWN_TYPE_1>>`, `<<INVALID>>`).
- Handles malformed counters gracefully (`strconv.Atoi` returning error → skip).
- Never returns PII values — only entity type → count mappings. This satisfies AC-6 perfectly.
- The `isKnownDebugEntityType` indirection allows future providers to add custom entity types without modifying the regex.

### 3. `enforce_transform` DEBUG log event (`internal/interceptor/enforce.go:183-191, 353-359`)
Both request and response paths emit identically structured `enforce_transform` JSON at DEBUG level:
- Request path: `detected_count`, `entity_summary`, `body_bytes_in`, `body_bytes_out`.
- Response path: `rehydration_count`, `body_bytes_in`, `body_bytes_out`.
- Both include `pii_values_logged: false` — satisfies AC-6.
- The `entity_summary` uses `buildEntitySummary` which creates a `map[string]int` of type counts, zero PII values.
- At default INFO log level, these are invisible — zero production overhead (satisfies DD-5).

### 4. `FlowRing.Snapshot()` independence (`internal/interceptor/debug.go:108-119`)
The snapshot returns a full copy (`make` + `copy`) rather than a slice reference. The test at `debug_test.go:210-244` verifies that mutating the returned snapshot does not leak into the ring buffer's internal state. This is critical for a debug inspector where operators might inspect the JSON and assume it represents the current state.

### 5. Comprehensive concurrency test coverage
The test suite at `debug_test.go:880-968` (`TestFlowHandler_TokenRaceImmunity`) runs 10 concurrent writers (20 writes each) + 50 handler reads simultaneously, asserting:
- JSON is always valid.
- `EntriesCount` never exceeds `BufferSize`.
- `EntriesCount` always equals `len(fr.Entries)`.
- This directly validates the PR-003 TOCTOU fix under aggressive concurrency.

### 6. Config `*bool` pattern consistency (`internal/policy/config.go`)
The `DebugConfig.FlowInspector *bool` with `FlowInspectorValue()` nil-safe accessor follows the established `PIILoggingValue()`, `CertCacheEnabledValue()`, `FailModeValue()` pattern. This is the correct Go idiom for distinguishing "not set" from "explicitly false" in YAML configs, and it's applied consistently across the Config struct (R-024 migration).

### 7. `bodyScanConfig` extensibility (`internal/interceptor/monitor.go:371-397`)
The shared body scanner now accepts `tokenize`, `rehydrate`, and `rewriter` callbacks alongside the existing `extractor`. This allows `EnforceInterceptor` to reuse the same `scanBody` function that `MonitorInterceptor` uses, rather than duplicating the read/detect/log workflow. The callback design is clean: `nil` means "skip this step", which is exactly how monitor mode and enforce mode coexist without branching.

---

## Section 5: Verdict

### **MERGE_READY**

All four HIGH issues from the previous iteration are resolved with supporting tests. The Debug Flow Inspector meets all 10 acceptance criteria. No critical bugs, panics, security holes, or data-loss risks were found. The five design flaws (PR-101 through PR-105) are all cosmetic/minor — none block merge.

**Qindu-specific security checks**:
1. ✅ No PII in logs, errors, or test fixtures (synthetic test data only: `test.user@example.com`, `alice@corp.com`)
2. ✅ No `InsecureSkipVerify` in production paths (only in debug config with explicit opt-in)
3. ✅ Loopback-only bind enforced at config validation + defense-in-depth handler check
4. ✅ N/A — no CA key writes in this sprint
5. ✅ Interceptor interface: bodies streamed through `io.ReadCloser`, no unbounded buffering outside flow inspector (which has explicit 64KB cap per AC-4)
6. ✅ `FlowRing` capped at 50 entries × 2 × 64KB ≈ 6.4MB max memory (bounded, explicit)
7. ✅ No hardcoded secrets, credentials, or keys
8. ✅ Graceful shutdown via `proxy.WaitForShutdown` in `cmd/agent/proxy.go:163`
9. ✅ Config validation at startup in `config.Validate()` — `flow_inspector`, loopback bind, agent.mode, provider domains all validated
10. ✅ No telemetry, analytics, tracking, or phone-home code

**Test Results**: All suites pass with race detector enabled (`go test -race ./...`):
- `internal/interceptor`: 1.7s ✅
- `internal/proxy`: 4.0s ✅
- `internal/policy`: 1.0s ✅
- `internal/vault`: 24.2s ✅
- Full `./...`: all OK, zero failures
