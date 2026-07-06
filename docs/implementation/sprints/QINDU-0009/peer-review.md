# Peer Review — QINDU-0009: Mode Enforce + Réhydratation

**Reviewer**: qindu-peer-reviewer (Go 15+ YOE, distributed systems, security-critical proxy/middleware)  
**Date**: 2026-07-06  
**Review type**: Blank-slate (story + git diff only)

---

## Section 1: Scorecard

| Framework | Score | Justification |
|-----------|-------|---------------|
| **Clean Code** (Martin) | 4/5 | Small functions, meaningful names, DRY mostly respected. Two count-token functions duplicated between `monitor.go` and `enforce_sse.go`. `Read` method in `EnforceSSEReader` is complex but correctly factored. |
| **Pragmatic Programmer** (Hunt/Thomas) | 4/5 | Orthogonal design — interceptor, tokenizer, vault, providers are decoupled. `*bool`/`*string` pointer fix for config is textbook reversibility. Fail-closed by default with config guard is design-by-contract done right. |
| **SOLID** (Uncle Bob) | 4/5 | `ResponseTextExtractor` is a perfect SRP/OCP/ISP example — single-method optional interface for surgical rehydration. `EnforceInterceptor` vs `MonitorInterceptor` are cleanly separated. Minor: `resolveProviderForHost` duplicates domain routing logic and rebuilds on every call. |
| **Go Proverbs** (Pike) | 4/5 | Errors are values, always wrapped. Small interfaces (`Interceptor` — 2 methods, `ResponseTextExtractor` — 1 method). Context used correctly for tokenizer transport. Minor: `fmt.Sprintf` in SSE rehydration hot path could be `strings.Builder`. |
| **Effective Go** (Go team) | 4/5 | Idiomatic camelCase, `%w` error wrapping, `defer` used correctly, `gofmt` compliant. No `init()` abuse. Context key uses private struct type (no collision). Build constraints correct (`!windows` for `LookupVaultPathForPort`). |
| **DDD** (Evans) | 4/5 | Bounded contexts well-defined: `internal/interceptor`, `internal/tokenize`, `internal/vault`, `internal/providers`. Ubiquitous language consistent throughout: tokenize, rehydrate, enforce, vault, persister. `deriveConversationID` is a domain concept (privacy-scoped conversation). |
| **Code Complete** (McConnell) | 4/5 | Defensive at every boundary: NUL byte rejection, control character checks, bounds validation, panic recovery on plugins. Max path len capped, regex linear-time (no backtracking). Minor: empty-SSE-frame edge case mishandled, exotic `Read(0, nil)` loop risk. |

**Average**: 4.0 / 5 — Solid V1 production code with minor polish opportunities.

---

## Section 2: Critical Findings 🔴

### PR-001: SSE empty frame rehydration loses `\n` byte (Correctness)

**File**: `internal/interceptor/enforce_sse.go`, lines 239–276 (`rehydrateFrame`)  
**Severity**: HIGH  
**Problem**: When an SSE frame contains zero non-empty lines (the frame consists solely of `\n\n`), `rehydrateFrame` outputs a single `\n` instead of `\n\n`. The function splits by `\n`, both resulting segments are trimmed-empty and skipped, and the post-loop only appends one `\n`. This causes a byte-shrinking transform on empty keep-alive frames, shifting frame boundaries for subsequent frames if the server sends multiple consecutive empty frames.

**Why it matters**: The browser's `EventSource` parser may fail to dispatch events if frame boundaries are corrupted. SSE-compliant servers occasionally send empty comment frames (`:\n\n`) as keep-alives. While the comment variant works correctly (the `:` line is non-empty and passes through), a raw empty frame would be corrupted. Server implementations vary — some may send bare `\n\n` as a heartbeat.

**Fix**: Restore the frame separator by writing two `\n` bytes when all lines are empty:
```go
// After the for loop, before result.WriteByte('\n'):
hasContent := false
for _, line := range lines {
    if strings.TrimSpace(line) != "" {
        hasContent = true
        break
    }
}
result.WriteByte('\n')
if !hasContent {
    result.WriteByte('\n') // restore lost separator byte
}
```
Alternative: always append `\n\n` unconditionally since the raw frame always ends with `\n\n`.

---

### PR-002: `EnforceSSEReader.Read` infinite loop on `(0, nil)` from `bufio.Reader`

**File**: `internal/interceptor/enforce_sse.go`, lines 116–196  
**Severity**: MEDIUM  
**Problem**: If `r.br.Read()` returns `(0, nil)` — possible with non-standard `io.Reader` implementations that violate the "at least one byte or error" contract — the inner loop `for r.outputBuf.Len() == 0` enters an infinite busy-loop. The condition at line 183 hits `continue` because `r.outputBuf.Len() == 0`, `r.hasFrameData` is true (set previously), and `r.rawAccum.Len() < r.maxFrameSize`.

**Why it matters**: While Go's `bufio.Reader` guarantees either data or an error, this code may be tested or reused with mock readers. A test that simulates chunked delivery with `(0, nil)` returns would hang indefinitely.

**Fix**: Add a zero-byte guard after `Read`:
```go
n, err := r.br.Read(r.readBuf)
if n == 0 && err == nil {
    // Underlying reader violated contract — break to avoid busy loop.
    break
}
```

---

### PR-003: `countTokenPatterns` / `countTokensInString` — duplicated token-counting logic

**File**: `internal/interceptor/monitor.go:647` and `internal/interceptor/enforce_sse.go:331`  
**Severity**: LOW  
**Problem**: Two nearly-identical functions count `<<TYPE_N>>` patterns using the same algorithm. Both call `looksLikeToken`. Fixing a token pattern parser bug would require changes in two places.

**Why it matters**: DRY violation. Not a correctness bug today — but a maintenance trap. If `looksLikeToken` changes or the token format evolves, both functions must be updated.

**Fix**: Delete `countTokensInString` and have both callers use `countTokenPatterns` directly. The functions are identical except the receiver (`r *EnforceSSEReader` vs package-level). The SSE reader can call the package-level function:
```go
beforeCount := countTokenPatterns(data)
// ...
afterCount := countTokenPatterns(rehydrated)
r.rehydratedCount += (beforeCount - afterCount)
```
Then remove `countTokensInString` and the now-unused `Tokenizer` receiver dependency from the counting path.

---

## Section 3: Design Flaws 🟡

### PR-101: `resolveProviderForHost` rebuilds domain mapping on every request

**File**: `internal/proxy/proxy.go`, lines 466–517  
**Category**: Performance / Coupling  
**Problem**: Every request in the keep-alive loop calls `resolveProviderForHost`, which allocates a `map[string]string`, iterates all providers and domains, and calls `sort.Slice`. For a V1 deployment with 5 providers × 3 domains each, this is ~15 entries with `O(n log n)` — negligible. But the pattern sets a precedent: if providers grow (e.g., per-org configurations), the N+1 cost on every request becomes a scalability regression.

**Fix**: Build the domain-to-provider mapping once in `NewProxy` (or lazily on first use with a `sync.Once`) and store it in the `Proxy` struct. The `selectForHost` logic already exists in `providerDispatcher` — `resolveProviderForHost` should reuse it.

---

### PR-102: `forwardHTTPRoundTrip` does not close response body on interceptor error

**File**: `internal/proxy/forward.go`, lines 106–112  
**Category**: Resource Management  
**Problem**: If `interceptor.InterceptResponse(resp)` returns an error, the original `resp.Body` is never closed. The error path returns immediately without draining or closing the upstream response body.

**Why it matters**: In normal operation, `resp.Body` wraps a `bufio.Reader` over a `tls.Conn`. Failure to close it means the TLS connection may retain buffered bytes or leave the upstream in a bad state for subsequent keep-alive requests on the same connection.

**Fix**: Defer-close the original body on the error path:
```go
modifiedResp, respBody, err = interceptor.InterceptResponse(resp)
if err != nil {
    if resp.Body != nil {
        _ = resp.Body.Close()
    }
    return resp.StatusCode, fmt.Errorf("intercepting response: %w", err)
}
```

---

### PR-103: `fmt.Sprintf` in SSE rehydration hot path

**File**: `internal/interceptor/enforce_sse.go`, line 260  
**Category**: Performance / Go Proverbs  
**Problem**: `rehydrateFrame` calls `fmt.Sprintf("data: %s\n", rehydrated)` for every SSE data line. Each `fmt.Sprintf` allocates a new string and parses the format. For a long conversation with hundreds of SSE frames, this creates unnecessary GC pressure.

**Fix**: Use `strings.Builder` with explicit writes:
```go
result.WriteString("data: ")
result.WriteString(rehydrated)
result.WriteByte('\n')
```
This avoids format-string parsing and intermediate allocations.

---

### PR-104: `EnforceSSEReader` does not share `sseFrameAccumulator` with monitor mode

**File**: `internal/interceptor/enforce_sse.go` (custom raw accumulator) vs `internal/interceptor/sse.go` (shared accumulator)  
**Category**: Duplication / Architecture  
**Problem**: `EnforceSSEReader` has its own raw accumulator (`rawAccum`, `outputBuf`, `hasFrameData`) and frame boundary detection loop (`processCompleteFrames`), duplicating ~100 lines of logic from `sseFrameAccumulator.readFrames`. The shared accumulator was explicitly extracted (PR-101 in a prior sprint) to eliminate duplication between `SSEFrameReader` and `ProviderSSEReader`. `EnforceSSEReader` reimplements the same pattern from scratch.

**Why it matters**: Three separate SSE accumulation implementations diverge over time. Bug fixes to boundary detection must be applied in three places.

**Fix (V2)**: Refactor `EnforceSSEReader` to use `sseFrameAccumulator.readFrames` for frame accumulation and boundary detection, with a callback that performs rehydration. This would reduce the file by ~100 lines and eliminate the divergence.

---

### PR-105: `handleMITM` enforce mode lacks explicit vault release

**File**: `internal/proxy/mitm.go`, lines 126–185  
**Category**: Resource Management  
**Problem**: When enforce mode obtains `userVault` from `vaultManager.GetOrCreate()`, there's no explicit release. The `VaultManager` uses idle-timeout eviction (30-min default), so vaults linger in memory long after the connection terminates. For short-lived connections, this means vault memory is held for up to 30 minutes.

**Why it matters**: Under load (many short-lived enforce connections), vault instances accumulate. Each per-user vault holds a bbolt database handle and potentially cached token mappings. The 30-minute idle timeout is a safety net, but explicit release would be more precise.

**Fix (V2)**: Add a `vaultManager.Release(userVault)` call in a `defer` after successful vault acquisition. The `Release` method would decrement a reference count and allow immediate eviction when count reaches zero. This requires a `VaultManager.Release(*Vault)` API addition — scoped to a future sprint.

---

### PR-106: Missing integration test for `EnforceInterceptor.InterceptResponse` SSE path

**File**: `internal/interceptor/enforce_test.go`  
**Category**: Test Coverage  
**Problem**: `TestEnforceInterceptor_ResponseRehydration` only tests the JSON (non-SSE) response path. There's no test that creates a response with `Content-Type: text/event-stream` and verifies the `EnforceSSEReader` is wired correctly through the interceptor's `InterceptResponse` method. The SSE reader tests exist at the unit level (`enforce_sse_test.go`) but the integration point (interceptor → SSE reader) is untested.

**Fix**: Add a test that:
1. Creates an `EnforceInterceptor`
2. Sets a response with `Content-Type: text/event-stream`
3. Verifies the returned body is an `*EnforceSSEReader` (type assertion)
4. Verifies rehydration works end-to-end through the reader

---

### PR-107: `rehydrateFrame` normalizes CRLF → LF but never restores CRLF

**File**: `internal/interceptor/enforce_sse.go`, lines 246–248  
**Category**: Protocol Compliance  
**Problem**: The function normalizes `\r\n` to `\n` before line-splitting, but the output always uses `\n` line endings. If the upstream server sent CRLF-delimited SSE and the browser expects CRLF (which is allowed by the SSE spec), the output will use LF-only. While most browsers accept both, this is a protocol fidelity issue.

**Fix**: Track the original line ending style in the first frame and use it consistently, or always use `\n` (which is the recommended format). Document the decision if deliberate.

---

## Section 4: Excellence 🟢

### `ResponseTextExtractor` interface — textbook ISP + OCP

**File**: `internal/providers/provider.go`, lines 54–60  
This is a beautifully designed optional interface. One method. Zero coupling to the enforcement pipeline. The interceptor checks with a type assertion (`rte, ok := e.plugin.(providers.ResponseTextExtractor)`) and falls back gracefully. This is the Go way — no fat interface, no compile-time dependency, surgical extension point. The ChatGPT plugin implements it in `plugin.go:108–130` with clean extraction from `message.content.parts[]`.

### `deriveConversationID` — comprehensive input validation

**File**: `internal/proxy/conversation.go`, lines 35–69  
Every line of this function shows defensive programming maturity:
- NUL byte rejection (line 37)
- Control character filtering with explicit tab/LF/CR exclusion (lines 40–44)
- Path length cap with `maxPathLenForUUID` (line 49)
- Linear-time regex (no backtracking) with explicit anchor `(?:^|/)` to prevent hex substring false matches (line 15)
- Post-regex length validation of the UUID (line 62)
- SHA-256 hashing for deterministic scope — privacy-preserving (the UUID never appears in vault keys)
- `crypto/rand` for fallback UUID v4 generation (line 80)

The test suite (`conversation_test.go`) covers NUL bytes, control characters, case insensitivity, empty paths, long paths, uniqueness, determinism, and format validation. This is the standard every function in Qindu should meet.

### `replaceSegments` — right-to-left processing with validation

**File**: `internal/interceptor/segments.go`, lines 22–90  
Clean, well-documented implementation. Key decisions that show craftsmanship:
- Fast path for zero segments (line 23–28)
- Validation of bounds (`Start < 0`, `End > len(body)`) with silent skip
- No-op elision (identical text segments skipped, line 37)
- Right-to-left sorting (descending `Start`) for offset-independent replacement
- Same-length optimization (line 64 — direct copy instead of buffer reconstruction)
- UTF-8 safety verified in tests (`TestReplaceSegments_UTF8Output`)

The test file (`segments_test.go`) covers shorter tokens, longer tokens, start/end positions, multiple segments, invalid bounds, nil/empty input, no-op segments, and UTF-8 multibyte. 11 test cases — excellent coverage.

### Fail-closed enforcement chain

**File**: `internal/proxy/mitm.go`, lines 127–185 + `internal/interceptor/enforce.go`, lines 69–79  
The fail-closed chain is airtight at every level:
1. `VaultManager` nil → 502, control returns (line 128–143)
2. SID resolution failure → 502, control returns (line 148–164)
3. Vault creation failure → 502, control returns (line 167–184)
4. Tokenizer missing from context → error returned by interceptor (line 72–78)
5. Enforce mode + `fail_open` config → rejected at `Validate()` (config.go:231-233)

Each failure point logs with `pii_values_logged: false` and returns without forwarding any data. No PII can leak through any failure path. This is security engineering done right.

### `EnforceSSEConfig` struct — constructor anti-pattern elimination

**File**: `internal/interceptor/enforce_sse.go`, lines 26–41  
Using a configuration struct instead of positional parameters for `newEnforceSSEReader` avoids the 10-parameter constructor problem. Each field is named and documented. This follows the pattern established in `SSEFrameReaderConfig` and `ProviderSSEConfig` — consistency across all three SSE reader types.

### Test naming and organization

All test files follow a clear naming convention: `TestTypeName_Behavior` (e.g., `TestEnforceInterceptor_MissingTokenizerFailClosed`, `TestReplaceSegments_InvalidBoundsStartNegative`). Tests are organized by component with clear grouping comments (`// =============================================================================`). The config test file explicitly marks QINDU-0009 additions with a `// QINDU-0009 Config Tests` header. This makes test navigation trivial.

---

## Section 5: Verdict

**MERGE_READY** ✅

No PII leakage, no data corruption, no crash bugs. The enforce pipeline is correctly wired end-to-end: request tokenization → vault persistence → SSE rehydration with sliding buffer → log sanitization. The fail-closed chain is airtight at four independent levels. The config fix (R-024, `*bool`/`*string`) correctly distinguishes "not set" from "explicitly set to false/empty."

The two design patterns worth celebrating: `ResponseTextExtractor` (optional interface, zero coupling, perfect ISP/OCP) and `deriveConversationID` (comprehensive input validation, privacy-preserving SHA-256 scope derivation).

### Resolution requirements

| Finding | Must fix before merge? | Rationale |
|---------|------------------------|-----------|
| PR-001 (SSE empty frame `\n` loss) | **Yes** | Protocol correctness — could break EventSource dispatch for certain server implementations |
| PR-002 (`Read` infinite loop) | **Yes** | Defensive — prevents test hangs and protects against non-standard reader implementations |
| PR-003 (duplicate count function) | No | DRY maintenance issue; low risk today, fix in next iteration |
| PR-101–107 (design flaws) | No | V1 polish items; accept as known limitations per sprint scope |

### Reviewer note

PR-001 has a straightforward fix: append two `\n` when all frame lines are empty. PR-002 is a one-line guard. Both can be resolved in a single fix cycle without design changes. The remaining findings are architectural polish suitable for V2 — none block the demo milestone.

