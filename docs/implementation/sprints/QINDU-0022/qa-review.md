# QA Review — QINDU-0022: Debug Flow Inspector

**Date**: 2026-07-06  
**Reviewer**: qindu-qa  
**Verdict**: **BLOCKED**

---

## Test Execution Summary

| Command | Result |
|---------|--------|
| `go vet ./...` | PASS (clean, zero warnings) |
| `go test ./... -count=1` | PASS (12/12 packages) |
| `go test -race ./internal/interceptor/...` | PASS (no data races) |
| `go test -race ./internal/proxy/...` | PASS (no data races) |

All existing tests pass cleanly with and without the race detector.

---

## Acceptance Criteria Coverage

| AC | Description | Test Coverage | Status |
|----|-------------|---------------|--------|
| AC-1 | `debug.flow_inspector: false` → no endpoint, no ring buffer, zero overhead | Code path exists (proxy.go:82–87), but **no explicit test** verifies this behavior at the proxy level. | **GAP** |
| AC-2 | `debug.flow_inspector: true` → `/debug/flow` on 127.0.0.1 only | FlowHandler tests exist. However, `isLocalhostRequest()` is **untested** — no test verifies non-localhost rejection (403). | **GAP** |
| AC-3 | Ring buffer captures ingress/egress for 50 entries | `TestFlowRing_MultipleEntries`, `TestDebugInterceptor_PassThrough`, `TestDebugInterceptor_CapturesTransformation` | PASS |
| AC-4 | FIFO eviction at 51st entry | `TestFlowRing_Eviction` (writes 60, verifies oldest 10 evicted, IDs correct) | PASS |
| AC-5 | `enforce_transform` log at DEBUG level | Emitted in `InterceptRequest` (enforce.go:183) and `InterceptResponse` (enforce.go:353). Tests check string presence. | PASS |
| AC-6 | `pii_values_logged: false` on log | Field is hardcoded `false` in all enforce_transform log calls. Tests verify string presence. | PASS |
| AC-7 | WARNING at startup when enabled | Logged at proxy.go:87. **No test** verifies this WARNING is emitted. | **GAP** |
| AC-8 | No disk persistence — buffer cleared on restart | FlowRing is in-memory only (no disk I/O). Redesign guarantees this by construction. | PASS |
| AC-9 | Tests: ring buffer, DebugInterceptor, handler HTTP (localhost only, JSON valid) | Ring buffer and DebugInterceptor tests are thorough. FlowHandler JSON validity tested. **localhost-only guard untested.** | **PARTIAL** |
| AC-10 | Zero regression: all existing tests pass | Confirmed: `go test ./...` clean, `go vet` clean. | PASS |

---

## Findings

### F1 — `isLocalhostRequest()` has zero test coverage (BLOCKING)

**Impact**: AC-2, AC-9  
**Location**: `internal/proxy/proxy.go` (lines ~531–549)

The `isLocalhostRequest` function is the defense-in-depth gate that rejects non-localhost requests to `/debug/flow` with HTTP 403. It parses `RemoteAddr`, handles port stripping, IPv6 bracket notation, and delegates to `net.IP.IsLoopback()`. This function has **no unit tests**.

Risks:
- A regression in port-stripping logic could allow non-loopback connections
- IPv6 parsing edge cases (e.g., `::1%lo`) are unverified
- The 403 rejection path is never exercised in tests

**Required**: Add `TestIsLocalhostRequest` with cases for: IPv4 loopback (`127.0.0.1`, `127.0.0.1:port`), IPv6 loopback (`::1`, `[::1]:port`), non-loopback (`192.168.1.1`, `10.0.0.1`), malformed input, empty string.

---

### F2 — `countTokenPatterns()` has zero test coverage (BLOCKING)

**Impact**: AC-5, AC-6  
**Location**: `internal/interceptor/monitor.go` (lines ~650–667)

This function computes `rehydration_count` for the `enforce_transform` log in non-streaming response paths. It uses `looksLikeToken` for validation. With no tests:

- False positives/negatives in token counting go undetected
- Malformed token patterns (`<<>>`, `<<EMAIL_>>`, `<< >>`) are not tested
- Boundary conditions (token at string start/end, overlapping patterns) are not verified
- Single-char tokens (minimal valid token like `<<A_1>>`) not tested

**Required**: Add `TestCountTokenPatterns` with cases: single token, multiple tokens, no tokens, malformed tokens (`<<>>`, `<<EMAIL_>>`, `<<_1>>`), overlapping false matches, token at byte 0, token at end of string.

---

### F3 — No proxy-level test for `debug.flow_inspector` flag gating (BLOCKING)

**Impact**: AC-1  
**Location**: `internal/proxy/proxy_test.go`

The code correctly gates FlowRing creation and `/debug/flow` endpoint on `debug.flow_inspector: true`. However, no test verifies that:

1. When `debug.flow_inspector: false` (default), `NewProxy` produces a proxy with `flowRing == nil`
2. When `debug.flow_inspector: true`, `NewProxy` produces a proxy with `flowRing != nil`
3. The `/debug/flow` endpoint returns 404 when `flowRing` is nil

**Required**: Add `TestNewProxy_FlowInspectorDisabled` and `TestNewProxy_FlowInspectorEnabled` using `DefaultConfig()` with the debug flag toggled.

---

### F4 — No test for AC-7 WARNING at startup (LOW)

**Impact**: AC-7  
**Location**: `internal/proxy/proxy.go:87`

The WARNING `"FLOW INSPECTOR ENABLED — request bodies held in memory. Disable in production."` is emitted at startup when `flow_inspector: true`. No test captures the log output and verifies this exact message.

**Required**: Capture logger output in a proxy creation test with `flow_inspector: true` and verify the WARNING string is present.

---

### F5 — Enforce transform log verification is shallow (LOW)

**Impact**: AC-5, AC-6  
**Location**: `internal/interceptor/enforce_test.go`

Current tests verify log fields by `strings.Contains(logOutput, "enforce_transform")` rather than parsing the JSON log and asserting specific field values. Risks:

- `detected_count` correctness never verified by tests
- `entity_summary` values never checked against actual detections
- `body_bytes_in` / `body_bytes_out` values never cross-referenced
- `rehydration_count` correctness not verified

**Recommended**: Add a test helper that parses the JSON log output and asserts specific field values (at minimum: `pii_values_logged: false`, `detected_count > 0`, `entity_summary` keys match expected types).

---

### F6 — Test fixtures use French mobile number `+33612345678` (LOW)

**Impact**: Compliance  
**Location**: Multiple test files

While `+33612345678` appears to be a synthetic sequential number, the `+336` prefix is assigned to French mobile operators. Using obviously reserved test numbers (e.g., `+33699999999` or `+33012345678` which is not allocated) would remove any residual risk.

**Recommended**: Replace `+33612345678` with `+33699999999` (unallocated French range) or use `+1-555-0100` patterns consistently.

---

## Test Quality Assessment

### Strengths

- **Ring buffer tests are excellent**: concurrency with writers + readers, snapshot independence verification, TOCTOU race immunity test with 200 concurrent operations
- **DebugInterceptor path filtering**: comprehensive sentinel-not-recorded / conversation-recorded / mixed-sequence tests
- **Body truncation tests**: under-limit, at-limit, over-limit with suffix verification, original byte count preservation
- **Enforce interceptor tests**: tokenization, rehydration, content-length recalc, fail-closed, path guards, body pre-read capping
- **Regex validation**: `tokenPatternRegex` compiled and verified by explicit tests
- **Race-free**: all tests pass with `-race` flag
- **No real PII in fixtures**: emails use `example.com` (IANA reserved), phone numbers are synthetic, credit cards use test numbers

### Weaknesses

- Missing proxy-level integration tests for the debug flow inspector
- Two untested functions (`isLocalhostRequest`, `countTokenPatterns`)
- Shallow log verification (string presence vs JSON field assertions)

---

## Edge Cases Verified

| Edge Case | Test | Status |
|-----------|------|--------|
| Empty ring buffer → nil snapshot | `TestFlowRing_Empty` | PASS |
| Ring buffer eviction at capacity | `TestFlowRing_Eviction` | PASS |
| Concurrent writes + reads | `TestFlowRing_Concurrency`, `TestFlowHandler_TokenRaceImmunity` | PASS |
| Snapshot independence (no aliasing) | `TestFlowRing_SnapshotIsCopy` | PASS |
| DebugInterceptor with nil body | `TestDebugInterceptor_NilBody` | PASS |
| DebugInterceptor with inner error | `TestDebugInterceptor_InnerErrorRecordsEmptyEgress` | PASS |
| Sentinel path not recorded | `TestDebugInterceptor_SentinelNotRecorded` | PASS |
| Conversation path recorded | `TestDebugInterceptor_ConversationRecorded` | PASS |
| JSON special characters round-trip | `TestFlowHandler_JSONValidity` | PASS |
| Cache-Control headers (no-store, no-cache) | `TestFlowHandler_CacheHeaders` | PASS |
| Oversize body truncation | `TestTruncateDebugBody_OverLimit`, `TestFlowRing_Record_TruncatesOversizeBody` | PASS |
| Tokenizer missing from context (fail-closed) | `TestEnforceInterceptor_MissingTokenizerFailClosed` | PASS |
| Content-Length recalc after tokenization | `TestEnforceInterceptor_ContentLengthUpdatedAfterTokenization` | PASS |
| Content-Length recalc after rehydration | `TestEnforceInterceptor_ResponseContentLengthUpdatedAfterRehydration` | PASS |
| Body pre-read capping (PR-002) | `TestEnforceInterceptor_BodyPreReadCap` | PASS |
| Empty body passthrough | `TestEnforceInterceptor_EmptyBody`, `TestEnforceInterceptor_NilBodyPassthrough` | PASS |

---

## Missed Edge Cases

| Missing Test | Rationale |
|--------------|-----------|
| `isLocalhostRequest` with IPv4, IPv6, non-loopback, malformed | AC-2/AC-9 security boundary |
| `countTokenPatterns` with empty, single, multiple, malformed tokens | AC-5 rehydration_count correctness |
| Proxy creation with `flow_inspector: false` → nil flowRing | AC-1 verification |
| Proxy startup WARNING when `flow_inspector: true` | AC-7 verification |
| `/debug/flow` returns 403 for non-localhost | AC-2 defense-in-depth |
| Large number of rapid writes only slightly exceeding buffer capacity (stress) | Edge case near eviction boundary |

---

## Verdict

**BLOCKED** — Three blocking findings (F1, F2, F3) must be addressed before this sprint can pass QA.

### Required fixes for unblocking

1. **F1**: Add `TestIsLocalhostRequest` unit test covering loopback/non-loopback/IPv6/malformed
2. **F2**: Add `TestCountTokenPatterns` unit test covering valid tokens, malformed tokens, edge cases
3. **F3**: Add proxy-level tests verifying `flow_inspector: false` → nil ring/no endpoint; `flow_inspector: true` → ring allocated/endpoint active

### Recommended (not blocking)

4. **F4**: Add startup WARNING verification test
5. **F5**: Add JSON log field assertions for `enforce_transform` events
6. **F6**: Replace `+33612345678` with an explicitly reserved test number
