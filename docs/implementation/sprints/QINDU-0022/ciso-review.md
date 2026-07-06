# CISO Security Review — QINDU-0022

**Reviewer**: `qindu-ciso`
**Date**: 2026-07-06
**Sprint**: QINDU-0022 — Debug Flow Inspector
**Mode**: Review Mode (blank-slate: story.md + git diff only)

---

## 1. Attack Surface (New and Modified)

| # | Surface | Type | Exposure |
|---|---------|------|----------|
| S1 | `GET /debug/flow` | New HTTP endpoint | localhost-only (127.0.0.1), gated behind `debug.flow_inspector: true` (default: false) |
| S2 | `FlowRing` in-memory buffer | New memory construct | 50 entries × 2 bodies × 64KB max = ~6.4MB cap; holds cleartext PII |
| S3 | `DebugInterceptor` | New interceptor wrapper | Wraps inner interceptor; reads full request bodies into memory for capture |
| S4 | `EnforceInterceptor` | **New implementation** (was stub returning error) | Tokenizes PII in requests → egress; rehydrates tokens in responses → browser |
| S5 | `EnforceSSEReader` | New streaming reader | SSE frame-by-frame rehydration with 4KB sliding buffer (SR-CISO-4) |
| S6 | `replaceSegments` | New byte-level body modifier | Replaces text segments in body bytes (req + resp path) |
| S7 | `config.debug.flow_inspector` (YAML) | New config knob | `*bool` pointer semantics; nil-safe default `false` |
| S8 | `resolveProviderForHost` + `buildProviderCache` | New domain→provider resolution | Pre-computed cache; suffix matching (longest-domain-first) |
| S9 | `enforce_transform` DEBUG log | New log event | Emitted per transformation; entity types + counts only (no PII values) |
| S10 | `ShouldProcess` on `Interceptor` interface | Interface extension | New method on all interceptors; used for sentinel/challenge body skipping |

---

## 2. Protected Assets

| Asset | Sensitivity | Exposure |
|-------|-------------|----------|
| Cleartext PII in request bodies | **CRITICAL** | Present in `FlowRing` ingress entries when `flow_inspector: true`; otherwise only in memory stack frames during processing |
| Tokenized PII in request bodies | HIGH | Present in `FlowRing` egress entries (tokens only, not values) |
| CA private key | **CRITICAL** | Not directly affected by this sprint |
| Vault (DPAPI-encrypted PII mappings) | **CRITICAL** | Accessed by enforce mode tokenizer; no new exposure surface |
| Per-request tokenizer instance | HIGH | Injected via request context; per-connection isolation (SR-CISO-10) |
| Config (`debug.flow_inspector`) | MEDIUM | Toggles entire debug surface; nil-safe accessor prevents accidental enablement |
| SSE sliding buffer contents | HIGH | Partial token fragments (<<EMAIL_ and such); zeroed on close (SR-CISO-4) |

---

## 3. Threat Model (STRIDE per attack surface)

### S1/S2 — `GET /debug/flow` + FlowRing

| Threat | Rating | Analysis |
|--------|--------|----------|
| **Spoofing** | LOW | No authentication on endpoint; any local process can impersonate a legitimate operator. Mitigated by localhost-only binding (127.0.0.1) + defense-in-depth `isLocalhostRequest()` check. |
| **Tampering** | N/A | Endpoint is read-only GET; no state mutation via handler. |
| **Repudiation** | LOW | No audit trail on `/debug/flow` access — impossible to know who viewed the flow data. Acceptable for dev/debug tool. |
| **Information Disclosure** | **MEDIUM** | `FlowRing` stores cleartext PII in process memory (ingress bodies). A local attacker with privilege escalation could: (a) read the debug endpoint, (b) dump process memory, (c) attach a debugger. Mitigations: flag defaults to `false`; startup WARNING message; `Cache-Control: no-store` on HTTP response; 50-entry/64KB caps; no disk persistence. **Residual risk accepted per DD-3 (DPO).** |
| **Denial of Service** | LOW | 50 entries × 64KB × 2 = ~6.4MB hard cap; no vector for unbounded growth. Concurrent handler reads + interceptor writes under `sync.Mutex` — low-contention by design. |
| **Elevation of Privilege** | LOW | No privilege escalation path; read-only JSON endpoint. |

### S3 — DebugInterceptor

| Threat | Rating | Analysis |
|--------|--------|----------|
| **Information Disclosure** | MEDIUM | Reads full request body into memory for every intercepted request (when `flow_inspector: true`). This includes ALL bodies including those that would otherwise only exist transiently in a streaming pipeline. |
| **Tampering** | LOW | Passes body through unchanged to inner interceptor; no modification in debug layer. Inner interceptor error results in empty-egress FlowRing entry (operator sees failure, no silent corruption). |
| **Denial of Service** | LOW | `ShouldProcess` guard skips sentinel/challenge/telemetry paths before body read — prevents unnecessary buffering of non-conversation payloads. |

### S4/S5/S6 — Enforce mode (full implementation)

| Threat | Rating | Analysis |
|--------|--------|----------|
| **Fatal error → PII passthrough** | **BLOCKED** | Mitigated. Enforce mode is **fail-closed**: missing tokenizer in context → 502; vault creation failure → 502; SID resolution failure → 502. Config validation rejects `enforce + fail_open`. No path exists for PII to leave un-tokenized in enforce mode. **This is the correct security posture.** |
| **Tokenizer context isolation** | LOW | Per-request tokenizer via `context.WithValue` with unexported `tokenizerCtxKey` (SR-CISO-10). No cross-request tokenizer leakage. |
| **SSE token split → PII leak** | LOW | Sliding buffer (4KB cap, SR-CISO-4) reassembles tokens across chunk boundaries. Buffer zeroed on close. Oversize partial tokens flushed as-is with WARN log (no PII values). |
| **Body segment corruption** | LOW | `replaceSegments` validates segment bounds (Start ≥ 0, End > Start, End ≤ len(body)). Right-to-left processing handles length changes safely. |
| **Response rehydration evasion** | LOW | Content-type classification routes SSE to `EnforceSSEReader` (per-frame rehydration), JSON/text to full-body blind rehydration. Binary/unknown content types are passthrough. |

### S7 — Config flag `debug.flow_inspector`

| Threat | Rating | Analysis |
|--------|--------|----------|
| **Misconfiguration (accidental enable in production)** | MEDIUM | Startup WARNING emitted. However, nothing prevents the operator from shipping with `flow_inspector: true`. The YAML field uses `*bool` with nil-safe default `false` — omitting the key entirely disables the feature. **Recommend adding a config validation check that emits an explicit confirmation prompt or refuses startup with `flow_inspector: true` in production-like environments.** Not blocking for V1 dev. |

### S8/S9/S10 — Supporting changes

| Threat | Rating | Analysis |
|--------|--------|----------|
| **Provider resolution injection** | LOW | `resolveProviderForHost` normalizes host, strips port, matches against pre-computed cache. No dynamic host interpretation vulnerability. |
| **Log injection via enforce_transform** | LOW | `enforce_transform` log emits only: `host`, `path`, `detected_count`, `entity_summary` (type→count map), `body_bytes_in`, `body_bytes_out`, `pii_values_logged: false`. No values, no headers, no cookies. **ADR-008 compliant.** |
| **Interface bloat (ShouldProcess)** | LOW | New method added to `Interceptor` interface. All implementations provide it. No security concern — enables sentinel/challenge body skip optimization. |

---

## 4. Blocking Security Requirements

### SR-CISO-22.1 — FlowRing PII Exposure Window
**Status**: ✅ MET — Accepted as residual risk per DD-3.

The following must be in place:
- [x] `debug.flow_inspector` defaults to `false` (nil-safe accessor: `FlowInspectorValue()`)
- [x] 127.0.0.1 binding only (SR4 config validation + defense-in-depth `isLocalhostRequest`)
- [x] No disk persistence (memory-only ring buffer)
- [x] Max 50 entries (FIFO eviction at 51st)
- [x] Max 64KB per body (PR-004 cap)
- [x] Startup WARNING: "FLOW INSPECTOR ENABLED — request bodies held in memory. Disable in production."
- [x] `Cache-Control: no-store` on handler response

### SR-CISO-22.2 — Enforce Mode Fail-Closed
**Status**: ✅ MET

- [x] `enforce + fail_open` rejected at config validation (`Validate()`)
- [x] Missing tokenizer → 502 (not passthrough)
- [x] Vault error → 502 (not passthrough)
- [x] SID resolution failure → 502 (not passthrough)
- [x] `FailModeValue()` defaults to `fail_closed` for enforce mode

### SR-CISO-22.3 — Zero PII in Logs
**Status**: ✅ MET

- [x] `enforce_transform` log: `pii_values_logged: false` on every emit
- [x] `entity_summary` contains type counts only (EMAIL: 1), never values
- [x] `host`, `path`, `method` only — no headers, no query params, no cookies
- [x] No body content in any log message
- [x] EnforceSSEReader sliding buffer content **never** logged

### SR-CISO-22.4 — Tokenizer Context Isolation
**Status**: ✅ MET

- [x] Per-request tokenizer via `tokenize.ContextWithTokenizer`
- [x] Unexported key type (`tokenizerCtxKey struct{}`) — no key collision (SR-CISO-10)
- [x] Context scoped to single HTTP round-trip (`forwardHTTPRoundTrip`)
- [x] `tokenizer.Close()` called explicitly in loop (no defer accumulation)

### SR-CISO-22.5 — Sentinel/Challenge Body Protection
**Status**: ✅ MET

- [x] `ShouldProcess` on all interceptors returns `false` for non-conversation endpoints
- [x] `DebugInterceptor` checks `ShouldProcess` before reading body
- [x] `EnforceInterceptor` path guard skips non-conversation paths before body read
- [x] Sentinel payloads are **never** buffered, scanned, tokenized, or recorded in FlowRing

---

## 5. Mandatory Security Tests

### Existing Tests (Verified Present)

| Test | What it validates | File |
|------|-------------------|------|
| `TestFlowRing_Empty` | Nil snapshot on empty ring | `debug_test.go` |
| `TestFlowRing_SingleEntry` | Correct metadata capture | `debug_test.go` |
| `TestFlowRing_TokenSummary` | Entity type extraction from tokens (no PII values) | `debug_test.go` |
| `TestFlowRing_Eviction` | FIFO eviction at 51st entry | `debug_test.go` |
| `TestFlowRing_Concurrency` | No data races under concurrent read/write | `debug_test.go` |
| `TestFlowRing_SnapshotIsCopy` | Snapshot isolation (no aliasing) | `debug_test.go` |
| `TestFlowRing_Record_TruncatesOversizeBody` | PR-004 body size cap; original sizes preserved | `debug_test.go` |
| `TestDebugInterceptor_SentinelNotRecorded` | Sentinel/challenge NOT in FlowRing | `debug_test.go` |
| `TestDebugInterceptor_ConversationRecorded` | Conversation body IS in FlowRing | `debug_test.go` |
| `TestDebugInterceptor_SentinelThenConversation` | Mixed sequence correctness | `debug_test.go` |
| `TestFlowHandler_EmptyRing` | 200 + valid JSON on empty buffer | `debug_test.go` |
| `TestFlowHandler_CacheHeaders` | `Cache-Control: no-store` | `debug_test.go` |
| `TestFlowHandler_EntriesCountFromSnapshot` | PR-003 TOCTOU fix | `debug_test.go` |
| `TestFlowHandler_TokenRaceImmunity` | No inconsistent JSON under concurrency | `debug_test.go` |
| `TestTokenSummary_MalformedTokensIgnored` | Malformed tokens filtered from entity_summary | `debug_test.go` |
| `TestTokenSummary_AllKnownTypes` | All 8 entity types recognized | `debug_test.go` |
| `TestBuildEnforceRegistry` | Registry construction, normalization, skipping disabled/unknown | `proxy_test.go` |
| `TestResolveProviderForHost` | Suffix match, exact match, port stripping, case insensitivity | `proxy_test.go` |
| `TestBuildProviderCache` | Cache correctness, disabled exclusion, sort order | `proxy_test.go` |
| `TestNewProxy_EnforceModeFatal` → now `TestNewProxy_EnforceModeSucceeds` | Enforce mode no longer returns error | `proxy_test.go` |

### Recommended Additional Tests (Non-Blocking)

| ID | Test | Priority | Rationale |
|----|------|----------|-----------|
| ST-1 | `TestIsLocalhostRequest_IPv6Loopback` | LOW | Verify `::1` is recognized as loopback; currently only IPv4 tested implicitly |
| ST-2 | `TestIsLocalhostRequest_XForwardedFor` | LOW | Verify X-Forwarded-For header is handled correctly (current code checks RemoteAddr only) |
| ST-3 | `TestFlowHandler_ConcurrentReadDuringWrite` | LOW | Stress-test handler reads during rapid ring buffer writes (different from existing test which tests SharedProcessor across goroutines reading the handler) |
| ST-4 | `TestEnforceTransformer_PIIInRequestBody_DoesNotLeakToLogs` | MEDIUM | Integration test: send request with real-looking PII, verify zero PII values in structured log output |
| ST-5 | `TestDebugFlow_DisabledByDefault` | LOW | Integration test: verify `/debug/flow` returns 404 when `flow_inspector` is unset or false |

---

## 6. Residual Risks

| ID | Risk | Severity | Accepted By | Mitigation |
|----|------|----------|-------------|------------|
| R-DEBUG-1 | Cleartext PII in FlowRing process memory | **MEDIUM** | DPO (DD-3) | Flag defaults to false; localhost-only; memory-only; 50-entry/64KB caps; startup WARNING; `Cache-Control: no-store`. A memory dump of the proxy process while `flow_inspector: true` would expose up to 50 request bodies. |
| R-DEBUG-2 | No access audit on `/debug/flow` | LOW | CISO | No authentication, no TLS, no access logging on the debug endpoint. Any local process can query it. The proxy binds to 127.0.0.1 per SR4 — defense-in-depth `isLocalhostRequest()` adds a second layer. |
| R-DEBUG-3 | Debug marker visible in process listing | LOW | CISO | The presence of `/debug/flow` on port 8787 signals to a local attacker that the proxy has PII-bearing request bodies in memory. A stealthier design (e.g., requiring a debug token in a header) would reduce this signal. Not blocking for V1. |
| R-DEBUG-4 | FlowRing mutex contention under extreme load | LOW | CISO | `sync.Mutex` (not `RWMutex`) means handler reads block interceptor writes and vice versa. Under heavy concurrent `/debug/flow` polling + high request rate, latency may increase. Caps prevent unbounded growth. |

---

## 7. ADR Compliance

| ADR | Requirement | Status |
|-----|-------------|--------|
| ADR-004 | `Interceptor` interface extension (`ShouldProcess`) | ✅ Non-breaking addition; all implementations provide it |
| ADR-008 | `pii_values_logged: false` in all security-sensitive logs | ✅ Enforced in all `enforce_transform`, `monitor_scan`, error logs |
| ADR-008 | Structured JSON logging | ✅ All new log calls use `slog` with key-value pairs |
| ADR-008 | No PII values in log messages | ✅ Entity types only; no body content in logs |

---

## 8. Verdict

### **PASS** ✅

The implementation satisfies all acceptance criteria (AC-1 through AC-10) and meets the security requirements established in the story. The enforce mode implementation (which was delivered alongside the debug flow inspector) is well-architected with fail-closed defaults, proper tokenizer context isolation, and comprehensive path guards for sentinel/challenge endpoints.

**Three findings to address in future sprints:**

1. **R-DEBUG-1 (MEDIUM)** — Cleartext PII in FlowRing memory. This is accepted per DD-3 but should be tracked in the risk register. A future DPO sprint could explore encryption-at-rest for the ring buffer (e.g., encrypting each entry with an ephemeral key held in memory), though the threat model is limited to local memory dump attacks.

2. **ST-4 (MEDIUM)** — Add an integration test that verifies zero PII values appear in logs when processing a request containing real-looking PII. This would provide regression protection against accidental PII leakage in log messages.

3. **ST-2 (LOW)** — The `isLocalhostRequest` function checks `r.RemoteAddr` but the comment mentions X-Forwarded-For — which is not actually checked in the current implementation. Either remove the misleading comment or implement X-Forwarded-For validation.

---

## 9. Commit Status Note

The following implementation files exist in the working tree but are **untracked** (not committed to `HEAD`):

```
internal/interceptor/debug.go
internal/interceptor/debug_test.go
internal/interceptor/enforce.go
internal/interceptor/enforce_sse.go
internal/interceptor/enforce_test.go
internal/interceptor/enforce_sse_test.go
internal/interceptor/enforce_integration_test.go
internal/interceptor/segments.go
internal/interceptor/segments_test.go
```

These files must be committed before the sprint can be considered complete. The committed diff (`HEAD~1..HEAD`) contains proxy/config changes that reference types and functions defined in these untracked files — the build currently succeeds only because these files are present in the working tree.

---
*End of CISO review for QINDU-0022.*
