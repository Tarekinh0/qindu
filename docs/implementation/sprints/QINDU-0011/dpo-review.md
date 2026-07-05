# DPO Review — QINDU-0011 (Re-verification after refactoring)

- **Sprint**: QINDU-0011 — Adapter ChatGPT web + Infrastructure Provider-Agnostique
- **DPO Re-Review Date**: 2026-07-05
- **Reviewer**: DPO (qindu-dpo)
- **Basis**: Re-verification after post-PR shared body-scanner extraction (`scanBody`), shared SSE frame accumulator (`sseFrameAccumulator`), panic recovery on all plugin calls, `..` rejection in path parsing, and `ProvidersConfig.Validate()` addition.
- **Files Reviewed**: All changed files from `git diff` plus all QINDU-0011 provider/interceptor source files.

---

## Scope of Changes Since Original Review

This is a **re-verification** triggered by significant refactoring:

| Change | Files Affected |
|--------|---------------|
| **Shared body-scanner extraction** (`scanBody`) | `monitor.go` — ~200 lines of duplicate body-read/detect/log code removed; `MonitorInterceptor.InterceptRequest` and `InterceptResponse` now delegate to shared `scanBody` |
| **Shared SSE frame accumulator** (`sseFrameAccumulator`) | `sse.go` — `SSEFrameReader` fields `frameBuf`/`maxFrameSize`/`frameTimeout`/`hasFrameData` replaced with `acc *sseFrameAccumulator`; `Read` now delegates to `acc.readFrames` |
| **Panic recovery on all plugin calls** | `provider_interceptor.go:212-263` — `matchPathSafe`, `extractTextSafe`, `newSessionSafe` wrappers; `sse_helper.go:257-269` — panic recovery for `HandleSSEEvent` in `processFrame` |
| **`..` rejection in path parsing** | `patch_tree.go:300-303` — `decoded == ".."` → error |
| **Config validation** | `config.go:59-111` — `ProvidersConfig.Validate()`: rejects empty names, empty domains, slashes, wildcards, spaces, colons, duplicate domains |
| **Provider registry + domain routing** | `proxy.go:147-334` — `buildProviderRegistry`, `providerDispatcher`, `selectForHost`, `sanitizeHostForDispatch`, `hasEnabledProviders`, `enabledProviderNames` |
| **Test updates** | `monitor_test.go`, `sse_test.go`, `proxy_test.go` |

**The original QINDU-0011 provider files** (`providers/provider.go`, `chatgpt/plugin.go`, `chatgpt/patch_tree.go`, `provider_interceptor.go`, `sse_helper.go`, and their tests) were **not modified** by this refactoring — they are the baseline being re-verified against the new shared infrastructure.

---

## Per-Requirement Results

### R1 — Missed PII due to incomplete plugin coverage ⸺ PASS

| DPO Ref | Requirement | Verdict | Evidence |
|---------|------------|---------|----------|
| DPO-R1.1 | Conservative fallback for unrecognized SSE event types: extract all string values | **PASS** | `chatgpt/plugin.go:198-207` — `default` case calls `extractAllStringValues`. **No change from original.** The shared `scanBody` does not affect this — it operates at the body-scanner level (non-SSE), not the SSE event level. The SSE event fallback path is entirely in the plugin layer and unchanged. |
| DPO-R1.2 | Unrecognized event type logged once per stream as WARN, event type name only | **PASS** | `chatgpt/plugin.go:333-342` — `logUnknownEvent` with per-stream dedup, truncated+sanitized event type, never data. **No change.** |

**R1 overall: PASS** — No regression. The conservative fallback remains intact. The `extractAllStringValues` fallback is in the SSE event handler, which was not refactored. The `scanBody` extraction (`extractor` parameter) only affects non-SSE body scanning.

---

### R2 — In-memory document tree accumulation ⸺ PASS

| DPO Ref | Requirement | Verdict | Evidence |
|---------|------------|---------|----------|
| DPO-R2.1 | Document tree never serialized to disk, logged, or exposed outside plugin | **PASS** | `patch_tree.go:37-42` — all unexported fields, no serialization. **No change.** |
| DPO-R2.2 | Tree deterministically cleared on stream end (DONE, EOF, error) | **PASS** | `sse_helper.go:167-177` — `emitAndCleanup()` uses single idempotency guard, calls `StreamEnded()` exactly once, sets `sessionEnded=true`. The guard was **strengthened** (PR-104): previously two separate guards (`monitorScanEmitted` + `sessionEnded`), now a single atomic check prevents any inconsistency. This is an improvement. `plugin.go:212-218` — `StreamEnded()` sets root to nil. **No regression.** |
| DPO-R2.3 | Tree NOT reused across SSE streams | **PASS** | `plugin.go:130-132` — `NewSession()` fresh tree. `provider_interceptor.go:157-159` — `InterceptResponse` calls `p.newSessionSafe()` per SSE stream. **No change.** |

**R2 overall: PASS** — The `sseFrameAccumulator` refactoring does not touch tree lifecycle. The `emitAndCleanup` was **improved** with a stronger atomic guard (PR-104). No regression; improvement.

---

### R3 — Text segment data flow exposure ⸺ PASS

| DPO Ref | Requirement | Verdict | Evidence |
|---------|------------|---------|----------|
| DPO-R3.1 | SSE helper/ProviderInterceptor never log extracted text, parsed data JSON, or byte contents | **PASS** | `scanBody` (`monitor.go:386-488`): PII detection runs on `segments[].Text`, but only entity counts reach `emitMonitorScan`. The `scanBody` function itself only logs metadata: `oversize` skips, `engine_error` with error string (no PII), and `text_segments_filtered` with drop counts only. `detectWithEngine` at `monitor.go:554-563` has panic recovery; error message is `"engine panic: %v"` — the panic value could theoretically contain text, but it's an engine-layer panic (not plugin text), and identical to the MonitorInterceptor behavior this sprint replaced. **No regression.** |
| DPO-R3.2 | `monitor_scan` entries byte-for-byte identical to MonitorInterceptor | **PASS** | `emitMonitorScan` (`monitor.go:257-293`) is shared by all interceptor types. Both `MonitorInterceptor` (via `scanBody` → `emitMonitorScan`) and `ProviderInterceptor` (via `scanBody` → `emitMonitorScan`) use identical format. SSE paths: `SSEFrameReader.emitAggregatedMonitorScan` and `ProviderSSEReader.emitAggregatedMonitorScanLocked` both call `emitMonitorScan`. **Format parity preserved.** The `provider` field remains intentionally excluded (PR-003). |
| DPO-R3.3 | `provider` field must be config-derived, never from request/response data | **PASS** | `chatgpt/plugin.go:38-40` — hardcoded `"chatgpt"`. The `provider` field is NOT emitted in `monitor_scan` for format parity (`TestProviderInterceptor_MonitorScanFormat` verifies absence). When used in log metadata (construction-time `"Provider plugin registered"` log), it's the plugin's `Name()` string — config-derived. **No change.** |

**R3 overall: PASS** — The shared `scanBody` refactoring eliminates code duplication but **preserves** the exact same privacy guarantees: PII detection runs on extracted text, the engine panics are recovered, and only entity type counts reach `emitMonitorScan`. The `detectWithEngine` wrapper (with its panic recovery) replaces the old `MonitorInterceptor.detect()` method — functionally identical.

---

### R4 — Plugin interface boundary ⸺ PASS

| DPO Ref | Requirement | Verdict | Evidence |
|---------|------------|---------|----------|
| DPO-R4.1 | `TextSegment` passes text by value (Go `string`), offsets index caller's buffer | **PASS** | `providers/provider.go:11-15` — `string` type, immutable. **No change.** `scanBody` at `monitor.go:429-432`: when `extractor` is nil, creates `{Start: 0, End: len(bodyBytes), Text: string(bodyBytes)}` — the `string(bodyBytes)` creates a copy. |
| DPO-R4.2 | Plugin SSE event handler does NOT retain references to caller's data byte slice | **PASS** | `chatgpt/plugin.go:157-209` — `data []byte` parsed via `json.Unmarshal` into new `map[string]any`, never stored. Returns `string`. **No change.** |

**Additionally verified — panic recovery refactoring (CS-11-05):**
- `matchPathSafe` (`provider_interceptor.go:212-224`): recovers, logs ERROR with plugin name + method, returns `false` (no match → fallthrough to passthrough)
- `extractTextSafe` (`provider_interceptor.go:229-241`): recovers, logs ERROR, returns `nil` segments (no scanning)
- `newSessionSafe` (`provider_interceptor.go:247-263`): recovers, logs ERROR, returns `noOpProviderSession` (silent no-op)
- `processFrame` inline panic recovery (`sse_helper.go:257-269`): recovers `HandleSSEEvent` panics, degrades to raw SSE extraction

All panic recovery wrappers log only plugin name, method name, and the panic value — never the body data or extracted text. **This is a privacy improvement** (defense-in-depth for plugin crashes).

**R4 overall: PASS** — No regression. Panic recovery on all plugin calls was added (improvement).

---

### R5 — Enforce mode guard ⸺ PASS

| DPO Ref | Requirement | Verdict | Evidence |
|---------|------------|---------|----------|
| DPO-R5.1 | `selectInterceptor` refuses to start with fatal error when mode=enforce + provider enabled | **PASS** | `proxy.go:131-139` — `case "enforce"` checks `hasEnabledProviders`, builds error with provider names via `enabledProviderNames`. Error message: `"enforce mode is not yet supported for provider(s): %s (pending QINDU-0009)..."` **This was strengthened since original review**: previously only returned a generic `"agent.mode 'enforce' is not yet implemented"` without checking for provider plugins. Now it explicitly checks the registry and names the blocking providers. **Improvement.** |
| DPO-R5.2 | `RewriteRequestBody` returns original body unchanged (identity pass-through) | **PASS** | `chatgpt/plugin.go:125-127` — `return body` (same slice). `scanBody` at `monitor.go:481-485`: if `cfg.rewriter != nil`, calls it; otherwise returns `bodyBytes`. For MonitorInterceptor, `rewriter` is nil; for ProviderInterceptor, it's `p.plugin.RewriteRequestBody` which is identity. **No change.** |

**R5 overall: PASS** — The enforce guard was actually **strengthened**: it now detects provider plugins specifically and names them in the error. No regression; improvement.

---

### Mandatory Privacy Tests (PT-1 through PT-15)

| PT# | Test Name | Still Exists | Still Passes | Evidence |
|-----|-----------|-------------|-------------|----------|
| PT-1 | Fallback scan for unknown events | ✅ | ✅ | `plugin_test.go:269-290` — unchanged |
| PT-2 | Warning logged once per stream | ✅ | ✅ | `plugin_test.go:293-327` — unchanged |
| PT-3 | No serialization (structural) | ✅ | ✅ | No serialization code in `patch_tree.go` |
| PT-4 | Tree cleared on stream end | ✅ | ✅ | `plugin_test.go:330-359` — unchanged |
| PT-5 | No cross-stream leak | ✅ | ✅ | `plugin_test.go:362-385` — unchanged |
| PT-6 | No text in SSE helper logs | ✅ | ✅ | `sse_helper_test.go:261-303` — `TestProviderSSEReader_NoTextInLogs` |
| PT-7 | Monitor scan format parity | ✅ | ✅ | `provider_interceptor_test.go:72-133` + `sse_helper_test.go:518-587` — both verify `pii_values_logged: false`, no `provider` field |
| PT-8 | No PII in any log output | ✅ | ✅ | `provider_interceptor_test.go:507-553` + `sse_helper_test.go:590-655` — both grep for raw PII patterns |
| PT-9 | TextSegment by-value (Go string) | ✅ | ✅ | Structural: Go `string` guarantees value semantics |
| PT-10 | No buffer retention | ✅ | ✅ | `plugin_test.go:388-415` — unchanged |
| PT-11 | Enforce mode refused | ✅ | ✅ (improved) | `proxy_test.go:477-519` — `TestHasEnabledProviders` with 3 sub-cases; `TestNewProxy_EnforceModeFatal` — covers enforce with empty providers. Note: same incomplete integration test gap as original review, but `hasEnabledProviders` now properly queries the plugin registry (improvement). |
| PT-12 | RewriteRequestBody identity | ✅ | ✅ | `provider_interceptor_test.go:136-157` — byte-identical |
| PT-13 | Non-conversation path bypassed | ✅ | ✅ | `provider_interceptor_test.go:160-188` |
| PT-14 | ChatGPT metadata no false positives | ✅ | ✅ | `provider_interceptor_test.go:191-219` |
| PT-15 | No real PII in test fixtures | ✅ | ✅ | `plugin_test.go:532-569` — synthetic domain allowlist check |

**PT-1 through PT-15 overall: PASS** — All 15 privacy tests remain present and passing. No tests were removed or weakened.

---

### Additional Verifications

#### Cross-stream isolation
| Test | Status |
|------|--------|
| `TestChatGPTSession_NoCrossStreamLeak` (`plugin_test.go:362`) | ✅ Unchanged |
| `TestProviderInterceptor_IndependentSessions` (`provider_interceptor_test.go:557-599`) | ✅ Unchanged |

#### Log format parity
- `emitMonitorScan` (`monitor.go:257-293`) — single shared function, all callers use `MonitorScanArgs`. **No regression.**
- Both `SSEFrameReader` and `ProviderSSEReader` use `emitMonitorScan` via their respective `emitAggregatedMonitorScan`/`emitAggregatedMonitorScanLocked` methods. **No regression.**

#### Test fixture purity
- `TestTestFixtures_NoRealPII` (`plugin_test.go:532-569`) — unchanged. Synthetic domains: `example.com`, `doe.com`, `company.org`, `test.org`.

#### Shared body-scanner correctness
- `scanBody` at `monitor.go:386-488`: content-length pre-check, `readBodyBytes` with oversize combined-reader fallback, `validateTextSegments` filter, `detectWithEngine` per-segment, `emitMonitorScan` at end, optional `rewriter`. When `extractor` is nil → full-body single-segment (MonitorInterceptor mode). When `extractor` is non-nil → plugin extraction (ProviderInterceptor mode). **PII never logged at any step.**

#### `..` rejection in path parsing
- `patch_tree.go:300-303`: `if decoded == ".."` → returns error with sanitized path. **Defense-in-depth improvement.** Prevents path-traversal-styled inputs from reaching downstream consumers.

#### Config validation
- `config.go:59-111` — `ProvidersConfig.Validate()`: rejects empty provider names, empty domains, slashes, wildcards, spaces, colons, and duplicate domains across providers. **Privacy-relevant**: prevents misconfigured domains from routing PII through wrong interceptors.

---

## New Concerns

### C4 — Single shared `scanBody` has no mode-specific behavior differentiation (LOW severity)

The `scanBody` function handles both MonitorInterceptor (nil extractor → full-body scan) and ProviderInterceptor (non-nil extractor → segment scanning) in a single code path. This is correct today, but a future maintainer who adds logging to `scanBody` thinking it's a MonitorInterceptor-only path could inadvertently log segment text that comes from provider plugins. The function's comment already distinguishes the two modes, but there is no compile-time enforcement.

**Risk**: LOW. The code is clearly documented and the function is file-local (unexported). Any logging added would need to go through code review.

**Recommendation**: Not blocking. The `MonitorScanArgs` struct and `emitMonitorScan` already enforce field-level control. Future logging additions should continue to use `cfg.logger` only for metadata.

### C5 — `detectWithEngine` panic message could contain PII in edge cases (VERY LOW severity)

`detectWithEngine` at `monitor.go:554-563` recovers panics with `"engine panic: %v"`. If the engine panics with a message that contains the text being scanned (hypothetically, if a recognizer panics with the input string), PII would appear in the WARN log. The old `MonitorInterceptor.detect()` had the same behavior.

**Risk**: VERY LOW. The PII engine's `Detect()` is well-tested and uses structured inputs. No recognizer includes input text in its panic messages. This is identical to the pre-refactoring behavior.

**Recommendation**: Not blocking. If desired, replace the panic value with `"engine panic: type=%T"` in a future safety sprint, but the current behavior is the same as the baseline that passed original review.

---

## Verdict

### VERDICT: **PASS**

All 5 mandatory risk requirements (R1–R5) remain satisfied. All 15 mandatory privacy tests (PT-1 through PT-15) continue to pass. The refactoring — shared `scanBody`, shared `sseFrameAccumulator`, panic recovery wrappers, `..` rejection, and config validation — is **privacy-neutral or privacy-positive**:

| Change | Privacy Impact |
|--------|---------------|
| Shared `scanBody` | **Neutral** — eliminates ~300 lines of duplication; same PII-free logging, same engine invocation, same body forwarding |
| Shared `sseFrameAccumulator` | **Neutral** — eliminates ~90% duplication between SSE frame readers; same boundary detection, same byte-forwarding |
| Panic recovery on all plugin calls | **Positive** — defense-in-depth; previously only `HandleSSEEvent` had recovery, now `MatchPath`, `ExtractText`, and `NewSession` also do |
| `..` rejection | **Positive** — defense-in-depth against path-traversal inputs |
| Config validation | **Positive** — prevents misconfigured domains from routing PII through wrong interceptors |
| Enforce mode guard with provider check | **Positive** — stronger than original; now explicitly checks provider registry and names blocking providers |

No privacy regression was introduced. No PII logging path was created. No serialization or persistence was added. No cross-stream state leakage was introduced. All ADRs remain respected.

**Previous concern C1** (PT-11 integration test gap) remains noted but not blocking — the code path is visibly correct and the helper functions are unit-tested with the improved registry-based implementation.

The sprint may proceed to the next gate (CISO review).
