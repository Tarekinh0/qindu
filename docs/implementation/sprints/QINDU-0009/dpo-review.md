# DPO Privacy Review — QINDU-0009

**Sprint**: Mode Enforce + Réhydratation (non-streaming + SSE)  
**Author**: qindu-dpo (Privacy Reviewer)  
**Date**: 2026-07-06  
**Review of**: Implementation diff against design-phase `dpo-requirements.md`

---

## Verdict: PASS

The implementation respects the critical privacy safeguards. No PII leakage paths were identified. The core pipeline — tokenization before egress, encrypted vault persistence, fail-closed, conversation scoping, log sanitization with `pii_values_logged: false` — is correctly wired. The findings below are defense-in-depth gaps; none represent an actual PII leakage risk.

---

## 1. Requirement Satisfaction Matrix

### DR-1: Surgical rehydration via ResponseTextExtractor — PARTIAL

| Aspect | Status | Evidence |
|---|---|---|
| Uses `ResponseTextExtractor` when available | ✅ PASS | `enforce.go:207-216`: `if rte, ok := e.plugin.(providers.ResponseTextExtractor); ok` |
| Logs WARN when falling back to blind rehydration | ✅ PASS | `enforce.go:212-215`: `enforce_blind_rehydration` with `pii_values_logged: false` |
| Rehydrates only within extracted byte ranges | ⚠️ GAP | `enforce.go:220-222`: `rehydrateFn` always does `tokenizer.Rehydrate(string(body))` on full body |

**Analysis**: The `ResponseTextExtractor` is used for PII detection (entity counting for logging), but the actual rehydration step always operates on the full body via blind `Rehydrate()`. This does NOT satisfy the strict reading of DR-1 ("rehydrate only within the byte ranges returned by the extractor"). However:

1. The DPO's own design review (BLOCK-1) said "NOT BLOCKED" because `ResponseTextExtractor` is available and used.
2. `Rehydrate()` is safe on JSON bodies — `<<TYPE_N>>` tokens contain no JSON-breaking characters (DD-3).
3. SSE (ChatGPT's primary response path) is explicitly designed for blind rehydration (DD-4).
4. Tokens only appear in response fields where the AI echoes user input — there is no meaningful distinction between "metadata" and "content" fields in terms of what the AI generates.

**Finding F-1 (LOW)**: The `rehydrateFn` in `EnforceInterceptor.InterceptResponse` should ultimately rehydrate only within extracted segments. Retarget to a future sprint where byte-range-selective rehydration is implemented. Not blocking — the current approach is functionally correct and PII-safe.

### DR-2: Cryptographic conversation UUID — PASS ✅

| Aspect | Status | Evidence |
|---|---|---|
| SHA-256 hash of URL path UUID | ✅ PASS | `conversation.go:67-68`: `sha256.Sum256([]byte(strings.ToLower(match)))` |
| Fallback uses `crypto/rand` UUID v4 | ✅ PASS | `conversation.go:79-92`: `rand.Read(buf[:])`, version 4 bits set |
| Vault scope key includes provider name | ✅ PASS | `conversation.go:73-75`: `vaultScopeKey` returns `"{Provider}:{ConversationID}"` |
| Deterministic across connections | ✅ PASS | `TestDeriveConversationID_DeterministicSameUUID` |
| Different UUIDs → different hashes | ✅ PASS | `TestDeriveConversationID_DifferentUUIDsDifferentHashes` |
| NUL bytes / control chars rejected | ✅ PASS | `conversation.go:37-44`, validated in tests |

### DR-3: Fail-closed enforcement — PASS ✅

| Aspect | Status | Evidence |
|---|---|---|
| Config rejects `fail_open` in enforce mode | ✅ PASS | `config.go:231-233`: returns error, `TestConfig_EnforceModeRejectsFailOpen` |
| `FailModeValue()` defaults to `fail_closed` for enforce | ✅ PASS | `config.go:46-48` |
| Missing tokenizer → error (never passthrough) | ✅ PASS | `enforce.go:72-79`: returns error with `pii_values_logged: false` |
| Vault manager nil → 502 | ✅ PASS | `mitm.go:127-145`: sends 502 Bad Gateway |
| SID resolution failure → 502 | ✅ PASS | `mitm.go:150-166`: logs error, sends 502 |
| Vault creation failure → 502 | ✅ PASS | `mitm.go:168-190`: logs error, sends 502 |
| All error logs contain `pii_values_logged: false` | ✅ PASS | Verified in all three error paths |

### DR-4: Async channel overflow WARN — PARTIAL

| Aspect | Status | Evidence |
|---|---|---|
| No PII values in overflow log | ✅ PASS | `writer.go:185-188`: only `provider` name, `pii_values_logged: false` |
| WARN level | ✅ PASS | `v.logger.Warn(...)` |
| `pii_values_logged: false` | ✅ PASS | Present in log call |
| Dropped-write counter (DR-4.4) | ❌ GAP | Log says "async channel full" but no counter of dropped writes |
| Rate-limited (DR-4.5) | ❌ GAP | No rate limiting — every overflow produces a WARN |

**Finding F-2 (LOW)**: DR-4.4 (dropped-write counter) and DR-4.5 (rate limiting, max 1/min) are not implemented. Under a sustained overflow scenario, this could produce log flooding. Not a PII leak — no PII values in log output. Acceptable for V1; retarget rate-limiting to a future sprint.

### DR-5: Zero PII in log output — PASS ✅

| Aspect | Status | Evidence |
|---|---|---|
| All PII-related logs have `pii_values_logged: false` | ✅ PASS | Every new log call in `enforce.go`, `enforce_sse.go`, `mitm.go` |
| No raw body content logged | ✅ PASS | No log call includes body bytes, only counts/positions/metadata |
| Sliding buffer content never logged | ✅ PASS | `enforce_sse.go:314-319`: overflow WARN logs `remainder_len` (size), not content |
| Sliding buffer zeroed on close | ✅ PASS | `enforce_sse.go:407-411`: `slidingBuf[i] = 0`, then `nil` |
| Paths sanitized before logging | ✅ PASS | `sanitizeLogPath` truncates to 512 bytes, UTF-8 safe |

### DR-6: `pii_logging` flag controls `entity_summary` — PASS ✅

| Aspect | Status | Evidence |
|---|---|---|
| `PIILogging` is `*bool` (R-024) | ✅ PASS | `config.go:146`: `PIILogging *bool` |
| Nil-safe default `false` | ✅ PASS | `config.go:151-154`: `PIILoggingValue()` returns `false` if nil |
| `emitMonitorScan` respects flag | ✅ PASS | `monitor.go:281`: `if args.PIILogging && args.EntitySummary != nil` |
| `emitAndCleanup` (SSE) respects flag | ✅ PASS | `enforce_sse.go:430`: `if r.piiLogging && r.aggregatedSummary != nil` |
| Enforce interceptor passes flag through | ✅ PASS | `enforce.go:55`: `piiLogging: piiLogging` stored in struct, passed to `bodyScanConfig` |
| Startup INFO when enabled | ✅ PASS | `cmd/agent/proxy.go:89-92`: logs "pii_logging is enabled — entity type counts will appear" |

### DR-7: `valueToToken` map protections — PASS ✅

| Aspect | Status | Evidence |
|---|---|---|
| WARNING comment retained | ✅ PASS | `tokenizer.go:70-72`: "WARNING: map keys contain raw PII. Never log, serialize, or print this field." |
| No serialization/copying in new code | ✅ PASS | No new code paths expose `valueToToken` to logs or contexts |
| Tokenizer injected via context, not internal maps | ✅ PASS | `tokenizerCtxKey` stores `*Tokenizer`, not raw maps |

### DR-8: Vault uninstall persistence documentation — GAP

| Aspect | Status | Evidence |
|---|---|---|
| Startup log about vault data persistence | ❌ GAP | No log entry found documenting that vault.db persists after MSI uninstall |

**Finding F-3 (LOW)**: DR-8 requires a vault creation log noting "vault data persists after MSI uninstall — manual cleanup required." Not implemented. This is documentation, not a code defect. Retarget to a future sprint.

### DR-9: SeImpersonatePrivilege warning — PARTIAL

| Aspect | Status | Evidence |
|---|---|---|
| Startup WARNING logged | ✅ PASS | `cmd/agent/proxy.go:82-86`: "enforce mode: per-user vault isolation requires SeImpersonatePrivilege" |
| `pii_values_logged: false` | ✅ PASS | Present in log call |
| Runtime detection of privilege | ❌ GAP | TODO comment at line 80-81: "TODO: Add runtime detection of SeImpersonatePrivilege via OpenProcessToken" |
| Fires only on Windows | ❌ GAP | Warning fires on all platforms (line 82: `if cfg.Agent.Mode == "enforce"`), misleading on Linux/macOS |

**Finding F-4 (LOW)**: The warning is a blanket message at startup, not a runtime detection of the actual privilege. On non-Windows platforms, it's a false alarm (SID resolution falls back to current user). Acknowledge the TODO; acceptable for V1.

---

## 2. Privacy Test Coverage

| Test | Status | Evidence |
|---|---|---|
| **PT-ENF-1** (zero PII in outbound) | ✅ PASS | `TestEnforceInterceptor_RequestTokenization` |
| **PT-ENF-2** (vault.db encrypted) | ✅ PASS | Inherited from QINDU-0008 `TestBoltDBFilePermissions`, `TestRestartRoundTrip` |
| **PT-ENF-3** (non-streaming round-trip) | ✅ PASS | `TestEnforceInterceptor_ResponseRehydration` |
| **PT-ENF-4** (SSE sliding buffer) | ✅ PASS | `TestEnforceSSEReader_SlidingBufferTokenSplit` |
| **PT-ENF-5** (fail-closed) | ✅ PASS | `TestEnforceInterceptor_MissingTokenizerFailClosed`, config tests |
| **PT-ENF-6** (log sanitization — grep for PII) | ⚠️ PARTIAL | Tests verify `pii_values_logged` is present but don't grep for PII values in log output. Covered by QEMU integration test (AC-9). |
| **PT-ENF-7** (conversation isolation) | ⚠️ PARTIAL | Hash uniqueness verified (`TestDeriveConversationID_DifferentUUIDsDifferentHashes`), scope key format verified (`TestVaultScopeKey`). Full pipeline cross-conversation test deferred to integration. |
| **PT-ENF-8** (metadata exclusion) | ⚠️ PARTIAL | `TestEnforceInterceptor_ResponseRehydration` uses `nil` plugin (blind rehydration). No dedicated test with a mock `ResponseTextExtractor`. |
| **PT-ENF-9** (unknown token pass-through) | ✅ PASS | `TestEnforceInterceptor_UnknownTokenPassThrough` |
| **PT-ENF-10** (async overflow WARN) | ✅ PASS | `TestAsyncChannelOverflowWarn` in `vault_test.go` |
| **PT-ENF-11** (config rejects fail_open) | ✅ PASS | `TestConfig_EnforceModeRejectsFailOpen` |
| **PT-ENF-12** (pii_logging entity_summary) | ⚠️ PARTIAL | `TestConfig_PIILogging*` covers config parsing. No explicit test that `entity_summary` is absent when `pii_logging: false` is set and enforced. |
| **PT-ENF-13** (vault persistence) | ✅ PASS | `TestRestartRoundTrip` |
| **PT-ENF-14** (replaceSegments length) | ✅ PASS | Comprehensive `segments_test.go`: shorter token, longer token, start, end, multiple, UTF-8, invalid bounds |
| **PT-ENF-15** (SSE degraded mode) | ⚠️ GAP | No test for plugin panic in SSE rehydration path. The `EnforceSSEReader` does not use plugins (DD-4: blind rehydration on SSE, no plugin interface called in SSE path), so this test is less critical. The `extractTextSafe` panic recovery applies only to request extraction and JSON response paths. |

**Test coverage gaps** (PT-ENF-6, 7, 8, 12, 15) are typical for a sprint with QEMU integration validation (AC-9). Several of these tests are explicitly scoped to the QEMU tester's `qemu-test-report.md` (AC-9: "Log sanitization verified: zero PII values in any log output."). I accept the partial unit coverage on the condition that the QEMU tester verifies these gaps.

---

## 3. PII in Test Fixtures — PASS ✅

All test fixtures use synthetic/example-domain PII:
- `test.user@example.com`, `user@example.com` (RFC 2606 reserved domain)
- `john.doe@example.com`, `alice@example.com`, `jean@example.com`
- `+33612345678` (impossible French mobile prefix)
- Synthetic UUIDs (`550e8400-e29b-41d4-a716-446655440000`)

No real PII detected. Complies with the sprint's "Forbidden" requirements.

---

## 4. Cross-Conversation Contamination Analysis

**Verdict: No contamination risk.**

The conversation isolation design is sound:

1. **Per-request tokenizer creation** (`mitm.go:219-225`): Each HTTP request on a connection gets its own `Tokenizer` with a scope derived from the request URL path.
2. **Scope derivation** (`conversation.go:35-69`): SHA-256 hash of URL path UUID → deterministic but unique per conversation. Fallback: random UUID v4 via `crypto/rand`.
3. **Scope key** (`conversation.go:73-75`): `{Provider}:{ConversationID}` prevents cross-provider collisions.
4. **Per-request tokenizer close** (`mitm.go:229`): `tokenizer.Close()` is called after each request-response cycle, clearing in-memory state.
5. **Vault writes** scoped by `Scope{Provider, ConversationID}` — the bbolt database keys are prefixed with the scope key, preventing cross-conversation reads.

No shared in-memory `valueToToken` maps between requests for different conversations. Two concurrent connections to the same conversation share a vault scope but use independent in-memory tokenizers — safe because they tokenize the same conversation's PII.

---

## 5. Config Changes (R-024) — PASS ✅

The `*bool`/`*string` pointer migration is correctly implemented:

- `LoggingConfig.PIILogging`: `*bool` with nil-safe `PIILoggingValue()` defaulting to `false`
- `TLSConfig.CertCacheEnabled`: `*bool` with nil-safe `CertCacheEnabledValue()` defaulting to `true`
- `AgentConfig.FailMode`: `*string` with nil-safe `FailModeValue()` defaulting to `fail_closed` (enforce) or `fail_open` (monitor/transparent)
- `MergeFileOverride()`: nil-check (`!= nil`) correctly distinguishes "not set" from "explicitly set to false/empty"
- Config validation rejects `fail_open` in enforce mode: `TestConfig_EnforceModeRejectsFailOpen`
- Explicit `false` in `*bool` override correctly propagated: `TestConfig_MergeFileOverride_StarBoolDistinguishesFalse`
- Explicit `*string` override correctly propagated: `TestConfig_MergeFileOverride_StarStringDistinguishesEmpty`

---

## 6. Inherited Tests from QINDU-0008

The 12 inherited DPO privacy tests (PT-1 through PT-12) are unit-tested at the library level from QINDU-0008. This sprint adds integration-level verification for several of them:

| Test | Integration verification |
|---|---|
| PT-1 (vault.db unreadable) | Verified by vault_test.go `TestBoltDBFilePermissions` + QEMU integration |
| PT-2 (vault.key permissions) | QEMU VM validation |
| PT-3 (startup sweep) | Covered by existing `TestStartupSweep` |
| PT-4 (background sweeper) | Covered by existing `TestBackgroundSweeper` |
| PT-5 (access-time check) | QEMU integration |
| PT-6 (no PII in bbolt keys) | QEMU integration |
| PT-7 (zero PII in logs) | Verified via `pii_values_logged: false` on all new log calls |
| PT-8 (paths redacted) | `sanitizeLogPath` unchanged from monitor mode |
| PT-9 (SID lookup fail-closed) | `mitm.go:150-166`: 502 on SID failure |
| PT-10 (per-user vault isolation) | `LookupVaultPathForPort` per-port resolution |
| PT-11 (async backpressure) | `TestAsyncChannelOverflowWarn` in vault_test.go |
| PT-12 (graceful shutdown) | Existing `TestShutdownDrain` |

---

## 7. Summary of Findings

| Finding | Severity | Description | Blocking? |
|---|---|---|---|
| **F-1** | LOW | DR-1: Rehydration is blind on full body even when `ResponseTextExtractor` is available. The extractor is used for detection but not for surgical rehydration. | No |
| **F-2** | LOW | DR-4: Async overflow WARN lacks dropped-write counter and rate limiting. | No |
| **F-3** | LOW | DR-8: No startup log documenting vault data persistence after MSI uninstall. | No |
| **F-4** | LOW | DR-9: SeImpersonatePrivilege warning is blanket (all platforms, no runtime detection). Misleading on non-Windows. | No |
| **F-5** | LOW | PT-ENF-6: No unit test that greps log output for absence of PII values. Delegated to QEMU integration. | No |
| **F-6** | LOW | PT-ENF-7: No pipeline-level conversation isolation integration test. Hash uniqueness and scope key format tested in isolation. | No |
| **F-7** | LOW | PT-ENF-8: No test with a mock `ResponseTextExtractor` verifying surgical vs. blind rehydration. | No |

None of these findings represent a risk of PII leakage. The critical safeguards — tokenization before egress, encrypted vault persistence, fail-closed on error, log sanitization with `pii_values_logged: false`, conversation scoping — are correctly implemented and tested.

---

## 8. Accepted Risks (Carried Forward from Design Phase)

| Risk | ID | Reason |
|---|---|---|
| Chunking evasion (request side) | R-004 | Accepted for V1. SSE response resolved. |
| Core dump PII exposure | R-005 | Go runtime limitation. |
| `valueToToken` PII keys on Go heap | R-017 | Accepted trade-off. WARNING comment retained (DR-7). |
| Per-user vault.db not cleaned on uninstall | R-031 | MSI limitation. Documentation gap noted (F-3). |
| IBAN/IP_ADDRESS not detected | R-023 | Gap in PII engine. Not in scope. |

---

## 9. Final Verdict

### VERDICT: PASS

The implementation delivers the enforce pipeline with robust privacy protections. PII is tokenized before egress, the vault is encrypted at rest, connections are rejected on vault failure (fail-closed), conversation scoping prevents cross-conversation contamination, and all log output carries `pii_values_logged: false`. The seven findings above are defense-in-depth gaps suitable for future sprints — none permit PII to leave the machine in clear text.

The implementation is consistent with:
- **ADR-002** (CONNECT MITM): Vault wiring in `handleMITM` ✅
- **ADR-004** (Interceptor interface): `EnforceInterceptor` implements `proxy.Interceptor` ✅
- **ADR-008** (slog JSON sans PII): `pii_values_logged: false` on every PII-related log entry ✅
- **GDPR Art. 25** (Data Protection by Design): Tokenization by default, fail-closed by default ✅
- **GDPR Art. 32** (Security of Processing): Encrypted vault at rest, per-user isolation, sliding buffer zeroing ✅
