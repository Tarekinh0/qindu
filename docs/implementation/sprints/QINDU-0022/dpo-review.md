# DPO Review — QINDU-0022 Debug Flow Inspector

**Reviewer**: qindu-dpo
**Date**: 2026-07-06
**Mode**: Review Mode
**Inputs**: `story.md` + `git diff`

---

## 1. Story Summary

QINDU-0022 introduces a debug tool — the **Flow Inspector** — accessible via `GET /debug/flow` on localhost. It exposes a ring buffer (`FlowRing`) of the last 50 HTTP request/response pairs flowing through the enforce pipeline, showing both the **ingress body** (browser → proxy, containing cleartext PII) and the **egress body** (proxy → upstream, containing token placeholders like `<<EMAIL_1>>`). The feature is gated behind `debug.flow_inspector: true` (default `false`), emits a prominent `WARN` at startup when active, and stores data in memory only — no disk persistence.

The sprint also adds a structured `enforce_transform` DEBUG-level log event emitted at each enforce pipeline transformation, containing only entity type counts and byte sizes with `pii_values_logged: false` hardcoded.

The diff additionally includes supporting infrastructure from preceding sprints (enforce mode, per-user vault, provider dispatcher, `ShouldProcess` interface) that are already reviewed.

---

## 2. Data Processed

| Data Category | Location | Format | PII Values? |
|---|---|---|---|
| **Ingress body** (pre-tokenization) | `FlowRing` in-memory ring buffer | JSON string in `FlowEntry.IngressBody` | **YES** — full cleartext request body including emails, phones, names, etc. |
| **Egress body** (post-tokenization) | `FlowRing` in-memory ring buffer | JSON string in `FlowEntry.EgressBody` | **No** — contains only `<<TYPE_N>>` token placeholders |
| **Entity summary** | `FlowEntry.EntitySummary` | `map[string]int` — type counts only | **No** — e.g., `{"EMAIL": 1, "PHONE": 2}` |
| **Request metadata** | `FlowEntry` fields | Host, method, path, byte sizes, timestamp | No |
| **`enforce_transform` log event** | Structured DEBUG log (request path) | `detected_count`, `entity_summary` (types+counts), `body_bytes_in`, `body_bytes_out` | **No** — `pii_values_logged: false` hardcoded |
| **`enforce_transform` log event** | Structured DEBUG log (response path) | `rehydration_count`, `body_bytes_in`, `body_bytes_out` | **No** — `pii_values_logged: false` hardcoded |
| **`monitor_scan` log with `tokenized_count`/`rehydrated_count`** | Structured DEBUG log | Numeric counts added to existing event | **No** — no PII values |

---

## 3. Purpose

The Flow Inspector serves a **legitimate operational purpose**: operators administering a Qindu enforce-mode deployment need the ability to visually verify that the tokenization pipeline is functioning correctly — that PII is being replaced with tokens before leaving the machine. Without this visibility, the operator has no way to validate `tokenized_count: 1` log claims against actual payloads.

The `enforce_transform` DEBUG log event provides auditable evidence that each transformation occurred, without exposing any PII values. This is essential for forensic verification in a privacy-critical proxy.

---

## 4. Minimization Basis

| Control | Justification |
|---|---|
| **`debug.flow_inspector: false` by default** | Zero overhead, zero risk in production; operator must explicitly opt in |
| **Ring buffer capped at 50 entries** | Bound on data volume — 50 is sufficient for visual debugging without excessive retention |
| **64 KB max body size per entry** (`maxDebugBodyLen`) | Prevents a single large upload from consuming ~6.4 MB. Truncation with `...[truncated]` suffix preserves visibility of the structure without retaining all bytes |
| **Memory only — no disk persistence** | Redémarrage = wipe complet. No residual PII on disk |
| **Localhost-only binding** | The proxy binds to `127.0.0.1` (SR4 validated). `isLocalhostRequest()` adds defense-in-depth. No remote access possible |
| **`ShouldProcess` path filtering** | The `DebugInterceptor` checks `ShouldProcess` before reading the body; sentinel/challenge payloads, telemetry, and static assets are never buffered or recorded in the `FlowRing` |
| **`entity_summary` uses type counts only** | The `tokenSummary()` function derives summary from token patterns in the egress body — never from PII values. Malformed/unknown tokens are filtered out via `isKnownDebugEntityType()` |
| **`enforce_transform` log at DEBUG level** | In production (INFO), zero log impact. Only numeric counts and type summaries |
| **`pii_values_logged: false` hardcoded** | On every `enforce_transform` and every error log line in `mitm.go` and `cmd/agent/proxy.go` — no configurable toggle, no ambiguity |
| **Cache-Control: `no-cache, no-store, must-revalidate`** | Prevents browser/proxy caching of the `/debug/flow` JSON response |

**Why less would not work**: The whole point of a **visual** flow inspector is to show the actual bodies. Showing only tokens (egress) without the original (ingress) defeats the purpose — the operator can't confirm that `<<EMAIL_1>>` corresponds to `alice@corp.com`. Truncation at 0 bytes would render the tool useless. A smaller buffer (e.g., 5 entries) might miss relevant traffic during rapid requests.

---

## 5. Rights and Freedoms Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Unauthorized local access to raw PII via `/debug/flow`** | Low — requires local machine access or malware already running with user privileges | High — full request bodies with cleartext PII exposed | Flag-gated (default off), `127.0.0.1` binding, no remote network exposure, `no-store` cache headers prevent browser disk persistence |
| **Memory dump / swap file exposure of PII from `FlowRing`** | Low-Medium — swap/pagefile could contain ring buffer bytes if memory pressure is high | Medium — PII leaked to disk via OS swap | Acceptable residual risk: swap is OS-level and the flag is off by default. The `WARN` at startup educates the operator |
| **Operator forgets `flow_inspector: true` in production** | Medium — plausible human error | High — continuous PII accumulation in memory on a production proxy | `WARN` at startup is prominent. Future: consider a TTL-based self-disable after N hours or a `--no-debug` CLI flag |
| **Test fixture with real-like phone number** | Very Low — purely synthetic | None (test-only) | `+33612345678` uses sequential digits; clearly synthetic. See Finding DPO-F1 |

---

## 6. Blocking Points

**None.** All privacy risks are adequately mitigated or accepted as residual.

The explicit acceptance by the human DPO (DD-3) of in-memory PII storage for the Flow Inspector, combined with the comprehensive safeguards (flag-gated, localhost-only, memory-only, bounded, cached-headers), forms a defensible position.

---

## 7. Findings

### DPO-F1 — Test fixture domain `corp.com` (LOW)

**Location**: `internal/interceptor/debug_test.go:77` and `internal/interceptor/debug_test.go:354-356`

```go
ring.Record(
    "Hello alice@corp.com, call +33612345678",
    ...
```

`corp.com` is a real, registered domain — not one of the IANA-reserved example domains (`example.com`, `example.org`, `test.example`). While `alice@corp.com` is self-evidently a synthetic test identity and the likelihood of a real `alice@corp.com` existing is negligible, best practice for privacy-conscious projects is to use **only** reserved domains in test fixtures.

**Recommendation**: Replace `alice@corp.com` with `alice@example.com` in test fixtures. The same comment applies to any use of non-reserved domains across test files.

**Test fixture phone number `+33612345678`**: This uses a legitimate French mobile prefix (`+336`), but the subscriber digits `12345678` are clearly sequential and synthetic. No real subscriber would have this number. This is acceptable.

**SHA-fixture phone `+1-555-0100`** in `internal/providers/chatgpt/plugin_test.go` uses the `555` prefix permanently reserved for fictional use in the NANP. Fully compliant.

### DPO-F2 — No TTL on debug flow entries (LOW, informational)

The `FlowRing` has no time-based eviction. An entry remains until it's pushed out by FIFO (50th new entry). If the operator enables the flag and traffic is very low, a PII-containing ingress body could remain in memory for an extended period.

**Risk**: Low. The memory-only constraint means a restart wipes the buffer. The flag is off by default. The operator has explicitly opted in and been warned.

**Recommendation** (future sprint): Consider adding a configurable TTL (`debug.flow_inspector_ttl: 5m`) to auto-evict entries older than the TTL, even if the ring buffer isn't full.

### DPO-F3 — Missing `enforce_transform` path field sanitization consistency (LOW)

The request-side `enforce_transform` log emits `"path", reqPath` (line 185 of `enforce.go`), while the response-side uses `"path", sanitizeLogPath(rawPath)` (line 355). Both are derived from internal URL paths, not user-controlled query strings, so the risk is minimal. However, the inconsistency suggests the request-side path is not sanitized.

**Risk**: Negligible. URL paths from browser-to-proxy requests are structurally constrained. No PII is transmitted via log paths.

**Recommendation**: Apply `sanitizeLogPath` consistently on both sides.

---

## 8. Verdict

# **PASS**

The QINDU-0022 implementation is privacy-compliant. The core design — a flag-gated, localhost-only, memory-resident ring buffer with bounded size and body truncation — respects data minimization, purpose limitation, and the principle of least privilege. The `enforce_transform` DEBUG event correctly limits itself to type counts and byte sizes with `pii_values_logged: false` hardcoded on every emission. The `ShouldProcess` path filtering prevents sentinel/challenge payloads (which may contain authentication tokens) from polluting the debug buffer.

All three findings (DPO-F1 through DPO-F3) are LOW severity and non-blocking. They should be addressed in a follow-up cleanup sprint or during the next touch of the relevant files.

**Conditions for DPO approval in production**:
1. `debug.flow_inspector` **must** remain `false` in any shipped/installed default configuration.
2. The startup `WARN` message **must not** be suppressed or downgraded.
3. The `/debug/flow` endpoint must **never** be exposed on non-loopback interfaces.
4. `QNDP-036` (DPO-F1) should be tracked in the backlog for test fixture cleanup.
