# CISO Requirements — QINDU-0005: Moteur PII Go-native (Recognizers)

- **Date**: 2026-06-27
- **CISO**: qindu-ciso
- **Verdict**: **PASS**

---

## 1. Summary

QINDU-0005 introduces a pure-computation PII detection engine with 9 recognizers operating on in-memory strings. It is detection-only — no storage, no network, no TLS manipulation, no CA key exposure. The attack surface is limited to:

1. Maliciously crafted input text (DoS via resource exhaustion, ReDoS)
2. Concurrent access to the detection engine (data races)
3. PII value leakage through logs, error messages, or crash dumps

All three are addressed by the story's architectural constraints. This document adds specific, testable security requirements to ensure robustness.

---

## 2. Attack Surface Analysis

### 2.1 New Attack Surfaces

| # | Surface | Risk | Mitigation |
|---|---------|------|------------|
| S1 | Regex matching on adversarial input | ReDoS / CPU exhaustion | Go `regexp` uses RE2 engine — guaranteed linear time O(n). No catastrophic backtracking possible. Input bounded to 1 MiB. |
| S2 | Entropy computation on adversarial input | CPU exhaustion | O(n) single-pass; pre-computed log2 table; input bounded to 1 MiB. |
| S3 | Luhn/MOD-97 validation on forged input | Minimal | O(n) integer arithmetic; no external state. |
| S4 | JWT base64url decoding | Memory allocation from malformed base64 | Go `encoding/base64` is robust; bounded to 8192 chars. |
| S5 | Concurrent `Engine.Detect()` calls | Data races, corrupted results | `sync.RWMutex` on engine; recognizers must be stateless. |
| S6 | Entity slice sharing between goroutines | Use-after-free, aliasing | Each `Detect()` returns independent backing arrays. |

### 2.2 Non-Surfaces (Not Applicable)

- **No network** — recognizers are pure functions `string → []Entity`
- **No filesystem** — everything compiled-in; no config file reads
- **No CA keys, TLS certificates, vault encryption** — those are QINDU-0001/0002/0008
- **No interceptor wiring** — deferred to QINDU-0007

### 2.3 Protected Assets

| Asset | Sensitivity | Protection |
|-------|-------------|------------|
| `Entity.Value` field | **CRITICAL** — raw PII | Must NEVER appear in logs, errors, `fmt.Print`, `t.Log`, test assertions, crash dumps, or reflection output. Only `Type`, `Confidence`, `Source`, `Start`, `End` are safe for logging. |
| Regex state machines (compiled `*regexp.Regexp`) | Low | Compiled at construction time, immutable after init. No `init()` functions. |
| Prefix database | Low | Compiled-in constant data. Public knowledge from Gitleaks/GitGuardian. |
| Pre-computed log2 table | Low | Constant 256-element array of `float64`. Read-only. |

---

## 3. Threat Model (STRIDE Condensed)

### T1 — Denial of Service via Malicious Input (Spoofing / DoS)

**Threat**: Attacker sends 1 MiB of characters designed to degrade regex or entropy performance, causing excessive CPU or memory consumption, impacting proxy responsiveness.

**Existing mitigations**:
- 1 MiB hard limit (`maxInputBytes`) — oversized inputs rejected before processing
- Go `regexp` RE2 engine — linear time guaranteed, no catastrophic backtracking
- Single-pass entropy with O(1) space

**Additional requirements**: See SEC-REQ-04, SEC-REQ-05, SEC-REQ-15.

### T2 — Information Disclosure via PII in Logs (Information Disclosure)

**Threat**: Developer accidentally logs `Entity.Value` (raw email, phone, credit card, API key) through `slog`, `fmt.Printf`, error wrapping, or test assertion messages.

**Existing mitigations**:
- `Entity.SafeString()` helper returning `"EMAIL(0.85)"` — no value
- ADR-008 mandates `pii_values_logged: false` flag
- Explicit prohibition in story constraints

**Additional requirements**: See SEC-REQ-10, SEC-REQ-11.

### T3 — Data Race on Concurrent Detection (Tampering)

**Threat**: Multiple goroutines call `Engine.Detect()` simultaneously. Without proper synchronization, entity slices could be corrupted, or one goroutine could observe another's partial results.

**Existing mitigations**:
- `Engine.mu sync.RWMutex` protects the recognizer list
- `Recognizer.Detect()` must be stateless — no mutable shared state

**Concern**: The NAME recognizer (email_inference) depends on EMAIL entity results. If all recognizers run in parallel (one goroutine each), NAME fires before EMAIL produces results, yielding zero entities.

**Resolution**: The Engine MUST run EMAIL before NAME, or run all independent recognizers in parallel and then run NAME as a second pass. This is an **orchestration requirement**, not a recognizer-level concern. See SEC-REQ-03.

**Additional requirements**: See SEC-REQ-01, SEC-REQ-02, SEC-REQ-03.

### T4 — Panic Propagation (Denial of Service)

**Threat**: Malformed input (null bytes, invalid UTF-8, zero-length strings, extremely deep regex state) causes a recognizer to panic, crashing the entire proxy.

**Existing mitigations**:
- Explicit constraint: "Must never panic; all errors are returned as empty results"
- `Recognizer.Detect()` contract: returns nil or empty slice, never panics

**Additional requirements**: See SEC-REQ-06, SEC-REQ-07, SEC-REQ-15.

### T5 — Secret Harvesting via Compiled-in Prefix Database (Information Disclosure)

**Threat**: The prefix database (~100 patterns) could be used by an attacker who reverse-engineers the binary to harvest known secret patterns for credential stuffing or scanning.

**Assessment**: This is a **low-risk** surface. The prefix database is a subset of publicly available patterns from Gitleaks and GitGuardian. Reverse engineering a Go binary to extract regex patterns provides no advantage over browsing the public GitGuardian/Gitleaks repositories. The database contains no actual secrets — only patterns.

**Additional requirements**: None. Residual risk accepted.

### T6 — False-Negative Exploitation (Tampering)

**Threat**: Attacker crafts input specifically to evade detection (e.g., splitting an email across chunks, using homoglyphs, RTL overrides, zero-width characters).

**Assessment**: Chunked/streaming assembly is QINDU-0007's responsibility. Unicode normalization and homoglyph detection are out of scope for V1. This is a documented limitation.

**Additional requirements**: See SEC-REQ-14 (fuzzing with random bytes).

---

## 4. ReDoS Audit

### 4.1 Go `regexp` Safety Guarantee

Go's `regexp` package uses the **RE2 engine**, which guarantees **linear-time O(n) matching** regardless of pattern complexity. Features that enable exponential backtracking (backreferences, lookahead/lookbehind, possessive quantifiers, atomic groups) are **not supported** and will cause compile errors or be rejected.

This means **catastrophic backtracking is impossible** in Go regex. The RE2 engine simulates an NFA that tracks all possible states simultaneously, never backtracking depth-first.

### 4.2 Per-Recognizer Audit

#### 4.2.1 EMAIL Recognizer

```
[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}
```

- All inner quantifiers bounded (`{0,61}`, `{2,}`).
- Outer `*` groups anchored by literal `\.` separators.
- RE2 linear-time guarantee applies.
- **Verdict**: SAFE. No ReDoS risk.
- **Note**: The `{2,}` at the end has no upper bound. On a 1 MiB alphabetic suffix, this consumes linearly. No backtracking explosion.

#### 4.2.2 PHONE Recognizer

Story describes multiple formats (FR, EU, NANP, INTL) but does not inline the exact combined regex. All formats use bounded digit counts (`[0-9]{4,14}`, `{7,15}`).

- **Requirement**: The implementation MUST provide the exact combined regex. Each variant must use bounded quantifiers and non-nested alternations. See SEC-REQ-09(b).

#### 4.2.3 IBAN Recognizer

Regex per country code, per-country digit counts. Each IBAN has fixed total length (e.g., DE=22, FR=27, GB=22). All quantifiers are bounded by definition.

- **Verdict**: SAFE. No ReDoS risk.

#### 4.2.4 CREDIT_CARD Recognizer

Issuer-specific regexes with fixed digit counts (13-19 digits). Bounded quantifiers only.

- **Verdict**: SAFE. No ReDoS risk.

#### 4.2.5 JWT Recognizer

Structural detection — three base64url segments separated by dots. No regex quantifier nesting. Base64url decoding is O(n) with n ≤ 8192.

- **Verdict**: SAFE. No regex risk. `encoding/base64` is robust.

#### 4.2.6 NAME Recognizer (Email Inference)

No regex. Pure Go string operations on already-detected EMAIL entities (split, title-case, stop-word filter). O(n) string manipulation.

- **Verdict**: SAFE. No regex used.

#### 4.2.7 SECRET (Prefix-Based) Recognizer

~100 specific-keyword regexes. Each regex uses:
- A literal prefix anchor (case-sensitive match)
- A character class with bounded or minimally-unbounded quantifier: `{32,}`, `{36}`, `{20,}`
- Alternation limited by the prefix pre-filter (O(1) lookup)

**Concern**: Several patterns use `{32,}` or `{100,}` with no upper bound on the quantifier. Examples:
- `sk-[A-Za-z0-9]{32,}` — no upper bound
- `sk-ant-api03-[A-Za-z0-9_-]{95}AA` — bounded at 95
- `ABSK[A-Za-z0-9+/]{109,269}={0,2}` — bounded at 269

For unbounded patterns (`{32,}`), on a 1 MiB input of matching chars, RE2 consumes linearly. No backtracking because the character class `[A-Za-z0-9]` has no ambiguity with what follows (end of string or whitespace/quote boundary).

- **Verdict**: SAFE. RE2 linear-time guarantee. No catastrophic backtracking possible.

**Recommendation**: Consider adding upper bounds to match realistic token lengths (e.g., `{32,512}` for generic `sk-`). Reduces memory allocation for false-positive matches on very long strings. See SEC-REQ-05.

#### 4.2.8 SECRET (Generic Entropy) Recognizer

Layer 1 Base64 detection: `[A-Za-z0-9+/]{20,}={0,2}` — `{20,}` unbounded, `={0,2}` bounded. Since `=` is NOT in `[A-Za-z0-9+/]`, there is no ambiguity. RE2 consumes base64 chars greedily, then optionally matches `=`. No backtracking.

Layer 4 Key-Value Assignment:

```
(?i)(?:access|auth|api|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:=|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})
```

- Keyword prefix acts as pre-filter — full match only attempted from keyword start positions.
- All groups bounded except `[a-z0-9+/]{11,}` in second alt. No ambiguity with `={0,3}` suffix (char class disjoint from `=`). RE2 linear-time.
- Large alternation `(?:access|auth|...|token)` — 10 keywords. RE2 compiles to efficient DFA.

- **Verdict**: SAFE. RE2 linear-time guarantee.

#### 4.2.9 PRIVATE_KEY (PEM Armor) Recognizer

No regex backtracking risk. Linear scan for `-----BEGIN ` markers with multi-line span collection. Base64 validation is O(n).

- **Verdict**: SAFE.

### 4.3 ReDoS Audit Summary

| Recognizer | Risk Level | Notes |
|-----------|------------|-------|
| EMAIL | LOW | Bounded inner quantifiers; literal anchors. |
| PHONE | LOW | Bounded digit counts; must audit combined regex. |
| IBAN | LOW | Fixed-length per country. |
| CREDIT_CARD | LOW | Fixed-length per issuer. |
| JWT | LOW | No regex; structural parsing. |
| NAME | NONE | No regex. |
| SECRET (Prefix) | LOW | Keyword pre-filter + bounded/extensible quantifiers. |
| SECRET (Entropy) | LOW | Keyword pre-filter + RE2-safe patterns. |
| PRIVATE_KEY | LOW | Linear scan; no regex nesting. |

**Global conclusion**: All regex patterns are safe under Go's RE2 engine. The 1 MiB input bound provides a hard backstop. No blocking ReDoS vulnerabilities.

---

## 5. Security Requirements

### SEC-REQ-01 — Engine Thread Safety

The `Engine.Detect()` method MUST be safe for concurrent use. All access to `Engine.recognizers` slice MUST be protected by `sync.RWMutex` (read-lock for detection, write-lock only if dynamic registration is added later). 

**ASVS**: V14.5.1 — Verify that the application is not susceptible to race conditions.

**Test**: `go test -race -count=100 ./internal/pii/...` with concurrent goroutines calling `Engine.Detect()` on shared engine instance.

### SEC-REQ-02 — Recognizer Statelessness

All `Recognizer.Detect()` implementations MUST be stateless and idempotent. They MUST NOT share mutable state between calls or between concurrent goroutines. Each call operates independently on the provided `text` parameter.

**Exception**: Recognizers MAY hold immutable compiled regexes set during construction. Regexes are read-only once compiled (`*regexp.Regexp` is safe for concurrent use).

**Test**: Concurrent `Detect()` calls on the same recognizer instance must pass race detector.

### SEC-REQ-03 — NAME Recognizer Ordering

The NAME recognizer (`email_inference`) depends on EMAIL entity results. The Engine MUST guarantee that EMAIL detection completes before NAME detection begins. This can be implemented as:

- **Option A** (Recommended): Run all 8 independent recognizers concurrently, collect results, then run NAME recognizer as a second pass with EMAIL entities passed as a parameter or context.
- **Option B**: Run recognizers sequentially in dependency order (simpler, marginally slower).

NAME MUST NOT modify the EMAIL entity slice or share its backing array.

**Rationale**: Without ordering, NAME fires before EMAIL produces results, silently returning zero entities — a correctness bug, not a security bug, but it invalidates the recognizer's purpose.

### SEC-REQ-04 — Input Size Rejection

The `Engine.Detect()` method MUST reject inputs exceeding `maxInputBytes` before any recognizer runs. The rejection MUST:
- Return an error (not silently truncate)
- Not allocate meme-sized buffers based on input length before the length check
- Not log any part of the input
- Not perform regex or entropy computation on the oversized input

**Test**: Call `Engine.Detect()` with a 2 MiB string; verify error returned, zero entities, no panic, memory usage bounded.

### SEC-REQ-05 — Unbounded Quantifier Upper Limits

All regex quantifiers using `{N,}` (unbounded minimum) SHOULD include a realistic upper bound to reduce memory allocation on extremely long false-positive matches:

| Pattern | Current | Recommended |
|---------|---------|-------------|
| `sk-[A-Za-z0-9]{32,}` | {32,} | {32,256} |
| `Bearer [A-Za-z0-9_\-\.\+/=]{20,}` | {20,} | {20,1024} |
| `base64{20,}={0,2}` | {20,} | {20,1024} |
| `hex{32,}` | {32,} | {32,256} |

The 1 MiB bound provides a backstop, but intermediate unbounded matches on large inputs can produce oversized entity `Value` strings before the layer 1/2/3 filtering is complete. Bounding to realistic maximum token lengths (≤ 1024 for base64 tokens, ≤ 256 for API keys, ≤ 128 for hex) reduces memory pressure.

**ASVS**: V5.1.4 — Verify that input validation is enforced on a trusted service layer.

### SEC-REQ-06 — No Panic Guarantee

All recognizers MUST handle all possible inputs without panicking. Specifically:

- **Empty string** (`""`): Must return empty/nil slice
- **Null bytes** (`\x00`): Must not cause index-out-of-bounds or regex panic. Go `regexp` handles null bytes in input natively; verify.
- **Invalid UTF-8**: Go strings are always valid UTF-8 by construction. If `[]byte` is converted to `string`, invalid sequences become `\uFFFD`. Verify that range-loops and regex operations tolerate replacement characters.
- **100% one character repeated** (e.g., 1 MiB of `AAAA...`): Must not hang or allocate unreasonable memory.
- **Extremely long regex match candidates**: With the 1 MiB limit and bounded quantifiers (SEC-REQ-05), this is bounded.
- **Recursive/nested format strings**: JWT with base64url-encoded JSON that contains another base64url string — the recognizer only decodes the outer header.
- **Single-byte input**: Must not divide-by-zero or index-out-of-bounds in entropy computation.

**Test**: Fuzz every recognizer with `go test -fuzz=. -fuzztime=30s` (see SEC-REQ-15).

### SEC-REQ-07 — Error Handling Without Panic

Where a recognizer encounters an error condition (e.g., base64 decode failure in JWT header), it MUST:
- Return an empty result or a result with downgraded confidence
- NOT panic
- NOT call `log.Fatal` or `os.Exit`
- NOT allocate unbounded memory

`Recognizer.Detect()` MUST NOT return an `error` — the contract is `[]Entity` only. Internal errors are suppressed or reflected through confidence downgrade.

### SEC-REQ-08 — Entropy Computation Safety

The Shannon entropy implementation MUST:
- Use a single-pass O(n) algorithm with O(1) space, as specified
- Pre-compute `log2` table at package initialization or construction time (256-element `float64` array is 2 KB — acceptable)
- Handle single-character inputs correctly: entropy of single char = 0 (one unique symbol → -1 * log2(1) = 0)
- Handle zero-length inputs: entropy = 0; return early, no division by zero
- NOT use `math.Log2` per-character (expensive); use pre-computed table lookup
- NOT allocate per character (no `map[rune]int`, no `append` to dynamic structures in hot path)
- Use `[256]int` byte frequency counter on stack (not heap-allocated slice)

**Verification**: The formula is H = -Σᵢ (count(cᵢ) / n) · log₂(count(cᵢ) / n), where Σ is over unique bytes found in the candidate string. Implementation MUST match this exactly.

**Threshold justification**:
- Base64 threshold 3.5: Truly random base64 (64-char alphabet, uniform) → H ≈ 6.0. Structured base64 (e.g., protobuf, JSON gzip) → H ≈ 4.0–5.0. Natural language text → H ≈ 3.0–4.0. A 3.5 threshold captures random and semi-random tokens while excluding most text.
- Hex threshold 3.0: Hex alphabet (16 chars, uniform) → H ≈ 4.0. The 3.0 threshold is conservative, accepting slightly non-uniform hex that may still be secret material.

**Test**: Unit test with known-entropy strings: uniform 64-char alphabet → ~6.0, English prose → ~4.0, all-same-char → 0.0.

### SEC-REQ-09 — Regex Compilation Safety

All regexes MUST be compiled at construction time (in `NewRecognizer()` or `New*Recognizer()`), NOT in `init()` functions.

**Rationale**: `init()` functions:
- Run at package import time (non-deterministic ordering across packages)
- Make unit test isolation difficult
- Obscure compilation errors (panics in init are hard to debug)
- Prevent injection of test-specific regex configurations

**Construction-time compilation**:
- Provides deterministic, controllable initialization order
- Enables dependency injection for testing
- Makes compilation errors explicit and testable

**Implementation**: Each recognizer constructor MUST call `regexp.MustCompile()` or return an error if `regexp.Compile()` fails. Failing to compile a known-good regex is a programming error — `MustCompile` is acceptable for compiled-in patterns. For the prefix database, compile all ~100 regexes at construction time; fail-fast if any pattern is invalid.

**Additional requirements**:
- **(a)** All compiled `*regexp.Regexp` MUST be treated as immutable after construction. Never call `regexp.Regexp.Longest()` or any mutating method post-construction.
- **(b)** The complete combined PHONE regex MUST be supplied and audited. Ensure it does not use RE2-incompatible features (backreferences, lookahead/lookbehind).

### SEC-REQ-10 — Zero PII in Logs (Categorical)

The `Entity.Value` field MUST NEVER appear in:
- `slog` calls (INFO, WARN, ERROR, DEBUG)
- `fmt.Print`, `fmt.Printf`, `fmt.Println`
- Error messages (`fmt.Errorf`, `errors.New`, `%w` wrapping)
- Panic messages
- `t.Log`, `t.Logf`, `t.Error`, `t.Errorf`, `t.Fatal` in test code
- Debug prints (`log.Print`, stdout/stderr)
- Stringer interface (`fmt.Stringer` on Entity)
- JSON marshaling output (unless explicitly excluded via `json:"-"` tag)
- Stack traces (value may appear in goroutine stack dumps — NOT acceptable)

**Safe for logging**: `Entity.Type`, `Entity.Confidence`, `Entity.Source`, `Entity.Start`, `Entity.End`.

**Implementation**:
- `Entity` struct MUST have `Value string` without `json`, `log` tags that expose it
- `Entity.String()` or `Entity.SafeString()` MUST return format like `"EMAIL(src=regex, conf=0.85, pos=12-31)"` — type, source, confidence, positions only. NO value.
- `Entity.Format()` / `Entity.LogValue()` MUST NEVER include `Value`.
- `json:"-"` tag on `Value` field to prevent accidental serialization.

**ASVS**: V7.1.2 — Verify that the application does not log sensitive data.

**Test**: Grep all source files in `internal/pii/` and test files for `.Value` in log calls, string interpolation, or error wrapping. Automated CI check.

### SEC-REQ-11 — Test Data PII Audit

100% of test data MUST be synthetic:
- **Emails**: `@example.com`, `@test.invalid` domains only (RFC 2606 reserved)
- **Phones**: Fictional numbers (do NOT use `+33 6 12 34 56 78` — the "movie number")
- **IBANs**: Official test IBANs from banking standards
- **Credit cards**: Industry test numbers (`4111111111111111` for Visa, `5555555555554444` for Mastercard)
- **API keys**: `sk-test-{random}` prefix; must NOT match real key patterns
- **JWTs**: HS256 with `{"alg":"HS256","typ":"JWT"}` header, base64url payload `{"sub":"test"}`, fake signature
- **PEM keys**: Generated test keys with `openssl genpkey`; NEVER use production keys

**Test**: CI step that greps for real PII patterns in `internal/pii/*_test.go` (e.g., `@(gmail|yahoo|outlook|hotmail|proton)`, non-test credit card BIN prefixes `^(?:3[47]|4[0-9]{5}|5[1-5])`).

### SEC-REQ-12 — Memory Independence

Each call to `Recognizer.Detect()` and `Engine.Detect()` MUST return a slice with an independent backing array. Re-slicing or sharing the backing array of the input `text` string is prohibited because:
- The input string may be freed by the caller
- Concurrent detection could read/write the same backing memory through string headers

**Implementation**: Use `append` to a newly allocated slice or `make`+`copy` for entity results. Do not use the slice expression `entities[start:end]` on a shared underlying array.

### SEC-REQ-13 — Prefix Database Integrity

The ~100-pattern prefix database MUST:
- Be compiled-in as a `var` or `const` table (no runtime loading from files or network)
- Use case-sensitive prefix matching (API keys ARE case-sensitive)
- Validate that prefix strings are unique (no duplicate prefixes causing lookup ambiguity)
- Compile all associated regexes at construction time; fail-fast on invalid patterns
- Include `MinLength` guard: do not attempt full regex match if the candidate string is shorter than the minimum token length for that provider

**Prefix overlap handling**: If two prefixes share a common prefix string (e.g., `sk-` and `sk-proj-` are both OpenAI patterns), the longer prefix MUST be checked first. Implement by sorting the prefix index by descending length or by using a trie-like lookup.

### SEC-REQ-14 — Fuzz Testing Coverage

Each recognizer MUST have a fuzz test (`*_fuzz_test.go` or `*_test.go` with `Fuzz*` function) that:
- Feeds random byte sequences to `Recognizer.Detect()`
- Verifies no panic, no excessive memory allocation
- Verifies `Start ≤ End` and `End ≤ len(text)` for all returned entities
- Verifies `Confidence` is in [0.0, 1.0] range
- Runs for minimum 30 seconds in CI

**Recognizers requiring fuzz tests**: all 9 recognizers plus `Engine.Detect()`.

**Additional**: Fuzz the overlap resolution algorithm directly with random overlapping entity collections.

### SEC-REQ-15 — Adversarial Input Benchmarks

The following adversarial inputs MUST be benchmarked per recognizer and MUST complete within 5 seconds on a single core:

| Input | Description | Target |
|-------|-------------|--------|
| 1 MiB of `A` repeated | Single-char monotone string | All recognizers |
| 1 MiB of random ASCII | Uniform distribution | All recognizers |
| 1 MiB of valid emails joined by semicolons | High-match-density input | EMAIL recognizer |
| 1 MiB of `A-Za-z0-9+/=` random | Base64-appearing noise | SECRET (entropy) |
| 1 MiB of alternating `0-9a-f` | Hex-appearing noise | SECRET (entropy) |
| 1000 valid PEM blocks concatenated | High structural matches | PRIVATE_KEY |

**Test**: `go test -bench=. -benchtime=1x ./internal/pii/...` with these inputs in `*_bench_test.go` files.

### SEC-REQ-16 — Entity Span Validation

Every returned `Entity` MUST satisfy:
- `0 ≤ Entity.Start < Entity.End ≤ len(text)`
- `Entity.Value == text[Entity.Start:Entity.End]` (value must exactly match the substring at those offsets)
- `Entity.Confidence` in range `[0.0, 1.0]`

**Test**: Assert these invariants in every recognizer unit test and the `Engine.Detect()` integration test.

### SEC-REQ-17 — Overlap Resolution Determinism

The overlap resolution algorithm MUST be deterministic:
- Same input → same output every time (no map iteration order dependency)
- Same registration order → same priority
- Tie-breaking rules applied in strict order: confidence → type priority → span length → registration order

**Test**: Call `Engine.Detect()` 100 times on the same input with concurrent goroutines; verify identical results.

---

## 6. ADR Compliance Checklist

| ADR | Requirement | Status |
|-----|------------|--------|
| **ADR-001** | Package path `internal/pii/` | ✅ Story specifies `internal/pii/`; matches ADR-001's `internal/` convention. |
| **ADR-001** | Tests co-located or external per strategy | ✅ Story lists `*_test.go` alongside source files, consistent with ADR-007 (unit tests in-package). Integration tests deferred. |
| **ADR-004** | Entity model compatible with Interceptor interface | ✅ Entities carry `Start`/`End` byte offsets → `PIIInterceptor` (QINDU-0007) can use these for tokenization. `Source` field enables mode-dependent policies. `Confidence` enables threshold filtering in interlceptor. |
| **ADR-008** | Zero PII in structured logs | ✅ `Entity.SafeString()` with no `Value`. Flag `pii_values_logged: false`. |
| **ADR-008** | slog JSON format | N/A — this sprint creates the engine; logging integration is in QINDU-0007 interceptor. However, the `SafeString()` method MUST produce slog-safe output. |
| **ADR-009** | Concurrency model (goroutine per connection) | ✅ `Engine.Detect()` is concurrent-safe (RWMutex). Recognizers are stateless. Each HTTP request in the proxy (QINDU-0001) will call `Detect()` in its own goroutine. |

No ADR violations detected.

---

## 7. False Positive Mitigation Review

### Global Exclusion Patterns

| Pattern | Security Assessment |
|---------|-------------------|
| UUID exclusion (`8-4-4-4-12`) | ✅ Safe. UUIDs are system-generated, not secrets. |
| Exact hash length exclusions (32, 40, 64, 128 hex) | ⚠️ **Residual risk**: A secret that happens to be exactly 32 hex chars would be missed. Assessment: acceptably low risk. Git SHAs and MD5/SHA hashes are far more common than 32-char hex secrets. If a secret is exactly 32 hex chars, it's also structurally a hash — false-positive reduction justifies this. |
| Placeholder values (true, false, null, example, test, demo, sample) | ✅ Safe. These are never real secrets. |
| Dot-separated identifiers | ✅ Safe. Java/golang package paths are not secrets. |
| ALL_CAPS identifiers | ✅ Safe. Environment variable names, not values. |
| URL query strings | ⚠️ Requires careful implementation. The exclusion should only apply to URL contexts (scheme://host/path?key=value), NOT to `token=value` in JSON bodies. See SEC-REQ-18. |

### SEC-REQ-18 — URL Context Detection

When excluding URL query strings from secret detection, the exclusion logic MUST:
- Only apply when the match occurs within a context that starts with `http://` or `https://` within the preceding 2000 characters
- NOT exclude matches in JSON bodies, YAML, or plain text where `token=...` appears without a URL scheme prefix
- NOT exclude matches where the URL is part of a formatted code block that may contain real secrets

---

## 8. Mandatory Security Tests (CI Gates)

| # | Test | Command / Method | Gate |
|---|------|-----------------|------|
| T1 | Race detector | `go test -race -count=100 ./internal/pii/...` | BLOCK if any race detected |
| T2 | Fuzz all recognizers | `go test -fuzz=. -fuzztime=30s ./internal/pii/...` | BLOCK if any panic |
| T3 | Coverage | `go test -coverprofile=coverage.out ./internal/pii/...` → ≥ 95% statement | BLOCK if < 95% |
| T4 | Lint | `golangci-lint run ./internal/pii/...` | BLOCK if > 0 issues |
| T5 | PII in logs grep | `rg -n '\.Value\b' internal/pii/*.go \| rg -v '_test.go' \| rg -v '//'` | BLOCK if Value appears in log/error context |
| T6 | PII in test data | `rg -n '@(gmail\|yahoo\|outlook\|hotmail\|proton)' internal/pii/*_test.go` | BLOCK if real email domains found |
| T7 | No `init()` functions | `rg -n '^func init\b' internal/pii/` | BLOCK if any `init()` found |
| T8 | No `os.Exit`, `log.Fatal` in recognizers | `rg -n 'os\.Exit\|log\.Fatal\|log\.Panic' internal/pii/*.go` (excl. test files) | BLOCK if found |
| T9 | Adversarial benchmarks | `go test -bench=. -benchtime=1x ./internal/pii/...` | BLOCK if > 5s per bench |
| T10 | Entity span invariants | Asserted in all _test.go files | BLOCK if any entity fails span checks |

---

## 9. Residual Risks

| # | Risk | Severity | Acceptance Rationale |
|---|------|----------|---------------------|
| R1 | **Exact-length hex hash false negatives**: A secret that is exactly 32, 40, 64, or 128 hex chars will be excluded. | Low | Such secrets are indistinguishable from cryptographic hashes. The false-positive rate from flagging every git SHA and MD5 hash would render the engine unusable. |
| R2 | **Unbounded quantifiers cause large allocations**: `{32,}` patterns on false-positive matches could allocate large `Value` strings. | Low | The 1 MiB input bound is the backstop. SEC-REQ-05 adds upper bounds to reduce this. |
| R3 | **Unicode/homoglyph evasion**: Attacker substitutes Latin `a` with Cyrillic `а` (U+0430) to evade email detection. | Low | Unicode normalization is out of V1 scope. A local attacker who controls the input to their own proxy has little incentive to evade it. For chat contexts, Unicode confusables are rare in legitimate API keys and emails. |
| R4 | **Chunked/streaming evasion**: An email split across two chunks may not be detected. | Low | Chunk assembly is QINDU-0007's concern. This sprint operates on complete strings. |
| R5 | **Prefix database staleness**: New API key formats introduced after compilation won't be detected. | Low | The database covers all major active formats from GitGuardian's 500+ detectors. Expansion requires a code change and rebuild — intentional design for attack surface minimization. |
| R6 | **NAME recognizer false positives**: A legitimate technical email like `john.tool@corp.com` could be misidentified as "John Tool". | Low | Confidence is 0.70 at best; the tokenizer can apply a higher threshold. The `Source: email_inference` tag enables tokenizer policy to treat these differently. |
| R7 | **Secret prefix short-match false positives**: Prefix `T` (Telegram) could match non-secret strings starting with 'T'. | Low-Medium | The associated regex `T[0-9]{8,10}:[A-Za-z0-9_-]{35}` requires 9-11 digits after 'T' followed by colon and 35 specific chars. False-positive rate empirically very low. Confidence 0.85 provides a filter. |
| R8 | **No cryptographic JWT validation**: Invalid signatures are accepted as secrets. | Low | Cryptographic operations are explicitly out of scope. Accepting all structurally-valid JWTs as secrets is conservative (false positive on legitimate non-secret JWTs) but safe (never false negative). |
| R9 | **Secret prefix overlap**: Patterns like `sk-` and `sk-proj-` share prefixes. | Low | SEC-REQ-13 requires longest-prefix-first matching. The `sk-` generic pattern with 0.70 confidence acts as a fallback for unrecognized `sk-*` sub-prefixes. |
| R10 | **PII in crash dumps / core dumps**: If Qindu crashes, a core dump could contain `Entity.Value` strings on the stack/heap. | Low | Qindu is user-installed local software. Core dumps are accessible only to the user (who already knows their own PII). No remote attacker can access local core dumps. |

---

## 10. Implementation Checklist for DevSecOps

The following must be evident in the delivered implementation (`dev-notes.md` + source):

- [ ] All 9 recognizers implement `Recognizer` interface
- [ ] `Engine` has `sync.RWMutex` and enforces `maxInputBytes`
- [ ] `Entity.Value` has `json:"-"` tag
- [ ] `Entity.SafeString()` or `String()` returns no `Value`
- [ ] All regexes compiled in constructors (zero `init()` functions)
- [ ] NAME recognizer receives EMAIL entities from Engine, not from concurrent detection
- [ ] All unbounded quantifiers bounded per SEC-REQ-05
- [ ] Entropy: single-pass O(n), O(1) space, pre-computed log2 table, `[256]int` counter
- [ ] Fuzz tests for all 9 recognizers + Engine
- [ ] Adversarial benchmarks for all recognizers
- [ ] Prefix database sorted by prefix length descending (longest-first lookup)
- [ ] No `os.Exit`, `log.Fatal`, `log.Panic` in recognizer code
- [ ] All test data synthetic per SEC-REQ-11
- [ ] `go test -race -count=100` clean
- [ ] `golangci-lint run` clean
- [ ] 95%+ statement coverage on all non-test `.go` files

---

## 11. Verdict

**Verdict: PASS**

**Rationale**: QINDU-0005 is a well-designed, security-conscious sprint. The detection engine operates entirely in-memory with bounded input, uses Go's RE2 engine (inherently ReDoS-safe), mandates thread safety, and enforces zero-PII logging. The 9 recognizers cover the high-value PII categories without introducing network, filesystem, or cryptographic attack surfaces. The residual risks are low-severity and explicitly documented as accepted tradeoffs.

**Blocking conditions**: None at design time. However, the following would cause a BLOCKED verdict at review time (QINDU-0005 review gate):
1. `go test -race` detects any data race
2. Any recognizer panics on fuzz input
3. `Entity.Value` appears in any log, error, or test assertion output
4. Any `init()` function exists in `internal/pii/`
5. Any real PII found in test fixtures
