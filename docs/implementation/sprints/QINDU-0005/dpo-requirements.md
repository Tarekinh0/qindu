# DPO Requirements — QINDU-0005: Moteur PII Go-native — Recognizers

## Verdict: **PASS**

The design is privacy-by-default and GDPR-compliant for a detection-only, local, in-memory processing engine. No blocking issues identified. All residual risks have adequate mitigations in the design or are controllable in subsequent sprints (QINDU-0006, QINDU-0008).

---

## 1. Story Summary

QINDU-0005 implements a pure detection engine (9 recognizers) that identifies PII entities in free text. The engine runs entirely in memory on the user's machine, with zero persistence, zero network access, and zero filesystem access. Entities flow through the `Interceptor` interface defined in ADR-004. This sprint is **detection-only** — no tokenization, no vault, no upstream modification. The output is an `[]Entity` slice with type, value, confidence, provenance, and byte offsets.

Recognizers: EMAIL, PHONE, IBAN (MOD-97), CREDIT_CARD (Luhn), JWT (structural), NAME (email inference), SECRET (prefix-based, ~100 patterns), SECRET (generic entropy), PRIVATE_KEY (PEM armor).

---

## 2. Data Processed — PII Categories

| Category | Detection Source | Data Type | GDPR Classification |
|----------|-----------------|-----------|-------------------|
| EMAIL | Regex (RFC 5322 simplified) | Direct PII | Personal data (Art. 4(1)) |
| PHONE | Regex (E.164, NANP, FR, INTL) | Direct PII | Personal data |
| IBAN | Regex + MOD-97 checksum | Direct PII | Personal data (financial) |
| CREDIT_CARD | Regex + Luhn checksum | Direct PII | Personal data (financial, Art. 9 sensitive in some interpretations) |
| JWT | Structural (base64url segments) | Indirect PII / credential | Personal data + security credential |
| NAME (inferred) | Email local-part inference | Derived PII | Personal data — **special attention required** |
| SECRET (prefix) | Known API key patterns | Security credential | Not personal data per se, but confidential |
| SECRET (entropy) | Shannon entropy + keyword pre-filter | Security credential | Not personal data per se, but confidential |
| PRIVATE_KEY | PEM/SSH/PGP armor detection | Security credential | Not personal data per se, but highly confidential |

**Data flow**: Browser prompt text → `Engine.Detect()` → `[]Entity` slice → returned to caller (eventually `PIIInterceptor` in QINDU-0007). No data leaves the process. No data is stored. All processing is ephemeral.

---

## 3. Purpose (Why This Processing Is Necessary)

Qindu's stated purpose is to protect users from accidentally sending PII to web-based AI services. Detection is the prerequisite gate: without knowing *what* is PII, Qindu cannot tokenize it.

The processing is necessary for:
1. **PII identification** — the engine must read prompt text to find PII spans
2. **Accuracy** — confidence scoring and overlap resolution ensure reliable detection
3. **Provenance tracking** — the `Source` field enables downstream tokenization policy decisions (e.g., inferring that NAME from `email_inference` should be scoped globally)

This processing aligns with Qindu's core functionality and does not exceed what is necessary.

---

## 4. Minimization Basis (Why Less Would Not Work)

The design minimizes data collection at every layer:

| Minimization Decision | Rationale |
|----------------------|-----------|
| Detection-only (no storage) | This sprint does not persist anything — entities exist only in the `[]Entity` return slice |
| In-memory only | No filesystem, no database, no network calls. ADR-008: decrypted PII only in memory-backed storage |
| Byte offsets, not copies | Entities reference positions in the original text — no data duplication beyond the `Value` field itself |
| No metadata beyond detection | Entities carry only `Type`, `Value`, `Confidence`, `Source`, `Start`, `End` — no user identity, no timestamp, no session ID |
| Input size bound (1 MiB) | Prevents memory exhaustion; inputs exceeding the bound are rejected entirely |
| Stop-word filtering (NAME) | Reduces unnecessary derived PII from role accounts (`support@`, `noreply@`, etc.) |
| Keyword pre-filter (entropy) | Shannon entropy only calculated when secret-related keywords are nearby — avoids processing non-secret text |
| `Value` never logged | `SafeString()` helper outputs only `Type(Confidence)` — zero PII in logs per ADR-008 |
| No persistent identifiers | The engine has no concept of users, sessions, or conversations — purely stateless |

**Why less would not work**: If the engine did not hold the detected `Value` in memory, downstream tokenization (QINDU-0006) could not replace PII with tokens. The `Value` field is a necessary transient artifact for the pipeline. Removing it would make tokenization impossible.

---

## 5. Rights and Freedoms Risks

### Risk 1: NAME Inference Produces False Positives (Derived PII)
**Severity**: Medium
**Description**: The NAME recognizer infers person names from email local-parts (e.g., `jean.dupont@gmail.com` → "Jean Dupont"). If the source email is not a personal email (e.g., shared team inbox `john.smith@company.com`), the inferred name is inaccurate.

**GDPR implication**: Article 5(1)(d) requires personal data to be accurate. Article 16 grants the right to rectification. A false inferred name could be tokenized and treated as PII when it is not actually a real person's name.

**Mitigation in design**:
- Stop-word list blocks known role accounts (`support`, `noreply`, `admin`, `info`, `contact`, `team`, `service`, etc.)
- Numeric segments blocked (`jd42` → no name emitted)
- Single-segment local-parts blocked (`jdoe` → no name emitted)
- Confidence floor: 0.70 for clean matches, 0.40 for borderline
- The `Source: email_inference` provenance tag allows downstream policy to treat these with lower priority or different TTL

**Residual risk**: A false name may still be emitted (e.g., `john.smith@startup.io` where the email belongs to a shared account, not an individual). The downstream tokenization policy (QINDU-0006) should allow configurability. **Acceptable for V1** — the benefit of protecting real names outweighs the risk of false derived names. Users will see rehydrated names and can detect errors.

**DPO requirement**: QINDU-0006 must allow tokenization policy to treat `Source: email_inference` entities differently (e.g., shorter TTL, higher confidence threshold override, or user-configurable opt-out of NAME inference).

---

### Risk 2: Secret Detection Processes Credentials
**Severity**: Low-Medium
**Description**: The SECRET and PRIVATE_KEY recognizers detect API keys, tokens, and private keys in user prompts. While this is privacy-positive (prevents accidental leakage), the engine momentarily holds these credentials in the `Entity.Value` field.

**GDPR implication**: Not directly a GDPR concern (credentials are not personal data), but a confidentiality concern. If a bug or debug log accidentally exposed `Value`, actual cloud/service credentials could leak.

**Mitigation in design**:
- `SafeString()` helper and explicit ban on logging `Value`
- Acceptance criterion 18: "No PII values in any log output, error string, `t.Log`, or test assertion message"
- In-memory only, no persistence
- Input size bounds prevent memory dumps from large malicious payloads

**DPO requirement**: The `SafeString()` or equivalent redaction helper must be applied consistently. Consider a linter rule or CI check that detects `Entity.Value` appearing in `slog.*`, `fmt.*`, or `t.Log.*` calls within `internal/pii/`.

---

### Risk 3: Internet-Derived Prefix Database (IP)
**Severity**: Low
**Description**: The prefix database for SECRET detection is derived from GitGuardian and Gitleaks taxonomies (public knowledge). While this is not personal data, the compiled-in database means that if patterns ever include provider-specific formats that could become vectors for fingerprinting, this could be a concern.

**GDPR implication**: None directly. However, the prefix database must not contain any actual API keys, tokens, or secrets (even expired ones). The story specifies only prefix strings and regex patterns — never example values that were once live.

**Mitigation in design**: The prefix table contains only pattern metadata (prefix string, provider name, format regex, min/max length). No actual token values are hardcoded.

**DPO requirement**: Audit the compiled prefix table before merge — confirm zero actual API keys or tokens appear as string literals in `secret_prefix.go`. All entries must be patterns, not values.

---

### Risk 4: False Positives Masking Non-PII Text
**Severity**: Low
**Description**: False-positive PII detection could cause non-sensitive text to be tokenized in QINDU-0006, potentially breaking AI responses or creating confusing rehydrated output.

**GDPR implication**: Article 5(1)(d) (accuracy). If the engine marks non-PII as PII, it creates inaccurate data processing.

**Mitigation in design**:
- Global exclusion patterns (UUIDs, hex hashes, placeholders, ALL_CAPS identifiers)
- Recognizer-specific exclusions (URL paths, HTML entities, JSON keys)
- Confidence scoring with floors per recognizer
- Overlap resolution favoring higher confidence
- Luhn/MOD-97 validation reduces financial false positives to near-zero

**DPO requirement**: The overlap resolution algorithm must never elevate a false positive's confidence above its detected value. Confidence must only decrease through validation, never increase through heuristics.

---

### Risk 5: Multi-Line Detection Scope (PRIVATE_KEY)
**Severity**: Medium
**Description**: The PRIVATE_KEY recognizer performs multi-line detection, capturing the entire PEM block (header + body + footer). This means the engine holds a complete private key in `Entity.Value`.

**GDPR implication**: Private keys are not personal data, but they are highly confidential. Holding them in a string field, even transiently, is sensitive.

**Mitigation in design**:
- In-memory only — the `Value` string is garbage-collected after the `[]Entity` is consumed
- No serialization, no swap, no core dump exposure (mitigated at OS level)
- Input size bounds limit maximum key size

**DPO requirement**: The PRIVATE_KEY recognizer must detect and emit the full PEM block, but the engine must ensure that the `Entity.Value` for PRIVATE_KEY entities is never included in any error message, debug output, or test assertion. This is already stated in constraints #1 and #2 — verify in review mode.

---

## 6. Blocking Points

**None.** No critical GDPR violations identified. The design aligns with:
- **Article 5(1)(a)** — Lawfulness, fairness, transparency: User runs locally, no hidden processing
- **Article 5(1)(b)** — Purpose limitation: Detection only, no repurposing
- **Article 5(1)(c)** — Data minimisation: Ephemeral entities, no storage, minimal metadata
- **Article 5(1)(d)** — Accuracy: Confidence scoring, validation algorithms (Luhn, MOD-97), stop-word filtering
- **Article 5(1)(e)** — Storage limitation: No storage in this sprint (deferred to QINDU-0008, which will implement TTL)
- **Article 5(1)(f)** — Integrity and confidentiality: In-memory, local-only, no network, encrypted vault planned

All AGENTS.md non-negotiable rules are respected:
- ✅ No user accounts, telemetry, analytics, tracking, or persistent identifiers
- ✅ PII never logged (explicit `SafeString()` requirement)
- ✅ PII never stored unencrypted (no storage at all in this sprint)
- ✅ PII never sent to external services (detection-only, no network)
- ✅ Vault will be DPAPI-encrypted (deferred to QINDU-0008, blueprint respected)
- ✅ Decrypted PII in memory-backed storage only
- ✅ No ADRs weakened (ADR-004, ADR-008 explicitly referenced and respected)

---

## 7. Approvals of Key Design Decisions

### 7.1 NAME Inference from Email — **APPROVED with conditions**

The email-to-name inference is a legitimate privacy feature: it protects the user's actual name derived from their email address. The stop-word list, segment validation, and confidence scoring provide reasonable false-positive controls.

**Conditions**:
1. The stop-word list must be documented as a named constant with a comment explaining its purpose (prevent role accounts from generating false NAME entities).
2. QINDU-0006 must enable different tokenization policies based on `Source: email_inference` (e.g., configurable TTL, opt-out).
3. Future sprints should consider a user-facing configuration to disable NAME inference entirely.

### 7.2 Secret Detection — **APPROVED**

Detecting API keys and tokens in user prompts is privacy-positive: it prevents accidental credential leakage to AI providers. The prefix-based approach with ~100 curated patterns is well-scoped. The entropy-based approach is appropriately conservative (keyword pre-filter, entropy thresholds, length minimums).

**Condition**: The compiled prefix database must be auditable — all entries should be in a single, clearly-commented Go file with no actual secrets hardcoded.

### 7.3 Entity Model with `Source` Provenance — **APPROVED**

The `Source` field is essential for GDPR-compliant data lifecycle management. It enables:
- **Purpose limitation**: Downstream systems know *how* data was detected and can apply purpose-specific policies
- **Storage limitation**: Tokenization in QINDU-0006 can assign different TTLs based on detection source
- **Accuracy**: Audit trails can distinguish between direct detection (regex, Luhn) and inference (email_inference, entropy)
- **Right to erasure**: Entities with `Source: email_inference` can be selectively purged without affecting directly-detected PII

This is a model of privacy-by-design.

### 7.4 Overlap Resolution Algorithm — **APPROVED**

The hierarchical resolution (confidence → type priority → span length → registration order) is deterministic, auditable, and favors more reliable detection methods. The rule that adjacent non-overlapping entities both survive is correct — sharing a boundary does not indicate conflict.

### 7.5 Input Size Bound (1 MiB) — **APPROVED**

The 1 MiB limit prevents memory exhaustion attacks and aligns with data minimization principles. Rejecting oversized inputs (rather than silently truncating) is the correct behavior — truncation could create undetected PII. The user receives clear feedback that their input was too large.

---

## 8. Required Privacy Tests

The following privacy-specific tests must be present in the implementation:

### PII-in-Log Prevention
| Test ID | Description |
|---------|-------------|
| DPO-T01 | `entity.SafeString()` must never include `entity.Value` — returns only `"TYPE(0.XX)"` format |
| DPO-T02 | For every recognizer, verify that error paths never include the matched value in error strings |
| DPO-T03 | `Engine.Detect()` error for oversized input must not echo the input text |

### Synthetic Test Data
| Test ID | Description |
|---------|-------------|
| DPO-T04 | All email test fixtures use the `@example.com` domain (IANA-reserved) |
| DPO-T05 | All phone test fixtures use numbers from designated test ranges (e.g., ITU-T test numbers, or obviously fake series) |
| DPO-T06 | All IBAN test fixtures use test IBANs from official test banks |
| DPO-T07 | All credit card test fixtures use synthetic test numbers (e.g., Visa `4111111111111111`) |
| DPO-T08 | All API key test fixtures use recognizably fake prefixes and values (e.g., `sk-test-deadbeef...`) |
| DPO-T09 | All JWT test fixtures use test tokens with `"alg":"none"` or clearly fake payloads |
| DPO-T10 | No test file contains strings that could plausibly be real PII (grep for real-looking emails, phone numbers) |

### NAME Inference Privacy
| Test ID | Description |
|---------|-------------|
| DPO-T11 | NAME recognizer does NOT fire on any email whose local-part is in the stop-word list |
| DPO-T12 | NAME recognizer does NOT fire on purely numeric local-part segments |
| DPO-T13 | NAME recognizer does NOT fire on single-segment local-parts without a separator (`.` or `_`) |
| DPO-T14 | NAME recognizer confidence never exceeds 0.70 for inferred names |
| DPO-T15 | NAME recognizer does NOT fire on emails where the local part contains the word "test" or "demo" |

### Data Minimization
| Test ID | Description |
|---------|-------------|
| DPO-T16 | `Engine.Detect()` returns nil or empty slice (not a non-nil zero-length slice with backing array) for input with no PII |
| DPO-T17 | Recognizers perform zero network calls (can be verified by code review — all detection is pure computation) |
| DPO-T18 | Recognizers perform zero filesystem access (no `os.Open`, no `os.ReadFile`, no `embed`) |
| DPO-T19 | No `context.Context` usage in recognizers that could carry user identity |

### Thread Safety
| Test ID | Description |
|---------|-------------|
| DPO-T20 | Concurrent calls to `Engine.Detect()` do not share mutable state containing PII values |
| DPO-T21 | `go test -race` passes cleanly (already acceptance criterion #17) |

---

## 9. Requirements for Implementation

These are binding requirements the DevSecOps agent must satisfy:

### R1: SafeString() Helper
Every `Entity` must have a method `SafeString() string` that returns only `Type(Confidence)` — e.g., `"EMAIL(0.85)"`. This must be the **only** method used when logging entity information. The `Value` field must carry a Go doc comment: `// Value contains the detected PII. MUST NEVER BE LOGGED. Use SafeString() for logging.`

### R2: Logging Hygiene
- Zero occurrences of `entity.Value`, `e.Value`, or `.Value` in any `slog.*` call, `fmt.Print*` call, `t.Log*` call, or `error.Error()` format string within `internal/pii/`.
- Error messages must reference only `Start`/`End` offsets and `Type`, never the matched text.
- The oversized-input rejection error must return `ErrInputTooLarge` containing only the max size and actual size — never the input text.

### R3: Synthetic Test Data
All test fixtures must use exclusively synthetic data. The following are explicitly prohibited in test files:
- Domains other than `example.com`, `example.org`, `example.net` (IANA-reserved), or `test.com`
- Phone numbers that could be real (use `+33 6 99 99 99 99` style — clearly fake)
- Real IBANs (use test IBANs from official sources)
- Real credit card numbers (use designated test numbers)
- Real or once-live API keys (any prefix)
- Real JWT tokens (even expired ones)
- Real PEM private keys (even generated for testing — use short, clearly fake test keys)

### R4: No Global State for PII
Recognizers must not use package-level variables to store PII values. All PII data must be scoped to the `Detect()` call's return value. `sync.Pool` or other buffer reuse must never leak PII between calls.

### R5: No PII in Test Names or Comments
Test function names, test case descriptions, and comments must not contain strings that could be mistaken for real PII. Use descriptive placeholder names like `"Jean Dupont"` (a well-known generic French name) rather than unusual or potentially real names.

### R6: Future-Proofing for QINDU-0006
The `Source` field on `Entity` must support being used as a key/selector for tokenization policy. It must be a defined type (`SourceKind string`) with typed constants, not arbitrary strings. This ensures the tokenizer in QINDU-0006 can reliably switch on provenance.

### R7: Audit Trail for Prefix Database
The `secret_prefix.go` file must include a comment at the top explaining the provenance of the prefix data (GitGuardian taxonomy, Gitleaks default config) and state that no actual secrets are hardcoded. Each prefix entry should have a comment identifying the provider.

### R8: Data Protection by Default
The engine must start with all 9 recognizers active by default. The `maxInputBytes` default must be 1 MiB. Inputs exceeding this limit must be rejected with an error — never truncated or silently processed.

---

## 10. Summary

The QINDU-0005 design demonstrates strong privacy-by-design principles:

- **Detection-only**: No persistence, no network, no side effects
- **Local execution**: Everything happens on the user's machine
- **Minimal data**: Only what's needed for detection — byte offsets, type, confidence, source
- **No logging of PII**: `SafeString()` helper, explicit ban on logging `Value`
- **Synthetic tests**: No real PII in test fixtures
- **Provenance tracking**: `Source` field enables granular privacy policies downstream
- **Deterministic, auditable**: Overlap resolution, confidence scoring, exclusion patterns are all reviewable

**Verdict: PASS** — The sprint may proceed to implementation with the conditions and requirements above.

---

*DPO Review by qindu-dpo. Date: 2026-06-27. Next review gate: Review Mode after DevSecOps delivers `dev-notes.md`.*
