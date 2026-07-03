# QINDU-0006: Tokenisation

## Metadata

| Field | Value |
|---|---|
| **Sprint ID** | QINDU-0006 |
| **Title** | Tokenisation |
| **Phase** | 2 — Moteur PII |
| **Status** | READY |
| **ADR Ref** | ADR-004 |
| **Go Version** | 1.26 |

## Dependencies

| ID | Title | Status |
|---|---|---|
| QINDU-0005 | Moteur PII Go-native — Recognizers | DONE |
| QINDU-0001 | Proxy TLS local sélectif — Fondation | DONE (interceptor interface exists) |

## Gates Required

| Gate | Agent | Stage |
|---|---|---|
| Privacy by Design | DPO | Design + Review |
| Security Review | CISO | Design + Review |
| Quality Assurance | QA | Validation |

## Forbidden

- Real PII in test fixtures — use synthetic data only
- PII in logs, error messages, or debug output
- Persistence of token↔PII mapping on disk (this sprint is memory-only; vault comes later)
- Modification of ADRs
- Modification of the existing `internal/pii/` package

---

## Functional Description

**What it does**: Given a text containing PII, the tokenizer replaces every detected PII entity with a stable, reversible placeholder token, and can later restore the original PII from those tokens.

**Input**: Arbitrary text (up to 1 MiB) that may contain PII entities.

**Output**: The same text with PII replaced by tokens, plus a mapping that allows restoring the originals.

**Reversibility**: The reverse operation restores tokens back to the original PII values. Text containing no tokens passes through unchanged.

## Token Format

Tokens follow the pattern `<<TYPE_N>>` where:
- `TYPE` is the uppercase entity type among: `EMAIL`, `PHONE`, `IBAN`, `CREDIT_CARD`, `JWT`, `NAME`, `SECRET`, `PRIVATE_KEY`
- `N` is an integer counter, starting at 1 and incrementing per type

Example: `<<EMAIL_1>>`, `<<PHONE_3>>`, `<<IBAN_2>>`

## Behavioral Rules

1. **Deterministic per conversation**: The same PII value encountered multiple times within a single conversation produces the same token every time. Counters are per-type and never reset mid-conversation.

2. **No cross-conversation guarantee**: Tokens between different conversations are independent. New conversation = fresh counters.

3. **Entity ordering**: PII entities are replaced starting from the end of the text (right-to-left) so that byte offsets of earlier entities remain valid during replacement.

4. **No PII in tokens**: The token string itself must not encode, hash, or embed any part of the PII value. The only link is the in-memory mapping.

5. **Token stability**: The same input text tokenized twice within the same conversation yields identical output.

6. **Safe for concurrent use**: Multiple goroutines can tokenize/rehydrate concurrently without data races.

## Acceptance Criteria

1. **Tokenization — single PII**: A text containing one email is transformed into the same text with `<<EMAIL_1>>` replacing the email.

2. **Tokenization — multiple PII, same type**: A text with three emails produces `<<EMAIL_1>>`, `<<EMAIL_2>>`, `<<EMAIL_3>>`.

3. **Tokenization — multiple PII, different types**: Mixed entities (email, phone, IBAN) each get their own type counter.

4. **Rehydration — round-trip**: `rehydrate(tokenize(text))` produces the original text byte-for-byte.

5. **Rehydration — partial tokens**: Text fragments that look like tokens but don't match any stored mapping are left as-is.

6. **Deterministic re-tokenization**: Tokenizing the same text twice within the same conversation produces identical token strings.

7. **Empty input**: Empty or whitespace-only input produces empty output with no error.

8. **No PII in output**: Tokenized text contains zero original PII values. The `<<TYPE_N>>` placeholders are the only replacements.

9. **Input bounds**: Input exceeding 1 MiB is rejected with a clear error (no PII in the error message).

10. **Tests**: All tests use synthetic PII only. Tests pass with `go test -race`. No `golangci-lint` issues.

## Out of Scope

- Integration with HTTP proxy or interceptor
- Streaming or chunked processing
- Persistent storage or encryption of the token mapping
- Fuzzing or benchmarks

## Design Decisions (from grilling)

| Decision | Choice |
|---|---|
| Token storage | In-memory, volatile |
| Token format | `<<TYPE_N>>` incremental |
| API surface | Whole-text processing (not streaming) |
| Package scope | Library only, no proxy dependency |
