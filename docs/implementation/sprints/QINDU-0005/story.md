# QINDU-0005: Moteur PII Go-native — Recognizers

## Status
READY

## Dependencies
- QINDU-0001: Proxy TLS local sélectif — **DONE** ✅

## ADR References
- ADR-004: Pipeline de données - interface Interceptor (entities flow through `InterceptRequest`/`InterceptResponse`)
- ADR-001: Go module and project structure (`internal/pii/` package)
- ADR-008: Structured logging slog JSON no PII (recognizers must never log PII values)

---

## Narrative

### Problem
Qindu currently proxies AI traffic transparently via `NoOpInterceptor` — zero inspection. Before we can tokenize PII (QINDU-0006) or store it in a vault (QINDU-0008), we need a detection engine that identifies PII entities in free text. This is the detection-only layer: zero storage, zero network, pure in-memory string analysis.

### Research foundation
This story is informed by analysis of:
- **Gitleaks** (Go-native secrets scanner, 27k+ stars): default config with ~120 specific rules + generic rules using regex + Shannon entropy
- **GitGuardian** (500+ detectors): taxonomy of secrets by provider, category, and detection method; Generic High Entropy Secret is the dominant pattern (24,561 occurrences per million commits)
- **Gitleaks blog**: *"Regex is (almost) all you need"* — the detection philosophy

---

## Recognizer Catalog (9 recognizers)

| # | Recognizer | Source tag | Detection method | Confidence floor |
|---|-----------|-----------|-----------------|-----------------|
| 1 | EMAIL | `regex` | RFC 5322 simplified regex, TLD whitelist | 0.85 |
| 2 | PHONE | `regex` | FR/EU (ITU-T E.164), US/CA (NANP), INTL variants | 0.75 |
| 3 | IBAN | `mod97` | Country-code-prefixed regex + MOD-97 checksum validation | 0.95 |
| 4 | CREDIT_CARD | `luhn` | Issuer-prefixed regex (visa/mc/amex/discover) + Luhn checksum | 0.95 |
| 5 | JWT | `structural` | Three base64url segments separated by dots, header decodes to valid JSON | 0.80 |
| 6 | NAME (email inference) | `email_inference` | Extract `first.last` / `first_last` local-parts from EMAIL entities; split, title-case; excludes roles, numerics, single-char segments | 0.70 |
| 7 | SECRET (prefix-based) | `prefix` | ~100 known API key/token prefix patterns from GitGuardian/Gitleaks taxonomy, organized by provider | 0.85 |
| 8 | SECRET (generic entropy) | `entropy` | Shannon entropy ≥ 3.5 on base64-like strings (≥20 chars) or ≥ 3.0 on hex strings (≥32 chars), keyword pre-filtered | 0.65 |
| 9 | PRIVATE_KEY | `pem_armor` | PEM/SSH/PGP armor header/footer block detection (`-----BEGIN ... PRIVATE KEY-----`) | 0.90 |

---

## Entity Model

```go
package pii

// EntityType identifies the kind of PII detected.
type EntityType string

const (
    Email       EntityType = "EMAIL"
    Phone       EntityType = "PHONE"
    IBAN        EntityType = "IBAN"
    CreditCard  EntityType = "CREDIT_CARD"
    JWT         EntityType = "JWT"
    Name        EntityType = "NAME"
    Secret      EntityType = "SECRET"
    PrivateKey  EntityType = "PRIVATE_KEY"
)

// SourceKind tags how the entity was detected (provenance).
// Enables granular tokenization policy in QINDU-0006.
type SourceKind string

const (
    SourceRegex          SourceKind = "regex"
    SourceLuhn           SourceKind = "luhn"
    SourceMod97          SourceKind = "mod97"
    SourceStructural     SourceKind = "structural"
    SourceEmailInference SourceKind = "email_inference"
    SourcePrefix         SourceKind = "prefix"
    SourceEntropy        SourceKind = "entropy"
    SourcePEMArmor       SourceKind = "pem_armor"
)

// Entity represents a detected PII instance with position and metadata.
type Entity struct {
    Type       EntityType // What kind of PII
    Value      string     // The detected value (MUST NEVER BE LOGGED)
    Confidence float64    // 0.0–1.0 detection confidence
    Source     SourceKind // How it was detected (provenance)
    Start      int        // Byte offset in original text
    End        int        // Byte offset (exclusive)
}
```

**Critical rule**: The `Value` field contains actual PII. It must never appear in log output (`slog`), error messages, debug prints, or test assertion messages. Logging helpers must redact `Value` and output only `Type`, `Confidence`, `Source`, `Start`, `End`.

---

## Engine API

```go
package pii

import "sync"

// Recognizer is the interface each detector implements.
// Each recognizer is responsible for one entity type.
type Recognizer interface {
    // Detect scans text and returns all detected entities of its type.
    // Returns nil or empty slice if nothing found.
    // Must never panic; all errors are returned as empty results.
    Detect(text string) []Entity

    // Type returns the entity type this recognizer detects.
    Type() EntityType
}

// Engine orchestrates all recognizers, runs detection, resolves overlaps.
// Safe for concurrent use.
type Engine struct {
    mu          sync.RWMutex
    recognizers []Recognizer
    maxInputLen int // reject inputs larger than this
}

// NewEngine creates a new detection engine with the given recognizers.
// Order matters for overlap resolution (first registered = higher priority).
func NewEngine(maxInputBytes int, recognizers ...Recognizer) *Engine

// Detect runs all recognizers, resolves overlapping spans, returns
// deduplicated entities sorted by byte position.
func (e *Engine) Detect(text string) []Entity
```

### Detection pipeline

```
text → [recognizer.Detect() × N] → merge all entities → sort by position → resolve overlaps → return
                                                         ↓
                                    filter: reject if confidence < threshold
```

### Overlap resolution algorithm

When two entities share bytes (overlapping byte spans `[Start, End)`):
1. Higher confidence wins
2. If confidence equal: entity type priority wins: EMAIL > PHONE > IBAN > CREDIT_CARD > JWT > NAME > SECRET > PRIVATE_KEY
3. If same type: longer span wins (more specific match)
4. If same length: first registered recognizer wins (registration order)

Entities that share boundaries exactly (End_A == Start_B) are NOT overlapping — both survive.

### Input size bounds

- Default `maxInputBytes`: **1,048,576** (1 MiB)
- Inputs exceeding this are rejected with an error (not truncated, not silently processed)
- Rationale: prevents memory exhaustion from maliciously large chat messages

---

## Recognizer Specifications

### 1. EMAIL Recognizer

**Source**: `regex`

**Regex** (simplified RFC 5322, compiled at init time):
```
[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}
```

**Validation**:
- TLD must be ≥ 2 alpha chars (no bare `@com`, no `@.com`)
- Domain must not start/end with hyphen
- No consecutive dots
- Total length ≤ 254 chars (RFC 5321)

**False positive rejection**: `noreply@`, `no-reply@`, `mailer-daemon@`, `root@localhost`

**Confidence**: 0.85 (regex match), 0.90 (validated domain)

---

### 2. PHONE Recognizer

**Source**: `regex`

**Formats detected**:
- **FR**: `+33 X XX XX XX XX`, `0X XX XX XX XX`, with separators (`.`, `-`, ` `)
- **EU/INTL**: `+XX ...` (E.164), 7-15 digits total
- **US/CA (NANP)**: `+1 (XXX) XXX-XXXX`, `(XXX) XXX-XXXX`, `XXX-XXX-XXXX`
- **INTL generic**: `+[1-9][0-9]{0,2}[ .-]?[0-9]{4,14}`

**Validation**:
- Digit count after stripping separators: 7-15
- Must not be all same digit (e.g., `000-000-0000`)
- Must not be sequential (e.g., `123-456-7890`) — low confidence downgrade

**Confidence**: 0.75 (regex match), 0.85 (validated digit count), 0.60 (sequential/pattern)

---

### 3. IBAN Recognizer

**Source**: `mod97`

**Detection**: Regex per country code (ISO 13616), then MOD-97 validation.

**Country code whitelist**: DE, FR, GB, ES, IT, NL, BE, CH, AT, PT, IE, LU, GR, FI, DK, SE, NO, PL, CZ, HU, RO, BG, HR, SK, SI, LT, LV, EE, IS, MT, CY, LI, MC, SM, AD (EU/EEA + CH/MC/SM/AD) — this is a privacy-first proxy, European PII is the priority.

**Validation**: IBAN check digits (positions 3-4) validated via ISO 7064 MOD-97-10.

**Confidence**: 0.95 (validated) — MOD-97 catches 99.9%+ of typos.

---

### 4. CREDIT_CARD Recognizer

**Source**: `luhn`

**Detection**: Regex by issuer prefix (IIN/BIN ranges), then Luhn checksum.

**Issuers detected**:
| Issuer | Prefixes | Length |
|--------|---------|--------|
| Visa | `4` | 13, 16 |
| Mastercard | `51-55`, `2221-2720` | 16 |
| American Express | `34`, `37` | 15 |
| Discover | `6011`, `644-649`, `65` | 16-19 |
| Diners Club | `300-305`, `36`, `38`, `39` | 14-19 |

**Validation**: Luhn algorithm (MOD-10 checksum).

**Confidence**: 0.95 (Luhn-validated). 0.85 (regex match only, if Luhn fails — still flag but lower confidence since user may have typed it wrong).

---

### 5. JWT Recognizer

**Source**: `structural`

**Detection**: Three base64url segments separated by exactly two dots: `eyJ... .eyJ... .signature`

**Validation**:
- Header (first segment) must base64url-decode to valid JSON
- Header must contain `"alg"` field
- Signature segment present (length ≥ 1)
- Total token length ≤ 8192 chars (realistic JWT max)

**What this is NOT**: This recognizer does NOT validate cryptographic signatures, decode payloads, or verify claims. No cryptographic operations. Structural check only.

**Confidence**: 0.80 (structural match). 0.90 (header decodes to valid JSON with `alg`). 0.60 (looks like JWT but header isn't valid JSON).

---

### 6. NAME Recognizer (Email Inference)

**Source**: `email_inference`

**Trigger**: Only fires on local-parts of EMAIL entities already detected by recognizer #1.

**Algorithm**:
1. Extract local-part from EMAIL entity `Value`
2. Strip `+suffix` if present (Gmail-style aliasing: `jean.dupont+newsletter@gmail.com` → `jean.dupont`)
3. Split on `.` or `_` separator
4. Each segment must:
   - Be ≥ 2 alpha chars
   - Start with a letter
   - Not be in the **stop-word list**: `support`, `noreply`, `info`, `contact`, `admin`, `help`, `sales`, `hello`, `team`, `service`, `office`, `billing`, `abuse`, `postmaster`, `webmaster`, `hostmaster`, `mail`, `news`, `newsletter`, `no-reply`, `noreply`, `root`, `test`, `demo`
   - Not be purely numeric
   - Not be a single character
5. Title-case each segment: `jean` → `Jean`, `dupont` → `Dupont`
6. Concatenate with space: `Jean Dupont`
7. Emit NAME entity with `Start`/`End` pointing to the EMAIL entity's span (NAME is a derived entity co-located with its source EMAIL)

**Confidence**: 0.70 (both segments pass validation), 0.55 (one segment borderline), 0.40 (single segment — still emit but low confidence).

**Examples**:
| Email | → Name | Confidence | Reason |
|---|---|---|---|
| `jean.dupont@gmail.com` | `Jean Dupont` | 0.70 | Clean first.last |
| `marie_curie@sorbonne.fr` | `Marie Curie` | 0.70 | Clean first_last |
| `support@company.com` | — | — | Blocked: stop-word |
| `noreply@github.com` | — | — | Blocked: stop-word |
| `jdoe@corp.com` | — | — | Blocked: single segment |
| `jd42@gmail.com` | — | — | Blocked: numeric |
| `john.doe+spam@gmail.com` | `John Doe` | 0.70 | +suffix stripped |
| `a.b@short.co` | `A B` | 0.55 | Single-char segments ok but low confidence |

---

### 7. SECRET Recognizer (Prefix-Based)

**Source**: `prefix`

**Design**: A compiled-in database of ~100 known API key/token prefix patterns. Each entry is a tuple `{Prefix, Provider, Category, MinLength, MaxLength, Regex, Confidence}`. Compiled at init time into a map indexed by the prefix for O(1) lookup.

**How it works**:
1. Walk the text looking for known prefixes (case-sensitive match on prefix characters)
2. On match, extract the full token via the associated regex
3. The regex includes length bounds and character class constraints
4. Apply any provider-specific validation (e.g., AWS key format check)

**Prefix database** — organized by category:

#### AI/ML Providers (highest priority — Qindu's target domain)

| Prefix | Provider | Format |
|--------|----------|--------|
| `sk-proj-` | OpenAI | `sk-proj-[A-Za-z0-9_-]{32,}` |
| `sk-svcacct-` | OpenAI (service account) | `sk-svcacct-[A-Za-z0-9_-]{32,}` |
| `sk-admin-` | OpenAI (admin) | `sk-admin-[A-Za-z0-9_-]{32,}` |
| `sk-ant-api03-` | Anthropic | `sk-ant-api03-[A-Za-z0-9_-]{95}AA` |
| `sk-ant-admin01-` | Anthropic (admin) | `sk-ant-admin01-[A-Za-z0-9_-]{95}AA` |
| `sk-` | Generic AI / OpenAI legacy | `sk-[A-Za-z0-9]{32,}` (lower confidence if no sub-prefix) |
| `hf_` | HuggingFace | `hf_[A-Za-z0-9]{34}` |
| `r8_` | Replicate | `r8_[A-Za-z0-9]{30,}` |
| `dapi` | Databricks | `dapi[a-f0-9]{32}(-\d)?` |
| `sk_live_` | Stripe / various | `sk_live_[0-9a-zA-Z]{24,}` |
| `pk_live_` | Stripe | `pk_live_[0-9a-zA-Z]{24,}` |

#### Cloud Providers

| Prefix | Provider | Format |
|--------|----------|--------|
| `AKIA` | AWS Access Key | `AKIA[A-Z2-7]{16}` |
| `ASIA` | AWS STS Temporary | `ASIA[A-Z2-7]{16}` |
| `ABIA` | AWS | `ABIA[A-Z2-7]{16}` |
| `ACCA` | AWS | `ACCA[A-Z2-7]{16}` |
| `ABSK` | AWS Bedrock | `ABSK[A-Za-z0-9+/]{109,269}={0,2}` |
| `AIza` | Google (GCP API key) | `AIza[\w-]{35}` |
| `doo_v1_` | DigitalOcean OAuth | `doo_v1_[a-f0-9]{64}` |
| `dop_v1_` | DigitalOcean PAT | `dop_v1_[a-f0-9]{64}` |
| `dor_v1_` | DigitalOcean Refresh | `dor_v1_[a-f0-9]{64}` |
| `LTAI` | Alibaba Cloud | `LTAI[a-z0-9]{20}` |

#### Version Control

| Prefix | Provider | Format |
|--------|----------|--------|
| `ghp_` | GitHub PAT (classic) | `ghp_[A-Za-z0-9]{36}` |
| `gho_` | GitHub OAuth | `gho_[A-Za-z0-9]{36}` |
| `ghu_` | GitHub User-to-Server | `ghu_[A-Za-z0-9]{36}` |
| `ghs_` | GitHub Server-to-Server | `ghs_[A-Za-z0-9]{36}` |
| `ghr_` | GitHub Refresh | `ghr_[A-Za-z0-9]{36}` |
| `github_pat_` | GitHub Fine-grained PAT | `github_pat_[A-Za-z0-9_]{22,82}` |
| `glpat-` | GitLab PAT | `glpat-[A-Za-z0-9_\-]{20,}` |
| `gldt-` | GitLab Deploy Token | `gldt-[A-Za-z0-9_\-]{20,}` |
| `glft-` | GitLab Feed Token | `glft-[A-Za-z0-9_\-]{20,}` |
| `glrt-` | GitLab Runner Token | `glrt-[A-Za-z0-9_\-]{20,}` |
| `glsoat-` | GitLab SCIM | `glsoat-[A-Za-z0-9_\-]{20,}` |
| `akcp` | Artifactory | `AKCp[A-Za-z0-9]{69}` |
| `cmVmd` | Artifactory (reference) | `cmVmd[A-Za-z0-9]{59}` |

#### Messaging / Collaboration

| Prefix | Provider | Format |
|--------|----------|--------|
| `xoxb-` | Slack Bot Token | `xoxb-\d{10,12}-\d{10,12}-[A-Za-z0-9]+` |
| `xoxp-` | Slack User Token | `xoxp-\d{10,12}-\d{10,12}-[A-Za-z0-9]+` |
| `xoxa-` | Slack App Token | `xoxa-\d{10,12}-\d{10,12}-[A-Za-z0-9]+` |
| `xoxr-` | Slack Refresh | `xoxr-\d{10,12}-\d{10,12}-[A-Za-z0-9]+` |
| `SG.` | SendGrid | `SG\.[A-Za-z0-9_\-]{22,68}` |
| `AC` | Twilio (Account SID) | `AC[a-f0-9]{32}` |
| `SK` | Twilio (API Key) | `SK[a-f0-9]{32}` |
| `key-` | Mailgun | `key-[a-f0-9]{32}` |
| `EAA` | Facebook Page | `EAA[MC][a-z0-9]{100,}` |
| `dt0c01.` | Dynatrace | `dt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}` |

#### Payments

| Prefix | Provider | Format |
|--------|----------|--------|
| `sk_live_` | Stripe (live secret) | `sk_live_[0-9a-zA-Z]{24,}` |
| `pk_live_` | Stripe (live publishable) | `pk_live_[0-9a-zA-Z]{24,}` |
| `sk_test_` | Stripe (test secret) | `sk_test_[0-9a-zA-Z]{24,}` |
| `pk_test_` | Stripe (test publishable) | `pk_test_[0-9a-zA-Z]{24,}` |
| `whsec_` | Stripe (webhook) | `whsec_[0-9a-zA-Z]{32,}` |
| `sq0atp-` | Square (production) | `sq0atp-[A-Za-z0-9_\-]{22}` |
| `sq0csp-` | Square (sandbox) | `sq0csp-[A-Za-z0-9_\-]{22}` |
| `rzp_live_` | Razorpay | `rzp_live_[A-Za-z0-9]{14}` |
| `rzp_test_` | Razorpay | `rzp_test_[A-Za-z0-9]{14}` |

#### Database / Storage

| Prefix | Provider | Format |
|--------|----------|--------|
| `mongodb\+srv://` | MongoDB Atlas | `mongodb\+srv://[^@\s]+@` |
| `postgresql://` | PostgreSQL | `postgresql://[^@\s:]+:[^@\s]+@` |
| `mysql://` | MySQL | `mysql://[^@\s:]+:[^@\s]+@` |
| `redis://` | Redis | `redis://[^@\s:]+(:[^@\s]+)?@` |
| `eyJ` | Supabase JWT | `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` |

#### CI/CD

| Prefix | Provider | Format |
|--------|----------|--------|
| `fo1_` | Fly.io | `fo1_[A-Za-z0-9_-]{43}` |
| `fm1` | Fly.io | `fm1[ar]_[A-Za-z0-9+/]{100,}={0,3}` |
| `fm2_` | Fly.io | `fm2_[A-Za-z0-9+/]{100,}={0,3}` |
| `pt-` | Buildkite | `pt-[A-Za-z0-9]{40}` |

#### Security / Secret Management

| Prefix | Provider | Format |
|--------|----------|--------|
| `ops_` | 1Password SA Token | `ops_eyJ[A-Za-z0-9+/]{250,}={0,3}` |
| `A3-` | 1Password Secret Key | `A3-[A-Z0-9]{6}-[A-Z0-9]{6,11}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}` |
| `dp.pt.` | Doppler | `dp\.pt\.[a-z0-9]{43}` |
| `SNYK-` | Snyk | `SNYK-[A-Za-z0-9_-]{36}` |
| `sqp_` | SonarQube | `sqp_[a-f0-9]{40}` |

#### Other Common

| Prefix | Provider | Format |
|--------|----------|--------|
| `ntn_` | Notion | `ntn_[A-Za-z0-9]{32,}` |
| `figd_` | Figma | `figd_[A-Za-z0-9_-]{28,}` |
| `npm_` | npm | `npm_[A-Za-z0-9]{36}` |
| `pypi-` | PyPI | `pypi-[A-Za-z0-9_]{36,}` |
| `T` | Telegram Bot | `T[0-9]{8,10}:[A-Za-z0-9_-]{35}` |
| `v1.0-` | Cloudflare CA | `v1\.0-[a-f0-9]{24}-[a-f0-9]{146}` |

**Confidence**: 0.85 (specific-known prefix match), 0.70 (generic prefix like `sk-` without sub-prefix).

---

### 8. SECRET Recognizer (Generic Entropy)

**Source**: `entropy`

**Design**: For secrets that don't have a known prefix — high-entropy, random-looking strings. Heavily inspired by Gitleaks' `generic-api-key` rule and GitGuardian's `Generic High Entropy Secret` (the #1 most common secret pattern at 24,561/million commits).

**Multi-layered detection**:

#### Layer 0: Keyword Pre-Filter

Before running expensive entropy calculation, check if the input contains any secret-related keywords. If no keyword is found within a 100-char window, skip the window entirely. This eliminates 90%+ of non-secret text from expensive analysis.

**Keyword list** (case-insensitive):
```
api_key, apikey, api-key, api_secret, apisecret, access_key, accesskey,
access_token, accesstoken, auth_token, authtoken, bearer_token, bearertoken,
client_secret, clientsecret, consumer_key, consumerkey, credential,
encryption_key, encryptionkey, license_key, licensekey, passwd, password,
private_key, privatekey, refresh_token, refreshtoken, secret, secret_key,
secretkey, session_key, sessionkey, token, webhook_secret, webhooksecret
```

#### Layer 1: Base64-like String Detection

**Pattern**: `[A-Za-z0-9+/]{20,}={0,2}` (≥ 20 base64 chars, optional `=` padding)

**Shannon entropy calculation**:
- Alphabet: `[A-Za-z0-9+/=]`
- Compute character frequency over the candidate string
- H = -Σ (count(c)/len * log2(count(c)/len)) over all unique chars
- Threshold: **H ≥ 3.5**

A truly random base64 string has entropy ≈ 6.0 (64-char alphabet). Base64-encoded structured data has entropy ≈ 4.0-5.0. Natural language has entropy ≈ 3.0-4.0. The 3.5 threshold balances false positives vs false negatives.

**Implementation note**: Shannon entropy is computed in a single pass: count `[256]int` for byte frequencies, then compute H. O(n) time, O(1) space. Pre-computed log2 table for performance. No allocations.

#### Layer 2: Hex String Detection

**Pattern**: `[0-9a-fA-F]{32,}` (≥ 32 hex chars)

**Shannon entropy** over hex alphabet `[0-9a-fA-F]`:
- Threshold: **H ≥ 3.0** (lower than base64 because hex is more constrained)

#### Layer 3: Bearer/Authorization Token Detection

**Pattern**: `(?i)bearer\s+([A-Za-z0-9_\-\.\+/=]{20,})` in Authorization headers or inline.

Also detect: `(?i)Authorization:\s*Bearer\s+([A-Za-z0-9_\-\.\+/=]{20,})`

#### Layer 4: Key-Value Assignment Detection

**Pattern** (adapted from Gitleaks' `generic-api-key` rule):
```
(?i)(?:access|auth|api|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:=|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})
```

Assignment value is then validated for entropy ≥ 3.5.

**Confidence**:
- 0.80 (base64+, H ≥ 4.5)
- 0.70 (base64+, H ≥ 3.5)
- 0.65 (hex, H ≥ 3.0)
- 0.60 (key-value assignment match)
- 0.50 (bearer token match without entropy validation)

---

### 9. PRIVATE_KEY Recognizer

**Source**: `pem_armor`

**Detection**: PEM/SSH/PGP armor header/footer blocks. Multi-line detection.

**Armor types detected**:

| Header | Type | Format |
|--------|------|--------|
| `-----BEGIN RSA PRIVATE KEY-----` | RSA Private Key | Full PEM block including body + footer |
| `-----BEGIN EC PRIVATE KEY-----` | EC Private Key | Full PEM block |
| `-----BEGIN DSA PRIVATE KEY-----` | DSA Private Key | Full PEM block |
| `-----BEGIN OPENSSH PRIVATE KEY-----` | OpenSSH Private Key | Full PEM block |
| `-----BEGIN PGP PRIVATE KEY BLOCK-----` | PGP Private Key | Full PGP block |
| `-----BEGIN ENCRYPTED PRIVATE KEY-----` | PKCS#8 Encrypted | Full PEM block |
| `-----BEGIN PRIVATE KEY-----` | PKCS#8 Unencrypted | Full PEM block |

**Detection algorithm**:
1. Find `-----BEGIN ` header
2. Read until matching `-----END ` footer + same key type
3. Verify body segment is valid base64 (≥ 40 chars)
4. Emit entire block (header + body + footer) as one entity
5. Multi-line: start offset is first char of BEGIN line, end offset is last char of END line

**Example detection span**:
```
-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----
```

**Confidence**: 0.95 (specific key type header), 0.90 (generic `PRIVATE KEY` header), 0.70 (header found but body is too short/degenerate).

---

## False Positive Mitigation

### Global exclusion patterns (applied before entity emission)

| Pattern | What it excludes | Reason |
|---------|-----------------|--------|
| `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}` | UUIDs | High entropy, not a secret |
| `^[0-9a-fA-F]{32}$` | 32-char hex (MD5/SHA-256) | Hash value, not a secret |
| `^[0-9a-fA-F]{40}$` | 40-char hex (SHA-1) | Hash value |
| `^[0-9a-fA-F]{64}$` | 64-char hex (SHA-256) | Hash value |
| `^[0-9a-fA-F]{128}$` | 128-char hex (SHA-512) | Hash value |
| `^(true\|false\|null\|undefined\|example\|test\|demo\|sample)$` | Common placeholder values | Not real secrets |
| `^[a-zA-Z_.-]+$` | Dot-separated identifiers | Java package names, not secrets |
| `^[A-Z_]{3,30}$` | ALL_CAPS identifiers | Environment variable names |
| URL query strings (in `?\w+=...` context) | `https://...?token=...` | URL-safe tokens in query strings are often non-secret |

### Recognizer-specific exclusions

- **SECRET**: After prefix match, check that the matched string isn't a URL path, HTML entity, or JSON key
- **GENERIC_ENTROPY**: After entropy match, verify the string doesn't appear to be a hash (exact known hash lengths), UUID, or CSS color
- **API_KEY prefix**: Never match within quoted string literals that start with `http://` or `https://` (URLs can contain key-like substrings)

---

## Constraints

1. **Zero PII in logs**: Entity `Value` must never appear in `slog` calls, error messages, `fmt.Printf`, `t.Log`, or any output. Log only `Type`, `Confidence`, `Source`, `Start`, `End`. Helper: `entity.SafeString()` returns `"EMAIL(0.85)"` — no value.

2. **Zero real PII in test fixtures**: All test data must be synthetic. Use domain `@example.com` for emails, obviously fake phone numbers (`+33 6 12 34 56 78` is the "movie number" — use something else), test IBANs from official test banks, test credit card numbers (e.g., Visa test `4111111111111111` is synthetic), fake API keys with recognizably fake prefixes (`sk-test-1234abcd...`).

3. **`go test -race ./internal/pii/...` must pass**: All tests clean under race detector.

4. **100% statement test coverage**: Every recognizer, every code path, every overlap resolution branch.

5. **No network calls, no filesystem access**: Recognizers are pure functions `string → []Entity`. Everything compiled in.

6. **No `init()` magic**: Compile regexes in `NewRecognizer()` constructor, not in `init()` functions. Enables deterministic testability.

7. **No panics**: All recognizers must handle malformed, empty, or adversarial input gracefully. Return empty slice, never panic.

8. **Package path**: `internal/pii/` (per ADR-001).

9. **ReDoS prevention**: All regexes must avoid catastrophic backtracking. Audit every regex for nested quantifiers `(a+)+`, `(a*)*`, `(a+)*`. Use atomic groups or limit quantifiers.

10. **Thread safety**: `Engine.Detect()` must be safe for concurrent use. `Recognizer.Detect()` implementations may be called concurrently by `Engine` (one goroutine per recognizer). Recognizers that maintain state (e.g., the email-to-name recognizer reading EMAIL entities) must not share mutable state.

11. **Memory**: Entity slices must be independent — no backing array sharing between returned slices. Each `Detect()` call returns a freshly allocated slice.

---

## Explicitly Out of Scope (Deferred)

- **Token format**: How entities become `<<TYPE_ID>>` strings → QINDU-0006
- **Scope/TTL metadata**: `conversation` vs `global`, TTL durations → QINDU-0006 (tokenization policy layer)
- **Vault storage**: Token → value mapping, DPAPI encryption → QINDU-0008
- **Interceptor integration**: Wiring `Engine` into `PIIInterceptor` → QINDU-0007 (Mode Monitor)
- **Streaming/chunked input**: The engine operates on complete strings; chunk assembly is QINDU-0007's concern
- **Person names from prose**: Only email-inferred names; regex/ML name detection from body text is excluded (false-positive risk too high for V1)
- **Configurable enable/disable of recognizers**: All 9 are always active; future UIs (QINDU-0016) can toggle
- **Secrets validity checks**: No API calls to validate tokens live → future enhancement

---

## Human Decisions Resolved

1. **Email-to-name inference**: Extract `first.last` / `first_last` local-parts as NAME entities with `Source: email_inference`. Stop-word filtered. False-positive risk accepted for derived names.
2. **Global vault scope for inferred names**: The NAME entity itself carries no scope/ttl — scope is a QINDU-0006 policy decision. The `Source: email_inference` tag enables the tokenizer to apply `scope: global, ttl: infinite` to these entities specifically.
3. **Entity provenance via `Source` field**: Enables granular tokenization policy in QINDU-0006 without coupling recognizers to storage semantics.
4. **Prefix-based secrets database scope**: ~100 curated prefixes from GitGuardian/Gitleaks taxonomy, focused on AI/cloud/VCS/messaging/payments — the domains most likely in AI chat. Extensible: adding a prefix is one line in the table.
5. **Generic entropy recognizer**: Shannon entropy on base64/hex + keyword pre-filtering. The Gitleaks approach adapted for chat text (shorter windows, different keyword set, no file paths).

---

## Package Structure

```
internal/pii/
├── entity.go           // Entity, EntityType, SourceKind types
├── recognizer.go       // Recognizer interface
├── engine.go           // Engine struct, Detect(), overlap resolution
├── email.go            // EMAIL recognizer
├── phone.go            // PHONE recognizer
├── iban.go             // IBAN recognizer (MOD-97)
├── creditcard.go       // CREDIT_CARD recognizer (Luhn)
├── jwt.go              // JWT recognizer (structural)
├── name_email.go       // NAME-from-email recognizer
├── secret_prefix.go    // SECRET prefix-based recognizer (~100 patterns)
├── secret_entropy.go   // SECRET generic entropy recognizer
├── privatekey.go       // PRIVATE_KEY recognizer (PEM/SSH/PGP)
├── entropy.go          // Shannon entropy computation + pre-computed log2 table
├── overlap.go          // Overlap resolution algorithm
├── engine_test.go      // Engine integration tests
├── email_test.go
├── phone_test.go
├── iban_test.go
├── creditcard_test.go
├── jwt_test.go
├── name_email_test.go
├── secret_prefix_test.go
├── secret_entropy_test.go
├── privatekey_test.go
├── entropy_test.go
├── overlap_test.go
```

---

## Acceptance Criteria

### Recognizer correctness
1. All 9 recognizers produce correct entities for valid inputs (unit tests per recognizer).
2. All 9 recognizers return empty/nil for inputs containing no PII.
3. Recognizers return zero false positives on known-negative inputs.

### Specific recognizer tests
4. EMAIL: rejects `notanemail`, `@missing.com`, `no@tld`, `a@b`; accepts `user@example.com`, `test+tag@domain.co.uk`.
5. PHONE: accepts `+33 6 12 34 56 78`, `(202) 555-0123`, `0612345678`; rejects `000-000-0000`, `123-456-7890` (downgrades confidence).
6. IBAN: validates DE, FR, GB IBANs via MOD-97; rejects check-digit-modified IBANs.
7. CREDIT_CARD: validates via Luhn; detects Visa, MC, Amex, Discover prefix BINs; rejects non-Luhn-compliant numbers.
8. JWT: detects valid structure; rejects invalid (non-base64url, wrong segment count, header not JSON).
9. NAME: extracts `Jean Dupont` from `jean.dupont@gmail.com`; does NOT fire on `support@`, `noreply@`, `admin@`, `jdoe@` (single segment), `jd42@` (numeric).
10. SECRET (prefix): detects OpenAI, GitHub, AWS, Slack, Stripe, HuggingFace, and 90+ other known prefix patterns.
11. SECRET (generic): detects high-entropy base64 strings ≥ 20 chars, hex strings ≥ 32 chars; skips UUIDs, hex hashes.
12. PRIVATE_KEY: detects RSA, EC, DSA, OpenSSH, PGP, PKCS#8 PEM blocks; detects multi-line correctly.

### Engine correctness
13. Overlap resolution picks the higher-confidence entity when spans overlap.
14. Non-overlapping entities all survive regardless of confidence.
15. Entities sorted by byte offset position in output.
16. Concurrent calls to `Engine.Detect()` do not data-race.

### Quality gates
17. `go test -race ./internal/pii/...` passes with 100% statement coverage (all `.go` files in `internal/pii/`).
18. No PII values in any log output, error string, `t.Log`, or test assertion message.
19. All test data is synthetic. No real emails, phones, IBANs, credit cards, API keys, JWTs.
20. `golangci-lint run ./internal/pii/...` reports 0 issues.
21. No `init()` functions. All regex compilation happens in constructors.
22. No panics on any input (fuzz each recognizer with random bytes).

---

## Gate Agents Required
- **DPO**: Privacy design (entity model, data minimization, `Source` provenance, no PII in logs, synthetic test data)
- **CISO**: Security (ReDoS audit, entropy implementation, no PII leakage, in-memory only, input size bounds, thread safety)
- **QA**: Test coverage (100% statement, edge cases per recognizer, false-positive/negative rates, fuzzing)
- **Peer Reviewer**: Code quality (SOLID, Go Proverbs, Clean Code, Effective Go, Uber Go Style Guide)
