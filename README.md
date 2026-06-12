# Qindu — AI Privacy Proxy

> **Use web AI without sending PII in clear text to the model.**

Qindu is a local proxy for Windows that sits between your browser and web AI services (ChatGPT, Claude, Gemini). It detects PII (emails, phone numbers, credit cards, etc.) before it leaves your machine, replaces it with tokens, and rehydrates AI responses locally. No browser extension needed.

⚠️ **Pre-implementation.** Sprint QINDU-0001 (proxy foundation) in progress. Zero code yet.

---

## What Qindu does

```
REQUEST (browser → AI)

  "Summarize this ticket from Jane Doe (jane@example.com):
   Payment of 423€ to IBAN FR76 3000 1007 9400 1234 5678 901 is stuck."
                 │
                 ▼
  ┌──────────────────────────────────────┐
  │            QINDU PROXY                │
  │                                       │
  │  1. PII engine detects:               │
  │     Jane Doe              → PERSON    │
  │     jane@example.com      → EMAIL     │
  │     FR76 3000...          → IBAN      │
  │                                       │
  │  2. Tokenizer replaces them:          │
  │     → <<PII_PERSON_0001>>             │
  │     → <<PII_EMAIL_0002>>              │
  │     → <<PII_IBAN_0003>>               │
  │                                       │
  │  3. Vault stores mapping (encrypted):  │
  │     <<PII_PERSON_0001>> → Jane Doe    │
  │     <<PII_EMAIL_0002>>  → jane@ex…    │
  │     <<PII_IBAN_0003>>   → FR76 3000…  │
  └──────────────────────────────────────┘
                 │
                 ▼
  "Summarize this ticket from <<PII_PERSON_0001>>
   (<<PII_EMAIL_0002>>): Payment of 423€ to IBAN
   <<PII_IBAN_0003>> is stuck."
                 │
                 ▼
  ┌──────────────────────────────────────┐
  │            AI SERVICE                 │
  │  The model analyzes the ticket text.  │
  │  It never sees the real name, email,  │
  │  or bank account.                     │
  └──────────────────────────────────────┘


RESPONSE (AI → browser)

  "The payment from <<PII_PERSON_0001>>
   (<<PII_EMAIL_0002>>) to IBAN <<PII_IBAN_0003>>
   appears to be pending due to a processing delay.
   No action needed from <<PII_PERSON_0001>>."
                 │
                 ▼
  ┌──────────────────────────────────────┐
  │            QINDU PROXY                │
  │                                       │
  │  4. Rehydrator looks up each token:   │
  │     → Jane Doe                        │
  │     → jane@example.com                │
  │     → FR76 3000 1007 9400 1234 5678…  │
  └──────────────────────────────────────┘
                 │
                 ▼
  "The payment from Jane Doe
   (jane@example.com) to IBAN FR76 3000 1007
   9400 1234 5678 901 appears to be pending due
   to a processing delay. No action needed from
   Jane Doe."
```

---

## What Qindu does NOT touch

```
  Browser ──▶ banking, health, SSO, mail, anything non-AI ──▶ DIRECT (no proxy)
  Browser ──▶ chatgpt.com, claude.ai                         ──▶ QINDU (MITM)
```

Only AI domains pass through the proxy. Everything else is tunneled without decryption — Qindu never sees your bank credentials, health data, or personal email.

---

## V1 scope

| In | Out |
|----|-----|
| Windows service (Go) | Kernel drivers |
| Chrome, Edge | Other browsers, macOS, Linux |
| Selective TLS MITM (ECDSA P-256) | Full traffic inspection |
| PII detection (rules, regex, validators) | SDK, enterprise console |
| Tokenization + streaming rehydration | Fleet management |
| DPAPI-encrypted vault | PDF, images |
| slog JSON logs (zero PII) | Anti-bypass EDR-grade |
| AGPL-3.0 | Guaranteed perfect detection |

Full spec: [`ARCHITECTURE.md`](ARCHITECTURE.md)

---

## Repo map

```
docs/
  ARCHITECTURE.md               Full spec
  decisions/                    ADR-001 → ADR-010
  implementation/
    backlog/                    qindu-v1-backlog.yaml (16 stories)
    sprints/QINDU-0001/         Current sprint: proxy foundation

cmd/agent/                      Entry point
internal/                       proxy, tls, policy, pii, vault, tokenize, logging, service
```

---

## Development

**Current sprint**: [QINDU-0001](docs/implementation/sprints/QINDU-0001/story.md) — TLS proxy (CONNECT MITM, PAC, certs, logs, graceful shutdown).

**Workflow**: strict multi-agent gates (DPO → CISO → DevSecOps → CISO+DPO → QA+Release). See [`AGENTS.md`](AGENTS.md).

```bash
git clone https://github.com/Tarekinh0/qindu
go run ./cmd/agent          # console mode
go test ./...               # requires Docker
go vet ./...
GOOS=windows GOARCH=amd64 go build ./cmd/agent/
```

---

## License

**AGPL-3.0** — see [`LICENSE`](LICENSE).

Free for any use. Building a SaaS on top of Qindu? You must publish your modifications. Want a proprietary enterprise license without copyleft obligations? Contact the maintainers.

Contributions require a CLA — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
