# Qindu -- AI Privacy Proxy

> **Use ChatGPT, Claude, and Gemini without sending personal data in clear text.**

Qindu is a local proxy for Windows that sits between your browser and web AI services. It detects PII (names, emails, phone numbers, IBANs, credit cards, API keys) before anything leaves your machine, replaces it with tokens, and rehydrates the AI response locally. No browser extension. No account. No telemetry.

---

## How it works

```
REQUEST (browser → AI)

  "Summarize this ticket from Jane Doe (jane@example.com):
   Payment to IBAN FR76 3000 1007 9400 1234 5678 901 is stuck."
                 │
                 ▼
  ┌──────────────────────────────────────────┐
  │              QINDU PROXY                  │
  │                                           │
  │  1. PII engine detects:                   │
  │     Jane Doe              → PERSON        │
  │     jane@example.com      → EMAIL         │
  │     FR76 3000...          → IBAN          │
  │                                           │
  │  2. Tokenizer replaces:                   │
  │     → <<PII_PERSON_0001>>                 │
  │     → <<PII_EMAIL_0002>>                  │
  │     → <<PII_IBAN_0003>>                   │
  │                                           │
  │  3. Vault stores mapping (DPAPI-encrypted)│
  │     <<PII_PERSON_0001>> → Jane Doe        │
  │     <<PII_EMAIL_0002>>  → jane@ex…        │
  │     <<PII_IBAN_0003>>   → FR76 3000…      │
  └──────────────────────────────────────────┘
                 │
                 ▼
  "Summarize this ticket from <<PII_PERSON_0001>>
   (<<PII_EMAIL_0002>>): Payment to IBAN
   <<PII_IBAN_0003>> is stuck."
                 │
                 ▼
  ┌──────────────────────────────────────────┐
  │             AI SERVICE                    │
  │  The model sees tokens, never real data.  │
  │  Prompt analysis, training, logging —     │
  │  all happen on tokenized text only.       │
  └──────────────────────────────────────────┘


RESPONSE (AI → browser)

  "The payment from <<PII_PERSON_0001>>
   (<<PII_EMAIL_0002>>) to IBAN <<PII_IBAN_0003>>
   appears to be pending. No action needed from
   <<PII_PERSON_0001>>."
                 │
                 ▼
  ┌──────────────────────────────────────────┐
  │              QINDU PROXY                  │
  │                                           │
  │  4. Rehydrator looks up each token:       │
  │     → Jane Doe                            │
  │     → jane@example.com                    │
  │     → FR76 3000 1007 9400 1234 5678 901   │
  └──────────────────────────────────────────┘
                 │
                 ▼
  "The payment from Jane Doe
   (jane@example.com) to IBAN FR76 3000 1007
   9400 1234 5678 901 appears to be pending.
   No action needed from Jane Doe."
```

---

## What Qindu intercepts — and what it doesn't

```
Browser ──▶ bank, health, SSO, email, anything non-AI ──▶ DIRECT (blind tunnel)
Browser ──▶ chatgpt.com, claude.ai, gemini.google.com    ──▶ QINDU (MITM + PII protection)
```

Qindu only decrypts traffic to AI providers. Every other domain passes through as a blind TCP tunnel — Qindu never sees your banking credentials, health data, or personal email. The proxy binds to `127.0.0.1` only, so nothing leaves your machine unencrypted.

---

## V1 features

### Core
- **Windows 10/11** — single binary, console or Windows service
- **Chrome, Edge** — automatic proxy configuration via PAC and browser policies
- **Selective TLS MITM** — ECDSA P-256 CA, ephemeral leaf certificates, never persisted to disk
- **Domain routing** — AI domains decrypted, everything else blind-tunneled
- **MSI installer** — one-click install, CA trusted automatically, policies applied

### PII protection
- **Detection engine** — regex, validators (Luhn), context-aware. Covers: email, phone, IBAN, credit card, API key, JWT. Configurable confidence threshold.
- **Tokenization** — `<⟨PII_TYPE_ID>>` format, deterministic (same value → same token within a session). Provider-scoped: each AI service gets independent tokens. Conversation-aware: tokens are scoped by conversation ID, so the same email in two different chats gets two different tokens.
- **DPAPI-encrypted vault** — token→value mapping, scoped by provider and conversation, configurable TTL (24h / 7d / infinite)
- **Streaming rehydration** — SSE responses rehydrated on the fly, sub-4KB sliding buffer, no added latency

### Modes
- **Monitor** — detect and log what would be tokenized, traffic passes through unmodified
- **Enforce** — tokenize before upstream, rehydrate before browser. The AI sees only tokens. Fail-closed: if the vault or tokenizer is unavailable, the request is blocked (502) rather than sent in the clear.
- **Flow Inspector** — feature-flagged (`debug.flow_inspector: true`), localhost-only ring buffer at `/debug/flow`. Captures ingress/egress body pairs (64KB cap per entry, 50 entries max) for verifying the enforce pipeline. Only records conversation endpoints — sentinel/challenge paths are skipped. Zero PII in logs.

### Providers
- **ChatGPT** (`chatgpt.com`) — conversation endpoint, streaming SSE, delta encoding v1
- **Claude** (`claude.ai`) — conversation endpoint, streaming
- **Gemini** (`gemini.google.com`) — conversation endpoint

### Security and privacy
- **Zero PII in logs** — structured JSON via `slog`, metadata only (host, status, duration, bytes)
- **Graceful shutdown** — 30-second connection drain on SIGTERM or service stop
- **CA key DPAPI-encrypted** — never in plaintext on disk
- **No user accounts, no telemetry, no analytics, no cloud dependency**
- **AGPL-3.0** — free for any use. Building a SaaS on top? You must publish your modifications.

---

## Architecture

```
cmd/agent/main.go              Single binary entry point

internal/
  proxy/                       HTTP/S proxy (CONNECT MITM, blind tunnel, interceptor pipeline)
  interceptor/                 Pipeline stages: debug (flow inspector), enforce (tokenize/rehydrate), monitor
  tls/                         CA, leaf certs, cert cache, trust store
  policy/                      YAML config, domain router, PAC generator
  pii/                         Detection engine (recognizers, validators)
  tokenize/                    Token replacement (deterministic, reversible)
  vault/                       DPAPI-encrypted token→value store
  session/                     Conversation ID resolution, token scoping
  logging/                     PII-free structured JSON logging
  service/                     Windows service handler, health endpoint
  providers/                   Per-provider adapters (chatgpt, claude, gemini)
```

Built in **Go** — single static binary, no runtime, native TLS/HTTP. Cryptographic operations via `crypto/rand`, `crypto/ecdsa`, `crypto/tls`. Concurrency: one goroutine per connection, `sync.RWMutex` on cert cache.

---

## Windows installation

### Prerequisites
- Windows 10 or 11 (x64)
- Chrome or Edge browser
- Administrator rights (one-time, for MSI install)

### Install

Download the latest MSI from [GitHub Releases](https://github.com/Tarekinh0/qindu/releases) and run:

```powershell
msiexec /i Qindu-Installer-x64.msi /qn /l*v install.log
```

The installer handles everything automatically:
- Installs `agent.exe` to `C:\Program Files\Qindu\`
- Registers and starts the `QinduAgent` Windows service
- Generates a local ECDSA P-256 CA, DPAPI-encrypted at `C:\ProgramData\Qindu\`
- Installs the CA in the Windows Trusted Root store
- Configures Chrome and Edge to route AI traffic through the proxy
- Binds the proxy to `127.0.0.1:8787` (loopback only)
- Blocks external connections in Windows Firewall

### Verify

```powershell
# Check the service is running
sc query QinduAgent

# Health check
curl http://127.0.0.1:8787/health
# → {"status":"up","version":"0.1.0"}

# Inspect the PAC file
curl http://127.0.0.1:8787/proxy.pac
```

### Configure

Override `configs/default.yaml` by dropping a `config.yaml` in `C:\ProgramData\Qindu\`:

```yaml
agent:
  mode: "enforce"            # "monitor" or "enforce"
  fail_mode: "fail_closed"   # "fail_closed" or "fail_open"
logging:
  level: "debug"
  output: "file"
providers:
  chatgpt:
    enabled: true
```

Restart the service to apply:

```powershell
sc stop QinduAgent
sc start QinduAgent
```

### Uninstall

```powershell
msiexec /x Qindu-Installer-x64.msi DELETEDATA=1 /qn /l*v uninstall.log
```

With `DELETEDATA=1`, the CA certificate, vault, and all configuration are removed. Without it, the vault and CA material are preserved for reinstallation.

---

## Development

```bash
go build ./cmd/agent/        # Build
go test -race ./...          # Test
```

---

## License

**AGPL-3.0** — see [`LICENSE`](LICENSE).

Free for any use. Building a SaaS on top of Qindu? You must publish your modifications. Want a proprietary enterprise license without copyleft obligations? Contact the maintainers.

Contributions require a CLA — see [`CONTRIBUTING.md`](CONTRIBUTING.md).
