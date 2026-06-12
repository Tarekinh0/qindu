# Qindu — AI Privacy Proxy

> **Use web AI normally, without sending sensitive data in clear text to the model.**

Qindu is a **local AI privacy proxy** for Windows. It sits between your browser and web-based AI services (ChatGPT, Claude, Gemini…), detects PII before it leaves your machine, replaces it with tokens, and rehydrates AI responses locally. The AI provider never sees your sensitive data in clear text.

**Current status**: ⚠️ Pre-implementation — specification complete, sprint QINDU-0001 (proxy foundation) in progress. Zero lines of Go yet.

---

## The problem

You use ChatGPT, Claude, or Gemini. You paste in code, contracts, emails, customer data. That data leaves your machine and sits on someone else's server. Even with "enterprise" plans, the model sees everything.

## The Qindu approach

Instead of blocking or alerting (like a DLP), Qindu **transforms** data before it leaves:

```
Your prompt:    "Email jean.dupont@example.com about the contract"
                                                                          ┌─────────────┐
Browser ──CONNECT──▶ Qindu Proxy ──▶ AI Service                           │ Local vault │
                     │    ▲              │ sees:                          │ (DPAPI)     │
                     │    │              │ "Email <<PII_EMAIL_0001>>      │ jean.dupont │
                     │    │              │  about the contract"           │ @example... │
                     │    └── rehydrate ── AI responds with token ────────└─────────────┘
                     │
               No extension needed — Chrome/Edge route AI domains to 127.0.0.1:8787 via PAC
```

- **No browser extension** — uses native proxy settings + PAC file
- **Selective** — only intercepts AI domains, ignores banking, health, SSO, everything else
- **Local only** — no cloud, no telemetry, no accounts
- **Streaming-aware** — handles SSE responses with partial tokens split across chunks

---

## V1 scope

| In | Out |
|----|-----|
| Windows service (Go) | Kernel drivers |
| Chrome / Edge | Other browsers / OS |
| Selective TLS MITM (ECDSA P-256) | Full traffic inspection |
| Go-native PII detection (rules, regex, validators) | SDK / enterprise console |
| Streaming + non-streaming rehydration | Fleet management |
| DPAPI-encrypted local vault | PDF / OCR / images |
| Structured JSON logs (slog, zero PII) | Anti-bypass EDR-grade |
| Open-source, MIT license | Guaranteed perfect detection |

Full specification: [`ARCHITECTURE.md`](ARCHITECTURE.md)

---

## Project structure

```
docs/
  ARCHITECTURE.md              ← Full V1 specification (31 sections)
  decisions/                   ← Architecture Decision Records (ADR-001 → ADR-010)
  implementation/
    backlog/
      qindu-v1-backlog.yaml    ← 16 stories, 5 phases, with dependencies and gates
      qindu-v1-roadmap.md      ← Dependency chain, milestones, blockers
    sprints/
      QINDU-0001/              ← Current sprint: proxy TLS foundation
        story.md               ← Story spec, acceptance criteria, tests

cmd/
  agent/                       ← Entry point (Go, planned)
  installer-helper/            ← MSI helper (planned)

internal/
  proxy/                       ← CONNECT + MITM + Interceptor pipeline (planned)
  tls/                         ← CA, cert cache, trust store (planned)
  policy/                      ← YAML config, PAC, domain routing (planned)
  providers/                   ← Per-service adapters (planned)
  pii/                         ← PII detection engine (planned)
  tokenize/                    ← Tokenization + stream rehydration (planned)
  vault/                       ← DPAPI-encrypted store (planned)
  logging/                     ← slog JSON logger (planned)
  service/                     ← Windows service handler (planned)
```

---

## Development

### Current sprint

[QINDU-0001](docs/implementation/sprints/QINDU-0001/story.md) — Proxy TLS local sélectif (CONNECT MITM, certificats, PAC, logs, graceful shutdown). This is the skeleton. Everything else (PII, vault, tokenization) builds on it.

### Workflow

Qindu uses a **strict multi-agent governance model** for security and privacy compliance:

```
Orchestrator → DPO (privacy) → CISO (security) → DevSecOps (impl) → CISO + DPO (review) → QA + Release (validation) → Closure
```

Each sprint goes through privacy review (DPO), security review (CISO), implementation (DevSecOps), quality review (QA), and release verification (Release) before merging. See [`AGENTS.md`](AGENTS.md) for details.

### Quickstart (once code exists)

```bash
# Clone
git clone https://github.com/Tarekinh0/qindu

# Run in console mode (development)
go run ./cmd/agent

# Tests
go test ./...                    # Unit + integration (requires Docker)
go vet ./...
GOOS=windows GOARCH=amd64 go build ./cmd/agent/  # Cross-compile for Windows
```

### Install (future)

```
msiexec /i qindu-v1.0.0-x64.msi
```

The installer will: create Windows service, generate local CA, install in trust store, configure Chrome/Edge policies, set up firewall rules, and disable QUIC.

---

## Tech stack

| Component | Choice | Why |
|-----------|--------|-----|
| Language | Go | Single binary, no runtime, great TLS/HTTP support |
| Platform | Windows | V1 target |
| TLS | `crypto/tls`, ECDSA P-256 | Native, fast, trusted by all browsers |
| Encryption | Windows DPAPI | Machine-bound, no key management |
| Proxy | HTTP/1.1 + HTTP/2 | Native Go support via `net/http` |
| Config | YAML | Readable, single source of truth |
| Logging | `log/slog` (JSON) | Standard library, structured, machine-readable |
| Testing | `testcontainers-go` | Real HTTPS servers, real HTTP/2 |
| CI | GitHub Actions | `ubuntu-latest`, cross-compile `GOOS=windows` |
| Packaging | Wix Toolset | MSI for Windows (planned) |

---

## License

MIT — see [LICENSE](LICENSE)
