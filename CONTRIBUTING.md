# Contributing to Qindu

Thanks for your interest in contributing. Qindu uses a dual licensing model (AGPL-3.0 + commercial) to keep the project open while reserving the right to offer an enterprise version. This document explains how to contribute and what it means for your code.

---

## Contributor License Agreement (CLA)

By submitting a contribution (pull request, patch, or any other form of code or documentation) to this project, you agree to the following:

1. **Copyright assignment**: You grant the Qindu project maintainers a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use, reproduce, modify, distribute, sublicense, and relicense your contribution under any license, including proprietary licenses, without restriction.

2. **Original work**: You certify that your contribution is your original work and you have the right to grant this license. If your contribution includes third-party material, you have identified it and obtained necessary permissions.

3. **No obligation**: You understand that your contribution may or may not be accepted, and that even if accepted, it may be modified or removed in the future.

4. **Patent grant**: You grant any party receiving your contribution a patent license for any patents you hold that are necessarily infringed by your contribution.

### Why a CLA?

The CLA enables dual licensing. Without it, the project would be locked into AGPL-3.0 only — the maintainers could not offer a commercial license for enterprise use, because they wouldn't own all the copyright. The CLA solves this while keeping the project fully open source under AGPL-3.0.

### Individual vs Corporate CLA

- If you contribute as an **individual**, you agree to the terms above by submitting your PR.
- If your employer owns the copyright to your work, a **Corporate CLA** must be signed. Contact the maintainers.

---

## How to Contribute

### 1. Understand the project

Read these documents before contributing:
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — Full V1 specification
- [`AGENTS.md`](AGENTS.md) — Multi-agent governance model
- [`docs/decisions/README.md`](docs/decisions/README.md) — Architecture Decision Records

### 2. Find something to work on

- Check the [backlog](docs/implementation/backlog/qindu-v1-backlog.yaml) for open stories
- Check the [roadmap](docs/implementation/backlog/qindu-v1-roadmap.md) for priorities
- Start with issues labeled `good first issue`

### 3. Pick an existing sprint or propose one

Qindu uses a strict sprint workflow (see [`AGENTS.md`](AGENTS.md)):

```
Orchestrator → DPO (privacy) → CISO (security) → DevSecOps (impl) → CISO + DPO (review) → QA + Release (validation) → Closure
```

Every feature touching TLS, cryptography, PII detection, vault, logging, or CI/CD must pass both DPO and CISO gates.

### 4. Development guidelines

- **Language**: Go 1.22+
- **Tests**: All changes require tests. Use `testcontainers-go` for integration tests.
- **No PII in code**: Never commit real PII, credentials, private keys, CA keys, or real browser traffic samples.
- **No PII in logs**: Logs use structured JSON (`log/slog`). No prompts, responses, or PII values are ever logged.
- **Cross-compilation**: Code must cross-compile with `GOOS=windows GOARCH=amd64`.
- **Windows-specific code**: Use `_windows.go` and `_other.go` (stub) files for platform-specific code.

### 5. Pull request checklist

- [ ] `go fmt ./...` passes
- [ ] `go vet ./...` passes
- [ ] `go test ./...` passes
- [ ] No new dependencies without justification
- [ ] No PII or credentials in code, tests, or fixtures
- [ ] If touching TLS, crypto, PII, vault, or logging: DPO and CISO gates added to PR description
- [ ] CLA acknowledged in PR description

---

## Code of Conduct

- Be respectful and constructive
- No proprietary code, no credentials, no real PII
- Follow the multi-agent governance workflow
- Security issues: contact the maintainers privately, do not open a public issue

---

## License

This project is dual-licensed. By contributing, you agree that your code may be used under both:

1. **GNU Affero General Public License v3.0** ([LICENSE](LICENSE)) — for the open-source community
2. **Commercial license** — for enterprise deployment without copyleft obligations

See [LICENSE](LICENSE) for full terms.
