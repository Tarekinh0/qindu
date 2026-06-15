# Peer Review: QINDU-0002 — Installer Windows + Service

**Reviewer**: qindu-peer-reviewer
**Date**: 2026-06-15
**Verdict**: **MERGE_READY**

---

## Section 1: Scorecard

| Framework | Score | Justification |
|-----------|-------|---------------|
| **Clean Code** | 4/5 | Small functions, meaningful names, no dead code, no `var _=` hacks. `cmd/agent/main.go` is dense with ~312 lines handling CLI dispatch, config resolution, ca-init, and config merge — the entrypoint is doing a lot but remains readable. |
| **Pragmatic Programmer** | 4/5 | Orthogonal modules (tls ⇄ proxy ⇄ policy). `resolveConfigPath` priority chain is well-specified by contract. `destroyExistingCA` does direct file deletion rather than going through `CAStore.Delete()`, breaking the abstraction. |
| **SOLID** | 4/5 | `Interceptor` interface (2 methods) and `CAStore` interface (3 methods) are ISP-compliant. `NoOpInterceptor` satisfies LSP. DIP used throughout. SRP weakened in `cmd/agent/main.go` where CLI dispatch, config resolution, and CA lifecycle cohabitate. |
| **Go Proverbs** | 5/5 | Errors are values with `%w` wrapping throughout. Small interfaces. No goroutine leaks found. `sync.RWMutex` used correctly with no deadlocks. `-race` in CI. No `defer` in loops. |
| **Effective Go** | 4/5 | CamelCase naming, `gofmt`-compliant, consistent error patterns. `qinduTls` import alias is unconventional (Effective Go recommends against renaming imports without clear reason). `oidNameConstraints` as file-level test var works but `[]int` cannot be `const` — acceptable. |
| **DDD** | 4/5 | Packages align with bounded contexts: `policy` (config + routing), `tls` (CA + certs), `proxy` (MITM + forward), `service` (Windows service). Ubiquitous language used (CA, leaf cert, interceptor, tunnel). `getCADir()` leaks OS path logic into the application layer. |
| **Code Complete** | 4/5 | Input validation at boundaries (config validation, loopback-only check, path traversal). No global mutable state. No magic numbers. `forwardingBufferSize = 32 * 1024` is well-named. Test isolation: `TestResolveConfigPath_ProgramFiles` uses a shared `/tmp/testpf` path instead of `t.TempDir()` — flakiness risk. |

**Composite**: **4.1/5** — Solid engineering with minor abstractions that could be cleaner.

---

## Section 2: Critical Findings 🔴

*None. No bugs, panics, security holes, data loss risks, or build breakers found.*

---

## Section 3: Design Flaws 🟡

### PR-100: `destroyExistingCA` bypasses the `CAStore` abstraction (Coupling)

- **File**: `cmd/agent/main.go:200-212`
- **Category**: Coupling / Abstraction leakage

`destroyExistingCA` directly removes `ca.crt` and `ca.key` via `os.Remove`, knowing the internal file layout of the CAStore. The `CAStore` interface has `Save`, `Load`, and `NeedsGeneration` but no `Delete` method. If the Windows store changes its file naming convention, `destroyExistingCA` breaks. And if someone implements a different `CAStore` (e.g., TPM-backed), the destroy logic would silently skip the actual secure erasure.

**Fix**: Add a `Delete() error` method to the `CAStore` interface. Implement it on `windowsCAStore` (removes `ca.crt` and `ca.key`) and on `otherCAStore` (clears the in-memory state). Call `store.Delete()` in `runCAInit` instead of direct file removal.

```go
// CAStore interface should include:
Delete() error
```

### PR-101: `getCADir()` does implicit OS detection via env vars (Coupling)

- **File**: `cmd/agent/main.go:303-311`
- **Category**: Orthogonality / Platform coupling

```go
func getCADir() string {
    if dir := os.Getenv("PROGRAMDATA"); dir != "" {
        return filepath.Join(dir, caSubDir)
    }
    if home, err := os.UserHomeDir(); err == nil {
        return filepath.Join(home, ".qindu", "ca")
    }
    return filepath.Join(os.TempDir(), "qindu-ca")
}
```

This function has three fallback behaviors based on environment variables, not build tags. On non-Windows, it falls through the first `if` (PROGRAMDATA empty) to `os.UserHomeDir()`. If a developer sets `PROGRAMDATA` on Linux for testing, the behavior changes silently. This is fragile and should use build tags like the rest of the codebase.

**Fix**: Use `runtime.GOOS` or provide `getCADir_windows.go` / `getCADir_other.go` with build tags, matching the pattern already used by `ca_windows.go` / `ca_other.go`.

### PR-102: `TestResolveConfigPath_ProgramFiles` uses a shared `/tmp/testpf` path (Testability)

- **File**: `cmd/agent/ca_init_test.go:99-117`
- **Category**: Test isolation / Flakiness

```go
t.Setenv("PROGRAMFILES", "/tmp/testpf")
...
configFile := filepath.Join("/tmp/testpf", "Qindu", "configs", "default.yaml")
os.MkdirAll(configDir, 0755)
defer os.RemoveAll("/tmp/testpf")
```

The test writes to a hardcoded path `/tmp/testpf`. Parallel test runs (e.g., `go test -count=N` or CI matrix) could collide. If `os.RemoveAll` fails (permissions, locked file), `/tmp/testpf` leaks and poisons subsequent runs. Every other test in the file correctly uses `t.TempDir()`.

**Fix**: Replace with `t.TempDir()`:

```go
testpf := t.TempDir()
t.Setenv("PROGRAMFILES", testpf)
configDir := filepath.Join(testpf, "Qindu", "configs")
os.MkdirAll(configDir, 0755)
configFile := filepath.Join(configDir, "default.yaml")
os.WriteFile(configFile, ...)
```

### PR-103: `resolveConfigPath` path-traversal guard is checked AFTER `filepath.Clean` resolves `..` (Security-in-depth)

- **File**: `cmd/agent/main.go:236-238`
- **Category**: Defensive programming / Validation ordering

```go
cleaned := filepath.Clean(explicitPath)
if strings.Contains(cleaned, "..") {
    return "", fmt.Errorf("config path must not contain '..': %s", explicitPath)
}
```

`filepath.Clean` resolves `..` elements in absolute paths *before* the check. For example, `filepath.Clean("/a/../../../etc/passwd")` → `"/etc/passwd"`, which passes the `..` check. While this doesn't allow privilege escalation (the user already has file access), the guard is misleading: it claims to prevent directory traversal but only catches relative paths. For absolute paths, the user can point the config at any readable file.

**Fix**: Either check for `..` *before* `filepath.Clean` on the raw input, or add `filepath.IsLocal()` (Go ≥1.20) to reject non-local paths:

```go
if explicitPath != "" {
    if !filepath.IsLocal(explicitPath) {
        return "", fmt.Errorf("config path must be a local path: %s", explicitPath)
    }
    return filepath.Clean(explicitPath), nil
}
```

### PR-104: `applyConfigOverride` boolean fields silently ignored during override merge (Data integrity)

- **File**: `internal/policy/config.go:192-197` (comment), `:215-217`
- **Category**: Defensive programming

```go
// CertCacheEnabled: yaml.v3 defaults bool to false, so we cannot distinguish
// "not present" from "explicitly false". The override struct keeps the
// zero-value, so we skip it to avoid forcing false on every merge.
```

Both `CertCacheEnabled` and `PIILogging` are skipped in the override merge because `yaml.v3` unmarshals absent bool fields as `false` (the zero value). If a user explicitly sets `cert_cache_enabled: false` in their override file, it is silently ignored — the original `true` from `default.yaml` persists. This violates the principle of least astonishment.

**Fix**: Change the override fields to `*bool` pointers so you can distinguish "not set" (nil) from "explicitly false" (pointer to `false`):

```go
// In the override struct or a separate OverrideConfig:
type TLSOverride struct {
    CertCacheEnabled *bool `yaml:"cert_cache_enabled"`
    // ...
}
```

### PR-105: `GracefulShutdownTimeout` constant re-exported (Duplication)

- **File**: `internal/proxy/graceful.go:16`
- **Category**: DRY / Maintenance

```go
// Deprecated: Use constants.GracefulShutdownTimeout directly.
const GracefulShutdownTimeout = constants.GracefulShutdownTimeout
```

The `graceful.go` file re-exports a constant that already exists in `internal/constants/`. The comment says "Deprecated" yet the code still defines and uses the re-export. This is a leftover from a previous refactor and adds no value — it creates two sources of truth for the same value.

**Fix**: Remove the re-export in `graceful.go` and use `constants.GracefulShutdownTimeout` directly. If any external package imported `proxy.GracefulShutdownTimeout`, update those references. Grep shows no external consumers in this sprint.

---

## Section 4: Excellence 🟢

### 🟢 `internal/tls/cert_cache.go` — Lock discipline with double-check optimization (Lines 73-105)

`GetOrCreate` is a textbook example of correct double-checked locking in Go. It avoids the fast-path deadlock (calling `Get()` while holding the write lock) by inlining the TTL check, and the comment on line 85 explicitly documents *why* this is necessary:

```go
// Double-check after acquiring write lock (another goroutine may have added it).
// Must inline the TTL check since we already hold the write lock;
// calling Get() here would deadlock (Get acquires RLock).
```

This is the kind of defensive commentary that prevents future maintainers from "refactoring" into a deadlock. The `evictIfNeededLocked` naming convention (`Locked` suffix) signals the caller must hold the lock — a well-established Go pattern.

### 🟢 `internal/tls/ca.go` — Clean, minimal public API (Lines 1-113)

The `CA` struct and `GenerateCA` function are focused, well-documented, and expose exactly what callers need. The function returns `(*CA, []byte, error)` — the certificate and key are returned separately, with `CertPEM` containing only the certificate block (verified by `TestCAInit_CAKeyNotInOutput`). No key material leaks through the cert PEM field. The `NameConstraints` addition is gated on `len(permittedDNSDomains) > 0`, and `PermittedDNSDomainsCritical = false` for browser compatibility — exactly matching the story requirement.

### 🟢 `internal/proxy/mitm.go:162-171` — Safe error response

```go
func (p *Proxy) sendBadGateway(conn io.Writer) {
    msg := "HTTP/1.1 502 Bad Gateway\r\n" +
        "Content-Type: application/json\r\n" +
        "Connection: close\r\n" +
        "\r\n" +
        `{"error":"bad_gateway","detail":"upstream connection failed"}` + "\n"
    conn.Write([]byte(msg))
}
```

No stack trace, no internal hostname, no error details leaked to the client. The hardcoded JSON body is minimal and PII-free. This is exactly how error responses should be built in a security-sensitive proxy.

### 🟢 `installer/wix/includes/ca-trust.wxs` — Rollback CustomAction (Lines 59-68)

The installer schedules a rollback action (`CARollbackTrustStore`) that runs *before* `CAInstallTrustStore`. If the CA is successfully added to the trust store but a later step fails (e.g., firewall rule creation), the rollback removes the CA. This ensures the machine is not left with an orphaned trust anchor. The use of `Return="ignore"` on rollback is correct — you don't want to fail the rollback itself if the CA is already absent.

### 🟢 `cmd/agent/ca_init_test.go` — Comprehensive edge case coverage

The test file covers:
- Name Constraints present/absent (`TestGenerateCAWithNameConstraints`, `TestGenerateCAWithoutNameConstraints`)
- Non-critical extension flag (`TestCAInit_NameConstraintsNonCritical`)
- CA regeneration produces different material (`TestCAInit_RegenerationProducesDifferentCA`)
- Key material isolation in PEM fields (`TestCAInit_CAKeyNotInOutput`)
- Idempotent destroy (`TestDestroyExistingCA_Idempotent`)
- Store roundtrip with filesystem state (`TestCAInit_DestroyAndRecreateCA`)
- Non-interactive unsafe mode rejection (`TestConfirmUnsafeMode_NonInteractive`)
- Config path resolution at all 4 priority levels
- Config override merge correctness

This is the kind of thoroughness expected in a security-critical component. The test file header also contains a SAFETY comment documenting the absence of PII — good practice.

### 🟢 CI: `validate-wix` job — XML well-formedness + include reference resolution

```yaml
validate-wix:
    name: Validate WiX Sources
    runs-on: ubuntu-latest
    steps:
      - name: Install xml utilities
        run: sudo apt-get update && sudo apt-get install -y libxml2-utils
      - name: Validate XML well-formedness
        run: find installer/wix -name "*.wxs" -exec xmllint --noout {} \;
      - name: Check include references
        run: |
          errors=0
          for wxs in $(find installer/wix -name "*.wxs"); do
            dir=$(dirname "$wxs")
            includes=$(grep -oP '<?include\s+\K[^?]+' "$wxs" 2>/dev/null || true)
            for inc in $includes; do
              resolved="$dir/$inc"
              if [ ! -f "$resolved" ]; then
                echo "ERROR: $wxs references non-existent include: $inc"
                errors=$((errors + 1))
              fi
            done
          done
```

Validating WiX source syntax on `ubuntu-latest` (without WiX Toolset) is a clever CI design choice — catches broken includes and XML syntax errors BEFORE the Windows MSI build job runs. The include resolution uses `<?include` regex matching with proper relative path resolution. This eliminates a whole class of "it built on my machine" failures.

---

## Section 5: Verdict

### **MERGE_READY**

The implementation faithfully delivers all 15 acceptance criteria from the story. The code is clean, well-tested (both unit and structure), and follows the architectural patterns established in QINDU-0001. No critical bugs, no security vulnerabilities, no race conditions, and no panics found.

The 5 design flaws flagged are all in the 🟡 category — non-blocking improvements that enhance maintainability and robustness. Specifically:

| Priority | ID | What to fix first |
|----------|-----|-------------------|
| Before next sprint | PR-102 | Use `t.TempDir()` in the shared-path test |
| Before next sprint | PR-100 | Add `Delete()` to `CAStore` interface |
| Soon | PR-103 | Tighten path traversal guard |
| Nice to have | PR-101 | Build-tag-based `getCADir` |
| Nice to have | PR-105 | Remove duplicated constant re-export |
| Defer to QINDU-0004+ | PR-104 | `*bool` for override booleans |

No re-review cycle needed. Proceed to CISO/DPO gates.

---

## Section 6: Compliance Checklist (Qindu-specific security)

| Check | Status | Evidence |
|-------|--------|----------|
| No PII in logs, errors, or test fixtures | ✅ | Logging limits to host/status/duration/bytes. Tests use synthetic domains only. |
| No `InsecureSkipVerify` in production paths | ✅ | Gated behind `upstream_validation: "insecure"` config option; default is `"system"`. |
| Loopback-only bind | ✅ | `config.Validate()` rejects non-loopback IPs. |
| DPAPI before disk write | ✅ | `ca_windows.go:Save()` encrypts key with `CryptProtectData` before `os.WriteFile`. |
| Interceptor interface safety | ✅ | `NoOpInterceptor` returns `req.Body` / `resp.Body` directly — no buffering. |
| Certificate cache has bounds | ✅ | `defaultMaxCacheSize = 1000`, random eviction via map iteration. |
| No hardcoded secrets | ✅ | No credentials, keys, or tokens in source. |
| Graceful shutdown drains connections | ✅ | Both `runConsole` and `windows_service.go` use `server.Shutdown` with timeout. |
| Config validation at startup | ✅ | `LoadConfig` → `cfg.Validate()` before use. |
| No telemetry, analytics, tracking | ✅ | No phone-home code found. |
| CA private key never logged | ✅ | `ca-init` output prints only Subject CN, NotAfter, SerialNumber, and paths. |
| Firewall blocks non-loopback on 8787 | ✅ | `netsh advfirewall` rule with `remoteip=any action=block dir=in localport=8787`. |
| MSI uses absolute paths for system tools | ✅ | `[System64Folder]certutil.exe` prevents PATH hijacking. |
| Unsafe CA blocks silent install | ✅ | WiX condition: `NOT (UNSAFE_CA="1" AND (UILevel=2 OR UILevel=3))`. |
