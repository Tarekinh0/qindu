# WiX Cleanup Audit — QINDU-0008

**Date**: 2026-07-04
**Auditor**: qindu-peer-reviewer
**Scope**: Audit Go source for file-permission, ACL, directory-creation, cleanup, and platform-specific concerns that belong in the WiX installer, not Go code.

---

## Summary

7 findings across 6 files. **None require immediate Go code removal** — the existing WiX installer already handles the `%PROGRAMDATA%` directory lifecycle correctly. The remaining Go code either (a) operates in per-user profile space that WiX cannot reach, (b) generates files at runtime that cannot be pre-packaged, or (c) provides safety-net behavior for non-MSI console-mode operation. All findings are `DOCUMENT` grade — they need WiX-awareness comments and path-sync discipline, not code deletion.

---

## Finding 1: Redundant `os.MkdirAll` for CA directory — duplicates WiX `CreateFolder`

| Field | Detail |
|-------|--------|
| **ID** | WIX-001 |
| **File** | `cmd/agent/main.go:107` |
| **Category** | Directory creation — redundant with WiX |
| **Severity** | LOW |
| **Verdict** | **DOCUMENT** |

**What it does**:
```go
caDir := getCADir()
err = os.MkdirAll(caDir, 0700)
```
Creates `%PROGRAMDATA%\Qindu\` before CA generation.

**What WiX already does**:
`installer/wix/includes/files.wxs:37-46` defines `ProgramDataDirComponent` with `<CreateFolder>` + explicit ACLs for SYSTEM, Administrators, and LocalService. WiX creates `PROGRAMDATADIR` at install time, before any custom action runs (sequenced `After="InstallFiles"`).

**Why Go still does it**:
When the agent runs in **console/debug mode** (`go run .`) without MSI installation, the directory does not exist. This `MkdirAll` is a safety net for developer workflows. In production (WiX-installed service), it is a no-op.

**Recommendation**: Add a comment documenting WiX ownership. Consider guarding with an `os.Getenv("QINDU_DEV") != ""` check, but do not remove — breaking console-mode development is worse than a harmless no-op.

---

## Finding 2: Redundant `os.MkdirAll` in `ca_windows.go` `Save()`

| Field | Detail |
|-------|--------|
| **ID** | WIX-002 |
| **File** | `internal/tls/ca_windows.go:53` |
| **Category** | Directory creation — redundant with WiX |
| **Severity** | LOW |
| **Verdict** | **DOCUMENT** |

**What it does**:
```go
func (s *windowsCAStore) Save(certPEM, keyPEM []byte) error {
    if err := os.MkdirAll(s.caDir, 0700); err != nil { ... }
```
Same issue as WIX-001 — creates `%PROGRAMDATA%\Qindu\` before writing CA files.

**Same rationale**: WiX creates this directory at install time with correct ACLs. Go's `MkdirAll` is a no-op in production, a safety net in console mode. The `0700` mode is decorative on Windows (Unix permission bits don't enforce ACLs).

**Recommendation**: Document the WiX ownership. Remove the `MkdirAll` if and only if all CA write paths are guaranteed to run after WiX directory creation. Currently, console-mode `ca-init` would break.

---

## Finding 3: Go creates `%PROGRAMDATA%\Qindu\logs` subdirectory — not pre-created by WiX

| Field | Detail |
|-------|--------|
| **ID** | WIX-003 |
| **File** | `internal/logging/logger.go:144,159-161` |
| **Category** | Directory creation — WiX could take over |
| **Severity** | MEDIUM |
| **Verdict** | **DOCUMENT** — recommend WiX pre-create `logs\` subdirectory |

**What it does**:
```go
func openLogFile(logDir string) (*os.File, error) {
    dir := logDir
    if dir == "" {
        dir = defaultLogDir()  // → %PROGRAMDATA%\Qindu\logs on Windows
    }
    if err := os.MkdirAll(dir, 0755); err != nil { ... }
```

**What WiX could do**:
Add a `<Directory>` under `PROGRAMDATADIR` for `logs\` with a `<CreateFolder>` component and the same ACLs as the parent. This would ensure the log directory exists with correct permissions before the service starts.

**Current risk**: The `logs\` directory is created with `0755` (world-readable) on first use. While the parent `PROGRAMDATADIR` has restrictive ACLs from WiX, the Go-created subdirectory may not inherit them cleanly — it depends on Windows ACL inheritance behavior. This is low-risk since `PROGRAMDATA` itself is system-restricted.

**Recommendation**: Add a `LogsDir` `<Directory>` under `PROGRAMDATADIR` in `files.wxs` with the same ACL `<Permission>` elements. Document that Go's `os.MkdirAll` is a fallback for console mode.

---

## Finding 4: `destroyExistingCA()` — Go handles CA file lifecycle during regeneration

| Field | Detail |
|-------|--------|
| **ID** | WIX-004 |
| **File** | `cmd/agent/main.go:230-241` |
| **Category** | Cleanup — mid-install atomic CA replacement |
| **Severity** | LOW |
| **Verdict** | **DOCUMENT** — legitimate Go concern, not WiX territory |

**What it does**:
```go
func destroyExistingCA(caDir string) error {
    os.Remove(filepath.Join(caDir, "ca.crt"))
    os.Remove(filepath.Join(caDir, "ca.key"))
}
```
Removes old CA files before writing new ones during `ca-init` regeneration.

**Why Go handles it**: This is **mid-install** cleanup (during MSI custom actions `CAInitNormal`/`CAInitUnsafe`), not uninstall cleanup. WiX `<RemoveFile>` operates on uninstall, not mid-install. The Go code implements an atomic "destroy old → generate new" pattern that WiX cannot express: if generation fails after destroying the old CA, the install would have no CA at all, but the install wouldn't roll back to the old one either.

**Uninstall cleanup**: WiX's `CleanupProgramDataCmd` (`rmdir /s /q "[PROGRAMDATADIR]"`) handles removal of ALL ProgramData contents on opt-in uninstall (`DELETEDATA=1`). This supersedes `destroyExistingCA`.

**Recommendation**: No change needed. Add a comment clarifying this is mid-install atomicity, not uninstall cleanup.

---

## Finding 5: Hardcoded Windows paths — must stay in sync with WiX directory structure

| Field | Detail |
|-------|--------|
| **ID** | WIX-005 |
| **Files** | `cmd/agent/main.go:282-283,319-324,333-341`; `internal/tls/cert.go:83` |
| **Category** | Path synchronization — Go ↔ WiX contract |
| **Severity** | HIGH |
| **Verdict** | **DOCUMENT** — establish explicit path contract |

**Hardcoded paths**:

| Go Code Location | Path | WiX Equivalent | Sync Risk |
|---|---|---|---|
| `main.go:282-283` | `%PROGRAMFILES%\Qindu\configs\default.yaml` | `INSTALLDIR\ConfigsDir` in `qindu.wxs:69-70` | **LOW** — standard per-machine install folder |
| `main.go:319-324` | `%PROGRAMDATA%\Qindu\config.yaml` | `PROGRAMDATADIR` in `qindu.wxs:74` | **LOW** — `config.yaml` is the override, not the default |
| `main.go:333-341` | `%PROGRAMDATA%\Qindu` (CA dir) | `PROGRAMDATADIR` in `qindu.wxs:74` | **LOW** — directory name `Qindu` matches |
| `cert.go:83` | `file:///C:/ProgramData/Qindu/ca.crl` | `PROGRAMDATADIR` in `qindu.wxs:74` | **HIGH** — hardcoded `C:` drive; breaks if Windows installed on `D:` |

**Critical finding — `cert.go:83`**:
```go
CRLDistributionPoints: []string{"file:///C:/ProgramData/Qindu/" + CRLFilename},
```
This hardcodes the root of the `C:` drive. Windows may be installed on `D:` or another volume. The CRL CDP is embedded in every leaf certificate, so all MITM TLS connections would fail if `%PROGRAMDATA%` resolves to a different drive.

**Fix** (outside scope of this audit — requires code change):
The CDP should derive from `os.Getenv("PROGRAMDATA")` + `\Qindu\ca.crl` at CA generation time, not be a compile-time constant. However, since `ca.crl` is generated by `ca-init` (which runs during MSI install), the correct fix is to pass the resolved `caDir` to `GenerateLeafCert` rather than hardcoding.

**Recommendation**: Add an ADR or code comment that explicitly lists the Go ↔ WiX path contract. Any WiX directory structure change must be matched by Go code updates.

---

## Finding 6: Go creates per-user vault directory — WiX cannot reach user profiles

| Field | Detail |
|-------|--------|
| **ID** | WIX-006 |
| **Files** | `cmd/agent/proxy.go:133`; `internal/crypto/crypto.go:156`; `internal/session/lookup_windows.go:311-315,409-413` |
| **Category** | Directory creation — per-user, outside WiX scope |
| **Severity** | NONE |
| **Verdict** | **DOCUMENT** — legitimate runtime behavior |

**What it does**:
```go
// proxy.go:133
os.MkdirAll(vaultUser.VaultPath, 0700)

// crypto.go:156
os.MkdirAll(filepath.Dir(path), 0700)
```
Creates `%LOCALAPPDATA%\Qindu\` and child directories for the vault key file and database.

**Why WiX cannot handle this**:
The vault lives in each user's profile (`%LOCALAPPDATA%\Qindu\`). WiX is a per-machine installer with `InstallScope="perMachine"`. It cannot:
1. Discover which user accounts exist or will exist on the machine
2. Create directories inside user profiles (profile ACLs prevent it)
3. Apply per-user ACLs (each user's `%LOCALAPPDATA%` is already restricted to that user + SYSTEM by Windows)

**Windows ACL reality**: `%LOCALAPPDATA%` already has correct ACLs enforced by the OS. The Go code's `0700` mode is cosmetic — Unix permission bits don't map to Windows ACLs. The real access control comes from profile directory ACLs.

**Uninstall cleanup gap**: WiX's `CleanupProgramDataCmd` removes `%PROGRAMDATA%\Qindu` but NOT `%LOCALAPPDATA%\Qindu`. Per-user vault data survives uninstall. This is **intentional** — a system-wide uninstaller should not silently delete per-user private data. The future UI (QINDU-0016) will provide per-user vault management.

**Recommendation**: Document that vault path creation is a Go runtime concern, not a WiX concern. Note the uninstall gap explicitly in WiX documentation.

---

## Finding 7: `os.Chmod(0600)` on key file — cosmetic on Windows

| Field | Detail |
|-------|--------|
| **ID** | WIX-007 |
| **File** | `internal/crypto/crypto.go:188` |
| **Category** | File permissions — Unix-only enforcement |
| **Severity** | NONE |
| **Verdict** | **DOCUMENT** — correct behavior |

**What it does**:
```go
// Ensure mode is 0600 even if umask interfered.
if err := f.Chmod(0600); err != nil {
    return fmt.Errorf("crypto: failed to set key file permissions: %w", err)
}
```

**What happens on Windows**: `os.Chmod` on Windows sets the read-only attribute for the "write" bits but does not map to ACLs. On Linux/macOS, this is critical security enforcement. On Windows, it's a no-op that cannot fail in practice.

**Why it stays**: The `crypto` package is cross-platform. The `Chmod` call is critical for Unix security and harmless on Windows. The companion check in `validateKeyFilePermissions()` (line 210) already has a `runtime.GOOS == "windows"` bypass to avoid false positives.

**Recommendation**: No change. Document that Unix permission operations are intentionally kept in the cross-platform crypto package and are no-ops/decorative on Windows where ACLs control access.

---

## Exclusion Confirmation: What stays in Go (correctly)

The following code patterns were examined and confirmed as **legitimate Go runtime concerns**, not WiX territory:

| Code | Reason |
|------|--------|
| `internal/session/lookup_windows.go` | Runtime TCP→PID→SID resolution. Cannot be done by WiX. Excluded per audit scope. |
| `internal/tls/ca_windows.go` DPAPI calls | Runtime encryption of CA key material. WiX cannot perform DPAPI operations. |
| `internal/service/windows_service.go` | Windows SCM integration. Service run loop. |
| `internal/tokenize/memlock_windows.go` | VirtualLock for in-memory PII protection. Runtime concern. |
| `internal/vault/*.go` bbolt operations | Vault persistence is runtime logic. WiX handles only filesystem layout, not application data lifecycle. |
| `vault_test.go:542-560` (`TestBoltDBFilePermissions`) | Tests bbolt file mode. Test concern, not production. |
| `internal/proxy/mitm.go:81` (`InsecureSkipVerify`) | Runtime flag, gated by config. Not installer concern. |
| `configs/default.yaml` | Contains no hardcoded paths. `log_dir: ""` triggers auto-detection which uses `%PROGRAMDATA%` at runtime. |

---

## Consolidated Recommendations

### Immediate (QINDU-0008 sprint)
1. **WIX-005 (cert.go:83)**: Fix the hardcoded CRL CDP path to derive from `os.Getenv("PROGRAMDATA")`. This is the only finding with functional risk on non-standard Windows installs.
2. **WIX-003 (logger.go)**: Consider adding `logs\` subdirectory to `files.wxs` so WiX pre-creates it with correct ACLs.

### Next sprint (QINDU-0009+)
3. **WIX-001 + WIX-002**: Add `// WiX creates %PROGRAMDATA%\Qindu at install time; MkdirAll is a no-op in production, safety net for console dev` comments.
4. **WIX-005**: Establish a `docs/decisions/ADR-0XX-wix-go-path-contract.md` that enumerates the shared filesystem paths and which side (WiX vs Go) owns creation, ACL enforcement, and cleanup.

### Long-term
5. **WIX-006**: In the vault UI sprint (QINDU-0016), provide explicit per-user vault deletion options so users can clean their own data without relying on a system-wide uninstaller.

---

## Verdict

**No Go code removal required.** The WiX installer already owns the correct concerns (ProgramData directory ACLs, service installation, firewall rules, trust store management). The Go code's remaining directory creation operates in user-profile space that WiX cannot and should not reach. The one actionable defect is the hardcoded `C:\ProgramData` path in `cert.go:83`.

**WiX ↔ Go boundary is clean.** The sprint's stated goal — "move ALL Windows-specific permission, ACL, file location, and cleanup concerns from Go code INTO the WiX installer" — is largely achieved. The remaining Go code handles runtime operations that are inherently outside the installer's lifecycle.

---

## WiX-Vault Integration Analysis

**Date**: 2026-07-04
**Analyst**: qindu-peer-reviewer
**Question**: Can WiX take over vault directory creation, ACL enforcement, and uninstall cleanup from Go code?

### Executive summary

**No — the proposal cannot work as stated.** The three parts of the proposal each fail against Windows security reality, for different reasons. However, the proposal surfaces a **pre-existing architectural defect** in the vault path strategy that should be addressed before QINDU-0009 (enforce mode).

---

### Part 1: Can WiX create `%LOCALAPPDATA%\Qindu\` at install time?

**Which `%LOCALAPPDATA%`?**

The Qindu runtime resolves three distinct vault paths, each owned by a different security principal. WiX runs as exactly one of them (the interactive installer user). The other two are unknown or unreachable at install time:

```
Security principal       %LOCALAPPDATA% path                                 When resolved
──────────────────────────────────────────────────────────────────────────────────────────────
Interactive user         C:\Users\opencode-admin\AppData\Local\Qindu\        WiX install time
(installer)

NT AUTHORITY\LocalService C:\Windows\ServiceProfiles\LocalService\           Go startup (initVault)
(service process)         AppData\Local\Qindu\

Browser user (Alice)     C:\Users\Alice\AppData\Local\Qindu\                 Go runtime per connection
                          (per DD-12/DD-13)                                  (LookupVaultPathForPort)
```

**Why WiX cannot pre-create per-user vault directories:**

1. **Service profile isolation.** `C:\Windows\ServiceProfiles\LocalService\` is a system-managed profile. Windows creates it on first use by the service account. WiX creating subdirectories inside it is brittle — the profile may not exist yet, or Windows may recreate it during servicing.

2. **Cross-profile ACL barrier.** Windows profile ACLs grant access **only** to the profile owner and `SYSTEM`. The Qindu service (`LocalService`) cannot read `C:\Users\opencode-admin\AppData\Local\`, and vice versa. If WiX creates `Qindu\` under the installer's profile, the service will receive `ACCESS_DENIED` when it tries to open vault files there.

3. **Unknown user set.** A shared Windows machine may have dozens of user accounts. WiX has no mechanism to enumerate them, and even if it did, `InstallScope="perMachine"` MSIs run as `SYSTEM` (not the user), but WiX cannot write to arbitrary user profiles on a multi-user system without breaking profile ACLs.

4. **Temporal mismatch.** New user accounts created after installation would have no vault directory. The creation must happen at first-use time, not at install time.

**Verdict: NOT VIABLE.** Per-user vault directory creation is inherently a runtime operation. The target path depends on a dynamic SID→profile resolution that occurs per-connection, not once at install time.

---

### Part 2: Can `<util:PermissionEx>` set `owner+SYSTEM only` on vault directories?

**Technical capability:** Yes, WiX `<util:PermissionEx>` can set explicit ACLs on any directory the installer can write to. It supports granting or denying specific rights to specific security principals.

**Practical reality:**

| Problem | Detail |
|---------|--------|
| **ACL inheritance** | Creating a subdirectory under `%LOCALAPPDATA%` inherits the parent ACL by default. WiX would need to break inheritance (`Inheritable=no` or explicit replace) to set custom ACLs. Breaking inheritance on profile subdirectories is fragile — Windows may reapply inherited ACLs during profile maintenance, group policy refresh, or OS upgrades. |
| **Principal mismatch** | The service runs as `LocalService`. A `owner+SYSTEM only` ACL on a directory under `C:\Users\Alice\AppData\Local\` would grant access to **Alice** (the profile owner) and **SYSTEM**, but NOT to `LocalService`. The service would be locked out of its own vault. To fix this, the ACL would need to explicitly grant `LocalService` access — but that would give the service account access to Alice's entire `%LOCALAPPDATA%` subtree, not just `Qindu\`. This is a **security regression**: `LocalService` should not have blanket access to user profiles. |
| **os.Chmod equivalence** | The current Go code's `os.Chmod(0600)` is decorative on Windows because Unix permission bits don't map to ACLs. But `<util:PermissionEx>` wouldn't be decorative — it would actively modify Windows ACLs. This is more powerful but also more dangerous if misconfigured. |

**Verdict: TECHNICALLY POSSIBLE but ARCHITECTURALLY WRONG.** The correct access control for per-user vault data comes from the **profile boundary** itself: Alice's `%LOCALAPPDATA%` is already inaccessible to Bob, to other users, and to `LocalService`. Adding WiX ACL manipulation would at best be redundant and at worst weaken the existing profile isolation.

---

### Part 3: Can WiX `<RemoveFile>` clean up vault files on uninstall?

**For `%PROGRAMDATA%\Qindu\`:** Already handled. `CleanupProgramDataCmd` runs `rmdir /s /q` on this tree during uninstall when `DELETEDATA=1`. ✓

**For per-user `%LOCALAPPDATA%\Qindu\`:** Not viable.

WiX `<RemoveFile>` requires the target path to be known at **install time** (it's recorded in the MSI database during `InstallFiles`). The per-user vault paths depend on which user accounts connect through the proxy — information unavailable when the MSI was authored.

Even if the paths were known, a system-wide uninstaller **should not silently delete per-user private data**. This is why `DELETEDATA=1` is opt-in. A user's vault may contain PII token mappings they want to preserve even after Qindu is uninstalled.

**For the service profile vault** (`C:\Windows\ServiceProfiles\LocalService\AppData\Local\Qindu\`):

This path IS known at install time. WiX could theoretically add a `<RemoveFile>` or `<RemoveFolder>` for it. However, this path should only contain the **bootstrap vault** — the `initVault()` call creates a vault for the service process itself (used for metadata, not per-user PII per DD-12). Per the QEMU test, this is the vault that currently gets created.

**Verdict: PARTIALLY VIABLE for the service profile vault only.** WiX could clean up the service's own bootstrap vault on opt-in uninstall. Per-user vault cleanup remains a runtime/UI concern (QINDU-0016).

---

### The deeper problem this proposal exposes

The proposal asks "can WiX create the vault directory?" — but the real question is **"should the vault live in `%LOCALAPPDATA%` at all?"**

The current architecture (DD-12) places the vault in `%LOCALAPPDATA%\Qindu\`. On a per-user process (Linux, macOS, Windows console mode), this works naturally: each user's process runs under their own account and has access to their own profile.

**But on Windows service mode**, the process runs as `LocalService`, NOT as the browser user. The service must cross a security boundary to read/write another user's profile. The `lookup_windows.go` code resolves the correct path via `SHGetKnownFolderPath`, but the **filesystem ACL still blocks access**.

Consider the code path in `initVault()`:

```go
// cmd/agent/proxy.go:124
vaultUser, lookupErr := session.LookupVaultPath()
// → On Windows: returns C:\Windows\ServiceProfiles\LocalService\AppData\Local\Qindu\
//   (the service's OWN profile, NOT any browser user's profile)

os.MkdirAll(vaultUser.VaultPath, 0700)   // ← creates service's own vault directory
crypto.New(vaultUser.KeyPath)            // ← creates vault.key in service profile
bolt.Open(vaultUser.DBPath, 0600, ...)   // ← creates vault.db in service profile
```

This creates a **bootstrap vault** in the service account's profile. Per-connection vaults (via `LookupVaultPathForPort`) would resolve to browser user profiles, but those paths are never used to create vault instances in the current code — `initVault()` only calls `LookupVaultPath()`, not `LookupVaultPathForPort()`.

**This is a pre-existing architectural gap**: the vault initialization path creates ONE vault (the service's own), not per-user vaults. Per-user vault isolation (AC-4) is not yet implemented in the runtime. The SID resolution code exists (`lookup_windows.go`) but is not wired into vault creation.

---

### Recommended path forward

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      WIX OWNS (install-time)                            │
│                                                                         │
│  %PROGRAMDATA%\Qindu\                                                   │
│  ├── ca.crt / ca.key / ca.crl     ← ACLs via <Permission>              │
│  ├── config.yaml (override)       ← created by MSI custom action        │
│  └── logs\agent.log              ← add to files.wxs (WIX-003)          │
│                                                                         │
│  Uninstall: CleanupProgramDataCmd (DELETEDATA=1, opt-in)               │
├─────────────────────────────────────────────────────────────────────────┤
│                      GO OWNS (runtime)                                  │
│                                                                         │
│  %LOCALAPPDATA%\Qindu\             ← per-user, created by Go at         │
│  ├── vault.key                      first connection (not WiX)          │
│  └── vault.db                                                           │
│                                                                         │
│  Uninstall: Future UI (QINDU-0016); not system-wide uninstaller        │
└─────────────────────────────────────────────────────────────────────────┘
```

**Immediate actions (this sprint):**

1. **Do not move vault directory creation to WiX.** It cannot work across security principal boundaries. The current Go code is correct for the service's own bootstrap vault.

2. **Do not add `<util:PermissionEx>` for vault directories.** The `%LOCALAPPDATA%` profile ACL is the correct security boundary. Adding or modifying ACLs on profile subtrees risks breaking Windows profile integrity.

3. **Add WiX `<RemoveFile>` for the service profile vault ONLY**, gated behind `DELETEDATA=1`:
   ```xml
   <!-- Clean up service's own bootstrap vault on opt-in uninstall -->
   <SetProperty Id="CleanupServiceVaultCmd" Before="CleanupServiceVaultCmd" Sequence="execute"
       Value="&quot;cmd.exe&quot; /c rmdir /s /q &quot;[%LOCALAPPDATA]\Qindu&quot;">
       Installed AND DELETEDATA=&quot;1&quot;
   </SetProperty>
   ```
   Note: `[%LOCALAPPDATA]` resolves to the **installing user's** `%LOCALAPPDATA%`, NOT the service account's. This would need adjustment — see below.

**Design actions (before QINDU-0009 enforce mode):**

4. **Resolve the vault location question.** The current design has an inherent tension between DD-12 (per-user vault in `%LOCALAPPDATA%`) and the Windows service reality (process runs as `LocalService`, not the browser user). Options:

   | Option | Description | Pros | Cons |
   |--------|-------------|------|------|
   | **A: Status quo** | Fix cross-profile ACLs so LocalService can access all user profiles | No path changes needed | Breaks Windows profile isolation; security risk |
   | **B: Machine-wide vault** | Move vault to `%PROGRAMDATA%\Qindu\vaults\{SID}\` | WiX can create parent; LocalService already has access; uninstall cleanup is trivial | Changes DD-12/DD-13; SID subdirectories still created at runtime |
   | **C: Per-user agent** | Run one agent.exe per user session (not a system service) | Natural profile isolation; no cross-account access needed | Requires ADR-006 revision; loses centralized service management |

   **Recommendation: Option B.** A machine-wide vault under `%PROGRAMDATA%\Qindu\vaults\{SID}\` with per-SID subdirectories gives WiX full control over the parent tree (creation, ACLs, cleanup) while Go creates SID subdirectories at runtime. The SID subdirectories inherit the parent's ACLs (SYSTEM + Administrators full control, LocalService read/write — already defined in `files.wxs`). This eliminates the cross-profile access problem entirely.

5. **Wire per-user vault creation to connection-time lookup.** The `LookupVaultPathForPort()` code exists but `initVault()` doesn't use it. Per-user vault instances should be created lazily on first connection from a given SID, not at agent startup.

---

### Final answer to the proposal

| Proposal part | Viable? | Why |
|---------------|---------|-----|
| WiX creates `%LOCALAPPDATA%\Qindu\` at install time | **No** | Target path depends on dynamic per-connection SID→profile resolution; installer runs as wrong principal; multiple profiles unknown at install time |
| WiX `<util:PermissionEx>` sets owner+SYSTEM ACLs | **Technically yes, architecturally no** | Would break existing profile isolation or be redundant with it; wrong security boundary |
| WiX `<RemoveFile>` handles vault uninstall cleanup | **Partially** | Can clean service profile vault path (known at install time); cannot reach per-user profile vaults; per-user vault cleanup should be a UI feature, not an uninstall action |

**The proposal is rejected as stated**, but the underlying concern — moving file-location and ACL responsibility out of Go — is valid. The fix is not to shove vault creation into WiX, but to **move the vault to a machine-wide location** where WiX already manages the directory lifecycle. This requires a design decision (Option B above) before QINDU-0009.
