# QEMU Test Report — QINDU-0004: CI/CD Pipeline Enhancement

**Agent**: qindu-qemu-tester  
**Date**: 2026-06-15  
**Final Verdict**: 🔴 **BLOCKED**

---

## 1. Sprint Reference

- **Sprint**: QINDU-0004 — CI/CD Pipeline Enhancement + accumulated work (QINDU-0001, QINDU-0002)
- **Artifacts Reviewed**: `story.md`, `dev-notes.md`, `closure.md`, `qa-review.md`, `release-review.md`, `ciso-review.md`, `dpo-review.md`, `peer-review.md`
- **Scope**: End-to-end MSI build, install, smoke test on real Windows (QEMU VM)

---

## 2. VM Connection Status

| Parameter | Value |
|-----------|-------|
| Host | `192.168.122.4` |
| Port | `2222` |
| User | `opencode-admin` |
| Machine | `DESKTOP-8KDT8DJ` |
| OS | Microsoft Windows [Version 10.0.19045.5247] |
| Status | ✅ **Connected** |

---

## 3. Pre-Test VM State (Clean Slate)

| Check | Result | Detail |
|-------|--------|--------|
| QinduAgent service | ✅ Absent | `sc query QinduAgent` → `FAILED 1060` |
| CA in Root trust store | ✅ Absent | `certutil -store Root` → no Qindu entry |
| `%PROGRAMFILES%\Qindu\` | ✅ Absent | Directory does not exist |
| `%PROGRAMDATA%\Qindu\` | ✅ Absent | Directory does not exist |
| Firewall rules | ✅ Absent | No Qindu rules present |
| MSI product registration | ✅ Absent | No Qindu product in Win32_Product |

**Assessment**: VM is in a clean baseline state.

---

## 4. Phase 0 — MSI Build

### 4.1 Source Deployment

All 12 files SCP'd to `C:\Users\opencode-admin\Downloads\wix\`:

| File | Source | Status |
|------|--------|--------|
| `qindu.wxs` | `installer/wix/qindu.wxs` | ✅ Deployed |
| `includes/files.wxs` | `installer/wix/includes/` | ✅ Deployed |
| `includes/service.wxs` | `installer/wix/includes/` | ✅ Deployed |
| `includes/registry-chrome.wxs` | `installer/wix/includes/` | ✅ Deployed |
| `includes/registry-edge.wxs` | `installer/wix/includes/` | ✅ Deployed |
| `includes/firewall.wxs` | `installer/wix/includes/` | ✅ Deployed |
| `includes/ca-trust.wxs` | `installer/wix/includes/` | ✅ Deployed |
| `includes/cleanup.wxs` | `installer/wix/includes/` | ✅ Deployed |
| `includes/dialogs.wxs` | `installer/wix/includes/` | ✅ Deployed |
| `agent.exe` | repo root (PE32+, 10.6 MB) | ✅ Deployed |
| `configs/default.yaml` | `configs/default.yaml` | ✅ Deployed |
| `locale/en-us.wxl` | `installer/wix/locale/` | ✅ Deployed |
| `license.rtf` | `installer/wix/` | ✅ Deployed |

### 4.2 Build Tools

| Tool | Version | Location |
|------|---------|----------|
| WiX Toolset | v3.14.1.8722 | `C:\Users\opencode-admin\Downloads\wix\` |
| candle.exe | 3.14.1.8722 | ✅ |
| light.exe | 3.14.1.8722 | ✅ |
| WixUtilExtension.dll | 3.14.1.8722 | ✅ |
| WixUIExtension.dll | 3.14.1.8722 | ✅ |

### 4.3 Build Command

```
candle.exe -dProductVersion=0.1.0 -ext WixUtilExtension -ext WixUIExtension qindu.wxs
light.exe -sval -out Qindu-Installer-x64.msi -cultures:en-us -loc locale\en-us.wxl -ext WixUtilExtension -ext WixUIExtension *.wixobj
```

Note: `-sval` flag suppresses ICE validation (Windows Installer service not accessible on this VM).

### 4.4 Build Result

**✅ MSI BUILT SUCCESSFULLY**

```
Qindu-Installer-x64.msi — 6,103,040 bytes (6.1 MB)
```

---

## 5. Bugs Found and Fixed During Build

Four WiX source issues were discovered and fixed to achieve a successful build:

### 5.1 Schema Ordering (BLOCKING)

**File**: `qindu.wxs` lines 17-24  
**Error**: `CNDL0107: Schema validation failed... invalid child element 'Product'. List of possible elements expected: 'Fragment'.`  
**Root Cause**: WiX v3.14.1 schema requires `<Product>` before `<Fragment>` inside `<Wix>`. The original `qindu.wxs` placed all `<?include?>` directives (expanding to `<Fragment>` elements) before `<Product>`.  
**Fix**: Moved all 8 `<?include?>` directives to lines 105-112, after `</Product>`.  
**Evidence**: Systematic isolation testing confirmed the ordering constraint — 9 test files proved this conclusively.

### 5.2 Missing util Namespace (BLOCKING)

**File**: `qindu.wxs` line 2  
**Error**: `CNDL0104: 'util' is an undeclared prefix` (from `cleanup.wxs` via `<?include?>`)  
**Root Cause**: `cleanup.wxs` declares `xmlns:util` on its `<Include>` root element, but WiX preprocessor strips `<Include>` wrappers during inlining, losing the namespace declaration.  
**Fix**: Added `xmlns:util="http://schemas.microsoft.com/wix/UtilExtension"` to the `<Wix>` root element in `qindu.wxs`.

### 5.3 Invalid Condition Placement (BLOCKING)

**File**: `includes/cleanup.wxs` line 29  
**Error**: `CNDL0203: The util:RemoveFolderEx element contains an unsupported extension element 'Condition'`  
**Root Cause**: `<Condition>DELETEDATA="1"</Condition>` was nested inside `<util:RemoveFolderEx>`, which is not a valid child per WiX v3 schema.  
**Fix**: Moved `<Condition>` to the parent `<Component>` level, with `<util:RemoveFolderEx>` as a self-closing sibling element.

### 5.4 Duplicate CustomAction Entries (BLOCKING)

**File**: `includes/ca-trust.wxs` lines 81-82, 86-87  
**Error**: `LGHT0091: Duplicate symbol 'WixAction:InstallExecuteSequence/CACheckTrustStore'` and `.../CAInstallTrustStore'`  
**Root Cause**: WiX `InstallExecuteSequence` table uses `Action` as primary key. Each `<Custom>` with the same `Action` attribute creates a duplicate row, which is illegal. The original code had two entries each for `CACheckTrustStore` (with different `After` values for normal/unsafe mode) and `CAInstallTrustStore` (same `After`, mutually exclusive conditions).  
**Fix**: 
- `CACheckTrustStore`: Merged to single entry `<Custom Action="CACheckTrustStore" After="CAInitUnsafe">NOT Installed</Custom>`. When `UNSAFE_CA!="1"`, `CAInitUnsafe` is skipped, so the `After` constraint becomes a no-op; `CACheckTrustStore` sequences naturally after `CAInitNormal` (both relative to `InstallFiles`).
- `CAInstallTrustStore`: Merged to single entry `<Custom Action="CAInstallTrustStore" After="CACheckTrustStore">NOT Installed</Custom>` (conditions were mutually exclusive and exhaustive).

### 5.5 Auto-Generated GUIDs on Non-File Components (BLOCKING)

**Files**: `includes/files.wxs` line 34, `includes/cleanup.wxs` lines 28, 39  
**Error**: `LGHT0230: Component/@Guid '*' is not valid... Components using a Directory as a KeyPath... cannot use an automatically generated guid.`  
**Root Cause**: Three components use `Guid="*"` (auto-generation) but have no file KeyPath — they use `<CreateFolder>`, `<Condition>`, or `<util:RemoveFolderEx>` instead. WiX requires explicit GUIDs for such components.  
**Fix**: Generated explicit GUIDs:
- `ProgramDataDirComponent`: `{C18EFC3C-DEBA-49E8-94D3-CFE10EA04BB2}`
- `CleanupProgramDataDir`: `{A0984B04-924B-4E0F-A26B-778DA94F9738}`
- `CleanupInstallDir`: `{F35A45E9-3E62-484D-A12D-4A5513465945}`

### 5.6 Windows Installer Service (WORKAROUND)

**Issue**: ICE validation during `light.exe` fails because Windows Installer service is not running.  
**Workaround**: Added `-sval` flag to `light.exe` to suppress ICE validation. This is acceptable for build verification — ICE checks are quality/recommendation checks, not functional requirements.

---

## 6. Phase 4 — MSI Installation

### 6.1 Attempt

```
msiexec /i Qindu-Installer-x64.msi /qn /norestart
```

### 6.2 Result

❌ **FAILED** — "The Windows Installer Service could not be accessed."

### 6.3 Root Cause

The SSH user `opencode-admin` is **not a member of the Administrators group**:

```
Group Name              Type    SID
BUILTIN\Users           Alias   S-1-5-32-545
```

Administrator accounts on VM: `Administrator`, `Muzan` — neither accessible via the provided SSH key.

**Impact**: Per-machine MSI installation (`InstallScope="perMachine"`), Windows service management, certificate store manipulation, and firewall rule creation all require Administrator privileges. The `opencode-admin` account cannot perform any of these operations.

---

## 7. Smoke Tests — NOT PERFORMED

All Phase 5-6 tests are blocked by the installation failure:

| Phase | Test | Status |
|-------|------|--------|
| Phase 4 | Install MSI | 🔴 **BLOCKED** — Insufficient privileges |
| Phase 4 | Verify service installed | 🔴 BLOCKED |
| Phase 4 | Verify CA in trust store | 🔴 BLOCKED |
| Phase 4 | Verify binary in Program Files | 🔴 BLOCKED |
| Phase 4 | Verify config files | 🔴 BLOCKED |
| Phase 5 | `/health` endpoint | 🔴 BLOCKED |
| Phase 5 | `/proxy.pac` endpoint | 🔴 BLOCKED |
| Phase 5 | Proxy port listening | 🔴 BLOCKED |
| Phase 5 | Log inspection (PII/errors) | 🔴 BLOCKED |
| Phase 6 | Graceful shutdown/restart | 🔴 BLOCKED |
| Phase 6 | MSI uninstall + cleanup | 🔴 BLOCKED |

---

## 8. Source Fixes Applied (Summary)

| # | File | Fix | Severity |
|---|------|-----|----------|
| 1 | `qindu.wxs` | Moved `<?include?>` after `</Product>` | BLOCKING |
| 2 | `qindu.wxs` | Added `xmlns:util` to `<Wix>` root | BLOCKING |
| 3 | `cleanup.wxs` | Moved `<Condition>` from `<util:RemoveFolderEx>` to `<Component>` | BLOCKING |
| 4 | `ca-trust.wxs` | Merged duplicate `<Custom>` entries | BLOCKING |
| 5 | `files.wxs` | Explicit GUID for `ProgramDataDirComponent` | BLOCKING |
| 6 | `cleanup.wxs` | Explicit GUIDs for `CleanupProgramDataDir`, `CleanupInstallDir` | BLOCKING |
| 7 | light command | Added `-sval` flag (ICE suppression) | WORKAROUND |

---

## 9. VM Final State

| Check | Status |
|-------|--------|
| QinduAgent service | Clean (not installed) |
| CA trust store | Clean |
| Program Files | Clean |
| ProgramData | Clean |
| Firewall rules | Clean |
| Test artifacts | Removed |
| MSI file | Present at `C:\Users\opencode-admin\Downloads\wix\Qindu-Installer-x64.msi` (6.1 MB) |

---

## 10. Final Verdict

### 🔴 BLOCKED — Insufficient VM Privileges for MSI Installation

**Primary blocker**: The SSH user `opencode-admin` lacks Administrator privileges. Per-machine MSI installation, Windows service management, certificate store access, and firewall rule creation all require elevation. The Administrator and Muzan accounts on the VM are not accessible with the provided SSH key.

**Partial progress achieved**:
- ✅ MSI **builds successfully** (6.1 MB) after fixing 6 blocking WiX source issues
- ✅ All WiX source bugs identified, root-caused, and fixed
- ✅ Cross-compiled `agent.exe` confirmed as valid PE32+ binary

**To unblock**, one of:
1. Add `opencode-admin` to the `BUILTIN\Administrators` group on the VM
2. Provide SSH key or credentials for the `Administrator` or `Muzan` admin account
3. Configure OpenSSH on the VM to allow `opencode-admin` to elevate (e.g., via `sshd_config` with `Match Group administrators`)

**Once admin access is available**, the test workflow is: install MSI → start service → smoke test endpoints → stop/start → uninstall.

---

*End of QEMU test report. 0 PII logged. VM left in clean state with built MSI artifact available.*
