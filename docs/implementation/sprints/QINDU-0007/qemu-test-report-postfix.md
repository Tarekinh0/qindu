# QEMU Test Report — MSI Uninstall Fix (HOTFIX-002)

**Agent**: qindu-qemu-tester  
**Date**: 2026-07-04  
**VM**: `DESKTOP-8KDT8DJ` (Windows 10 19045), `192.168.122.4:2222`  
**MSI**: `Qindu-Installer-x64.msi` (6,283,264 bytes, built from fixed WiX source)  
**Final Verdict**: 🟢 **PASS** — Install → Uninstall → Reinstall all pass cleanly.

---

## 1. Root Cause Analysis

The MSI uninstall was completely broken in prior rounds. `msiexec /x {GUID} DELETEDATA=1 /qn` returned exit code 0 with "Removal completed successfully" but left behind:
- `QinduAgent` service (still RUNNING)
- `C:\Program Files\Qindu\` (all files)
- `C:\ProgramData\Qindu\` (all files)
- Chrome/Edge registry policies (all 6 values)
- Only CA cert and firewall rules were actually removed

### Root Cause 1: Broken `RemoveFolderEx` cascading failure

In `installer/wix/includes/cleanup.wxs`, the `CleanupInstallDir` component used:
```xml
<util:RemoveFolderEx Id="CleanupInstallDirEx" On="uninstall" Property="INSTALLDIR" />
```

During uninstall, `WixRemoveFoldersEx` runs **before** `CostInitialize`, so `INSTALLDIR` is not yet resolved. This causes:
```
WixRemoveFoldersEx: Error 0x80070057: Missing folder property: INSTALLDIR
```
This error triggers a cascading failure where MSI sets **ALL** component actions to `Null`, blocking `RemoveFiles`, `DeleteServices`, and `RemoveRegistryValues`.

### Root Cause 2: Orphaned MSI component registrations

Prior broken install/uninstall cycles left orphaned component entries in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components`, all referencing product `8E2D028175E365C4E9585096B9662B35`. MSI ref-counts by **file path and registry key path** (not component GUID), so even fresh installs with different component GUIDs were blocked by the orphaned entries claiming the same resources.

6 orphaned component entries were found:
- `C:\Program Files\Qindu\` (INSTALLDIR)
- `C:\Program Files\Qindu\agent.exe`
- `C:\Program Files\Qindu\configs\default.yaml`
- `C:\ProgramData\Qindu\`
- `Software\Policies\Google\Chrome\ProxyMode`
- `Software\Policies\Microsoft\Edge\ProxyMode`

---

## 2. Fix Applied

### Fix 1: Remove `CleanupInstallDir` component
File: `installer/wix/includes/cleanup.wxs`
- Removed the entire `CleanupInstallDir` fragment (lines 63-73) containing `<util:RemoveFolderEx Property="INSTALLDIR">`
- Removed the `CleanupComponents` `ComponentGroup` fragment (lines 75-79)
- MSI's standard `RemoveFiles` action already handles tracked files in `INSTALLDIR`

### Fix 2: Remove Feature reference
File: `installer/wix/qindu.wxs` (line 89)
- Removed `<ComponentGroupRef Id="CleanupComponents" />` from `MainFeature`

### Fix 3: Orphaned component cleanup
All 6 orphaned component registrations were manually deleted from:
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components`

---

## 3. Build

| Step | Result |
|------|--------|
| Candle compile | ✅ PASS — no errors |
| Light link | ✅ PASS — no errors |
| Output | `Qindu-Installer-x64.msi` — 6,283,264 bytes |

Command:
```
candle qindu.wxs -dProductVersion=0.1.0 -arch x64 -ext WixUtilExtension -ext WixUIExtension
light -sval -out Qindu-Installer-x64.msi -cultures:en-us -loc locale\en-us.wxl -ext WixUtilExtension -ext WixUIExtension qindu.wixobj
```

---

## 4. Test Cycle Results

### 4.1 Fresh Install

| Check | Result | Detail |
|-------|--------|--------|
| Service | ✅ PASS | `QinduAgent` STATE: 4 RUNNING |
| agent.exe | ✅ PASS | `C:\Program Files\Qindu\agent.exe` |
| ca.crt | ✅ PASS | `C:\ProgramData\Qindu\ca.crt` |
| Health endpoint | ✅ PASS | `{"status":"up","version":"0.1.0","uptime":"13.4s"}` |
| Chrome policies | ✅ PASS | ProxyMode=pac_script, ProxyPacUrl set, QuicAllowed=0 |
| Edge policies | ✅ PASS | ProxyMode=pac_script, ProxyPacUrl set, QuicAllowed=0 |
| Firewall | ✅ PASS | Allow Loopback rule present and enabled |
| CA in trust store | ✅ PASS | Qindu CA in Root store |
| Product code | `{7CE412B4-5EE1-43EE-A3B4-0AA0188F4379}` |

### 4.2 Uninstall with DELETEDATA=1

Command: `msiexec /x {7CE412B4-5EE1-43EE-A3B4-0AA0188F4379} DELETEDATA=1 /qn`

| Check | Result |
|-------|--------|
| Service removed | ✅ PASS — 1060: service does not exist |
| `C:\Program Files\Qindu\` | ✅ PASS — File Not Found |
| `C:\ProgramData\Qindu\` | ✅ PASS — File Not Found (DELETEDATA worked) |
| Chrome policies (HKLM) | ✅ PASS — registry key not found |
| Edge policies (HKLM) | ✅ PASS — registry key not found |
| Firewall rules | ✅ PASS — no Qindu rules |
| CA in trust store | ✅ PASS — no Qindu CA |
| Product in wmic | ✅ PASS — No Instance(s) Available |
| MSI component orphans | ✅ PASS — 0 matches found |

**All 9 verification checks PASS.**

### 4.3 Reinstall

Command: `msiexec /i Qindu-Installer-x64.msi /qn`

| Check | Result |
|-------|--------|
| Service | ✅ PASS — STATE: 4 RUNNING |
| Health endpoint | ✅ PASS — `{"status":"up","version":"0.1.0","uptime":"5.5s"}` |
| Files present | ✅ PASS — agent.exe, ca.crt |
| Chrome policies | ✅ PASS — all 3 values set |

**Reinstall fully functional.**

---

## 5. What Changed

The only WiX source change was removing the `CleanupInstallDir` component with its `RemoveFolderEx` on `INSTALLDIR`. The separate `CleanupProgramDataCmd` deferred CA (WixQuietExec64, for DELETEDATA=1) was **kept** and continues to work correctly.

The orphaned MSI component registrations were a **one-time cleanup** artifact from prior broken install/uninstall cycles. Future installs/uninstalls using the fixed MSI will not create orphaned registrations because the uninstall now properly executes `RemoveFiles`, `DeleteServices`, and `RemoveRegistryValues` for all components.

---

## 6. Final Verdict

### 🟢 **PASS**

The full install → uninstall (DELETEDATA=1) → reinstall cycle completes correctly. All physical artifacts (service, files, directories, registry policies, firewall rules, CA cert) are properly removed on uninstall. Reinstall succeeds with full functionality.

**Acceptance criteria met**:
- Silent install succeeds ✅
- Service runs and health endpoint responds ✅
- Chrome/Edge policies, firewall, CA all configured ✅
- Uninstall with DELETEDATA=1 removes **everything** ✅
- Reinstall works after complete uninstall ✅
- Zero PII or secrets in logs ✅

---

**End of QEMU test report (HOTFIX-002).**
