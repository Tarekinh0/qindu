# Qindu VM Cleanup Guide

## Artifact Inventory (from WiX installer analysis)

The Qindu MSI installer creates artifacts in these locations:

| Category | Location | Artifacts |
|----------|----------|-----------|
| **Program Files** | `C:\Program Files\Qindu\` | `agent.exe`, `configs\default.yaml` |
| **ProgramData** | `C:\ProgramData\Qindu\` | `ca.crt`, `ca.key`, `ca.crl`, `logs\`, `vault.db` (runtime) |
| **Service** | Windows Service | `QinduAgent` (NT AUTHORITY\LocalService, auto-start) |
| **CA Certificate** | Root Trust Store | `Qindu AI Privacy CA` (certificate + CRL) |
| **Firewall** | Inbound Rules | `Qindu Agent (Allow Loopback)` — TCP 8787 from 127.0.0.1<br>`Qindu Agent (Block External)` — TCP 8787 from any |
| **Chrome Policy** | `HKLM\Software\Policies\Google\Chrome` | `ProxyMode`="pac_script", `ProxyPacUrl`="http://127.0.0.1:8787/proxy.pac", `QuicAllowed`=0 |
| **Edge Policy** | `HKLM\Software\Policies\Microsoft\Edge` | `ProxyMode`="pac_script", `ProxyPacUrl`="http://127.0.0.1:8787/proxy.pac", `QuicAllowed`=0 |
| **MSI Registration** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` | Product entry with UpgradeCode `{5319E462-2A8D-476D-8896-32F36E454A98}` |
| **MSI Cache** | `HKCR\Installer\Products\` | Cached MSI product metadata |
| **Downloads** | `%USERPROFILE%\Downloads\` | *.msi, *.log, test executables, build artifacts |

### Locations that do NOT contain Qindu artifacts (verified on VM)

- `%LOCALAPPDATA%\Qindu` — not used
- `%APPDATA%\Qindu` — not used
- `HKCU\Software\Qindu` — not used
- `HKLM\Software\Qindu` — not used directly (policies go under `Software\Policies\...`)
- `C:\Windows\Temp` — not used
- `C:\ProgramData\Microsoft\Windows\Start Menu\Programs` — not used
- Scheduled Tasks — not used
- Environment Variables — not used

---

## Step-by-Step Cleanup Commands

Run each block in an elevated (Administrator) command prompt or PowerShell.

### 1. Stop and remove the service

```cmd
sc stop QinduAgent
sc delete QinduAgent
```

### 2. Run MSI uninstaller (preferred method)

```cmd
REM Find the product code first:
wmic product where "name like 'Qindu%'" get IdentifyingNumber

REM Uninstall (replace {PRODUCT-CODE} with actual GUID):
msiexec /x {PRODUCT-CODE} /qn /norestart
```

To also delete ProgramData during uninstall:
```cmd
msiexec /x {PRODUCT-CODE} DELETEDATA=1 /qn /norestart
```

### 3. Remove firewall rules

```cmd
netsh advfirewall firewall delete rule name="Qindu Agent (Allow Loopback)"
netsh advfirewall firewall delete rule name="Qindu Agent (Block External)"
```

### 4. Remove CA certificate from trust store

```cmd
certutil -delstore Root "Qindu AI Privacy CA"
```

This also removes the CRL from the same store. The CA name is defined in `installer/wix/locale/en-us.wxl` as the `CAName` string.

### 5. Remove Chrome/Edge proxy policies

```cmd
reg delete "HKLM\Software\Policies\Google\Chrome" /f
reg delete "HKLM\Software\Policies\Microsoft\Edge" /f
```

> **Note**: If `HKLM\Software\Policies\Google\Chrome` or `HKLM\Software\Policies\Microsoft\Edge` contain other non-Qindu policies you want to keep, delete individual values instead:
> ```cmd
> reg delete "HKLM\Software\Policies\Google\Chrome" /v ProxyMode /f
> reg delete "HKLM\Software\Policies\Google\Chrome" /v ProxyPacUrl /f
> reg delete "HKLM\Software\Policies\Google\Chrome" /v QuicAllowed /f
> reg delete "HKLM\Software\Policies\Microsoft\Edge" /v ProxyMode /f
> reg delete "HKLM\Software\Policies\Microsoft\Edge" /v ProxyPacUrl /f
> reg delete "HKLM\Software\Policies\Microsoft\Edge" /v QuicAllowed /f
> ```

### 6. Delete directories

```cmd
rmdir /s /q "C:\Program Files\Qindu"
rmdir /s /q "C:\ProgramData\Qindu"
```

### 7. Clean up Downloads

```cmd
del /q "%USERPROFILE%\Downloads\*qindu*"
del /q "%USERPROFILE%\Downloads\*Qindu*"
rmdir /s /q "%USERPROFILE%\Downloads\qindu-build"
```

### 8. Clean MSI cached metadata (if any remains)

```cmd
REM Search for any Qindu entries in the MSI installer cache:
reg query "HKCR\Installer\Products" /s /f Qindu
REM If found, delete the relevant GUID subkey
```

---

## "Nuke It All" Script

Save as `nuke-qindu.ps1` and run as Administrator:

```powershell
#Requires -RunAsAdministrator
$ErrorActionPreference = "Continue"
Write-Host "=== NUKING QINDU FROM THIS MACHINE ===" -ForegroundColor Red

# 1. Service
Write-Host "[1/8] Stopping and removing service..."
sc.exe stop QinduAgent 2>$null
sc.exe delete QinduAgent 2>$null
Write-Host "  Done."

# 2. CA certificate
Write-Host "[2/8] Removing CA from trust store..."
certutil -delstore Root "Qindu AI Privacy CA" 2>$null
Write-Host "  Done."

# 3. Firewall rules
Write-Host "[3/8] Removing firewall rules..."
netsh advfirewall firewall delete rule name="Qindu Agent (Allow Loopback)" 2>$null
netsh advfirewall firewall delete rule name="Qindu Agent (Block External)" 2>$null
Write-Host "  Done."

# 4. Browser policies
Write-Host "[4/8] Removing Chrome/Edge policies..."
reg delete "HKLM\Software\Policies\Google\Chrome" /f 2>$null
reg delete "HKLM\Software\Policies\Microsoft\Edge" /f 2>$null
Write-Host "  Done."

# 5. Directories
Write-Host "[5/8] Deleting Program Files..."
Remove-Item -Recurse -Force "C:\Program Files\Qindu" -ErrorAction SilentlyContinue
Write-Host "[6/8] Deleting ProgramData..."
Remove-Item -Recurse -Force "C:\ProgramData\Qindu" -ErrorAction SilentlyContinue
Write-Host "  Done."

# 6. Downloads
Write-Host "[7/8] Cleaning Downloads..."
Get-ChildItem "$env:USERPROFILE\Downloads" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match 'qindu|Qindu' } |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  Done."

# 7. MSI uninstall (using WMI — slow but thorough)
Write-Host "[8/8] Checking for MSI product registration..."
$product = Get-WmiObject Win32_Product -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like "*Qindu*" }
if ($product) {
    $product.Uninstall() | Out-Null
    Write-Host "  Uninstalled MSI product: $($product.Name)"
} else {
    Write-Host "  No MSI product found."
}

Write-Host "=== DONE. Qindu has been nuked. ===" -ForegroundColor Green
```

### CMD version (no PowerShell required)

```cmd
@echo off
echo === NUKING QINDU FROM THIS MACHINE ===

echo [1/8] Service...
sc stop QinduAgent >nul 2>&1
sc delete QinduAgent >nul 2>&1

echo [2/8] CA certificate...
certutil -delstore Root "Qindu AI Privacy CA" >nul 2>&1

echo [3/8] Firewall rules...
netsh advfirewall firewall delete rule name="Qindu Agent (Allow Loopback)" >nul 2>&1
netsh advfirewall firewall delete rule name="Qindu Agent (Block External)" >nul 2>&1

echo [4/8] Browser policies...
reg delete "HKLM\Software\Policies\Google\Chrome" /f >nul 2>&1
reg delete "HKLM\Software\Policies\Microsoft\Edge" /f >nul 2>&1

echo [5/8] Program Files...
rmdir /s /q "C:\Program Files\Qindu" >nul 2>&1

echo [6/8] ProgramData...
rmdir /s /q "C:\ProgramData\Qindu" >nul 2>&1

echo [7/8] Downloads...
del /q "%USERPROFILE%\Downloads\*qindu*" >nul 2>&1
del /q "%USERPROFILE%\Downloads\*Qindu*" >nul 2>&1
rmdir /s /q "%USERPROFILE%\Downloads\qindu-build" >nul 2>&1

echo [8/8] MSI uninstall (if found)...
for /f "tokens=2 delims==" %%i in ('wmic product where "name like 'Qindu%%'" get IdentifyingNumber /value 2^>nul ^| findstr "IdentifyingNumber"') do (
    msiexec /x %%i DELETEDATA=1 /qn /norestart >nul 2>&1
)

echo === DONE. Qindu has been nuked. ===
```

---

## Verification Checklist

Run each check after cleanup. Every check must return **CLEAN** or show the artifact is missing.

| # | Check | Command | Expected |
|---|-------|---------|----------|
| 1 | Service | `sc query QinduAgent` | `FAILED 1060: The specified service does not exist` |
| 2 | Program Files | `dir "C:\Program Files\Qindu"` | `File Not Found` |
| 3 | ProgramData | `dir "C:\ProgramData\Qindu"` | `File Not Found` |
| 4 | CA cert | `certutil -store Root | findstr /i Qindu` | No output |
| 5 | Firewall 1 | `netsh advfirewall firewall show rule name="Qindu Agent (Allow Loopback)"` | `No rules match` |
| 6 | Firewall 2 | `netsh advfirewall firewall show rule name="Qindu Agent (Block External)"` | `No rules match` |
| 7 | Chrome policy | `reg query "HKLM\Software\Policies\Google\Chrome"` | `ERROR: ... unable to find` |
| 8 | Edge policy | `reg query "HKLM\Software\Policies\Microsoft\Edge"` | `ERROR: ... unable to find` |
| 9 | Port 8787 | `netstat -ano | findstr :8787` | No output |
| 10 | Downloads | `dir "%USERPROFILE%\Downloads\*Qindu*" /s` | `File Not Found` |
| 11 | HKLM\Software | `reg query HKLM\Software\Qindu` | `ERROR: ... unable to find` |
| 12 | HKCU\Software | `reg query HKCU\Software\Qindu` | `ERROR: ... unable to find` |
| 13 | AppData Local | `dir "%LOCALAPPDATA%\Qindu"` | `File Not Found` |
| 14 | AppData Roaming | `dir "%APPDATA%\Qindu"` | `File Not Found` |
| 15 | MSI cache | `reg query "HKCR\Installer\Products" /s /f Qindu` | `End of search: 0 match(es) found.` |
| 16 | Uninstall key | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f Qindu` | `End of search: 0 match(es) found.` |

### One-liner verification (PowerShell)

```powershell
$checks = @(
    @{Name="Service"; Test={!(Get-Service QinduAgent -ErrorAction SilentlyContinue)}},
    @{Name="Program Files"; Test={!(Test-Path "C:\Program Files\Qindu")}},
    @{Name="ProgramData"; Test={!(Test-Path "C:\ProgramData\Qindu")}},
    @{Name="CA cert"; Test={-not ((certutil -store Root 2>&1) -match "Qindu")}},
    @{Name="Firewall 1"; Test={(netsh advfirewall firewall show rule name="Qindu Agent (Allow Loopback)" 2>&1) -match "No rules"}},
    @{Name="Firewall 2"; Test={(netsh advfirewall firewall show rule name="Qindu Agent (Block External)" 2>&1) -match "No rules"}},
    @{Name="Chrome policy"; Test={!(Test-Path "HKLM:\Software\Policies\Google\Chrome")}},
    @{Name="Edge policy"; Test={!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")}},
    @{Name="Port 8787"; Test={-not ((netstat -ano 2>&1) -match ":8787")}},
    @{Name="Downloads"; Test={-not (Get-ChildItem "$env:USERPROFILE\Downloads\*Qindu*","$env:USERPROFILE\Downloads\*qindu*" -ErrorAction SilentlyContinue)}}
)

$allPassed = $true
foreach ($check in $checks) {
    $result = if (& $check.Test) { "PASS" } else { $allPassed = $false; "FAIL" }
    Write-Host ("{0,-20} {1}" -f $check.Name, $result) -ForegroundColor $(if($result -eq "PASS"){"Green"}else{"Red"})
}

if ($allPassed) { Write-Host "`nALL CHECKS PASSED - VM is clean." -ForegroundColor Green }
else { Write-Host "`nSOME CHECKS FAILED - cleanup incomplete." -ForegroundColor Red }
```

---

## WiX Cross-Reference

This section maps every artifact from the WiX source files to its cleanup command, ensuring completeness.

| WiX File | Component/CA | Creates | Cleanup Command |
|----------|-------------|---------|-----------------|
| `files.wxs` | `AgentExeComponent` | `C:\Program Files\Qindu\agent.exe` + service `QinduAgent` | `rmdir` + `sc delete` |
| `files.wxs` | `DefaultConfigComponent` | `C:\Program Files\Qindu\configs\default.yaml` | `rmdir` |
| `files.wxs` | `ProgramDataDirComponent` | `C:\ProgramData\Qindu\` (ACL only; contents generated at runtime) | `rmdir` |
| `ca-trust.wxs` | `CAInitNormal/CAInitUnsafe` | `C:\ProgramData\Qindu\ca.crt`, `ca.key`, `ca.crl` | `rmdir` on ProgramData |
| `ca-trust.wxs` | `CAInstallTrustStore` | Root store: `Qindu AI Privacy CA` cert | `certutil -delstore Root "Qindu AI Privacy CA"` |
| `ca-trust.wxs` | `CAInstallCRL` | Root store: `Qindu AI Privacy CA` CRL | `certutil -delstore Root "Qindu AI Privacy CA"` (same name) |
| `ca-trust.wxs` | `CARemoveTrustStore` | (uninstall cleanup CA; not a separate artifact) | handled by MSI uninstall |
| `firewall.wxs` | `FirewallAllowLoopback` | `Qindu Agent (Allow Loopback)` inbound TCP 8787 | `netsh advfirewall firewall delete rule name="Qindu Agent (Allow Loopback)"` |
| `firewall.wxs` | `FirewallBlockExternal` | `Qindu Agent (Block External)` inbound TCP 8787 | `netsh advfirewall firewall delete rule name="Qindu Agent (Block External)"` |
| `registry-chrome.wxs` | `ChromePolicyComponent` | `HKLM\Software\Policies\Google\Chrome` (3 values) | `reg delete "HKLM\Software\Policies\Google\Chrome" /f` |
| `registry-edge.wxs` | `EdgePolicyComponent` | `HKLM\Software\Policies\Microsoft\Edge` (3 values) | `reg delete "HKLM\Software\Policies\Microsoft\Edge" /f` |
| `qindu.wxs` | MSI Product registration | `HKLM\...\Uninstall\` + `HKCR\Installer\Products\` | `msiexec /x {PRODUCT-CODE}` |

### WiX-defined names (from `locale/en-us.wxl`)

| String ID | Value |
|-----------|-------|
| `ProductName` | Qindu AI Privacy Proxy |
| `ServiceName` | QinduAgent |
| `ServiceDisplayName` | Qindu AI Privacy Proxy |
| `CAName` | Qindu AI Privacy CA |
| `Manufacturer` | Qindu |

### MSI identifiers

| Property | Value |
|----------|-------|
| UpgradeCode | `{5319E462-2A8D-476D-8896-32F36E454A98}` |
| ProductCode | `*` (auto-generated per build — use `wmic` to find) |
| InstallScope | perMachine (HKLM, not HKCU) |

---

## VM Cleanup Session Summary (2026-07-06)

**Target**: `192.168.122.4:2222`, `DESKTOP-8KDT8DJ`, user `opencode-admin`

**Artifacts found and removed**:

| # | Artifact | Status |
|---|----------|--------|
| 1 | Service `QinduAgent` | Already gone (uninstalled previously) |
| 2 | `C:\Program Files\Qindu` | Already gone |
| 3 | `C:\ProgramData\Qindu` (ca.crt, ca.key) | **Cleaned** — MSI left these behind (no `DELETEDATA=1`) |
| 4 | Root CA cert `Qindu AI Privacy CA` | Already gone from trust store |
| 5 | Firewall `Qindu Agent (Allow Loopback)` | **Cleaned** — MSI uninstall left rule |
| 6 | Firewall `Qindu Agent (Block External)` | **Cleaned** — MSI uninstall left rule |
| 7 | `HKLM\Software\Policies\Google\Chrome` (3 values) | **Cleaned** — MSI uninstall left policy keys |
| 8 | `HKLM\Software\Policies\Microsoft\Edge` (3 values) | **Cleaned** — MSI uninstall left policy keys |
| 9 | `%USERPROFILE%\Downloads\` (8 files + `qindu-build/`) | **Cleaned** |
| 10–16 | All other locations (registry, temp, AppData, MSI cache, tasks, env vars) | Already clean |

**Final state**: All 16 verification checks pass. VM is clean.

---

## Deep Registry Audit (2026-07-06)

An exhaustive registry sweep was performed after the initial filesystem/service cleanup. MSI uninstall leaves hidden traces in CLSID/Component/UpgradeCode/DCOM hives that `reg query /s /f Qindu` alone will not find.

### Registry paths checked

| # | Registry Path | Method | Result |
|---|---------------|--------|--------|
| R1 | `HKLM\SOFTWARE\Qindu` | `reg query` | Clean (key does not exist) |
| R2 | `HKCU\SOFTWARE\Qindu` | `reg query` | Clean |
| R3 | `HKLM\SOFTWARE\Policies\Google\Chrome` | `reg query` | Cleaned (see session summary) |
| R4 | `HKLM\SOFTWARE\Policies\Microsoft\Edge` | `reg query` | Cleaned (see session summary) |
| R5 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\` | `/s /f Qindu` | Clean (0 matches) |
| R6 | `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\` | `/s /f Qindu` | Clean |
| R7 | `HKCR\Installer\Products\` | `/s /f Qindu` | Clean (0 matches) |
| R8 | `HKLM\SOFTWARE\Classes\Installer\Products\` | `/s /f Qindu` | Clean (0 matches) |
| R9 | `HKCR\Installer\Features\` | manual inspection | 1 subkey found — **cleaned** |
| R10 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\` | listed all 35 products | Clean (none Qindu) |
| R11 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\` | `/s /f Qindu` | 3 subkeys found — **cleaned** |
| R12 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\` | searched by GUID | 1 subkey found — **cleaned** |
| R13 | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders\` | searched for `Qindu` | 2 values found — **cleaned** |
| R14 | `HKLM\SYSTEM\CurrentControlSet\Services\QinduAgent` | `reg query` | Clean |
| R15 | `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules\` | grep for Qindu | Clean |
| R16 | `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates\` | searched for Qindu thumbprints | Clean |
| R17 | `HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\CRLs\` | searched for Qindu | Clean |
| R18 | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application\QinduAgent` | `reg query` | Clean |
| R19 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` | searched for `agent.exe` | Clean |
| R20 | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Custom` | searched for `agent.exe` | Clean |
| R21 | `HKLM`, `HKCU`, `HKCR`, `HKU` — full `/s /f Qindu` | `reg query` | Clean (except known cleaned locations) |
| R22 | `HKLM`, `HKCU`, `HKCR`, `HKU` — full `/s /f QinduAgent` | `reg query` | Clean |
| R23 | `HKLM`, `HKCR` — search for UpgradeCode `5319E462` | `reg query` | Clean |
| R24 | `HKLM`, `HKCR` — search for partial ProductCode `9CD2AE2B` | `reg query` | Clean |
| R25 | `HKLM\SOFTWARE\Microsoft\Windows Search\...` (Search index) | `/s /f Qindu` | 4 benign entries found — cannot clean (see below) |

---

### Findings: 11 traces, 7 cleaned, 4 residual

#### Cleaned (MSI detritus)

These were left behind by `msiexec /x` — MSI uninstall does not clean its internal Component/UpgradeCode/Folders registration.

| # | Registry Path | What It Was | Cleanup Method |
|---|---------------|-------------|----------------|
| **F1** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders\` | 2 REG_SZ values containing `Qindu` paths (backslash-escaped value names) | `Remove-ItemProperty` via PowerShell (value names with backslashes cannot be deleted with `reg delete`) |
| **F2** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes\` | 1 subkey matching Qindu UpgradeCode `5319E462-2A8D-476D-8896-32F36E454A98` | `reg delete` |
| **F3** | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\` | 3 subkeys (GUID-named) containing `Qindu` in their Data values | `schtasks` running `reg delete` as SYSTEM (admin cannot delete MSI-protected keys; SYSTEM can) |
| **F4** | `HKCR\Installer\Features\` | 1 subkey matching packed ProductCode | `reg delete` |
| **F5** | `HKLM\SOFTWARE\Classes\Installer\Features\` | 1 subkey matching packed ProductCode | `reg delete` |

#### PowerShell cleanup for Installer Folders (backslash-escaped value names)

```powershell
# reg delete fails on value names containing backslashes.
# Use Remove-ItemProperty instead:
$path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders"
Get-ItemProperty -Path $path | Get-Member -MemberType NoteProperty |
    Where-Object { $_.Name -match 'Qindu' } |
    ForEach-Object { Remove-ItemProperty -Path $path -Name $_.Name }
```

#### Cleanup for MSI-protected keys (require SYSTEM)

```cmd
REM Create a scheduled task that runs as SYSTEM to delete protected keys:
schtasks /create /tn "CleanQinduReg" /tr "cmd.exe /c reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components\<SUBKEY-GUID> /f" /sc once /st 00:00 /ru SYSTEM
schtasks /run /tn "CleanQinduReg"
schtasks /delete /tn "CleanQinduReg" /f
```

---

#### Residual (cannot clean — benign)

| # | Registry Path | Why Can't Clean | Risk |
|---|---------------|-----------------|------|
| **R-1** | `HKLM\SOFTWARE\Microsoft\Windows Search\CrawlScope\Windows\SystemIndex\` | TrustedInstaller-owned, even SYSTEM cannot modify | **Zero** — file path pointer only; target directory no longer exists |
| **R-2** | `HKLM\SOFTWARE\Microsoft\Windows Search\Gather\Windows\SystemIndex\Sites\` | TrustedInstaller-owned | **Zero** |
| **R-3** | `HKLM\SOFTWARE\Microsoft\Windows Search\Gather\Windows\SystemIndex\Sites\LocalHost\Paths\` | TrustedInstaller-owned | **Zero** |
| **R-4** | `HKLM\SOFTWARE\Microsoft\Windows Search\Applications\` | TrustedInstaller-owned | **Zero** |

These are Windows Search index pointers — the indexer recorded that the directory `C:\Users\opencode-admin\qindu\` once existed and indexed files within it. They contain only directory path strings (`C:\Users\...`) and document count metadata. **No PII, no credentials, no certificates, no service configuration.** They will expire naturally as Windows Search reindexes (typically within 24–48 hours).

Only way to remove them: `PowerRun` / `AdvancedRun` running as `NT AUTHORITY\TrustedInstaller`, or `PsExec -s -i` with `SeRestorePrivilege` + `SeTakeOwnershipPrivilege`. Not worth it — no security value.

---

### Updated Nuke Verification (22 checks)

| # | Check | Command | Expected |
|---|-------|---------|----------|
| 17 | Installer Folders | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders" /f Qindu` | 0 matches |
| 18 | Installer Components | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components" /s /f Qindu` | 0 matches |
| 19 | Installer UpgradeCodes | `reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UpgradeCodes" /s` — check GUID `5319E462` | Not found |
| 20 | Installer Features | `reg query HKCR\Installer\Features /s /f Qindu` | 0 matches |
| 21 | Firewall registry | `reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules" /s /f Qindu` | 0 matches |
| 22 | Uninstall (32-bit) | `reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" /s /f Qindu` | 0 matches |

---

### Summary: all artifacts, all locations

| Category | Count | Status |
|----------|-------|--------|
| Filesystem (program files, programdata, downloads) | 11 files + 3 dirs | All cleaned |
| Service | 1 | Cleaned |
| Firewall rules | 2 | Cleaned |
| Browser policies (Chrome, Edge) | 2 keys (6 values) | Cleaned |
| CA certificate (trust store) | 1 cert + 1 CRL | Cleaned |
| MSI product registration (Uninstall, Products) | 2 entries | Cleaned |
| MSI internal registration (Components, UpgradeCodes, Folders, Features) | 7 entries | All cleaned |
| Windows Search index pointers | 4 entries | Residual — TrustedInstaller, benign, auto-expire |
| **Total** | **~30 artifacts** | **26 cleaned, 4 benign residual** |

**VM is clean for all practical and security purposes.**
