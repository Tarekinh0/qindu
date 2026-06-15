# DPO Review — QINDU-0002: Installer Windows + Service

**Reviewer**: qindu-dpo (Data Protection Officer)
**Date**: 2026-06-15
**Sprint**: QINDU-0002
**Phase**: Review Gate (after Peer Review MERGE_READY, CISO PASS)

---

## 1. Privacy Requirements Verification Table (R1–R12)

Each binding requirement from the design-phase `dpo-requirements.md` is verified against source code, not against claims in `dev-notes.md`.

### R1 – Installer Transparency Notice (Critical) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| Dedicated dialogue before system changes | ✅ | `dialogs.wxs:17-37` — `QinduNoticeDlg` is a custom WiX dialog inserted into the install sequence (`LicenseAgreementDlg` → `QinduNoticeDlg` → `QinduOptionsDlg` → `VerifyReadyDlg`). All changes (files, CA, registry, service, firewall) happen in deferred CustomActions after `VerifyReadyDlg`. |
| Explains CA installs TLS interception | ✅ | `en-us.wxl:13` (NoticeText): `"Qindu will:\n• Install a local Certificate Authority (CA) to inspect TLS traffic on AI service domains (e.g., chatgpt.com, claude.ai)"` |
| States all processing is local | ✅ | `en-us.wxl:13`: `"Qindu does NOT collect, transmit, or store your AI conversations — all processing is local"` |
| States CA key stored locally, never shared | ✅ | `en-us.wxl:13`: `"The CA private key is stored only on your machine (DPAPI-encrypted) and never shared"` |
| States no telemetry, tracking, or accounts | ✅ | `en-us.wxl:13`: `"No data is sent to Qindu as an organization. There is no telemetry, no tracking, and no user account."` |
| States browser policies are machine-wide | ✅ | `en-us.wxl:13`: `"Browser policies are machine-wide: all user accounts on this computer will have their AI traffic routed through Qindu."` |
| Mentions uninstall data deletion option | ✅ | `en-us.wxl:13`: `"You can uninstall Qindu at any time. During uninstallation, you can choose to delete all Qindu data."` |
| Dialogue has Back/Next/Cancel controls | ✅ | `dialogs.wxs:25-36` — user can navigate back to `WelcomeDlg` or cancel the install entirely. |
| Strings in locale file (i18n-ready) | ✅ | All text in `en-us.wxl` with `!(loc.NoticeText)`, `!(loc.NoticeTitle)` references. |

**Verdict**: PASS. The transparency notice is comprehensive, covering all required elements: TLS interception, local-only processing, CA key protection, machine-wide scope, no telemetry/tracking, and uninstall data deletion. The dialogue appears before any system changes via WiX deferred CustomAction sequencing. Satisfies GDPR Art. 5(1)(a), Art. 12–14, and ePrivacy Directive informed consent requirements.

---

### R2 – CA Private Key Never Exposed (Critical) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| Generated via ECDSA P-256 (crypto/rand) | ✅ | `ca.go:40`: `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)` |
| DPAPI-encrypted before any disk write | ✅ | `ca_windows.go:52-76`: `Save()` sequence: `os.MkdirAll` → `dpapiEncrypt(keyPEM)` → `os.WriteFile(keyPath, encryptedKey, 0600)`. Plaintext `keyPEM` never written to disk. |
| DPAPI uses `CRYPTPROTECT_LOCAL_MACHINE` | ✅ | `ca_windows.go:115,149`: flag `0x4` applied in both `dpapiEncrypt` and `dpapiDecrypt`. Cross-context (console ↔ service) decryption works. |
| File permissions `0600` on `ca.key` | ✅ | `ca_windows.go:72`: `os.WriteFile(keyPath, encryptedKey, 0600)` — owner read/write only. |
| Never appears in `ca-init` stdout/stderr | ✅ | `main.go:129-144`: Success output prints only Subject CN, expiry date, serial number, storage path, and Name Constraint domains. Zero references to `keyPEM`, `keyBytes`, or private key material. Verified by `TestCAInit_CAKeyNotInOutput` (`ca_init_test.go:399-439`): `CertPEM` contains only `CERTIFICATE` PEM block, `keyPEM` isolated. |
| No key in WiX CustomAction output | ✅ | `ca-trust.wxs:8,20`: `ExeCommand` only invokes `agent.exe ca-init` and `agent.exe ca-init --unsafe --auto-confirm-unsafe`. No `--verbose`, `--debug`, or key-export flags. |
| No key in any `slog` or `fmt` call | ✅ | `slog` moved to `proxy.go` (PR-M2 fix). `main.go` uses only `fmt.Printf`/`fmt.Fprintf(os.Stderr, ...)` for metadata. Grep audit: zero references to `keyPEM` or `keyBytes` in print/log calls within `main.go` — only passed to `store.Save()` and `GenerateCA()`. |
| SAFETY comments documenting no-PII discipline | ✅ | `main.go:125-127`: `// SAFETY: No PII in log output — prints only x509 certificate metadata`. `main.go:153-154`: similar in `confirmUnsafeMode`. `ca_init_test.go:14-17`: file-level SAFETY comment listing synthetic test data. |
| On non-Windows: memory-only, no disk | ✅ | `ca_other.go`: `otherCAStore` stores CA in-memory only. `main.go:135-136`: correctly reports `"Storage: memory-only (CA regenerated on next run)"`. |

**Verdict**: PASS. The DPAPI-before-write sequence is correctly ordered. Key material never touches disk in plaintext. No key material in any log, print, or CustomAction output. SAFETY comments document the no-PII discipline. File-level `0600` provides defense-in-depth. Satisfies GDPR Art. 25 (data protection by design) and extends QINDU-0001 R3.

---

### R3 – No Telemetry, Analytics, Tracking, or Phoning Home (Critical) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| No telemetry/analytics in Go source | ✅ | Grep audit: Zero matches for `telemetry`, `analytics`, `crash-report`, `api.qindu`, `update.qindu` in production code. |
| No machine identifiers or installation IDs | ✅ | Grep audit: Zero matches for `uuid.New`, `machineid`, `device_id`, `installation_id` in production code. Only match: `pac_test.go:95` — negative test verifying PAC doesn't contain `machineid`. |
| No phone-home in WiX CustomActions | ✅ | All `ExeCommand` calls reviewed (ca-trust.wxs, firewall.wxs): only `agent.exe ca-init`, `certutil`, `netsh advfirewall`. Zero external URLs, no `curl`, `wget`, or PowerShell remote calls. |
| No outbound connections from `ca-init` | ✅ | `runCAInit` has zero `net.Dial`, `http.Get`, or `http.Post` calls. Only filesystem, x509 generation, and DPAPI operations. |
| No outbound connections from installer | ✅ | WiX CustomActions are deferred system commands (`certutil`, `netsh`, `sc`) — all local-only operations. |
| No update checking | ✅ | Zero `http.Get` to external URLs anywhere. `appVersion` is a compile-time constant used for display only. |
| Sustained from QINDU-0001 | ✅ | `proxy.go` (unchanged) maintains zero external connections beyond AI-provider upstream traffic through the proxy pipeline. |

**Verdict**: PASS. Comprehensive grep audit across Go source, WiX source, and CI configuration confirms zero telemetry, zero tracking, zero external communication beyond proxy forwarding. Satisfies AGENTS.md non-negotiable constraints, ADR-008, and GDPR Art. 5(1)(c) (data minimization).

---

### R4 – Browser Policies: Machine-Wide Scope Disclosed (High) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| Chrome policies in HKLM | ✅ | `registry-chrome.wxs:7-11`: `RegistryKey Root="HKLM" Key="Software\Policies\Google\Chrome"` with `ProxyMode="pac_script"`, `ProxyPacUrl="http://127.0.0.1:8787/proxy.pac"`, `QuicAllowed=0` |
| Edge policies in HKLM | ✅ | `registry-edge.wxs:7-11`: Identical structure for `Software\Policies\Microsoft\Edge` |
| PAC URL hardcoded to localhost | ✅ | Both files use hardcoded literal string `"http://127.0.0.1:8787/proxy.pac"` — no config substitution, no external host. Satisfies SR-INSTALLER-18. |
| Machine-wide scope disclosed in notice | ✅ | `en-us.wxl:13`: `"Browser policies are machine-wide: all user accounts on this computer will have their AI traffic routed through Qindu."` |
| Policies written systematically (no browser detection) | ✅ | Both registry components are always installed — no conditional logic, no browser detection. |
| QUIC disabled for both browsers | ✅ | Both registry files set `QuicAllowed` `Type="integer" Value="0"`. |

**Verdict**: PASS. HKLM machine-wide policies correctly configured with hardcoded localhost PAC URL. Machine-wide scope transparently disclosed in the installer notice (R1). QUIC disabled for both Chrome and Edge. Satisfies DPO caveat C2 mitigation.

---

### R5 – Uninstall Data Deletion: Explicit Consent (High) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| Checkbox unchecked by default | ✅ | `dialogs.wxs:72`: `DELETEDATA` checkbox has no default value — WiX CheckBox with `CheckBoxValue="1"` and no `Property` default → unchecked. |
| Clear English label | ✅ | `en-us.wxl:19`: `"Delete all Qindu data (vault, logs, and configuration)"` |
| Triggers `RemoveFolderEx` only if checked | ✅ | `cleanup.wxs:29-31`: `<RemoveFolderEx ... On="uninstall" Property="PROGRAMDATADIR"><Condition>DELETEDATA="1"</Condition></RemoveFolderEx>` |
| Unchecked preserves `%PROGRAMDATA%\Qindu\` | ✅ | `RemoveFolderEx` fires only when `DELETEDATA="1"`. Absent condition → directory preserved. |
| Uses WiX-native API (no shell injection) | ✅ | `cleanup.wxs:29`: `<RemoveFolderEx>` uses Windows Installer API directly. No `cmd.exe /c rmdir` or `ExeCommand` — eliminates command injection surface (PR-004 fix). |
| `INSTALLDIR` cleaned unconditionally on uninstall | ✅ | `cleanup.wxs:39-42`: Separate `RemoveFolderEx` on `INSTALLDIR` without condition — always cleans Program Files (PR-H4 fix). This is acceptable: Program Files contains no PII or user data. |
| Uninstall dialog provides context | ✅ | `en-us.wxl:18` (DeleteDataText): `"If you plan to reinstall Qindu later, you may want to keep this data to preserve your settings."` |

**Verdict**: PASS. Explicit opt-in deletion with unchecked-by-default checkbox, clear labeling, and WiX-native implementation. Satisfies GDPR Art. 17 (right to erasure) and Art. 4(11)/Art. 7 (explicit, affirmative consent). The separation of Program Files (always cleaned) from ProgramData (conditional) correctly distinguishes installation artifacts from user data.

---

### R6 – ACL Restrictions on Qindu Data Directory (High) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| SYSTEM: Full Control | ✅ | `files.wxs:37`: `<Permission User="NT AUTHORITY\SYSTEM" GenericAll="yes" />` |
| Administrators: Full Control | ✅ | `files.wxs:39`: `<Permission User="BUILTIN\Administrators" GenericAll="yes" />` |
| LocalService: Read/Write/Execute | ✅ | `files.wxs:41`: `<Permission User="NT AUTHORITY\LocalService" GenericRead="yes" GenericWrite="yes" GenericExecute="yes" />` |
| No Authenticated Users, Everyone | ✅ | Only three `<Permission>` elements. No `Authenticated Users`, `Everyone`, or `BUILTIN\Users`. |
| ACL applied before `ca-init` writes | ✅ | `ca-trust.wxs:75`: `CAInitNormal`/`CAInitUnsafe` sequenced `After="InstallFiles"`. MSI processes `CreateFolder` (with ACL `<Permission>` elements) during `InstallFiles` phase. PR-H3 fix ensures ordering. |
| File-level `0600` on `ca.key` (defense-in-depth) | ✅ | `ca_windows.go:72`: `os.WriteFile(keyPath, encryptedKey, 0600)` — owner read/write only regardless of directory ACL. |
| `%PROGRAMFILES%\Qindu\` uses standard ACLs | ✅ | Program Files directories inherit standard read-only-for-users permissions by default. Acceptable: config files are not secret. |

**Verdict**: PASS. Directory ACL correctly restricts access to SYSTEM + Administrators + LocalService, excluding all other principals. ACL is applied via `<CreateFolder>` before `ca-init` runs. File-level `0600` on `ca.key` provides defense-in-depth. DPAPI encryption provides cryptographic protection beyond filesystem controls. Satisfies GDPR Art. 25 (data protection by design and by default).

---

### R7 – CA Name Constraints by Default (Medium) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| PermittedDNSDomains from provider config | ✅ | `main.go:77-78`: `permittedDomains = cfg.AllAIDomains()` when `!unsafe`. `ca.go:68-71`: `template.PermittedDNSDomains = permittedDNSDomains` when `len > 0`. |
| Default domains: `chatgpt.com`, `claude.ai` | ✅ | `TestAllAIDomains` (`ca_init_test.go:262`) verifies default config yields both domains. |
| Non-critical extension (browser compatibility) | ✅ | `ca.go:70`: `template.PermittedDNSDomainsCritical = false`. Verified by `TestCAInit_NameConstraintsNonCritical`. |
| Empty domains → error (not silent unconstrained) | ✅ | `main.go:79-81`: If `!unsafe && len(permittedDomains) == 0`, abort with descriptive error message. PR-003 Round 5 fix. |
| Unsafe mode: interactive warning banner | ✅ | `main.go:155-195`: `confirmUnsafeMode()` prints English warning banner (lines 156-171) describing the expanded risk. |
| Unsafe mode: requires stdin confirmation "YES" | ✅ | `main.go:182-191`: Reads from `bufio.NewReader(os.Stdin)`, requires exact `"YES"` match. |
| Unsafe mode: blocked in non-interactive context | ✅ | `main.go:174-179`: Checks `os.Stdin.Stat()` for `ModeCharDevice`. Non-terminal → error. Verified by `TestConfirmUnsafeMode_NonInteractive`. |
| Unsafe checkbox unchecked by default | ✅ | `dialogs.wxs:46`: `UNSAFE_CA` property has no default value → unchecked. |
| Unsafe checkbox clear warning label | ✅ | `en-us.wxl:16`: `"Skip domain restrictions (reduces security — the CA will be able to intercept ANY website, not just AI services)"` |
| Silent install + unsafe blocked | ✅ | `qindu.wxs:111-113`: WiX LaunchCondition `NOT (UNSAFE_CA="1" AND (UILevel=2 OR UILevel=3))`. `ca-trust.wxs:79`: `CAInitUnsafe` also guards `AND (NOT UILevel=2) AND (NOT UILevel=3)`. PR-2RH1 fix. |
| MSI unsafe uses `--auto-confirm-unsafe` skip | ✅ | `ca-trust.wxs:20`: MSI `CAInitUnsafe` passes `--auto-confirm-unsafe`. The `QinduOptionsDlg` checkbox already served as informed consent mechanism (PR-C2 fix). |

**Verdict**: PASS. Name Constraints correctly implemented by default, deriving from provider config. Three-layer consent for unsafe mode: (1) unchecked-by-default MSI checkbox, (2) clear warning label text, (3) interactive terminal confirmation (CLI) or MSI dialog checkbox consent (MSI). Silent/quiet install with unsafe CA is blocked at the WiX LaunchCondition level. Empty domain list produces an error rather than silent unconstrained generation. Satisfies GDPR Art. 25 (data protection by default — least-decrypt principle).

---

### R8 – Firewall Rules: Loopback Only (Medium) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| Allow loopback rule created first | ✅ | `firewall.wxs:64-65`: `FirewallAllowLoopback` `After="InstallServices"`, `FirewallBlockExternal` `After="FirewallAllowLoopback"`. Allow rule created first → evaluated first in Windows firewall stack. |
| Allow rule: `remoteip=127.0.0.1,::1` | ✅ | `firewall.wxs:9`: `remoteip=127.0.0.1,::1 localport=8787 protocol=TCP action=allow` |
| Block rule: `remoteip=any` | ✅ | `firewall.wxs:19`: `remoteip=any localport=8787 protocol=TCP action=block` |
| Both rules use `Return="check"` | ✅ | `firewall.wxs:12,22`: PR-H1 fix — genuine failures are not silently swallowed. |
| Rule names hardcoded in English | ✅ | `firewall.wxs:9,19`: Both install commands use hardcoded names `"Qindu Agent (Allow Loopback)"` and `"Qindu Agent (Block External)"`. PR-H5 fix ensures locale-independent uninstall. |
| Uninstall removes both rules in reverse order | ✅ | `firewall.wxs:70-71`: `FirewallRemoveBlockExternal` `Before="RemoveFiles"`, `FirewallRemoveAllowLoopback` `After="FirewallRemoveBlockExternal"`. |
| Rollback rules for failed install | ✅ | `firewall.wxs:67-68`: `FirewallRollbackBlockExternal` `Before="FirewallBlockExternal"`, `FirewallRollbackAllowLoopback` `Before="FirewallAllowLoopback"`. Rollback returns `"ignore"` (correct — don't fail rollback itself). |

**Verdict**: PASS. Correct firewall rule ordering (allow-before-block) ensures loopback connectivity. Both rules correctly configured with `Return="check"` for error detection. Uninstall removes both rules in reverse order with locale-independent hardcoded names. Rollback actions ensure orphaned rules are cleaned up if install fails. Satisfies defense-in-depth requirement for loopback binding (QINDU-0001 R4).

---

### R9 – No PII in Installer Logging or CustomAction Output (Medium) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| `ca-init` output: metadata only | ✅ | `main.go:129-144`: Prints only `Subject`, `Expires`, `Serial`, `Storage`, `Name Constraints`. Zero key material, zero config contents, zero PII. |
| SAFETY comments document no-PII discipline | ✅ | `main.go:125-127`: `// SAFETY: No PII in log output`. `main.go:153-154`: similar in `confirmUnsafeMode`. `ca_init_test.go:14-17`: file-level SAFETY. |
| No `--verbose`/`--debug` flags in WiX CAs | ✅ | `ca-trust.wxs:8`: `ca-init` (no flags). `ca-trust.wxs:20`: `ca-init --unsafe --auto-confirm-unsafe` (no debug flags). |
| Serial number printed as hex (acceptably public) | ✅ | `main.go:132`: `Serial: %X` — SerialNumber is a public x509 field per RFC 5280. |
| Config contents not printed | ✅ | `ca-init` loads config silently, uses only provider domains for Name Constraints. No config dump in output. |
| MSI properties (UNSAFE_CA, DELETEDATA) logged | ⚠️ | MSI verbose logs `(/l*v)` will record property values. These are consent metadata (checkbox state), not PII — expressly documented as acceptable in the DPO requirements. |
| `confirmUnsafeMode` output to stderr | ✅ | `main.go:156-171`: All warning banner output uses `fmt.Fprintln(os.Stderr, ...)`. PR-M1 fix — consistent with error output channel. |

**Verdict**: PASS. `ca-init` output is strictly limited to x509 certificate metadata and storage paths. No key material, no config content, no PII. SAFETY comments document the discipline. The serial number is a public x509 field and acceptably exposed. MSI property logging is consent metadata, not PII.

---

### R10 – No User Accounts or Persistent Identifiers (High) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| No user registration, authentication, or login | ✅ | Zero auth endpoints, zero `bcrypt`, `jwt`, or session management in the codebase. Sustained from QINDU-0001. |
| No unique installation ID or machine hash | ✅ | Grep audit: zero matches for `uuid.New`, `machineid`, `device_id`, `installation_id`. Only match: `pac_test.go:95` — negative test. |
| No activation or license mechanism | ✅ | MSI uses standard WiX licensing (`LicenseAgreementDlg` + `license.rtf` with AGPL-3.0) — no product key, no online activation. |
| No differentiation between users | ✅ | Proxy binds `127.0.0.1:8787` — any local user can connect. No per-user state, no user context in logs or interceptors. Sustained from QINDU-0001. |
| No account management | ✅ | Grep audit for `account`, `login`, `register`, `signup`, `password_hash`, `user_id`: zero hits in production code. |
| `appVersion` is a compile-time constant | ✅ | `main.go:31`: `appVersion = "0.1.0"` — shared across all installations, not unique. |

**Verdict**: PASS. Sustained from QINDU-0001 R6. The installer introduces zero user identity, zero identifiers, and zero tracking mechanisms. Same comprehensive grep audit confirms no regression.

---

### R11 – Config File Permissions (Medium) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| `default.yaml` in ProgramFiles (standard ACLs) | ✅ | `files.wxs:27-29`: `DefaultConfigComponent` places `default.yaml` in `INSTALLDIR` (`%PROGRAMFILES%\Qindu\configs\`). Program Files is read-only for non-admin users by Windows default. |
| Override `config.yaml` in ACL-restricted ProgramData | ✅ | `main.go:294`: Override path is `filepath.Join(pd, "Qindu", "config.yaml")` — inside `%PROGRAMDATA%\Qindu\`, which has ACL restricted to SYSTEM + Administrators + LocalService (R6). |
| `default.yaml` not world-writable | ✅ | Standard Program Files permissions grant read/execute to Users, write only to Administrators and SYSTEM. |
| Config controls MITM scope — write access gated | ✅ | Only admin-level accounts can modify the override file (via R6 ACL) or the default config (via Program Files ACL). |

**Verdict**: PASS. Config file placement respects defense-in-depth: `default.yaml` in read-only Program Files, override in ACL-restricted ProgramData. Write access to both requires admin privileges. Satisfies GDPR Art. 25 (data protection by design).

---

### R12 – Test Fixtures Contain No Real PII (High) → **PASS**

| Sub-Requirement | Status | Evidence |
|---|---|---|
| Email: synthetic only | ✅ | Test data uses no email addresses. `ca_init_test.go` uses only synthetic domains. |
| Names: synthetic only | ✅ | Test CA names: `"Test CA"`, `"New CA"`, `"Roundtrip CA"` — not real people. |
| Credit card: none present | ✅ | Grep audit: zero card PANs anywhere in the repository. |
| Phone: none present | ✅ | Grep audit: zero phone patterns in test data. |
| IBAN: none present | ✅ | Grep audit: zero IBAN patterns in test data. |
| Domain names: synthetic or AI service only | ✅ | Test domains: `test.com`, `test.example`, `rt.example`, `new.example`, `chatgpt.com`, `claude.ai`. Service domains are AI provider config targets (not PII). All test-specific domains are synthetic. |
| CA keys: throwaway test-only | ✅ | All `GenerateCA` calls in tests use `1`-year validity with synthetic names. No production key material in tests. |
| SAFETY comment at file level | ✅ | `ca_init_test.go:14-17`: `// SAFETY: This file contains only synthetic test data. All domains and names are fictional. No PII patterns (emails, credit cards, SSN, phone numbers) are present.` |

**Verdict**: PASS. All test data uses synthetic, throwaway, or AI-service-domain identifiers. Zero real PII patterns in test fixtures. File-level SAFETY comment documents the discipline. Sustained from QINDU-0001 R7.

---

## 2. Privacy Test Coverage

| Test ID | Requirement(s) | Source | What it verifies | Status |
|---|---|---|---|---|
| PRIV-T1 | R2, R9 | `TestCAInit_CAKeyNotInOutput` (`ca_init_test.go:399-439`) | `CertPEM` contains only `CERTIFICATE` block; `keyPEM` isolated in `EC PRIVATE KEY` block | ✅ PASS |
| PRIV-T2 | R2, R9 | Grep audit: zero key material in `fmt.Printf`/`slog` in `runCAInit` + `confirmUnsafeMode` | No `keyPEM`, `keyBytes`, or private key data in output | ✅ PASS |
| PRIV-T3 | R3, R10 | Grep audit: `telemetry`, `analytics`, `uuid.New`, `machineid`, `device_id` | Zero matches in production code | ✅ PASS |
| PRIV-T4 | R7 | `TestGenerateCAWithNameConstraints` (`ca_init_test.go:17-47`) | CA cert contains OID 2.5.29.30 with permitted domains | ✅ PASS |
| PRIV-T5 | R7 | `TestGenerateCAWithoutNameConstraints` (`ca_init_test.go:49-68`) | CA cert does NOT contain Name Constraints when `nil` passed | ✅ PASS |
| PRIV-T6 | R7 | `TestCAInit_NameConstraintsNonCritical` (`ca_init_test.go:441`) | Extension is non-critical (false) for browser compatibility | ✅ PASS |
| PRIV-T7 | R7 | `TestConfirmUnsafeMode_NonInteractive` (`ca_init_test.go:283-292`) | Unsafe mode blocked when stdin is not a terminal | ✅ PASS |
| PRIV-T8 | R7 | `TestAllAIDomains` / `TestAllAIDomains_DisabledProvider` (`ca_init_test.go:261-292`) | Default config yields `chatgpt.com` + `claude.ai`; disabled providers excluded | ✅ PASS |
| PRIV-T9 | R7 | WiX source audit: `UNSAFE_CA` checkbox no default (dialogs.wxs:46) | Checkbox unchecked by default | ✅ PASS |
| PRIV-T10 | R7, R5 | WiX source audit: `DELETEDATA` checkbox no default (dialogs.wxs:72) | Checkbox unchecked by default | ✅ PASS |
| PRIV-T11 | R5 | `cleanup.wxs:29-31`: `RemoveFolderEx` conditioned on `DELETEDATA="1"` | Data only deleted with explicit opt-in | ✅ PASS |
| PRIV-T12 | R6 | `files.wxs:34-42`: `<Permission>` elements for SYSTEM, Administrators, LocalService | ACL restricted to three SIDs, no Authenticated Users/Everyone | ✅ PASS |
| PRIV-T13 | R1 | `en-us.wxl:13` (NoticeText): full text audit | All required transparency elements present | ✅ PASS |
| PRIV-T14 | R4 | `registry-chrome.wxs:9`, `registry-edge.wxs:9`: `ProxyPacUrl` value audit | PAC URL hardcoded to `http://127.0.0.1:8787/proxy.pac` | ✅ PASS |
| PRIV-T15 | R12 | `ca_init_test.go:14-17`: SAFETY comment + grep audit | All test data synthetic or AI service domains | ✅ PASS |
| PRIV-T16 | R7 | `qindu.wxs:111-113`: LaunchCondition blocks silent/quiet + unsafe | `NOT (UNSAFE_CA="1" AND (UILevel=2 OR UILevel=3))` | ✅ PASS |

**Coverage**: 16/16 privacy verification checks (100%). Every R1–R12 requirement has at least one dedicated verification through code audit, unit test, or WiX source review.

---

## 3. Cross-Reference: Peer Review and CISO Findings

The peer reviewer (MERGE_READY, 4.1/5) identified 5 design flaws (PR-100 through PR-105). The CISO (PASS) identified 4 findings (F1–F4). I assess each for privacy impact:

| Finding | Category | Privacy Impact | DPO Assessment |
|---|---|---|---|
| **Peer PR-100**: `destroyExistingCA` bypasses `CAStore` interface | Coupling/Abstraction | None — current `windowsCAStore` is the only implementation; file removal is correct | **Non-blocking**. Maintainability item. Does not affect PII protection — the CA key is encrypted regardless. Track for QINDU-0005. |
| **Peer PR-101**: `getCADir()` implicit OS detection via env vars | Platform coupling | None — non-Windows correctly returns memory-only store regardless of path | **Non-blocking**. Code clarity issue. Actual privacy behavior is correct (memory-only on non-Windows). |
| **Peer PR-102**: `TestResolveConfigPath_ProgramFiles` uses shared `/tmp/testpf` | Test isolation | None — test-only code, no PII | **Non-blocking**. Test quality issue. No privacy impact. |
| **Peer PR-103**: `filepath.Clean` before traversal guard | Defensive programming | Very Low — for absolute paths, user already has file access rights; no privilege escalation | **Non-blocking**. Defense-in-depth improvement. Track for QINDU-0005 (matching CISO F4). |
| **Peer PR-104**: `applyConfigOverride` bool fields silently ignored | Data integrity | None — affects `CertCacheEnabled` and `PIILogging`, neither of which control PII handling in this sprint | **Non-blocking**. Config UX issue. `PIILogging` is a future-use flag (DPO-F3 from QINDU-0001). Must be addressed before QINDU-0005 when PII processing begins. |
| **Peer PR-105**: `GracefulShutdownTimeout` constant re-exported (duplication) | Code quality | None — purely cosmetic | **Non-blocking**. |
| **CISO F1**: `certutil -addstore` `Return="check"` may fail on upgrade | Operational | None — affects upgrade path only. Fresh installs fine. Does not cause PII leak or privacy bypass. | **Tracked**. Known edge case. Workaround exists. |
| **CISO F2**: `destroyExistingCA` bypasses `CAStore` interface | Maintainability | None — same as Peer PR-100 | **Duplicate of Peer PR-100**. |
| **CISO F3**: Unsigned MSI (Supply Chain) | User trust | None directly — SmartScreen warning degrades user trust UX but no PII exposure | **Accepted** per sprint scope (DPO C1). Must be addressed in dedicated release sprint before production distribution. |
| **CISO F4**: `filepath.Clean` before traversal check weakens absolute path guard | Defense-in-depth | Very Low — same as Peer PR-103 | **Non-blocking**. Track for QINDU-0005. |

**Summary**: All 9 findings from peer review and CISO review are non-blocking for privacy. Zero privacy violations. Zero PII exposure risks. The one finding with future privacy relevance (Peer PR-104: `*bool` for override booleans, needed before `PIILogging` is functional) is explicitly tracked for QINDU-0005.

---

## 4. Findings

### DPO-F1 — Config Override Bool Fields Silently Ignored (Low / Tracked)

- **Source**: `internal/policy/config.go:192-197` (comment), Peer review PR-104
- **Finding**: The `CertCacheEnabled` and `PIILogging` boolean fields are skipped during config override merging because `yaml.v3` unmarshals absent `bool` fields as `false` (the zero value), making it impossible to distinguish "not set" from "explicitly set to false." If a user explicitly sets `pii_logging: false` in their override file, it is silently ignored — the original `true` from `default.yaml` persists.
- **Privacy impact**: None in QINDU-0002 (zero PII processing). Becomes relevant in QINDU-0005 when `PIILogging` controls log redaction middleware (DPO-F3 from QINDU-0001). A user who thinks they've disabled PII logging via override would be unprotected.
- **Severity**: Low for QINDU-0002. Must be resolved before QINDU-0005 (PII interceptor sprint).
- **Recommendation**: Change override boolean fields to `*bool` pointer types to distinguish "not present" (nil) from "explicitly false" (pointer to false). Block the QINDU-0005 DPO gate if unresolved.

### DPO-F2 — `ca-init` Prints CA Certificate Serial Number (Low / Accepted)

- **Source**: `main.go:132`: `fmt.Printf("  Serial:  %X\n", ca.Cert.SerialNumber)`
- **Finding**: The CA certificate serial number is printed to stdout during `ca-init`. While this is a public x509 field (RFC 5280, §4.1.2.2) and not secret, it could theoretically be used to correlate CA instances across reinstalls or identify the specific CA generation event.
- **Privacy impact**: Very Low. The serial number is randomly generated (`crypto/rand`), not derived from PII or machine identifiers. It is already present in the CA certificate (public file). Printing it provides operational transparency (the user can verify the CA they generated).
- **Severity**: Negligible.
- **Recommendation**: Accept as-is. The serial number is documented in the SAFETY comment as acceptable metadata. No action needed.

### DPO-F3 — MSI Transparent Notice References `license.rtf` AGPL-3.0 Text (Positive Finding)

- **Source**: `qindu.wxs:116`: `<WixVariable Id="WixUILicenseRtf" Value="license.rtf" />`. `license.rtf` (PR-2RM4 fix): expanded to include AGPL-3.0 copyleft summary, warranty disclaimer, source code URL, and issues link.
- **Finding**: The MSI installer now presents an AGPL-3.0 license agreement alongside the transparency notice. The expanded `license.rtf` explicitly states the license terms, source code availability (`https://github.com/Tarekinh0/qindu`), and warranty disclaimer. This strengthens transparency: users clicking "I Agree" understand the copyleft terms, not just a blank agreement.
- **Privacy impact**: Positive — enhanced transparency about the software's legal terms and source code availability.
- **Recommendation**: No action needed. This is a privacy-positive improvement.

---

## 5. Design-Phase Caveats: Status Update

| ID | Description | Status After Implementation |
|---|---|---|
| **C1** | No Authenticode code signing — SmartScreen warnings | **Unchanged**. Accepted per sprint scope. Must be addressed in dedicated release sprint before production distribution. CISO F3 confirms. |
| **C2** | Machine-wide browser policies without per-user escape hatch | **Unchanged**. Mitigated by clear disclosure in transparency notice (R1, R4). The notice text explicitly states "all user accounts on this computer." |
| **C3** | CA without Name Constraints (`--unsafe`) expands trust scope | **Well-mitigated**. Three-layer consent (unchecked checkbox, warning label, interactive terminal confirmation). Silent/quiet install with unsafe CA blocked at WiX LaunchCondition level. Empty-domain guard prevents accidental unconstrained CA from disabled providers. |
| **C4** | Uninstall data deletion is all-or-nothing | **Unchanged**. Acceptable for V1. Clear labeling ("vault, logs, and configuration") informs user what is included. Unchecked-by-default ensures no accidental deletion. |
| **C5** | No automated privacy regression tests for installer | **Substantially improved**. CI now includes `validate-wix` job (XML well-formedness + include reference resolution), Windows `go vet` + `go test -race` in `build-msi` job, and 143 total tests (up from 122 in QINDU-0001). WiX sources are validated before the MSI build. Manual Windows VM testing still needed for full MSI integration, but automated coverage is significantly better than the design-phase expectation. |
| **C6** | Config override mechanism introduces tampering surface | **Unchanged**. By design. ACL restrictions (R6) limit write access to admin-level accounts. `installer/README.md` documents this. Acceptable: admin owns the machine. |

---

## 6. Residual Privacy Risks

| Risk | Severity | Mitigation | Residual |
|---|---|---|---|
| CA key leaked via MSI verbose log (`/l*v`) | High | R2: zero key material in `ca-init` output; `TestCAInit_CAKeyNotInOutput` verifies key isolation; DPAPI encrypt before disk write | **Very Low** |
| Unsafe CA deployed silently via SCCM/script | Medium | R7: WiX LaunchCondition blocks `UNSAFE_CA=1` with silent/quiet mode; `ca-init` non-interactive check; `--auto-confirm-unsafe` only available in MSI GUI context | **Very Low** |
| `PIILogging` override ignored silently | Medium (future) | DPO-F1: `*bool` pointer change needed before QINDU-0005. Currently zero PII processing — risk is entirely future. | **Medium (future)** — must be resolved before QINDU-0005 DPO gate |
| Machine-wide browser policies without per-user knowledge | Medium | R4: transparency notice explicitly states machine-wide scope; typical use case is single-user machine | **Low** |
| Unsigned MSI — SmartScreen warning | Medium | C1: accepted for QINDU-0002; dedicated release sprint for Authenticode signing | **Medium** (user trust, not PII) |
| Config override expands MITM scope | Low | C6: ACL restricts write to admins; documented in README; admin owns the machine | **Very Low** |
| `filepath.Clean` before traversal guard | Low | DPO-F2/Peer PR-103: defense-in-depth weakness for absolute paths; user already has file access rights | **Very Low** |
| `certutil` duplicate on upgrade | Low | CISO F1: upgrade path edge case; manual workaround exists | **Low** |

---

## 7. Verdict

### **PASS** ✅

The QINDU-0002 implementation correctly and completely satisfies all 12 binding privacy requirements (R1–R12) established in the design-phase DPO requirements. Every critical privacy surface — installer transparency notice, CA private key protection with DPAPI encryption, zero telemetry/tracking, machine-wide browser policy disclosure, explicit opt-in uninstall data deletion, ACL restrictions on the Qindu data directory, CA Name Constraints by default (with gated unsafe mode), firewall loopback-only rules, no PII in installer logs, zero user accounts/identifiers, config file permissions, and synthetic test data — is implemented with production-quality rigor and verified through code audit, WiX source review, and automated testing.

**Evidence summary**:
- ✅ `go build ./...` — passes
- ✅ `go vet ./...` — clean (including Windows runner in CI)
- ✅ `go test -race -count=1 -timeout 180s ./...` — 147 tests pass (143 from sprint + 4 test additions in Round 6), zero races
- ✅ `GOOS=windows GOARCH=amd64 go build ./...` — cross-compiles cleanly
- ✅ Grep audit: zero `telemetry`, `analytics`, `uuid.New`, `machineid`, `device_id`, `installation_id` in production code
- ✅ Grep audit: zero CA key material in `fmt.Printf`/`slog` output from `ca-init`
- ✅ Grep audit: zero `InsecureSkipVerify` outside config-gated path (production default: `upstream_validation: "system"`)
- ✅ WiX source: transparency notice (R1) with all required elements in `en-us.wxl` + `dialogs.wxs`
- ✅ WiX source: `UNSAFE_CA` and `DELETEDATA` checkboxes default unchecked
- ✅ WiX source: `RemoveFolderEx` conditional on `DELETEDATA="1"`
- ✅ WiX source: LaunchCondition blocks silent/quiet + unsafe
- ✅ WiX source: ACL on `%PROGRAMDATA%\Qindu\` restricted to SYSTEM + Administrators + LocalService
- ✅ WiX source: `certutil` invoked via `[System64Folder]certutil.exe` (absolute path)
- ✅ WiX source: PAC URL hardcoded to `http://127.0.0.1:8787/proxy.pac` in both Chrome and Edge registry files
- ✅ Peer review: MERGE_READY (4.1/5 weighted score, zero critical findings)
- ✅ CISO review: PASS (all 18 SR-INSTALLER requirements satisfied, zero security violations)

**The three DPO findings (DPO-F1, DPO-F2, DPO-F3) are ALL non-blocking for QINDU-0002**:
- **DPO-F1** (config override bool fields ignored): Future relevance only — becomes blocking for QINDU-0005 when PII processing begins. Zero privacy impact today.
- **DPO-F2** (CA serial number printed): Public x509 field, randomly generated, already present in the public certificate file. Operational transparency benefit outweighs negligible privacy concern.
- **DPO-F3** (expanded license.rtf): Privacy-positive improvement — enhanced transparency about AGPL-3.0 terms.

**All 5 design-phase caveats remain non-blocking**, with C5 (automated testing) substantially improved over the design-phase expectation and C3 (unsafe CA) well-mitigated through three-layer consent.

**The QINDU-0002 sprint is cleared for closure from a data protection perspective.**

---

*Reviewed with Go 1.26 toolchain. Full code audit, WiX source review, grep analysis, and cross-reference with peer-review and CISO-review findings completed 2026-06-15.*
