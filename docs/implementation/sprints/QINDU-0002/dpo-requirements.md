# DPO Requirements — QINDU-0002: Installer Windows + Service

**Agent**: qindu-dpo
**Date**: 2026-06-14
**Sprint**: QINDU-0002
**Phase**: 2 - Installation & Packaging
**Verdict**: PROCEED_WITH_CAVEATS

---

## Privacy Analysis

### Nature of processing

QINDU-0002 delivers the Windows MSI installer that deploys Qindu as a system service. This sprint does **not** introduce any PII detection, tokenization, vault, or rehydration (those are QINDU-0005+). The installer:

- Deploys `agent.exe` and `configs/default.yaml` to `%PROGRAMFILES%\Qindu\`
- Creates `%PROGRAMDATA%\Qindu\` for CA key material, certificates, logs, and (future) vault
- Generates a local root CA via `agent.exe ca-init` and installs it into the Windows machine trust store
- Optionally generates a CA **without Name Constraints** (`--unsafe` mode) via an MSI checkbox
- Installs QinduAgent as a Windows service running under `NT AUTHORITY\LocalService`
- Writes machine-wide browser policies to HKLM (Chrome and Edge: PAC URL + QUIC disabled)
- Creates firewall rules allowing loopback-only access to port 8787
- During uninstall, presents an explicit checkbox for deletion of all Qindu data (`%PROGRAMDATA%\Qindu\`)
- Provides the `ca-init` subcommand and path resolution logic in `cmd/agent/main.go`

**Crucially, zero PII is detected, tokenized, stored, logged, or transmitted in this sprint.** The installer itself handles no user content — it only deploys infrastructure.

### Data processed

| Category | Collected | Stored | Transmitted externally | Notes |
|---|---|---|---|---|
| CA private key | Generated locally via `ca-init` | Disk: `%PROGRAMDATA%\Qindu\ca.key` (DPAPI-encrypted) | No | ACL-restricted to SYSTEM + Administrators + LocalService |
| CA certificate | Generated locally | Disk: `%PROGRAMDATA%\Qindu\ca.crt` + Windows trust store | No | Public key only |
| Browser policy keys | Written to HKLM registry | Machine registry (HKLM) | No | PAC URL, QUIC disable — machine-wide scope |
| Firewall rules | Created via netsh | Windows firewall store | No | Loopback allow + external block on port 8787 |
| User's uninstall choice | MSI checkbox (DELETEDATA property) | Transient (MSI session) | No | "Delete vault and logs" consent |
| Unsafe CA choice | MSI checkbox (UNSAFE_CA property) | Transient (MSI session) | No | User opt-in to skip Name Constraints |
| Installer log (MSI) | WiX/MSI internal logging | `%TEMP%\` (MSI standard) | No | Must not contain CA key material, config secrets, or PII |
| `ca-init` console output | CA generation status messages | Not persisted (stdout/stderr) | No | Must not contain the CA private key |
| Config override file | User-edited `%PROGRAMDATA%\Qindu\config.yaml` | Disk | No | Shallow-merged over default.yaml |
| No user identity, no installation ID, no hardware hash, no phoning home | — | — | — | Sustained from QINDU-0001 |

### Purpose and necessity

The installer infrastructure is a **prerequisite** for the privacy-enhancing PII tokenization pipeline (QINDU-0005+). Without:

- A deployed Windows service, the proxy cannot run persistently
- A CA in the machine trust store, the browser will present TLS warnings on AI domains
- Browser policy configuration, the user would need to manually configure PAC and disable QUIC
- Firewall rules, the proxy port has a broader attack surface
- Uninstall logic, users cannot easily exercise their right to remove the software and its artifacts

The installer **minimizes** what it deploys: one binary, one config file, one CA. No drivers, no browser extensions, no background updaters, no DLLs.

### Legal basis

Consistent with QINDU-0001 (household exemption, GDPR Article 2(2)(c)):

- **GDPR**: Qindu receives zero personal data from the installer. The software processes everything locally on the user's machine. The installer is a delivery mechanism, not a data processing operation.
- **Transparency (GDPR Art. 5(1)(a), Art. 12–14)**: The installer MUST present clear, plain-language notice that it will:
  - Install a local Certificate Authority capable of decrypting TLS traffic to AI services
  - Write machine-wide browser policies
  - Configure firewall rules
- **Right to erasure (GDPR Art. 17)**: The uninstaller must provide a clear, affirmative mechanism to delete all Qindu data (`%PROGRAMDATA%\Qindu\`). A pre-checked or hidden default-delete is unacceptable — consent must be explicit and informed.
- **Data protection by design and by default (GDPR Art. 25)**: CA Name Constraints limited to provider domains by default. The `--unsafe` wider-scope CA is gated behind an explicit opt-in checkbox with a warning.
- **ePrivacy Directive**: The installer informs the user that Qindu will intercept TLS traffic on AI domains. The user's informed consent is obtained through installation.

### Scope of machine-wide impact

The installer writes to **HKLM**, affecting all user accounts on the Windows machine. This has privacy implications:

- All Chrome and Edge users on the machine will have their AI traffic routed through Qindu's proxy (if the service is running)
- All user accounts will trust the Qindu CA (machine trust store)
- The firewall rules apply machine-wide

This is **acceptable** because:
1. Qindu is a privacy-protecting tool — routing through the proxy adds PII protection (once QINDU-0005+ is complete)
2. The proxy binds exclusively to `127.0.0.1` — no other machine can access it
3. The CA is constrained to AI provider domains (by default), limiting its scope
4. Uninstalling Qindu removes all machine-wide artifacts

Nevertheless, the scope of impact must be transparently disclosed.

---

## Requirements

The following requirements **MUST** be satisfied by the implementation. These are binding conditions for the DPO gate.

### R1 – Installer Transparency Notice (Critical)

**Rule**: The MSI installer must present a clear, plain-language dialogue explaining what Qindu does, what it installs, and what data it processes on the machine. This notice must appear **before** any system changes are made (files, CA, registry, service, firewall).

The notice must communicate, at minimum:

- "Qindu is a local privacy proxy that protects personal data in your AI conversations"
- "Qindu will install a local Certificate Authority (CA) to inspect TLS traffic on AI service domains (e.g., chatgpt.com, claude.ai)"
- "This CA is stored only on your machine and never shared"
- "Qindu does not collect, transmit, or store your AI conversations — all processing is local"
- "Browser settings will be configured to route AI traffic through Qindu. QUIC will be disabled to ensure TLS inspection works correctly."
- "No data is sent to Qindu as an organization. There is no telemetry, no tracking, and no user account."
- "You can uninstall Qindu at any time. During uninstallation, you can choose to delete all Qindu data."

**Rationale**: GDPR transparency (Art. 5(1)(a), Art. 12), ePrivacy Directive informed consent for TLS interception. Installing a root CA is a highly privileged operation — the user must understand what they are consenting to. This also fulfills C1 from QINDU-0001.

**Verification**: Inspect `installer/wix/includes/dialogs.wxs` for the presence of a dedicated dialogue with the above content. Verify the dialogue appears before the `InstallExecuteSequence` commits changes. Confirm the strings in `locale/en-us.wxl` contain complete transparency messaging.

### R2 – CA Private Key Never Exposed (Critical)

**Rule**: The CA private key must:
- Be generated by `agent.exe ca-init` using ECDSA P-256 (per ADR-003)
- Be stored **only** in DPAPI-encrypted form at `%PROGRAMDATA%\Qindu\ca.key`
- **Never** appear in MSI CustomAction logs, WiX session logs, `ca-init` stdout/stderr, or any installer UI
- **Never** be logged by `agent.exe` at any log level (including DEBUG)
- Have ACL restricting access to `SYSTEM`, `Administrators`, and `LocalService` — no `Authenticated Users`, no `Everyone`

**Rationale**: The CA private key is the highest-sensitivity asset in the Qindu architecture. A compromised CA key would allow an attacker with local admin access to decrypt all past and future AI traffic on that machine. The installer passes through several subsystems (MSI engine, CustomAction, agent.exe) — the key must not leak at any boundary. This extends R3 from QINDU-0001.

**Verification**: Review `cmd/agent/main.go` `runCAInit` for any `fmt.Printf`, `slog.Info`, or `slog.Debug` calls that include key material. Grep WiX CustomAction strings for key-related output. Verify DPAPI encryption path in `internal/tls/ca.go` is invoked before any disk write. Confirm ACL configuration in `installer/wix/includes/files.wxs` or `ca-trust.wxs` for `%PROGRAMDATA%\Qindu\`.

### R3 – No Telemetry, Analytics, Tracking, or Phoning Home (Critical)

**Rule**: The installer, the service, and `agent.exe ca-init` must not:
- Initiate any outbound network connection except to AI service destinations through the proxy pipeline (once running)
- Transmit installation telemetry, usage statistics, crash reports, or machine identifiers
- Include a persistent installation ID, hardware hash, device fingerprint, or tracking UUID
- Check for updates by contacting any external server
- Embed any form of analytics SDK or beacon

**Rationale**: This is a non-negotiable architectural constraint of Qindu (AGENTS.md, ADR-008, QINDU-0001 R5/R6). The installer, as a new component, must not introduce backdoors to this principle.

**Verification**: Review `cmd/agent/main.go` (both service and `ca-init` paths) for any `http.Get`, `http.Post`, or `net.Dial` to non-localhost addresses. Review WiX CustomActions for any `netsh`, `certutil`, or `powershell` commands that contact external hosts. Grep for `uuid`, `machineid`, `device_id`, `installation_id`, `analytics`, `telemetry`, `track`.

### R4 – Browser Policies: Machine-Wide Scope Disclosed (High)

**Rule**: The installer writes browser proxy policies to `HKLM\Software\Policies\Google\Chrome\` and `HKLM\Software\Policies\Microsoft\Edge\`. These policies affect **all user accounts** on the machine, not just the installing user. The transparency notice (R1) must explicitly mention that the browser configuration is machine-wide.

The installer must write these policies systematically (no browser detection required). The proxy PAC URL must point to `http://127.0.0.1:8787/proxy.pac` — no other host, no external URL.

**Rationale**: Machine-wide scope is a deliberate architectural choice (configuring once via HKLM is more reliable than per-user HKCU). However, users sharing a machine must be informed. The PAC URL being localhost is essential for data locality.

**Verification**: Inspect `installer/wix/includes/registry-chrome.wxs` and `registry-edge.wxs` for HKLM paths. Verify `ProxyPacUrl` is `http://127.0.0.1:8787/proxy.pac`. Confirm the transparency notice text mentions machine-wide impact.

### R5 – Uninstall Data Deletion: Explicit Consent (High)

**Rule**: During uninstallation, the MSI must present a checkbox allowing the user to delete all Qindu data (`%PROGRAMDATA%\Qindu\` — containing CA key, certificate, logs, and future vault). The checkbox must:
- Be **unchecked by default** (opt-in, not opt-out)
- Be labeled clearly in plain English: "Delete all Qindu data (vault, logs, and configuration)"
- Trigger `RemoveFolderEx` on `%PROGRAMDATA%\Qindu\` **only if checked** (controlled by the `DELETEDATA` MSI property)
- If unchecked, preserve `%PROGRAMDATA%\Qindu\` intact for potential reinstallation

**Rationale**: GDPR Art. 17 (right to erasure) requires that data subjects can obtain the erasure of personal data. The vault will contain PII mappings (future sprints). An unchecked-by-default checkbox respects the principle that consent must be explicit and affirmative (GDPR Art. 4(11), Art. 7). Pre-checking the box would constitute a nudge toward deletion, which while pro-privacy in effect, sets a poor precedent for consent UX.

**Verification**: Inspect `installer/wix/includes/dialogs.wxs` for the checkbox definition — confirm `CheckboxValue` maps to `DELETEDATA` property and default is off. Inspect `installer/wix/includes/cleanup.wxs` — confirm `RemoveFolderEx` is conditional on `DELETEDATA=1`. Verify that when `DELETEDATA` is not set, `%PROGRAMDATA%\Qindu\` is not removed.

### R6 – ACL Restrictions on Qindu Data Directory (High)

**Rule**: The `%PROGRAMDATA%\Qindu\` directory must be created with ACLs restricting access to:
- `SYSTEM` (Full Control)
- `BUILTIN\Administrators` (Full Control)
- `NT AUTHORITY\LocalService` (Read/Write — the service account)
- **No** `Authenticated Users`, `Users`, or `Everyone` entries

The `%PROGRAMFILES%\Qindu\` directory inherits standard Program Files permissions (read-only for users), which is acceptable given the binary and default config are not secret.

**Rationale**: `%PROGRAMDATA%\Qindu\` will contain the DPAPI-encrypted CA key and, in future sprints, the vault. ACL hardening reduces the attack surface against non-admin users and processes on the machine. DPAPI provides cryptographic protection, but defense in depth requires filesystem-level restrictions.

**Verification**: Inspect `installer/wix/includes/files.wxs` for `Permission` or `PermissionEx` elements on the `%PROGRAMDATA%\Qindu\` directory. If WiX `Permission` elements are used, verify they match the required SIDs. If CustomAction `icacls` or `SetAcl` is used, verify the exact command. Alternate: confirm that `agent.exe ca-init` configures ACLs on first run (and verify the implementation).

### R7 – CA Name Constraints by Default (Medium)

**Rule**: When `agent.exe ca-init` runs in **normal mode** (without `--unsafe`), the generated CA certificate must include the X.509 `Name Constraints` extension with `PermittedDNSDomains` restricted to the provider domains configured in `default.yaml` (currently `chatgpt.com` and `claude.ai`). This means:
- `permitted;DNS:chatgpt.com`
- `permitted;DNS:claude.ai`

The `--unsafe` mode (triggered by the MSI `UNSAFE_CA=1` checkbox) must:
- Display an interactive warning banner in English before allowing the unsafe generation
- Clearly state: "WARNING: Generating CA without Name Constraints. This CA could be used to sign certificates for ANY domain. Only proceed if your browser does not support Name Constraints."
- Require explicit user confirmation via stdin before proceeding
- Generate a CA without Name Constraints

**Rationale**: Privacy by design and default (GDPR Art. 25). Name Constraints are a technical enforcement of the "least decrypt" principle — even if an attacker gained access to the CA key, they could only impersonate AI provider domains, not arbitrary websites (banking, email, healthcare). The `--unsafe` mode is a compatibility escape hatch (some Chrome/Edge versions may not fully respect Name Constraints) but must carry strong warnings.

**Verification**: Review `cmd/agent/main.go` `runCAInit` for:
- `PermittedDNSDomains` being populated from provider config when `!unsafe`
- Interactive confirmation prompt when `unsafe` is true
- Warning banner content and format
- Confirm `x509.Certificate.PermittedDNSDomains` is used (not `PermittedDNSDomainsCritical` unless required)

### R8 – Firewall Rules: Loopback Only (Medium)

**Rule**: The installer firewall CustomActions must create two rules on the `Qindu Agent` profile:
1. **Allow loopback**: `dir=in remoteip=127.0.0.1,::1 localport=8787 protocol=TCP action=allow`
2. **Block external**: `dir=in remoteip=any localport=8787 protocol=TCP action=block`

Rule #2 (the block rule) must have **lower priority/higher specificity** than rule #1 in the Windows firewall stack, or the ordering must ensure loopback is allowed before the block is evaluated. Both rules must be removed during uninstallation.

**Rationale**: The proxy binds `127.0.0.1:8787` (enforced by QINDU-0001 R4), but defense in depth requires a firewall layer. If a future bug or configuration change causes the proxy to bind a non-loopback interface, the firewall block rule would prevent external connections. The loopback allow rule ensures local connections continue working.

**Verification**: Inspect `installer/wix/includes/firewall.wxs` for the exact `netsh advfirewall` commands. Verify both rules are added. Verify uninstall removes both rules. Confirm the block rule uses `remoteip=any` (not just IPv4 ranges). Test that `curl http://127.0.0.1:8787/health` succeeds post-install.

### R9 – No PII in Installer Logging or CustomAction Output (Medium)

**Rule**: The MSI installer logs (WiX session logs, CustomAction output, `msiexec /l*v` verbose logs) must not contain:
- CA private key material
- Configuration secrets
- Any PII (the installer processes no user content, but this rule must constrain future changes)
- The user's uninstall choices (DELETEDATA, UNSAFE_CA) may be logged as MSI property values — this is acceptable as it is consent metadata, not PII

`agent.exe ca-init` must not log the CA private key, the CA certificate serial number, or any cryptographic material at any log level.

**Rationale**: Prevents accidental PII/key leakage through verbose installer logs that users might share for support purposes. Extends QINDU-0001 R1 to the installer context.

**Verification**: Review `cmd/agent/main.go` `runCAInit` for any log calls containing key material. Review WiX CustomAction `ExeCommand` strings for any `/verbose` or debug flags on `ca-init`. Test: run `msiexec /i installer.msi /l*v install.log` and grep install.log for private key indicators (e.g., `PRIVATE KEY`, `EC PRIVATE KEY`, hex dumps).

### R10 – No User Accounts or Persistent Identifiers (High)

**Rule**: Sustained from QINDU-0001 R6. The installer must not:
- Create, reference, or require any user account within Qindu
- Generate or embed a unique installation ID, machine hash, or hardware fingerprint
- Differentiate between users on the same machine (beyond standard Windows ACLs)
- Include any login, registration, or activation mechanism

**Rationale**: Same as QINDU-0001 R6. The installer is a new code path and must not regress this principle.

**Verification**: Grep the installer WiX source, `agent.exe ca-init`, and any helper scripts for `uuidgen`, `machineid`, `device`, `user_id`, `account`, `register`, `activate`, `license_key`.

### R11 – Config File Permissions (Medium)

**Rule**: The deployed `%PROGRAMFILES%\Qindu\configs\default.yaml` must be readable by `LocalService` (the proxy needs it) but should not be world-writable. Standard Program Files permissions (read-only for non-admin users) are acceptable.

The optional override file `%PROGRAMDATA%\Qindu\config.yaml`, if created by the user, should reside within the ACL-restricted `%PROGRAMDATA%\Qindu\` directory (R6) and thus be inaccessible to non-admin users.

**Rationale**: The config file contains the provider domain list and TLS settings. While not PII, it controls which domains are MITM'd. Tampering could redirect interception. Defense in depth: ACL-restrict the directory that may contain the override.

**Verification**: Inspect `installer/wix/includes/files.wxs` for the file component of `configs/default.yaml` — verify it is placed in `%PROGRAMFILES%` (standard ACLs). Verify `%PROGRAMDATA%\Qindu\` ACLs (R6) cover the override file.

### R12 – Test Fixtures Must Contain No Real PII (High)

**Rule**: Sustained from QINDU-0001 R7. Any test fixtures, test YAML configs, sample MSI inputs, or CI/CD artifacts created for this sprint must use synthetic data only. Test CA keys generated during `ca-init` unit tests must use deterministic or throwaway keys, not production key material.

**Rationale**: Same as QINDU-0001 R7 — extended to include any test fixtures related to `ca-init`, path resolution, or MSI configuration.

**Verification**: Grep `cmd/agent/` test files and `installer/` test fixtures for real PII patterns (emails outside example.com/test.local, valid credit card PANs not from test ranges, real phone numbers outside 555-01xx range).

---

## Caveats

The following are non-blocking concerns that must be acknowledged and tracked:

### C1 – No Authenticode Code Signing in This Sprint

The MSI is **not signed** in QINDU-0002 (Authenticode EV/OV excluded per story line 87). Unsigned MSIs trigger Windows SmartScreen warnings ("Windows protected your PC"). This degrades the trust UX for end users — they must click through security warnings to install.

**Mitigation**: The transparency notice (R1) should prepare users for this. A release-specific sprint should add code signing. Tracked as story exclusion line 87.

### C2 – Machine-Wide Browser Policies Without Per-User Escape Hatch

The HKLM policies affect all users, and there is no per-user opt-out mechanism built into the installer. A non-admin user on a shared machine could be routed through Qindu without their individual knowledge or consent if they were not the one who installed it.

**Mitigation**: The transparency notice must mention machine-wide scope (R4). In enterprise deployments, the IT administrator installing Qindu would be the data controller and responsible for employee notification. For personal use, this is a non-issue (single user). Future sprints could add a tray icon with per-user pause capability.

### C3 – CA Without Name Constraints (`--unsafe` Mode) Expands Trust Scope

The `--unsafe` mode generates a CA with no Name Constraints. If a user selects this option to work around browser compatibility issues, the CA can sign certificates for **any domain** (banking, email, healthcare, SSO). This violates the "least decrypt" principle and expands the blast radius of a compromised CA key.

**Mitigation**: The interactive warning banner (R7) and the unchecked-by-default checkbox provide informed consent. The majority of users should use the default (constrained) CA. Future browser updates may improve Name Constraints support, obsoleting the need for `--unsafe`.

### C4 – Uninstall Data Deletion Is All-or-Nothing

The uninstall checkbox (`DELETEDATA`) offers a binary choice: delete everything in `%PROGRAMDATA%\Qindu\` or keep everything. In the future, when the vault contains PII mappings, users might want to delete the vault but keep logs, or vice versa.

**Mitigation**: Acceptable for V1. The all-or-nothing approach is simple and user-understandable. Granular deletion can be added in a future sprint if user research indicates demand. The unchecked-by-default behavior (R5) ensures no accidental deletion.

### C5 – No Automated Privacy Regression Tests for Installer

The MSI installer cannot be integration-tested in CI (requires interactive Windows session per story line 78). Tests are limited to:
- `ca-init` unit tests (Go)
- WiX syntax validation (`candle -nologo` dry-run)
- Cross-compilation verification

This means the privacy requirements for the installer (transparency notice text, checkbox behavior, ACL configuration) must be verified manually during release or through code review.

**Mitigation**: The DPO review gate for this sprint will inspect WiX source and dialogue strings. Manual testing on a Windows VM must be part of the release checklist. This is an acceptable risk for the second sprint.

### C6 – Config Override Mechanism Introduces Tampering Surface

The `%PROGRAMDATA%\Qindu\config.yaml` override file (story line 63) allows users (with admin access to the directory) to override any key from `default.yaml`, including `providers.*.domains`. A malicious admin could expand the MITM scope. This is a feature, not a bug — the local admin owns the machine — but it should be documented clearly.

**Mitigation**: ACL restrictions (R6) limit write access to admin-level accounts. The override is a deliberate power-user feature. Document that modifying provider domains expands TLS interception scope.

---

## Test Scenarios for QA

The following scenarios must be tested to verify privacy requirements:

- [ ] **TS1 — Transparency notice present**: Run `msiexec /i Qindu-Installer-x64.msi` and verify a dialogue appears explaining TLS interception, CA installation, and local-only processing before any system changes are committed.
- [ ] **TS2 — CA private key not in install logs**: Run `msiexec /i Qindu-Installer-x64.msi /l*v install.log`. Grep `install.log` for `PRIVATE KEY`, `EC PRIVATE`, `BEGIN EC`, `-----BEGIN`. Verify zero matches.
- [ ] **TS3 — CA Name Constraints present by default**: After installation, inspect the CA certificate (`certutil -dump "%PROGRAMDATA%\Qindu\ca.crt"`). Verify the Name Constraints extension contains `Permitted DNS: chatgpt.com` and `Permitted DNS: claude.ai` (or whatever providers are in default.yaml).
- [ ] **TS4 — Unsafe mode warning interactive**: Run `agent.exe ca-init --unsafe` from a terminal. Verify an English warning banner appears and requires stdin confirmation before proceeding.
- [ ] **TS5 — Unsafe CA checkbox defaults to off**: Run the MSI installer UI. Verify the `UNSAFE_CA` checkbox is **unchecked** by default.
- [ ] **TS6 — Uninstall with DELETEDATA=1 removes all**: Run `msiexec /x <ProductCode> DELETEDATA=1`. Verify `%PROGRAMDATA%\Qindu\` directory is deleted. Verify registry keys for Chrome/Edge proxy policies are removed. Verify firewall rules are removed. Verify CA certificate is removed from trust store.
- [ ] **TS7 — Uninstall without DELETEDATA preserves data**: Run `msiexec /x <ProductCode>`. Verify `%PROGRAMDATA%\Qindu\` directory is **preserved**. Verify all other artifacts (service, registry, CA trust, firewall) are still removed.
- [ ] **TS8 — Uninstall data deletion checkbox defaults to off**: Run the MSI uninstall UI. Verify the "Delete all Qindu data" checkbox is **unchecked** by default.
- [ ] **TS9 — Loopback-only access enforced**: Post-install, verify `curl http://127.0.0.1:8787/health` returns `{"status":"up"}`. From another machine on the same network, verify `curl http://<machine-ip>:8787/health` is **blocked** (connection refused or timeout).
- [ ] **TS10 — Firewall rules present and correct**: Run `netsh advfirewall firewall show rule name="Qindu Agent (Allow Loopback)"` and `name="Qindu Agent (Block External)"`. Verify both exist with correct parameters.
- [ ] **TS11 — ACLs restrict Qindu data directory**: Run `icacls "%PROGRAMDATA%\Qindu"`. Verify the output shows only `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`, and `NT AUTHORITY\LocalService` with access rights. Verify `Authenticated Users` and `Everyone` are **absent**.
- [ ] **TS12 — Browser policies machine-wide**: Post-install, check `reg query HKLM\Software\Policies\Google\Chrome` and `HKLM\Software\Policies\Microsoft\Edge`. Verify `ProxyMode=pac_script`, `ProxyPacUrl=http://127.0.0.1:8787/proxy.pac`, `QuicAllowed=0x0`.
- [ ] **TS13 — No telemetry endpoints in code**: Grep the full codebase (including WiX source) for `api.qindu`, `telemetry`, `analytics`, `crash-report`, `update-check`, `metrics.qindu`. Verify zero matches.
- [ ] **TS14 — `ca-init` output contains no key material**: Run `agent.exe ca-init --config test_config.yaml 2>&1` and capture stdout/stderr. Grep for hex patterns, `PRIVATE KEY`, DER base64 blocks. Verify only status messages appear.
- [ ] **TS15 — No user identifiers generated**: Grep the codebase for `uuid.New`, `machineid`, `device_id`, `installation_id`. Verify zero matches outside of test/debug code (if any).
- [ ] **TS16 — Config file not world-writable**: Run `icacls "%PROGRAMFILES%\Qindu\configs\default.yaml"`. Verify `Authenticated Users` do not have Write or Modify permissions.
- [ ] **TS17 — Upgrade does not delete vault data**: Install Qindu v1, then install Qindu v2 (upgrade MSI). Verify `%PROGRAMDATA%\Qindu\` (including any test files placed there) survives the upgrade intact.
- [ ] **TS18 — `ca-init` re-generation clears old CA**: Run `agent.exe ca-init` twice. Verify the second run destroys and replaces the CA key and certificate. Verify no copy of the old key remains.

---

## Risk Assessment

| ID | Risk | Likelihood | Impact | Mitigation | Residual |
|---|---|---|---|---|---|
| RK1 | CA private key leaked in MSI verbose log (`/l*v`) | Low | High — key compromise | R2 (never log key), R9 (no PII/key in logs). Verify via grep in QA TS2 | Low |
| RK2 | Unsafe CA selected by default (checkbox pre-checked) | Low | Medium — CA scope expanded to all domains without user awareness | R7 (unchecked default), interactive warning. QA TS5 | Very Low |
| RK3 | Vault data deleted without consent (DELETEDATA pre-checked) | Low | Medium — loss of PII token mappings (future sprints) | R5 (unchecked default). QA TS8 | Very Low |
| RK4 | Non-admin user on shared machine has traffic intercepted without knowledge | Medium | Low — traffic is only inspected for PII protection on AI domains, no data leaves the machine | R4 (machine-wide scope disclosed in transparency notice). C2 | Low |
| RK5 | Firewall block rule misconfigured, allows external connections to port 8787 | Low | High — remote attacker could use the proxy | R8 (two-rule strategy), QA TS9, TS10 | Low |
| RK6 | Browser QUIC not fully suppressed by policy, traffic bypasses proxy | Medium | Medium — some AI traffic not inspected (PII leakage in future sprints) | Registry policy writes to HKLM for both Chrome and Edge. QUIC bypass is an assumed limitation (ARCHITECTURE.md §6) | Medium |
| RK7 | Uninstall fails silently for registry cleanup, leaving proxy policies | Low | Medium — browser remains configured to use non-existent proxy, connection errors | MSI rollback on failure, QA TS6 (verify registry cleanup) | Low |
| RK8 | `%PROGRAMDATA%\Qindu\` ACL too permissive, non-admin users can read CA key | Low | Medium — DPAPI prevents decryption but defense in depth is weakened | R6, QA TS11 | Low |

---

## Verdict

### Verdict: **PROCEED_WITH_CAVEATS**

**Rationale**: QINDU-0002 introduces no new PII processing — it is purely installation and deployment infrastructure. The sprint is a necessary prerequisite for the privacy-enhancing PII tokenization pipeline (QINDU-0005+). The architecture respects all established Qindu principles:

- **Local-only**: Everything runs on the user's machine, no external services
- **CA protected**: DPAPI encryption, ACL-restricted directory, never logged
- **Least decrypt**: Name Constraints limit CA scope to AI provider domains by default
- **Transparency**: Mandatory installer notice (R1) explains TLS interception
- **Consent**: Explicit opt-in for unsafe CA (R7) and data deletion (R5)
- **No tracking**: Sustained from QINDU-0001 (R3, R10)
- **Defense in depth**: Firewall loopback restriction (R8), ACL hardening (R6)

**Blocking issues**: None. All concerns are captured as caveats (C1–C6) with documented mitigations.

**Requirements for DPO review gate** (to be verified against `dev-notes.md`): R1 (transparency notice text present in WiX dialogs), R2 (no CA key in logs/output), R3 (no telemetry), R5 (DELETEDATA unchecked by default), R7 (Name Constraints applied by default, --unsafe gated behind warning), R8 (firewall rules correct).

**Caveats that must be addressed in subsequent sprints or during implementation review:**

1. **C1 (Release sprint)**: MSI must be Authenticode-signed before production distribution.
2. **C3 (QINDU-0005+)**: Monitor browser compatibility with Name Constraints. If major browsers consistently support them, consider removing the `--unsafe` option.
3. **C2 (Future)**: Consider a tray icon with per-user pause/disable for shared-machine scenarios.
4. **C5 (Release process)**: Manual Windows VM testing must verify all QA scenarios before release.
5. **C4 (Future)**: Consider granular data deletion options (vault vs logs) if user research warrants it.

**The DPO gate for QINDU-0002 design phase is PASSED, contingent on verification of requirements R1–R12 during the review phase.**
