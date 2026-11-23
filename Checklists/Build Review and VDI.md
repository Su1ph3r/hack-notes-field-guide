---
tags:
  - hack-notes
  - checklist
  - build-review
  - vdi
---

# Build Review and VDI Testing Checklist

> Use for a workstation/server "gold image" build review and Virtual Desktop Infrastructure (Citrix, VMware Horizon, AVD, Windows 365) or kiosk breakout assessment. Core question: given a corporate laptop or a locked-down VDI session, what can a malicious insider or a thief actually do? Methodology-first; long commands live in the linked cheatsheets.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Hardening Baseline Review](#2-hardening-baseline-review)
- [3. Application Control and Whitelisting](#3-application-control-and-whitelisting)
- [4. Privilege Escalation on the Build](#4-privilege-escalation-on-the-build)
- [5. VDI and Kiosk Breakout](#5-vdi-and-kiosk-breakout)
- [6. Network and Data Egress](#6-network-and-data-egress)
- [7. Credential and Identity](#7-credential-and-identity)
- [8. Endpoint Protection Evaluation](#8-endpoint-protection-evaluation)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

### Engagement definition
- [ ] **Confirm the artifact under test:** physical laptop, a captured `.wim`/`.vhdx` gold image, a live VDI session, or all three. Record build name, version, and image date.
- [ ] **Confirm test accounts:** at minimum a standard-user account; ideally a second standard account (to test cross-user reads) and, if in scope, a separate admin account for white-box comparison. Note which the findings were proven under.
- [ ] **Confirm the threat model in scope:** thief with physical access (offline attacks allowed), malicious insider with valid creds (online only), or both. This decides whether BitLocker/firmware offline attacks are fair game.
- [ ] **Confirm VDI platform and delivery type:** Citrix Virtual Apps and Desktops, VMware Horizon, Azure Virtual Desktop (AVD), or Windows 365 Cloud PC. Record version and the broker/gateway in front of it.
- [ ] **Confirm session type:** published single application (seamless), published full desktop, or kiosk/assigned-access shell. The breakout surface differs sharply per type.
- [ ] **List in-scope breakout objectives:** reach `cmd.exe`/`powershell.exe`, reach `explorer.exe`, read the local/redirected filesystem, reach the internet egress-free, escalate to local admin, or reach back-end infrastructure. Get each signed off explicitly.

### Rules of engagement and safety
- [ ] **Agree blast radius:** is the image a throwaway test build or a live production session that other users share? Flag any destructive or persistence-creating step before running it.
- [ ] **Agree on offline/physical actions:** PXE, USB boot, drive removal, firmware changes. These can brick a device; require written approval and ideally a spare unit.
- [ ] **Confirm logging expectations:** whether the SOC should see your activity (purple-team) or not, and whether EDR alerts during testing are expected.

```
⚠️ Firmware/BIOS password changes, Secure Boot key edits, and PXE/USB boot can leave a
device unbootable. BitLocker reconfiguration can trigger recovery-key lockout. Never run
these on the only copy of a production build. Snapshot or image first.
```

### Baseline capture
- [ ] **Capture the as-delivered state:** OS build (`winver`, `Get-ComputerInfo`), patch level (`Get-HotFix`), installed software inventory, and a screenshot of the locked-down session before you touch anything.
- [ ] **Record the comparison standard:** which CIS Benchmark level (L1/L2) or internal hardening standard the build claims to meet, so findings map to a named control.

---

## 2. Hardening Baseline Review

### OS patch and configuration baseline
- [ ] **Check patch currency:** compare `Get-HotFix` and build number against the latest cumulative update. Flag any missing patch tied to a local-privesc or BitLocker CVE (see Recent Techniques).
- [ ] **Run an automated CIS/hardening audit:** use a CIS-CAT-style or PowerShell baseline tool and capture the pass/fail summary. Treat each failed control as a candidate finding, then validate the high-impact ones by hand.
- [ ] **Review PowerShell exposure:** is Constrained Language Mode enforced, script block + module logging on, transcription on, PowerShell v2 removed? `$ExecutionContext.SessionState.LanguageMode` should return `ConstrainedLanguage` on a hardened build for a standard user.
- [ ] **Check legacy protocol/feature exposure:** SMBv1, LLMNR/NBT-NS, WDigest cred caching, WPAD. Each is a build-level weakness even before you escalate.

### Disk encryption
- [ ] **Confirm full-volume encryption is on:** `manage-bde -status` (Windows) shows all fixed volumes Fully Encrypted; `fdesetup status` (macOS) shows FileVault On. A "Used Space Only" or partially encrypted volume is a finding.
- [ ] **Determine the BitLocker protector type:** `manage-bde -protectors -get C:`. TPM-only (no PIN/USB) is the weak case: it auto-releases the key at boot and is exposed to bitpixie, TPM sniffing, and DMA (see Recent Techniques). TPM+PIN or TPM+USB is the hardened case.
- [ ] **Check for a stored recovery key path:** confirm recovery keys are escrowed to AD/Entra, not printed and left with the device. Confirm a standard user cannot read their own recovery key from the portal if that grants offline decrypt.
- [ ] **macOS: confirm FileVault recovery key custody** and that the user is not a Secure Token holder able to add bypass accounts.

### Boot chain and firmware
- [ ] **Confirm Secure Boot is enabled and enforcing:** `Confirm-SecureBootUEFI` returns `True`. A disabled or audit-mode Secure Boot lets an attacker boot an unsigned recovery/Linux image.
- [ ] **Check the Secure Boot revocation state (DBX):** an un-updated DBX leaves the system exposed to revoked boot managers (the bitpixie path). Confirm KB5025885 / UEFI CA 2023 hardening is applied if in scope.
- [ ] **Verify a firmware/BIOS supervisor password is set** and that boot order is locked. Without it, an attacker re-enables USB/PXE boot in seconds.
- [ ] **Check DMA/Thunderbolt posture:** Kernel DMA Protection on, or SBP-2/Thunderbolt controllers blocked, to reduce 1394/Thunderbolt DMA key-extraction risk on a powered/standby device.

### Removable media and local rights
- [ ] **Test USB and removable-media policy:** insert a mass-storage device and confirm it is blocked or read-only per policy. Test whether a USB-HID (rubber-ducky style) device is allowed even when mass storage is blocked.
- [ ] **Enumerate local administrators:** `net localgroup administrators`. A standard build should not place the interactive user in local admins. Note any helpdesk/vendor accounts present.
- [ ] **Confirm LAPS (or Windows LAPS) is deployed:** local admin password is unique per host and rotated. A shared/static local admin password across the fleet is a high-impact lateral-movement finding. Confirm a standard user cannot read the LAPS attribute.
- [ ] **Check for cleartext or weak local accounts:** unattend.xml/sysprep leftovers, autologon creds in registry (`DefaultPassword`).

---

## 3. Application Control and Whitelisting

### Inventory the control
- [ ] **Identify the application-control mechanism:** AppLocker, Windows Defender Application Control (WDAC), Smart App Control, or a third party. Dump the active policy: `Get-AppLockerPolicy -Effective -Xml` and check WDAC via the CodeIntegrity event log and `CiTool`.
- [ ] **Determine enforcement vs audit mode:** a policy in audit-only mode blocks nothing. Confirm Block/Enforced mode for each rule collection (Exe, Script, MSI, DLL, Packaged apps). Missing DLL and Script collections are common gaps.
- [ ] **Map the allow-list philosophy:** path-based (weak, user-writable paths defeat it) vs publisher/hash-based (stronger). Flag any rule that allows a whole user-writable directory.

### Test for bypasses
- [ ] **Hunt user-writable allowed paths:** if any allow rule covers a directory a standard user can write to (e.g. a misconfigured `C:\Windows\Tasks`, a temp/spool path), drop and run a binary there. This is the simplest defeat.
- [ ] **Test default-rule weaknesses:** AppLocker's default rules allow everything under `C:\Windows` and `C:\Program Files`; find a user-writable subfolder within those trees and execute from it.
- [ ] **Test LOLBAS signed-binary proxy execution:** attempt code execution through trusted Microsoft binaries that app control usually permits. Confirm each is blocked or allowed:
  - `regsvr32` (scriptlet/COM), `mshta` (HTA), `rundll32`, `wscript`/`cscript`.
  - `MSBuild.exe` and `InstallUtil.exe` inline-task/installer execution (classic AppLocker defeats).
  - `winget.exe` to stage binaries into an allowed location.
  - `presentationhost`, `dnx`, `regasm`/`regsvcs`, `wmic` where present.
- [ ] **Check the full LOLBAS catalog against the policy** rather than a handful: pull the current LOLBAS list and test the Execute/Download/AWL-bypass entries that the policy does not explicitly block.
- [ ] **Test script-interpreter exposure:** can a standard user run unrestricted PowerShell, VBScript, JScript, or HTA? Confirm Constrained Language Mode actually blocks `Add-Type`/reflection, not just the prompt cosmetics.
- [ ] **Test container/format smuggling:** mount an `.iso`/`.vhd` to run an internal payload (mark-of-the-web is lost inside the image), and abuse `.lnk` and `.scf` files. Confirm these are blocked.
- [ ] **Test Office macro policy:** open a macro-enabled doc; confirm macros from the internet are blocked (MOTW), VBA is locked down, and ASR macro rules fire. Test XLL/add-in and DDE paths too.
- [ ] **Test WDAC-specific gaps:** look for an allowed but vulnerable signed binary, a permissive Intelligent Security Graph (ISG) fallback, or supplemental-policy gaps. WDAC is stronger than AppLocker, so failures here matter more.

---

## 4. Privilege Escalation on the Build

> Run the full local-privesc methodology here. This section is the build-specific lens; the deep technique reference is [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md).

### Automated triage
- [ ] **Run a privesc enumerator as the standard user:** PrivescCheck and/or WinPEAS. Capture the report and triage every "exploitable" and "potentially vulnerable" hit. Do not stop at the first finding.
- [ ] **Cross-check findings manually:** automated tools over- and under-report; confirm each candidate has a real, writable target before claiming it.

### Service and task weaknesses
- [ ] **Find unquoted service paths with spaces** and a writable intermediate directory: `wmic service get name,pathname,startmode` then test write access to the hijack point.
- [ ] **Find weak service permissions:** services a standard user can reconfigure (`SERVICE_CHANGE_CONFIG`) or whose binary/folder is user-writable. Use `accesschk` against the binary path.
- [ ] **Find weak scheduled tasks:** a task running as SYSTEM/admin whose script or binary lives in a user-writable path. Enumerate `schtasks /query /v /fo LIST` and check ACLs on each action target.
- [ ] **Check DLL hijack/search-order opportunities** for privileged processes that load a missing DLL from a writable directory.

### UAC and auto-elevation
- [ ] **Identify the UAC level** and whether auto-elevating Microsoft binaries are reachable. If the user is in admins behind UAC, test a current auto-elevate/fodhelper-style bypass to go from medium to high integrity.
- [ ] **Note the distinction:** a UAC bypass only matters when the user is already a local admin. For a pure standard user, focus on service/task/secret paths instead.

### Stored secrets
- [ ] **Hunt GPP cached secrets:** `Groups.xml`/`Services.xml` `cpassword` in SYSVOL cache or `C:\ProgramData`. Still appears in migrated estates.
- [ ] **Hunt registry and file secrets:** autologon creds, mapped-drive scripts, `unattend.xml`, app config files, RunOnce entries, and credential blobs in `C:\ProgramData`.
- [ ] **Check credential caching policy:** number of cached domain logons (`CachedLogonsCount`), WDigest, and whether Credential Guard is on (raises the bar for LSASS theft).
- [ ] **Enumerate the local attack surface for AD context** if domain-joined, then pivot via [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md) and confirm the host's position with BloodHound.

---

## 5. VDI and Kiosk Breakout

> Goal: escape a published app, published desktop, or kiosk to reach a general-purpose shell or filesystem. Acquiring any Windows dialog is the usual first foothold.

### Map the cage
- [ ] **Enumerate what you are given:** is it a single seamless app, a restricted desktop with no Start menu, or assigned-access kiosk? Note every visible UI element, menu, toolbar, and hyperlink as a potential pivot.
- [ ] **Identify the published app:** browsers, Office, PDF readers, custom LOB apps, and admin tools are all rich breakout vectors. A "lowly" Notepad or Help window is often enough.

### File-dialog and picker abuse
- [ ] **Force an Open/Save/Print dialog** (File > Open, attach, upload, export, print-to-file) and use it as a mini file explorer:
  - Type a path such as `C:\Windows\System32\` into the filename field to navigate.
  - Type `cmd.exe` or `\\127.0.0.1\c$\Windows\System32\cmd.exe` and Open it.
  - Set the file-type filter to `All Files`, right-click a binary, and choose Open/Run.
- [ ] **Use the dialog address bar / Run-equivalent:** enter a UNC path, a `file://` or `shell:` location, or an environment variable path to reach restricted areas.
- [ ] **Right-click / context-menu escapes:** right-click in the dialog or on the desktop for "Open command window here", "Edit", "Run as", or "New > Shortcut" pointing at a shell. Create a `.bat`/`.lnk` to `cmd.exe` and launch it.
- [ ] **Drag-and-drop:** drag a binary onto `cmd.exe` or onto a tool that executes its argument.

### Protocol and helper abuse
- [ ] **Abuse URI/URL handlers:** in any address field or hyperlink, try `file:`, `shell:`, `ms-settings:`, `search-ms:`, `mailto:`, and app-specific schemes to spawn helper processes or Explorer windows.
- [ ] **Abuse Help, Print, and About dialogs:** legacy Help (`.chm`/`hh.exe`), "Print to file", and embedded hyperlinks frequently spawn a browser or Explorer that escapes the cage.
- [ ] **Browser-based escape:** if a browser is reachable, use `file:///C:/` to browse the disk, the download dialog as a file picker, view-source/devtools, and `about:` pages. Confirm devtools and the address bar are not locked.
- [ ] **Keyboard-shortcut escapes:** test Win+E (Explorer), Win+R (Run), Ctrl+Shift+Esc (Task Manager > File > Run new task), Win+D, sticky-keys/utilman, F1 (Help), Shift+F10, and app hotkeys. Note which the policy actually suppresses.

### Redirection-channel abuse
- [ ] **Drive redirection:** if client-drive mapping is on, the mapped drive is a writable channel to stage tools into the session or exfil files out. Confirm whether it is enabled and read/write.
- [ ] **Clipboard redirection:** test bidirectional clipboard as a copy/paste exfil and tool-injection channel; large or file-clipboard transfers are the interesting case.
- [ ] **Printer / "print to PDF" redirection:** redirect-to-client printing (including print-to-file) can write attacker-readable output to the client and is a data-egress channel.
- [ ] **Other virtual channels:** test COM/LPT mapping, USB redirection, and smart-card channels for unexpected reach into the host or client.

### Platform-specific checks
- [ ] **Citrix:** check published-app lockdown, Local App Access / URL redirection config, and whether `explorer.exe` or a console is reachable. Citrix and Terminal Services deployments are frequently under-hardened.
- [ ] **VMware Horizon:** check published-app vs full-desktop scope, USB/drive/clipboard redirection policy, and whether the agent restricts shell access.
- [ ] **AVD / Windows 365:** for a kiosk/assigned-access or RemoteApp deployment, test the same dialog/handler escapes, RemoteApp argument injection, and whether the underlying session host is a shared multi-session VM (lateral risk to other users).
- [ ] **Confirm the post-breakout integrity:** once you reach a shell, you are now a standard user on the session host. Re-run Section 4 there to chase privilege escalation and back-end reach.

---

## 6. Network and Data Egress

### Egress filtering from the build
- [ ] **Test outbound reachability:** from the standard-user context, attempt direct outbound on common ports (80/443/53/22) and to arbitrary IPs. Confirm whether the build forces all traffic through a proxy/SWG or allows direct egress.
- [ ] **Test DNS egress:** can the host resolve and reach arbitrary external domains? Test a DNS-tunnel style query as a covert-channel proof if direct egress is blocked.
- [ ] **Test proxy bypass:** try bypassing the configured proxy (direct connect, alternate proxy, PAC-file manipulation, raw IP, non-standard ports). A bypassable proxy defeats web filtering and DLP that depend on it.
- [ ] **Test allowed-destination abuse:** if egress is whitelisted, can you tunnel over an allowed service (cloud storage, a permitted SaaS, ICMP) for C2/exfil?

### Data loss prevention and exfil
- [ ] **Test DLP on the obvious channels:** copy a marked-sensitive sample file to USB, to a personal cloud upload, to webmail, and to the clipboard. Record which channels DLP blocks, alerts on, or misses.
- [ ] **Test VDI-specific exfil:** clipboard out, drive-redirection copy out, print-to-client/PDF, and screenshot/screen-capture. These bypass host-level USB DLP because the data leaves via the session channel.
- [ ] **Test USB exfil end to end** where removable media is allowed: confirm whether write is blocked, encrypted-only enforced, or wholly open.
- [ ] **Test renaming/encoding evasion of DLP:** archive, rename extension, split, or encode the sensitive file and retry the channels that blocked the cleartext.

```
⚠️ Use synthetic/marked canary files for DLP and exfil testing, never real client data.
Coordinate egress tests with the SOC so a covert-channel proof is not mistaken for a live breach.
```

---

## 7. Credential and Identity

### Local and cached credentials
- [ ] **Assess cached domain credentials:** with the threat model of a stolen, offline device, cached logon verifiers (MSCache2) are crackable. Confirm `CachedLogonsCount` is minimal and Credential Guard is on.
- [ ] **Test LSASS reachability:** as the standard user, attempt to read LSASS (expected to fail). Note whether Credential Guard / PPL / ASR LSASS rule actually blocks it.
- [ ] **Enumerate the Credential Manager / vault:** `cmdkey /list` and the Windows Credential Manager for saved RDP, network share, and web credentials reachable by the user.

### DPAPI and stored secrets
- [ ] **Assess DPAPI-protected secrets:** browser passwords, Wi-Fi keys, and app secrets are recoverable by the owning user without admin. Test extraction of browser-stored credentials from the user profile.
- [ ] **Check browser-stored credentials and cookies:** can the user (or anyone with the unlocked profile) dump saved passwords, session cookies, and SSO tokens? App-bound encryption raises the bar on current Chrome/Edge; confirm it is in effect.
- [ ] **Hunt saved RDP/VPN credentials:** `.rdp` files with stored creds, saved VPN profiles, and stored gateway passwords.

### SSO and modern identity
- [ ] **Test SSO/token theft surface:** look for PRT (Primary Refresh Token) use, browser session cookies, and OAuth refresh tokens cached on the build. On Entra-joined devices, confirm token protection / conditional access binds tokens to the device.
- [ ] **Assess Windows Hello / passwordless config:** is Hello for Business backed by TPM and biometric/PIN, and is the device the trust anchor? Note whether a stolen unlocked device yields silent SSO to corporate apps.
- [ ] **Check for credential reuse impact:** if any local-admin or service credential recovered here is shared across the fleet (no LAPS), document the lateral-movement blast radius and hand off to [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md).

---

## 8. Endpoint Protection Evaluation

### Presence and configuration
- [ ] **Confirm EDR/AV is installed, running, and current:** identify the product, agent version, and last definition update. A stale or absent agent on the gold image is a finding.
- [ ] **Confirm real-time protection and key ASR rules are in Block mode** (not audit/off): LSASS theft, Office child-process, obfuscated-script, and the copied/impersonated-system-tools rule.
- [ ] **Confirm cloud-delivered protection and sample submission are on** for Defender, or the equivalent cloud lookup for third-party EDR.

### Tamper resistance
- [ ] **Test whether a standard user can disable protection:** stop/uninstall the service, kill the agent process, disable via the tray UI, or flip the registry/Set-MpPreference. Standard user disabling AV is a high-impact finding.
- [ ] **Test whether a local admin can disable it without tamper protection challenge:** confirm Tamper Protection is on and blocks `Set-MpPreference -DisableRealtimeMonitoring`, exclusion edits, and service stop even from an elevated context.
- [ ] **Check the exclusion list:** overly broad path/process exclusions (a user-writable folder, a whole drive) are an unmonitored execution lane. Confirm a standard user cannot read or write exclusions.
- [ ] **Assess BYOVD exposure:** confirm the Microsoft vulnerable-driver blocklist (HVCI/WDAC) is enabled, since EDR-killer toolkits load signed vulnerable drivers to blind protection from kernel.

### Detection and logging
- [ ] **Confirm telemetry reaches the SIEM:** generate a benign-but-noisy event (e.g. a known LOLBin invocation) and verify with the blue team that it logged and alerted. A silent EDR is as bad as no EDR.
- [ ] **Check that your earlier breakout/privesc actions generated alerts:** correlate Sections 3-5 activity with what the SOC saw, and note any blind spots as detection-gap findings.

---

## Recent Techniques (2024-2026)

- [ ] **bitpixie / CVE-2023-21563 BitLocker bypass:** software-only attack that forces a PXE soft-reboot leaving the BitLocker VMK in memory, recovered via an attacker-controlled boot. Test for: TPM-only protectors plus an un-updated Secure Boot DBX (pre-KB5025885 / UEFI CA 2023). Mitigation is a pre-boot PIN.
- [ ] **WinPE / signed-bootloader downgrade variants of bitpixie:** booting a vulnerable signed Windows boot manager to extract the VMK. Test for: Secure Boot not enforcing DBX revocation.
- [ ] **YellowKey BitLocker attack (2024):** low-skill, fast TPM-released-key recovery against TPM-only/no-pre-boot-auth builds, no dedicated hardware. Test for: any volume with TPM-only and no PIN.
- [ ] **TPM bus sniffing (LPC/SPI):** capture the VMK on the TPM bus at boot when no pre-boot auth is set. Test for: TPM-only protector; mitigation is PIN/key pre-boot auth, not the TPM alone.
- [ ] **Thunderbolt/PCIe DMA key extraction:** read keys from memory on a powered/standby device via DMA. Test for: Kernel DMA Protection off and Thunderbolt/SBP-2 not blocked.
- [ ] **"Block copied or impersonated system tools" ASR rule (preview):** counters LOLBin-copied-to-non-system-path abuse. Test for: rule absent/audit; then run the copy-and-execute bypass to prove the gap.
- [ ] **winget.exe app-control bypass:** stage and run executables into AppLocker-allowed locations via winget. Test for: winget reachable and not blocked by policy.
- [ ] **MSBuild / InstallUtil inline execution:** still defeats default AppLocker rule sets. Test for: dev/build binaries present and not explicitly blocked (WDAC needed to close it).
- [ ] **Ligolo-based app-control + tunneling bypass:** combine in-memory/trusted-process execution with internal tunneling to defeat application control and reach the network. Test for: app control that stops files but not embedded execution logic.
- [ ] **BYOVD EDR-killers (e.g. GentleKiller and similar 2025 toolkits):** signed-but-vulnerable drivers loaded to blind EDR from Ring 0. Test for: vulnerable-driver blocklist / HVCI disabled.
- [ ] **EDR free-trial / unmanaged-agent abuse:** deploying a second, attacker-controlled EDR/agent to suppress the managed one. Test for: ability to install unauthorized security agents as the user.
- [ ] **Entra token / PRT theft on managed builds:** lifting PRTs and SSO cookies from a stolen device. Test for: token protection / device-bound conditional access not enforced.

---

## Reporting and Evidence

### Evidence to capture per finding
- [ ] Screenshot the locked-down starting state and the exact UI action that began a breakout (the dialog, menu, or handler used).
- [ ] Capture the proof of escape: a shell prompt showing `whoami`, hostname, and integrity level, with a timestamp.
- [ ] For config findings, save the raw command output (`manage-bde -status`, `Get-AppLockerPolicy`, `cmdkey /list`, ASR state) rather than a retyped summary.
- [ ] For egress/DLP, save the request/response or transfer evidence and name the channel, the marked file, and the result (blocked/alerted/passed).
- [ ] Record which test account (standard vs admin) and which artifact (image/laptop/live session) each finding was proven under.

### Severity guidance
| Finding | Typical severity |
| --- | --- |
| Standard user reaches a shell / breaks out of kiosk-VDI | High to Critical |
| Standard user disables EDR/AV | High |
| TPM-only BitLocker exposed to bitpixie/sniffing (thief model) | High |
| Standard-user local privesc to admin | High |
| App-control bypass to arbitrary execution | High |
| Shared/static local admin password (no LAPS) | High |
| Browser/DPAPI credential recovery by the user | Medium to High |
| DLP or egress bypass for sensitive data | Medium to High |
| Missing hardening control with no proven exploit | Low to Medium |

### Common false positives to rule out
- [ ] An app-control "bypass" that only works because your test account was actually a local admin: re-prove as a true standard user.
- [ ] A "breakout" into a shell that is itself constrained (Constrained Language Mode, AppLocker still enforcing): confirm you can actually execute and not just see a prompt.
- [ ] A BitLocker "weakness" that is out of the agreed threat model (e.g. claiming an offline attack when only the insider/online model was in scope).
- [ ] An EDR "disable" that required a UAC/tamper prompt you clicked through with admin: distinguish standard-user from admin-with-tamper-off.
- [ ] A DLP "bypass" where the channel actually alerted silently to the SOC: confirm with the blue team before calling it a miss.

---

## Tools and References

| Tool / Reference | Use |
| --- | --- |
| PrivescCheck, WinPEAS | Standard-user local privilege-escalation triage on the build |
| LOLBAS project list | Signed-binary proxy execution to defeat app control |
| UltimateAppLockerByPassList, UltimateWDACBypassList | Catalogued AppLocker/WDAC bypass techniques |
| `accesschk`, `manage-bde`, `Confirm-SecureBootUEFI`, `Get-AppLockerPolicy`, `CiTool` | Build/config inspection |
| BloodHound | Map the host's position and privesc reach once domain context is reached |
| CIS Benchmarks (Windows / macOS) | Authoritative hardening baseline to score the build against |
| `bitpixie` PoC, TPM-Sniffing references | Offline BitLocker attack validation (with approval) |
| Citrix / VMware Horizon / AVD security baselines | Vendor hardening guidance for the VDI layer |
| Microsoft Defender ASR rules reference | Confirm and test ASR rule coverage |

---

## Related
- [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md)
- [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md)
- [Assumed Breach](Assumed%20Breach.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
