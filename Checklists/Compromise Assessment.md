---
tags:
  - hack-notes
  - checklist
  - dfir
  - threat-hunting
---

# Compromise Assessment Testing Checklist

> Proactive, point-in-time hunt for evidence of existing or past compromise across endpoints, identity, network, and cloud. Defensive / threat-hunting engagement aligned to MITRE ATT&CK and the hunting loop. Use when a client wants assurance no adversary is currently resident, or when low-confidence indicators warrant a structured sweep short of a full incident response. If you confirm an active intrusion, STOP hunting and trigger the IR escalation path agreed in scoping.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Data Source Inventory and Visibility](#2-data-source-inventory-and-visibility)
- [3. Endpoint Hunting](#3-endpoint-hunting)
- [4. Identity and Active Directory Hunting](#4-identity-and-active-directory-hunting)
- [5. Network Hunting](#5-network-hunting)
- [6. Cloud and M365 Hunting](#6-cloud-and-m365-hunting)
- [7. Threat Intelligence and IOC Sweep](#7-threat-intelligence-and-ioc-sweep)
- [8. Triage, Validation, and Reporting](#8-triage-validation-and-reporting)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

A compromise assessment is hypothesis-driven hunting, not alert triage. Define what "good" looks like before you hunt so you can call a host clean with evidence, not just an absence of alerts.

### Objectives and Hypotheses
- [ ] **Set the engagement objective:** assurance sweep, M&A due diligence, post-incident clean-bill, or breach-suspicion confirmation. The objective drives depth and which data sources matter most.
- [ ] **Write explicit hunt hypotheses** before touching data. Each ties to ATT&CK tactics, e.g. "an adversary maintains persistence via scheduled tasks on domain-joined servers" or "valid-account abuse exists in M365 via stolen session tokens." Track each hypothesis to a pass/fail conclusion.
- [ ] **Agree the time window** to hunt over (e.g. last 90 days) and reconcile it against actual log retention. Dwell time for many intrusions exceeds default retention; flag the gap as a finding.
- [ ] **Define what disproves a hypothesis** so "we found nothing" is a defensible conclusion, not satisficing. Record the coverage you achieved per host class.

### Environment and Access
- [ ] **Size the environment:** endpoint count, server count, DC count, domain/forest topology, cloud tenants (Entra, AWS, GCP), SaaS estate (M365, Okta, Salesforce). Sizing drives tool choice and timeline.
- [ ] **Secure read access** to EDR console, SIEM, AD/identity logs, cloud audit logs, and a deployment path for a hunting agent (Velociraptor) if endpoint collection is in scope.
- [ ] **Confirm the deployment model** for any hunting agent: standalone server vs offline triage collection. Get change-approval for agent rollout.
- [ ] **Obtain a network and asset map**, crown-jewel inventory, and a list of expected admin tooling (PsExec, AnyDesk, RMM agents) so legitimate dual-use tooling does not generate noise.

### Legal, Privacy, and Handling
- [ ] **Confirm authorization and data-handling rules** in writing. Endpoint and mailbox content is sensitive; agree scope, regions, and works-council / GDPR constraints before collecting.
- [ ] **Define evidence handling:** chain of custody, where collected artifacts are stored, encryption at rest, and retention/destruction after the engagement.
- [ ] **Agree finding handling:** who receives interim findings, classification markings, and the secure channel. Assume the adversary may be reading email; use out-of-band comms if active compromise is suspected.

### Active-Compromise Escalation Path
- [ ] **Pre-agree the IR escalation trigger and contacts** before hunting starts. Know who to call, day or night, the moment you confirm active adversary activity.
- [ ] **Define the "do-not-tip-off" posture.** Decide in advance whether to observe-and-report or contain on discovery; premature containment burns intel and warns the adversary.

```
⚠️ If you confirm an ACTIVE intrusion, switch out of hunt mode immediately.
Do not start remediating ad hoc. Preserve volatile evidence (memory, network
state), avoid alerting the adversary, and invoke the agreed IR escalation path.
Uncoordinated containment can trigger destruction (ransomware detonation, log wipe).
```

---

## 2. Data Source Inventory and Visibility

You can only hunt what you can see. Inventory telemetry first; visibility gaps are findings in their own right and bound every "clean" conclusion.

### EDR and Endpoint Coverage
- [ ] **Reconcile EDR install base against the asset inventory.** Hunt the gap: unmanaged hosts, decommissioned-but-live servers, and OT/IoT are where adversaries hide. A 95% deployment leaves 5% blind.
- [ ] **Verify EDR is actively reporting**, not just installed. Check for tamper events, stopped sensors, or hosts silent for N days (an EDR-killer / BYOVD precursor signal).
- [ ] **Confirm telemetry depth:** process creation with command line, parent-child lineage, module loads, named-pipe events, registry writes, and network connections. Thin telemetry limits which hypotheses you can test.

### Log Sources and Retention
- [ ] **Build a telemetry matrix** of every source, what it captures, and retention. Map each to the hunt hypotheses it can or cannot serve.

| Source | Key events to confirm present | Typical gap |
|---|---|---|
| Windows Security log | 4624/4625, 4672, 4688 (+cmdline), 4698, 4720, 4662 | 4688 cmdline often disabled; short retention |
| Sysmon | 1 (proc), 3 (net), 7 (image load), 8 (CreateRemoteThread), 11 (file), 13 (reg), 22 (DNS) | Not deployed; config too narrow |
| PowerShell | 4103 module, 4104 scriptblock | Scriptblock logging off |
| AD / DC | 4662 (DCSync), 5136 (ACL change), 4768/4769 (Kerberos) | 4662 noisy and unforwarded |
| Firewall / proxy | egress allow/deny, full URL, JA3/JA4 | No egress logging; SSL not inspected |
| DNS | full query logs | Not captured at resolver |
| Cloud (Entra/AWS/GCP) | sign-in + audit + CloudTrail/management | Data-plane events off by default |
| M365 Unified Audit Log | MailItemsAccessed, New-InboxRule, Add-Consent | UAL not enabled historically |

- [ ] **Confirm time synchronization** (NTP) across sources. Skewed clocks wreck timeline correlation.
- [ ] **Check log-source integrity:** gaps, suspicious clears (Security 1102, Sysmon service stop), and disabled auditing. A missing window is itself a defense-evasion indicator (ATT&CK T1070).

### Identity, Cloud, and Network Telemetry
- [ ] **Confirm identity logging** for every IdP in scope: Entra sign-in + audit logs, on-prem 4768/4769/4624, Okta system log, and any federated SSO.
- [ ] **Confirm cloud audit logging is on AND retained:** AWS CloudTrail (all regions + management and data events), Azure Activity + Entra diagnostic settings exported, GCP Cloud Audit Logs (Admin + Data Access).
- [ ] **Confirm network telemetry:** NetFlow/Zeek, full DNS logs, proxy/egress logs, and whether TLS is inspected. East-west visibility is usually the biggest blind spot; note it explicitly.
- [ ] **Record every visibility gap as a preliminary finding** with the hunt impact (e.g. "no DNS logging: DNS-tunneling C2 cannot be excluded").

---

## 3. Endpoint Hunting

Hunt persistence and execution where adversaries live longest. Sweep at scale with a hunting agent (Velociraptor) or KAPE triage collections, then parse with Sigma-based tooling. Stack-rank by rarity: the outlier across 10,000 hosts is the lead.

### Persistence Mechanisms (T1543, T1053, T1547, T1546)
- [ ] **Services (T1543.003):** hunt new/modified services, services with binaries in user-writable or temp paths, unsigned service binaries, and `svchost`-masquerading names. Cross-check Event ID 7045 and registry `CurrentControlSet\Services`.
- [ ] **Scheduled tasks (T1053.005):** enumerate all tasks; flag tasks created in the hunt window, tasks launching from temp/AppData, encoded-PowerShell actions, and hidden tasks missing an SD value in the registry. Correlate Event ID 4698.
- [ ] **Run keys and startup (T1547.001):** dump Run/RunOnce, Winlogon Shell/Userinit, Startup folders, and Active Setup. Flag references to LOLBins, scripts, or paths outside `Program Files`.
- [ ] **WMI event subscriptions (T1546.003):** enumerate `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding` in root\subscription. Any CommandLine/ActiveScript consumer is high-suspicion; this is a classic fileless persistence spot.
- [ ] **DLL search-order hijack and side-loading (T1574):** hunt unsigned or unexpected DLLs adjacent to signed binaries (e.g. a rogue `msimg32.dll` / `version.dll` beside a legit EXE), and phantom DLLs in writable PATH dirs.
- [ ] **COM hijack, IFEO debuggers, services-DLL, and AppInit/AppCert** (T1546.015, T1546.012): check `Image File Execution Options` Debugger values, AppInit_DLLs, and ServiceDll pointers in writable locations.
- [ ] **Boot/logon and screensaver/print-monitor/LSA** persistence: check LSA security/notification packages, print monitors, and netsh helper DLLs for unexpected entries.

```bash
# Velociraptor server-side hunt examples (run from the hunt console)
# Autoruns-style persistence sweep across the fleet:
#   Windows.Persistence.PermanentWMIEvents
#   Windows.System.Services
#   Windows.System.TaskScheduler
#   Windows.Sysinternals.Autoruns
# Anchor only; full VQL and KAPE targets live in the cheatsheet.
```

### Suspicious Processes and Execution (T1059, T1218)
- [ ] **LOLBin abuse (T1218):** hunt anomalous use of `rundll32`, `regsvr32`, `mshta`, `msbuild`, `installutil`, `certutil`, `bitsadmin`, `wmic`, and signed-binary proxy execution. Pivot on parent process and command line, not the binary name alone.
- [ ] **Suspicious lineage:** `winword/excel/outlook -> cmd/powershell/wscript`, `w3wp/services -> cmd`, `lsass` as a parent, and any `powershell -enc`/long base64. Office and webserver spawning shells is a top lead.
- [ ] **Unsigned / abnormally-located binaries:** flag executables running from `C:\Users\...\AppData`, `C:\ProgramData`, `\Temp`, `\PerfLogs`, or recycle bin. Verify Authenticode and compare hashes to known-good.
- [ ] **Masquerading (T1036):** processes named like system binaries but wrong path/parent/signer (`svch0st`, `lssas`, a `services.exe` outside System32).
- [ ] **In-memory / fileless implants:** hunt RWX private memory, unbacked executable regions, reflective-loaded modules, and process hollowing/injection. Use EDR memory telemetry or YARA-over-memory; Cobalt Strike, Sliver, and Brute Ratel default profiles are common.
- [ ] **Named pipes (T1572 / C2):** enumerate named pipes for known-bad and default-toolkit patterns (e.g. `\msagent_*`, `\postex_*`, GUID-like pipes). Correlate with the owning process.

### Execution and Access Artifacts
- [ ] **Recent-execution evidence:** parse Prefetch, Amcache/Shimcache, SRUM, UserAssist, BAM/DAM, and MUICache for first-seen-anywhere binaries in the hunt window.
- [ ] **Shellbags, RunMRU, and LNK/JumpLists:** reconstruct interactive activity and recent file access for suspected hosts.
- [ ] **Credential-access traces (T1003):** hunt LSASS-access patterns, `comsvcs.dll MiniDump`, procdump usage, SAM/SECURITY hive copies, and NTDS.dit access off the DC.
- [ ] **Defense evasion (T1562):** hunt EDR/AV service stops, Defender exclusion additions, AMSI patching, ETW tampering, and driver loads of known-vulnerable signed drivers (BYOVD). See Recent Techniques.
- [ ] **Staging and exfil prep:** large archives (`.7z`, `.rar`, `.zip`) in odd locations, `rar a -hp`, and rclone/MEGA/web-storage CLI artifacts.

### Forensic Triage Workflow
- [ ] **Collect triage images** with KAPE (targets for $MFT, registry, event logs, prefetch, browser) on suspected hosts; capture memory where in-memory implants are hypothesized.
- [ ] **Run Sigma over event logs** with Chainsaw (rapid hunt/search) and Hayabusa (timeline + detection summary) for fast first-pass triage at scale.
- [ ] **Build a per-host super-timeline** (Plaso/log2timeline) for confirmed leads to establish sequence and first-evidence-of.

---

## 4. Identity and Active Directory Hunting

Identity is the modern adversary's primary terrain. Hunt for credential abuse, ticket forgery, and AD object/ACL tampering. Forward DC Event ID 4662 centrally if not already.

### Anomalous Authentication (T1078, T1110)
- [ ] **Logon anomalies:** hunt 4624 type 3/10 from unexpected sources, service accounts with interactive logons, off-hours admin logons, and one-to-many auth fan-out (a single source authenticating to many hosts in minutes).
- [ ] **Brute force / spray (T1110):** cluster 4625 by source, account, and time. Low-and-slow spray shows as many accounts, one failure each, from one source.
- [ ] **Dormant and new accounts:** flag accounts created or re-enabled in the window, accounts with passwords set after long dormancy, and never-before-seen admin logons.

### Kerberos Abuse (T1558, T1550, T1208)
- [ ] **Kerberoasting (T1558.003):** hunt 4769 with RC4 (encryption type 0x17) for SPN-bearing accounts, especially bursts of TGS requests for many SPNs from one host.
- [ ] **AS-REP roasting (T1558.004):** hunt 4768 with pre-auth-not-required (accounts with `DONT_REQ_PREAUTH`). Enumerate which accounts carry that flag as a posture check.
- [ ] **Golden ticket (T1558.001):** hunt TGTs with anomalous lifetimes, logons with no preceding 4768, RC4 TGTs in an AES domain, and tickets referencing nonexistent or mismatched accounts.
- [ ] **Silver ticket (T1558.002):** service access (4769/service logons) with no corresponding TGT issuance and malformed PAC indicators.
- [ ] **Overpass-the-hash / PtH / PtT (T1550):** NTLM where Kerberos is expected, and ticket-injection patterns.

### Directory Object and ACL Abuse (T1207, T1484, T1222)
- [ ] **DCSync (T1003.006):** hunt Event ID 4662 with replication GUIDs (`DS-Replication-Get-Changes` / `-All`) by any principal that is not a DC or known sync account. This is the highest-fidelity domain-compromise signal.
- [ ] **New privileged accounts and group changes:** hunt 4728/4732/4756 (adds to Domain Admins, Enterprise Admins, built-in admins) and AdminSDHolder tampering.
- [ ] **ACL / object changes (T1222):** hunt 5136 for DACL writes granting DCSync, GenericAll, WriteDACL, or AddMember on sensitive objects.
- [ ] **GPO abuse (T1484.001):** hunt newly created/modified GPOs, especially those adding scheduled tasks, scripts, or local-admin membership. Review SYSVOL for rogue scripts.
- [ ] **Shadow credentials (T1556):** hunt writes to `msDS-KeyCredentialLink` on user/computer objects (Whisker-style key-based persistence). Anomalous writes to this attribute are high-suspicion.

### ADCS Misuse (Certificate Persistence)
- [ ] **Certificate-based persistence and theft:** hunt CA issuance events (4886/4887) for certificates with arbitrary SANs, requests for accounts other than the requester, and enrollment by unexpected principals.
- [ ] **ESC abuse signals:** misconfigured templates allowing SAN specification (ESC1), agent/enrollee abuse, NTLM relay to web enrollment (ESC8), and Golden Certificate (ESC5, stolen CA key). Certificates survive krbtgt resets, so treat any rogue issuance as a durable re-entry mechanism.
- [ ] **Enumerate template/CA posture** with Certify/Certipy as a hunting aid to know which ESC paths are even possible before declaring identity clean.

> For attacker-side mechanics and command detail, cross-reference [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md) and the [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md) cheatsheet.

---

## 5. Network Hunting

Hunt for command-and-control and lateral movement in flow, DNS, and proxy data. Beaconing and rare-egress analysis find C2 that endpoint controls missed.

### Command and Control (T1071, T1573, T1572)
- [ ] **Beaconing detection:** hunt periodic connections with low jitter to a single destination. Score by regularity of inter-arrival time, consistent payload size, and long-lived low-volume sessions. RITA / Zeek connection analysis is the standard approach.
- [ ] **Rare external destinations:** stack-rank outbound destinations by rarity across the fleet; a single host talking to a never-before-seen ASN/domain is a lead.
- [ ] **Suspicious TLS:** hunt self-signed certs, default Cobalt Strike/Sliver cert traits, anomalous JA3/JA4 client fingerprints, and SNI/host mismatch (domain fronting).
- [ ] **DNS tunneling (T1071.004):** hunt high query volume to one domain, long/encoded subdomain labels, high entropy, unusual record types (TXT/NULL), and high NXDOMAIN rates.
- [ ] **Non-standard ports and protocol mismatch:** TLS on odd ports, HTTP on 8443, and C2-over-DoH/DoT to public resolvers.

### Egress and Exfiltration (T1041, T1567, T1048)
- [ ] **Anomalous egress volume:** hunt large outbound transfers, especially to cloud storage (MEGA, Dropbox, S3), paste sites, and file-transfer services. Correlate with on-host archiving from Phase 3.
- [ ] **C2 over web services (T1102):** hunt traffic to legitimate platforms abused for C2 (Telegram, Discord, Slack, GitHub, Pastebin, cloud functions).

### Lateral Movement (T1021, T1570)
- [ ] **SMB lateral (T1021.002):** hunt admin-share access (`ADMIN$`, `C$`, `IPC$`) followed by service creation (PsExec-style 7045 + 4624 type 3), and one-host-to-many SMB fan-out.
- [ ] **Remote WMI/WinRM (T1021.006):** hunt `wmiprvse.exe` spawning shells and WinRM (5985/5986) from non-admin hosts.
- [ ] **RDP (T1021.001):** hunt 4624 type 10 chains, RDP from internal pivots, and 4778/4779 session reconnects. Map the RDP graph to spot a pivot host.
- [ ] **East-west anomalies:** workstation-to-workstation traffic, unexpected DC-bound admin protocol from non-admin segments, and tooling transfer (T1570) over SMB.

> Egress and C2 detail pairs with [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md) for understanding the attacker tradecraft you are hunting.

---

## 6. Cloud and M365 Hunting

Cloud identity compromise often leaves no endpoint trace. Hunt audit and sign-in logs for token theft, illicit consent, and post-ATO persistence. Confirm the M365 Unified Audit Log is enabled before concluding anything is clean.

### Sign-in and Token Abuse (T1078.004, T1528, T1550.004)
- [ ] **Risky and impossible-travel sign-ins:** hunt Entra sign-in logs for impossible travel, anonymizer/VPN/Tor sources, and atypical-location alerts. Triage Identity Protection risk detections.
- [ ] **Token theft / AiTM session hijack:** hunt sign-ins reusing a session without fresh MFA, anomalous device/browser for an established session, and Okta/Entra sessions whose user-agent or device-enrollment markers do not match the enrolled browser. AiTM (Evilginx-style) steals the post-MFA session cookie, so MFA-satisfied does not mean trusted.
- [ ] **Legacy auth and MFA gaps:** hunt successful logons over legacy protocols (no MFA possible) and recently disabled/modified Conditional Access or MFA registration (new authenticator added by attacker).

### Application and Consent Abuse (T1098.003, T1136.003)
- [ ] **Illicit OAuth consent grants:** hunt `Consent to application` / `Add OAuth2PermissionGrant` audit events. Flag grants to rare/unverified apps requesting broad scopes (`Mail.ReadWrite`, `.default`, `offline_access`, `full_access_as_user`). Consented apps retain access independent of password resets.
- [ ] **New app registrations and service-principal credentials:** hunt `Add application`, `Add service principal`, and especially `Add service principal credential` / `Update application - Certificates and secrets`. A new client secret on an existing SP is a stealthy backdoor.
- [ ] **Role and directory changes:** hunt additions to Global Admin / Privileged Role Admin, new owners on apps/SPs, and Conditional Access policy edits.

### Mailbox and Collaboration Persistence (T1114, T1564.008)
- [ ] **Mailbox forwarding and inbox rules:** hunt `New-InboxRule`, `Set-InboxRule`, and `Set-Mailbox` enabling `ForwardingSmtpAddress` / external auto-forward. Flag rules with nonsensical names (`.`, `...`, `;`) and actions that delete or move to RSS/Archive to hide replies, a classic post-ATO tell.
- [ ] **Mailbox access anomalies (T1114.002):** hunt `MailItemsAccessed` and `Add-MailboxPermission` / delegate grants from unusual IPs, plus mass-read patterns indicating collection.
- [ ] **Sharing and exfil:** hunt anomalous SharePoint/OneDrive mass downloads, external-sharing link creation, and Teams data access spikes.

### IaaS Audit Anomalies (AWS / Azure / GCP)
- [ ] **AWS CloudTrail:** hunt `CreateUser`/`CreateAccessKey` for existing identities, `AttachUserPolicy`/`PutUserPolicy` privilege grants, `ConsoleLogin` without MFA, `GetSecretValue`/`Decrypt` spikes, and `StopLogging`/`DeleteTrail` (defense evasion). Hunt new keys on service identities.
- [ ] **Azure activity:** hunt RBAC role assignments (especially Owner/Contributor at subscription scope), new SP credentials, Key Vault access spikes, and runbook/automation-account abuse.
- [ ] **GCP audit:** hunt service-account key creation, IAM policy `setIamPolicy` grants, and impersonation (`generateAccessToken`).
- [ ] **Cross-cloud persistence:** hunt federation/trust changes, new identity-provider config, and seldom-used-region resource creation (cryptomining or staging).

> Hunt against the same surface the attacker checklist [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md) and the [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md) / [AWS Pentest](../Cheatsheets/AWS%20Pentest.md) cheatsheets describe.

---

## 7. Threat Intelligence and IOC Sweep

Pivot from behavior-led hunting to intel-led sweeping. IOC matching catches known campaigns fast but misses novel tradecraft, so run it alongside, not instead of, behavioral hunts.

- [ ] **Hash sweep:** match running and on-disk binaries against known-bad hashes and your EDR/TI feeds. Sweep Amcache/Shimcache for historic-execution hashes too.
- [ ] **Domain/IP sweep:** match DNS, proxy, and flow logs against current C2 and malware-infrastructure feeds. Watch for stale indicators producing false positives.
- [ ] **YARA sweep:** run curated YARA over disk and memory across the fleet (Velociraptor `Windows.Detection.Yara.*`, THOR/Loki) for implant families, webshells, and packers. Tune to avoid alerting on legit packed software.
- [ ] **Sigma sweep:** run a current Sigma ruleset over collected event logs via Chainsaw/Hayabusa for known technique signatures. Prefer behavior rules over brittle string IOCs.
- [ ] **Webshell hunt:** scan web roots for recently-modified scripts, eval/exec patterns, and known-webshell signatures on internet-facing servers.
- [ ] **Recent-CVE exploitation artifacts:** for exposed assets (VPN, gateway, mail, file-transfer, WSUS), hunt for post-exploitation traces of recently weaponized CVEs: dropped tools, child processes of the appliance/service account, and config tampering. An n-day exploited edge device is a top initial-access vector.
- [ ] **Map every hit to a host and timeline.** An IOC match is a lead, not a conclusion; pivot back to behavioral evidence to confirm and scope.

---

## 8. Triage, Validation, and Reporting

Convert leads into validated findings, scope the compromise, and hand off cleanly. Discipline here separates a credible assessment from a pile of low-confidence alerts.

### Validate and Eliminate False Positives
- [ ] **Confirm true positives with multiple independent signals.** One artifact is a lead; corroborate across endpoint, identity, and network before calling it compromise.
- [ ] **Rule out benign explanations:** sanctioned admin/RMM tools, pentest/red-team activity, vulnerability scanners, backup jobs, and legitimate developer behavior. Check the expected-tooling list from scoping.
- [ ] **Assign confidence** (confirmed / suspected / informational) to every lead and state the evidence behind it.

### Scope and Timeline
- [ ] **Scope the blast radius:** enumerate every affected host, account, and cloud identity. Pivot from each confirmed indicator outward (shared C2, shared credential, lateral path).
- [ ] **Build the master timeline:** earliest evidence of compromise, initial access vector, persistence established, lateral movement, and any exfiltration. Note evidence-of-absence boundaries (log retention) explicitly.
- [ ] **Estimate dwell time** (first evidence to detection). Caveat it against retention: "at least N days; earliest activity may predate available logs."
- [ ] **Determine objective and impact:** ransomware staging, data theft, espionage persistence, or BEC/financial. State what evidence supports the assessment.

### Containment and Handoff
- [ ] **Provide prioritized containment recommendations** mapped to confirmed findings: isolate hosts, revoke sessions/tokens, reset krbtgt (twice) and affected credentials, remove illicit consents/SP secrets, and block C2.
- [ ] **Hand off to IR cleanly** if active: deliver indicators, timeline, scoped asset/account list, and preserved evidence. Recommend rebuild over clean for kernel-level / BYOVD or domain-controller compromise.
- [ ] **Deliver hardening and visibility recommendations** tied to the gaps found: close the logging blind spots, enable missing auditing (4688 cmdline, scriptblock, UAL), and add detections for the techniques you hunted.
- [ ] **State the clean-bill caveat honestly:** "no evidence of compromise within the assessed scope and available telemetry." Never overstate certainty beyond your visibility.

---

## Recent Techniques (2024-2026)

- [ ] **BYOVD EDR killers at scale (T1562.001):** 50+ EDR-killer tools abuse 35+ signed vulnerable drivers; Qilin/Warlock side-load a rogue `msimg32.dll` capable of terminating 300+ EDR drivers. Hunt for: known-vulnerable driver loads (Event 6/Sysmon 6), driver writes to non-standard paths, EDR sensor going silent, and DLL side-load lineage. Reynolds and DeadLock ransomware (2025-2026) use the same pattern.
- [ ] **AiTM / Evilginx session-cookie theft (T1539/T1550.004):** post-MFA session tokens proxied to attacker infra. Test for: Entra/Okta sessions whose user-agent or device-enrollment markers do not match the enrolled browser, session reuse without fresh MFA, and sign-ins from AiTM phishing infrastructure.
- [ ] **Scattered Spider identity intrusions (CISA AA23-320A, updated Jul 2025):** helpdesk social engineering, SIM swap, self-service MFA reset, then DragonForce ransomware and Snowflake/cloud DB targeting. Hunt for: attacker-added MFA methods, helpdesk-driven password resets followed by new-device sign-in, and rapid cloud-to-on-prem pivot.
- [ ] **Velociraptor abused offensively (CVE-2025-6264, CVE-2025-59287 WSUS chain):** threat actors deploy outdated Velociraptor for C2/persistence. Hunt for: unexpected Velociraptor binaries/services on hosts that are not part of your DFIR rollout, and rogue collection clients.
- [ ] **ADCS ESC9-ESC16 and Golden Certificate (ESC5):** Certipy v5 expanded the cert-abuse surface. Hunt for: rogue CA issuance with arbitrary SANs (4886/4887), enrollment for other principals, and certificate-based logons that survive krbtgt resets.
- [ ] **Shadow credentials (msDS-KeyCredentialLink, T1556):** Whisker/key-based stealth persistence. Hunt for: writes to `msDS-KeyCredentialLink` (5136) on accounts that should not have key credentials.
- [ ] **Illicit OAuth consent + SP-credential backdoors (T1098.003):** rare-app broad-scope consent and new client secrets on existing service principals. Hunt for: `Add OAuth2PermissionGrant` to unverified apps and `Add service principal credential` events.
- [ ] **Stealthy inbox-rule persistence:** ~10% of compromised M365 accounts (Q4 2025) had malicious rules with nonsensical names (`.`, `...`, `;`) that delete or hide replies. Test for: `New-InboxRule` with single-char names and delete/move-to-RSS actions.
- [ ] **n-day edge-device exploitation:** internet-facing VPN/gateway/file-transfer/WSUS CVEs weaponized within days. Hunt for: appliance service accounts spawning shells, dropped tooling, and config tampering on exposed assets.

---

## Reporting and Evidence

### Evidence to Capture per Finding
- [ ] **Artifact provenance:** host/identity, source log/tool, exact timestamps (UTC), and the raw event or file hash. Preserve original evidence with chain of custody.
- [ ] **Reproducible query:** the VQL/Sigma/KQL/SPL that surfaced the lead, so the client SOC can re-run and operationalize it.
- [ ] **Corroboration:** the independent signals that confirm the finding, and the timeline position.
- [ ] **Triaged status:** confirmed / suspected / benign, with the evidence behind the call.

### Severity Guidance

| Severity | Criteria |
|---|---|
| Critical | Active intrusion confirmed: live C2, domain compromise (DCSync/golden ticket), ransomware staging, or active data exfiltration |
| High | Confirmed historic compromise or durable persistence (cert/SP backdoor, shadow creds) with unclear eradication |
| Medium | Strong suspicion needing more data, or a material visibility gap that prevents excluding compromise |
| Low | Hygiene/posture weaknesses (legacy auth, missing logging) with no compromise evidence |
| Info | Hunt coverage notes, ruled-out leads, and recommendations |

### Common False Positives to Rule Out
- [ ] **Sanctioned dual-use tooling:** PsExec, AnyDesk/TeamViewer, RMM agents, and admin scripts mistaken for lateral movement.
- [ ] **Security tooling:** the client's own EDR, vuln scanners, and prior pentest/red-team activity firing IOC matches.
- [ ] **Legitimate automation:** backup jobs, deployment pipelines, and scheduled maintenance resembling persistence or beaconing.
- [ ] **Cloud noise:** Microsoft/cloud first-party service principals, normal impossible-travel from VPN/mobile roaming, and benign OAuth grants to verified apps.
- [ ] **Stale intel:** expired IOCs and recycled IP space producing phantom matches.

---

## Tools and References

| Category | Tools / References |
|---|---|
| Fleet hunting | Velociraptor (VQL artifacts, fleet YARA/Sigma), EDR console hunt |
| Triage collection | KAPE (targets + modules), velociraptor offline collector |
| Event-log hunting | Chainsaw (rapid Sigma search), Hayabusa (Sigma timeline + summary), EvtxECmd |
| Detection rules | Sigma (incl. v2 correlation), Sigma HQ ruleset, hayabusa-rules |
| Memory / signatures | YARA, THOR/Loki, Volatility |
| Timeline | Plaso / log2timeline, Zimmerman tools (Amcache, Shimcache, Prefetch, Shellbags) |
| Network | Zeek, RITA (beaconing), Arkime, Suricata, JA3/JA4 |
| Identity / cloud | BloodHound (AD attack paths), Certipy/Certify (ADCS posture), Microsoft-Extractor-Suite, AzureHound, ROADtools, Hawk (M365), CloudTrail/Activity log analytics |
| Frameworks | MITRE ATT&CK, MITRE D3FEND, PEAK/TaHiTI hunting loop, NIST SP 800-61 (IR), CISA AA23-320A (Scattered Spider) |

---

## Related

- Playbooks (offensive chains to hunt for): [DCSync to Golden Ticket Persistence](../Playbooks/DCSync%20to%20Golden%20Ticket%20Persistence.md), [Azure AiTM Token Theft to Global Admin](../Playbooks/Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md), [Poisoned CI Pipeline to Cloud Admin](../Playbooks/Poisoned%20CI%20Pipeline%20to%20Cloud%20Admin.md), [Coercion to ADCS ESC8 to Domain Admin](../Playbooks/Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md)
- [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md)
- [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md)
- [Red Team Operation](Red%20Team%20Operation.md)
- [Assumed Breach](Assumed%20Breach.md)
- [Email Security](Email%20Security.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
- [AWS Pentest](../Cheatsheets/AWS%20Pentest.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
