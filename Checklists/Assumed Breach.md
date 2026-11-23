---
tags:
  - hack-notes
  - checklist
  - active-directory
  - internal
---

# Assumed Breach Testing Checklist

> Use when the engagement starts the tester from an already-compromised position (a standard domain user account, a managed workstation/VDI, or an assumed-foothold host). The question is not "can we get in" but "what does a phished user lead to": measure blast radius and detection from that foothold to crown jewels. Distinct from a full red team: no initial-access campaign and no evasion-heavy entry phase, though detection telemetry is measured throughout.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Host Situational Awareness](#2-host-situational-awareness)
- [3. Local Privilege Escalation](#3-local-privilege-escalation)
- [4. Credentialed Domain Recon](#4-credentialed-domain-recon)
- [5. Credential Access and Harvesting](#5-credential-access-and-harvesting)
- [6. Lateral Movement](#6-lateral-movement)
- [7. Privilege Escalation to Domain](#7-privilege-escalation-to-domain)
- [8. Objective and Crown-Jewel Access](#8-objective-and-crown-jewel-access)
- [9. Detection and Response Measurement](#9-detection-and-response-measurement)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Nail the starting position and the rules before touching anything. Assumed breach lives or dies on a precise definition of the foothold and what "compromise" means for this client.

### Starting position
- [ ] **Confirm the foothold type:** which of these is provided, and capture it in writing: standard AD user credentials (username, password or hash), a managed/golden-image workstation, a VDI/Citrix session, or a pre-staged implant on an assumed-foothold host.
- [ ] **Record the privilege baseline of the starting identity:** confirm the supplied account is a *standard* user (not pre-seeded local admin, not a service account) so escalation findings are attributable. `whoami /groups`, `net user <u> /domain`.
- [ ] **Get the build representativeness:** is the workstation the real corporate gold image with production EDR, GPO, and AppLocker/WDAC applied, or a lab clone? A clone undercuts the detection story; flag it.
- [ ] **Confirm network placement:** is the host on the production user VLAN with normal egress and DC reachability, or a segmented test segment? Blast radius depends on this.

### Objectives and crown jewels
- [ ] **Define crown jewels explicitly with the client:** name the systems, data, or business functions that constitute "game over" (DA, Enterprise Admin, specific app/DB, finance/HR data, code-signing, cloud tenant admin). Vague objectives produce vague findings.
- [ ] **Set the success criteria per objective:** what proof is acceptable (read a marked file, screenshot a record, dump a hash) without taking destructive or irreversible action.
- [ ] **Define blast-radius questions to answer:** from this one phished user, how many hosts, how many credentials, which trust boundaries, and which crown jewels become reachable. This is the headline deliverable.

### Rules of engagement
- [ ] **Detection-in-scope vs stealth:** agree whether this is detection-measured (SOC watches, telemetry is a deliverable) or stealth-graded (avoid detection as a goal). The two demand different tradecraft and reporting.
- [ ] **Set the noise budget:** confirm whether loud techniques (LSASS dump, Kerberoast at scale, coercion) are permitted, and whether the SOC is blinded or aware.
- [ ] **Establish deconfliction:** a real-time channel (signal/phone) and a tester source-IP/host list so live alerts can be attributed to the test, not a real intrusion. Agree the "stand down" word.
- [ ] **Confirm out-of-scope and no-go systems:** production DCs you may read but not alter, OT/ICS, medical, anything with a change-freeze.
- [ ] **Agree handling of found credentials and data:** storage, encryption at rest, and destruction at end of engagement. Do not exfiltrate real PII; use markers.
- [ ] **Authorization in writing:** signed scope covering the starting host, the user account, the domain(s), and any cloud tenant in scope before any action.

```
⚠️ Assumed breach is loud by design. Coercion (PetitPotam/Coerce), NTLM relay, mass
Kerberoasting, and LSASS access can disrupt production auth, lock accounts, or trip
account-based DoS. Get explicit sign-off per technique and keep deconfliction open.
```

---

## 2. Host Situational Awareness

Orient on the assumed workstation before acting. Everything downstream (what escalates, what gets logged, what you can run) is shaped by host posture. Read first, write little.

### Identity and context
- [ ] **Enumerate the current token:** `whoami /all` for user SID, groups, and privileges. Flag any sensitive privilege already held (SeImpersonate, SeBackup, SeDebug, SeLoadDriver).
- [ ] **Check local admin membership:** are you already a local admin on this box? `net localgroup administrators`. If yes, note it as a baseline finding, not an escalation.
- [ ] **List logged-on and recently logged-on users:** `query user`, `quser`, and cached profiles under `C:\Users`. High-value if a privileged user has a session or saved creds here.

### OS, patch, and defenses
- [ ] **OS build and patch level:** `systeminfo`, OS version, last hotfix dates. Map to known LPE CVEs (PrintNightmare-era, CVE-2025-33073 SMB client, etc.).
- [ ] **Identify EDR/AV present and posture:** product, version, and whether tamper protection is on. Enumerate by service/driver/process (e.g. CrowdStrike, Defender for Endpoint MDE, SentinelOne, Carbon Black). Note this drives tooling choice for the rest of the test.
- [ ] **Defender specifics if present:** `Get-MpComputerStatus`, ASR rule state, AMSI status, cloud-delivered protection, tamper protection.
- [ ] **Application control:** detect AppLocker and/or WDAC policy and enforcement mode. `Get-AppLockerPolicy -Effective`, check `HKLM\...\SrpV2` and WDAC CI policies. Identify allowed paths and LOLBins not blocked.
- [ ] **PowerShell constraints:** language mode (`$ExecutionContext.SessionState.LanguageMode`), script-block/transcription logging, JEA. Constrained Language Mode changes your tradecraft.

### Policy and reach
- [ ] **Dump applied GPOs:** `gpresult /h gp.html` (or `/r`) for applied policies, restricted groups, LAPS, scripts, and security settings that hint at the broader estate.
- [ ] **Proxy and egress:** system proxy (`netsh winhttp show proxy`), PAC file, DNS servers, and whether direct internet egress exists. Determines C2/exfil viability and external-tooling reach.
- [ ] **Mounted drives and shares:** `net use`, mapped drives, and any auto-mounted DFS/home/share. Home-drive and departmental shares are early loot.
- [ ] **Installed software and agents:** management agents (SCCM/Intune, PDQ, automation), backup agents, vaults/password managers, browsers. Each is a future pivot or loot source.
- [ ] **Scheduled tasks and services running as privileged accounts:** `schtasks /query /fo LIST /v`, `sc query`, services with non-system run-as. Note any cleartext creds in task config.
- [ ] **Network position quick map:** local subnet, default gateway, DC IPs (`nltest /dsgetdc:`, `echo %LOGONSERVER%`), and reachable internal ranges for later recon.

---

## 3. Local Privilege Escalation

Goal: SYSTEM or local admin on the assumed workstation, which unlocks LSASS, DPAPI master keys, and stored creds for other users. Run the structured methodology in the linked cheatsheets; this is the assumed-breach-relevant ordering.

- [ ] **Run an automated triage pass:** winPEAS / Seatbelt / PrivescCheck (or LinPEAS on Linux), but tuned to the EDR present. Treat output as leads, validate manually.
- [ ] **Token privilege abuse:** if SeImpersonate/SeAssignPrimaryToken is held (common on web/SQL service contexts), use a Potato-family technique to reach SYSTEM. High-value and often quiet.
- [ ] **Service misconfig:** unquoted service paths, weak service binary/registry ACLs, modifiable service config, DLL hijack in a writable PATH dir.
- [ ] **Scheduled task and startup abuse:** writable task binaries or autoruns executing as a privileged user.
- [ ] **Credentials at rest on host:** unattend.xml/sysprep, registry autologon, saved RDP/VNC, `cmdkey /list`, Credential Manager, scripts in shares, GPP cpassword in SYSVOL cache.
- [ ] **Kernel/driver LPE:** map the patch level to a known LPE; prefer a vetted exploit and only with sign-off (crash risk). BYOVD only if explicitly authorized.
- [ ] **UAC bypass** where a medium-integrity admin is the start state and SYSTEM is needed.
- [ ] **Linux foothold path** if the assumed host is Linux: sudo rules, SUID, capabilities, cron, writable units, container/escape. See cheatsheet.
- [ ] **Validate and screenshot the new context:** `whoami` showing SYSTEM/root with a marker, plus timestamp, before proceeding.
- See [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md) and [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md) for full command detail.

---

## 4. Credentialed Domain Recon

You already hold valid domain creds, so enumerate the directory from the user context (the realistic phished-user view). This phase finds the path; do not authenticate to targets yet beyond read.

### Map the directory
- [ ] **Collect BloodHound data from the user context:** SharpHound/RustHound/the Python collector with the supplied account. Capture sessions, ACLs, group memberships, GPO links, trusts, and certificate data. This is the central artifact for path-finding and blast-radius.
- [ ] **Mark the owned principal in BloodHound** and run shortest-path-to-DA and shortest-path-to-crown-jewel queries from it. Record every path for the report, not just the first.
- [ ] **Enumerate domain basics:** users, groups, computers, OUs, password policy, and trusts. `nltest /domain_trusts`, RSAT/PowerView/NetExec LDAP queries.
- [ ] **Find privileged groups and their members:** Domain Admins, Enterprise Admins, Backup Operators, Account Operators, DnsAdmins, server-local admin nesting via Restricted Groups/LAPS.

### Find weaknesses from current creds
- [ ] **Kerberoastable accounts:** enumerate SPNs (do not necessarily crack yet; that is phase 5). Note service accounts in privileged groups (high-value roast targets).
- [ ] **AS-REP roastable accounts:** users with pre-auth disabled.
- [ ] **Delegation:** unconstrained delegation hosts, constrained delegation (and protocol transition), and resource-based constrained delegation (RBCD) write targets. Each is a potential DA path.
- [ ] **AD CS posture:** enumerate the PKI. Certipy `find` for vulnerable templates and CA settings (ESC1-ESC16). A single ESC1/ESC8 often shortcuts to DA. See phase 7.
- [ ] **Dangerous ACLs from the owned principal:** GenericAll/GenericWrite/WriteDACL/WriteOwner/AddMember/ForceChangePassword over users, groups, computers, GPOs, or OUs. BloodHound surfaces these as edges.
- [ ] **GPO abuse candidates:** GPOs you can edit that apply to privileged hosts/users.
- [ ] **MAQ and OU CreateChild:** machine-account-quota (default 10) for RBCD/computer-creation paths, and CreateChild on OUs (feeds BadSuccessor, phase 7).

### Share and data hunting
- [ ] **Hunt shares estate-wide:** NetExec spider / Snaffler for readable shares, then for secrets in them: scripts, configs, `*.kdbx`, `*.config`, web.config connection strings, `unattend*`, `*.ps1`, password spreadsheets, private keys.
- [ ] **SYSVOL/NETLOGON:** cached GPP passwords, logon scripts with creds, mapped-drive scripts.
- [ ] **Map readable file servers and home directories** for crown-jewel-adjacent data and additional credential material.
- See [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md) and [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md) for full enumeration commands.

---

## 5. Credential Access and Harvesting

With local admin/SYSTEM (phase 3) and directory knowledge (phase 4), harvest credentials to widen the path. This is the loudest phase against modern EDR; sequence by noise and value, and capture what fired for the detection report.

### On-host secrets (requires admin/SYSTEM)
- [ ] **LSASS credentials:** extract logon secrets (cleartext where present, NTLM hashes, Kerberos tickets). On EDR-monitored hosts prefer lower-signature methods over a raw minidump (e.g. handle-duplication, comsvcs is heavily signatured, parse an offline dump on the tester box). Record exactly which method tripped EDR.
- [ ] **SAM and LSA secrets:** local account hashes, cached domain logons (DCC2), service-account secrets, autologon. `reg save HKLM\SAM/SECURITY/SYSTEM` then parse offline.
- [ ] **DPAPI:** harvest master keys and decrypt protected blobs (saved browser/Wi-Fi/RDP/vault secrets). With SYSTEM you can pull the backup key from the DC to decrypt any user's DPAPI domain-wide.
- [ ] **Kerberos tickets:** harvest TGTs/TGSs from memory for Pass-the-Ticket; note any privileged session tickets present.

### User-data secrets
- [ ] **Browser credentials and cookies:** extract saved passwords and, crucially, session cookies/tokens. App-Bound Encryption on modern Chrome requires in-user-context decryption; note the technique used. Cookies enable MFA-bypassing cloud pivot (phase 8).
- [ ] **Password managers and vaults:** KeePass `.kdbx` (and the CVE-2023-32784 memory-dump master-key recovery where applicable), browser-integrated managers, and any enterprise vault agent on the host.
- [ ] **Credential files and config:** `cmdkey`/Credential Manager, `.aws/credentials`, `.azure`, kube configs, SSH keys, `.git-credentials`, RDP `.rdp` with saved creds, scripts with embedded secrets.
- [ ] **Cloud and SaaS tokens on host:** Azure/Entra PRT (primary refresh token) and tokens for AAD-joined/hybrid devices, MSAL token caches, CLI tokens. These bridge on-prem to cloud (phase 8).

### Validate and expand
- [ ] **Spray and validate harvested creds carefully** against the domain, respecting lockout policy (low-and-slow, account-aware). NetExec with `--continue-on-success` only after checking the policy.
- [ ] **Crack roastable hashes offline** (Kerberoast/AS-REP) and feed cracked service-account creds back into path-finding.
- [ ] **Record each credential's source host, account, and privilege** so the report can show the harvesting chain and blast radius.
- See [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md) for dumping and validation commands.

---

## 6. Lateral Movement

Pick the *best* path from current creds toward the objective, not every path. Validate the BloodHound route, move with the quietest technique that works, and log telemetry.

- [ ] **Re-query BloodHound with all owned principals marked** (owned set grows after phase 5). Re-run shortest path to the objective and choose the route with fewest hops and least noise.
- [ ] **Confirm where current creds are local admin:** NetExec sweep across the estate to find boxes you can already access with harvested creds/hashes (the practical blast-radius map).
- [ ] **Move with the appropriate primitive:**
  - [ ] **Pass-the-Hash / Pass-the-Ticket** for NTLM hash or Kerberos ticket reuse.
  - [ ] **Overpass-the-Hash** to mint a TGT from a hash.
  - [ ] **Remote exec:** WMI, WinRM, SMB (psexec-style), DCOM, scheduled tasks. Prefer WMI/WinRM over service-creation on EDR-watched hosts.
  - [ ] **RDP** where session theft or saved creds allow, including RDP-cookie/cookie-token reuse.
- [ ] **Chain via harvested sessions:** if a privileged user is logged into a reachable host, target that host to steal their token/ticket (the classic "phished user shares a box with an admin" pivot).
- [ ] **Pivot networks where needed:** set up tunneling/SOCKS to reach segmented servers, the DC tier, or admin jump hosts. Respect segmentation findings from phase 2.
- [ ] **Track every hop:** for each lateral move record source, destination, credential used, technique, timestamp, and whether it alerted. This is the spine of the blast-radius narrative.
- [ ] **Stop at the proven primitive:** demonstrate access, do not pile on destructive actions to "prove" more than the controls already allow.
- See [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md) for tunneling and proxy setup.

```
⚠️ Lateral movement touches production auth and can lock accounts or crash services
(e.g. service-creation exec on a fragile host). Confirm the technique noise budget and
keep deconfliction live, especially before any DC-tier action.
```

---

## 7. Privilege Escalation to Domain

Convert the path into Domain Admin / Enterprise Admin (or the crown-jewel-equivalent privilege). Pick the cleanest of the available domain-escalation primitives surfaced in phase 4.

### Kerberos and delegation
- [ ] **Unconstrained delegation:** if you control such a host, coerce a DC or high-value computer to authenticate to it and capture its TGT.
- [ ] **Constrained delegation / protocol transition:** abuse S4U2Self/S4U2Proxy to impersonate a privileged user to allowed SPNs.
- [ ] **RBCD:** with write over a target computer object (and MAQ available), configure resource-based delegation and impersonate an admin to that host.

### AD CS escalation
- [ ] **ESC1 / ESC2 / ESC3:** enrollee-supplies-subject or overbroad EKU templates: request a cert as a privileged user, then authenticate (PKINIT) or extract the NTLM hash via UnPAC-the-hash.
- [ ] **ESC4:** template ACL write: reconfigure a template into an ESC1 condition, then exploit.
- [ ] **ESC8:** relay NTLM auth (from coercion) to the CA web-enrollment HTTP endpoint to obtain a DC/admin cert.
- [ ] **ESC9 / ESC10 / ESC13 / ESC15 (EKUwu)** where present: weak mapping, no-security-extension, issuance-policy-to-group, and V1-schema application-policy injection. See Recent Techniques.

### ACL, GPO, and coercion+relay
- [ ] **DACL abuse to DA:** WriteDACL/Owner/GenericAll over a privileged group or user → add yourself / reset password / grant DCSync rights.
- [ ] **DCSync:** once you hold replication rights (DS-Replication-Get-Changes-All), pull the KRBTGT and any account's hash for golden-ticket and full domain compromise. This is typically the "game over" proof.
- [ ] **GPO abuse:** edit a GPO you control that applies to the DC tier or a privileged OU to gain code execution as a privileged context.
- [ ] **Coercion + relay:** PetitPotam/PrinterBug/Coerce to force a DC or server to authenticate, relayed to LDAP (set RBCD) or AD CS (ESC8). Pair with CVE-2025-33073 where SMB-client reflection applies.
- [ ] **Prove the privilege without irreversible change:** demonstrate DCSync or a DA-context action against a marked object; do not create persistent backdoors or alter KRBTGT unless explicitly authorized.
- See [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md) for delegation, ADCS, and DCSync command detail.

---

## 8. Objective and Crown-Jewel Access

Translate domain or path-level privilege into the business impact defined in scope. Findings here are what the client actually cares about; tie each back to "a phished user reached this".

- [ ] **Access the named crown jewels:** read/screenshot the in-scope data set or system with a marker, using the minimum action that proves access.
- [ ] **Application and database access:** reach the in-scope app/DB using harvested or escalated creds (SQL via integrated auth, app admin via group membership). Read a marked record; do not exfiltrate real data.
- [ ] **File-server and document repositories:** access finance/HR/IP shares or SharePoint sites reachable from the escalated identity.
- [ ] **Backup and infrastructure tier:** demonstrate reach to backup systems, hypervisors, or management planes (a common "ransomware-equivalent" blast-radius proof).
- [ ] **On-prem to cloud pivot:** use harvested PRT/refresh tokens or browser session cookies (phase 5) to access the Entra/AAD tenant, M365, or other SaaS, demonstrating MFA bypass via stolen session material. Pivot to cloud admin where the identity allows.
- [ ] **Email and collaboration:** demonstrate mailbox or Teams/SharePoint access from a compromised cloud identity if in scope.
- [ ] **Quantify blast radius explicitly:** from the single phished user, enumerate hosts reachable, credentials obtained, privileged groups compromised, crown jewels accessed, and trust boundaries crossed. Produce the count and the map.
- [ ] **Do not run destructive impact** (encryption, deletion, real exfil); describe the demonstrated capability and stop.
- See [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md) for the cloud-pivot phase detail.

---

## 9. Detection and Response Measurement

The differentiator of assumed breach: measure what the defenders saw. This is co-produced with the SOC in a detection-in-scope engagement and is often the most valuable deliverable.

- [ ] **Reconcile your action log against SOC telemetry:** for each significant action (LSASS access, Kerberoast, lateral move, DCSync, coercion), record whether it generated telemetry, an alert, or a response.
- [ ] **Compute time-to-detect and time-to-respond** per noisy action where the SOC was watching: first telemetry timestamp, first alert, first analyst action, first containment.
- [ ] **Identify detection gaps:** actions that produced *no* telemetry or alert. These are the highest-value defensive findings.
- [ ] **Map every action to MITRE ATT&CK** technique IDs so the client can drive detection-engineering coverage (e.g. T1003 LSASS, T1558.003 Kerberoasting, T1550 use of alternate auth material, T1207 DCSync, T1649 cert theft).
- [ ] **Note which EDR/control caught what** and which were bypassed, to inform tuning (ASR rules, LSASS protection, app-control gaps).
- [ ] **Pair findings with detection logic:** for each gap, suggest a concrete detection (Sigma rule, log source to enable, alert to build). This converts the test into a purple-team uplift.
- [ ] **Run a wash-up / purple-team replay** if scoped: walk the SOC through the timeline, replay key actions live so they can validate new detections.
- [ ] **Produce the coverage matrix:** technique × (telemetry? alert? blocked? detected-in-time?) so the client sees coverage at a glance.

---

## Recent Techniques (2024-2026)

- [ ] **BadSuccessor (dMSA abuse, CVE-2025-53779):** Windows Server 2025 dMSA migration abuse. With CreateChild on an OU (or write over a dMSA), set `msDS-ManagedAccountPrecededByLink` and `msDS-DelegatedMSAState` to inherit any account's privileges, including DA. **Test for:** any 2025 DCs present, then enumerate non-DA principals holding CreateChild on OUs / write over dMSA objects (BloodHound and the Akamai checker).
- [ ] **CVE-2025-33073 (SMB-client NTLM reflection):** coerce a host to authenticate, relay its own Kerberos/NTLM back to itself via a marshalled DNS name that Windows mis-resolves as local, yielding SYSTEM. Patched June 2025. **Test for:** unpatched (pre-June-2025) servers reachable for coercion; combine with PetitPotam-style triggers.
- [ ] **ADCS ESC15 / EKUwu (CVE-2024-49019):** inject arbitrary application policies (e.g. Client Auth, Certificate Request Agent) into certs issued from V1-schema templates on unpatched CAs. **Test for:** Certipy `find` flagging schema-V1 templates with enrollee-supplied subject on an unpatched CA.
- [ ] **ADCS ESC9-ESC16 (Certipy v5):** weak certificate mapping (ESC9/ESC10), issuance-policy-to-group linkage (ESC13), and the newer ESC14-ESC16 mapping/extension abuses. **Test for:** run a current Certipy `find -vulnerable` and triage each flagged template/CA.
- [ ] **Browser session-cookie / token theft for MFA-bypass cloud pivot:** with user-context access, decrypt App-Bound-Encrypted Chrome cookies and steal live session tokens; replay to reach M365/SaaS without re-auth or MFA. **Test for:** valid session cookies in the foothold user's browser profile; attempt authenticated cloud access with the stolen cookie.
- [ ] **Entra PRT / refresh-token theft on hybrid-joined hosts:** extract the primary refresh token from an AAD-joined device to mint tokens into the cloud tenant. **Test for:** device join state (`dsregcmd /status`) and a reachable PRT; pivot to Graph/Azure.
- [ ] **EDR-aware credential access:** modern EDR scores LSASS access and signatures comsvcs/minidump heavily; current tradecraft favors handle-duplication, indirect syscalls, or offline-parsed dumps, and operating inside the user's behavioral baseline. **Test for:** dump method that does not alert, and confirm with the SOC which signal fired.
- [ ] **KeePass master-key memory recovery (CVE-2023-32784):** recover most of a KeePass master password from a process/memory dump on older builds. **Test for:** KeePass < 2.54 in memory on the foothold or a reachable host.
- [ ] **Detection-engineering pairing as a deliverable:** every offensive action mapped to ATT&CK with a paired Sigma/detection suggestion and a time-to-detect figure, increasingly expected as the assumed-breach output rather than a flat finding list.

---

## Reporting and Evidence

### Evidence to capture per finding
- [ ] **Per action:** command/technique, source host, target, credential/identity used, timestamp (and timezone), and a marker in any output so screenshots are attributable to the test.
- [ ] **The escalation chain:** a linked sequence from phished-user foothold → each pivot → crown jewel, so impact is traceable, not asserted.
- [ ] **Blast-radius artifacts:** the BloodHound path graphs, the count of reachable hosts/creds/groups, and the crown-jewels accessed.
- [ ] **Detection artifacts:** for each noisy action, the telemetry/alert it produced (or did not), time-to-detect, ATT&CK ID, and the paired detection suggestion.
- [ ] **Credential handling:** redact real secrets in the report; store the working set encrypted and confirm destruction at close.

### Severity guidance
| Outcome from the assumed foothold | Typical severity |
| --- | --- |
| Full domain compromise (DCSync/DA) reachable from a standard user | Critical |
| Crown-jewel data/system accessed from a standard user | Critical/High |
| Local admin/SYSTEM on the workstation + broad credential harvest | High |
| Cloud-tenant pivot via stolen session/PRT with MFA bypass | High |
| Lateral movement to additional hosts without escalation to DA | Medium/High |
| Notable detection gap on a high-signal action (e.g. DCSync unalerted) | High (defensive) |

### False positives to rule out
- [ ] **Pre-seeded privilege:** confirm the starting account was genuinely standard; an over-privileged test account inflates findings.
- [ ] **Lab-clone build:** detection gaps on a non-production image are not real gaps. Validate the build represents production EDR/GPO.
- [ ] **Stale BloodHound data:** sessions and ACLs change; re-collect before claiming a path is live, and validate the path end-to-end.
- [ ] **Validated, not asserted:** every escalation and crown-jewel claim must be demonstrated, not inferred from an ACL alone.
- [ ] **Lockout-policy artifacts:** a "failed spray" may be lockout, not invalid creds; check the policy.

---

## Tools and References

| Area | Tools |
| --- | --- |
| Directory mapping | BloodHound (+ SharpHound/RustHound/bloodhound-python), PingCastle, PowerView |
| Credentialed enum / exec | NetExec, Impacket, ldapsearch, RSAT |
| Host triage | winPEAS, Seatbelt, PrivescCheck, LinPEAS |
| Credential access | Mimikatz/equivalents, secretsdump, DonPAPI, SharpDPAPI, Snaffler |
| AD CS | Certipy (v5), Certify |
| Kerberos / delegation | Rubeus, Impacket (getST, ntlmrelayx), Kerberoast tooling |
| Coercion / relay | Coercer/PetitPotam, ntlmrelayx |
| Path synthesis | Ariadne for attack-path graphing from correlated findings |
| Detection mapping | MITRE ATT&CK Navigator, Sigma |

- MITRE ATT&CK (Enterprise) for technique mapping and the detection coverage matrix.
- SpecterOps AD CS whitepaper (ESC1-ESC8) and Certipy wiki (ESC9-ESC16) for the certificate attack surface.
- Akamai BadSuccessor research and checker for dMSA abuse enumeration.
- OWASP / NIST framing for the report; client crown-jewel definition is the authoritative scope.

---

## Related

- Playbooks: [Kerberoasting to Domain Admin](../Playbooks/Kerberoasting%20to%20Domain%20Admin.md), [Coercion to ADCS ESC8 to Domain Admin](../Playbooks/Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md), [badSuccessor dMSA to Domain Admin](../Playbooks/badSuccessor%20dMSA%20to%20Domain%20Admin.md), [DCSync to Golden Ticket Persistence](../Playbooks/DCSync%20to%20Golden%20Ticket%20Persistence.md)
- [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md)
- [Red Team Operation](Red%20Team%20Operation.md)
- [Build Review and VDI](Build%20Review%20and%20VDI.md)
- [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md)
- [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
- Ariadne

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
