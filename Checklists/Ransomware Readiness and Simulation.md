---
tags:
  - hack-notes
  - checklist
  - ransomware
---

# Ransomware Readiness and Simulation Checklist

> Two jobs in one checklist: a readiness review that walks the ransomware kill chain control by control, and a safe simulation that emulates the crews' TTPs without ever encrypting real client data. Simulation touches marked test files only, with benign markers and canaries. Backup resilience is the headline, not the encryptor: a shop that detects nothing but restores cleanly survives, a shop that alerts on everything but cannot restore does not. Command detail lives in the linked cheatsheets; this is the ordered method, the pass/fail signal, and the evidence to bank.

## Table of Contents
- [1. Scoping and Safety](#1-scoping-and-safety)
- [2. Initial Access Readiness](#2-initial-access-readiness)
- [3. Identity and Privilege Exposure](#3-identity-and-privilege-exposure)
- [4. Lateral Movement Readiness](#4-lateral-movement-readiness)
- [5. Credential Access Resilience](#5-credential-access-resilience)
- [6. Defense Evasion Exposure](#6-defense-evasion-exposure)
- [7. Backup and Recovery](#7-backup-and-recovery)
- [8. Data Exfiltration Readiness](#8-data-exfiltration-readiness)
- [9. Detection and Response](#9-detection-and-response)
- [10. Safe Simulation Execution](#10-safe-simulation-execution)
- [11. Tabletop and IR](#11-tabletop-and-ir)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Scoping and Safety

Decide what this engagement actually is before anyone touches a keyboard. A readiness review reads config and asks questions. An active simulation fires benign TTPs on live infrastructure. A tabletop never leaves the conference room. They carry different blast radius and different consent, and conflating them is how a "test" becomes an outage.

### Engagement model
- [ ] **Pick the mode in writing:** readiness/controls review (evidence and config, no payloads), active safe simulation (benign TTP emulation on live hosts), or tabletop (discussion only). Most mature programs want all three in sequence. Record which one each activity belongs to.
- [ ] **Set the objective:** validate backup recoverability, measure time-to-detect for destructive precursors, prove or disprove a path from a phished user to the backup repository, or exercise the IR plan. The objective sets the stop condition.
- [ ] **Confirm detection posture:** is the SOC told (purple/announced) or is this blind? Shadow-copy deletion and mass-file-touch tests are loud by design. Announced is usually right for a first run, so the point is measuring detection, not evading it.
- [ ] **Get scope in writing:** in-scope hosts, segments, the specific test-file paths simulation may touch, and a named out-of-scope list (production file servers holding real data, DCs, ESXi hosts carrying prod VMs unless explicitly included).

### The hard rule
```
⚠️ NEVER RUN REAL ENCRYPTION AGAINST CLIENT DATA.
No production encryptor, no real crypto over real files, not "just one share to prove it".
Simulation operates ONLY on pre-created, clearly-marked test files in a pre-agreed test
directory. The "encryptor" writes a benign marker (a known byte string or renames to a
harmless .test-locked suffix) and is fully and trivially reversible. If a step cannot be
made reversible on marked test files alone, it does not run in this engagement. One real
file encrypted is an incident you caused and a client you lost.
```

### Emulation boundaries and test data
- [ ] **Stage marked test files first:** create a dedicated directory tree of obviously-fake files (a recognizable name prefix, a header line identifying them as simulation artifacts) before any simulation step. The "encryption" step must only ever enumerate inside that tree.
- [ ] **Confirm reversibility:** every destructive-looking action (file marker write, shadow-copy test, service stop) has a documented undo, run and verified on a throwaway host before it runs anywhere that matters.
- [ ] **Deconfliction channel:** a live channel to the SOC/IR lead so a simulated alert is not escalated as a real breach. Agree a code phrase and a way to prove an alert belongs to the test.
- [ ] **Out-of-hours window:** schedule loud or disruptive steps (EDR tamper tests, service stops, shadow-copy deletion attempts) outside business hours with a named technical contact and an abort signal. Capture a clean baseline (running services, backup job status, shadow copies present) before you start so you can prove you changed nothing lasting.

### Scope guardrails
- [ ] **Exclude fragile systems:** name and exclude ICS/SCADA, medical and lab devices, legacy embedded hosts, and any production hypervisor carrying live VMs unless explicitly in scope. A simulated service stop on the wrong host is a real outage.
- [ ] **Agree the destructive-action boundary:** no real encryption, no deleting production shadow copies or catalogs (test those on expendable VMs only), no disabling production EDR, no persistence that survives the engagement. Write the line down and both sides sign it.
- [ ] **Define evidence handling:** where simulation output, screenshots, and any credential material captured during a live test are stored, encrypted at rest, and destroyed at close. Treat anything resembling real data as off-limits to copy.

---

## 2. Initial Access Readiness

The crews are not clever about the front door. Phishing, an exposed RDP or a vulnerable edge appliance, and reused or unprotected remote-access credentials account for most entries. Review the vectors that actually get used, not the exotic ones.

### Phishing resistance
- [ ] **Mail controls:** confirm SPF, DKIM, and a DMARC policy at `p=reject` (not `p=none`), plus attachment/macro sandboxing and link rewriting. A `p=none` record is monitoring, not protection.
- [ ] **Macro and payload execution:** confirm Office macros from the internet are blocked by policy (Mark-of-the-Web enforced), and that common payload carriers (ISO, IMG, LNK, OneNote, HTA, script hosts) are restricted. These are the current delivery containers.
- [ ] **Web and browser-delivered lures:** confirm protections against malvertising, fake-update ("ClickFix" / fake CAPTCHA paste) lures, and SEO-poisoned downloads. The inbox is not the only delivery path anymore.
- [ ] **User reporting path:** a one-click report button that lands in a monitored queue, and a measured median report time. The fastest ransomware control is a user who reports the lure before clicking. See [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md).
- [ ] **Callback and voice-phish resistance:** confirm the help desk verifies identity before resetting credentials or MFA. The current access-broker move is a phone call to the help desk, not an email, and a help desk that resets MFA on request is the hole.

### Exposed remote access
- [ ] **Internet-facing RDP:** scan the external range for 3389 (and NAT'd variants). Any directly-exposed RDP is a finding; crews buy and brute these daily. MFA-fronted VDI or a gateway is the expectation.
- [ ] **VPN and edge appliances:** inventory the VPN, firewall, and gateway devices (the SSL-VPN / remote-access product lines are repeat ransomware entry points) and confirm each is patched to a current fixed build, not "latest in the console". Verify the version at the appliance, not the vendor page.
- [ ] **MFA on all remote access:** confirm MFA on VPN, RDP gateway, webmail, and every externally reachable admin surface. One un-MFA'd remote path is the one they find. Phishing-resistant factors (FIDO2) beat push, which beats SMS.
- [ ] **MFA fatigue and legacy-auth gaps:** confirm push-bombing protections (number matching) and that legacy/basic auth protocols which bypass MFA are disabled. An enforced MFA policy with a legacy-auth exception is not enforced.
- [ ] **External attack surface:** enumerate exposed services (RDP, SMB, RADIUS, management consoles, backup appliance web UIs, hypervisor management). A backup console or ESXi host reachable from the internet is critical on its own. See [External Network Penetration Test](External%20Network%20Penetration%20Test.md).

### Patch and known-exploited exposure
- [ ] **Known-exploited vulns on the edge:** cross-check exposed edge devices and public-facing apps against CISA's Known Exploited Vulnerabilities catalog. The crews weaponize edge-appliance bugs within days of disclosure; an unpatched KEV entry on an internet-facing device is a live entry vector, not a theoretical one.
- [ ] **Patch cadence for internet-facing systems:** confirm a defined, fast SLA for edge and public-facing patches, distinct from the general estate cadence. "Patched monthly" is too slow for the devices crews target first.
- [ ] **Patched at the running version, not the console claim:** confirm the fixed build is the one actually running on the appliance, not the version the management page reports or the one the vendor marks latest. Verify at the artifact.
- [ ] **Third-party and supply-chain access:** inventory MSP/RMM tooling, remote-support agents, and vendor VPNs with standing access. Compromise of an RMM is a repeat ransomware entry path that bypasses the whole front door. Confirm each has MFA and is monitored.
- [ ] **Unauthorized RMM detection:** confirm detection for remote-access tools the crews bring themselves (AnyDesk, ScreenConnect, Atera, and similar) appearing where they do not belong. A second RMM installing itself is an intrusion signal, and an allow-listing approach beats chasing names.

---

## 3. Identity and Privilege Exposure

Once inside, the crew needs privilege, and they take the same escalation paths a normal AD pentest does. This phase is a focused read of the escalation surface that ransomware operators actually walk. Full method in [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md).

### Tiering and privileged accounts
- [ ] **Tier-0 separation:** confirm Domain Admin and other Tier-0 accounts do not log on to workstations or servers where they expose credentials. A DA that touches a user workstation hands the keys to whoever owns that box.
- [ ] **Privileged account sprawl:** count the members of Domain Admins, Enterprise Admins, Backup Operators, and local Administrators across the estate. Oversized privileged groups widen the blast radius of a single compromise. Flag stale and service accounts sitting in Tier-0.
- [ ] **Separate admin identities:** confirm admins use a distinct privileged account for admin work, not their day-to-day user. Shared day/admin identities collapse tiering.
- [ ] **Privileged access workstations:** confirm Tier-0 admin happens from hardened, dedicated jump hosts, not from internet-browsing endpoints. A DA that administers from the same laptop that opens email collapses the whole tier model.
- [ ] **Standing vs just-in-time admin:** confirm privileged access is time-bound (PAM/JIT) rather than permanent membership. Standing DA rights are a bigger target than rights that exist for an hour.

### Credential-exposure escalation paths
- [ ] **Password policy and weak-password rate:** confirm a modern policy (length over complexity, breached-password rejection) and sample the real crack rate against a captured hash set. The policy on paper and the passwords in use are rarely the same thing.
- [ ] **Kerberoasting exposure:** enumerate service accounts with SPNs, especially any in privileged groups with weak or non-rotated passwords. A kerberoastable DA-equivalent is a straight line to domain control. See [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md).
- [ ] **AS-REP roasting exposure:** list accounts with Kerberos pre-auth disabled. Each is an offline-crackable hash for the asking.
- [ ] **LAPS coverage:** confirm a local-admin password solution (LAPS/Windows LAPS) is deployed estate-wide and read rights are tightly scoped. Without it, one cracked local-admin hash often unlocks every workstation (the classic lateral path).
- [ ] **Service-account hygiene:** confirm service accounts are least-privilege, use managed/gMSA where possible, and are not reused as local admin across hosts. A reused service account is a pre-built lateral highway.

### Delegation and ACL surface
- [ ] **Unconstrained and constrained delegation:** enumerate delegation on hosts and accounts. Unconstrained delegation on a non-DC is a straight path to a domain-controller ticket if the crew can coerce auth to it.
- [ ] **Dangerous ACLs to high-value objects:** hunt GenericAll/WriteDACL/ForceChangePassword edges toward privileged groups and Tier-0 accounts (BloodHound, read-only). These are the escalation edges operators buy pre-mapped.
- [ ] **Stale and dormant privileged accounts:** flag enabled admin accounts with no recent logon. A forgotten DA with a weak password is the quiet win.
- [ ] **GPO edit rights and linked scope:** enumerate who can edit GPOs linked to privileged OUs. An editable GPO over a server OU is code execution across every host it touches, exactly the fan-out an operator wants before encrypting.

---

## 4. Lateral Movement Readiness

The decisive question is how far a single compromised workstation can reach, and whether it can reach the backup and server networks at all. Flat networks are why one phished laptop becomes a whole-estate encryption event.

### Lateral paths
- [ ] **SMB/RDP/WinRM reachability:** from a representative user VLAN, map which server and workstation ports (445, 3389, 5985) are reachable. Workstation-to-workstation SMB is rarely needed and is the worm path; confirm host firewalls block it.
- [ ] **Segmentation to server and backup networks:** confirm a user-segment host cannot reach backup infrastructure, hypervisor management, or domain controllers except through controlled, authenticated paths. A user VLAN with a clear route to the backup repo is a critical finding by itself.
- [ ] **Admin-protocol exposure:** confirm management protocols (WinRM, RDP, SMB admin shares) to servers are restricted to admin jump hosts, not open from any user endpoint.
- [ ] **DC and Tier-0 reachability:** confirm domain controllers accept admin protocols only from designated admin tiers, not from the general workstation VLAN. A DC reachable for SMB exec from any desktop is a short path to domain-wide encryption.
- [ ] **East-west visibility:** confirm there is network visibility between segments (not just at the perimeter) so lateral SMB/RDP sweeps are observable. A flat internal network with no east-west monitoring is a blind spot the crew depends on.

### EDR coverage on the path
- [ ] **Agent coverage gaps:** reconcile the EDR/AV console against the asset inventory and AD computer objects. The uncovered host (an old file server, an appliance, a hypervisor, a forgotten VM) is where the crew lands and stages. Count the gap; do not eyeball it.
- [ ] **Server and hypervisor coverage:** confirm servers, and ESXi/Linux hosts where supported, carry protection or compensating monitoring. Encryptors increasingly run on the hypervisor, below the Windows agents entirely.
- [ ] **Sensor health, not just presence:** confirm agents are reporting and healthy, not installed-but-stale. A silent sensor is an uncovered host that shows green in the asset count.

```bash
# Coverage reconciliation anchor: AD computers vs EDR-enrolled hosts
# (anchor only; full tooling in cheatsheet) -- the DIFFERENCE is the finding
comm -23 <(sort ad_computers.txt) <(sort edr_enrolled.txt)
```

---

## 5. Credential Access Resilience

Mass encryption needs domain-wide credentials, and the crews get them out of memory and local stores the same way every pentest does. This phase checks whether the easy credential dumps are closed off.

### Memory and in-process secrets
- [ ] **LSASS protection:** confirm LSASS runs as a protected process (RunAsPPL) and/or Credential Guard is enabled on supported hosts. Without it, a local-admin foothold dumps domain creds from memory in seconds.
- [ ] **Credential Guard coverage:** confirm Credential Guard is actually on where the hardware supports it, not merely licensed. Check the running state on sampled hosts, not the GPO alone.
### Stored and cached secrets
- [ ] **Cached credentials:** confirm cached interactive logons are limited and that privileged accounts are not cached on general-population machines. Cached DA creds on a laptop are crackable offline.
- [ ] **DPAPI and stored secrets:** confirm browsers, credential managers, and scripts are not leaving reusable secrets a foothold can decrypt. Hunt for plaintext creds in shares, scripts, and scheduled tasks (the GPP `cpassword` class of mistake).
- [ ] **Local admin password reuse:** confirm the local Administrator password is unique per host (LAPS again, from the other side). A single shared local-admin hash plus SMB is the textbook ransomware spread.
- [ ] **Protected Users and auth policies:** confirm Tier-0 accounts are in the Protected Users group (no NTLM, no cached creds, no unconstrained delegation) and, where available, bound by authentication policy silos. This shrinks what a dumped privileged credential can do.
- [ ] **Autologon and plaintext stores:** confirm no autologon registry secrets, no plaintext credentials in scheduled tasks, scripts, or the LSA secrets a service account left behind. These are harvested before any cracking is needed.
- [ ] **Backup and service passwords in the open:** confirm backup, hypervisor, and service-account passwords are not sitting in shares, wikis, or password-protected spreadsheets a foothold can read. A plaintext backup-admin password in a share hands over the one system that decides the outcome.

---

## 6. Defense Evasion Exposure

Before they encrypt, the crews try to blind the defenders. The modern move is not disabling AV from the GUI; it is killing the EDR from the kernel with a vulnerable signed driver, or rebooting into safe mode where the agent does not load. Test whether those work here.

- [ ] **Uninstall and recovery password:** confirm the EDR requires a separate, protected password or token to uninstall, and that the account used for deployment is not a general local admin. Self-service uninstall is self-service blinding.
- [ ] **EDR tamper protection:** confirm tamper protection is on and that a local admin cannot stop, uninstall, or unload the sensor from user space. A sensor a local admin can `sc stop` is decoration.
- [ ] **BYOVD exposure:** confirm the vulnerable-driver blocklist (Microsoft's driver blocklist / HVCI with the blocklist enforced) is enabled so known-abusable signed drivers cannot load. BYOVD is how current EDR-killers (the AuKill/EDRKillShifter class of tooling) neutralize sensors. Do not fabricate a driver CVE; confirm the blocklist state and test with a benign known-blocked driver only.
- [ ] **Safe-mode boot abuse:** confirm the EDR either starts in safe mode or that safe-mode boot is restricted, because booting to safe mode to run the encryptor without the agent is an established technique.
- [ ] **AV exclusion abuse:** review AV/EDR exclusion lists. Over-broad path exclusions (whole drives, user-writable directories) are a staging ground an attacker will drop into. An exclusion for `C:\` is a finding.
- [ ] **Script and LOLBin controls:** confirm PowerShell logging (script block + module), constrained language mode where feasible, and application control (WDAC/AppLocker) on servers. The encryptor and its stagers lean on living-off-the-land binaries.
- [ ] **Log-clearing and anti-forensics:** confirm clearing the Windows event logs (`wevtutil cl`, event ID 1102) and disabling logging are alerted and that logs are already shipped off-host. Crews clear logs to slow the responders who come after.
- [ ] **Firewall and recovery-config tamper:** confirm disabling the host firewall, deleting restore points, and turning off Windows Defender via `Set-MpPreference` raise alerts. Each is a staging move that precedes the encryptor.

```powershell
# Shadow-copy deletion detection test (anchor only; full tooling in cheatsheet).
# Run on an EXPENDABLE test VM. The point is whether the SOC sees it, not to destroy data.
vssadmin delete shadows /all /quiet   # EXPECT: EDR/SIEM alert fires; verify it did
```

---

## 7. Backup and Recovery

This is the phase that decides the outcome. A shop that detects nothing but can restore from a clean, offline, immutable copy survives a ransomware event as an outage. A shop with perfect telemetry and online-only backups reachable from a domain admin account pays or dies. Weight the scorecard accordingly.

### Architecture
- [ ] **3-2-1 (or 3-2-1-1-0):** confirm three copies, on two media types, one off-site, one offline/immutable, zero errors on the last verified restore. Count the copies that actually exist, not the ones the policy describes.
- [ ] **Offline copy that is actually offline:** confirm the air-gapped copy is disconnected except during its backup window, not merely on a different server that is online 24/7. A second online copy is redundancy against disk failure, not against an attacker.
- [ ] **Immutability and air-gap:** confirm at least one copy is genuinely immutable (object-lock/WORM) or physically offline. Then test the claim: if a backup admin or a domain admin can shorten the retention lock, delete the object, or disable immutability from a console, it is not immutable. Immutable that an admin can delete is not immutable.
- [ ] **Backup account separation:** confirm the backup system authenticates with accounts that are NOT members of the production domain's privileged groups, ideally in a separate identity domain or workgroup. If a compromised production domain admin can log into the backup console, the backups die with the domain.
- [ ] **Reachability from a compromised account:** this is the single most important test in the engagement. From the position of a compromised domain admin (on paper in a readiness review, or via a safely-scoped access check in a live test), determine whether the backup repository, its management plane, and its storage can be reached, authenticated to, and deleted. A reachable, mutable, online backup from a prod domain account is critical.
- [ ] **Backup network segmentation:** confirm the backup infrastructure sits in its own segment with tightly controlled, authenticated paths in and out, not on the general server VLAN. Backups on the same flat network as production die with it.

### Recoverability (the part everyone skips)
- [ ] **Restore actually tested:** confirm a real restore has been performed and verified within a recent, defined interval, not merely that jobs report success. A backup you have not restored is a hope, not a backup.
- [ ] **Full-system / bare-metal restore:** confirm the plan covers rebuilding domain controllers and critical servers from scratch, including a tested AD forest recovery runbook. Restoring files onto a still-compromised domain is not recovery.
- [ ] **Documented RTO/RPO:** confirm recovery time and recovery point objectives exist, are approved by the business, and that the last restore test actually met them. An RTO nobody has measured against a real restore is a number on a slide.
- [ ] **Recovery capacity vs full-estate loss:** confirm the restore infrastructure can rebuild the whole estate in the RTO, not one server at a time. Recovering 500 systems serially when the plan assumed parallel is how a 24-hour RTO becomes a two-week one.
- [ ] **Clean-room rebuild path:** confirm there is isolated, known-good infrastructure to restore into so recovery does not happen on the compromised network. Restoring into the same environment the attacker still holds just re-infects the clean copy.
- [ ] **Backup catalog and infrastructure protection:** confirm the backup catalog, config, and the backup server itself are also backed up and protected. Crews specifically target the backup catalog and the `vssadmin`/`wbadmin`/`bcdedit` recovery surfaces to foreclose recovery before encrypting.

### Cloud and SaaS backups
- [ ] **SaaS data coverage:** confirm M365/Google Workspace mailboxes, SharePoint/OneDrive, and other SaaS stores have an independent backup. Native recycle bins and retention are not backup; an attacker with admin can purge them.
- [ ] **Cloud snapshot immutability:** confirm cloud volume snapshots and object-storage backups use retention locks and are protected from deletion by the same credentials that run production. Stolen cloud admin keys delete unprotected snapshots in one API call.
- [ ] **Backup MFA and console exposure:** confirm the backup and cloud-backup consoles enforce MFA and are not reachable from the production network or the internet. The backup web UI is a primary target.
- [ ] **Backup integrity and scanning:** confirm restored data is scanned for the dormant malware or backdoor that may have been backed up alongside it. Restoring a clean-looking copy that carries the implant just restarts the clock.

```
⚠️ Validate backups on an ISOLATED restore target, never by restoring over live production
data during a test. A "restore test" that overwrites the only good copy is its own disaster.
```

---

## 8. Data Exfiltration Readiness

Double extortion is now the default: the crew steals the data before encrypting, then threatens to leak it whether or not you restore. A clean backup does not solve exfiltration. There is a window between first compromise and encryption where gigabytes leave the building, and the question is whether anything sees it.

### Egress visibility
- [ ] **Egress monitoring:** confirm outbound traffic is monitored and that large or anomalous transfers to cloud storage, paste sites, and file-transfer services (the `rclone`/`MEGAcmd`/`FileZilla` exfil pattern) raise an alert. Most shops watch inbound and ignore outbound.
- [ ] **DLP coverage:** confirm DLP (or equivalent content inspection) covers the crown-jewel data stores and the egress paths, not just email. Note what it does not cover.
- [ ] **TLS-inspected egress or endpoint DLP:** confirm exfil over HTTPS is visible either through inspection or endpoint-side DLP. Blind TLS egress means the exfil is invisible on the wire by default.
- [ ] **Large-transfer and cloud-sync detection:** confirm a detection exists for a single host moving an abnormal volume off a file server, or syncing a share to a personal cloud account. This is the exfil fingerprint before encryption.
### Staging and data awareness
- [ ] **Staging detection:** confirm there is visibility into the pre-exfil staging step (mass read/archive of a file server into a single RAR/7z/zip). The archive-then-upload sequence is detectable if anyone is looking.
- [ ] **Egress chokepoints:** confirm outbound is constrained to known destinations where feasible, so exfil to arbitrary internet hosts is not trivially allowed from a file server. A file server with unrestricted outbound is an exfil launch pad.
- [ ] **Tunneling and C2 egress:** confirm detection of DNS tunneling, HTTPS beaconing, and traffic to anonymizing infrastructure. Exfil and C2 often ride the same covert channel; blindness to one is blindness to both.
- [ ] **Crown-jewel locality:** confirm the most sensitive stores are known, inventoried, and monitored specifically. You cannot detect abnormal egress from data you have not located. An unmapped sensitive share is an unmonitored one.
- [ ] **Data minimization:** confirm retention and cleanup actually remove stale sensitive data. What was deleted on schedule cannot be exfiltrated; the oldest unneeded archive is often the one that ends up on the leak site.

---

## 9. Detection and Response

The destructive precursors are noisy and specific. Shadow-copy deletion, backup-catalog tampering, `bcdedit` recovery disabling, and a sudden spike of file renames with high entropy are not normal admin activity. Measure whether each one alerts, and how fast.

### Ransomware-specific detections
- [ ] **Mass file rename / entropy spike:** confirm a detection for a single account or process renaming or rewriting files across a share at machine speed with an entropy jump. This is the encryptor's own signature. Test it (phase 10) rather than assuming the EDR ships it tuned.
- [ ] **Shadow-copy deletion:** confirm `vssadmin delete shadows`, `wmic shadowcopy delete`, and VSS tampering fire a high-priority alert. This is a near-universal ransomware precursor and should be a tuned, tested rule, not a buried log line.
- [ ] **Backup-catalog and boot-config tampering:** confirm `wbadmin delete catalog`, `bcdedit /set recoveryenabled no`, `bcdedit /set bootstatuspolicy ignoreallfailures`, and WMI/PowerShell backup deletion are alerted. These exist only to foreclose recovery.
- [ ] **EDR canaries / honeypot files:** confirm canary files or a ransomware-canary capability is deployed on key shares so a touch of the bait fires immediately. A canary on the file server that nobody wired to an alert is not a control.
- [ ] **Automated containment on detection:** confirm the shadow-copy-deletion and mass-encryption detections can trigger automatic host isolation, not just a ticket. Minutes matter once the encryptor is live; a human-in-the-loop that takes an hour loses the estate.
- [ ] **Service and defense tamper alerts:** confirm stopping security services, clearing the Windows event log (`wevtutil cl`, event ID 1102), and disabling Defender raise alerts.
- [ ] **New-service and scheduled-task creation:** confirm remote service creation and new scheduled tasks (the common exec and persistence channels) are logged and alerted on servers. The encryptor often arrives as a freshly-created service.
- [ ] **Ransom-note and extension signals:** confirm a detection for the appearance of ransom-note files (readme/recovery text dropped across directories) and bulk unknown-extension creation. These are late signals, but they should still fire for scope confirmation.

### Response readiness
- [ ] **SOC runbook exists:** confirm there is a written, current ransomware playbook the on-call analyst can execute (isolate, preserve, escalate), not just general IR guidance.
- [ ] **Isolation capability:** confirm hosts can be network-isolated fast (EDR containment or NAC) and that the SOC has actually used it. Time this in the simulation.
- [ ] **Kill-switch for spread:** confirm there is a rehearsed way to halt propagation fast (disable the spreading account, block SMB between segments, pull a VLAN) without taking the whole business dark by reflex. The decision to pull the plug needs an owner and a threshold set in advance.
- [ ] **Evidence preservation:** confirm the runbook preserves forensic evidence (memory, logs, a sample of encrypted files and the ransom note) before wiping and rebuilding. Rebuilding first destroys the data that proves scope and entry.
- [ ] **MTTD/MTTR baseline:** capture current mean time to detect and respond for the destructive precursors. Time-to-detect on shadow-copy deletion is the metric that predicts whether recovery is even possible.
- [ ] **24/7 coverage reality:** confirm there is genuine round-the-clock monitoring (in-house or MSSP) with an escalation path that wakes a human, not a queue read on Monday. Crews pick the hours nobody is on.

### Logging and visibility
- [ ] **Log retention and reach:** confirm security logs ship off-host to a SIEM the attacker cannot reach or clear, with retention long enough to reconstruct the dwell time (crews sit for days to weeks). Local-only logs get wiped with the host.
- [ ] **Coverage of the quiet precursors:** confirm visibility into the slow, early steps (discovery, net share enumeration, credential access) and not only the loud finale. By the time the encryptor runs, detection is damage control.
- [ ] **After-hours alerting:** confirm high-priority ransomware alerts reach a human out of hours. Most encryption events are deliberately timed for a weekend or holiday night when nobody is watching.

---

## 10. Safe Simulation Execution

Now emulate the chain with benign tooling and watch what lights up. Every step here runs against marked test files and expendable test hosts only. The deliverable from this phase is a list of which stages alerted, which were silent, and how fast.

```
⚠️ Re-read the phase 1 rule before every step: the "encryptor" writes a benign marker to
pre-staged TEST files in the agreed test directory and nothing else. Never point any
simulation step at a path containing real data, even to "prove" the detection works.
```

### Chain emulation
- [ ] **Map TTPs to a framework:** drive the simulation from Atomic Red Team tests or a MITRE Caldera adversary profile mapped to ATT&CK, so each step is a named, documented, reversible technique with a known undo. Record the technique ID per step.
- [ ] **Benign marker "encryptor":** run a reversible routine that enumerates ONLY the staged test directory and renames/marks those files (for example appends a `.sim-locked` suffix and a known header). Confirm it refuses to run outside the test tree, then confirm the mass-rename/entropy detection fired and how fast.
- [ ] **Shadow-copy deletion test:** on an expendable test VM, run `vssadmin delete shadows` and confirm the SOC alert fires. The objective is detection timing, not destruction. Restore the VM from snapshot after.
- [ ] **Backup-tamper test:** on the test VM, attempt `wbadmin delete catalog` and a `bcdedit` recovery-disable and confirm each alerts. Revert.
- [ ] **Exfil simulation:** move a benign, clearly-marked dummy dataset to a controlled endpoint you own, mimicking the `rclone`-to-cloud pattern, and confirm egress/large-transfer detection fires. Never move real client data; the dataset is synthetic.
- [ ] **Discovery and credential-access tests:** fire benign ATT&CK discovery (net share/AD enumeration) and credential-access (an LSASS-read attempt on a test host) techniques; confirm the quiet early stages alert, not just the loud finale.
- [ ] **Lateral-movement test:** from one test host, exercise a benign remote-exec and a reachable-share check into another test host to validate segmentation and lateral-movement detection without moving real tooling onto production.
- [ ] **EDR-tamper and canary tests:** attempt a user-space sensor stop and a canary-file touch; confirm tamper protection holds and the canary alerts.

```bash
# Atomic Red Team invoke anchor (anchor only; full tooling in cheatsheet).
# Each test maps to an ATT&CK technique and ships its own cleanup command.
Invoke-AtomicTest T1490 -TestNumbers 1   # Inhibit System Recovery; run cleanup after
```

### Confirm what alerted
- [ ] **Walk the chain end to end once:** after per-step testing, run the full sequence (access, discovery, lateral, credential, defense-evasion, staging, benign marker) against the test hosts to see which stages correlate into a single incident versus scatter as unlinked low-priority alerts. Correlation is often the real gap.
- [ ] **Record the detection result per step:** for every technique fired, log alerted/silent, the detecting control, and the time from action to alert. This table is the core of the scorecard.
- [ ] **Full teardown:** reverse every marker, restore every test VM, remove every canary and artifact you added, and confirm with the SOC that simulated alerts are closed, not left masquerading as a live incident.
- [ ] **Confirm the environment is as you found it:** re-check the phase 1 baseline (services, backup jobs, shadow copies, group memberships) and prove nothing you touched persists. The simulation is not done until the client's estate is provably back to where it started.

---

## 11. Tabletop and IR

Technology restores files; the business decides whether it survives. The tabletop tests whether leadership has actually made the hard calls before the morning they have to make them live, under a ticking leak-site countdown.

- [ ] **IR playbook exists and is current:** confirm a ransomware-specific IR plan exists, names roles, and was reviewed recently. A plan last touched three years ago is a document, not a capability.
- [ ] **Retainer and external help on call:** confirm an IR/forensics retainer or equivalent is in place and the activation path is known. Finding and onboarding a responder during the incident costs the days you do not have.
- [ ] **Roles and decision authority:** confirm it is clear who declares an incident, who can authorize isolation and shutdown, and who owns the recovery decision. Ambiguity here costs hours at the worst time.
- [ ] **Decisions survive key-person absence:** confirm the plan names deputies, because the incident will not wait for the one person who knows the backup password to come back from leave. Single points of human failure are as real as technical ones.
- [ ] **Out-of-band comms:** confirm there is a communication plan that does not depend on the (possibly encrypted) corporate email, AD, or Teams. If the IR bridge runs on the domain that just went down, there is no bridge.
- [ ] **Offline copy of the plan and contacts:** confirm the IR plan, contact tree, and key credentials exist in a form reachable when the network is down (printed, or in an out-of-band store). A recovery plan that only lives on the encrypted file server is gone when you need it.
- [ ] **Pay / no-pay decision path:** confirm leadership has a pre-agreed position and process on ransom payment, including who decides and what legal and sanctions constraints apply. Deciding this live, under extortion, is how bad calls happen.
- [ ] **Sanctions and payment mechanics:** confirm someone has checked that paying a given crew is not itself a sanctions violation, and that the mechanics (crypto, negotiator) are understood in principle. A pay decision that turns out to be illegal is worse than no decision.
- [ ] **Legal, insurance, notification:** confirm the cyber-insurance contacts, breach-counsel, and regulatory/customer notification obligations are documented and reachable out of band. Know the reporting clocks before the event, not during it.
- [ ] **Third-party and customer impact:** confirm the plan accounts for downstream notification to partners and customers whose data may have been exfiltrated. The leak-site exposure is often other people's data, and they have reporting clocks too.
- [ ] **Leadership has rehearsed it:** confirm executives, not just IT, have sat through a tabletop. The technical team restoring servers while leadership improvises the business response is the common failure mode.
- [ ] **Scenario reflects double extortion:** confirm the tabletop assumes the data is already stolen and a leak countdown is running, not just "files are encrypted". The recover-only scenario trains the wrong reflexes.
- [ ] **Inject the backups are gone:** run the scenario once where the first restore attempt fails or the backups were reachable and deleted. The plan that assumes a clean restore always works has never met a real crew.
- [ ] **Recovery sequencing decided:** confirm there is an agreed order of restoration (identity and DCs first, then crown-jewel systems) and a defined clean-rebuild criterion. Restoring in the wrong order onto a still-owned domain re-triggers the event.
- [ ] **Lessons feed back:** confirm findings from the last tabletop or real incident produced tracked remediation, not just a report. A tabletop that changes nothing is theater.

---

## Recent Techniques (2024-2026)

Current ransomware-crew TTPs worth testing for. Technique classes, not fabricated CVEs; verify any specific driver or appliance CVE at the artifact before citing it.

- [ ] **Double / triple extortion:** encrypt, leak-threaten, and add a third lever (DDoS, direct customer/partner harassment, regulator tip-offs). Test for: exfil detection and a comms plan that assumes the data is already gone, not just an encryption-recovery plan.
- [ ] **Exfil before encryption:** steal data in the dwell window, then encrypt. Test for: egress/large-transfer alerting on file servers and the `rclone`/`MEGAcmd`/web-upload staging pattern (phase 8).
- [ ] **EDR killers via BYOVD:** load a vulnerable signed driver to terminate or blind the sensor from the kernel (the AuKill / EDRKillShifter / "spyboy" driver-abuse class). Test for: Microsoft vulnerable-driver blocklist / HVCI enforced, and tamper protection the kill tool cannot reach. Confirm the real driver and CVE at source; do not invent one.
- [ ] **Safe-mode / boot-time encryption:** reboot into safe mode (where many agents do not load) to run the encryptor unwatched. Test for: EDR safe-mode start or restricted safe-mode boot.
- [ ] **ESXi and Linux ransomware:** encrypt VMs at the hypervisor, beneath the Windows agents (the ESXi-targeting lockers across the current crews). Test for: ESXi management isolation, lockdown mode, and that hypervisor hosts are not reachable from user segments (phase 4).
- [ ] **Cloud and backup deletion:** delete or encrypt cloud backups and snapshots using stolen cloud/console credentials before on-prem encryption. Test for: backup-plane auth separation, object-lock immutability, and MFA on the backup/cloud console (phase 7).
- [ ] **Shadow-copy and backup-catalog destruction:** the universal recovery-inhibition step via `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, and `bcdedit` recovery-disable (ATT&CK T1490, Inhibit System Recovery). Test for: a tuned, tested alert on each of these commands (phases 9 and 10).
- [ ] **Intermittent / partial encryption:** encrypt only portions of each file for speed and to slip entropy-based detection. Test for: detection that does not rely solely on whole-file entropy, plus volume-of-change signals.
- [ ] **Ransomware-as-a-service affiliates:** the same locker arrives via different access brokers and playbooks, so initial access and TTPs vary run to run. Test for: breadth of detection across vectors, not a single-signature defense tuned to one crew.
- [ ] **Remote and cross-network encryption:** encrypt files on remote shares over SMB from one compromised host rather than running on each endpoint. Test for: detection of a single host rewriting files across many remote shares, and segmentation that limits reachable shares (phase 4).
- [ ] **Credential and token theft to cloud:** on-prem compromise pivots to cloud identity (stolen tokens, sync accounts) to reach cloud data and backups. Test for: conditional access, token-theft detection, and MFA on cloud admin. See [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md).
- [ ] **Delayed / low-and-slow execution:** dwell for weeks, then encrypt on a holiday, sometimes after disabling backups quietly days earlier. Test for: long log retention, detection of early backup-tamper, and after-hours alerting (phases 7 and 9).
- [ ] **Bring-your-own-vulnerable-appliance pivot:** compromise a neglected network appliance or IoT device as a quiet staging host beneath endpoint coverage. Test for: EDR/monitoring coverage gaps on non-standard hosts and segmentation that limits what they reach (phase 4).

---

## Reporting and Evidence

Frame the deliverable as a readiness scorecard mapped to the ransomware kill chain, with backup resilience as the headline metric. The executive reading it should see, in one view, whether this organization survives an event, and the detection gaps and time-to-detect numbers behind that verdict.

### Scorecard and evidence to capture
- [ ] **Kill-chain scorecard:** rate each phase (initial access, identity, lateral, credential, evasion, backup, exfil, detection, response) as the readiness view. Lead with backup resilience; it is the metric that most decides the outcome.
- [ ] **Time-to-detect for destructive precursors:** report the measured MTTD for shadow-copy deletion, backup-catalog tampering, mass-file-touch, and exfil staging from the simulation. These numbers are the report's spine.
- [ ] **Detection gap list:** every simulated TTP that was silent, with the control that should have caught it. Silence is the finding.
- [ ] **Simulation provenance:** the technique-to-result table (technique ID, alerted/silent, time-to-alert, detecting control), plus confirmation that all markers and artifacts were reverted. Keep raw evidence in the secured store.
- [ ] **Prioritized remediation, backup first:** order fixes by their effect on survivability, not by count. One change that puts a tested immutable copy out of a compromised admin's reach outranks a dozen tuning tweaks.
- [ ] **What went right:** record the controls that held and alerted. The scorecard is a readiness picture, not only a defect list, and the client needs to know what to keep funding.

### Severity guidance
| Severity | Typical ransomware-readiness examples |
|---|---|
| Critical | Mutable/online-only backups reachable and deletable from a compromised prod domain account; backup console or ESXi exposed to the internet; no tested restore exists |
| High | EDR killable via BYOVD / user-space stop; flat network with a user-VLAN route to the backup repo; no exfil detection; shadow-copy deletion unalerted |
| Medium | Single immutable copy but weak backup-account separation; partial EDR coverage; slow (hours) time-to-detect on destructive precursors; MFA gaps on one remote path |
| Low | Missing PowerShell logging; over-broad AV exclusions with compensating controls; canary files deployed but not alert-wired |
| Info | Documentation freshness, best-practice deviations with no demonstrated impact |

Let proven reachability and recoverability set the label, not the technique's reputation. The decisive question is almost always "can a compromised domain account destroy the backups", and a yes there is Critical regardless of how good the detection looks.

### Common false positives and pitfalls to rule out
- [ ] **A backup that exists but was never restore-tested:** an untested backup is a hope. Do not score it as recovery capability until a real restore has met the RTO.
- [ ] **"Immutable" an admin can still delete:** confirm the retention lock survives a privileged console user shortening or removing it. A togglable lock is not immutability.
- [ ] **A detection for the encryptor but not the exfil before it:** catching the encryption while the data already left is a partial control. Score the exfil window separately.
- [ ] **A GPO that sets a control vs the control running:** Credential Guard "configured" is not Credential Guard running. Verify the live state on sampled hosts.
- [ ] **Backup jobs "succeeding" vs data being recoverable:** green job status is not a verified restore. The catalog can be intact and the data still unrecoverable.
- [ ] **Agent "deployed" vs agent covering every host:** reconcile the console against the real asset list; the uncovered host is the one that matters.
- [ ] **Backup separation on paper vs in auth:** a backup account documented as separate can still trust the production domain under the hood. Confirm the actual authentication path, not the org chart.
- [ ] **A silenced alert vs no alert:** a rule that fires into a muted or ignored queue is operationally the same as no rule. Confirm the alert reaches a human who acts, not just a dashboard nobody watches.

---

## Tools and References

| Tool | Use |
|---|---|
| Atomic Red Team | ATT&CK-mapped, individually-reversible TTP tests (incl. T1490 Inhibit System Recovery); the safe simulation backbone |
| MITRE Caldera | Automated adversary-emulation profiles mapped to ATT&CK for chained, controlled runs |
| Infection Monkey | Safe breach-and-attack simulation for lateral movement and segmentation validation |
| Canary / file-marker tooling | Honeypot/canary files and benign file-markers for the reversible "encryptor" on test data only |
| vssadmin / wmic / wbadmin / bcdedit (detection tests) | Run on expendable VMs to validate shadow-copy, catalog, and boot-config tamper alerting |
| PingCastle / BloodHound CE | AD privilege-exposure and escalation-path mapping (phase 3), run read-only |
| EDR/SIEM console | Coverage reconciliation, tamper-protection state, and detection-result capture |
| Microsoft vulnerable-driver blocklist / HVCI | BYOVD exposure check (phase 6); confirm enforcement state |
| CISA KEV catalog / nuclei | Known-exploited exposure on edge and public-facing systems (phase 2) |

Authoritative references:
- CISA #StopRansomware Guide and the StopRansomware.gov resources: joint controls and response guidance.
- NIST SP 800-61 (incident handling) and the NIST Cybersecurity Framework / ransomware profile.
- MITRE ATT&CK: the ransomware-relevant techniques (Inhibit System Recovery T1490, Data Encrypted for Impact T1486, Exfiltration tactics) and the ATT&CK-mapped emulation plans.
- Vendor and CISA advisories for current crew TTPs; confirm any specific driver/appliance CVE at the release artifact before citing it.

---

## Related

- Checklists: [Red Team Operation](Red%20Team%20Operation.md), [Assumed Breach](Assumed%20Breach.md), [Compromise Assessment](Compromise%20Assessment.md), [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md), [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md)
- Cheatsheets: [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md), [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md), [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md)
- Playbooks: [Kerberoasting to Domain Admin](../Playbooks/Kerberoasting%20to%20Domain%20Admin.md), [DCSync to Golden Ticket Persistence](../Playbooks/DCSync%20to%20Golden%20Ticket%20Persistence.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
