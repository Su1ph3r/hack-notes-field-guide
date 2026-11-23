---
tags:
  - hack-notes
  - checklist
  - red-team
  - adversary-emulation
---

# Red Team Operation Testing Checklist

> Full-scope, objective-based adversary emulation methodology mapped to the Unified Kill Chain and MITRE ATT&CK. Use for authorized red-team and purple-team engagements where the goal is to reach defined objectives (crown jewels, flags) and measure detection, not to enumerate every CVE. This is an operator and OPSEC methodology, not a malware build guide.

## Table of Contents
- [1. Pre-Engagement and Rules of Engagement](#1-pre-engagement-and-rules-of-engagement)
- [2. Reconnaissance](#2-reconnaissance)
- [3. Resource Development and Infrastructure](#3-resource-development-and-infrastructure)
- [4. Initial Access](#4-initial-access)
- [5. Execution and Foothold C2](#5-execution-and-foothold-c2)
- [6. Persistence and Privilege Escalation](#6-persistence-and-privilege-escalation)
- [7. Defense Evasion and Credential Access](#7-defense-evasion-and-credential-access)
- [8. Discovery and Lateral Movement](#8-discovery-and-lateral-movement)
- [9. Collection, Exfiltration, and Impact](#9-collection-exfiltration-and-impact)
- [10. Detection, Deconfliction, and Purple-Team Wash-Up](#10-detection-deconfliction-and-purple-team-wash-up)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Rules of Engagement

Nothing touches a target until this phase is signed. The single most common red-team failure is operating outside an agreed boundary. Treat the Rules of Engagement (RoE) as the controlling document for the whole operation.

### Objectives and Scope

- [ ] **Define objectives, not just scope:** Agree concrete flags / crown jewels (domain admin, specific data store, payment system, a planted canary file). Objective-based emulation passes when an objective is reached, not when a finding count is hit.
- [ ] **Map crown jewels to systems:** Get the client to name the 3 to 5 assets whose compromise would constitute real impact. These anchor the attack path.
- [ ] **Confirm in-scope vs out-of-scope:** IP ranges, domains, cloud tenants (AWS accounts, Azure/Entra tenants, GCP projects), SaaS apps, physical sites, and subsidiaries. Get explicit yes/no on each.
- [ ] **Confirm prohibited actions:** No DoS, no production data modification, no real ransomware/encryption, no targeting of personal devices, no off-hours-only constraints unless stated.
- [ ] **Agree third-party deconfliction:** Cloud providers, CDN/WAF vendors, MSSP/SOC-as-a-service. Some require advance notice (AWS/Azure pen-test policies). Confirm who notifies them.
- [ ] **Pick the engagement model:** Black box, grey box, or [Assumed Breach](Assumed%20Breach.md) (start from a planted foothold). Assumed breach buys depth when initial access is slow or out of scope.

### Engagement Style

- [ ] **Detection-testing vs full-stealth:** Decide up front. Detection-testing (purple-leaning) prioritizes generating telemetry and measuring response. Full-stealth tests whether the blue team catches a quiet adversary. They drive opposite tradecraft.
- [ ] **Set a noise budget:** Even in stealth ops, agree what level of failed logins, scanning, or alerts is tolerable before pausing.
- [ ] **Agree stop conditions:** When does the team halt (objective met, detected and burned, business-impacting instability, white-cell call)?

### Authorization and Legal

- [ ] **Signed authorization to operate:** Written, dated, scoped, signed by someone with authority over the assets. No signature, no operation.
- [ ] **Get-out-of-jail-free letter:** Carry a physical/electronic letter naming the operators, the client sponsor, scope, dates, and an emergency 24/7 contact. Mandatory for any physical or on-site component.
- [ ] **Verify asset ownership:** Confirm the client owns or has authority over every in-scope IP/domain (registrant, hosting, cloud tenant). Do not take scope on faith for leased ranges.
- [ ] **Data handling agreement:** How is captured data (creds, PII, screenshots, loot) stored, encrypted, transmitted, and destroyed post-engagement? Agree retention window and secure-delete.

### Deconfliction and Contacts

- [ ] **Identify the white cell:** The small trusted group aware of the test. Get names, phones, and an out-of-band channel (Signal, separate bridge) that does not run through the systems under test.
- [ ] **Establish a deconfliction line:** A way for the SOC to ask "is this you?" and get a fast yes/no without tipping the wider blue team. Keep a real-time activity log keyed by source IP and timestamp to answer those queries.
- [ ] **Traffic-light protocol (TLP) for findings:** Agree TLP marking on all interim and final reporting (TLP:RED for live operational detail, downgrading later). Controls who sees what, when.
- [ ] **Emergency contact tree:** Who to call if something breaks production, a real intruder is found, or evidence of a prior compromise surfaces (you must report this immediately and pause).

> ⚠️ If you discover signs of a real, pre-existing compromise, STOP, preserve state, and notify the white cell out-of-band immediately. Do not continue operating through someone else's active intrusion.

---

## 2. Reconnaissance

Passive-first. The aim is to build a target model (people, infrastructure, technology, exposure) without touching client assets in a way that generates defender telemetry. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md) for tooling and queries.

### Organizational and People Mapping

- [ ] **Org structure and key people:** Leadership, IT/security staff, help-desk and HR (social-engineering targets), recent hires and layoffs (LinkedIn). Map reporting lines.
- [ ] **Email and username convention:** Derive the format (`first.last@`, `flast@`) from public sources, then build a candidate user list for later spraying/phishing.
- [ ] **Breach and credential exposure:** Check breach corpuses and stealer-log markets for in-scope emails and reused passwords. Note which feed initial-access hypotheses.
- [ ] **Document and metadata leakage:** Public docs, PDFs, and code repos for usernames, internal hostnames, paths, and software versions (metadata, comments, commit history).

### Infrastructure and Attack-Surface Mapping

- [ ] **Domain and subdomain enumeration:** Passive sources (cert transparency, DNS aggregators, passive DNS) before any active resolution. Build the external footprint.
- [ ] **ASN and IP-range mapping:** Tie owned ranges to the org via registrant and reverse DNS. Distinguish self-hosted from CDN/cloud-fronted assets.
- [ ] **Exposed services inventory:** Use third-party scan data (Shodan/Censys-style) to find exposed RDP, VPN, mail, Citrix, file-transfer, and edge appliances without scanning the client yourself.
- [ ] **Cloud and SaaS footprint:** Public S3/blob/GCS buckets, exposed cloud consoles, tenant ID discovery, and SaaS apps (Okta/Entra login realms, M365 tenant enumeration).
- [ ] **Email and tech profiling:** SPF/DKIM/DMARC posture (informs spoofing and phishing-domain choice), mail gateway (Proofpoint/Mimecast/M365), and which security stack fronts the perimeter.

### Active Recon (Throttled, In-Scope Only)

- [ ] **Light active validation:** Resolve and lightly probe only confirmed in-scope hosts, throttled and from non-attributable infrastructure. Treat every active packet as something the SOC may see.
- [ ] **Edge-appliance fingerprinting:** Identify VPN/gateway products and versions (login banners, favicon hashes) to line up known-CVE initial-access leads.

---

## 3. Resource Development and Infrastructure

Build the operational infrastructure before initial access. OPSEC here determines whether the whole operation gets burned in week one. Map to ATT&CK Resource Development (TA0042).

### C2 and Redirector Architecture

- [ ] **Tiered C2 design:** Separate team server from anything the target touches. Front all target-facing traffic through redirectors so the C2 host is never directly exposed.
- [ ] **Redirector layer:** Stand up HTTP(S) and/or DNS redirectors (reverse proxy, socat, or CDN domain fronting where permitted) that forward only valid beacon traffic and serve a decoy site to everything else.
- [ ] **Pick the C2 framework to fit the threat model:** Match capability and noise to the engagement (see table). Have a long-haul/low-and-slow channel and a separate interactive channel.

| Framework | Notes for selection |
|-----------|---------------------|
| Sliver | Open-source, cross-platform implants, mTLS/HTTPS/DNS/WireGuard channels. Strong default for most ops. |
| Mythic | Modular, multi-agent, collaborative web UI, strong reporting/ATT&CK export. Good for team ops and purple work. |
| Havoc | Open-source, depth in Windows in-memory evasion; less customization needed against hardened EDR. |
| Cobalt Strike | Industry baseline; heavily signatured, needs malleable profile tuning and a fresh license/infra. |
| Nighthawk | Commercial, evasion-first; awareness item for hardened-target ops (vetted access). |

- [ ] **Malleable / custom profiles:** Shape C2 traffic to blend with expected enterprise traffic (jitter, sleep, realistic URIs, user-agents, host headers). Never run a default profile against a monitored target.
- [ ] **Separate infra per objective:** Phishing infra, payload-staging, C2, and exfil should not share IPs or domains. One burned component must not collapse the others.

### Domain and Phishing Infrastructure

- [ ] **Domain selection and aging:** Register or buy domains that are plausible (look-alike or generic-business). Aged domains beat fresh registrations against reputation filters.
- [ ] **Domain categorization:** Get domains categorized (business/uncategorized) by web-proxy vendors before use; uncategorized or miscategorized domains get blocked by SWGs.
- [ ] **TLS and reputation:** Valid certs, clean IP reputation (not on spam/abuse lists), and warmed sending IPs for any email path.
- [ ] **Phishing infrastructure:** Stand up the landing/AiTM relay separate from C2. For credential capture use an AiTM reverse-proxy (evilginx-style) to also capture session cookies and survive MFA. See [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md).
- [ ] **Sender authentication:** Configure SPF/DKIM/DMARC on sending domains so phishing mail passes auth and reaches inboxes.

### Payload Development and OPSEC

- [ ] **Payload strategy at a methodology level:** Decide delivery format (signed loader, container/ISO/LNK, HTA, macro-free Office, or legitimate-app sideload) based on the target's mail/web controls. Keep payloads minimal and stage the rest over C2.
- [ ] **Stager vs stageless:** Stageless reduces network artifacts but is larger; stagers are stealthier on disk but noisier on the wire. Choose per channel.
- [ ] **Detonation testing in a safe lab:** Validate payloads against a representative AV/EDR build offline. Never test detection against the live target's stack with throwaway samples (it trains their detections and burns infra).
- [ ] **OPSEC hygiene:** Unique infra per engagement, no reuse of burned domains/IPs, no operator metadata in artifacts, no test callbacks to personal IPs, source-IP and timestamp logging for deconfliction.

> ⚠️ Do not upload live payloads to public multi-engine scanners (VirusTotal etc.). It shares samples with vendors and instantly burns the implant and infra.

---

## 4. Initial Access

Get the first authenticated foothold or beacon inside the boundary. Map to ATT&CK Initial Access (TA0001). Phishing and exposed-edge are the two dominant modern vectors. See [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md) and the [External Network Penetration Test](External%20Network%20Penetration%20Test.md) checklist.

### Social Engineering Vectors

- [ ] **Spear-phishing for execution:** Targeted lure delivering a loader to a small, well-chosen recipient set. Pass/fail: a beacon checks in.
- [ ] **AiTM credential + session theft:** Reverse-proxy phishing page that relays the real login, captures credentials AND the post-MFA session cookie. Replay the cookie to bypass MFA entirely.
- [ ] **MFA fatigue / push bombing:** Where creds are already held, trigger repeated push prompts to coax an approval. Pair with a help-desk pretext for credibility.
- [ ] **Help-desk / vishing pretext:** Call the service desk impersonating an employee to drive a password reset or MFA re-enrollment to an attacker device (the Scattered Spider playbook). Test the identity-verification process directly.
- [ ] **Smishing / callback phishing:** SMS or "call this number" lures that route around email gateways.

### Technical Access Vectors

- [ ] **Exposed-service exploitation:** Edge appliances (VPN, Citrix, file-transfer, mail) with known CVEs identified in recon. Validate carefully; edge exploits can crash production boxes.
- [ ] **Valid accounts:** Use creds from breach data, stealer logs, spraying, or AiTM against externally reachable auth (VPN, OWA/M365, SSO, RDP gateway, VDI). Password-spray slowly to dodge lockout and detection.
- [ ] **Supply chain / third-party access:** Compromised contractor or managed-provider access, malicious dependency, or trusted-relationship abuse where in scope.
- [ ] **Public-facing app compromise:** Web app footholds (RCE, deserialization, SSRF-to-metadata) that yield code execution on an internal-adjacent host.
- [ ] **Token / cookie replay:** Replay stolen OAuth/refresh tokens or session cookies to enter SaaS and cloud tenants without ever touching a password.

### Foothold Validation

- [ ] **Confirm the access is usable:** From the foothold, confirm reachability to internal resources and that the beacon survives a reboot/logoff if persistence is in scope.
- [ ] **Capture the entry evidence:** Record vector, account, host, and timestamp for the attack-path narrative and deconfliction log.

---

## 5. Execution and Foothold C2

Establish reliable, low-profile command and control. Map to ATT&CK Execution (TA0002) and Command and Control (TA0011). EDR-evasion here is treated at a methodology and tradecraft-decision level, not as code. For interactive shells and staging see [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md).

### Beaconing and Channel Hygiene

- [ ] **Establish primary beacon:** Long-haul, high-jitter, low-frequency callback through a redirector. Verify it blends with the malleable profile chosen in Phase 3.
- [ ] **Stand up a fallback channel:** Independent C2 path (different protocol/domain, e.g. DNS or a second HTTPS profile) so loss of one channel does not mean loss of the foothold.
- [ ] **Tune sleep and jitter:** Match beacon cadence to the noise budget. Tighten only on a host you are actively working, then loosen again.
- [ ] **Domain fronting / CDN where permitted:** Front beacon traffic behind a high-reputation domain to defeat reputation-based egress filtering, if the RoE and provider terms allow.

### Payload Delivery and In-Memory Tradecraft

- [ ] **Prefer in-memory execution:** Run post-ex modules in memory (reflective load, fork-and-run vs inline) to minimize disk artifacts. Decide fork-and-run vs inline per module risk.
- [ ] **Process and parent selection:** Inject into or spawn from plausible parent processes; avoid orphaned or implausible parent/child relationships that EDR flags.
- [ ] **Sleep masking (concept):** Where the implant supports it, encrypt/obfuscate beacon memory during sleep to evade periodic memory scanning. This is a configuration/selection decision, not something to hand-roll on a live op.
- [ ] **Module discipline:** Run the least-noisy capability that achieves the step. Heavy post-ex (keylog, screenshot loops, mass collection) is high-signal; save it for when it directly serves an objective.

### EDR-Awareness (Methodology Level)

- [ ] **Know the stack:** Identify the EDR/AV product before running post-ex. Tradecraft that is safe against one product burns you on another.
- [ ] **Userland-hook awareness:** Assume userland API hooking and behavioral telemetry. Choose tradecraft (e.g. syscall-based execution, BYOVD only where authorized) consciously, and log what you used so the blue team can map coverage.
- [ ] **AMSI / script-host awareness:** Treat in-memory script execution as scanned. Prefer compiled/in-memory loaders over raw PowerShell where the engagement style is stealth.
- [ ] **Fail quietly:** If a module trips a detection, stop, assess via the deconfliction log whether you are burned, and switch tradecraft rather than retrying the same noisy action.

> ⚠️ BYOVD, driver loading, and kernel tampering are high blast radius and can blue-screen production hosts. Use only when explicitly authorized, on agreed hosts, with a rollback plan.

---

## 6. Persistence and Privilege Escalation

Survive reboots and credential resets, then climb. Map to ATT&CK Persistence (TA0003) and Privilege Escalation (TA0004). For host-level escalation technique detail see [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md) and [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md).

### Persistence (Minimal and Deliberate)

- [ ] **Persist only where needed:** Each persistence mechanism is a detection opportunity and cleanup obligation. Persist on the few hosts that matter, not everywhere.
- [ ] **User-level persistence first:** Run keys, scheduled tasks, startup folder, COM hijack. Lower privilege requirement, often lower scrutiny than service-level.
- [ ] **Privileged persistence:** Services, WMI event subscriptions, and (where in scope) AD-level persistence after escalation. Higher value, higher detection risk.
- [ ] **Identity persistence:** Where the objective is identity (cloud/SaaS), prefer token/refresh-token and app-registration persistence over host implants. See cloud sections of [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md) / [AWS Pentest](../Cheatsheets/AWS%20Pentest.md).
- [ ] **Catalogue every mechanism:** Log host, mechanism, and artifact location for guaranteed teardown. Orphaned persistence is a serious post-engagement liability.

### Privilege Escalation

- [ ] **Local recon for escalation paths:** Enumerate misconfigurations, unquoted paths, weak service perms, writable autoruns, token privileges, and stored creds. Pull a privilege-escalation tool output and triage.
- [ ] **Credential-backed escalation:** Reuse creds/tokens harvested so far against higher-privileged local or domain accounts before reaching for exploits.
- [ ] **Kernel/exploit escalation last:** Public LPE exploits are noisy and can crash hosts. Prefer misconfig and credential paths first.
- [ ] **Cloud privilege escalation:** Abuse over-permissive IAM, role assumption, and managed-identity/metadata access where the objective lives in cloud.

```bash
# Methodology anchor: triage, do not spray exploits
# Windows: run a privesc enumerator, review writable services / token privs / autoruns
# Linux: enumerate sudo rules, SUID, cron, capabilities, writable PATH
# Full command sets live in the privesc cheatsheets, not here.
```

---

## 7. Defense Evasion and Credential Access

Move without lighting up the SOC, and harvest the credentials/tokens that unlock the attack path. Map to ATT&CK Defense Evasion (TA0005) and Credential Access (TA0006). Treat credential theft as methodology; do not paste dumping commands here.

### Defense Evasion (Tradecraft Decisions)

- [ ] **Log and telemetry awareness:** Know what is logged (Sysmon, EDR, Windows event channels, cloud audit logs). Assume command-line, process, and network telemetry are captured.
- [ ] **AMSI / script-engine handling:** Where stealth is required, avoid raw script execution paths that are scanned; prefer in-memory compiled tradecraft. Record any AMSI-affecting action for the wash-up.
- [ ] **Indicator hygiene:** Avoid known-bad tool names on disk, default named pipes, and signatured strings. Rename and obfuscate tooling per engagement.
- [ ] **Timestomp / artifact discipline (only if in scope):** Minimize forensic footprint deliberately, but never destroy logs or evidence the client needs (and never to cover a real intrusion).
- [ ] **Live off the land:** Prefer built-in binaries and admin tooling (LOLBins) for discovery and movement to blend with normal admin activity.

### Credential Access (Methodology)

- [ ] **In-memory credential theft:** Methodology for extracting credentials from process memory (LSASS) and secrets stores. High-signal; choose the quietest access method available and expect EDR scrutiny on the target process.
- [ ] **DPAPI / browser / token theft:** Harvest stored secrets, browser cookies/tokens, and cloud session tokens. Token theft often beats password theft because it sidesteps MFA.
- [ ] **AD credential material:** Where AD is in scope, methodology for Kerberos ticket abuse (roastable accounts, ticket theft) and the eventual domain-credential objective. Detail in [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md).
- [ ] **Cloud/SaaS keys:** Hunt for cloud access keys, service-account JSON, CI/CD secrets, and IaC state with embedded creds.
- [ ] **Reuse map:** Maintain a living map of which credential opens which system. This map IS the attack path.

> ⚠️ Accessing credential stores (LSASS, KDC, secrets vaults) is among the most heavily monitored actions in a modern environment. Sequence it deliberately, and only when it advances a named objective.

---

## 8. Discovery and Lateral Movement

Build the internal picture and traverse toward the objective. Map to ATT&CK Discovery (TA0007) and Lateral Movement (TA0008). For AD attack paths see [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md); for routing tooling between segments see [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md).

### Internal Discovery

- [ ] **Quiet host and network discovery:** Enumerate the local host, reachable subnets, and shares with low-noise, native methods before any scanning. Avoid sweeping ping/port scans on monitored segments.
- [ ] **Active Directory mapping:** Collect AD structure (users, groups, computers, ACLs, trusts, GPOs) and feed it to attack-path analysis to find the shortest route to the objective. See [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md).
- [ ] **Identify high-value targets:** Locate the systems holding the crown jewels and the accounts/paths that reach them. Do not wander; navigate toward objectives.
- [ ] **Cloud/identity discovery:** Map federation, Entra/Okta roles, and cloud-to-on-prem trust where the path crosses into cloud.

### Lateral Movement

- [ ] **Pick the quietest movement primitive:** Remote service exec, WMI, WinRM, SSH, or scheduled-task creation. Match to what is normal in the environment to blend in.
- [ ] **Credential / ticket reuse:** Pass-the-hash, pass-the-ticket, overpass-the-hash, and token reuse to move without re-phishing. Methodology in [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md) and [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md).
- [ ] **Session and pivot management:** Establish pivots/tunnels to reach segmented networks from the foothold. Keep a clear map of which beacon routes to which segment. See [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md).
- [ ] **Validate each hop:** Confirm access on the new host, plant minimal persistence only if needed, and update the attack-path map before moving again.
- [ ] **Path narration:** Continuously record the chain (host to host, credential to credential) so the final attack-path story is reconstructable. Feed this into Ariadne for attack-path synthesis.

---

## 9. Collection, Exfiltration, and Impact

Reach the objective, prove it, and (where authorized) demonstrate controlled impact. Map to ATT&CK Collection (TA0009), Exfiltration (TA0010), and Impact (TA0040).

### Objective Completion and Collection

- [ ] **Reach the defined objective:** Domain admin, the named data store, the planted flag/canary. Pass = the agreed objective is provably reached.
- [ ] **Collect only what proves it:** Capture the minimum evidence (the canary file, a screenshot of access, a hash of the target record). Do NOT mass-exfiltrate real sensitive data unless explicitly authorized and necessary.
- [ ] **Stage in scope:** Any staging of loot stays on in-scope, controlled systems. No client data leaves to operator-personal infrastructure.

### Controlled Exfiltration

- [ ] **Use a separate exfil channel:** Distinct from C2 (e.g. cloud-storage upload, DNS, or HTTPS to dedicated infra) to also test data-loss-prevention controls.
- [ ] **Use canary / synthetic data where possible:** Exfiltrate a planted marker file rather than real records to prove the path without handling real PII. Pass = the marker reaches attacker-controlled storage and/or DLP did or did not fire.
- [ ] **Measure DLP and egress detection:** Record whether exfil was blocked, alerted, or silent. That result is a primary deliverable.

### Impact Demonstration

- [ ] **Demonstrate, do not detonate:** Prove the capability for impact (e.g. show write access to a critical share, ability to disable a backup) WITHOUT executing destructive actions. Never run real encryption/ransomware or delete production data.
- [ ] **Capture impact evidence safely:** A benign marker write, a screenshot of access, or a dry-run log is sufficient proof of impact for the report.

> ⚠️ Real destructive impact (encryption, deletion, account lockout at scale) is out of scope by default. Demonstrating reach is the objective, not causing the damage.

---

## 10. Detection, Deconfliction, and Purple-Team Wash-Up

Convert the operation into measurable defensive value. This phase is what separates a red-team engagement from a break-in.

### Detection Reconstruction

- [ ] **Reconcile activity vs telemetry:** Walk the operator activity log against the blue team's alerts and logs. For every major action, record: detected, logged-not-alerted, or invisible.
- [ ] **Map every action to MITRE ATT&CK:** Tag each technique used with its ATT&CK ID so coverage and gaps are expressed in a shared language. Sliver/Mythic and similar frameworks can export technique mappings to seed this.
- [ ] **Identify detection gaps:** Where the operation was invisible, that is a detection-engineering action item, not a brag. Pair each gap with a proposed detection.

### Deconfliction Close-Out

- [ ] **Resolve the deconfliction log:** Confirm every blue-team "is this you?" query was answered and reconciled. Surface any activity the client saw that was NOT the red team (possible real intrusion).
- [ ] **Confirm full teardown:** Remove every implant, persistence mechanism, planted file, scheduled task, and account created. Cross off the Phase 6 persistence catalogue item by item. Tear down C2 and phishing infra.
- [ ] **Return/secure captured data:** Securely destroy or hand back all captured credentials and loot per the data-handling agreement. Confirm in writing.

### Purple-Team Wash-Up

- [ ] **Run a replay / detection workshop:** Re-run or table-top key techniques with the blue team watching, so they can build and validate detections in real time.
- [ ] **Deliver the attack-path narrative:** A clear, ordered story from initial access to objective, with the chain of decisions and pivots. Synthesize with Ariadne.
- [ ] **Ship detection-engineering output:** Each gap closed with a concrete detection (rule, log source to enable, alert to tune) and a re-test plan to verify the fix.
- [ ] **Prioritized remediation:** Rank fixes by where they break the attack path earliest (e.g. fixing initial access or the first privesc kills the whole chain).

---

## Recent Techniques (2024-2026)

- [ ] **AiTM session-cookie phishing:** Reverse-proxy phishing kits (evilginx-style) that relay the real login and steal the post-MFA session cookie. Test for: MFA bypass via captured-cookie replay even with MFA enforced.
- [ ] **Scattered Spider / Octo Tempest help-desk SE (G1015):** Vishing the IT help desk to drive password resets or MFA re-enrollment to an attacker device. Test for: identity-verification rigor at the service desk and on account-recovery flows.
- [ ] **MFA fatigue / push bombing:** Repeated push prompts to coax approval, often paired with a vishing pretext. Test for: number-matching MFA, push-volume throttling, and user reporting.
- [ ] **Token / refresh-token theft and replay:** Steal OAuth/refresh tokens and session cookies to enter cloud/SaaS without a password. Test for: token-binding, impossible-travel, and conditional-access on token reuse.
- [ ] **BYOVD (Bring Your Own Vulnerable Driver):** Load a legitimately signed but vulnerable driver to reach kernel-mode and blind/kill EDR. Test for: Microsoft Vulnerable Driver Blocklist enabled, HVCI on, and driver-load telemetry. Authorized-hosts-only, high blast radius.
- [ ] **Indirect / randomized syscalls (SysWhispers-style):** Execute via syscall;ret gadgets inside ntdll so the call appears legitimate, defeating userland hooks. Test for: kernel-callback (ETW/Kernel) telemetry that survives userland-hook bypass.
- [ ] **Sleep masking (Ekko / FOLIAGE / DreamWalkers class):** Encrypt implant memory during sleep to evade periodic memory scanning. Test for: EDR memory-scan cadence and detection of encrypt/decrypt-on-sleep behavior.
- [ ] **AMSI bypass via hardware breakpoints / VEH:** Redirect AmsiScanBuffer through a vectored exception handler returning a clean result, avoiding the in-memory patch signature. Test for: AMSI-tamper and script-block telemetry plus follow-on behavioral rules.
- [ ] **Modern open-source C2 (Sliver, Mythic, Havoc):** Cross-platform, multi-channel implants increasingly replacing Cobalt Strike. Test for: detections that key on behavior/JA3/profile anomalies, not just Cobalt Strike signatures.
- [ ] **Domain fronting / CDN-backed C2 resurgence:** High-reputation fronting to bypass egress reputation filtering. Test for: TLS SNI vs Host mismatch inspection and egress allow-listing.
- [ ] **Identity-first cloud attack paths:** Federation/Entra/Okta role abuse and app-registration persistence as the objective, bypassing host-based detection entirely. Test for: cloud audit-log coverage and risky app-consent monitoring.
- [ ] **Purple-team-by-default operating model:** Real-time shared telemetry so every emulated technique ends in a confirmed detection or a shipped detection-engineering fix, mapped technique-by-technique to ATT&CK.

---

## Reporting and Evidence

### Evidence to Capture per Step

- [ ] **Operator activity log:** Source IP, timestamp, target host, action, and ATT&CK technique for every significant action. This is the backbone of both deconfliction and reporting.
- [ ] **Per-objective proof:** The flag/canary, a screenshot of privileged access, or a hash of the target record. Enough to prove reach, no more.
- [ ] **Vector evidence:** For initial access, persistence, and privesc, capture the exact mechanism and artifact so the client can both reproduce and remediate.
- [ ] **Detection outcome:** For each technique, whether it was detected, logged-only, or invisible, plus the blue-team alert (or its absence).

### Severity and Prioritization

| Tier | Meaning |
|------|---------|
| Critical | Crown-jewel objective reached and/or full domain/tenant compromise; minimal or no detection along the path. |
| High | Significant access (privileged foothold, sensitive data reachable) with detection gaps at key chokepoints. |
| Medium | Foothold and lateral movement achieved but blocked or detected before reaching objective. |
| Low / Informational | Hygiene and config issues that did not advance the path, plus successful detections to credit the blue team. |

Prioritize remediation by where a fix breaks the attack path earliest. Always credit detections that fired; the report is a measure of defense, not just a list of wins.

### Common False Positives to Rule Out

- [ ] **Stale/planted artifacts:** Confirm an "open" path is real and not test scaffolding or assumed-breach seeding mistaken for a discovered foothold.
- [ ] **Out-of-scope reachability:** Verify a reached asset is actually in scope and client-owned before reporting impact.
- [ ] **Detection vs response:** Distinguish "the SIEM logged it" from "the SOC acted on it." A logged-not-actioned event is a response gap, not a detection win.
- [ ] **Self-inflicted noise:** Exclude alerts caused by your own deconfliction queries or noisy-but-authorized testing from the client's true detection rate.

---

## Tools and References

| Area | Tools / References |
|------|--------------------|
| Framework | MITRE ATT&CK (Enterprise, Cloud, Containers matrices); Unified Kill Chain |
| C2 | Sliver, Mythic, Havoc, Cobalt Strike; Nighthawk (awareness) |
| Attack-path analysis | Ariadne, BloodHound-class AD path mapping |
| Initial access / phishing | AiTM reverse-proxy kits (evilginx-class), GoPhish-class senders |
| AD / lateral | [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md), Kerberos tooling |
| Recon | Cert-transparency, passive DNS, Shodan/Censys-class exposure data |
| Methodology refs | MITRE ATT&CK technique catalogue; Unified Kill Chain; CREST / TIBER-EU / red-team frameworks |

Authoritative references: MITRE ATT&CK (attack.mitre.org), the Unified Kill Chain model, and recognized red-team frameworks (CREST, TIBER-EU, CBEST) for engagement structure and RoE discipline.

---

## Related

- Playbooks: [Edge Device Exploit to Internal Foothold](../Playbooks/Edge%20Device%20Exploit%20to%20Internal%20Foothold.md), [Coercion to ADCS ESC8 to Domain Admin](../Playbooks/Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md), [DCSync to Golden Ticket Persistence](../Playbooks/DCSync%20to%20Golden%20Ticket%20Persistence.md), [Azure AiTM Token Theft to Global Admin](../Playbooks/Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md), and the full [Attack Graph](../Playbooks/Attack%20Graph.md)
- [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md)
- [External Network Penetration Test](External%20Network%20Penetration%20Test.md)
- [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md)
- [Assumed Breach](Assumed%20Breach.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
- [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md)
- [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
- [AWS Pentest](../Cheatsheets/AWS%20Pentest.md)
- Ariadne

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
