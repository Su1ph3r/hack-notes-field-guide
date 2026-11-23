---
tags:
  - hack-notes
  - checklist
  - network
  - external
---

# External Network Penetration Test Testing Checklist

> Use for an authorized assessment of an internet-facing estate (perimeter IP ranges, public web, VPN and remote-access gateways, mail, exposed services). Methodology-first: work it top to bottom, capture evidence per step, and link out to the cheatsheets for full command syntax.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Passive Recon and OSINT](#2-passive-recon-and-osint)
- [3. Active Discovery and Service Enumeration](#3-active-discovery-and-service-enumeration)
- [4. Service-by-Service Testing](#4-service-by-service-testing)
- [5. Authentication Attacks](#5-authentication-attacks)
- [6. Vulnerability Validation and Exploitation](#6-vulnerability-validation-and-exploitation)
- [7. Initial Access and Foothold](#7-initial-access-and-foothold)
- [8. Post-Exploitation Pivot to Internal](#8-post-exploitation-pivot-to-internal)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Nothing is tested until scope and authorization are in writing. The perimeter is where third-party and fragile assets hide, so confirm ownership before you touch anything.

### Authorization and Legal
- [ ] **Signed authorization in hand:** confirm a countersigned SOW or rules-of-engagement (RoE) document exists, names the testing window, and lists the legal entity authorizing the work. Do not scan before it lands.
- [ ] **Scope ownership verified:** confirm the client actually owns or controls every IP/CIDR and domain in scope. Cloud-hosted and CDN-fronted assets often belong to a provider whose RoE forbids testing.
- [ ] **Third-party carve-outs:** identify SaaS, CDN, WAF, and managed-hosting assets (Cloudflare, Akamai, AWS, Azure) and get written provider authorization or exclude them.
- [ ] **Out-of-scope list captured:** record explicitly excluded hosts, ranges, and actions (no DoS, no social engineering unless contracted, no data exfiltration of real records).

### Scope Definition
- [ ] **IP/CIDR scope frozen:** record the exact in-scope ranges and a one-line provenance for each (client-provided, ASN-derived, DNS-resolved). Flag any range you discovered but the client did not list for confirmation.
- [ ] **Domain and subdomain scope:** capture in-scope apex domains and whether wildcard subdomains are in or out.
- [ ] **Allowed test windows:** note any blackout periods, change-freeze windows, or "business hours only" constraints.

### Rules of Engagement
- [ ] **Source IPs registered:** provide your testing source IPs (and any VPS/redirector egress IPs) to the client so they can allow-list or correlate. Test from those IPs only.
- [ ] **Deconfliction channel agreed:** confirm a named contact, out-of-band channel (phone/Signal), and response SLA for "is this you?" calls and for halting on incident.
- [ ] **Emergency stop conditions:** agree the conditions under which you halt (production outage, evidence of a prior real intruder, data showing up that should not).
- [ ] **Fragile-host warnings collected:** ask for and record any fragile, legacy, SCADA/OT, medical, or single-homed production hosts. Throttle or hand-test these; never mass-scan them.

```
⚠️ Perimeter scanning can knock over fragile appliances, legacy SSL VPN concentrators,
   printers, and OT gear. Confirm fragile-host list FIRST. Default to low-rate, no
   aggressive NSE/UDP storms, and no exploit attempts on flagged hosts without sign-off.
   If you discover evidence of a pre-existing real-world compromise, STOP and invoke the
   deconfliction channel immediately.
```

### Test Infrastructure
- [ ] **Egress reliability:** confirm your testing box has stable egress and that a backup path exists if an IP gets blocked mid-engagement.
- [ ] **Evidence store ready:** stand up a per-engagement, access-controlled evidence folder. Every request/response pair, scan output, and screenshot goes here with timestamps.
- [ ] **Logging on by default:** run all proxy/tooling with full request and response logging so findings are reproducible after the fact.

---

## 2. Passive Recon and OSINT

Build the external footprint without sending a packet to client infrastructure first. The goal is a complete, deduplicated asset inventory and a credential/leak picture before active scanning. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md) for the full tooling and command set.

### Organization and Network Footprint
- [ ] **ASN and netblock discovery:** map the org's ASNs and announced prefixes (BGP looking glasses, `whois`, bgp.he.net). Reconcile against the client-provided CIDR scope and flag deltas.
- [ ] **WHOIS and registrant pivots:** pull registrant org, emails, and name servers; pivot to sibling domains via shared registrant data.
- [ ] **Reverse DNS and PTR sweep:** resolve PTR records across in-scope ranges to surface naming conventions and forgotten hosts.

### Domain and Subdomain Enumeration
- [ ] **Passive subdomain enumeration:** aggregate from multiple sources (`subfinder`, `amass` passive, crt.sh, VirusTotal, securitytrails). Deduplicate into one master list.
- [ ] **Certificate transparency mining:** harvest hostnames from CT logs (crt.sh, censys); CT often reveals internal-naming and staging hosts.
- [ ] **DNS record harvest:** collect A/AAAA, CNAME, MX, TXT, SPF, DMARC, DKIM, NS, and CAA. Note third-party CNAMEs (candidates for subdomain takeover).
- [ ] **Subdomain takeover check:** flag dangling CNAMEs pointing to deprovisioned cloud/SaaS resources and verify takeover potential before claiming it.
- [ ] **Zone transfer attempt:** test `AXFR` against each authoritative NS. Successful transfer is a finding and a goldmine.

```bash
# Quick passive surface stitch (detail in [[OSINT and Recon]])
subfinder -d target.com -all -silent | anew subs.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | anew subs.txt
for ns in $(dig +short NS target.com); do dig @$ns target.com AXFR; done
```

### Cloud and SaaS Asset Discovery
- [ ] **Cloud bucket and blob hunt:** enumerate S3/GCS/Azure blob names from the org and product names; test for public listing/read.
- [ ] **Cloud IP attribution:** identify which assets live in AWS/Azure/GCP ranges so RoE provider rules apply.
- [ ] **SaaS tenant discovery:** identify Microsoft 365 / Entra tenant, Okta org, Google Workspace, and other identity providers (these drive the auth-attack phase).

### Credential and Secret Leakage
- [ ] **Breach-credential harvest:** collect exposed credentials for in-scope email domains from breach datasets (HaveIBeenPwned domain search, Dehashed, stealer-log dumps). Record source and date; treat as leads, not proof.
- [ ] **Code and secret leakage:** search GitHub/GitLab/Gist for the org's domains, API keys, internal hostnames, and credentials. Check `git` history and CI config, not just current files.
- [ ] **Paste and document leakage:** check paste sites and public document indexes for leaked configs and internal references.
- [ ] **Metadata harvest:** extract usernames, software versions, and internal paths from public documents (PDF/DOCX metadata).

### Email and Identity Posture
- [ ] **SPF policy review:** confirm SPF exists and is not overly permissive (`+all` or broad includes are findings).
- [ ] **DMARC policy review:** confirm DMARC exists and the policy is `p=quarantine`/`p=reject`, not `p=none`. A weak or missing DMARC enables spoofing.
- [ ] **DKIM presence:** confirm DKIM signing is configured.
- [ ] **User/email enumeration prep:** build the candidate username list (firstname.lastname, etc.) from OSINT for the auth phase, mapped to the discovered identity provider.

---

## 3. Active Discovery and Service Enumeration

Now touch the in-scope ranges. Move from "what is alive" to "what is listening" to "what version." Stay rate-aware on flagged fragile hosts.

### Host Discovery
- [ ] **Live-host sweep:** identify responsive hosts across in-scope ranges (ICMP, TCP SYN to common ports, ARP only on local segments). Build the live-host list before full port scans.
- [ ] **Firewall/IPS behavior note:** record whether the perimeter drops vs rejects, and whether rate-limiting or tarpitting is in play (affects scan strategy and timing).

### Port and Service Scanning
- [ ] **Full TCP port scan:** scan all 65535 TCP ports on live hosts, not just the top 1000. Perimeter wins hide on high ports.
- [ ] **Targeted UDP scan:** scan key UDP services (53, 123, 161, 500, 1194, 4500, 5060). UDP is slow and noisy: scope it, and skip on fragile hosts.
- [ ] **Service and version detection:** run version detection and banner grab on open ports. Record product and version for the validation phase.
- [ ] **TLS/SSL inventory:** enumerate TLS certs, SANs, protocols, and ciphers per service (`sslscan`/`testssl.sh`). SAN fields reveal more hostnames; weak TLS is a finding.

```bash
# Anchor only. Full flags and timing profiles in the recon cheatsheet.
nmap -p- --min-rate 1000 -Pn -oA tcp_full <host>
nmap -sUV --top-ports 50 -Pn -oA udp_top <host>
nmap -sV -sC -p <open_ports> -oA svc <host>
```

### Web and Virtual-Host Enumeration
- [ ] **HTTP/HTTPS service screenshotting:** screenshot every web service (`gowitness`/`aquatone`/`httpx -screenshot`) to triage hundreds of hosts fast.
- [ ] **Virtual-host enumeration:** test for name-based vhosts on each web IP (Host-header fuzzing). Default IP response often hides the real app served by hostname.
- [ ] **Technology fingerprinting:** identify web stacks, frameworks, WAFs, and CMS/appliance signatures (`whatweb`, `httpx -td`, Wappalyzer).
- [ ] **Edge-appliance signature triage:** flag any host whose banner/title/cert points to a remote-access appliance (NetScaler/Gateway, Ivanti/Pulse, FortiGate, GlobalProtect, ASA/AnyConnect, SonicWall, BIG-IP, ESXi/vCenter, OWA/Exchange). These are the highest-value targets: route them to Phase 4 edge testing.

---

## 4. Service-by-Service Testing

Test each exposed service for its own weakness class. On the modern perimeter the edge access devices are the crown jewels, so they get their own subsection and the most depth.

### Web Applications and APIs
- [ ] **Per-app triage:** for each in-scope web app, run the surface map (auth model, roles, input points, file upload, API endpoints). Full payloads and per-class methodology live in [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md) and [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md).
- [ ] **Default and exposed content:** check for exposed admin panels, `.git`/`.env`/backup files, directory listing, and default pages.
- [ ] **Known-CVE check on the stack:** map fingerprinted framework/CMS/server versions to known CVEs and validate (do not just trust the banner).
- [ ] **WAF presence and bypass posture:** identify the WAF and whether origin IPs are reachable directly (bypassing the WAF/CDN).

### VPN and Remote-Access Gateways (Edge Devices)
This is where external compromises overwhelmingly start. Fingerprint the exact appliance and build, then map to the device-specific CVEs in [Recent Techniques (2024-2026)](#recent-techniques-2024-2026).
- [ ] **Precise build fingerprint:** pull the exact firmware/version from login pages, error strings, JS bundle hashes, and TLS cert metadata. Vague "FortiGate" is not enough; you need the build to map CVEs.
- [ ] **Citrix NetScaler / Gateway:** identify ADC/Gateway, version, and whether configured as Gateway/AAA vserver. Test for Citrix Bleed and Bleed 2 memory disclosure (session/token leakage) per the recent-techniques section.
- [ ] **Ivanti Connect Secure / Policy Secure (Pulse):** fingerprint ICS/IPS build; check for the 2024-2025 auth-bypass and RCE chain and the integrity-checker state.
- [ ] **Fortinet FortiOS / FortiGate (SSL VPN):** fingerprint FortiOS build; test the SSL VPN endpoint and admin/websocket surface for the known auth-bypass and out-of-bounds RCE classes.
- [ ] **Palo Alto GlobalProtect / PAN-OS:** fingerprint PAN-OS; test GlobalProtect portal and (if reachable) the management web interface for command injection and auth bypass.
- [ ] **Cisco ASA / IOS XE / AnyConnect:** identify ASA/FTD or IOS XE; if the IOS XE Web UI (HTTP/HTTPS server) is exposed, test for the unauthenticated privilege-escalation implant chain.
- [ ] **SonicWall SSL VPN / SonicOS:** fingerprint Gen 6/7 and SSLVPN; check for the access-control and migration-credential issues and recent SSLVPN activity.
- [ ] **F5 BIG-IP:** identify TMUI/iControl REST exposure; test for the iControl REST auth-bypass RCE class. TMUI should never be internet-facing.
- [ ] **VMware ESXi / vCenter:** flag any internet-exposed hypervisor management; treat as critical-by-exposure and test for the known auth-bypass and RCE classes.
- [ ] **IKE/IPsec VPN:** for UDP 500/4500, enumerate IKE, aggressive-mode PSK exposure, and vendor fingerprints.

```
⚠️ Edge-device exploits are frequently memory-corruption or state-corruption bugs that
   can hang or brick the appliance and drop every live VPN user. Confirm exploitation is
   in scope and sign-off is explicit. Prefer non-destructive version/PoC checks (info leak,
   benign marker) over full RCE on a production concentrator. Never run public exploit code
   blind against a live gateway.
```

### Mail Services
- [ ] **SMTP enumeration:** banner-grab MX hosts; test `VRFY`/`EXPN`/`RCPT TO` user enumeration and open-relay behavior.
- [ ] **Exchange / OWA / ECP:** fingerprint Exchange version from OWA/ECP; map to ProxyShell/ProxyNotShell-class CVEs; test Autodiscover and EWS exposure. OWA is also a password-spray target (see Phase 5).
- [ ] **Mail security controls:** confirm STARTTLS, and re-confirm SPF/DKIM/DMARC enforcement from the receiving side.

### Remote Management: RDP and SSH
- [ ] **RDP exposure:** flag internet-facing 3389; check NLA enforcement, cert/CredSSP posture, and BlueKeep-class patch level. Exposed RDP is a spray and ransomware magnet.
- [ ] **SSH exposure:** banner and version; enumerate auth methods (password vs key), weak ciphers, and known-CVE versions.
- [ ] **Other admin protocols:** flag exposed VNC, Telnet, Cockpit, IPMI/BMC (623), and vendor management ports. Any of these on the perimeter is a finding by exposure.

### File and Data Services
- [ ] **SMB/NetBIOS exposure:** flag internet-facing 139/445; check null/guest sessions and signing. SMB should not be on the perimeter.
- [ ] **FTP/TFTP:** test anonymous login and writable directories.
- [ ] **Managed file transfer (MFT):** identify MOVEit, GoAnywhere, Cleo (Harmony/VLTrader/LexiCom), Aspera, and similar. These are a primary ransomware entry class: map to recent CVEs and test.
- [ ] **NFS/rsync/object storage:** check exported shares, anonymous rsync modules, and exposed object endpoints for read/write.

### Databases and Caches Exposed
- [ ] **Direct DB exposure:** flag any internet-reachable MSSQL (1433), MySQL (3306), PostgreSQL (5432), Oracle (1521), MongoDB (27017), Redis (6379), Elasticsearch (9200), or Memcached (11211).
- [ ] **No-auth / default-auth check:** test for unauthenticated access, default creds, and (Redis/Mongo/ES) legacy no-auth defaults. Capture a benign read as proof, never dump real data.

### Named Appliances and IoT
- [ ] **Printers and MFPs:** flag exposed printer web UIs (often leak LDAP/SMB creds and address books).
- [ ] **NAS and backup appliances:** identify Synology/QNAP/Veeam and similar; map to known CVEs.
- [ ] **Network gear admin:** flag exposed router/switch/load-balancer/UPS/iDRAC/iLO management interfaces.

---

## 5. Authentication Attacks

Credential attacks are the single most common real-world perimeter breach path. Do them carefully: lockout policy and detection are part of the test.

### Pre-Conditions and Safety
- [ ] **Lockout policy known:** determine or conservatively assume the account-lockout threshold and reset window BEFORE spraying. Locking out real staff is a stop-the-test event.
- [ ] **Username validity established:** confirm the username format and (where possible) which accounts exist via enumeration, so you spray valid accounts only.
- [ ] **Target surface mapped:** list every auth endpoint that shares the same directory (OWA/EWS, M365/Entra, ADFS, VPN portals, Citrix, SSH, RDP gateway). One valid credential often unlocks several.

```
⚠️ Password spraying can lock out an entire workforce and trigger real IR. Spray ONE
   password per round across many users, then wait out the lockout window before the next
   round. Track attempts per account in writing. Coordinate timing with the client and
   never exceed the agreed attempt budget.
```

### Password Spraying
- [ ] **Low-and-slow spray:** spray a small set of seasonal/contextual passwords one at a time across the validated user list, respecting the lockout window between rounds. Tooling and timing in [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md).
- [ ] **M365 / Entra spray:** spray the discovered tenant's auth endpoints; account for Smart Lockout and conditional-access behavior.
- [ ] **VPN/portal spray:** spray edge-device portals only where lockout behavior is understood and sign-off allows it.
- [ ] **Spray result hygiene:** on a hit, stop hammering that account, record the proof pair, and move to controlled validation. Do not pivot deeper than authorized.

### Credential Stuffing and Breach Reuse
- [ ] **Breach-credential replay:** test harvested breach/stealer credentials against in-scope auth surfaces (respecting lockout). Real reuse is common and high-impact.
- [ ] **Password-reset and policy probing:** check reset flows for user enumeration and weak policy (short minimums, no breach-list blocking).

### Default and Weak Credentials
- [ ] **Appliance default creds:** test vendor defaults on admin panels, appliances, printers, BMCs, and databases (only those in scope).
- [ ] **Service-account weak creds:** check exposed services for blank/weak/guessable creds.

### MFA Gaps
- [ ] **MFA coverage gaps:** identify auth surfaces where MFA is NOT enforced (legacy protocols, basic auth, EWS/Autodiscover, specific VPN groups). A valid credential on a no-MFA endpoint is full access.
- [ ] **Legacy-auth bypass:** test legacy/basic-auth endpoints that sidestep modern MFA and conditional access.
- [ ] **MFA-fatigue feasibility (if contracted):** assess whether push-based MFA is in use and fatigue/bombing is viable. Only attempt prompt bombing against a consenting target account with explicit sign-off.
- [ ] **Token/session reuse:** where a memory-leak edge bug yields a session token (e.g., Citrix Bleed class), test reuse to confirm MFA-bypass impact safely.

---

## 6. Vulnerability Validation and Exploitation

Turn "interesting" into "confirmed" with the least possible blast radius. A perimeter finding must be reproducible and safe. Use [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md) for templated validation at scale.

### Triage and Validation
- [ ] **Template-scan known CVEs:** run curated, version-matched templates against fingerprinted services to confirm exploitability (not just presence). See [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md).
- [ ] **Manual confirmation:** manually verify each scanner/template hit with a captured request/response pair. Treat unconfirmed scanner output as a lead, not a finding.
- [ ] **False-positive cull:** rule out WAF-faked responses, honeypots, default banners that lie about version, and patched-but-fingerprinted hosts.
- [ ] **Severity from impact, not CVSS alone:** rate by realistic external impact (pre-auth RCE on a gateway outranks an info-leak). Capture the chain that gets to impact.

### Safe Exploitation
- [ ] **Non-destructive PoC first:** prove the bug with a benign marker (read a canary file, trigger a controlled callback, leak a non-sensitive value). Avoid writes, service restarts, and memory-corruption payloads on fragile/production hosts.
- [ ] **No DoS, no data exfil:** never run availability-impacting exploits or pull real customer data. If impact can only be shown destructively, document the path and stop, then discuss with the client.
- [ ] **Public-exploit hygiene:** read and understand any public exploit before use; strip miner/backdoor stubs; test against a lab build first where feasible.
- [ ] **Chain validation:** for multi-step chains (auth-bypass to RCE), validate each link and document the full path with evidence at each stage.

```
⚠️ Exploitation on the perimeter is high-stakes: one wrong payload can drop a production
   VPN, encrypt nothing but break everything, or trip a real ransomware-style alert. Get
   explicit per-target sign-off for any active exploitation, prefer info-leak/benign-marker
   proofs, and keep the deconfliction channel open while you do it.
```

---

## 7. Initial Access and Foothold

Once a confirmed exploitable vuln yields code execution or valid credentials, establish a stable, authorized foothold and document it. See [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md) for payload and transfer tradecraft, and [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md) for the social-engineering path.

### Establishing Access
- [ ] **Edge-device RCE foothold:** where an appliance bug yields execution, capture the proof (whoami/id, hostname, a benign marker write) and the exact request. Avoid persistence on the appliance unless contracted.
- [ ] **Web-shell or callback:** where a web/app bug yields execution, establish a controlled shell/callback through your registered redirector. Payloads in [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md).
- [ ] **Credentialed access:** where auth attacks yield valid creds, log in through the intended channel (VPN/portal/RDP) and capture the authenticated session as proof.
- [ ] **Phishing handoff (if contracted):** for the assumed-breach or social path, run the campaign per [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md) and capture credential-capture or payload-execution evidence.

### Foothold Hygiene
- [ ] **Stable but minimal:** keep the foothold stable enough to demonstrate impact but minimal in footprint. Prefer in-memory and reversible over installed persistence.
- [ ] **Inventory what you touched:** log every host, file, account, and config you created or modified for the cleanup and report appendices.
- [ ] **Sensitive-data restraint:** confirm access to sensitive data with a benign indicator (file name/listing, a canary record), do not exfiltrate real records.

### Cleanup Tracking
- [ ] **Artifact removal plan:** list web shells, dropped binaries, created accounts, scheduled tasks, and config changes to remove at end of test, and remove them.
- [ ] **Credential disclosure:** record any client credentials you obtained so they can be rotated, and hand them over securely at debrief.

---

## 8. Post-Exploitation Pivot to Internal

The external test ends at the perimeter unless internal testing is in scope. If it is, this is the handoff into the internal/AD methodology. See [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md) and the [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md) checklist.

### Internal Reachability
- [ ] **Pivot established:** from the foothold, set up an authorized tunnel/proxy into the internal network (per [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)). Confirm reachability with a benign internal probe.
- [ ] **Internal recon (light):** map immediately reachable internal hosts and services from the foothold to scope the internal phase. Stay within authorized depth.
- [ ] **Credential and secret sweep on foothold:** check the compromised host/appliance for stored credentials, config secrets, session tokens, and connection strings that enable lateral movement.

### Handoff to Internal Methodology
- [ ] **Domain context check:** determine whether the foothold is domain-joined or reaches AD; if so, transition to the [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md) checklist for the internal phase.
- [ ] **Impact narrative built:** assemble the end-to-end external-to-internal path (internet to perimeter to internal asset) as the headline finding.
- [ ] **Stop at authorized depth:** do not pivot beyond the contracted scope. If the path leads somewhere out of scope, document the reachability and stop.

---

## Recent Techniques (2024-2026)

The current perimeter-breach wave is dominated by pre-auth bugs in edge access devices and managed file transfer, plus identity attacks against M365. Fingerprint the exact build, then check the device-specific items below.

### Edge-Device Exploitation Wave
- [ ] **Ivanti Connect Secure auth-bypass + RCE chain (CVE-2024-21887, CVE-2023-46805):** command injection chained with an auth bypass on ICS/IPS. Test for: unauth access to admin web components and command-injection markers on unpatched ICS builds.
- [ ] **Ivanti Connect Secure RCE (CVE-2025-0282, CVE-2025-0283):** unauthenticated stack buffer overflow (0282) to RCE, plus a local priv-esc (0283), exploited from late 2024. Test for: vulnerable ICS build via version fingerprint and integrity-checker state; treat exploitation as destructive, prefer version-based confirmation.
- [ ] **Citrix Bleed (CVE-2023-4966):** out-of-bounds read in NetScaler ADC/Gateway leaking session tokens for MFA-bypassing session hijack. Test for: token/memory leakage from the Gateway/AAA vserver, then session reuse.
- [ ] **Citrix Bleed 2 (CVE-2025-5777):** uninitialized-memory overread via a malformed login POST (missing `login` value) returning stack data in `<InitialValue>`. Test for: send the malformed auth POST and check the response body for leaked memory; mass-exploited since mid-2025.
- [ ] **FortiOS SSL VPN OOB write RCE (CVE-2024-21762):** out-of-bounds write in SSLVPNd, pre-auth RCE. Test for: vulnerable FortiOS build on the SSL VPN endpoint; prefer version confirmation over live OOB payloads.
- [ ] **FortiOS auth bypass (CVE-2024-55591):** alternate-path auth bypass via the Node.js websocket module granting super-admin, exploited since November 2024. Test for: unauth admin actions and rogue admin/SSL-VPN user creation artifacts on FortiGate.
- [ ] **Palo Alto GlobalProtect command injection (CVE-2024-3400):** arbitrary file creation to command injection, unauth root RCE on PAN-OS GlobalProtect. Test for: the file-creation primitive against the GlobalProtect feature on vulnerable builds.
- [ ] **PAN-OS management auth bypass (CVE-2025-0108):** Nginx/Apache path-confusion bypass on the management web interface, chained with CVE-2024-9474 / CVE-2025-0111 for root. Test for: reachable management interface and the path-confusion bypass; management UI should never be internet-facing.
- [ ] **Cisco IOS XE Web UI priv-esc (CVE-2023-20198) + implant (CVE-2023-20273):** unauth account creation via the exposed Web UI, then privilege elevation and an implant. Test for: exposed HTTP/HTTPS server feature and the implant-presence indicator (`/webui/logoutconfirm.html?logon_hash=1`).
- [ ] **SonicWall SSLVPN access control (CVE-2024-40766):** improper access control plus carried-over migration passwords on Gen7 SonicOS, abused by Akira ransomware through 2025. Test for: vulnerable SonicOS build and unreset local accounts on SSLVPN.
- [ ] **Cleo MFT unauth file write to RCE (CVE-2024-50623, CVE-2024-55956):** unrestricted upload/download (0623, incompletely patched) and Autorun-directory unauth command execution (55956), used by Clop. Test for: the Autorun/upload primitive on Harmony/VLTrader/LexiCom builds.
- [ ] **VMware ESXi AD auth bypass (CVE-2024-37085):** recreate the `ESXi Admins` AD group to gain full host admin on domain-joined ESXi (ransomware-favored). Test for: internet-exposed ESXi management and AD-integration posture.
- [ ] **VMware ESXi VMX escape (CVE-2025-22224 + siblings):** TOCTOU out-of-bounds write to code execution as the VMX process. Relevant when ESXi management is exposed or reachable post-foothold.
- [ ] **F5 BIG-IP iControl REST auth bypass:** TMUI/iControl REST exposure to auth-bypass RCE class. Test for: internet-facing TMUI/iControl and version-mapped CVEs.
- [ ] **Exchange ProxyShell / ProxyNotShell class:** version-map exposed OWA/ECP/Autodiscover to the known SSRF-to-RCE chains. Test for: vulnerable Exchange build and reachable ECP/Autodiscover.

### Identity and Credential Trends
- [ ] **Infostealer-fed credential stuffing:** stealer-log credentials drive large-scale M365 access; replay harvested creds against tenant auth (respecting lockout).
- [ ] **Botnet password spraying against M365:** distributed low-and-slow spray from large botnets evades simple lockout/IP throttles. Mirror the low-and-slow approach and check whether the tenant detects it.
- [ ] **MFA fatigue / push bombing (MITRE T1621):** repeated push prompts until a user approves; up sharply year over year. Only with explicit per-account sign-off, assess whether push MFA is fatigue-vulnerable.
- [ ] **Adversary-in-the-middle phishing kits:** reverse-proxy kits (Evilginx-class, iframe-injection lures) capture session cookies to bypass MFA. Relevant to the phishing-handoff path where contracted.
- [ ] **Legacy-auth / device-code abuse:** legacy protocols and OAuth device-code flows bypass conditional access and MFA. Test for legacy-auth reachability and weak conditional-access coverage.

---

## Reporting and Evidence

### Evidence to Capture per Finding
- [ ] **Raw request/response pair:** save the exact HTTP (or protocol) request and response that proves each finding, to file, at test time. A screenshot of the proven condition supplements but does not replace the raw pair.
- [ ] **Reproduction steps:** record the minimal, ordered steps to reproduce, including source IP, timestamp, and exact target.
- [ ] **Scope and asset context:** for each finding note the host, port, service, and exact fingerprinted build/version.
- [ ] **Impact proof:** capture the benign-marker proof (canary read, controlled callback, leaked non-sensitive value, authenticated session) rather than destructive impact.
- [ ] **Chain documentation:** for multi-step findings, evidence each link so the chain stands on its own.

### Severity Guidance
| Severity | Typical external example |
| --- | --- |
| Critical | Pre-auth RCE or auth bypass on an internet-facing edge device; exposed unauth admin of a gateway; direct internet-to-internal path |
| High | Valid credentials with no MFA on a remote-access surface; pre-auth memory/token leak enabling session hijack; exposed DB with real data access |
| Medium | Authenticated/limited-impact vuln; user enumeration enabling targeted spray; weak TLS/old protocol on a sensitive service |
| Low | Information disclosure with no direct path to access; verbose banners; missing security headers |
| Info | Hardening and hygiene observations with no demonstrated impact |

### Common False Positives to Rule Out
- [ ] **Version-banner lies:** appliances and backports may report a version that does not reflect the patch state. Confirm exploitability, do not rate on banner alone.
- [ ] **WAF-faked responses:** a WAF can return success/error pages that mimic a vulnerable app. Confirm against the origin.
- [ ] **Honeypots and tarpits:** an unusually "everything is open" host may be a decoy. Sanity-check before reporting.
- [ ] **Scanner-only hits:** never report an unconfirmed scanner/template result. Manually validate every one.
- [ ] **Out-of-scope provider assets:** confirm a flagged asset is actually the client's and in scope before including it.

---

## Tools and References

| Purpose | Tools |
| --- | --- |
| Subdomain / passive recon | subfinder, amass, crt.sh, securitytrails, dnsx, httpx |
| Breach / leak intel | HaveIBeenPwned, Dehashed, stealer-log sources, gitleaks, trufflehog |
| Port / service scanning | nmap, masscan, naabu, rustscan |
| Web triage / screenshotting | httpx, gowitness, aquatone, whatweb, Wappalyzer |
| TLS inspection | testssl.sh, sslscan |
| Vuln validation | nuclei (version-matched templates), per-vendor PoCs |
| Auth attacks | NetExec (nxc), Impacket, Hydra, MSOLSpray / spray tooling |
| Proxy / manual testing | Burp Suite, mitmproxy |

References:
- OWASP Web Security Testing Guide (WSTG) for the web-app surface
- OWASP ASVS for control-coverage framing
- PTES (Penetration Testing Execution Standard) for phase structure
- NIST SP 800-115 for technical assessment methodology
- CISA Known Exploited Vulnerabilities (KEV) catalog for prioritizing edge-device CVEs
- Vendor security advisories (Citrix, Ivanti, Fortinet, Palo Alto, Cisco, SonicWall, F5, VMware, Microsoft Exchange)

---

## Related

- Playbooks: [Edge Device Exploit to Internal Foothold](../Playbooks/Edge%20Device%20Exploit%20to%20Internal%20Foothold.md), [Blind SSRF to Cloud Metadata RCE](../Playbooks/Blind%20SSRF%20to%20Cloud%20Metadata%20RCE.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md)
- [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md)
- [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
