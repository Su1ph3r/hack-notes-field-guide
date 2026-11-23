---
tags:
  - hack-notes
  - checklist
  - network
  - infrastructure
---

# Firewall and Network Device Review Testing Checklist

> Configuration review and security assessment of firewalls and network devices (Palo Alto PAN-OS, Fortinet FortiOS, Cisco ASA/IOS/IOS-XE/Firepower, Check Point, Juniper, SonicWall). Covers offline config-audit (ruleset and hardening review from exports) and active testing (firewalking, segmentation validation, edge-CVE exposure). Run Vallum for automated config audit first, then work the active phases against the live devices.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Device Hardening and Management Plane](#2-device-hardening-and-management-plane)
- [3. Ruleset and Policy Review](#3-ruleset-and-policy-review)
- [4. Segmentation and Zoning](#4-segmentation-and-zoning)
- [5. VPN and Remote Access](#5-vpn-and-remote-access)
- [6. NAT and Exposure](#6-nat-and-exposure)
- [7. Active Testing](#7-active-testing)
- [8. Logging, Monitoring, and Failover](#8-logging-monitoring-and-failover)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Network gear is high-blast-radius. A bad rule push or a `commit` on a live perimeter device can black-hole production traffic. Lock down scope and safety before touching anything.

### Scope and Inputs
- [ ] **Confirm engagement type:** config-audit (offline review of exports), active testing (live firewalking/segmentation), or both. The two have very different blast radii. Get explicit sign-off for each.
- [ ] **Collect the device inventory:** vendor, model, OS version, role (perimeter, internal, DMZ, DC edge, VPN concentrator), HA pair membership, and management IP. Build a device matrix you can track findings against.
- [ ] **Obtain config exports per device** in native format so Vallum and Nipper can parse them:
  - Palo Alto: `set` format or exported running config XML (`scp export configuration`).
  - Fortinet: `show full-configuration` or the backed-up `.conf`.
  - Cisco ASA: `show running-config` (request `more system:running-config` for unmasked secrets if authorized).
  - Cisco IOS / IOS-XE: `show running-config` plus `show version`.
  - Check Point: exported policy package and `cpinfo` / Gaia config.
  - Juniper: `show configuration | display set`.
- [ ] **Confirm exports are complete and unredacted enough to audit:** masked password hashes are fine, but redacted ACLs/objects make ruleset review impossible. Flag missing sections early.
- [ ] **Get management-plane access** if active hardening checks are in scope (read-only admin account preferred). Note the access method (HTTPS GUI, SSH CLI, API key) and source IP that is allowed.
- [ ] **Identify the source-test network:** where you launch active tests from (which VLAN/zone). Segmentation results are only meaningful relative to a known origin.

### Safety and Change Control
- [ ] **Establish a maintenance/test window** for any active testing that could degrade throughput (scan storms, VPN brute, fail-open tests).
- [ ] **Identify change-control process** and confirm you will make NO config changes. Read-only on production unless a lab/standby device is provided.
- [ ] **Get an emergency contact** (network on-call) and rollback owner for the duration of active testing.
- [ ] **Confirm HA behavior:** know whether the pair fails over on probe-induced CPU spikes and whether session sync will replicate any test artifacts.

```
⚠️ Do NOT run aggressive scans, VPN credential brute, or fail-open/fail-closed tests against a
production perimeter device outside an approved window. A firewalking sweep can exhaust the session
table or trip IPS auto-block and self-inflict a DoS. Throttle, and have the network on-call standing by.
```

- [ ] **Define out-of-scope IPs/services** (e.g. the SCADA segment, third-party managed links, partner extranets) and load them into a do-not-touch list.

---

## 2. Device Hardening and Management Plane

The management plane is the crown jewel: own it and you own every rule. The 2024-2026 edge-device wave (PAN-OS, FortiOS, Cisco IOS-XE) was almost entirely management-interface and VPN-portal exposure. Hit this phase hard.

### Management Interface Exposure
- [ ] **Determine where the management interface is reachable from.** It must be on a dedicated mgmt network or restricted to named admin IPs, never any/any or the untrust/Internet zone. This is the single highest-value finding in modern reviews.
  - PAN-OS: check `Device > Setup > Management > Permitted IP Addresses` and whether the mgmt profile on data interfaces enables HTTPS/SSH.
  - FortiOS: check `set allowaccess` per interface for `https ssh http telnet` on any untrust/WAN interface.
  - Cisco ASA: `http`/`ssh`/`telnet` statements scoping source nets; look for `0.0.0.0 0.0.0.0`.
  - IOS-XE: `ip http server` / `ip http secure-server` enabled with no ACL is the CVE-2023-20198 precondition.
- [ ] **Active check (if in scope):** from an untrusted segment, probe mgmt ports and flag any reachable admin surface.
```bash
nmap -Pn -p 22,23,443,4443,8443,10443 --open <device-ip>
# PAN-OS mgmt often 443; FortiGate GUI 443/tcp or custom; ASA ASDM 443; IOS-XE WebUI 443
```
- [ ] **Verify mgmt is not co-located with data plane** on a single interface where a data-plane bug exposes admin functions.

### Admin Authentication and MFA
- [ ] **Check for default or weak credentials** (admin/admin, admin/<blank>, vendor defaults). Confirm the default admin account was renamed or disabled.
- [ ] **Verify MFA on administrative login** (GUI and CLI). Local-only single-factor admin on a perimeter device is a finding.
- [ ] **Review password policy:** min length, complexity, lockout threshold, and admin idle-timeout. Flag absent lockout (enables the credential-stuffing seen in the SonicWall/Akira campaigns).
- [ ] **Check for shared admin accounts** and confirm per-admin accountability (named accounts, not a single `admin`).
- [ ] **Review role-based access (RBAC):** read-only vs superuser separation; no unnecessary superusers.

### Firmware and Known CVEs
- [ ] **Record exact OS version and build** per device and map to vendor PSIRT advisories and the CISA KEV catalog. Edge devices are the most-exploited class in 2024-2026; an out-of-date FortiOS/PAN-OS/IOS-XE is often the highest finding in the report.
- [ ] **Cross-reference the live edge CVEs** in [Recent Techniques (2024-2026)](#recent-techniques-2024-2026) against each device's version. Run [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md) version-detection templates for fast confirmation where active testing is allowed.
- [ ] **Check end-of-life status:** EoL hardware/firmware that can no longer receive patches is a standalone finding.

### Insecure Services and Protocols
- [ ] **Telnet:** must be disabled everywhere. Cleartext admin = finding.
- [ ] **SSH:** version 2 only; flag weak KEX/cipher/MAC (diffie-hellman-group1, CBC, hmac-md5) and any v1 fallback.
- [ ] **HTTP (non-TLS) management:** disabled. Redirect-to-HTTPS only is acceptable, plaintext admin is not.
- [ ] **Management TLS:** flag SSLv3/TLS 1.0/1.1, self-signed/expired certs on the mgmt portal, and weak cipher suites.
- [ ] **SNMP:** flag SNMPv1/v2c with default community strings (`public`, `private`) or any community string readable in the config. Require SNMPv3 with auth+priv. A readable RW community = device takeover.
```bash
snmp-check <device-ip> -c public        # confirm v1/v2c read access
onesixtyone <device-ip> public private  # community-string sweep
```
- [ ] **Disable unused services:** finger, BOOTP, DHCP, web-cache, vendor cloud-management agents not in use.

### Time, Logging, and AAA
- [ ] **NTP configured** and pointed at trusted internal servers (accurate timestamps are required for forensics and correlation).
- [ ] **Logging enabled** to a central syslog/SIEM, including config-change and admin-login events. Local-only logging on a perimeter device is a finding (and attackers disable syslog forwarding, per the Ivanti CVE-2025-0282 TTPs).
- [ ] **AAA / TACACS+ / RADIUS** for admin auth where present: verify the shared secret is not weak/default, the server is reachable over a protected path, and there is a sane fallback (local account that is NOT the default, with break-glass procedure).
- [ ] **Banner / login warning** present where required by policy.

---

## 3. Ruleset and Policy Review

The ruleset is where intent meets reality. Audit it for permissiveness, hygiene, and documentation. Vallum flags most of these automatically across vendor syntaxes; use this phase to validate and contextualize its output rather than eyeballing thousands of rules by hand.

### Overly Permissive Rules
- [ ] **Any-any-any rules:** flag every rule with `any` source, `any` destination, and `any` service/application. On a perimeter device this is critical. Note position (an early any-any shadows everything below it).
- [ ] **Any-source inbound rules** to internal services. Internet-to-internal on broad ports is a finding unless justified.
- [ ] **Overly broad service objects:** rules permitting `any` service, large port ranges (e.g. 1-65535), or `tcp/any` where a single port would do.
- [ ] **Permit-all egress:** outbound `any` with no filtering. Lack of egress control enables C2, data exfil, and lateral tunneling. Cross-reference with [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md) for what unfiltered egress lets an attacker do.
- [ ] **Management-from-any rules:** any rule allowing SSH/HTTPS/SNMP to the device or to other infra mgmt from broad sources (ties back to Phase 2).

### Rule Hygiene
- [ ] **Shadowed rules:** a broad rule above a specific one makes the specific rule unreachable. Flag (dead rule, masks intent and audit trail).
- [ ] **Duplicate / redundant rules:** identical or fully-overlapping rules indicate drift and bloat.
- [ ] **Unused rules:** zero hit-count rules over a meaningful window. Pull hit counters where the device tracks them.
  - PAN-OS: `show rule-hit-count`. ASA: `show access-list | include hitcnt=0`. FortiOS: policy hit count in GUI/`diagnose firewall`.
- [ ] **Expired/temporary rules:** "temp open for migration" rules with no expiry that never got removed.
- [ ] **Disabled rules left in config:** clutter that hides intent; recommend removal.
- [ ] **Overlapping/contradictory rules:** a later deny that can never fire because an earlier permit matched.

### Documentation and Justification
- [ ] **Rule descriptions/comments present** with business justification, owner, and ticket/change reference. Undocumented permit rules cannot be validated and should be flagged for recertification.
- [ ] **Object naming hygiene:** descriptive named objects vs raw IPs/ranges inline. Bare CIDR blocks in rules are hard to audit and recertify.
- [ ] **Recertification evidence:** check for a periodic firewall-rule review process. Absence is a process finding (and a PCI/ISO gap).
- [ ] **Default policy is deny-all** at the end of each ruleset/zone-pair. An implicit or explicit trailing `permit any` is critical.

### Zone and Interface Design (config-level)
- [ ] **Map interfaces to security zones** and confirm trust levels are sane (no WAN interface in a trust zone).
- [ ] **Confirm inter-zone default is deny** and traffic only flows where a rule explicitly allows it.
- [ ] **Check for "intrazone allow" defaults** (PAN-OS allows intrazone by default) that may unintentionally permit broad same-zone traffic.

---

## 4. Segmentation and Zoning

Segmentation is the control most often claimed and least often verified. The config tells you intent; only active testing tells you reality. Build an allowed-path matrix from policy, then prove or break it in Phase 7.

### Design Review
- [ ] **DMZ design:** confirm public-facing services sit in a DMZ that cannot initiate connections into the internal/trust zone except on tightly-scoped, justified ports. A DMZ host with broad inbound access to internal = failed segmentation.
- [ ] **East-west controls:** verify lateral traffic between internal segments (user VLANs, server VLANs, OT/IoT, PCI/CDE) is filtered, not just north-south. Flat internal networks behind a hard perimeter are a recurring finding.
- [ ] **Critical-asset isolation:** DC/management/PCI/OT segments have explicit allow-lists in and out, default-deny otherwise.
- [ ] **Microsegmentation:** where claimed (NSX, host firewalls, ACI, security groups), confirm enforcement points exist between workloads and are not bypassable via a shared flat VLAN.
- [ ] **VLAN-to-zone mapping:** confirm VLANs map to enforced zones and there is no inter-VLAN routing that sidesteps the firewall (router-on-a-stick or L3 switch SVIs that bypass policy).

### Segmentation Testing Methodology
- [ ] **Build the allowed-path matrix** from the ruleset: for each source zone/segment, list which destination segments and ports policy permits. This is your test oracle.

| Source Segment | Destination Segment | Allowed (policy) | Observed (tested) | Verdict |
| --- | --- | --- | --- | --- |
| User VLAN | Server VLAN | tcp/443, tcp/3389 | _to fill_ | _pass/fail_ |
| User VLAN | CDE/PCI | none (deny) | _to fill_ | _pass/fail_ |
| DMZ | Internal | none (deny) | _to fill_ | _pass/fail_ |
| Guest WiFi | Corp/anything | none (deny) | _to fill_ | _pass/fail_ |
| OT/SCADA | IT | none/scoped | _to fill_ | _pass/fail_ |

- [ ] **Test allowed paths** to confirm policy works as intended (positive testing): a path policy says is open should be open.
- [ ] **Test denied paths** to confirm isolation holds (negative testing): every cell marked `none/deny` must be unreachable from the stated source. A reachable deny-cell is a segmentation-bypass finding.
- [ ] **Test from each defined origin segment**, not just one. Segmentation is asymmetric; results differ per source VLAN.
- [ ] **Probe TCP, UDP, and ICMP** separately. A path closed on TCP may be open on UDP/ICMP, and ICMP often slips through.
- [ ] **Test the full port range, not just common ports.** Use the active-testing tooling in Phase 7. A "closed" verdict from a 100-port scan is satisficing; sweep all 65535 where the window allows.

---

## 5. VPN and Remote Access

VPN portals are the other half of the 2024-2026 edge wave. Every major vendor shipped a pre-auth VPN/portal RCE or auth-bypass in this window. Treat any exposed SSL-VPN/IPsec gateway as a primary target.

### SSL-VPN / IPsec Configuration
- [ ] **Inventory exposed VPN portals** and map their exact version to the edge CVEs in [Recent Techniques (2024-2026)](#recent-techniques-2024-2026). An unpatched SSL-VPN portal is frequently the highest finding in the engagement.
- [ ] **Weak IKE/IPsec proposals:** flag IKEv1 aggressive mode, DH groups 1/2/5, DES/3DES, MD5/SHA1, and PSK auth where cert-based is feasible. Aggressive mode with PSK is offline-crackable.
```bash
ike-scan -M -A <gateway-ip>     # detect IKEv1 aggressive mode + grab PSK hash material
```
- [ ] **TLS posture of the SSL-VPN portal:** flag TLS 1.0/1.1, weak ciphers, missing HSTS, self-signed/expired certs. Run [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md) TLS templates.
- [ ] **Split tunneling:** confirm whether enabled. If full-tunnel is required by policy, flag split-tunnel as a data-exfil/visibility gap; if split-tunnel is allowed, confirm the routes do not leak internal ranges or bypass egress inspection.
- [ ] **VPN client-to-internal access scope:** confirm VPN users land in a restricted zone with its own ruleset, not directly onto flat internal. The Fortinet CVE-2024-55591 TTPs specifically abused SSL-VPN tunnels into internal after creating rogue accounts.

### Remote-Access Authentication
- [ ] **MFA on VPN login (all portals):** mandatory. Single-factor SSL-VPN is the entry point in most ransomware intrusions this cycle (Akira/SonicWall). Confirm MFA cannot be bypassed (see CVE-2024-12802).
- [ ] **Account lockout / rate-limiting** on the VPN auth endpoint to stop credential stuffing and brute. Absent lockout is a finding.
- [ ] **Legacy-credential carryover:** on devices migrated between hardware generations (e.g. SonicWall Gen6 to Gen7), confirm local accounts/passwords were reset, not imported. Imported legacy creds drove the Akira campaign.
- [ ] **Orphaned/stale VPN accounts:** dormant or ex-staff accounts still enabled.
- [ ] **Default/local VPN admin portals** reachable that should be internal-only (clientless portals, SPA/management consoles).

---

## 6. NAT and Exposure

NAT and port-forwarding quietly expose internal services. Enumerate everything reachable from outside and tie each back to a justified rule.

- [ ] **Enumerate all inbound NAT / port-forward / DNAT rules.** For each, record external IP:port to internal host:port and confirm a documented business need.
- [ ] **Flag exposed internal/management services** published via NAT: RDP, SSH, SMB, database ports, IPMI/iLO/iDRAC, hypervisor consoles, and device mgmt should never be NATed straight to the Internet.
- [ ] **Map external attack surface** independently of the config and reconcile against the NAT table. Anything reachable that the NAT table does not explain is a finding (rogue/forgotten forward). See [External Network Penetration Test](External%20Network%20Penetration%20Test.md).
```bash
nmap -Pn -sV --top-ports 1000 <external-range>   # reconcile against documented NAT rules
```
- [ ] **Hairpin / NAT-loopback:** check whether internal hosts can reach published services via the external IP and whether that path bypasses internal segmentation or inspection.
- [ ] **Overlapping/identity NAT and no-NAT rules** that unintentionally expose internal ranges or break the intended deny path.
- [ ] **Outbound NAT scope:** confirm source-NAT does not mask which internal segment originated traffic in a way that defeats egress logging/attribution.

---

## 7. Active Testing

Validate the paper findings against the live device. This is where segmentation claims live or die. Stay inside the approved window and throttle.

### Firewalking and Ruleset Validation
- [ ] **Firewalk to discover which ports a gateway forwards** for a given destination (uses TTL expiry past the firewall):
```bash
firewalk -S 1-65535 -i eth0 -n -pTCP <firewall-ip> <target-behind-fw>
```
- [ ] **Cross-check live reachability against the allowed-path matrix** from Phase 4. Every deviation (open where policy says deny, closed where policy says allow) is a finding or a ruleset-accuracy issue.
- [ ] **Validate rule order effects:** confirm shadowed rules really are unreachable and that early broad permits are not allowing more than intended.
- [ ] **Test both TCP and UDP** and confirm stateful behavior (does the device permit unsolicited inbound that should require established state).

### Egress Filtering Test
- [ ] **Test outbound on a wide port range** from an internal segment to a controlled external listener. Unfiltered egress = C2/exfil path.
```bash
# from internal host, with a listener you control on the outside:
for p in 21 22 23 53 80 443 445 1433 3389 4444 8080 8443 53/udp; do
  nc -w2 -z <external-listener> ${p%/*}; done
# or use an egress-check service / your own catch-all to log which ports land
```
- [ ] **Test DNS/ICMP/HTTP-CONNECT egress** specifically (common tunneling channels). Confirm whether DNS exfil and ICMP tunneling are possible. See [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md).
- [ ] **Test protocol-vs-port mismatch** if the device claims app-layer filtering (e.g. SSH over 443, non-HTTP over 80) to see whether app-ID/DPI actually enforces or just port-filters.

### Segmentation Validation
- [ ] **Execute the negative-path tests** from the Phase 4 matrix from each source segment. Any reachable deny-cell is a segmentation-bypass finding with concrete evidence.
- [ ] **Sweep the full port range on deny-paths**, not a sample, before declaring a segment isolated.
- [ ] **Test inter-VLAN routing bypass:** confirm traffic between VLANs is actually forced through the firewall and not switched/routed around it via an L3 switch SVI.

### IDS/IPS and Evasion Awareness
- [ ] **Determine whether IPS is in-line (blocking) or passive (detect-only)** and inline-fail behavior. Note this affects all active-test results.
- [ ] **Note auto-block behavior:** scanning may trigger IP auto-quarantine and skew later results (and self-DoS). Account for it; do not interpret an auto-blocked source as "segmentation working."
- [ ] **Awareness-level evasion checks** (only as authorized): fragmentation, slow-scan, and protocol-mismatch to gauge whether the IPS inspects or merely passes. Document detection gaps; do not weaponize against production.

```
⚠️ Egress, firewalking, and full-range segmentation sweeps generate heavy traffic and can trip IPS
auto-block or fill the session table. Run inside the window, throttle scan rate, and coordinate with
the network on-call so an auto-block or failover is recognized as test-induced, not an incident.
```

---

## 8. Logging, Monitoring, and Failover

A device that does not log or fails open is a control gap even with a perfect ruleset.

### Logging and Monitoring
- [ ] **Confirm traffic logging on deny and key allow rules**, not just denies. Allow-logging on sensitive paths is needed for incident response.
- [ ] **Confirm admin-action and config-change logging** is enabled and forwarded off-box (attackers disable local logging first).
- [ ] **Verify log forwarding to SIEM/syslog over a protected path** and that the collector is actually receiving (check for gaps). Local-only or unmonitored logs = no detection.
- [ ] **Check log retention** meets policy/compliance (PCI 1 year, etc.).
- [ ] **VPN and auth logging:** confirm successful/failed VPN logins and MFA events are logged and alerted (this is what catches the SonicWall-style intrusions early).

### High Availability and Failover
- [ ] **Confirm HA pairing** (active/passive or active/active), heartbeat link health, and config/session sync status.
- [ ] **Verify failover does not drop to a less-secure state** (no policy reset, no temporary any-any, secondary runs the same patched OS version as primary).
- [ ] **Fail-open vs fail-closed:** determine the device's behavior on overload, license expiry, or subsystem crash. A perimeter device that fails OPEN (passes traffic uninspected) on IPS/license failure is a critical finding. Confirm the configured/default behavior and, if a window allows, validate it.
- [ ] **Bypass/maintenance modes:** check for hardware bypass NICs or maintenance toggles that route around inspection, and confirm they are not silently engaged.
- [ ] **Config backup and integrity:** confirm regular off-box config backups exist and that an integrity-check / tamper-detection capability is enabled (the Ivanti intrusions specifically defeated the on-box Integrity Checker, so off-box validation matters).

---

## Recent Techniques (2024-2026)

The dominant theme of this window is pre-auth exploitation of perimeter VPN portals and management interfaces, followed by rogue-account creation and SSL-VPN tunneling into flat internal networks. Map every device's exact version to these and run Vallum + [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md) to confirm exposure.

### Fortinet FortiOS / FortiProxy
- [ ] **CVE-2024-21762** (FortiOS SSLVPNd out-of-bounds write, CVSS 9.8, pre-auth RCE; CISA KEV, Volt Typhoon): test for vulnerable SSL-VPN versions; confirm patch level on any FortiGate with SSL-VPN enabled.
- [ ] **CVE-2024-55591** (FortiOS/FortiProxy Node.js websocket auth-bypass to super-admin, CVSS 9.6; exploited from Nov 2024): test for vulnerable 7.0.x; check for attacker artifacts (rogue admin/local accounts, SSL-VPN user-group additions, modified policies).
- [ ] **FortiGate config leak (Belsen Group, Jan 2025):** ~15k device configs/creds dumped publicly. Treat any historically-exposed FortiGate's credentials and PSKs as compromised; check for and rotate.

### Palo Alto PAN-OS
- [ ] **CVE-2024-3400** (GlobalProtect gateway command injection, CVSS 10.0, pre-auth root; KEV): test only firewalls with GlobalProtect gateway AND device telemetry enabled; confirm patched.
- [ ] **CVE-2025-0108** (PAN-OS mgmt web-interface auth-bypass via Nginx/Apache/PHP path confusion): test for unauthenticated PHP-script access on the mgmt interface; chained in the wild with CVE-2024-9474 and CVE-2025-0111 for full compromise.
- [ ] **Management-interface exposure:** the common precondition across the PAN-OS chain. Confirm the mgmt web interface is NOT internet-reachable (Phase 2).

### Cisco IOS XE / ASA / Firepower
- [ ] **CVE-2023-20198** (IOS-XE Web UI privilege-escalation, CVSS 10.0; mass-exploited, BadCandy implant) chained with **CVE-2023-20273** (command injection to root): confirm `ip http server`/`secure-server` is disabled or ACL-restricted. Implant check:
```bash
curl -k -X POST "https://<device-ip>/webui/logoutconfirm.html?logon_hash=1"
# a hex string in the response indicates the implant is present
```
- [ ] **Cisco ASA/FTD VPN web-services CVEs (ArcaneDoor wave):** confirm WebVPN/AnyConnect services are patched and management is restricted; check for unexplained config persistence.

### Ivanti Connect Secure (VPN edge)
- [ ] **CVE-2025-0282 / CVE-2025-0283** (Connect Secure stack buffer overflow, pre-auth RCE; exploited from Dec 2024 by UNC5337): test version; look for disabled SELinux/syslog, remounted FS, and web shells. Off-box integrity validation (on-box ICT was defeated).
- [ ] **CVE-2023-46805 + CVE-2024-21887** (auth-bypass + command injection chain, UNC5221): the original wave; ZIPLINE/LIGHTWIRE/WARPWIRE implants, domain-cred harvesting, and segmentation bypass into internal.

### SonicWall
- [ ] **CVE-2024-40766** (improper access control, SSL-VPN, CVSS 9.3; Akira ransomware, login-to-encryption in under 4 hours): confirm patch; on Gen6-to-Gen7 migrations, confirm local creds were RESET not imported.
- [ ] **CVE-2024-12802** (SSL-VPN MFA bypass, brute-forceable from early 2026): confirm MFA enforcement cannot be sidestepped and that lockout/rate-limiting is in place.

### Cross-Cutting Tradecraft
- [ ] **Rogue admin/local-account creation post-exploit:** audit account lists on edge devices for accounts not in your inventory; a recurring TTP across FortiOS, PAN-OS, and IOS-XE.
- [ ] **Syslog/SELinux disablement:** attackers blind the device first. Confirm off-box logging would have captured the gap.
- [ ] **Edge-to-internal pivot via SSL-VPN:** once an edge device is owned, flat internal networks fall fast. This is why Phase 4 segmentation testing matters even when the perimeter "looks fine."

---

## Reporting and Evidence

### Evidence to Capture (per finding)
- [ ] **The exact config stanza** (rule, NAT entry, `allowaccess` line, SNMP community) with line/section reference and the device/version it came from.
- [ ] **Tool output:** Vallum/Nipper finding ID and section, nmap/firewalk/ike-scan output, and the implant/version-check command output where relevant.
- [ ] **Segmentation evidence:** the filled allowed-path matrix showing source segment, destination, expected vs observed, and the raw scan proving a deny-path was reachable (or an allow-path blocked).
- [ ] **Screenshots/raw request-response** for active findings (management surface reachable from untrust, MFA bypass, exposed NAT service). Save raw pairs at test time.
- [ ] **Version-to-CVE mapping table** for any patch-level finding, citing the vendor PSIRT advisory and CISA KEV entry.

### Severity Guidance

| Finding | Typical Severity |
| --- | --- |
| Internet-reachable mgmt interface on unpatched edge device (KEV CVE) | Critical |
| Pre-auth VPN/portal RCE or auth-bypass exposed (live CVE) | Critical |
| Reachable segmentation deny-path (e.g. user to CDE/OT) | High to Critical |
| Default/weak admin or SNMP RW community string | High to Critical |
| No MFA on VPN or admin login | High |
| Any-any-any permit on perimeter | High |
| Permit-all egress / no egress filtering | Medium to High |
| Weak VPN ciphers (IKEv1 aggressive, DH1/2, 3DES) | Medium |
| Fail-open IPS on license/subsystem failure | High |
| Shadowed/unused/undocumented rules | Low to Medium |
| Telnet/HTTP mgmt enabled | Medium to High |

### Common False Positives to Rule Out
- [ ] **"Any-any" that is actually scoped by zone/application:** PAN-OS app-ID or a zone-pair restriction may constrain a rule that looks broad in raw service terms. Confirm the effective scope before rating.
- [ ] **Reachability blocked by an upstream device, not the one under review:** attribute the control to the right box.
- [ ] **IPS auto-block masquerading as segmentation:** a deny-path that "passes" only because your scanner got quarantined is not real isolation. Re-test from a fresh source.
- [ ] **Hit-count of zero on a genuinely seasonal/DR rule:** confirm a rule is truly unused over a representative window before flagging.
- [ ] **Mgmt interface "exposed" but on an isolated OOB network:** verify the source network is actually untrusted before calling it internet-reachable.
- [ ] **Version banner that does not reflect the running patch:** some devices report a base train; confirm the actual maintenance/patch build before mapping to a CVE.

---

## Tools and References

| Tool | Use |
| --- | --- |
| Vallum | Primary automated firewall/network-device config auditor; multi-vendor ruleset, hardening, and exposure findings from config exports. Run first. |
| Nipper / Nipper Studio | Config-audit against CIS/STIG/PCI benchmarks; rule and hardening reporting. |
| nmap | Mgmt-port discovery, external NAT reconciliation, segmentation port sweeps. |
| firewalk | Discover which ports a gateway forwards to hosts behind it. |
| ike-scan | IKEv1/v2 detection, aggressive-mode and PSK material capture. |
| snmp-check / onesixtyone | SNMP community-string sweep and v1/v2c read access. |
| [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md) | Version/CVE detection and TLS posture against live edge devices. |

### Authoritative References
- CIS Benchmarks (per-vendor: Cisco IOS/ASA, Palo Alto, Fortinet, Juniper, Check Point) for hardening baselines.
- Vendor PSIRT advisories (Fortinet PSIRT, Palo Alto Security Advisories, Cisco Security Advisories, Ivanti, SonicWall PSIRT).
- CISA Known Exploited Vulnerabilities (KEV) catalog for edge-device prioritization.
- NSA/CISA network-infrastructure and segmentation hardening guidance.
- PCI DSS firewall/segmentation requirements (rule recertification, segmentation testing) where the engagement is compliance-driven.
- DISA STIGs for network devices where applicable.

---

## Related

- Playbooks: [Edge Device Exploit to Internal Foothold](../Playbooks/Edge%20Device%20Exploit%20to%20Internal%20Foothold.md)
- Vallum
- [External Network Penetration Test](External%20Network%20Penetration%20Test.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
