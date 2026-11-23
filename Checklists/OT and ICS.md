---
tags:
  - hack-notes
  - checklist
  - ot
  - ics
---

# OT and ICS Testing Checklist

> SAFETY-FIRST methodology for assessing Operational Technology and Industrial Control Systems (SCADA, PLCs, DCS, HMI, historians). Aligned to the Purdue model, IEC 62443 zones and conduits, and MITRE ATT&CK for ICS. Default to PASSIVE techniques. Active probing can crash fragile PLCs and cause physical and safety impact.

```
⚠️ READ BEFORE TOUCHING ANYTHING ⚠️
OT is not IT. A dropped packet or an unexpected byte can hang a PLC, trip a process,
or disable a safety function with real-world physical consequences (fire, flood, gas
release, equipment destruction, injury, death). A "harmless" TCP connect or an nmap
SYN scan has crashed production controllers. Treat EVERY active action as potentially
destructive. The default mode of this engagement is PASSIVE. Active tests run ONLY with
written authorization, in a maintenance window, with the asset-owner engineer present and
their hand on the e-stop. NEVER scan, probe, or touch a Safety Instrumented System (SIS).
When in doubt, capture traffic and ask. Do not improvise on a live plant.
```

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Architecture and Purdue-Model Mapping](#2-architecture-and-purdue-model-mapping)
- [3. Passive Discovery](#3-passive-discovery)
- [4. IT/OT Boundary and DMZ Testing](#4-itot-boundary-and-dmz-testing)
- [5. Engineering Workstation and HMI](#5-engineering-workstation-and-hmi)
- [6. Industrial Protocol Assessment](#6-industrial-protocol-assessment)
- [7. Wireless and Field](#7-wireless-and-field)
- [8. Reporting](#8-reporting)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

```
⚠️ This phase is a hard gate. Do not advance to any active step until every safety
control below is signed off in writing. Physical-process impact is the controlling
risk, not data confidentiality.
```

### Safety and Authorization Gate

- [ ] **Establish physical-process impact as the primary risk:** before any technical scoping, document what each zone controls (boilers, pumps, breakers, valves, robotic cells, chemical dosing) and the worst-case physical/safety consequence of a controller fault or trip.
- [ ] **Default to passive-only:** baseline rules of engagement state PASSIVE techniques only (traffic capture, document review, interviews). Active testing is opt-in per zone, never blanket-authorized.
- [ ] **Get plant and operations signoff, not just IT/security:** the plant manager, operations lead, and process-safety engineer must authorize the scope in writing. IT signoff alone is insufficient for OT.
- [ ] **Active tests in maintenance windows only:** any active probe, scan, or protocol interaction is confined to a scheduled maintenance window or planned outage. Never during live production.
- [ ] **Asset-owner engineer present for active work:** a qualified control engineer who knows the specific equipment must be physically present and able to halt the test and recover the process.
- [ ] **Exclude all Safety Instrumented Systems (SIS) from active testing:** SIS (e.g. emergency shutdown, burner management, fire-and-gas) are NEVER actively scanned or touched. Mark them out-of-scope for active work and confirm their network location so passive capture does not even probe them. Document them as off-limits in the RoE.
- [ ] **Define an abort/recovery plan:** agree the stop signal, who calls it, how the process is brought to a safe state, and the rollback for any device that misbehaves. Confirm backups and recovery media exist for HMIs/EWS/PLCs before testing.
- [ ] **Confirm insurance, liability, and emergency contacts:** 24/7 on-call control engineer, vendor support lines, and the incident escalation path are listed before work begins.
- [ ] **Agree blast-radius limits:** no broadcast storms, no asset-discovery sweeps of L0-L2, no aggressive timing. Rate, concurrency, and target lists are explicitly bounded and approved.

### Scoping Inputs to Collect

- [ ] **Network diagrams and asset inventory:** request P&IDs, network topology, IP/VLAN schemes, and any existing OT asset inventory. Treat as starting hypotheses to verify passively, not ground truth.
- [ ] **Identify the IT/OT boundary owners:** who manages the firewall/DMZ between enterprise and OT, who manages remote access, who manages vendor connections.
- [ ] **Map vendors and support contracts:** every vendor with remote access (PLC, HMI, drives, historian) is a path into the OT network. List them.
- [ ] **Classify systems by criticality and consequence:** tier assets by safety consequence and process criticality, not just CVSS. A low-CVSS bug on a safety-adjacent controller can outrank a high-CVSS bug on an office host.

---

## 2. Architecture and Purdue-Model Mapping

> Build the zone-and-conduit picture before any traffic work. The Purdue model is the basis for IEC 62443 zones/conduits, NIST SP 800-82, and current CISA guidance. Map first; everything else hangs off this.

### Purdue Levels

| Level | Name | Typical assets | Active-test posture |
|---|---|---|---|
| L5 | Enterprise | ERP, corporate IT, internet | Standard IT testing (out of OT scope) |
| L4 | Site business / IT | Email, file servers, business planning | Standard IT testing |
| L3.5 | IT/OT DMZ | Jump hosts, patch/AV relays, replicated historian, remote-access broker | Careful active testing in window |
| L3 | Site operations | EWS, SCADA servers, primary historian, domain controllers for OT | Careful active testing in window |
| L2 | Area supervisory | HMI, SCADA/area controllers, alarm servers | Passive strongly preferred |
| L1 | Basic control | PLCs, RTUs, DCS controllers, IEDs | PASSIVE ONLY unless lab/test cell |
| L0 | Process | Sensors, actuators, drives, field instruments | PASSIVE ONLY. Never probe |
| SIS | Safety | ESD, BMS, F&G, SIL-rated logic solvers | OUT OF SCOPE for active. Do not touch |

- [ ] **Place every known asset on a Purdue level:** if an asset cannot be levelled, that is itself a finding (unclear segmentation).
- [ ] **Map the IT/OT boundary and DMZ:** identify the firewall(s) and the DMZ between L3.5 and L3/L4. Note whether a true DMZ exists or whether enterprise talks straight to OT.
- [ ] **Enumerate conduits (allowed flows between zones):** document every sanctioned cross-zone path and its protocol. Flag any direct L4-to-L1/L2 path as a high-risk conduit collapse.
- [ ] **Identify the SIS and isolate it on the map:** confirm SIS is in its own zone with its own conduit rules. Shared SIS/BPCS networks are a top finding. Mark for no-touch.
- [ ] **Locate the historians:** primary historian (L3) and any DMZ-replicated/cloud-published historian (L3.5/L5). The historian is a prime IT-side data target and a common pivot.
- [ ] **Locate engineering workstations (EWS) and project files:** EWS hold PLC logic, project archives, and often vendor credentials. They are the crown jewels for an OT attacker.
- [ ] **Locate jump hosts and remote-access brokers:** the sanctioned path from IT into OT. Note MFA, session recording, and whether it is bypassable.
- [ ] **Note dual-homed hosts:** any host with a NIC in two zones (especially OT + corporate) collapses the boundary. Enumerate them; each is a candidate pivot.
- [ ] **Assign IEC 62443 target Security Levels (SL-T) per zone:** SL1 (casual/accidental) to SL4 (nation-state). Test findings are later scored against the zone's SL-T.

---

## 3. Passive Discovery

```
⚠️ "Passive" means you transmit NOTHING toward L0-L2 devices. Receive-only capture
via SPAN/mirror port or a hardware TAP. Do not run nmap, do not ping, do not ARP-sweep,
do not let your capture host's OS send discovery traffic onto the OT segment. Disable
the capture NIC's IP stack or use a one-way TAP.
```

### Capture Setup

- [ ] **Get a SPAN/mirror port or a passive hardware TAP:** prefer a TAP for full-duplex fidelity and guaranteed receive-only behavior. Confirm with the network owner where to connect.
- [ ] **Harden the capture host to be silent:** disable IPv6, mDNS, LLMNR, NetBIOS, DHCP client, and any agent that beacons. Bring the interface up without an IP (`ip link set <if> up` then capture). On a TAP, physical isolation guarantees silence.
- [ ] **Capture long and at the right vantage points:** capture at the IT/OT boundary, on supervisory (L2) segments, and near the historian. Run multi-hour to multi-day captures to see periodic and shift-driven traffic.
- [ ] **Record capture metadata:** location, duration, link, and what process state the plant was in. Needed for evidence and to explain gaps.

### Passive Asset Inventory and Protocol ID

- [ ] **Build the asset inventory from traffic:** enumerate hosts, MACs, vendor OUIs, IPs, and roles purely from observed packets. Feed pcaps to GRASSMARLIN (or a modern passive successor) and Malcolm/Arkime for asset and flow mapping.
- [ ] **Fingerprint device vendors/models passively:** OUI lookup plus protocol banners in observed traffic (Modbus, S7comm, EtherNet/IP, DNP3, OPC, Profinet, BACnet) usually reveal vendor and often firmware.
- [ ] **Classify protocols and map them to conduits:** in Wireshark, identify every industrial protocol on the wire and which zones it crosses. Compare against the sanctioned conduit list from Phase 2; unsanctioned flows are findings.
- [ ] **Identify cleartext and unauthenticated control traffic:** most legacy ICS protocols (Modbus, S7comm classic, DNP3 without Secure Auth) carry no authentication or encryption. Observing read/write function codes in cleartext is itself a reportable exposure.
- [ ] **Spot engineering/programming sessions in capture:** EWS-to-PLC programming traffic (e.g. S7comm function-code download, CIP forward-open to a controller) reveals the management path an attacker would abuse. Note it; do not replay it.
- [ ] **Detect rogue or unexpected devices:** any asset not on the provided inventory, any IT-style host on an L1/L2 segment, any internet-bound flow from OT. Flag for follow-up.
- [ ] **Map external and remote connectivity from flows:** identify any traffic egressing to the internet, to corporate, or to vendor ranges. Each is a boundary or remote-access finding to chase in Phase 4.
- [ ] **Run an ATT&CK-for-ICS lens over the capture:** classify observed flows against ATT&CK for ICS tactics (Discovery, Collection, Lateral Movement, Inhibit Response Function). Modern passive tools project findings onto the ICS matrix directly.

---

## 4. IT/OT Boundary and DMZ Testing

> The boundary is where most real OT compromises start (FrostyGoop entered via an internet-facing router into an unsegmented network). Test it hard, but stay on the IT/DMZ side. Do not let boundary testing leak packets onto L1/L2.

### Segmentation and Firewall Rules

- [ ] **Validate the firewall ruleset enterprise-to-OT:** review the config, do not just port-scan. Look for `any/any`, overly broad source ranges, and management protocols (RDP, SSH, SMB, WinRM) permitted into OT.
- [ ] **Test for direct enterprise-to-L1/L2 reachability:** from an authorized IT-side host, confirm whether control-network devices are reachable at all. Any direct path that skips the DMZ is a high finding. Confirm reachability without touching the controller (e.g. observe a deny in firewall logs).
- [ ] **Check DMZ broker pattern is enforced:** historians, patch servers, and AV relays in the DMZ should be the only things bridging. Verify nothing in L4 talks straight through to L3/L2.
- [ ] **Hunt dual-homed hosts:** confirm each dual-homed host found in Phase 2 and assess whether it bridges OT and corporate. Routing/forwarding enabled on such a host is a critical segmentation break.
- [ ] **Assess outbound from OT:** OT zones should not reach the internet. Verify egress filtering. Outbound OT-to-internet is both an exfil path and a malware C2 path.

### Remote Access and Vendor Paths

- [ ] **Enumerate all remote-access paths into OT:** jump hosts, VPNs, vendor remote-support tools (TeamViewer/AnyDesk-class), cellular modems on RTUs, and cloud-connected gateways.
- [ ] **Test the jump host / broker:** MFA enforced, session recording on, no split-tunnel, no direct RDP-through. Check whether a foothold on the jump host yields unfettered OT access.
- [ ] **Scrutinize vendor VPNs:** persistent vendor tunnels often have static creds, no MFA, and broad access. Verify least-privilege scoping and time-bounded access. Default/shared vendor creds are a recurring critical.
- [ ] **Check for internet-exposed OT:** correlate with Shodan/Censys for the org's ranges. Internet-facing PLCs/HMIs on default ports with default or no password is the Unitronics/CyberAv3ngers pattern. Do not authenticate to live devices; report exposure.
- [ ] **Data historian exposure:** the historian is frequently published to corporate/cloud for dashboards. Test its IT-side interfaces (web, SQL, API) for authn/authz flaws, but treat it as a pivot point back into OT, not just an IT app.

---

## 5. Engineering Workstation and HMI

> EWS and HMI are Windows (or thin-client) hosts running OT software. They are usually unpatched, flat-privileged, and trusted by the controllers. Standard host testing applies, with OT-specific caveats. Do NOT push the controller from here.

### Host Posture

- [ ] **Patch level and EOL OS:** EWS/HMI commonly run Windows 7/Server 2008/XP or unpatched Win10. Enumerate OS, hotfix level, and known exploitable CVEs. EOL OS supporting OT software is a standard high finding.
- [ ] **Removable media controls:** USB is the classic OT infection vector (Stuxnet lineage). Test whether USB mass storage and autorun are blocked and whether media is scanned at a kiosk before transfer.
- [ ] **Application whitelisting / allow-listing:** verify AppLocker/WDAC or a vendor allow-list is enforced. OT vendors often recommend allow-listing over AV. Absence is a finding; misconfigured rules (writable allowed paths) are a bypass.
- [ ] **Antivirus/EDR presence and exclusions:** check AV/EDR exists, is current, and that vendor-recommended exclusions are not so broad they create a malware safe-zone.
- [ ] **Local privilege and shared accounts:** operators frequently run as local admin with a shared, never-rotated password. Enumerate local users, admin membership, and password-reuse across HMIs.
- [ ] **Default and hardcoded credentials:** OT software ships with default app and DB creds (SCADA admin, historian SQL `sa`, vendor service accounts). Check vendor defaults; these are widely documented.

### OT Software and Project Files

- [ ] **Enumerate installed OT software and versions:** SCADA/HMI runtime (e.g. WinCC, FactoryTalk, Ignition, Wonderware/AVEVA), PLC programming suites (TIA Portal, Studio 5000, CODESYS, Unity Pro/EcoStruxure), historian (PI, Aspen). Map versions to CISA ICS advisories.
- [ ] **Locate PLC project archives and logic backups:** project files often sit unencrypted on the EWS and contain controller IPs, logic, comments, and embedded credentials. Their exposure is a finding; do not download logic to a controller.
- [ ] **Check SCADA/HMI software for known vulns:** test the HMI web/runtime interfaces and the SCADA server for the vendor's published CVEs (auth bypass, path traversal, deserialization, hardcoded keys). Validate carefully; do not crash the runtime.
- [ ] **Assess HMI lockdown / kiosk escape:** operator HMIs should be kiosked. Test for shell escape (dialog boxes, file pickers, help viewers, hotkeys) to the underlying OS.
- [ ] **Review project/version control hygiene:** are logic and project files versioned, integrity-checked, and access-controlled? Unmanaged logic enables silent, unauthorized PLC changes.

---

## 6. Industrial Protocol Assessment

```
⚠️ HIGHEST-RISK PHASE. Industrial protocols mostly have no authentication, so a single
write packet can change a setpoint, force an output, stop a CPU, or download logic to a
live controller, with direct physical consequence. Run protocol WRITE/replay/scan tests
ONLY against a lab cell or an explicitly authorized test controller, in a window, with the
engineer present. NEVER against production L0-L2. NEVER against SIS. On production, your
protocol "assessment" is the passive read from Phase 3 plus documentation, not live probing.
```

### Approach

- [ ] **Decide the venue per protocol test:** production = passive observation only. Active read/write/replay = lab/test cell with an identical or representative controller, authorized in writing.
- [ ] **Confirm a known-good recovery state before any active protocol step:** controller backup, ability to cold-restart, and the engineer ready to recover.

### Protocol Reference

| Protocol | Port | Auth by default | Test (lab/authorized only) |
|---|---|---|---|
| Modbus TCP | 502 | None | Unauth read/write of coils/registers, function-code enumeration, replay |
| DNP3 | 20000 | None (Secure Auth optional, rare) | Unauth reads, control relay output, replay; check if Secure Authentication v5 is on |
| EtherNet/IP / CIP | 44818, 2222 | None | enip/CIP identity enum, forward-open to controller, attribute read |
| S7comm / S7comm-plus | 102 | Weak/none (classic), per-session (plus) | CPU stop/start, block read/download, enum; S7-1200/1500 anti-replay varies |
| OPC DA/UA | 135 + dynamic, 4840 (UA) | Varies (UA can be strong) | DA = DCOM weaknesses; UA = check security policy, anonymous, cert validation |
| Profinet | DCP (L2), 34962-34964 | None | DCP device discovery, name/IP set, alarm injection |
| BACnet | 47808/UDP | None | Who-Is/I-Am enum, object read, writable present-value |

### Tests (lab cell or authorized test controller only)

- [ ] **Lack of authentication:** confirm the controller accepts unauthenticated function-code requests. Reading is lower-risk than writing; still scope-controlled.
- [ ] **Unauthorized read:** read coils/registers/objects/tags to show an attacker can fingerprint and monitor the process without credentials.
- [ ] **Unauthorized write (lab only):** demonstrate a setpoint/coil/register/present-value write changes process state. This is the impact proof; it is also why it never runs on production.
- [ ] **Replay:** capture a legitimate command and replay it to show no session integrity (e.g. replayed control-relay or setpoint write).
- [ ] **CPU mode control (lab only):** for S7comm and CIP, demonstrate stop/start or run/program mode change. Maps to ATT&CK for ICS Inhibit Response Function and Loss of Control.
- [ ] **Logic/firmware integrity:** assess whether logic download or firmware update is authenticated and signed. Unsigned logic download to a controller is the FrostyGoop/PLC-attack class.
- [ ] **Safe active fingerprinting (only if authorized, with care):** Redpoint NSE scripts (`modicon-info`, `s7-enumerate`, `enip-enumerate`, `BACnet-discover-enumerate`) use legitimate protocol commands but can still crash fragile devices. Run only in window, with engineer, never on SIS. See [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md) and the OT cheatsheet for invocation; below is the anchor form.

```bash
# AUTHORIZED + WINDOWED + ENGINEER PRESENT. Single host, slowest timing, no host discovery.
nmap -Pn -n -T1 --max-parallelism 1 -p 502 \
  --script modbus-discover --script-args='modbus-discover.aggressive=false' <target>
# Redpoint / icsmaster NSE: enip-enumerate, s7-enumerate, BACnet-discover-enumerate
```

---

## 7. Wireless and Field

> Field and wireless links extend the attack surface beyond the wired plant. Many use unlicensed bands, weak or no crypto, and bridge straight to control. Passive RF survey first.

- [ ] **Industrial WLAN survey:** enumerate 802.11 used for AGVs, mobile HMIs, and remote I/O. Check for WEP/WPA-PSK, shared keys, and whether the WLAN bridges directly into a control VLAN. See [Wireless](../Cheatsheets/Wireless.md).
- [ ] **Proprietary and sub-GHz radio links:** identify 900 MHz / 2.4 GHz telemetry, LoRa, and vendor radios for RTU/SCADA backhaul. Assess encryption and authentication; many are cleartext and replayable.
- [ ] **Serial and serial-over-IP:** legacy RS-232/RS-485 (Modbus RTU, DNP3 serial) and serial-to-Ethernet gateways (Moxa/Lantronix-class). Gateways often have weak web admin and expose serial to the network. Test the gateway's IT-side admin, not the serial bus on production.
- [ ] **Cellular and satellite backhaul:** RTUs with cellular modems are internet-reachable. Check APN isolation, default modem creds, and exposed management.
- [ ] **GPS/timing dependencies:** note reliance on GPS for time sync (PMUs, sequence-of-events). Spoofing/jamming is a documented availability risk; flag the dependency, do not transmit.

---

## 8. Reporting

> Score on consequence and safety, not just CVSS. Tie every finding to a Purdue zone and an IEC 62443 conduit, and to the compensating controls that do or do not contain it.

- [ ] **Map each finding to physical/process consequence:** state the realistic worst-case (loss of view, loss of control, manipulation of process, safety impact), not just the technical defect.
- [ ] **Place each finding in its zone and conduit:** name the Purdue level and the IEC 62443 zone/conduit, and whether the finding crosses a boundary it should not.
- [ ] **Score against the zone's SL-T:** compare the finding's exposure to the zone's target Security Level. A gap between achieved and target SL is the core OT narrative.
- [ ] **Credit compensating controls:** OT relies on physical interlocks, hardwired safety, manual operation, and air gaps. Note where these reduce real-world risk even when a software bug exists. This is essential for honest severity.
- [ ] **Frame as defect reports, not attack stories:** describe the control gap and remediation. Keep the impact factual and tied to evidence.
- [ ] **Map to ATT&CK for ICS:** tag findings to techniques (Discovery, Lateral Movement, Inhibit Response Function, Impair Process Control, Loss of Control/View) so defenders can align detections.
- [ ] **Provide OT-appropriate remediation:** segmentation/conduit hardening, DMZ broker enforcement, MFA on remote access, allow-listing on EWS/HMI, protocol-aware monitoring, and patching aligned to vendor and maintenance windows (not blind IT patch cadence).

---

## Recent Techniques (2024-2026)

- [ ] **FrostyGoop / BUSTLEBERM (2024, ninth known ICS malware):** uses Modbus TCP/502 to write registers and disable PLC operation; entered Ukrainian district-heating OT via an internet-facing router into an unsegmented network, leaving 600+ buildings without heat in winter. Test for: internet-facing routers/gateways fronting OT, flat networks with no L3.5 DMZ, and unauthenticated Modbus/502 write reachable across the boundary.
- [ ] **Fuxnet (2024, BlackJack vs Moskollektor):** targeted sensor gateways on a municipal sensor network, corrupting flash/filesystems and flooding the bus to brick thousands of field sensors. Test for: exposed sensor gateways, weak gateway admin, and lack of integrity monitoring on field-bus traffic.
- [ ] **CyberAv3ngers / IRGC-affiliated Unitronics campaign (CISA AA23-335A, ongoing into 2024-2026):** compromised 75+ internet-exposed Unitronics Vision PLC/HMI on default TCP/20256 with default or no password across US water/wastewater. Test for: internet-exposed PLC/HMI on default ports, default/blank passwords, and direct internet reachability of L1/L2.
- [ ] **Sandworm / VOLTZITE and OT-focused state actors (Dragos/CISA 2024-2026):** living-off-the-land in OT, abuse of legitimate remote access and engineering tooling, and pre-positioning in critical infrastructure. Test for: unmonitored remote-access paths, vendor VPN sprawl, and engineering-workstation trust that enables logic changes.
- [ ] **PLC firmware and logic-download attacks:** unsigned/unauthenticated logic download and firmware update on controllers (S7, CIP class). Test for (lab only): whether the controller accepts unauthenticated logic download and whether firmware images are signature-verified.
- [ ] **CISA ICS advisory surge (450+ in 2025, 200+ vendors):** dominated by improper input validation, out-of-bounds access, and buffer overflows in Rockwell, Siemens, Schneider, Mitsubishi products; water, critical manufacturing, and energy most affected. Test for: software/firmware versions mapped against current CISA ICS advisories for the in-scope vendors.
- [ ] **OPC UA misconfiguration:** UA supports strong security but is frequently deployed with `SecurityPolicy#None`, anonymous sessions, or no certificate validation. Test for: anonymous/None endpoints and accepted self-signed/invalid certs on UA servers.
- [ ] **Modern passive OT discovery with ATT&CK-for-ICS projection:** GRASSMARLIN is EOL (2017); current passive tooling (modern successors, Malcolm/Arkime, commercial Nozomi/Dragos/Claroty concepts) maps pcaps straight onto the ICS matrix. Test for: build the asset inventory and ATT&CK-ICS coverage entirely from receive-only capture, no active probing.
- [ ] **Safe-active enumeration with Redpoint/ICS NSE:** `modicon-info`, `s7-enumerate`, `enip-enumerate`, `BACnet-discover-enumerate` use legitimate protocol commands but remain risky on fragile devices. Test for: enumeration only in a window, slowest timing, single-host, engineer present, never on SIS.

---

## Reporting and Evidence

- [ ] **Capture per finding:** pcap excerpt (anonymized as needed), screenshots of HMI/EWS/config, firewall rule extracts, device banners/identity responses, and the exact protocol exchange that demonstrates the issue.
- [ ] **Record the venue and conditions:** state clearly whether evidence came from passive production capture or from an authorized lab/test-cell active test. This separation is mandatory in an OT report.
- [ ] **Severity guidance:** weight by physical/safety consequence and proximity to control and to SIS, then by exploit reachability across boundaries. A reachable unauthenticated write to a process-critical controller outranks a high-CVSS bug on an isolated office host. Always factor compensating physical/hardwired controls down.

### Common false positives to rule out

- [ ] **"Unauthenticated protocol" that is actually segmented:** an unauth Modbus device is low risk if it is genuinely unreachable from any attacker-controlled position. Verify reachability before rating.
- [ ] **EOL OS that is air-gapped and physically controlled:** still a finding, but severity is bounded by real isolation and compensating controls. Do not over-rate.
- [ ] **Hardwired safety covers the cyber impact:** if a physical interlock or SIL-rated SIS independently prevents the unsafe state, the realistic safety impact is reduced. Note it; do not claim catastrophic impact a hardwired control blocks.
- [ ] **Internet "exposure" that is a honeypot or decommissioned asset:** confirm the device is live, owned, and in-scope before reporting internet exposure.
- [ ] **Vendor-default config that the vendor explicitly hardens at commissioning:** verify the deployed state, not the out-of-box default, before claiming default creds.

---

## Tools and References

| Tool / reference | Use |
|---|---|
| Wireshark / tshark | Passive protocol decode and analysis (Modbus, S7comm, DNP3, ENIP/CIP, BACnet, Profinet) |
| GRASSMARLIN | Passive ICS network mapping from pcap (EOL 2017; use a modern passive successor where possible) |
| Malcolm / Arkime / Zeek | Passive OT traffic analysis, flow and asset inventory at scale |
| Redpoint / icsmaster NSE | Active protocol enumeration (`modicon-info`, `s7-enumerate`, `enip-enumerate`, BACnet). Fragile-device caution |
| Shodan / Censys | External exposure discovery for internet-facing OT (read-only OSINT) |
| MITRE ATT&CK for ICS | Adversary tactic/technique taxonomy for classifying findings and detections |
| IEC 62443 | Zones-and-conduits architecture and Security Levels (SL-T vs SL-A) for scoring |
| NIST SP 800-82 | Guide to OT/ICS security; architecture and control guidance |
| Purdue model (ISA-95) | Reference architecture for levelling assets and conduits |
| CISA ICS advisories | Current vendor/product vulnerability mapping for in-scope assets |

---

## Related

- [IoT Device](IoT%20Device.md)
- [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md)
- [Wireless](../Cheatsheets/Wireless.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md)
- [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
