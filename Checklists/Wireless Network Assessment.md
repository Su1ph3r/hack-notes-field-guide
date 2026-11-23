---
tags:
  - hack-notes
  - checklist
  - wireless
---

# Wireless Network Assessment Testing Checklist

> Phased methodology for authorized Wi-Fi assessments: WPA2/WPA3-Personal, WPA-Enterprise (802.1X/EAP), rogue AP and client-side attacks, open/guest and captive portals, post-access pivoting, and adjacent RF (BLE/Bluetooth). Methodology-first. Long commands live in the [Wireless](../Cheatsheets/Wireless.md) cheatsheet.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Recon and Survey](#2-recon-and-survey)
- [3. WPA2/WPA3-Personal (PSK) Attacks](#3-wpa2wpa3-personal-psk-attacks)
- [4. WPA-Enterprise (802.1X/EAP) Attacks](#4-wpa-enterprise-8021xeap-attacks)
- [5. Client-Side and Rogue AP](#5-client-side-and-rogue-ap)
- [6. Open/Guest and Captive Portals](#6-openguest-and-captive-portals)
- [7. Post-Access](#7-post-access)
- [8. Bluetooth/BLE and Other RF](#8-bluetoothble-and-other-rf)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Wireless testing is uniquely high-blast-radius: deauth, jamming, and rogue APs can knock real users and IoT/medical/OT devices offline. Lock scope and authorization before any RF is transmitted.

### Targets and Boundaries
- [ ] **In-scope SSIDs:** Get the exact list of corporate SSIDs to test. Pass = each SSID named in writing. Note any that are explicitly out of scope (neighbor tenants, guest provider SSIDs).
- [ ] **In-scope BSSIDs:** Where possible obtain the client's AP BSSID list or OUI ranges (vendor) so you can distinguish target APs from neighboring networks. Critical in multi-tenant buildings.
- [ ] **Physical area / RoE:** Confirm which buildings, floors, parking areas, and outdoor perimeter you may operate from. Pass = a map or address list and permission to be physically present.
- [ ] **Band scope:** Confirm 2.4 GHz, 5 GHz, and 6 GHz (Wi-Fi 6E/7) are all in scope. 6 GHz needs a capable adapter and regulatory-domain awareness.
- [ ] **Guest vs corporate:** Clarify whether guest, corporate, BYOD, and IoT/OT SSIDs are each in scope. Segmentation testing between them is usually a key objective.

### Authorization and Safety
- [ ] **Client-attack authorization:** Get explicit written sign-off to attack client devices (evil twin, karma, deauth, credential capture). Without it, restrict to passive recon and AP-side tests only.
- [ ] **Credential-capture handling:** Define how captured PSKs / MSCHAPv2 hashes / cleartext creds are stored, transmitted, and destroyed. Confirm whether you may attempt to crack and reuse them.
- [ ] **Deauth / DoS authorization:** Confirm whether active deauthentication is permitted and during which hours. Some environments forbid it entirely on safety-critical SSIDs.
- [ ] **No jamming of production:** Confirm you will not RF-jam or run continuous channel-wide deauth against production. Targeted, time-boxed deauth of a single client is the ceiling unless explicitly authorized.

```
⚠️ RF SAFETY: Broadband jamming is illegal in most jurisdictions and can disable life-safety
   systems (alarms, medical telemetry, OT). Never run continuous all-channel deauth or signal
   jammers. Scope deauth to specific client MACs, time-box it, and stop if you observe collateral
   outage. Rogue/evil-twin APs on a real corporate ESSID can break legitimate connectivity:
   keep transmit power low and tear down APs immediately after capture.
```

- [ ] **Emergency contact / kill criteria:** Record a client contact reachable during testing and the conditions under which you abort (production outage, safety-system disruption).
- [ ] **Legal / regulatory:** Confirm regulatory domain (`iw reg get`) so 5/6 GHz transmit is lawful. Confirm you are authorized to operate APs on the client ESSIDs.
- [ ] **Logistics:** Confirm parking, escort, badge access, and whether a long-dwell survey (overnight capture) is permitted.

---

## 2. Recon and Survey

Goal: enumerate every in-scope AP, its security posture, and associated clients before touching anything. Passive first.

### Adapter and Monitor Mode
- [ ] **Adapter capability:** Use an adapter with monitor mode + packet injection. Verify chipset supports the bands in scope (2.4/5/6 GHz). Atheros AR9271 (2.4 only), MediaTek MT7612U/MT7921, RTL8812AU/8814AU are common; 6 GHz needs newer MT7925/AX-class hardware.
- [ ] **Enable monitor mode:** `sudo airmon-ng start wlan0` (or `iw dev wlan0 set type monitor`). Pass = interface shows `type monitor`. Kill interfering processes (`airmon-ng check kill`).
- [ ] **Verify injection:** `sudo aireplay-ng --test wlan0mon`. Pass = AP responds to injected probes. Failure here invalidates every active test downstream.
- [ ] **Regulatory unlock for survey:** Confirm channels in scope are visible (`iw list` shows the band/channels). 6 GHz PSC channels may require correct reg domain.

### Channel and SSID Survey
- [ ] **Full-band sweep:** Run `airodump-ng` across 2.4, 5, and 6 GHz. Pass = a complete inventory of in-scope BSSIDs with channel, band, signal, and encryption.
  ```bash
  sudo airodump-ng --band abg wlan0mon          # a=5GHz, b/g=2.4GHz; add 6GHz per adapter
  sudo airodump-ng -c 36 --bssid AA:BB:CC:DD:EE:FF -w cap wlan0mon
  ```
- [ ] **SSID/BSSID enumeration:** Record every BSSID per SSID (multiple APs / radios per ESSID), channel, and band. Map which BSSIDs belong to the target vs neighbors using the scoped OUI/BSSID list.
- [ ] **Hidden SSID discovery:** Note any APs broadcasting a null/hidden ESSID. Recover the name passively from a client probe/association, or (if deauth authorized) force a reconnect and read the SSID from the association request.
- [ ] **Client enumeration:** Catalog associated STATION MACs per BSSID. Identify high-value clients (laptops, domain-joined hosts) vs IoT. Note client OUIs.
- [ ] **Probe-request harvest:** Passively log probe requests to build a picture of client Preferred Network List (PNL) entries. Useful for karma/known-beacon planning (see Phase 5).

### Encryption and Auth Identification
- [ ] **Cipher / auth type per SSID:** Classify each SSID. Pass = a table of SSID to security mode driving which later phase applies.

| Privacy | Auth (AKM) | Cipher | Goes to |
|---|---|---|---|
| Open | none | none | Phase 6 (open/guest) |
| Open (OWE) | Enhanced Open / OWE | CCMP | Phase 6 (note PMF) |
| WPA2-Personal | PSK | CCMP (AES) | Phase 3 |
| WPA2/WPA3 transition | PSK / SAE | CCMP | Phase 3 (downgrade) |
| WPA3-Personal | SAE | CCMP/GCMP | Phase 3 (PMKID rarely; SAE) |
| WPA2-Enterprise | 802.1X (MGT) | CCMP | Phase 4 |
| WPA3-Enterprise | 802.1X-SHA256 / 192-bit | GCMP-256 | Phase 4 |

- [ ] **PMF / 802.11w status:** Detect whether Protected Management Frames are required, optional, or disabled per BSSID. PMF-required defeats classic deauth and is mandatory on WPA3 and 6 GHz. Record this; it gates Phase 5 deauth viability.
- [ ] **WPS state:** Note APs advertising WPS (locked/unlocked). Legacy WPS PIN / Pixie-Dust may apply on older 2.4 GHz gear.
- [ ] **Signal mapping / heat survey:** Walk the physical perimeter logging RSSI per BSSID (Kismet, or airodump + GPS). Pass = a coverage map showing where the corporate SSID bleeds outside the building (parking lot reachability = attack surface).
- [ ] **Rogue/unauthorized AP detection:** Flag any in-scope-ESSID BSSIDs not on the client's authorized AP list (possible pre-existing rogue or neighbor spoof). Report regardless of exploitation.

---

## 3. WPA2/WPA3-Personal (PSK) Attacks

Goal: recover the PSK offline, or prove a downgrade path. Capture material on-site, crack off-site.

### 4-Way Handshake Capture
- [ ] **Targeted capture:** Lock airodump to the AP channel and BSSID and wait for a client to (re)connect. Pass = airodump shows `WPA handshake: <BSSID>`.
- [ ] **Deauth-assisted reconnect (if authorized + PMF off):** Send a minimal, targeted deauth to one client to force a reconnect, then capture the handshake.
  ```bash
  sudo aireplay-ng --deauth 3 -a <BSSID> -c <CLIENT> wlan0mon
  ```
  - [ ] If PMF is required, deauth is ignored: do not escalate volume. Pivot to PMKID or passive capture instead.
- [ ] **Validate the capture:** Confirm all required EAPOL frames are present (`aircrack-ng cap.cap` lists "1 handshake", or `hcxpcapngtool` reports a usable hash). A partial handshake is a false negative.

### PMKID Capture (clientless)
- [ ] **PMKID harvest:** Use hcxdumptool to request the PMKID directly from the AP (no client needed). Pass = a pcapng containing a PMKID for a target BSSID.
  ```bash
  sudo hcxdumptool -i wlan0mon -w pmkid.pcapng -c 1a,6a,11a
  hcxpcapngtool -o hash.hc22000 -E wordlist.txt pmkid.pcapng
  ```
  - [ ] Filter to in-scope BSSIDs with a BPF (`--bpf`) so you do not capture neighbor networks.
  - [ ] Note: many modern/enterprise APs disable PMKID roaming caching; absence of a PMKID is expected, not a failure. Fall back to the 4-way handshake.

### Offline Cracking
- [ ] **Convert to mode 22000:** Produce a single `.hc22000` (handles both PMKID and EAPOL). The legacy `.cap`/`.hccapx` path is deprecated.
- [ ] **Dictionary + rules:** Run hashcat `-m 22000` with a strong wordlist (rockyou, weakpass, client-themed) plus rules (best64, OneRule). Off-site GPU rig, `-w 3 -O`.
  ```bash
  hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule -w 3 -O
  ```
- [ ] **Targeted masks:** Try org-specific patterns (company name + year, phone numbers, `SSID` + digits) and known default-password schemas for the AP vendor.
- [ ] **Report negative cracking honestly:** A PSK that survives a bounded crack window is "not recovered within X GPU-hours," not "uncrackable." State the wordlist/rules/time budget.

### WPA3-Personal (SAE)
- [ ] **SAE means no offline handshake crack:** Confirm WPA3-SAE; the Dragonfly handshake does not yield an offline-crackable 4-way exchange the way PSK does. Do not claim handshake-cracking against pure SAE.
- [ ] **Transition-mode downgrade:** If the SSID runs WPA2/WPA3 transition mode, stand up a WPA2-only rogue AP with the same ESSID and lure a client to authenticate over WPA2, then capture and crack that handshake offline. This is the practical WPA3 break in 2024-2026.
  - [ ] Validate the AP actually supports transition mode (mixed AKM in the RSN element). A pure-WPA3 / Transition-Disable network is not vulnerable.
- [ ] **Dragonblood side-channels (legacy):** On unpatched WPA3 implementations, test for the timing/cache side-channels (CVE-2019-9494/9496) that leak password-element info. Largely patched; note vendor/firmware before claiming.
- [ ] **H2E vs Hunting-and-Pecking:** On 6 GHz, Hash-to-Element (H2E) is mandatory and resists the original Dragonblood dictionary leak. Confirm which PWE method the AP uses before asserting exploitability.

---

## 4. WPA-Enterprise (802.1X/EAP) Attacks

Goal: harvest domain credentials via RADIUS impersonation, then test cert validation. The headline finding is almost always weak/absent server-certificate validation on clients.

### EAP Method Enumeration
- [ ] **Identify inner/outer EAP:** Determine the EAP method the network expects (PEAP-MSCHAPv2, EAP-TTLS, EAP-TLS, EAP-PWD, EAP-FAST). Pass = method confirmed from the client's EAP-Response/Identity and negotiation.
- [ ] **EAP-TLS check:** If the network is EAP-TLS (mutual cert), credential phishing does not apply; pivot to cert/PKI and client-config review. Note it and move on.
- [ ] **Realm / anonymous identity:** Capture the outer identity / realm to make the rogue RADIUS convincing.

### Evil-Twin RADIUS Impersonation
- [ ] **Stand up rogue enterprise AP:** Use eaphammer or hostapd-mana/hostapd-wpe to broadcast the target ESSID with a rogue RADIUS endpoint. Pass = a victim attempts inner auth against your server.
  ```bash
  ./eaphammer --cert-wizard                     # generate a server cert first
  ./eaphammer -i wlan0 --essid CorpWiFi --creds # capture MSCHAPv2
  ```
- [ ] **Capture MSCHAPv2 challenge/response:** Record the username + NETNTLM challenge/response from inner PEAP/TTLS-MSCHAPv2. Pass = a crackable hash with a valid domain username.
- [ ] **Crack MSCHAPv2 offline:** Convert to hashcat NetNTLMv1 (`-m 5500`) and crack, or recover the NT hash directly via DES keyspace (`-m 27000` / `assless-chaps` against an NT-hash DB) and reuse the NT hash (pass-the-hash) without the cleartext.
  ```bash
  hashcat -m 5500 mschap.txt wordlist.txt -r rules/best64.rule
  ```
- [ ] **Autocrack-and-add (optional):** eaphammer can crack and append the cleartext to `eap_user` live so the victim authenticates successfully and never notices a failed connection.

### Certificate Validation Testing (the real bug)
- [ ] **Self-signed cert acceptance:** Present an untrusted/self-signed RADIUS cert. If clients connect anyway, server-cert validation is disabled or "ask user" -> harvest creds at will. This is the core WPA-Enterprise finding.
- [ ] **CN / SAN mismatch:** Present a valid-CA but wrong-CN cert. If clients accept it, hostname pinning is not enforced.
- [ ] **Per-platform config review:** Test Windows (GPO `ValidateServerCertificate`), macOS/iOS (profile `TLSTrustedServerNames`), and Android clients separately. Each can be misconfigured independently.
- [ ] **Document the secure baseline:** Pass condition for the client = rejects any cert not chaining to the configured CA and matching the configured RADIUS server name, with no user override.

### Relay
- [ ] **MSCHAPv2 relay (no crack):** Where the inner method is MSCHAPv2, test relaying the challenge/response to the legitimate RADIUS to authenticate without recovering the password. Confirm authorization scope first; this puts you on the network directly.
- [ ] **Strength-of-credential note:** A long random machine-cert-backed credential resists cracking but still falls to relay and to cert-validation bypass. Frame findings on validation, not just crackability.

---

## 5. Client-Side and Rogue AP

Goal: attack the clients themselves. Requires explicit client-attack authorization (Phase 1).

### Evil Twin (same-ESSID)
- [ ] **Clone the target AP:** Broadcast a matching ESSID (and BSSID/channel for open or PSK transition targets) at higher local signal. Pass = target clients associate to your AP.
- [ ] **Deauth-driven migration (if authorized + PMF off):** Targeted deauth of clients off the real AP so they roam to the evil twin. Stop immediately on collateral impact.
- [ ] **PMF blocks this:** On WPA3/6 GHz/PMF-required networks, clients ignore deauth. Note that the deauth-driven path is mitigated and rely on signal/known-beacon instead.

### Karma / Known-Beacon
- [ ] **Karma (probe-response):** Respond to directed probe requests, claiming to be whatever network the client asks for, to capture devices with a populated PNL. Pass = client auto-associates.
- [ ] **Known-beacon:** Beacon a dictionary of common/likely ESSIDs (airport, hotel, common corp guest names) so clients that only passively scan still join. eaphammer `--known-beacons`.
- [ ] **Modern-client caveat:** iOS 14+/Android 10+ send fewer directed probes and randomize MACs, reducing karma yield. Treat low yield as a finding about good client hygiene, not a tooling failure.

### Credential Capture and PNL Harvesting
- [ ] **PNL harvest:** Passively collect the PNL/probe data per client (Phase 2) and report devices leaking sensitive prior-network names (home, other-employer SSIDs).
- [ ] **Deauth-driven handshake capture:** Tie back to Phase 3: use a targeted deauth to capture a PSK 4-way handshake from a roaming client.

### Captive Portal Phishing
- [ ] **Hostile portal:** Pair the evil twin with a captive portal that mimics the corporate guest/onboarding page to harvest creds (eaphammer hostile-portal / wifiphisher). Pass = submitted credentials captured.
- [ ] **Onboarding/MDM lure:** Test a fake "install Wi-Fi profile/certificate" page that would push a malicious 802.1X profile. Report client willingness to install untrusted profiles.

```
⚠️ Rogue APs broadcasting the real corporate ESSID will pull in and disrupt legitimate users.
   Keep TX power minimal, time-box the AP, capture-and-teardown, and never leave a rogue AP
   running unattended. Log every client MAC you touch for the report and for cleanup.
```

---

## 6. Open/Guest and Captive Portals

Goal: prove (or disprove) isolation. The valuable findings are bypass + lateral movement, not "guest Wi-Fi is open."

### Segmentation Testing
- [ ] **Guest-to-corporate reachability:** From the guest network, scan for and attempt to reach corporate ranges/services. Pass (secure) = guest is fully isolated to internet-only. Fail = any corporate host/port reachable.
- [ ] **Guest-to-infrastructure:** Probe the gateway, AP management interfaces, DNS, and DHCP for admin exposure from the guest VLAN.
- [ ] **Inter-SSID leakage:** Test whether IoT/BYOD/guest SSIDs can reach each other or shared services they should not.

### Captive Portal Bypass
- [ ] **MAC-based bypass:** Identify an already-authorized client MAC (sniff) and clone it to inherit its portal session. Pass = internet access without authenticating.
- [ ] **DNS tunneling / exfil pre-auth:** Test whether DNS resolves before portal auth (common) and whether it tunnels traffic out. Pass = data egress before payment/auth.
- [ ] **Pre-auth IP/port allowlist abuse:** Find any host/port reachable before auth (NTP, vendor update servers) and test for tunneling.
- [ ] **Portal app flaws:** Treat the portal as a web app: test the auth/redirect logic, parameter tampering on the "authenticated" flag, and any voucher/registration endpoints (see [Web Application](Web%20Application.md)).
- [ ] **Session fixation / timeout:** Check whether a session persists indefinitely or can be reused after the paying user leaves.

### Client Isolation (AP/Station Isolation)
- [ ] **Layer-2 peer reachability:** From one guest client, attempt to ARP/scan/connect to other guest clients on the same SSID. Pass (secure) = isolation blocks peer traffic. Fail = guests can attack each other.
- [ ] **OWE / Enhanced Open check:** If the open network uses OWE, confirm traffic is actually encrypted per-client (no shared-key passive sniffing). Note PMF status.
- [ ] **Captive ARP-spoof:** Where isolation is absent, test ARP/MITM against peer clients as proof of impact (within authorization).

---

## 7. Post-Access

Once on the wireless segment (cracked PSK, harvested 802.1X creds, or guest/portal foothold), treat it as a network foothold. Hand off to the internal methodology.

### Establish and Characterize the Foothold
- [ ] **DHCP / segment mapping:** Pull an IP, identify the subnet, gateway, DNS, and domain (`ipconfig`/`ip a`, DHCP options). Pass = you know which VLAN/segment the SSID lands on.
- [ ] **Egress / reachability:** Map what the wireless segment can reach: internal ranges, AD services (445/389/88), management planes, internet egress.
- [ ] **Credential reuse:** Test harvested 802.1X/PSK-adjacent creds against internal services (SMB, RDP, VPN, web SSO). Wireless-harvested domain creds frequently unlock the internal estate.

### VLAN Hopping and Segmentation Bypass
- [ ] **VLAN hopping:** From the wireless segment test switch-spoofing (DTP) and double-tagging (802.1Q) to reach other VLANs if the AP uplink trunk is misconfigured. Pass = traffic reaches an out-of-scope-for-the-SSID VLAN.
- [ ] **Voice/native VLAN abuse:** Check for a reachable voice or native VLAN that bypasses the intended guest/BYOD isolation.
- [ ] **NAC / 802.1X wired bypass adjacency:** If the wireless drops onto a NAC-controlled segment, test posture/MAB bypass to widen access.

### Pivot
- [ ] **Pivot into internal:** Use the wireless foothold as the entry node for internal enumeration and AD attacks. Continue with [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md).
- [ ] **Tunnel back:** Establish stable C2/tunnel from the wireless foothold for off-site continuation. See [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md).
- [ ] **Document the path:** Capture the full chain (RF capture -> crack/harvest -> segment -> VLAN/host -> domain) for the report's attack narrative.

---

## 8. Bluetooth/BLE and Other RF

Brief adjacent-RF coverage; expand only if in scope (badge readers, IoT, peripherals, BLE locks).

- [ ] **Bluetooth/BLE inventory:** Scan for discoverable BR/EDR and BLE devices (`bluetoothctl`, `hcitool`/`btmgmt`, `bettercap` BLE). Pass = an inventory of nearby devices, MACs, names, and service UUIDs.
- [ ] **BLE GATT enumeration:** Connect and enumerate services/characteristics (`gatttool`, `nRF Connect`, bettercap `ble.enum`). Flag readable/writable characteristics without auth.
- [ ] **Pairing / security mode:** Identify Just-Works pairing (no MITM protection) vs LE Secure Connections. Just-Works on a sensitive device (lock, medical, badge) is a finding.
- [ ] **Sniffing:** Where authorized and hardware allows (Ubertooth, nRF sniffer), capture advertising/connection traffic to assess exposure.
- [ ] **Other RF (note only):** Flag in-scope sub-GHz / RFID / Zigbee / proprietary IoT for a dedicated assessment; deep RF is out of scope for a standard Wi-Fi engagement unless contracted.

---

## Recent Techniques (2024-2026)

- [ ] **WPA3 transition-mode downgrade (2024-2025):** TrustedSec/RedLegg demonstrated standing up a WPA2-only twin of a WPA3 transition-mode ESSID, capturing the WPA2 4-way handshake, and cracking offline with hashcat. Test for: any SSID advertising mixed PSK+SAE AKM and not enforcing Transition Disable.
- [ ] **DragonShift automation:** Tooling that automates the WPA3-transition downgrade. Test for: feasibility of an automated downgrade-and-capture against transition-mode APs.
- [ ] **Transition Disable enforcement:** Wi-Fi Alliance made Transition Disable mandatory on WPA3-certified gear. Test for: whether the AP actually sets the Transition Disable bit so clients refuse future WPA2 downgrades (absence = downgrade-able).
- [ ] **6 GHz / Wi-Fi 6E + Wi-Fi 7 baseline:** 6 GHz mandates WPA3-SAE, H2E, and PMF; Wi-Fi 7 adds Beacon Protection and GCMP-256. Test for: a 6 GHz SSID running anything weaker than SAE+H2E+PMF, or a 5/2.4 GHz transition SSID that undercuts the 6 GHz security.
- [ ] **PMKID clientless capture (modern hcxdumptool):** Current workflow is `hcxdumptool -i <if> -w out.pcapng` -> `hcxpcapngtool -o hash.hc22000`. Test for: APs that still cache/serve a PMKID (no client needed). Note many enterprise APs disable it.
- [ ] **Unified hashcat mode 22000:** `.cap`/`.hccapx` deprecated; use `.hc22000` for both PMKID and EAPOL. Test for: efficient cracking pipeline with `-w 3 -O` and org-themed masks/rules.
- [ ] **eaphammer/hostapd-mana enterprise evil twin:** Current standard for PEAP/TTLS-MSCHAPv2 credential capture with cert-wizard and autocrack-and-add. Test for: clients that accept an untrusted RADIUS cert and leak MSCHAPv2.
- [ ] **MSCHAPv2 to NT-hash recovery:** Instead of cracking cleartext, recover the NT hash via the DES keyspace (hashcat `-m 27000`, `assless-chaps`) and pass-the-hash. Test for: reusable NT hash from a captured PEAP-MSCHAPv2 exchange.
- [ ] **FragAttacks (CVE-2020-24586/24587/24588 + impl CVEs):** Aggregation, mixed-key, and fragment-cache design flaws plus implementation bugs affecting essentially all Wi-Fi devices. Test for: unpatched APs/clients with vanhoefm/fragattacks test suite (medium severity, CVSS ~4.8-6.5).
- [ ] **KRACK relevance (2017, residual):** Key-reinstallation largely patched but resurfaces on stale IoT/embedded clients. Test for: unpatched legacy stations vulnerable to 4-way/group-key reinstallation.
- [ ] **PMF / 802.11w prevalence:** Deauth-based attacks fail against PMF-required networks (mandatory on WPA3/6 GHz). Test for: PMF status per BSSID and frame your deauth findings accordingly (disabled PMF on WPA2 = legacy-attack exposure).
- [ ] **MAC randomization impact:** iOS 14+/Android 10+ randomize MACs and reduce probe verbosity, cutting karma/PNL yield. Test for: devices that still expose a stable MAC or rich PNL (poor client hygiene).
- [ ] **OWE / Enhanced Open:** Open networks may use OWE for opportunistic encryption. Test for: legacy open SSIDs with no OWE (fully passive-sniffable) and confirm OWE-transition is not downgrade-able.

---

## Reporting and Evidence

### Evidence to Capture per Finding
- [ ] Raw capture files (`.pcapng`/`.cap`) for every handshake/PMKID, with BSSID, ESSID, channel, and timestamp.
- [ ] The exact `.hc22000`/NetNTLM hash and the cracking parameters (wordlist, rules, mode, GPU-hours) plus result (cracked / not recovered within budget).
- [ ] For enterprise: the captured username + challenge/response, the rogue cert presented, and a screenshot/log of the client accepting an untrusted cert.
- [ ] For rogue AP/evil twin: the client MACs that associated, time-boxed start/stop, and any captured creds/portal submissions.
- [ ] For segmentation/portal bypass: source segment, reached destination (IP:port), and a request/response or screenshot proving access.
- [ ] Survey/coverage map showing where the corporate SSID is reachable off-premises.

### Severity Guidance

| Finding | Typical severity | Key qualifier |
|---|---|---|
| Crackable WPA2-PSK recovered | High to Critical | Network access; worse if flat/segmentation-poor |
| WPA-Enterprise cert validation disabled -> creds harvested | High to Critical | Domain credentials = internal foothold |
| WPA3 transition-mode downgrade -> PSK cracked | High | Requires transition mode + crackable PSK |
| Guest-to-corporate segmentation bypass | High | Direct lateral path |
| No client isolation on guest/open | Medium | Peer attack; impact depends on users |
| PMKID/handshake captured but PSK not recovered | Low to Medium | Offline-crack exposure, not yet access |
| PNL leakage / no MAC randomization | Low | Privacy/karma exposure |
| FragAttacks/KRACK on legacy unpatched client | Medium | Often hard to exploit at range |

### Common False Positives to Rule Out
- [ ] **Neighbor networks reported as target:** Verify BSSID/OUI against the scoped AP list before reporting an "insecure SSID."
- [ ] **Partial handshake claimed as capture:** Confirm all EAPOL frames; a 1/4 or 2/4 fragment is not crackable.
- [ ] **PMKID absence called a vuln:** Many APs legitimately disable PMKID; absence is not a finding.
- [ ] **WPA3-SAE handshake "cracking":** Do not claim offline cracking of pure SAE; only the WPA2 downgrade path yields a crackable handshake.
- [ ] **Deauth "ineffective" on PMF networks:** That is expected hardening, not a tooling fault. Report PMF as a positive control.
- [ ] **Cert-accept tested on a single misconfigured device:** Confirm the policy/profile, not one user clicking "trust," before claiming systemic cert-validation failure.

---

## Tools and References

| Tool | Use |
|---|---|
| `aircrack-ng` suite (airmon-ng, airodump-ng, aireplay-ng) | Monitor mode, survey, deauth, handshake capture/crack |
| `hcxdumptool` / `hcxtools` (hcxpcapngtool) | Clientless PMKID capture and mode-22000 conversion |
| `hashcat` | Offline PSK (`-m 22000`) and MSCHAPv2/NetNTLM (`-m 5500`/`27000`) cracking |
| `eaphammer` | WPA-Enterprise evil twin, cert-wizard, known-beacons, hostile portal |
| `hostapd-mana` / `hostapd-wpe` | Rogue enterprise AP, EAP credential interception |
| `wifiphisher` | Captive-portal phishing / rogue AP automation |
| `kismet` | Passive survey, signal mapping, device discovery |
| `bettercap` | Wi-Fi + BLE recon and MITM |
| `assless-chaps` | MSCHAPv2 -> NT-hash recovery |
| `vanhoefm/fragattacks` | FragAttacks/KRACK client and AP testing |

References:
- OWASP WSTG (auth/session/portal web testing for captive portals)
- Wi-Fi Alliance WPA3 / Transition Disable specification and 6 GHz security requirements
- Mathy VanHoef research: KRACK, Dragonblood (CVE-2019-9494/9496), FragAttacks (CVE-2020-24586/24587/24588)
- hashcat wiki: cracking WPA/WPA2 (mode 22000)
- ZerBea/hcxdumptool documentation and changelog
- Synacktiv "Wireless-(in)Fidelity: Pentesting Wi-Fi in 2025"

---

## Related
- [Wireless](../Cheatsheets/Wireless.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md)
- [Web Application](Web%20Application.md)
- [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
