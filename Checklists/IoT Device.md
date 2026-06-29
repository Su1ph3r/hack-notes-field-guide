---
tags:
  - hack-notes
  - checklist
  - iot
  - hardware
---

# IoT Device Testing Checklist

> Full-ecosystem methodology for an IoT/embedded device assessment: hardware, firmware, radio, companion app, and cloud API. Structured on the OWASP IoT Top 10 and the OWASP Firmware Security Testing Methodology (FSTM) with ISVS as acceptance criteria. Use for routers, cameras, smart-home, wearables, gateways, and similar embedded targets.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Reconnaissance and Architecture](#2-reconnaissance-and-architecture)
- [3. Hardware Analysis](#3-hardware-analysis)
- [4. Firmware Analysis](#4-firmware-analysis)
- [5. Network and Services](#5-network-and-services)
- [6. Radio and Protocols](#6-radio-and-protocols)
- [7. Mobile and Cloud](#7-mobile-and-cloud)
- [8. Authentication and Updates](#8-authentication-and-updates)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

The device is the visible part of a system. The contract must cover the whole ecosystem (device, radio, app, cloud) or findings will fall out of scope mid-engagement. Hardware work is often destructive, so get that authorization in writing before a screwdriver touches a case.

### Authorization and Rules of Engagement
- [ ] **Confirm the ecosystem scope in writing:** device hardware, firmware, all radios, companion mobile app(s), and the backend cloud API/web portal. Get explicit yes/no per layer. A device-only scope blocks the most impactful findings (cloud IDOR, ownership transfer).
- [ ] **Get destructive/invasive-hardware authorization:** teardown, desoldering flash, chip-off, glitching, and bus tapping can brick units permanently. Confirm the client accepts unit loss.
- [ ] **Confirm cloud-API testing authorization and owner:** the cloud backend is frequently a third-party (Tuya, Meari, vendor SaaS). Testing it may require that party's consent, not just the device vendor's. Identify the operator before sending any traffic.
- [ ] **Define account boundaries:** confirm you have at least two tenant accounts (Attacker A, Victim B) for authorization/IDOR testing. Cross-tenant testing without a second account is impossible to do safely.
- [ ] **Clarify out-of-scope cloud regions/multi-tenant blast radius:** the cloud serves all customers. Confirm rate limits, prohibited endpoints, and that destructive cloud actions (mass device de-provisioning) are off-limits.

### Devices, Spares, and RF Legality
- [ ] **Record devices and quantity provided:** model, hardware revision, firmware version, FCC ID, and serial of every unit. Photograph each before opening.
- [ ] **Confirm spare units:** request at least 2-3 identical units. One for non-destructive analysis, one as the desolder/chip-off sacrifice, one as a known-good reference and re-flash recovery source.
- [ ] **Identify the recovery path:** document the vendor reflash/factory-reset/serial-recovery procedure before bricking a unit. Note if a unit is unrecoverable once flash is wiped.
- [ ] **Define RF legal limits:** confirm which transmissions are authorized. Active jamming, deauth, and high-power transmit can be illegal outside a shielded environment. Prefer a Faraday/shielded bag or RF enclosure for transmit testing.
- [ ] **Set up a contained lab network:** isolated VLAN/SSID for the device so cloud and DUT traffic is observable and the device cannot reach production. Record the device MAC for filtering.
- [ ] **Agree on a contact for bricked/lost devices and emergency stop:** named person, response window, and what halts testing.

```
⚠️ Hardware teardown, desoldering, glitching, and chip-off are DESTRUCTIVE and IRREVERSIBLE. Do not begin invasive work without signed authorization and confirmed spare/recovery units. Active RF transmit (replay, jam, deauth) may be illegal outside a shielded enclosure. Confirm RF authorization and contain emissions.
```

---

## 2. Reconnaissance and Architecture

Map the whole system before touching it. The goal is an attack-surface diagram: every interface (physical, radio, network, app, cloud) and every trust boundary between them. FSTM Stage 1 (information gathering) lives here.

### Public Intelligence
- [ ] **FCC ID lookup:** read the FCC ID off the device label and pull the filing from fcc.gov/oet/ea/fccid (or fccid.io). Internal photos reveal chips, board layout, and debug headers without opening the case. The test report lists operating frequencies and radios.
- [ ] **Pull datasheets for every major IC:** SoC/MCU, flash, RAM, radio, PMIC. Datasheets give pinouts (UART, JTAG, SPI), voltage levels, and boot modes. Cross-reference with FCC internal photos.
- [ ] **Search for existing firmware and CVEs:** vendor support/download site, archived images, and `cve.mitre.org` / NVD for the model and chipset. Treat known CVEs as a vuln class to re-verify on this revision, not a checkbox.
- [ ] **Identify the cloud/backend platform:** many devices ride a white-label IoT cloud (Tuya, Tencent, AWS IoT, vendor SaaS). Fingerprint via DNS, certificate CN/SAN, and app strings. A known platform inherits known platform bugs.
- [ ] **OSINT the app and protocols:** app store listing, permissions, SDKs, privacy policy (data flows), and any public protocol docs or teardowns. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md).

### Attack-Surface Mapping
- [ ] **Enumerate physical interfaces:** USB, Ethernet, debug pads/headers, microSD, reset/recovery buttons, exposed test points.
- [ ] **Enumerate radios:** Wi-Fi, BLE/Bluetooth, Zigbee, Z-Wave, Thread, LoRa, sub-GHz, NFC, cellular. Confirm against the FCC filing.
- [ ] **Map the data flows and trust boundaries:** device to cloud, app to cloud, app to device (local), device to device (mesh). Note where auth/encryption is claimed at each hop.
- [ ] **Build the architecture diagram:** label every component, interface, protocol, and trust boundary. This drives prioritization for the rest of the engagement.

| Surface | Interfaces to enumerate | Primary risk |
| --- | --- | --- |
| Hardware | UART, JTAG/SWD, SPI/eMMC flash, I2C, USB, test pads | Debug shell, flash dump, secret extraction |
| Firmware | OTA images, flash contents, bootloader | Hardcoded creds, backdoors, no signing |
| Network | Telnet, SSH, HTTP(S) admin, UPnP, mDNS, custom TCP/UDP | Default creds, exposed API, weak TLS |
| Radio | Wi-Fi, BLE, Zigbee/Z-Wave, LoRa, sub-GHz | Pairing bypass, replay, sniffing |
| App | Companion app, local + cloud channels | Hardcoded keys, weak local auth |
| Cloud | REST/MQTT/WebSocket API, device provisioning | IDOR, broken authz, ownership abuse |

---

## 3. Hardware Analysis

Physical access usually yields the firmware and a root shell faster than any network bug. Work non-destructively first (in-circuit UART/JTAG), escalate to desolder/chip-off only if needed and authorized. FSTM Stage 2 acquisition often completes here.

### Teardown and Identification
- [ ] **Document the teardown:** photograph each step, the PCB (both sides), and every chip's markings before doing anything irreversible.
- [ ] **Identify the silicon:** read part numbers off the SoC/MCU, flash (SPI NOR like Winbond W25Q, NAND, or eMMC), RAM, radio, and PMIC. Look them up for datasheets and known boot/recovery modes.
- [ ] **Locate debug and test interfaces:** find UART (often a 4-pad row marked RX/TX/VCC/GND), JTAG/SWD headers, and unpopulated footprints. FCC internal photos and the datasheet pinouts guide this.

### Debug Interfaces (UART / JTAG / SWD)
- [ ] **Identify UART pinout:** use a multimeter (GND continuity) and a logic analyzer to find TX (idles high, bursts on boot) and GND, then guess RX. Determine baud (commonly 115200, also 57600).
- [ ] **Attach to UART and capture boot:** wire a USB-TTL adapter (match voltage, 3.3V typical) and capture the full boot log. The bootloader banner, kernel cmdline, and any login prompt or interrupt key are gold.
```bash
# Identify port, then open a serial console
screen /dev/ttyUSB0 115200
# Watch for: "Hit any key to stop autoboot", a root shell, or a login prompt
```
- [ ] **Test for an unauthenticated or default root shell on UART:** many devices drop straight to a root prompt or accept a known default. Interrupt the bootloader (U-Boot) for an even lower-level shell.
- [ ] **Probe JTAG/SWD:** use JTAGulator or a logic analyzer to find the pinout, then OpenOCD to halt the CPU, read/write memory, and dump flash. JTAG can bypass software locks and read protected regions if not fused off.

### Flash Extraction and Bus Sniffing
- [ ] **Dump SPI NOR flash in-circuit or chip-off:** clip a SOIC test clip onto the flash and read it with a flashrom-capable programmer (CH341A, FT2232). If in-circuit reads are noisy (SoC holding the bus), hold the SoC in reset or desolder the chip.
```bash
# Read a SPI flash chip with flashrom
flashrom -p ch341a_spi -r firmware_dump.bin
flashrom -p ch341a_spi -r dump1.bin && flashrom -p ch341a_spi -r dump2.bin
# Read twice and diff to confirm a stable, complete dump
```
- [ ] **Dump eMMC:** read via an eMMC reader/adapter or in-system through exposed clock/cmd/data lines. eMMC holds full Linux images on higher-end devices.
- [ ] **Confirm dump integrity:** read twice and diff; a stable image is required before firmware analysis. Note the architecture and endianness for emulation later.
- [ ] **Sniff I2C/SPI buses:** capture EEPROM/secure-element/sensor traffic with a logic analyzer (Saleae/sigrok). Look for secrets, provisioning data, and keys moving across the bus at boot.
- [ ] **Note glitching exposure (awareness):** if secure boot or read-out protection blocks you, voltage/clock fault injection (ChipWhisperer) may bypass it. Flag as a finding and an avenue; only attempt if scoped, time-boxed, and on a sacrificial unit.

---

## 4. Firmware Analysis

Firmware is where the credentials, keys, and logic live. Acquire it (Stage 2), extract it (Stage 3), analyze it statically (Stage 4-5), then emulate it for dynamic analysis (Stage 6). The hardware dump from Phase 3 is the most trustworthy source.

### Acquisition
- [ ] **Acquire firmware by the cheapest available path:** vendor download/OTA capture, the flash dump from Phase 3, or an intercepted update. Prefer the on-device dump; vendor images can differ from what actually ships.
- [ ] **Capture OTA update traffic:** MITM the device's update check and download (see Phase 5). Note whether the image is encrypted, signed, and served over TLS.

### Extraction
- [ ] **Run entropy analysis first:** high, flat entropy means encrypted or compressed; a clear structure means an unpacked image. This sets expectations before extraction.
- [ ] **Extract with binwalk:** binwalk 3.x (Rust rewrite, faster, fewer false positives) identifies and carves embedded filesystems and images recursively.
```bash
binwalk firmware_dump.bin                 # identify
binwalk -Me firmware_dump.bin             # recursive (Matryoshka) extract
```
- [ ] **Fall back to EMBA / unblob for stubborn images:** EMBA runs binwalk then automatically escalates to unblob for deeper extraction and orchestrates the whole analysis. Use it as the workhorse for the firmware phase.
```bash
# EMBA full firmware analysis (Docker)
sudo ./emba -f firmware_dump.bin -l ./logs -p ./scan-profiles/default-scan.emba
```
- [ ] **Identify and mount the filesystem:** SquashFS, JFFS2, UBIFS, CramFS, ext are common. Get a browsable root filesystem before hunting secrets.

### Static Analysis of the Filesystem
- [ ] **Hunt hardcoded secrets:** grep the rootfs for private keys, certs, API keys, tokens, Wi-Fi creds, and cloud endpoints. Tinxy and Philips devices stored creds in plaintext in firmware (CVE-2025-2189, CVE-2024-9991).
```bash
grep -rniE 'password|passwd|secret|api[_-]?key|token|BEGIN (RSA|EC|OPENSSH|PRIVATE)' squashfs-root/
find . -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.p12'
```
- [ ] **Check shadow/passwd for backdoor accounts and crackable hashes:** pull `/etc/shadow`, crack with hashcat/john. Look for undocumented accounts, hardcoded root passwords (CVE-2024-57790), and weak/empty passwords.
- [ ] **Inventory components and versions for outdated/CVE'd software:** BusyBox, dropbear/OpenSSH, OpenSSL, lighttpd/boa, dnsmasq, kernel. EMBA's SBOM engine builds this list; map each to known CVEs.
- [ ] **Review startup scripts and exposed services:** `/etc/init.d`, `/etc/rc*`, `inittab`. Identify what listens by default (telnetd, dropbear, web admin) and whether any debug service auto-starts.
- [ ] **Analyze the web admin and CGI binaries:** decompile CGI/native binaries (Ghidra) for command injection, auth bypass, and buffer overflows in request handlers. This is the classic router-RCE surface.
- [ ] **Look for OTA/update logic and keys:** find the update verification code and any signing public keys; absence of signature checks is a high-severity finding.

### Emulation (Dynamic)
- [ ] **Emulate the firmware with FirmAE:** FirmAE automates architecture detection, rootfs extraction, NVRAM, and networking, and brings the web/services up under QEMU (about 80% success on routers/cameras). Run dynamic tests against the emulated device when physical access is limited.
```bash
# FirmAE one-shot: check, then run, the image
./run.sh -c <brand> firmware.bin
./run.sh -r <brand> firmware.bin    # emulate and expose services on a tap interface
```
- [ ] **Fall back to manual QEMU + chroot:** for images FirmAE/Firmadyne cannot handle, chroot into the rootfs with the right `qemu-<arch>-static` and run target binaries directly to fuzz handlers.
- [ ] **Drive the emulated services:** point Burp/nuclei/zap at the emulated web admin and API to find injection and authz bugs without risking the physical unit. See [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md).

---

## 5. Network and Services

What the device exposes on the wire to anyone on the LAN, plus the device-to-cloud channel. Scan the live device, then intercept and tamper with its cloud traffic.

### Service Enumeration
- [ ] **Full TCP/UDP scan of the device:** `nmap -p- -sV` plus a UDP sweep of common IoT ports. Catch telnet, SSH/dropbear, HTTP(S) admin, RTSP, MQTT, CoAP, UPnP, mDNS, and vendor TCP services.
- [ ] **Test default and hardcoded credentials on every login:** web admin, telnet, SSH, RTSP. Cross-reference creds found in firmware (Phase 4). Default-cred IoT botnets (Mirai, Matrix) still thrive on this.
- [ ] **Enumerate UPnP/SSDP and check for dangerous actions:** `AddPortMapping` (WAN exposure), control of internal services. UPnP frequently exposes unauthenticated control.
- [ ] **Probe MQTT/CoAP brokers:** anonymous connect, wildcard `#` subscribe, and publish to control topics. A local or cloud broker with no ACL leaks and controls every device.
- [ ] **Review the web admin thoroughly:** auth bypass, CSRF, command injection in diagnostic/ping fields, path traversal, and session handling. Treat it like a web app: see [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md).

### TLS and Device-to-Cloud Traffic
- [ ] **Intercept device-to-cloud traffic (MITM):** put the device behind a proxy (mitmproxy/Burp transparent, or DNS redirect). Observe the API, MQTT/WebSocket frames, and provisioning handshake.
```bash
# Transparent intercept after redirecting the device's gateway/DNS to your host
mitmproxy --mode transparent --showhost
```
- [ ] **Test certificate validation:** present a self-signed/invalid cert. If the device accepts it, cloud traffic is fully MITM-able. Many embedded clients skip validation entirely.
- [ ] **Check for certificate pinning and its bypass:** if pinned, note it; pivot to the companion app or firmware to extract the pin or disable it for testing.
- [ ] **Assess TLS strength:** protocol versions, ciphers, and whether sensitive control traffic falls back to plaintext. Capture any cleartext credentials or tokens.
- [ ] **Replay and tamper captured cloud messages:** modify device IDs, commands, and tokens in intercepted frames to test server-side authorization (feeds Phase 7 IDOR testing).

---

## 6. Radio and Protocols

Every radio is an interface. Enumerate, then test pairing, sniffing, and replay per protocol. Keep transmit contained and authorized. For deeper Wi-Fi/BLE tradecraft and command detail see [Wireless](../Cheatsheets/Wireless.md).

### Wi-Fi
- [ ] **Assess the device's AP/provisioning mode:** the setup/SoftAP mode often has weak or no auth and leaks the Wi-Fi PSK during onboarding. Capture the provisioning exchange.
- [ ] **Test WPS and the station-side config:** WPS PIN brute force, and whether the device leaks credentials over its setup channel. See [Wireless](../Cheatsheets/Wireless.md).
- [ ] **Capture and crack the WPA handshake** if testing the device-hosted network, to confirm PSK strength.

### BLE / Bluetooth
- [ ] **Enumerate GATT services and characteristics:** `bluetoothctl`/`gatttool`/nRF Connect. Map readable/writable characteristics and look for control or config exposed without auth.
- [ ] **Test the pairing/bonding model:** Just Works pairing (no MITM protection) lets an attacker pair and control. Check for static passkeys and legacy pairing.
- [ ] **Sniff BLE and replay:** capture advertising and connection traffic (Ubertooth, Sniffle, nRF) and replay control writes. Test for command replay where the link lacks per-message freshness.
- [ ] **Probe for known BLE stack flaws:** legacy SweynTooth (crash/deadlock/bypass) and BleedingTooth families, plus current stack CVEs, against the device's BLE SoC.
- [ ] **Test for unauthenticated GATT control:** write to control characteristics without bonding. A surprising number of devices gate nothing.

### Zigbee / Z-Wave / Thread
- [ ] **Sniff Zigbee with a compatible radio:** capture join/commissioning. Test for default/leaked Trust Center link keys and unencrypted application traffic.
- [ ] **Assess Z-Wave inclusion:** test for downgrade to non-S2, weak inclusion, and replay of unencrypted frames.
- [ ] **Replay captured mesh commands** to test freshness/anti-replay at the application layer.

### Sub-GHz and LoRa
- [ ] **Capture and analyze sub-GHz control signals (SDR/HackRF):** demodulate with Universal Radio Hacker (URH) to recover the encoding and protocol of remotes, sensors, and actuators.
- [ ] **Replay fixed-code transmissions with Flipper Zero or HackRF:** capture and re-transmit. Fixed-code remotes (many garage/gate/doorbell/sensor links) replay trivially; rolling-code should resist a straight replay.
```bash
# Flipper Zero: Sub-GHz > Read (or Read RAW) to capture, then Saved > Send to replay
# HackRF capture/replay for analysis:
hackrf_transfer -r capture.iq -f 433920000 -s 2000000
hackrf_transfer -t capture.iq -f 433920000 -s 2000000 -x 20
```
- [ ] **Test rolling-code and authenticated links for weaknesses:** desync, RollJam-style capture-and-replay, and weak/PRNG-based code generation.
- [ ] **Assess LoRa/LoRaWAN join:** ABP vs OTAA, default AppKeys, and replay/join-accept handling.

```
⚠️ Transmitting on licensed/restricted bands, jamming, and deauth can be illegal and disruptive. Confirm RF authorization, transmit only within scope, and contain emissions in a shielded enclosure where possible.
```

---

## 7. Mobile and Cloud

The companion app and cloud API are usually the highest-impact, lowest-effort surface: a single cloud authz bug affects every customer, no hardware required. Test the app to find the API, then attack the API's server-side authorization. For app internals see [Mobile Application](Mobile%20Application.md) checklist; for the API methodology see [API Security](API%20Security.md) checklist and [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md).

### Companion App
- [ ] **Static-analyze the app for hardcoded secrets:** decompile (jadx/apktool, or the iOS bundle) and grep for API keys, cloud endpoints, MQTT creds, signing keys, and the AppSecret. Hardcoded cloud keys are common and grant API access. See [Mobile Application](Mobile%20Application.md) checklist.
- [ ] **Intercept app-to-cloud and app-to-device traffic:** proxy the app, defeat pinning if present (Frida), and map the full API the app drives.
- [ ] **Review local control auth:** apps that talk directly to the device on LAN/BLE often use weak or static local credentials separate from cloud auth.

### Cloud API Authorization
- [ ] **Map the API and identify object references:** device IDs, home/group IDs, user IDs, and share/claim tokens in requests. Predictable or enumerable IDs flag IDOR candidates.
- [ ] **Test BOLA/IDOR across tenants:** as Attacker A, swap in Victim B's device/home/user IDs (read status, stream, control). Server-side authz failures here let you control or watch other users' devices (Meari OpenAPI device-status IDOR CVE-2026-33357; Nexx CVE-2023-1751 pattern). This is the headline IoT cloud bug class.
- [ ] **Test broken function-level authz:** call admin/provisioning endpoints as a normal user; remove or downgrade tokens and re-send.
- [ ] **Attack device claiming/ownership transfer:** can you claim a device already bound to another account, or one you no longer physically possess? Test reset-then-reclaim, claim-without-possession, and stale-binding after transfer. Failed de-provisioning leaves prior owners with cloud access.
- [ ] **Test device sharing/guest access:** privilege of a shared/guest user, revocation actually cutting access, and whether a revoked user retains MQTT/WebSocket subscriptions or tokens.
- [ ] **Probe the realtime channel authz:** MQTT/WebSocket topic ACLs. Subscribe to another tenant's device topic; the Nexx flaw was exactly an unvalidated bearer token on the device-association WebSocket.
- [ ] **Test mass-assignment and provisioning abuse:** inject extra fields (owner, role, deviceType) during claim/register to escalate or bind unauthorized devices.

---

## 8. Authentication and Updates

The cross-cutting integrity controls: how the device proves identity, and how it trusts new code. Weak update integrity is a direct path to persistent RCE on the whole fleet.

### Device and Identity
- [ ] **Assess device-to-cloud authentication:** per-device unique credentials/certs vs a shared global key. A shared key extracted from one unit's firmware impersonates the whole fleet.
- [ ] **Test credential provisioning at manufacture:** are device certs/keys unique and stored in a secure element, or generated/derived predictably? Sniff the I2C secure-element bus (Phase 3) to confirm.
- [ ] **Check session and token handling:** token lifetime, revocation on password change/transfer, and replay resistance.

### Update Integrity
- [ ] **Verify update signing:** modify a captured firmware image, re-serve it, and confirm the device rejects an unsigned/tampered image. No signature check means trivial persistent backdoor (the highest-value finding on most devices).
- [ ] **Test the transport for the update:** plaintext HTTP or no cert validation lets you swap the image in transit (Phase 5).
- [ ] **Test rollback/downgrade protection:** can you force an older, vulnerable firmware version? Missing anti-rollback re-opens patched bugs.
- [ ] **Assess secure boot:** is the boot chain verified from ROM, and is read-out protection/JTAG locked (fused)? An open debug port or unsigned bootloader defeats secure boot. Confirm against Phase 3 findings.
- [ ] **Test for update-server takeover prospects:** hardcoded update URLs, expired/claimable update domains, and weak server-side controls that let an attacker serve firmware to the fleet.

---

## Recent Techniques (2024-2026)

- [ ] **binwalk 3.x (Rust rewrite):** faster, fewer false positives, broader filesystem support. Test by running it as the first-pass extractor before falling back to unblob/EMBA.
- [ ] **EMBA orchestrated firmware analysis:** binwalk-then-unblob extraction, SBOM/CVE mapping, and automatic emulated device startup to verify findings on the running firmware. Test by running a full EMBA profile against any acquired image.
- [ ] **FirmAE / Firmadyne emulation:** about 80% emulation success on routers and IP cameras via QEMU with NVRAM/network arbitration. Test by emulating the image and proxying its web/API when physical access is constrained.
- [ ] **CVE-2026-33357 (Meari OpenAPI device-status IDOR):** cloud API returns another tenant's device status without authorization. Test for: swapping device IDs across accounts on the cloud OpenAPI.
- [ ] **CVE-2023-1751 (Nexx) pattern, still recurring:** WebSocket device-association does not validate the bearer token owns the device. Test for: unvalidated bearer/topic ownership on realtime MQTT/WebSocket channels.
- [ ] **CVE-2024-57790 (hardcoded root in SPI flash, ICS/OT edge gateway):** root password recovered from the flash dump enabled serial console login. Test for: hardcoded creds in the SPI/eMMC dump and on UART.
- [ ] **CVE-2025-2189 (Tinxy) / CVE-2024-9991 (Philips):** plaintext credentials (incl. Wi-Fi) stored in firmware, extractable with physical access. Test for: cleartext secrets in the extracted rootfs.
- [ ] **CVE-2024-3721 (TBK DVR, "Broadside" Mirai variant):** command injection on an exposed endpoint weaponized into a botnet. Test for: injection in DVR/camera/router request handlers.
- [ ] **CVE-2025-65606 (TOTOLINK EX200):** firmware-upload error handling starts an unauthenticated root telnet service. Test for: services that fault-open during update/error paths.
- [ ] **Flipper Zero sub-GHz capture/replay:** one-device capture-and-replay of fixed-code 300-928 MHz links (gates, sensors, doorbells, fixed-code fobs). Test for: fixed vs rolling codes and per-message freshness.
- [ ] **BLE: SweynTooth legacy + current stack CVEs:** crash/deadlock/security-bypass families against BLE SoCs; pair with Sniffle/nRF sniffing. Test for: Just Works pairing, unauthenticated GATT writes, and known stack-level flaws on the specific BLE chipset.
- [ ] **Default/hardcoded-cred IoT botnets (Mirai, Matrix campaigns):** still the dominant real-world IoT compromise. Test for: default and firmware-extracted creds on every exposed login.

---

## Reporting and Evidence

### Evidence to Capture per Finding
- [ ] **Hardware:** annotated PCB/chip photos, the pinout you used, oscilloscope/logic-analyzer captures, and the flash dump hash. Note the exact unit (serial) and that it may be destroyed.
- [ ] **Firmware:** the path to the secret/backdoor in the rootfs, the extraction command, the component+version for CVE claims, and the cracked hash (redact the plaintext per policy).
- [ ] **Network/cloud:** full request/response pairs (raw HTTP, MQTT/WebSocket frames) for every authz finding, with both Attacker-A and Victim-B context shown. Save pairs to file at test time.
- [ ] **Radio:** the captured IQ/demodulated frame, the replay that triggered the action, and a short video for physical-effect findings (gate opens, lock disengages).
- [ ] **Reproduction:** exact steps, accounts/IDs used (anonymized), and tooling versions.

### Severity Guidance

| Severity | Typical IoT findings |
| --- | --- |
| Critical | Unauthenticated remote RCE; unsigned firmware update (fleet backdoor); cross-tenant cloud control/stream of arbitrary devices |
| High | Default/hardcoded creds on exposed service; cross-tenant IDOR (read); MITM of cloud control traffic (no cert validation); UART root shell + extractable fleet key |
| Medium | Sub-GHz/BLE replay of a control action; local-only auth bypass; missing rollback protection; verbose info leak |
| Low | Physical-access-only secret extraction with no remote angle; minor info disclosure; defense-in-depth gaps |

Map findings to OWASP IoT Top 10 and ISVS requirement IDs. Anchor severity in the CVSS vector first, then label. A physical-access-only finding is not High unless it yields a remote/fleet-wide primitive (e.g., a shared key).

### Common False Positives to Rule Out
- [ ] **"Hardcoded key" that is a public cert or a non-secret default.** Confirm it is actually sensitive and actually used.
- [ ] **IDOR that returns data but is properly scoped server-side.** Re-test cross-account with a genuinely different victim object; a 200 is not proof of access to someone else's data.
- [ ] **Replay that "works" because you used your own credential/session.** Confirm the captured signal/message replays without your secrets present.
- [ ] **Emulated-only behavior that does not reproduce on hardware.** NVRAM/network arbitration in FirmAE can create artifacts. Confirm on the physical unit before reporting.
- [ ] **TLS "no validation" that is actually pinned/handled elsewhere.** Confirm with a real invalid-cert MITM, not an assumption.

---

## Tools and References

| Category | Tools |
| --- | --- |
| Firmware extraction/analysis | binwalk 3.x, EMBA, unblob, firmwalker, Ghidra |
| Emulation | FirmAE, Firmadyne, QEMU (`qemu-<arch>-static`), Docker |
| Hardware/flash | flashrom, CH341A/FT2232, SOIC test clip, JTAGulator, OpenOCD, logic analyzer (Saleae/sigrok), ChipWhisperer (glitching) |
| Serial/debug | USB-TTL adapter, screen/minicom, bus pirate |
| Network | nmap, mitmproxy, Burp Suite, nuclei, MQTT/CoAP clients |
| Radio | HackRF, Flipper Zero, Ubertooth/Sniffle (BLE), Universal Radio Hacker (URH), GNURadio, RTL-SDR |
| Mobile | jadx, apktool, Frida, objection |

References:
- OWASP IoT Top 10 (and OWASP Internet of Things project)
- OWASP Firmware Security Testing Methodology (FSTM), 9 stages
- OWASP IoT Security Verification Standard (ISVS), levels L1-L3
- OWASP MASTG/MASVS (companion app), OWASP API Security Top 10 (cloud API)
- FCC ID database (fccid.io / fcc.gov/oet/ea/fccid) for internal photos and RF filings
- NVD / cve.mitre.org for model and chipset CVEs

---

## Related
- [Wireless](../Cheatsheets/Wireless.md)
- [Mobile Application](Mobile%20Application.md)
- [API Security](API%20Security.md)
- [OT and ICS](OT%20and%20ICS.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [API JWT and GraphQL](../Cheatsheets/API%20JWT%20and%20GraphQL.md)
- [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
