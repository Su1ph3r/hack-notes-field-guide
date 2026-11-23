---
tags:
  - hack-notes
  - checklist
  - firmware
---

# Firmware and Embedded Device Testing Checklist

> Firmware-first methodology for an embedded device assessment: acquire the image, unpack it, read it statically, confirm reachability in the binary, then prove it on a running target. Use for routers, cameras, UPS/power gear, NVRs, industrial controllers, audio hardware, and similar. This is the device-agnostic firmware lane; for the full hardware/radio/app/cloud ecosystem see the [IoT Device](IoT%20Device.md) checklist. Commands and deeper tooling live in the linked cheatsheets; this is the ordered method, the pass/fail signals, and where to draw the honest line between proven and suspected.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Firmware Acquisition](#2-firmware-acquisition)
- [3. Extraction and Unpacking](#3-extraction-and-unpacking)
- [4. Static Filesystem Analysis](#4-static-filesystem-analysis)
- [5. Binary Analysis](#5-binary-analysis)
- [6. Emulation and Dynamic Analysis](#6-emulation-and-dynamic-analysis)
- [7. Network Services and Protocols](#7-network-services-and-protocols)
- [8. Hardware Interfaces](#8-hardware-interfaces)
- [9. Cryptography and Secure Boot](#9-cryptography-and-secure-boot)
- [10. Update Mechanism](#10-update-mechanism)
- [11. Wireless, RF, and OT Adjacency](#11-wireless-rf-and-ot-adjacency)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

The firmware is one build for one hardware revision. Pin the version and the revision before you touch anything, because a finding on build A is not automatically present on build B, and a byte offset from one SoC is noise on another. Decide up front which claims you can prove from the image alone and which need a live unit.

### Target and Version Pinning
- [ ] **Exact device, model, and hardware revision:** record the full model string, board revision (silk-screen rev, PCB marking), and region/SKU. Two SKUs of the same model routinely ship different flash layouts and different default accounts.
- [ ] **Firmware version range in scope:** get the specific build(s) under test and whether older/newer builds are in scope. A hardcoded account you find in 1.2.3 may have been added in 1.1.0 and removed in 1.3.0; the version is part of the finding.
- [ ] **Latest-release confirmation:** confirm the build you pulled is the current shipping release, not a cached or stale image. Hunt the latest release and verify every sink against that exact build. A fix claimed in a changelog means nothing until you see it in the release artifact.
- [ ] **Silicon and architecture:** record the SoC/MCU family and endianness if known from the datasheet or FCC filing. This sets your disassembler target before you ever open Ghidra.
- [ ] **Prior CVEs on the model and chipset:** pull known advisories for the device, the SoC, and the shared SDK (Realtek, MediaTek, Cortina reference stacks leak the same bug into dozens of OEM products). Treat each as a class to re-verify on this build, not a checkbox; a vendor may have forked and never patched.
- [ ] **Shared-SDK blast radius:** if the firmware is built on a reference SDK, a finding here likely reproduces across every OEM that shipped that SDK. Note the SDK and version so the report can speak to fleet scope honestly.

### Authorization and Legality
- [ ] **Flash-extraction authorization in writing:** chip-off, SOIC-clip reads, and JTAG dumps can brick a unit and may touch anti-circumvention law depending on jurisdiction and whether the image is DRM-protected. Confirm the client owns the units and accepts the legal and physical risk.
- [ ] **Redistribution limits on the image:** confirm whether the extracted firmware, strings, and keys can leave the lab, go in the report, or be shared with a coordinating body. Vendor firmware is copyrighted; a dumped image in a public repo is a separate problem you do not want to create.
- [ ] **Safety and bricking agreement:** name the sacrificial unit, the known-good reference, and the recovery path (serial reflash, factory ROM, JTAG recovery) before the first destructive step. Confirm the client accepts loss of the units you flag as at-risk.

### Provable vs Device-Dependent
- [ ] **Decide which bounds are byte-provable:** a hardcoded hash in `/etc/shadow`, a cleartext key in the rootfs, a missing signature check in the updater, these you can prove from the image and a crack. Mark them PROVEN-IN-IMAGE.
- [ ] **Flag device-dependent claims from the start:** a missing bounds check or a hardcoded account is a reachable vulnerability only on a live unit, with the service running, the input reaching the sink, and no mitigation you cannot see in the image. A string in a binary is not a 9.8 until the code path reaches it on a device.

```
⚠️ Flash extraction (SOIC clip, chip-off, JTAG) is DESTRUCTIVE and can permanently brick a unit,
and may carry legal exposure (anti-circumvention, redistribution of copyrighted firmware). Get
signed authorization, a confirmed recovery path, and a sacrificial unit before any invasive step.
```

---

## 2. Firmware Acquisition

Get the image by the cheapest path that yields the real shipping build. Prefer two independent sources when you can: a vendor download tells you what they published, an on-device dump tells you what actually runs, and the difference between them is sometimes the finding.

### Vendor and Network Sources
- [ ] **Vendor download portal:** pull the image from the official support/download site. Record the URL, the version, and a hash. This is the lowest-risk acquisition and often enough to start.
- [ ] **OTA / update-server capture:** let the device check for updates behind a proxy and capture the update manifest and the image download. Note whether the channel is TLS, whether the cert is validated, and whether the image is encrypted or merely compressed on the wire (see Phase 10).
- [ ] **Hidden or predictable update URLs:** many devices fetch from a predictable path (`/firmware/<model>/latest.bin`). Walk the update host for older builds; a diff across versions localizes added or removed backdoors fast.
- [ ] **Diff vendor download against on-device dump:** when you have both, compare them. A difference is either a benign per-unit config region or a sign the shipping build is not the published one. Either way you want to know before you cite an offset.

### On-Device Extraction
- [ ] **UART console dump:** if the bootloader or a root shell is reachable over UART (Phase 8), dump flash from U-Boot (`sf read`, `nand dump`) or from Linux (`dd` over the MTD partitions, `cat /dev/mtdblock*`). Slow but non-destructive.
- [ ] **SPI flash chip-off / SOIC-8 clip:** for SPI NOR (Winbond W25Q, Macronix MX25, GigaDevice), clip a SOIC-8 test clip and read with a CH341A or flashrom-capable programmer. If the SoC holds the bus, pull it into reset or desolder the chip.
- [ ] **JTAG/SWD dump:** halt the CPU with OpenOCD and read flash or memory directly. JTAG can bypass software read-out locks when the debug fuse is not blown.
- [ ] **Bootloader extraction:** capture the bootloader region separately (U-Boot, often at offset 0). It carries the environment, the boot command, and sometimes the signature-verification public key you will need in Phase 9.

```bash
# Read SPI NOR twice and diff to confirm a stable dump (anchor only; full tooling in cheatsheet)
flashrom -p ch341a_spi -r dump1.bin
flashrom -p ch341a_spi -r dump2.bin
cmp dump1.bin dump2.bin && echo "stable dump"
```

- [ ] **Confirm dump integrity before analysis:** read at least twice and compare. A single noisy read wastes a day of analysis on bit-flips that are not in the real image. Record the hash of the confirmed image.

### Recovery and Boot Modes
- [ ] **Vendor recovery mode:** many SoCs expose a serial or USB download mode (TFTP recovery, Rockchip MaskROM, Allwinner FEL, NXP serial download). It can read and write flash without a clip and is the safest path back from a bricked unit. Document it before the first destructive step.
- [ ] **TFTP/U-Boot recovery upload:** if the bootloader fetches a recovery image over TFTP, capture that exchange. It frequently accepts an unsigned image, which is both a recovery path for you and a finding for Phase 10.

---

## 3. Extraction and Unpacking

Carve the image into bootloader, kernel, and rootfs, then get a browsable filesystem. The one judgment call that trips people here: high entropy is compression until you prove it is encryption. Do not write "encrypted firmware" in a report because binwalk drew a flat entropy line.

### First-Pass Carving
- [ ] **Identify the container:** run `file` and `binwalk` for a first read of the layout (bootloader, kernel magic, filesystem signatures). Note offsets; you will mount or re-carve from them.
- [ ] **Recursive extraction:** carve embedded filesystems and nested images. `binwalk` (3.x Rust rewrite is faster with fewer false positives) and `unblob` both recurse; `firmware-mod-kit` still helps on older TRX/uImage router formats.
```bash
# Identify, then recursively extract (anchor only; full tooling in cheatsheet)
binwalk firmware.bin
unblob -e firmware.bin
```
- [ ] **Filesystem identification:** expect SquashFS (by far the most common, note the compressor: gzip/xz/lzma/lzo), JFFS2 and UBIFS on raw NAND, CramFS and romfs on smaller devices, ext2/3/4 on eMMC-backed Linux. Match the SquashFS tooling to the compressor or the unpack silently truncates.

### Compressed vs Encrypted
- [ ] **Do not call high entropy "encrypted":** compressed data (xz, lzma, gzip) also reads as high flat entropy. Confirm by trying the decompressor, by finding a recognizable header after the compressed region, or by locating the decompression routine in the bootloader. Entropy alone proves nothing.
- [ ] **Look for the structure encryption would hide:** a plausibly encrypted image has no filesystem magic anywhere, no readable strings, and no compressor that accepts it. If `strings` on the "encrypted" blob returns config keys, it is not encrypted.
- [ ] **Find the decryption path if it is encrypted:** the bootloader or a first-stage loader must decrypt it to run it, so the key or the routine is on the device. Pull the key from the bootloader or dump the decrypted image from RAM over JTAG after the SoC decrypts it.

### Component Identification
- [ ] **Separate bootloader, kernel, rootfs:** label each region with its offset and type. The kernel version (`strings` the kernel for the `Linux version` banner) and the rootfs libc tell you the CVE surface before you read a single binary.
- [ ] **Mount the rootfs read-only:** get a stable, browsable root (`mount -o loop`, or unpack with `unsquashfs`). Everything in Phase 4 runs against this tree.
- [ ] **Account for multiple partitions and overlays:** many devices carry a read-only squashfs base plus a writable JFFS2/UBIFS overlay that holds the live config and sometimes the real credentials. Extract and read both; the base image alone can hide the default that actually ships.
- [ ] **Keep a rebuildable copy:** firmware-mod-kit can unpack and repack a squashfs image, which matters when you want to modify and reflash for dynamic testing (Phase 6/10). Confirm you can repack before you rely on reflashing as a test method.

---

## 4. Static Filesystem Analysis

The credentials, keys, and startup logic live in the rootfs. This phase is high yield and low cost: grep, read, and crack. Keep one rule in mind throughout: a string is not a credential until you prove the code path reaches it.

### Accounts and Hashes
- [ ] **`/etc/passwd` and `/etc/shadow`:** pull both. Look for undocumented accounts, UID 0 accounts beyond root, empty-password fields, and hashes to crack with hashcat/john. A cracked root hash plus a reachable console is a real finding; a cracked hash for a disabled account is not.
- [ ] **Hardcoded and backdoor accounts:** grep init scripts and binaries for account names, `useradd`, and credential constants that create or gate a login the UI never shows. These persist across versions more often than vendors admit; check the version range.
- [ ] **Default credential material:** config defaults, factory-reset values, and provisioning passwords baked into the image. Note whether they are per-device or a single global value; a global default is a fleet-wide finding.

### Keys, Certs, and Secrets
- [ ] **TLS private keys and certs:** find `.pem/.key/.crt/.p12`. A shipped private key is extractable by anyone with the image and lets an attacker impersonate the device or decrypt its traffic fleet-wide.
- [ ] **API keys and cloud credentials:** grep for API keys, bearer tokens, cloud endpoints, MQTT creds, and Wi-Fi secrets. Confirm each is actually sensitive and actually used, not a public cert or a placeholder.
```bash
# Secret sweep over the unpacked rootfs (anchor only; full tooling in cheatsheet)
grep -rniE 'password|passwd|secret|api[_-]?key|token|BEGIN (RSA|EC|OPENSSH|PRIVATE)' squashfs-root/
find squashfs-root/ -name '*.pem' -o -name '*.key' -o -name '*.crt' -o -name '*.p12'
```
- [ ] **A key in the image is not automatically live:** confirm it is loaded and used by a running service, not a leftover test cert or a sample. "Found in firmware" and "used by the device" are two different claims; report which one you proved.

### Startup, Services, and Permissions
- [ ] **Init and startup scripts:** read `/etc/init.d`, `/etc/rc*`, `inittab`, and systemd units. Identify every service that auto-starts (telnetd, dropbear, web admin, vendor daemons) and any debug service that starts on an error path.
- [ ] **BusyBox applets:** list the symlinks to BusyBox to see which utilities are present (`telnetd`, `tftp`, `nc`). The applet set is the on-device toolkit an attacker inherits.
- [ ] **World-writable and setuid files:** `find` for setuid/setgid root binaries and world-writable files in the rootfs. A setuid custom binary is a local-privesc candidate for Phase 5.
- [ ] **Component and version inventory:** list BusyBox, dropbear/OpenSSH, OpenSSL/mbedTLS, the web server (lighttpd/boa/uhttpd), dnsmasq, and the kernel with versions, and map each to known CVEs. An SBOM tool (EMBA's engine, syft) builds this; the outdated-component list is often the fastest real finding in the image.
- [ ] **Config defaults:** read the shipped default config. Unauthenticated-by-default services, debug flags left on, and permissive defaults are findings even before you reach the binaries.
- [ ] **Persisted SSH host keys and dropbear keys:** a host key shipped in the image is identical across every unit, so a fleet-wide key lets an attacker impersonate any device or ride a trust relationship. Confirm whether the key is generated on first boot or baked in.
- [ ] **Cron and scheduled tasks:** read `/etc/cron*`, `/etc/crontabs`, and any vendor scheduler. A periodic job that fetches or runs from a writable path or a network location is a persistence and injection surface.

---

## 5. Binary Analysis

This is where device-dependent claims are won or lost. A missing bounds check is a vulnerability when you can show the untrusted input reaches it; otherwise it is a note. Identify the architecture correctly first, because a Thumb binary disassembled as ARM is pure garbage and every "finding" from that garbage is false.

### Architecture and Entry Point
- [ ] **Identify architecture and endianness:** `file` and `readelf -h` for ARM, MIPS (big vs little), PowerPC, m68k/ColdFire, MicroBlaze, or Xtensa. The flash dump byte order and the ELF header must agree before you disassemble.
- [ ] **Thumb detection before disassembly:** on ARM, check the low bit of the entry point. `e_entry & 1 == 1` means the entry is Thumb; set the disassembler to Thumb first or the first instructions decode to nonsense. Check this before you trust anything Ghidra auto-analyzed.
```bash
# Thumb check: low bit of e_entry (anchor only; full method in cheatsheet)
readelf -h busybox | awk '/Entry point/ {print $NF}'   # odd value => Thumb entry
```
- [ ] **Load address and base:** for raw (non-ELF) blobs, recover the load/base address from the bootloader or by matching string/pointer references, or Ghidra's cross-references point nowhere.

### Dangerous Sinks and Primitives
- [ ] **Command-injection sinks:** trace `system`, `popen`, `exec*`, and `do_system`-style wrappers in CGI and vendor daemons. Confirm an untrusted request field reaches the argument unescaped. This is the classic router/camera RCE surface.
- [ ] **Memory-unsafe calls:** map `strcpy`, `strcat`, `sprintf`, `memcpy`, `gets`, and length-less copies in network-facing handlers. Each is a candidate; the finding is the one where attacker-controlled length or data reaches it.
- [ ] **Missing bounds and length-floor checks:** look for handlers that read a length or index from the wire and use it without an upper bound, a lower bound, or a floor. A missing length floor on a network handler is an out-of-bounds read or write primitive, device-dependent until fired.
- [ ] **OOB read/write and write-what-where:** where a parsed offset or index indexes a buffer or table, check for the bounds check. An attacker-controlled index into a global table is a write-what-where candidate; prove reach before you rate it.
- [ ] **Authentication and authorization in the binary:** find where the daemon checks auth. A handler registered before the auth check, or a command dispatched without re-checking the session, is an auth bypass. Sweep the whole command table, not just the handler you were reading.
- [ ] **Format-string and integer sinks:** check `printf`-family calls that take a user-influenced format argument, and size/length arithmetic that can overflow or underflow before it reaches an allocation or copy. An integer that wraps before a `malloc` is a heap-overflow setup.
```bash
# List imported dangerous calls in a target binary (anchor only; full method in cheatsheet)
readelf --dyn-syms httpd | grep -iE 'strcpy|strcat|sprintf|system|popen|memcpy|gets'
```

### Reachability Discipline
- [ ] **Trace the path from input to sink:** name the listening service, the request that reaches the handler, and the absence of a bounds check or auth gate in between. Without that chain, you have a suspicious call, not a finding.
- [ ] **An unreferenced function is a claim about your tooling:** "no caller" from a disassembler that missed an indirect call, a jump table, or a Thumb/ARM mode switch is not proof the code is dead. Confirm absence by the disassembly, not by the absence of an auto-found xref.

---

## 6. Emulation and Dynamic Analysis

Emulation turns a static maybe into a fired yes without risking (or needing) the physical unit. It also lies: a handler that faults under QEMU because NVRAM is missing is an emulation artifact, not a crash you can report. Confirm anything load-bearing against hardware.

### User-Mode and Single-Binary
- [ ] **QEMU user-mode a single binary:** chroot into the rootfs with the matching `qemu-<arch>-static` and run the target daemon or CGI directly. Fastest way to reach one handler and fuzz its parser.
- [ ] **Docker with the right platform:** for ARM/ARM64 userland, run the rootfs in a container with `--platform linux/arm/v7` (or `arm64`) under binfmt/qemu. Clean, repeatable, disposable.
```bash
# Run an ARMv7 rootfs under emulation (anchor only; full setup in cheatsheet)
docker run --rm -it --platform linux/arm/v7 -v "$PWD/squashfs-root":/fw alpine chroot /fw /bin/sh
```

### Full-System Emulation
- [ ] **FirmAE / Firmadyne for the whole device:** FirmAE automates arch detection, rootfs extraction, NVRAM, and network bring-up and gets the web/services running under QEMU on most routers and cameras. Drive the emulated admin and API with Burp/nuclei to find injection and authz bugs.
- [ ] **Bring up the services deliberately:** if full-system emulation stalls, start the single daemon under user-mode QEMU with a stub NVRAM and faked `/dev` nodes. Getting the listener up is usually the whole battle.
- [ ] **Fuzz the parsers:** point a fuzzer (AFL++ with QEMU mode, or a protocol harness) at the network-facing parser you flagged in Phase 5. A reproducible crash under emulation is the evidence that upgrades a "missing bounds check" to a proven OOB, but confirm the crash is not NVRAM/stub noise.
- [ ] **Confirm emulated findings on hardware where it matters:** if the rating depends on the crash, reproduce it on a live unit. An emulation-only crash is INFERRED, not PROVEN.
- [ ] **Stub NVRAM and faked peripherals honestly:** when you patch around a missing NVRAM key or a `/dev` node to get a daemon to start, note every stub. A code path that only runs because you faked a value proved something about your stub, not the device.
- [ ] **Instrument the running process:** attach gdb (gdbserver over the emulated network, or native under QEMU) to catch the fault address and the controlled registers. A crash with `pc` under your control is the difference between a DoS note and a code-execution claim.

---

## 7. Network Services and Protocols

What the device exposes to the network, and whether those endpoints check who is calling. Scan the live or emulated device, then attack the custom vendor protocol, which is usually weaker than the HTTP admin and less tested.

### Service Enumeration
- [ ] **Full TCP/UDP scan:** `nmap -p- -sV` plus a UDP sweep. Catch telnet, SSH/dropbear, HTTP(S) admin, RTSP, UPnP, mDNS, and vendor TCP/UDP services on nonstandard ports.
- [ ] **Default and firmware-extracted credentials:** try documented defaults and the accounts/hashes recovered in Phase 4 on every login (web, telnet, SSH, RTSP). Default-cred reuse is still the dominant real-world embedded compromise.
- [ ] **Unauthenticated endpoints:** enumerate every handler the service exposes and test each without a session. The finding is the endpoint that acts (reads status, changes config, runs a command) with no auth, not the one that returns a login page.

### Protocol and Authorization
- [ ] **Vendor custom protocol:** reverse the proprietary TCP/UDP protocol (from the binary in Phase 5 and captured traffic). These home-grown protocols routinely ship no auth, no integrity, and a command set that maps straight to device control.
- [ ] **Auth bypass:** test whether a later command can be sent without completing the login handshake, whether a session token is actually validated, and whether the handler re-checks authorization per command. Sweep every command in the dispatch table, not the one you happened to read.
- [ ] **Property and command authorization gaps:** for get/set-property style protocols, test reading and writing properties a low-privilege or unauthenticated caller should not touch. Differential-check every property against the role that should gate it.
- [ ] **UPnP/SSDP and mDNS:** check UPnP for dangerous unauthenticated actions (`AddPortMapping`, service control) and mDNS for information leak and reachable control endpoints.
- [ ] **Diagnostic and debug endpoints:** ping/traceroute/nslookup fields, a `cmd=` or `debug=` parameter, and vendor diagnostic pages are the recurring command-injection surface. Test every field that could reach a shell call, tracing back to the Phase 5 sink.
- [ ] **RTSP and streaming auth:** on cameras and NVRs, test whether the RTSP stream and the snapshot/JPEG endpoint are reachable without credentials. An unauthenticated stream is a direct privacy finding independent of the admin interface.
- [ ] **MQTT/CoAP on the device:** if the device runs or connects to a broker, test anonymous connect, wildcard `#` subscribe, and publish to control topics. A broker with no ACL leaks and controls every device that shares it.

---

## 8. Hardware Interfaces

Physical access usually yields the firmware and a root shell faster than any network bug, and it is how you confirm secure-boot and read-out-protection claims. Work non-destructively first; escalate to desolder and glitch only when scoped and on a sacrificial unit.

### Serial and Debug
- [ ] **UART console and bootloader interrupt:** find the TX/RX/GND pads (TX idles high and bursts on boot; a logic analyzer confirms baud, commonly 115200). Capture the full boot log, then test for a drop to root shell and for the "hit any key" U-Boot interrupt that gives a lower-level shell.
- [ ] **JTAG/SWD debug:** locate the port with a JTAGulator or logic analyzer, then OpenOCD to halt the CPU, read memory, and dump flash. Confirm whether the debug fuse is blown; an open JTAG defeats most software protections.
- [ ] **Bootloader environment:** at the U-Boot prompt, dump the environment (`printenv`), check for `bootdelay` > 0, and look for a settable `bootcmd` or console that lets you boot an unsigned image or drop a shell.
- [ ] **Console password and silent-boot gates:** some bootloaders gate the console behind a password or hide the interrupt key. Check the environment and the bootloader binary for the compare; a hardcoded console password in the dumped bootloader is extractable and global.

### Buses, Test Points, and Secure Boot
- [ ] **SPI/I2C bus sniffing:** capture EEPROM, secure-element, and sensor traffic with a logic analyzer (Saleae/sigrok) or a Bus Pirate. Keys and provisioning data cross these buses in the clear at boot on many devices.
- [ ] **Debug test points:** probe unpopulated headers and test pads found in the teardown and FCC internal photos. An unmarked 4-pad row is a UART more often than not.
- [ ] **Glitching basics (awareness):** if secure boot or read-out protection blocks you, voltage or clock fault injection (ChipWhisperer) may bypass the check. Flag it as an avenue; attempt only if scoped, time-boxed, and on a sacrificial unit.
- [ ] **Secure-boot presence:** determine whether the boot chain is verified from ROM and whether JTAG and flash read-out are locked. Confirm against the firmware findings in Phase 9; an open debug port makes a "secure boot" claim moot.

---

## 9. Cryptography and Secure Boot

Image integrity is the control that decides whether a tampered firmware runs. The distinction that matters most and gets missed most: verifying a signature at boot time is not the same as verifying it at flash time. A device that boot-checks but flash-accepts can be written a malicious image that then fails to boot, or worse, runs an image signed for a different model.

- [ ] **Signature verification at flash time vs boot time:** test whether the updater verifies the image before writing it to flash, or only the bootloader verifies at boot. Flash-time-only or boot-time-only each leave a gap; prove which the device does by feeding a tampered image and watching where it is rejected.
- [ ] **Where the verification key lives:** find the public key or hash the device checks against (bootloader, a dedicated partition, OTP/fuses). A verification key stored in writable flash can be replaced; that defeats the whole chain.
- [ ] **Hardcoded symmetric keys:** a single global AES/HMAC key in the firmware that protects updates or config is extractable from one unit and breaks the fleet. Confirm it is used and not per-device.
- [ ] **Downgrade and rollback:** test whether an older, validly signed but vulnerable image is accepted. Missing anti-rollback re-opens every bug the vendor already patched.
- [ ] **Encryption vs signing confusion:** an encrypted image is not a signed image. Confidentiality (someone cannot read it) is not integrity (someone cannot replace it). Report them separately; a plaintext image with a real signature is often more secure than an encrypted one with no integrity check.
- [ ] **Signature coverage:** confirm the signature covers the whole image, not just a header or a manifest that lists hashes the device never recomputes. A signed manifest whose referenced blobs are not themselves hash-checked is a swap-the-payload gap.
- [ ] **Config and data partitions:** check whether the signed boot chain extends to the writable config/overlay partition. If it does not, an attacker with write access persists through a config the verified kernel then trusts.

---

## 10. Update Mechanism

The update path is the direct route to persistent RCE on the whole fleet. If you can get the device to run your code through its own update process, nothing else on the device matters as much.

- [ ] **Unsigned or unverified update acceptance:** modify a captured image, re-serve it, and confirm the device rejects it. Acceptance of a tampered or unsigned image is the highest-value finding on most devices.
- [ ] **OTA transport security:** confirm the update is fetched over TLS with a validated certificate. Plaintext HTTP or skipped cert validation lets you swap the image in transit (pair with Phase 7).
- [ ] **MITM of the update channel:** put yourself between the device and the update server (DNS redirect, transparent proxy) and serve a modified manifest or image. Prove whether the device can be driven to install attacker-controlled firmware.
- [ ] **Unsigned module / .so load:** check whether the device loads shared objects, plugins, or kernel modules without verifying them. An unsigned `.so` that the device `dlopen`s from a writable or attacker-influenced path is code execution without touching the main image.
- [ ] **Plaintext image with a boot-only-checked manifest:** a common real pattern is an unencrypted firmware shipped with an RSA-signed manifest that only the bootloader checks. Test whether the updater writes the image before (or without) checking that manifest; the signature is worthless if the write happens first.
- [ ] **Anti-rollback counter, not just version string:** real rollback protection compares a monotonic security-version counter the device will not decrement, not the cosmetic version in the UI. Test whether an older validly signed image with a lower counter is actually refused, or whether only the displayed version changed.
- [ ] **Update-server takeover prospects:** check for hardcoded update URLs on expired or claimable domains and weak server-side controls. A claimable update domain is a fleet-wide code-push primitive.

---

## 11. Wireless, RF, and OT Adjacency

Radios are additional firmware-reachable interfaces, and many embedded targets sit on an OT network where the device is the soft entry to hard infrastructure. Keep transmit contained and authorized; hand the detail off to the dedicated checklists.

- [ ] **BLE / Bluetooth:** enumerate GATT services, test the pairing model (Just Works gives no MITM protection), and test for unauthenticated control-characteristic writes. Firmware often gates nothing on the BLE path. Full method in [Wireless](../Cheatsheets/Wireless.md).
- [ ] **Zigbee / Thread / proprietary mesh:** sniff join/commissioning for default or leaked link keys and unencrypted application traffic. Replay captured mesh commands to test application-layer freshness.
- [ ] **Sub-GHz and proprietary RF:** capture control signals with an SDR (HackRF) or Flipper Zero and demodulate with Universal Radio Hacker. Fixed-code links replay trivially; rolling-code should resist a straight replay. Confirm the signal replays without your own credential present.
- [ ] **OT adjacency:** if the device speaks Modbus, BACnet, DNP3, or a vendor fieldbus, treat it as the pivot into the control network. Hand off to the [OT and ICS](OT%20and%20ICS.md) checklist and respect that an availability mistake on OT has physical consequences.

```
⚠️ Transmitting on licensed or restricted bands, jamming, and deauth can be illegal and
disruptive. Confirm RF authorization, transmit only within scope, and contain emissions in a
shielded enclosure where possible. On OT, a probe that reboots a controller is an incident.
```

---

## Recent Techniques (2024-2026)

The classes Cairn actually finds on networked audio, UPS/power, NVR/camera, and industrial gear. Each item is a technique class with a one-line test-for. Named CVEs are examples of the class, not the whole class.

- [ ] **Persistent hardcoded backdoor accounts (telnet/ftp/CLI):** an undocumented login baked into the image that survives across firmware versions. Test for: account constants and credential-creating init logic in the rootfs and binaries, then check the version range the account appears in.
- [ ] **Unauthenticated OOB read in a network daemon:** a request field (length, offset, index) read from the wire and used without an upper bound, leaking memory to an unauthenticated caller. Test for: length/index parsing in a pre-auth handler with no bounds check, confirmed by a reproducible read primitive.
- [ ] **Unauthenticated write-what-where in an embedded handler:** an attacker-controlled index or offset that selects the destination of a copy. Test for: parsed-offset-indexes-buffer patterns in network handlers; prove reach before rating.
- [ ] **Root no-MMU uClinux daemons with no memory protection:** on no-MMU uClinux, every process shares one flat address space and a corruption in one daemon can clobber another or the kernel. Test for: uClinux/flat-binary rootfs plus a memory-unsafe network daemon running as root; the lack of MMU raises impact.
- [ ] **Missing length-floor / index bounds on network-facing handlers:** not just a missing upper bound, a missing lower bound or floor that lets a zero or negative length underflow a size calculation. Test for: subtractions on a wire-supplied length used as a copy size.
- [ ] **Plaintext firmware with boot-only-checked RSA-signed manifest:** image is unencrypted and carries a real signature, but only the bootloader verifies it and the updater writes first. Test for: updater that flashes before manifest verification; prove where rejection actually happens.
- [ ] **Services that fault-open on an error path:** an update failure or malformed request that starts an unauthenticated telnet/debug service. Test for: error and update paths that launch a shell or listener instead of failing closed.
- [ ] **Unsigned `.so` / module load from a writable path:** device `dlopen`s a plugin or loads a module without verifying it. Test for: load-from-writable-or-influenced-path with no signature check.
- [ ] **binwalk 3.x and unblob as first-pass extractors:** faster carving with fewer false positives and broader filesystem support. Test by running both before reaching for firmware-mod-kit on older formats.
- [ ] **FirmAE full-system emulation:** high emulation success on routers and IP cameras via QEMU with NVRAM/network arbitration. Test by emulating the image and driving its web/API when physical access is constrained, then confirming load-bearing crashes on hardware.
- [ ] **Shared-SDK bug propagation across OEMs:** one vulnerable reference SDK (Realtek, MediaTek, Cortina, and similar) reappears in dozens of rebranded products. Test by confirming the chipset/SDK, then checking whether a known SDK bug survived the OEM fork on this build.
- [ ] **Hardcoded console or recovery password in the bootloader:** a global secret in U-Boot that gates the console or recovery mode. Test for: a password compare in the dumped bootloader, extractable and identical across the fleet.

---

## Reporting and Evidence

### Honest Bounds (read this before rating anything)
- [ ] **Label every finding PROVEN or INFERRED/SUSPECTED:** PROVEN means byte-verified in the image (a cracked hash, a cleartext key, a missing check you can point to by `path:offset`) or runtime-fired (a crash, a shell, a cross-account read you reproduced). INFERRED means the code looks wrong but you did not reach it. Say which, in plain words.
- [ ] **Flag DEVICE-DEPENDENT findings explicitly:** a hardcoded account or a missing bounds check is not automatically a 9.8. It is a proven 9.8 only when you show the service running, the input reaching the sink, and no mitigation you cannot see. On the image alone it is a reachable-pending-confirmation finding, and the report must say so.
- [ ] **Prove you can still produce the bytes:** keep the extraction command, the image hash, and the exact `path:offset` for every static claim, so the finding can be reproduced from the image, not just from your notes.

### Evidence to Capture per Finding
- [ ] **Static:** the unpack command, the image hash and version, the file path and byte offset of the secret/sink, the cracked hash (redact the plaintext per policy), and the component+version for any CVE claim.
- [ ] **Binary:** the architecture and (for ARM) Thumb/ARM mode, the disassembly of the sink with the missing check highlighted, and the traced path from the listening service to the sink.
- [ ] **Runtime:** the request/response or protocol frames that fired it, the crash artifact or shell, and whether it was reproduced under emulation only or on hardware. Save pairs to file at test time.
- [ ] **Hardware:** annotated PCB/chip photos, the pinout used, the logic-analyzer capture, and the flash-dump hash. Note the exact unit and that it may be destroyed.

### Severity Guidance
| Severity | Typical firmware examples |
|---|---|
| Critical | Unauthenticated remote RCE in a network daemon; unsigned/unverified update accepted (fleet backdoor); global signing/decryption key extracted from the image |
| High | Hardcoded backdoor account on an exposed service; unauthenticated OOB write reaching code execution on a live unit; MITM of the update channel; UART root shell plus an extractable fleet-wide key |
| Medium | Unauthenticated OOB read (info leak); missing rollback protection; local-only auth bypass; device-dependent finding not yet confirmed on hardware |
| Low | Physical-access-only secret extraction with no remote angle; verbose info leak; defense-in-depth gap |
| Info | Version banners, non-secret defaults, best-practice deviations with no reachable impact |

Anchor severity in the CVSS vector first, then label, and default to the lower band on a boundary. A physical-access-only finding is not High unless it yields a remote or fleet-wide primitive (a shared key, a reflashable backdoor). I tend to inflate; the device-dependent discount is real, apply it.

### Common False Positives to Rule Out
- [ ] **High binwalk entropy is not proof of encryption.** Compression reads as high entropy too. Confirm with the decompressor or the decryption routine, or do not claim encryption.
- [ ] **A string is not a reachable credential.** A hardcoded-looking secret in a binary is a finding only when a running code path uses it. "Found in firmware" and "used by the device" are different claims.
- [ ] **An unreferenced function is a claim about your tooling, not the binary.** Disassemblers miss indirect calls, jump tables, and Thumb/ARM switches. Confirm dead code by the disassembly, not by a missing auto-xref.
- [ ] **A cracked hash for a disabled account is not a login.** Confirm the account is enabled and the service that honors it is reachable.
- [ ] **An emulation-only crash can be an NVRAM/stub artifact.** Confirm on hardware before rating a crash that FirmAE produced.
- [ ] **A device-dependent bug rated at full severity is overstated until fired.** Rate the reachable-pending-confirmation version, then raise it when the live unit confirms.

---

## Tools and References

| Tool | Use |
|---|---|
| binwalk 3.x / unblob | First-pass carving and recursive extraction |
| firmware-mod-kit | Older TRX/uImage router image unpacking and rebuild |
| unsquashfs / jefferson / ubi_reader | SquashFS / JFFS2 / UBIFS extraction |
| flashrom + CH341A/FT2232 | SPI NOR chip-off and in-circuit reads |
| OpenOCD + JTAGulator | JTAG/SWD pinout discovery, CPU halt, flash dump |
| Bus Pirate / logic analyzer (Saleae/sigrok) | UART/SPI/I2C bring-up and bus sniffing |
| Ghidra (+ headless) | Disassembly and decompilation of embedded binaries |
| QEMU (`qemu-<arch>-static`) / Docker `--platform` | User-mode and container emulation |
| FirmAE / Firmadyne | Full-system firmware emulation |
| AFL++ (QEMU mode) | Fuzzing network-facing parsers |
| hashcat / john | Cracking recovered password hashes |
| ChipWhisperer | Voltage/clock fault injection (glitching) |

References:
- OWASP Firmware Security Testing Methodology (FSTM), 9 stages.
- OWASP IoT Security Verification Standard (ISVS), levels L1-L3.
- NIST SP 800-193 (Platform Firmware Resiliency) for update/integrity expectations.
- NVD / cve.mitre.org for model, SoC, and component CVEs.
- FCC ID database (fccid.io) for internal photos, chip identification, and RF filings.

---

## Related

- Checklists: [IoT Device](IoT%20Device.md), [OT and ICS](OT%20and%20ICS.md), [Wireless Network Assessment](Wireless%20Network%20Assessment.md)
- Cheatsheets: [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md), [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md), [Wireless](../Cheatsheets/Wireless.md)
- Playbooks: [Edge Device Exploit to Internal Foothold](../Playbooks/Edge%20Device%20Exploit%20to%20Internal%20Foothold.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
