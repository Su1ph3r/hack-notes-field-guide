---
tags:
  - hack-notes
  - checklist
  - physical
  - red-team
---

# Physical Security Testing Checklist

> Methodology for an authorized physical-security / covert-entry / red-team physical-intrusion assessment. Use top to bottom for any engagement that involves a tester physically present on client property: badge cloning, door bypass, on-site pretexting, network drops, and objective capture inside a target building.

```
⚠️ AUTHORIZATION AND SAFETY FIRST. Physical intrusion without a current, signed
   authorization letter is breaking-and-entering and can get you arrested or hurt.
   Do not start, do not improvise outside scope, and do not skip this section.
   - Carry the signed Letter of Authorization (LoA) on your person AT ALL TIMES.
   - Carry government photo ID matching the name on the LoA.
   - Stay strictly inside the approved buildings, areas, hours, and techniques.
   - NEVER use force on people. NEVER damage property or pick a lock you cannot
     restore. NEVER block fire exits or disable life-safety systems.
   - If detained or challenged, comply, present the LoA, and call the engagement
     point of contact (POC). Do not run, do not resist, do not escalate.
   - The tester's physical safety and the safety of staff and guards override any
     objective. Abort over arguing.
```

## Table of Contents
- [1. Pre-Engagement and Rules of Engagement](#1-pre-engagement-and-rules-of-engagement)
- [2. Reconnaissance and OSINT](#2-reconnaissance-and-osint)
- [3. Perimeter and External](#3-perimeter-and-external)
- [4. Access Control and Entry](#4-access-control-and-entry)
- [5. Pretexting and Social Engineering On-Site](#5-pretexting-and-social-engineering-on-site)
- [6. Internal Movement and Objectives](#6-internal-movement-and-objectives)
- [7. Network Drop and Persistence](#7-network-drop-and-persistence)
- [8. Reporting](#8-reporting)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Rules of Engagement

The single most important deliverable before anyone steps on site is a clear, signed Rules of Engagement (RoE) and a current Letter of Authorization. Nothing in this checklist is legal to perform without them.

### Authorization and legal cover
- [ ] **Signed LoA in hand:** Obtain a Letter of Authorization signed by someone with the authority to grant it (CISO, facilities VP, or a corporate officer who actually owns the buildings). Confirm the signer can legally authorize entry, not just a manager.
- [ ] **Validity window on the LoA:** LoA states explicit start/end dates and times. An expired letter is no protection. Renew if the engagement slips.
- [ ] **ID-check clause:** LoA states the holder must carry government photo ID matching the name on the letter, and that challengers should verify ID against the named tester.
- [ ] **Carry it always:** Physical copy on the tester's body at all times, plus a photo on the phone as backup. Each on-site operator carries their own.
- [ ] **Emergency contacts on the LoA:** Include 24/7 phone numbers for the primary POC and at least one backup (CISO and SOC manager). Keep this list SHORT (need-to-know only) so guards cannot phone a non-witting employee who blows the test.
- [ ] **Verify the contacts answer:** Call every emergency number before day one. A get-out-of-jail letter with a dead number is useless when you are in a security office.

### Scope definition
- [ ] **In-scope buildings and addresses:** List exact street addresses, building names, suite numbers, and floors that are authorized. Anything not listed is out of scope.
- [ ] **In-scope areas:** Define which interior zones count (lobby only? data center? executive floor?) and explicitly list off-limits zones (e.g. trading floor, classified spaces, HR records, medical).
- [ ] **Permitted techniques:** Confirm in writing what is allowed: tailgating, lock bypass, badge cloning, pretexting, network drops, dumpster diving, photography. Confirm what is forbidden: lock picking that risks lockout, breaking glass, social engineering of specific protected staff, accessing customer/regulated data.
- [ ] **Permitted hours:** Business hours, after hours, or both. Note guard shift times and cleaning-crew windows if relevant.
- [ ] **No-force / no-damage rule:** Written agreement that no destructive entry is permitted and that any lock or door must be left in working order.
- [ ] **Third-party / shared-tenant boundaries:** If the building has other tenants, landlords, or shared lobbies, confirm those areas are excluded and that the client has the right to authorize entry to shared space.

### Deconfliction and safety
- [ ] **Law-enforcement deconfliction:** Decide with the client whether local police are pre-notified. If not, the LoA must be strong enough to satisfy responding officers. Document the agreed handling of a police response.
- [ ] **Guard / SOC deconfliction:** Confirm whether on-site guards and the SOC are witting (informed) or unwitting. Unwitting is more realistic but raises the detention risk; plan accordingly.
- [ ] **Detention protocol:** Agreed steps if challenged or detained: stop, present LoA, request the POC be called, remain calm and compliant. Tester never resists or flees.
- [ ] **Safety plan:** Identify hazards (guards who may be armed, dogs, industrial areas, height/ladder work). Set a hard rule that the tester aborts rather than risk injury or confrontation.
- [ ] **Two-person rule (recommended):** Where possible, keep a second operator or off-site overwatch in contact so someone always knows the tester's location and status.

### Evidence and success criteria
- [ ] **Evidence/photo handling agreed:** Define what may be photographed and what must NOT (faces of staff, customer data, regulated documents). Agree on encrypted storage and a destruction/retention timeline for captured media and any cloned credentials.
- [ ] **Cloned-credential handling:** Agree that any cloned badge data is stored encrypted, used only in scope, and securely wiped after reporting. Never leave cloned credentials or live implants behind unaccounted for.
- [ ] **Define success / flags:** Agree what counts as a win up front, e.g. reach the server room, photograph the MDF, plant a callback implant that beacons out, sit at an unattended unlocked workstation, retrieve a planted "flag" document, or exfiltrate a marked asset. Write the flag list into the RoE.
- [ ] **Abort conditions:** Agree triggers that end the test early (life-safety event, real intruder/incident in progress, repeated detection, anything that endangers staff or operations).

---

## 2. Reconnaissance and OSINT

Map the target before going near it. Most of this is passive and can be done remotely. See [OSINT and Reconnaissance](OSINT%20and%20Reconnaissance.md) for the full OSINT methodology and tooling.

### Remote site mapping
- [ ] **Satellite and aerial imagery:** Use satellite/aerial views to map building footprint, parking, fence lines, gates, loading docks, generators, and likely camera mast positions.
- [ ] **Street-level imagery:** Use street view to study entrances, reader placement, door types, signage, smoking areas, and adjacent buildings. Note imagery dates; verify on site as it may be stale.
- [ ] **Building layout sources:** Pull floor plans from fire-evacuation diagrams, leasing/real-estate listings, permit filings, and LinkedIn office photos. Identify lobby, elevator banks, stairwells, restrooms (often inside the secure line), and likely server-room location.
- [ ] **Entrance inventory:** Enumerate every door: main lobby, employee side entrances, loading dock, garage, roof access, fire exits. Note which are badge-controlled, guarded, or propped.

### Human and credential recon
- [ ] **Badge / uniform research:** Find photos of employee badges and uniforms (LinkedIn, Instagram, press photos, conference lanyards). Note badge color, logo, photo layout, lanyard style, and orientation so a prop badge passes a glance test.
- [ ] **Vendor and contractor research:** Identify the cleaning company, HVAC/elevator vendor, ISP/telco, security integrator, and delivery couriers serving the site. Their uniforms and pretexts are high-value impersonation targets.
- [ ] **Employee schedules:** Profile arrival/departure peaks, lunch flows, shift changes, and cleaning-crew timing. Tailgating works best in busy in/out windows.
- [ ] **Social-media leakage:** Hunt staff posts for interior photos, badge close-ups, screen contents, server-room shots, network gear, and "first day at the office" badge selfies. Note Wi-Fi SSIDs and visible reader models.
- [ ] **Key personnel:** Identify reception, security guards, facilities, and IT staff who may challenge or assist. Identify the executives whose offices are objectives.

### Timing and on-site recon
- [ ] **Dumpster / waste recon (if in scope):** Time trash and shred pickups. Casually observe (or, if authorized, retrieve) discarded printouts, shipping labels, visitor logs, and old badges that reveal naming and access conventions.
- [ ] **Drive-by / walk-by recon:** Conduct one or more passive recon passes at different times of day. Photograph from public space only. Note guard patrols, camera fields of view, door-prop habits, and delivery schedules.
- [ ] **Pretext validation:** Confirm details a real vendor would know (account numbers, contact names, equipment models) so an on-site pretext survives a question.
- [ ] **Reader and camera survey:** From public vantage, identify reader makes/models (HID Prox, iCLASS, MIFARE), camera types and coverage, intercoms, and turnstile/mantrap presence to plan the entry approach.

---

## 3. Perimeter and External

Assess the outer layers before touching a door. Photograph everything from authorized vantage points.

### Boundary and grounds
- [ ] **Fencing and gates:** Inspect fence height, condition, gaps, and whether vehicle/pedestrian gates are tailgate-friendly. Note tailgate-detection (anti-passback) on vehicle gates.
- [ ] **Lighting:** Map lit vs dark approaches at night. Dark zones along a fence or near a side door are likely covert-approach routes.
- [ ] **Landscaping and cover:** Note shrubs, dumpsters, and parked-vehicle cover that conceal an approach to a door or window.

### Surveillance coverage
- [ ] **Camera / CCTV survey:** Map every camera, its type (fixed vs PTZ), and field of view. Identify blind spots: under-camera dead zones, areas between coverage, and doors not covered at all.
- [ ] **Monitoring posture:** Determine if cameras are actively monitored or recorded-only. A recorded-only camera does not stop entry, it only documents it.
- [ ] **Intercom / video entry:** Note buzz-in doors and whether reception screens callers, and how easily a pretext talks past them.

### Doors, windows, and openings
- [ ] **Door inventory and hardware:** For each external door, record lock type, hinge orientation (outswing hinges may be vulnerable), gap size, and presence of door-position sensors and astragals.
- [ ] **Windows and ground-floor openings:** Note accessible/openable windows, propped windows, and smoking-door props.
- [ ] **Loading docks:** Docks are a classic soft entry: roll-up doors left open, propped man-doors, busy with vendors who do not challenge. Assess dock supervision and the door between dock and interior.
- [ ] **Roof and utility access:** Note ladders, fire escapes, roof hatches, and utility/mechanical rooms that may bypass the main access-control line.

### Human-factor entry openings
- [ ] **Tailgating opportunities:** Identify doors with heavy two-way foot traffic where holding the door is the social norm. Rank by busyness and lack of guard.
- [ ] **Smoking areas:** Smoking doors are frequently propped or quick to reopen and staff routinely hold them. High-value tailgate target.
- [ ] **Delivery and reception flow:** Watch how couriers and vendors are admitted. A clipboard and a box often beat a badge.

---

## 4. Access Control and Entry

Defeat the electronic and mechanical access controls. Stay non-destructive. Capture evidence at each successful step.

### Tailgating and piggybacking
- [ ] **Tailgate test:** Follow an authorized person through a controlled door in a natural in/out window. Hands full, on a phone call, or carrying a box all increase success. Record whether anti-tailgate measures (mantrap, turnstile, guard) stop you.
- [ ] **Piggyback test:** Engage a staff member so they knowingly hold/badge the door for you (pretext: "forgot my badge," "I'm with the HVAC crew"). Note whether challenge-culture exists.
- [ ] **Reverse / exit tailgate:** Catch a door as someone exits, or wait for a propped door, to enter without ever presenting a credential.

### Badge cloning and credential capture
- [ ] **Identify card technology:** Read a target badge to determine frequency and type: 125 kHz LF (HID Prox, EM4100, Indala, AWID) vs 13.56 MHz HF (MIFARE Classic, iCLASS, DESFire, SEOS). Technology dictates clonability.
- [ ] **LF clone (125 kHz):** LF Prox/EM4100/Indala are typically cloneable in under 60 seconds to a T5577 blank or emulated on a Flipper Zero / Proxmark3. Capture a target read in a tailgate/elevator/queue, write the blank, and test at an in-scope reader.
- [ ] **HF read (13.56 MHz):** MIFARE Classic with weak/default keys is cloneable (nested/darkside key recovery). iCLASS SE, SEOS, and DESFire EV2/EV3 resist consumer cloning and usually cannot be duplicated, document that as a control that held.
  ```
  # Proxmark3 (Iceman) quick triage of a presented card
  hf search        # detect HF tech (MIFARE/iCLASS/etc.)
  lf search        # detect LF tech (Prox/EM/Indala)
  ```
- [ ] **Long-range / covert read:** Where allowed, use a concealed long-range reader (e.g. a Tastic Thief style reader with an ESPKey/Proxmark backend) to skim badges at conversational distance or from a bag. Note effective read range achieved.
- [ ] **Wiegand wire-tap (if authorized + accessible):** If a reader's back wiring is reachable, an ESPKey clipped to the D0/D1 Wiegand lines captures every swipe in cleartext for later replay. Flag as a high-impact finding where exterior readers expose wiring.
- [ ] **Clone validation:** Test the cloned credential at an in-scope reader and record success/failure. Do NOT use it beyond the agreed scope.

### Door bypass (non-destructive)
- [ ] **Under-door tool:** On inswing doors with a lever handle, slip an under-door tool ("UDT") to hook and pull the interior handle. Note whether door sweeps/astragals defeat it.
- [ ] **Latch slipping / loiding:** On spring-latch doors without a deadlatch or guard plate, slip a shim ("Jim"/loid) between latch and strike to retract the bolt. A deadlatching latch should defeat this, record which.
- [ ] **REX motion-sensor abuse:** On doors with an interior PIR Request-to-Exit sensor, trigger it from outside by introducing motion and temperature change through the door gap (e.g. compressed air/canned air inverted under the door). A correctly placed/shielded REX should not be triggerable from outside.
- [ ] **Lever / handle bypass:** Test crash-bar and lever-handle manipulation tools (e.g. tools that reach a push-bar through a gap). Non-destructive only.
- [ ] **Lock picking / bypass (if in scope):** Pick, bump, or bypass conventional locks only where authorized and where you can restore the lock. Stop at any sign of risk of lockout. Document time-to-open.
  ```
  ⚠️ Do not pick or shim a lock you cannot return to working order, and never
     leave a door insecure when you walk away. A door you opened is your
     responsibility until it is re-secured.
  ```
- [ ] **Hinge / surface-hardware attacks:** Where outswing doors expose hinge pins or where strikes/closers are reachable, assess (do not destroy) and report.

### Anti-bypass controls
- [ ] **Mantrap / airlock test:** Where a mantrap exists, confirm it actually enforces one-person-per-cycle and rejects tailgating. Test the interlock behavior.
- [ ] **Turnstile / speed-gate test:** Attempt tailgate, jump-over, crawl-under, and "two on one badge" against optical turnstiles. Note alarm/response.
- [ ] **Anti-passback:** Test whether the system blocks a badge used to enter twice without an exit (indicates a shared/cloned badge in use).
- [ ] **Door-held / forced-door alarms:** Note whether held-open and forced-door conditions actually alarm and whether anyone responds.

---

## 5. Pretexting and Social Engineering On-Site

People are the most reliable bypass. Pretext must be researched, rehearsed, and backed by props. See [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md) for the broader social-engineering and pretext methodology.

### Pretext selection
- [ ] **Choose a researched pretext:** Common high-success on-site pretexts: delivery courier, HVAC/elevator/maintenance vendor, IT support / "here to fix the network," fire/safety inspector, new employee who forgot their badge, telco/ISP technician, auditor. Pick one supported by your recon.
- [ ] **Back the pretext with facts:** Know the real vendor name, the contact you "report to," the equipment/ticket number, and a plausible reason. A pretext fails on the first question you cannot answer.
- [ ] **Time the pretext:** Align with the vendor's real schedule (deliveries mid-morning, cleaning after hours) so the pretext is expected, not anomalous.

### Props and appearance
- [ ] **Lanyard and badge props:** Carry a convincing prop badge/lanyard matching the recon (color, logo, photo layout). Even a wrong-but-confident badge often passes a glance. A printed visitor or vendor badge plus a hi-vis vest is potent.
- [ ] **Uniform / role kit:** Dress the part: hi-vis and tool bag for maintenance, polo and laptop bag for IT, courier garb and a box for delivery. Carry a clipboard, work order, or tablet as a prop "ticket."
- [ ] **Pretext kit contents:** Assemble a kit per pretext: work order printouts, business cards, a clipboard, a label-maker, a fake "maintenance" sticker, and the relevant entry tools concealed appropriately.

### Confidence techniques
- [ ] **Confidence and tempo:** Move with purpose, make brief eye contact, greet people first. Hesitation invites challenge; acting like you belong defeats most soft controls.
- [ ] **Authority and urgency:** Use plausible authority ("facilities sent me") and mild urgency ("they need this fixed before the meeting") to discourage verification.
- [ ] **Reciprocity / helpfulness:** Let a helpful employee badge you in or carry your "heavy box." Note staff who hold secure doors for a stranger as a finding.
- [ ] **Reception / guard handling:** Test whether reception verifies appointments, calls the named contact, checks ID, and logs visitors. Note every gap (no sign-in, no escort, no callback).
- [ ] **Shoulder surfing and desk recon:** While moving, observe unlocked screens, sticky-note passwords, whiteboards, and printouts. Photograph in-scope evidence only.

---

## 6. Internal Movement and Objectives

Once inside the secure line, reach the agreed objectives quietly and prove it. Photograph each flag.

### Orientation and blending
- [ ] **Internal recon:** Locate stairwells, elevators, restrooms (often inside the secure zone and a safe regroup spot), and signage pointing to IT/server/MDF areas.
- [ ] **Maintain cover:** Keep the pretext (vest, clipboard, tool bag). Move toward objectives as if assigned there; avoid lingering in open areas.
- [ ] **Internal door controls:** Note whether interior sensitive doors are separately badged or whether a single perimeter breach grants free internal movement (a major finding if so).

### Sensitive-area objectives
- [ ] **Server room / data center:** Attempt to reach the server room. Test its door controls separately. Photograph the rack(s) and door as proof of access. Do not touch production gear beyond the agreed objective.
- [ ] **MDF / IDF / telecom closets:** Reach the main and intermediate distribution frames and wiring closets. These are prime spots for a network drop (see phase 7) and often poorly locked. Photograph open switches and patch panels.
- [ ] **Executive offices:** Reach exec/finance/HR offices if in scope. Note unlocked doors, exposed documents, and accessible workstations.
- [ ] **Other flags:** Reach any other agreed objectives (badge office, mailroom, lab) per the flag list.

### Asset and data capture (proof, not theft)
- [ ] **Unattended unlocked workstations:** Find logged-in, unlocked machines. As authorized, prove access (screenshot of a benign prompt, plant a marker file, or note the open session). Do NOT read regulated or customer data.
- [ ] **Network jacks:** Identify live wall jacks, conference-room ports, and printers/VoIP phones you can unplug to get a jack. Test whether an unauthenticated device gets network access (link to phase 7).
- [ ] **USB drop test:** Where in scope, leave marked USB "bait" in common areas (lobby, break room, parking) to measure who plugs them in (beacon callback). Use benign payloads only.
- [ ] **Document / asset proof:** Photograph (do not remove unless agreed) sensitive printouts, whiteboards, and shipped/stored assets. If physical exfil of a marked asset is a flag, take only the agreed marked item and log chain of custody.
- [ ] **Implant placement:** Place any agreed dropped implant or rogue device (see phase 7). Record exact location and time for later retrieval and for the report.
- [ ] **Inventory everything you placed:** Maintain a running list of every implant, USB, and marker placed so all are retrieved and nothing is left behind.

---

## 7. Network Drop and Persistence

If the objective includes a network foothold, plant a rogue device that calls back so the internal-network team can continue remotely. See [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md) for what to do once the implant is on the wire, and [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md) for the C2/tunnel side.

### Implant selection and prep
- [ ] **Choose the implant:** Match device to the drop. Small/fast: Shark Jack for a quick scripted payload. Persistent MITM: LAN Turtle or a Raspberry Pi dropbox with two NICs and a cellular/Wi-Fi out-of-band uplink for remote callback.
- [ ] **Pre-stage callback:** Configure the implant before the engagement to auto-connect to your C2/VPN on boot (reverse SSH, VPN, or a beacon) over an independent uplink, so it phones home without relying on the target's egress.
- [ ] **Conceal and power:** Plan placement (behind a printer, VoIP phone, under a desk, in an IDF) with reliable power. Devices that pass-through power/Ethernet to the host they replaced are less likely to be noticed.

### NAC / 802.1X bypass at the jack
- [ ] **Probe the jack:** Plug into a wall/conference/printer jack and check whether you get a DHCP lease and reach the network with no authentication. Many jacks (printers, phones, public rooms) are unauthenticated, that is an immediate finding.
- [ ] **Detect 802.1X:** If access is blocked, look for 802.1X (EAPOL). If present, plan a transparent-bridge bypass.
- [ ] **Transparent-bridge bypass:** Insert the implant inline between an already-authenticated device (e.g. a VoIP phone or a printer) and its jack, bridge the two NICs, and ride the device's existing authenticated session to source your own traffic from behind it (the classic "drop and run" NAC bypass). Spoof the host MAC where needed.
  ```
  ⚠️ Inline insertion briefly drops the host's link. Do it on a non-critical
     device, expect a few seconds of host re-auth, and never bridge through a
     life-safety, medical, or production-critical endpoint.
  ```
- [ ] **MAC-auth-bypass (MAB) test:** Where ports fall back to MAC allow-listing, clone the MAC of an allowed device (printer/phone/camera) and test whether the port admits you.
- [ ] **Verify callback:** Confirm the implant beacons out to C2 from inside before you leave. A drop that never calls home is a failed objective. Note egress path that succeeded (DNS, HTTPS, cellular).
- [ ] **MACsec / strong-NAC note:** If the network enforces MACsec (802.1AE) or post-2004 802.1X with per-port supplicants, transparent-bridge bypass likely fails. Document that as a control that held.

### Hygiene
- [ ] **Label and track implants:** Tag each implant (covertly) and log its location/time so every device is recovered. Never leave a live implant behind after the engagement.
- [ ] **Retrieval plan:** Confirm how and when each implant comes out (return visit or client-assisted) and that all callbacks are torn down afterward.

---

## 8. Reporting

The report is the deliverable. Tell the story chronologically and make every control failure fixable.

- [ ] **Attack timeline:** Reconstruct the engagement as a timestamped narrative: arrival, recon, each entry attempt, each control that held or failed, objectives reached, exit. Tie photos to timeline entries.
- [ ] **Photo evidence per step:** Attach the captured photo/video for each milestone (door bypassed, server room reached, implant placed, unlocked workstation). Redact staff faces and any regulated data.
- [ ] **Control failures:** For each finding, name the specific control that failed (no anti-tailgate, cloneable LF badges, unmonitored cameras, unauthenticated jack, no visitor verification) and the access it granted.
- [ ] **Controls that held:** Credit the controls that stopped you (mantrap rejected tailgate, SEOS badges not cloneable, 802.1X/MACsec blocked the drop). A balanced report builds trust and shows what to keep.
- [ ] **Risk rating:** Rate each finding by ease of exploitation and impact of the access gained. A single cloneable Prox badge that opens the data center is critical; a propped smoking door to a low-value zone is lower.
- [ ] **Remediation:** Give concrete, prioritized fixes (upgrade LF Prox to SEOS/DESFire, add anti-tailgate at the data-center door, enable forced/held-door alarms with SOC response, enforce 802.1X with MACsec, port-disable unused jacks, train reception on visitor verification).
- [ ] **Cleanup confirmation:** State that all cloned credentials were wiped, all implants/USBs recovered, all callbacks torn down, and all doors/locks left secured.

---

## Recent Techniques (2024-2026)

- [ ] **MIFARE Classic static-encrypted-nonce + backdoor keys (Quarkslab, 2024):** Hardware backdoor keys and a static-encrypted-nonce attack defeat even hardened MIFARE Classic compatibles. Test for: re-pull any "MIFARE Classic" badge with current Proxmark Iceman attacks before assuming it is safe.
- [ ] **iCopy-X / iCopy-XS as one-touch cloner:** Pocket Iceman-based cloner reads ~45 and writes ~37 card types, with an iCS decoder add-on that extends to some iCLASS SE / SEOS workflows. Test for: how fast a captured LF/HF badge becomes a working clone in the field.
- [ ] **Chameleon Ultra emulation:** Battery card-form emulator that replays captured HF/LF credentials at a reader without a blank. Test for: replay-based entry where writing a physical blank is impractical.
- [ ] **Flipper Zero LF triage:** Flipper handles most 125 kHz (HID Prox, EM4100, Indala) and weak MIFARE Classic in seconds; it does NOT clone DESFire EV2/EV3, modern iCLASS SE, or PIV. Test for: which of the site's badges fall to a consumer tool vs require the control to hold.
- [ ] **ESPKey Wiegand wiretap + long-range "new Tastic Thief" (NetSPI):** ESPKey clipped to D0/D1 captures swipes in cleartext; paired with a long-range reader it skims and harvests credentials covertly. Test for: exposed reader wiring on exterior/garage readers and skimmable read range.
- [ ] **HID Mercury / LenelS2 controller CVEs (CVE-2022-31481 RCE CVSS 10.0 and the -31479/-31483/-31486 set):** Unauthenticated buffer overflow to RCE and command injection on widely deployed Mercury LP/EP controllers can remotely unlock doors. Test for: controller firmware version and network exposure of the access-control panel itself.
- [ ] **OSDP vs Wiegand:** Sites still on cleartext Wiegand are wiretap/replay-vulnerable; OSDP Secure Channel mitigates it but is often deployed in clear/unsecured mode. Test for: whether reader-to-panel uses OSDP Secure Channel or falls back to clear.
- [ ] **Raspberry Pi 4 NAC dropbox + dolosjs/nac_bypass/Red-Box tooling:** Mature transparent-bridge 802.1X-bypass implants with out-of-band cellular callback. Test for: drop-and-run bypass behind an authenticated phone/printer and successful C2 egress.
- [ ] **Hak5 Shark Jack / LAN Turtle drops:** Fast scripted recon (Shark Jack) and persistent covert MITM/remote-access (LAN Turtle) as off-the-shelf implants. Test for: time-to-callback from a concealed jack.
- [ ] **MACsec (802.1AE) and post-2004 802.1X as the counter:** Networks enforcing MACsec or modern per-port supplicants defeat inline-bridge bypass. Test for: whether the segment actually enforces it or only partially.
- [ ] **REX PIR abuse via thermal+motion through the door gap:** Inverted compressed air introduces the temperature drop and motion a PIR REX needs. Test for: any motion-REX door triggerable from outside through gaps or mail slots.

---

## Reporting and Evidence

**Capture per finding:**
- Timestamped photo/video of the milestone (door open, area reached, implant in place, clone working at a reader, unlocked session).
- The specific control that failed and the access it yielded.
- For cloning: card technology, capture method, time-to-clone, and the reader it worked against (never the actual credential data in the report body).
- For network drops: jack location, NAC posture observed, bypass method, and proof of C2 callback (egress path, timestamp).
- Chain of custody for any marked asset physically exfiltrated.

**Severity guidance:**

| Severity | Example |
|---|---|
| Critical | Cloneable badge or single tailgate reaches the data center / MDF; rogue implant gets persistent internal C2; controller CVE remotely unlocks doors. |
| High | Perimeter breach grants free internal movement; unauthenticated jack yields network access; unmonitored cameras + unalarmed forced door. |
| Medium | Tailgate into general office space; propped doors; reception does not verify visitors or check ID. |
| Low | Cosmetic policy gaps; dark perimeter zones; minor signage/process issues with no demonstrated access. |

**Common false positives to rule out:**
- An "unlocked" door that is actually within an already-public area (no control was bypassed).
- A "cloned" badge that was never validated at a live reader, confirm it actually opens a door.
- A network jack that issues a DHCP lease but is dropped into a quarantine/guest VLAN with no internal reach, verify you can actually touch internal hosts.
- A camera blind spot that is covered by a guard patrol or a second camera you missed.
- Attributing a control "failure" to a witting employee who was actually instructed to assist.

---

## Tools and References

| Category | Tools / References |
|---|---|
| RFID cloning | Proxmark3 RDV4 (Iceman firmware), Flipper Zero, iCopy-X / iCopy-XS, Chameleon Ultra, T5577 blanks |
| Long-range / wiretap | Long-range reader (Tastic Thief style), ESPKey Wiegand wiretap |
| Covert entry | Under-door tool, latch shims ("Jim"/loid), lever/crash-bar bypass tools, lock-pick / bypass kits (Sparrows, Covert Instruments, Serepick, SouthOrd) |
| Network implants | LAN Turtle, Shark Jack, Raspberry Pi dropbox (dual-NIC), Packet Squirrel |
| NAC bypass tooling | nac_bypass (scipag), dolosjs (fkasler), Red-Box NAC bypass |
| Pretext kit | Hi-vis vest, prop badge/lanyard, clipboard, work-order printouts, tool bag, label maker |
| References | OSSTMM (physical security testing), NIST SP 800-115, PTES physical section, "Inside the NAC Pi" / The Hacker Recipes (NAC), NetSPI get-out-of-jail-letter guidance |

---

## Related
- [OSINT and Reconnaissance](OSINT%20and%20Reconnaissance.md)
- [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md)
- [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md)
- [Red Team Operation](Red%20Team%20Operation.md)
- [Wireless](../Cheatsheets/Wireless.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- BypassBurrito
