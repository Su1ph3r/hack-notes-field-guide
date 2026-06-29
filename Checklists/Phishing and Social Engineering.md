---
tags:
  - hack-notes
  - checklist
  - phishing
  - social-engineering
---

# Phishing and Social Engineering Testing Checklist

> Use for authorized phishing and social-engineering engagements: spear-phishing, AiTM credential and token theft, vishing/smishing, MFA-fatigue and help-desk pretexting, through to initial-access handoff. Methodology-first. Command detail lives in the linked cheatsheets.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. OSINT and Target Profiling](#2-osint-and-target-profiling)
- [3. Infrastructure Setup](#3-infrastructure-setup)
- [4. Pretext and Payload Development](#4-pretext-and-payload-development)
- [5. Credential Harvesting and AiTM](#5-credential-harvesting-and-aitm)
- [6. Delivery and Tracking](#6-delivery-and-tracking)
- [7. Vishing, Smishing, and Physical-Adjacent SE](#7-vishing-smishing-and-physical-adjacent-se)
- [8. Post-Compromise Handoff](#8-post-compromise-handoff)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Social engineering touches real people and real law. Nothing here proceeds without written authorization and an agreed safe-word. Scoping failures (out-of-scope targets, captured creds mishandled, no escalation path) are the findings that end engagements and careers, not the client's.

### Authorization and Legal

- [ ] **Signed authorization in hand:** statement of work plus a signed authorization letter naming the client legal entity, the test window, and explicit permission for phishing/vishing/SE. No letter, no send.
- [ ] **Get-out-of-jail letter on the operator:** carry a physical/electronic copy with an emergency client contact for any physical or in-person component.
- [ ] **Legal and HR signoff captured:** confirm in writing that legal and HR are aware. SE simulations create employee-relations and privacy exposure; the client owns that decision, not you.
- [ ] **Jurisdiction and data-residency check:** confirm which countries the targets sit in. Some regions (works-council, GDPR, two-party-consent recording) restrict employee phishing and call recording. Document the constraints.
- [ ] **Recording consent for vishing:** confirm whether calls may be recorded and under what consent model (one-party vs two-party). Default to no recording unless explicitly authorized.

### Rules of Engagement

- [ ] **Target list approved by the client:** every recipient address/number is on a client-approved list. Confirm no execs/board, no contractors, no recently-bereaved or on-leave staff are in scope unless explicitly named.
- [ ] **Pretext themes pre-approved:** the client signs off on allowed pretext categories. Forbid sensitive lures: layoffs/RIF, bonuses/payroll fraud, medical/benefits scares, charity/disaster, union activity, legal threats. Document the banned list.
- [ ] **Brand-impersonation rules set:** clarify whether you may impersonate the client's own brand, named executives, named third parties (M365, Okta, DocuSign), or only generic senders. Third-party brand use can carry trademark exposure.
- [ ] **Volume, cadence, and blast radius agreed:** max recipients per wave, sends per day, total campaign duration. Cap concurrency to avoid an availability impact on mail/help-desk.
- [ ] **Allow-list coordination decided:** decide up front whether the security stack is allow-listed (assumed-breach / control-validation) or live (full deliverability test). Record which, because it changes every result's meaning.
- [ ] **Success criteria defined:** define what "compromise" means for this test (click, credential submit, MFA-relay session token, payload execution, AiTM-authenticated mailbox access) and where you stop.

### Safe-Word, Escalation, and Contacts

- [ ] **Primary and backup client POCs documented:** name, phone, and out-of-band channel (Signal/phone, not the target mail tenant) for both sides.
- [ ] **Safe-word / abort signal agreed:** a phrase that immediately halts the campaign. Define who can call it and the max time-to-stop (e.g. all sending paused within 15 minutes).
- [ ] **Real-incident deconfliction plan:** agree how to tell a SOC "this is us" if blue team escalates, and a channel for the client to ask "is this you?" Keep a deconfliction reference ID per campaign.
- [ ] **Off-hours coverage:** confirm who is reachable if a payload or AiTM session triggers a real-looking incident at 2am.

### Data Handling for Captured Credentials

```
⚠️ Captured credentials, session cookies, and tokens are live keys to the client. Treat the capture store as the single most sensitive artifact of the engagement.
```

- [ ] **Encryption at rest mandated:** captured creds/tokens stored only in an encrypted volume/vault. No plaintext in framework logs, screenshots, or chat.
- [ ] **Never authenticate beyond scope:** captured passwords are evidence of submission, not a license to log in everywhere. Re-use of creds/tokens is bounded by the RoE (often: prove access to one target mailbox, then stop).
- [ ] **Token/cookie handling rule:** AiTM session cookies grant live MFA-satisfied access. Define exactly what you may do with them and a hard expiry/destroy date.
- [ ] **Retention and destruction agreed:** how long captures are kept post-report and the secure-wipe method. Get the client's retention preference in writing.
- [ ] **PII minimization:** redact captured passwords to a verifiable hash/partial in the report; never paste full plaintext employee passwords into deliverables.

---

## 2. OSINT and Target Profiling

Reconnaissance drives every later choice: who to target, what address format, which pretext lands, and which mail defenses you must evade. Stay passive here. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md) for collection tooling and tradecraft.

### Employee Enumeration

- [ ] **Build the employee roster:** harvest names, roles, and locations from LinkedIn, the corporate site, conference talks, GitHub commit authors, and press releases. Map who is technical, who is finance/HR, who is new (new hires are softer targets).
- [ ] **Identify high-value pretext anchors:** locate IT/help-desk staff, finance approvers, and executive assistants. These shape both who to impersonate and who to hit.
- [ ] **Cross-reference org chart:** reconstruct reporting lines so a "from your manager" pretext names a real manager. Tools: theHarvester, hunter.io, LinkedIn, Apollo/RocketReach.

### Email Format and Identity Discovery

- [ ] **Derive the email naming convention:** confirm `first.last@`, `flast@`, `firstl@`, etc. from breach data, hunter.io, or a known-good address. Validate before generating the list.
- [ ] **Validate addresses without sending:** use SMTP RCPT probing carefully, catch-all detection, or O365/Okta user-enumeration oracles to confirm live mailboxes. Note catch-all domains (they break validity signals).
- [ ] **Enumerate via M365/Okta where exposed:** check for username-enumeration via login response differences, autodiscover, GetCredentialType, or `/.well-known` endpoints. See [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md) checklist.

### Breach Credentials and Exposure

- [ ] **Check breach corpora:** query HIBP, Dehashed, and combolists for target-domain creds. Reused passwords inform both pretext realism and a credential-stuffing fallback (only if in scope).
- [ ] **Map exposed secrets:** scan public GitHub/GitLab, paste sites, and S3 buckets for tokens or internal docs that strengthen a pretext (project names, ticketing URLs, vendor names).

### Tech-Stack and Email-Security Profiling

- [ ] **Fingerprint the mail provider:** MX records reveal M365, Google Workspace, Proofpoint, Mimecast, etc. This sets your AiTM target (M365 vs Google) and the gateway you must beat.
- [ ] **Read the sender's published mail auth:** pull the target's SPF, DKIM, and DMARC. A `p=reject` DMARC kills exact-domain spoofing and pushes you to look-alike domains or compromised senders. See [Email Security](Email%20Security.md) checklist.
- [ ] **Identify the security stack:** look for link-rewriting (Proofpoint URL Defense `urldefense.com`, Mimecast, Microsoft Safe Links), SEG banners, and sandbox detonation behavior from prior test bounces.
- [ ] **Profile the SSO/IdP:** Entra ID, Okta, Ping, Duo. Determines whether AiTM, device-code, or OAuth-consent phishing is viable and what the login page looks like.

```bash
# Mail + auth posture in one pass (anchor only; see Email Security cheatsheet)
dig +short MX target.com
dig +short TXT target.com | grep -i spf
dig +short TXT _dmarc.target.com
```

---

## 3. Infrastructure Setup

The goal: infrastructure that delivers, survives reputation checks, and does not burn the campaign on first detection. Separate sending identity from harvesting identity from redirector so one takedown does not collapse everything.

### Domains

- [ ] **Register look-alike / plausible domains:** combosquats, TLD swaps, and neutral "service" names. Avoid obvious typosquats of the client brand if RoE forbids brand use.
- [ ] **Age and categorize domains:** older registration and a categorized reputation (Business, IT) beat freshly-registered. Submit to URL categorization services; stand up a benign placeholder site for crawlers.
- [ ] **Warm sending domains:** light, legitimate-looking traffic before the campaign to build sender reputation and avoid new-domain spam flags.
- [ ] **Separate domains by function:** one for sending, one for the phishing/landing host, one for redirectors. Compartmentalize blast radius.

### Sending Infrastructure

- [ ] **Stand up dedicated send infra:** dedicated VPS/SMTP relay or a reputable ESP (within ToS). Avoid shared IPs with bad reputation.
- [ ] **Publish sender auth for your domains:** configure SPF, DKIM, and DMARC for your sending domain so your mail authenticates and lands in inbox, not junk. Ironically you need good mail hygiene to phish well.
- [ ] **Enforce TLS:** valid certificates on every landing/redirector host (Let's Encrypt). Browsers flag plain HTTP login pages and users bail.
- [ ] **Set reverse DNS / PTR:** align PTR with the sending hostname; mismatches hurt deliverability.

### Redirectors and Evasion

- [ ] **Front everything with redirectors:** put a redirector (nginx/Apache/Cloudflare Worker) between the lure link and the real harvesting backend so scanners and takedowns hit the front, not the kit.
- [ ] **Filter scanners and sandboxes:** allow only intended targets; redirect everyone else to a benign page. Gate on:
  - [ ] **IP/ASN allow-list or block-list:** drop known security-vendor and cloud-scanner ranges (Proofpoint, Microsoft, Google, crawlers).
  - [ ] **User-Agent and header heuristics:** redirect bots, headless browsers, and missing-header requests to a decoy.
  - [ ] **Geofencing:** restrict to the target's expected geography.
  - [ ] **One-time / per-target tokens:** unique URL token per recipient so a link detonated in a sandbox burns only that target, and link-replay is detectable.
- [ ] **Add a human-check gate:** a CAPTCHA / Cloudflare Turnstile in front of the kit stops automated SEG crawlers from reaching the credential page (the same trick the real kits use).
- [ ] **Validate link rewriting survival:** test that your link still resolves correctly after Safe Links / URL Defense rewrites it, and that detonation does not trip your one-time token before the user clicks.

---

## 4. Pretext and Payload Development

The lure has to be believable to a busy person on a phone, and the payload (page or file) has to survive the gateway and the endpoint. Map each lure to an approved pretext theme from Phase 1.

### Lure Design

- [ ] **Build pretexts from OSINT:** reference a real vendor, real project, or real internal process surfaced in Phase 2. Specificity beats generic "your account is locked" spray.
- [ ] **Match sender to pretext:** an IT pretext comes from an IT-shaped sender; a DocuSign lure from a DocuSign-shaped sender. Consistency survives scrutiny.
- [ ] **Tune urgency without tripping filters:** pressure ("action required by EOD") drives clicks but classic phishing phrasing trips content filters. Iterate copy against your own SEG if available.
- [ ] **Localize:** language, currency, time zone, and signature block match the target region.
- [ ] **Stay inside the banned-theme list:** re-check the pretext against the Phase 1 forbidden categories before building anything.

### Landing Pages

- [ ] **Clone the real login flow:** pixel-match the target IdP page (Entra ID, Okta) or use an AiTM proxy (Phase 5) so the page is the real one. Verify favicon, branding, and URL bar plausibility.
- [ ] **Decide harvest model:** static credential-harvest page (captures username/password only) vs AiTM reverse proxy (captures the live session token too). AiTM is mandatory against any MFA-protected target. See Phase 5.
- [ ] **Prefill and validate to add realism:** carry the target's email in the link so the page greets them by address, mirroring real SSO behavior.
- [ ] **Wire post-submit redirect:** after capture, bounce the user to the real service (or a "session expired, re-login") so they self-explain the experience and do not immediately report.

### Payload Types

Choose the delivery primitive against the endpoint posture and what the RoE allows. Macro execution is heavily mitigated post-2022 (Office blocks internet macros by default), so modern access leans on container and script-paste techniques.

| Payload | Vector | Notes / current viability |
| --- | --- | --- |
| VBA macro (doc/xls) | Mark-of-the-Web bypass needed | Largely dead by default; only viable where macro policy is loose |
| LNK shortcut | Zip/ISO-delivered | Common loader; runs PowerShell/script on click |
| ISO/IMG/VHD container | Email attachment or download | Bypasses MotW on contained files; mounts and presents an LNK |
| HTML smuggling | HTML attachment / page | Reassembles payload client-side via JS Blob, slips past SEG content scan |
| OneNote (.one) | Email attachment | Embedded-script lure; popular after macro lockdown |
| ClickFix / paste lure | Web page instruction | No file at all; user pastes attacker clipboard into Run/terminal (see Recent Techniques) |
| Quishing (QR) | Image in email/PDF | Moves the URL off-host to the phone, off the corporate-managed path |

- [ ] **Pick the payload to match the goal:** credential capture (page) vs code execution (container/LNK/HTML-smuggle). Do not staple RCE onto a creds-only objective.
- [ ] **Apply MotW-aware packaging:** wrap executable payloads in ISO/IMG or password-protected zip to strip/avoid Mark-of-the-Web prompts where in scope.
- [ ] **MFA capture by design:** if the target has MFA, the credential-only page proves nothing actionable. Plan for AiTM token capture or device-code/consent flows from the start.
- [ ] **Detonate your own payload first:** test against an up-to-date Defender/EDR sandbox you control before sending. Never let the client's EDR be your first detonation.

---

## 5. Credential Harvesting and AiTM

Static credential harvesting is obsolete against MFA. The modern standard is Adversary-in-the-Middle: a reverse proxy that relays the victim to the real IdP, captures the password AND the post-MFA session cookie, giving you an authenticated session. See [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md) for the access tradecraft that follows capture.

### AiTM Reverse-Proxy Harvesting

- [ ] **Stand up the AiTM proxy:** evilginx2/Evilginx3 (or Modlishka) with a phishlet matching the target IdP (M365/Entra, Okta, Google). The proxy serves the real login, so the page is genuine and the cert is valid.
- [ ] **Capture the session token, not just the password:** confirm the phishlet captures the authenticated session cookie/`ESTSAUTH` token after the victim completes MFA. That cookie is the prize: it is MFA-satisfied.
- [ ] **Verify real-time relay:** the victim's MFA approval must pass through to the real IdP live. Test the full flow end-to-end against a controlled account before going live.
- [ ] **Test cookie replay immediately:** import the captured cookie into a clean browser and confirm it lands an authenticated session before the token's lifetime expires. This is the proof of compromise.
- [ ] **Account for token-binding defenses:** note whether the tenant enforces conditional-access device compliance, continuous access evaluation (CAE), or token protection that limits replay. Record what blocks it.

```bash
# Evilginx anchor flow (detail in Phishing and Initial Access cheatsheet)
evilginx -p ./phishlets
# config domain phish.example
# phishlets hostname o365 login.phish.example
# phishlets enable o365
# lures create o365 ; lures get-url 0
```

### Device-Code Phishing

- [ ] **Run the OAuth device-authorization-grant flow:** request a device code from the real IdP, then lure the target to enter YOUR code on the genuine `microsoft.com/devicelogin` page. They authenticate on a trusted Microsoft URL; you receive the token.
- [ ] **Capture the token, survive password reset:** the resulting access/refresh token persists even after the victim's password changes, which makes this potent. Confirm token validity and refresh behavior.
- [ ] **Pair with a QR lure:** device-code codes deliver cleanly via QR/email; tooling like SquarePhish-style frameworks automates the grant. See Recent Techniques.

### OAuth Illicit-Consent Phishing

- [ ] **Register an attacker app in a tenant:** an app requesting Graph scopes (Mail.Read, Files.Read, offline_access). The consent prompt is the real Microsoft consent page.
- [ ] **Harvest a long-lived grant:** once the victim consents, you hold a refresh token for the granted scopes with no password or MFA needed and no credential capture at all. Verify the granted scopes resolve to mailbox/file access.
- [ ] **Confirm persistence:** illicit-consent grants survive password resets; only admin revocation of the app consent kills them. Note this for the report.

### Static Harvesting (non-MFA / control test)

- [ ] **Deploy a credential-capture page only where it still proves something:** legacy apps, VPNs, or basic-auth portals without MFA. For anything MFA-protected, escalate to AiTM (above).
- [ ] **Log submissions with timestamp and source IP:** capture is your evidence; do not authenticate beyond the RoE limit.

---

## 6. Delivery and Tracking

Delivery is where careful infra pays off or fails. Throttle, track, and measure each stage of the funnel: delivered, opened, clicked, submitted, executed.

### Sending and Deliverability

- [ ] **Seed-test before the live wave:** send to your own seed mailboxes across providers (M365, Gmail) and check inbox-vs-junk placement, link-rewrite behavior, and banner injection.
- [ ] **Throttle the send:** drip messages over time rather than a single burst. A spike trips rate-based SEG detection and tips off the SOC.
- [ ] **Stagger and randomize:** vary send times, and where useful, subject/body variants to avoid identical-message clustering detection.
- [ ] **Monitor for bounces and blocks mid-flight:** a wave of bounces means your domain/IP burned; pause and rotate rather than push through.

### Tracking the Funnel

- [ ] **Instrument open, click, and submit tracking:** use GoPhish (or equivalent) campaign tracking. Distinguish a real human click from a Safe Links / SEG pre-click. Pre-clicks fire instantly from scanner IPs; treat them separately.
- [ ] **De-duplicate scanner noise:** correlate clicks against the redirector's scanner filter so automated detonations do not inflate the click rate.
- [ ] **Capture per-target state:** map each recipient to delivered/opened/clicked/submitted/executed so the report shows the funnel, not just a headline rate.
- [ ] **Time-box the window:** record first-click and time-to-first-report (how fast someone alerted the SOC). Reporting latency is a key blue-team metric.

```bash
# GoPhish runs the send + tracking; AiTM/device-code handle the capture.
# Keep the tracking instance separate from the harvesting backend.
```

---

## 7. Vishing, Smishing, and Physical-Adjacent SE

Voice and SMS bypass the entire mail security stack and hit the human directly. The current high-impact path is help-desk pretexting for MFA/password reset, the exact technique behind major 2025 intrusions. Stay strictly inside the approved pretext and recording rules from Phase 1.

### Vishing (Voice)

- [ ] **Script the call pretext:** opening, the believable reason, the ask, and fallback answers to pushback. Anchor it in OSINT (real names, real ticket system, real vendor).
- [ ] **Prepare caller-ID handling:** within RoE, set a plausible caller ID (spoofing may be restricted by law/RoE; confirm before doing it).
- [ ] **Target the help desk for resets:** the high-yield play is impersonating an employee to get IT/help-desk to reset a password or, critically, re-enroll MFA onto an attacker-controlled device. Test whether the desk's identity-verification holds.
- [ ] **Probe the verification gate:** what does the help desk require to prove identity (employee ID, manager callback, knowledge questions)? Note exactly what was sufficient. Weak verification is the finding.
- [ ] **MFA-reset to attacker device:** if the desk re-enrolls MFA to your device/number, that is full account takeover with no credential phishing at all. Capture the call recording/notes as evidence (if recording is authorized).

### MFA-Fatigue / Push-Bombing

- [ ] **Test push-bombing tolerance:** where you hold valid creds (from Phase 5 or breach data) but are MFA-blocked, repeatedly trigger push approvals to see whether the user eventually approves out of annoyance.
- [ ] **Combine with a vishing nudge:** call the target posing as IT, telling them to "approve the prompt to clear the queue." This pairing is what makes fatigue work in practice.
- [ ] **Check for number-matching defense:** note whether the tenant enforces number-matching MFA, which largely defeats blind push-bombing. Record presence/absence.

### Smishing (SMS)

- [ ] **Send SMS lures via approved sender:** short, urgent, link to the redirector. SMS strips most enterprise URL inspection.
- [ ] **Pretext around mobile-native flows:** MFA code requests, delivery notices, HR/payroll app prompts. Keep within banned-theme rules.
- [ ] **Pair SMS with QR / device-code:** a smished link into a device-code or AiTM flow keeps the whole chain off the managed laptop.

### Physical-Adjacent SE (if in scope)

- [ ] **Badge/tailgating and drop tests only if explicitly authorized:** confirm the get-out-of-jail letter covers physical, and an on-site POC knows you are there.
- [ ] **USB / QR drop:** seeded media or posted QR codes that beacon on access, measuring who plugs in / scans. Beacon only, no payload, unless RoE says otherwise.

---

## 8. Post-Compromise Handoff

Capture is the start, not the end. Convert a captured token/credential into demonstrated initial access, prove impact within the RoE, then stop and report cleanly.

- [ ] **Validate access before claiming compromise:** replay the AiTM cookie / use the device-code or consent token to reach the mailbox or portal. A submitted password without a working login is a weaker finding; say so honestly.
- [ ] **Bound the access to the RoE:** prove access to the agreed target (e.g. read the target's own mailbox), then stop. Do not pivot to other users, exfiltrate real data, or establish persistence unless the SoW authorizes it.
- [ ] **Hand off to the access phase deliberately:** if escalation to internal foothold is in scope, treat the phished session as the initial-access primitive and continue under that workstream. See [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md).
- [ ] **Capture clean evidence at the moment of access:** authenticated screenshot with timestamp, the redacted credential/token reference, and the request/response proving the session worked.
- [ ] **Report the access metrics:** sent / delivered / opened / clicked / submitted / executed / authenticated, plus time-to-first-report and help-desk verification outcomes.
- [ ] **Clean up:** revoke any attacker app consents you registered, destroy captured tokens per the data-handling plan, decommission infra, and confirm no live attacker session remains in the tenant.

```
⚠️ Captured tokens are live access. Before closing out, confirm with the client that all phished sessions are revoked and no operator-registered OAuth app retains a grant.
```

---

## Recent Techniques (2024-2026)

Current phishing tradecraft has shifted decisively to MFA-bypass via AiTM and token theft, help-desk social engineering, and file-less browser/clipboard lures. Test for these specifically.

### AiTM Phishing-as-a-Service Kits

- [ ] **Tycoon 2FA:** dominant M365/Gmail AiTM PhaaS using WebSocket relay to capture session cookies post-MFA. 2025 builds add browser fingerprinting, payload encryption, anti-debug (detects Selenium/WebDriver/Burp, blocks F12/Ctrl+Shift+C/Ctrl+U), and rotating CAPTCHAs. Test for: AiTM-resilient controls (token binding, CAE), not just "user has MFA."
- [ ] **EvilProxy:** reverse-proxy PhaaS with strong anti-analysis (detects researchers/VMs, redirects or drops suspicious connections). Test for: scanner/sandbox reach to the real login page through redirectors.
- [ ] **Mamba 2FA / Rockstar 2FA / Greatness:** additional M365 AiTM kits in active use; all relay the genuine IdP and harvest the post-MFA cookie. Test the same control set.
- [ ] **Evilginx3:** the open reverse-proxy framework underpinning red-team AiTM; phishlet-driven credential + session-cookie capture defeating 2FA. Use for authorized AiTM emulation.

### Token, Device-Code, and Consent Abuse

- [ ] **OAuth device-code phishing (RFC 8628):** lure target to enter the operator's device code on the genuine `microsoft.com/devicelogin`; operator receives a token that survives password reset. Surged from late 2025 (TA2723, UNK_AcademicFlare; SquarePhish2/Graphish tooling). Test for: conditional-access restrictions on device-code flow, and whether the flow is disabled where unneeded.
- [ ] **OAuth illicit-consent (app-consent) phishing:** attacker app requests Graph scopes; victim consent yields a long-lived refresh token with no password/MFA. Test for: admin-consent requirements, app-consent governance, risky-app detection. See [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md) checklist.

### File-less and Browser-Delivered Lures

- [ ] **ClickFix / fake-CAPTCHA clipboard paste:** fake CAPTCHA/error page uses JS to plant a command in the clipboard, instructs the user to Win+R and paste, self-executing PowerShell. Surged 517% in H1 2025; Microsoft observed it as the initial-access method in ~47% of tracked intrusions. Test for: clipboard-hijack awareness, Run-dialog/script execution telemetry, and user reaction.
- [ ] **HTML smuggling:** payload reassembled client-side from a JS Blob inside an HTML attachment/page, evading SEG content inspection because no file traverses the gateway. Test for: SEG handling of HTML attachments and browser download policy.
- [ ] **Quishing (QR phishing):** URL embedded as an image (email body, PDF attachment, signage) moves the link onto the user's phone, off the managed/inspected path. 2025 evolution: split/nested QR codes (Gabagool kit) and QR-in-PDF to defeat link-rewriting. Test for: QR handling in mail/PDF and mobile-device exposure.

### Help-Desk and Identity Social Engineering

- [ ] **Scattered Spider help-desk pretexting:** call IT/help-desk impersonating an employee (armed with prior PII) to force a password reset or MFA re-enrollment onto an attacker device. Behind major 2025 retail/insurance intrusions (CISA/FBI AA23-320A updated 2025-07-29). Test for: help-desk identity-verification strength before any reset.
- [ ] **MFA-fatigue / push-bombing:** spam push approvals (optionally with a vishing nudge) until the user approves. Test for: number-matching enforcement and approval-rate limiting.
- [ ] **SIM-swap-assisted MFA intercept:** social-engineer the carrier to port the number and capture SMS OTPs. Out of scope for most tests; note SMS-OTP as a weak factor regardless.

---

## Reporting and Evidence

### Evidence to Capture per Finding

- [ ] **Per-campaign funnel data:** sent, delivered, opened, clicked, submitted, payload-executed, authenticated. Show the funnel, not a single rate.
- [ ] **The lure as sent:** full email/SMS source including headers, the rendered message, and the live link (redacted/defanged in the report).
- [ ] **Proof of capture:** redacted credential reference, captured-token presence (never full plaintext passwords/live tokens in the deliverable), and the timestamped capture log entry.
- [ ] **Proof of access:** authenticated, timestamped screenshot plus the request/response showing the session worked (for AiTM/device-code/consent).
- [ ] **Help-desk/vishing notes:** call log, what verification was asked, what was accepted, and (if authorized) the recording reference.
- [ ] **Defense observations:** what blocked or detected you (Safe Links rewrite, SEG quarantine, number-matching, CAE token-binding) and what did not.
- [ ] **Time-to-first-report:** how quickly a human alerted the SOC, and whether the SOC acted.

### Severity Guidance

| Outcome | Indicative severity |
| --- | --- |
| Click only, no submit | Low / informational (awareness signal) |
| Credential submitted, MFA blocked access | Medium |
| AiTM session token captured and replayed to authenticated access | High |
| Help-desk reset/MFA-re-enroll to attacker device, or token surviving password reset | High to Critical |
| Authenticated access leading to in-scope sensitive data/admin | Critical |

- [ ] **Rate by realized impact, not theater:** a captured password that never yields a session is not a High. Derive severity from what access you actually proved.
- [ ] **Frame as control gaps, not employee blame:** report the missing/weak controls (no number-matching, weak help-desk verification, AiTM-replayable tokens), not "users are stupid." Awareness is one control among many.

### Common False Positives to Rule Out

- [ ] **Scanner pre-clicks counted as user clicks:** Safe Links / URL Defense detonate links automatically from vendor IPs; filter these or you over-report clicks.
- [ ] **Catch-all "delivered":** a catch-all domain marks everything delivered/valid; confirm real mailbox receipt before claiming delivery.
- [ ] **Allow-listed test mistaken for live deliverability:** if the stack was allow-listed (assumed-breach), do not report inbox placement as a gateway-bypass finding.
- [ ] **Sandbox submissions as human submissions:** automated detonation may submit decoy creds to the page; correlate with the redirector's filter before counting a submit.
- [ ] **Expired-token "access":** confirm the replayed session was actually live at test time, not a cached/expired artifact.

---

## Tools and References

| Tool / Resource | Use |
| --- | --- |
| Evilginx2 / Evilginx3 | AiTM reverse-proxy credential + session-cookie capture (see [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md)) |
| GoPhish | Campaign send, open/click/submit tracking, reporting |
| Modlishka | Reverse-proxy AiTM alternative |
| o365-attack-toolkit | M365 OAuth-consent and token-abuse phishing |
| theHarvester / hunter.io | Email-format and employee enumeration (see [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)) |
| HIBP / Dehashed | Breach-credential exposure checks |
| SquarePhish-style frameworks | Device-code phishing automation via QR |
| dnstwist | Look-alike domain generation |
| MSFT / Sekoia / Proofpoint threat-intel blogs | Current AiTM, device-code, and ClickFix tradecraft |

- Authoritative references: OWASP Web Security Testing Guide (social-engineering and authentication sections), MITRE ATT&CK T1566 (Phishing), T1621 (MFA Request Generation), T1528 (Steal Application Access Token), G1015 (Scattered Spider); CISA/FBI advisory AA23-320A; vendor IdP hardening docs (Entra ID Conditional Access, token protection, number-matching).

---

## Related

- Playbooks: [Device Code Phishing to M365 Takeover](../Playbooks/Device%20Code%20Phishing%20to%20M365%20Takeover.md), [Azure AiTM Token Theft to Global Admin](../Playbooks/Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md)
- [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md)
- [Email Security](Email%20Security.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
