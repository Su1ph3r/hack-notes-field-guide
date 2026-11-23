---
tags:
  - hack-notes
  - checklist
  - email
  - phishing
---

# Email Security Testing Checklist

> Use when assessing an organization's email security posture: spoofing resistance, sender authentication (SPF/DKIM/DMARC), mail-flow hardening, and anti-phishing controls across Microsoft 365, Google Workspace, and on-prem Exchange. Methodology-first; link out to cheatsheets for full command syntax.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Authentication Records](#2-authentication-records)
- [3. Spoofing and Bypass Testing](#3-spoofing-and-bypass-testing)
- [4. Inbound Filtering and Anti-Phishing](#4-inbound-filtering-and-anti-phishing)
- [5. Mail Server and Transport](#5-mail-server-and-transport)
- [6. M365 and Exchange Online Hardening](#6-m365-and-exchange-online-hardening)
- [7. Account and Mailbox Abuse](#7-account-and-mailbox-abuse)
- [8. Reporting Posture and User Workflow](#8-reporting-posture-and-user-workflow)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

### Scope definition
- [ ] **Enumerate in-scope domains:** confirm every apex and subdomain the org owns, including parked, marketing, and legacy brands. Spoofers target the weakest, not the primary.
- [ ] **Map mail platform per domain:** establish whether each domain runs Microsoft 365, Google Workspace, on-prem Exchange, a hybrid, or a third-party gateway. The MX record is the first tell.
- [ ] **Identify the MX edge:** record where MX points. A third-party gateway (Proofpoint, Mimecast, Cisco) in front of M365/Workspace changes where authentication is evaluated and is a recurring source of spoofable misconfig.
- [ ] **Confirm authority to send test mail:** get written authorization to send spoofed/test messages to org recipients. Some tests deliver live phishing-shaped mail; that authorization must be explicit and name the test mailboxes.
- [ ] **Agree target recipients:** use dedicated test mailboxes where possible, not random staff, to avoid triggering IR or alarming users.
- [ ] **Confirm out-of-band channel:** so a real spoof during testing can be distinguished from your test traffic and won't trigger a false IR escalation.

### Rules of engagement
- [ ] **Set a no-impact baseline:** DNS and header inspection (Phase 2) is fully passive. Spoof and relay testing (Phase 3, 5) actually injects mail; gate those behind explicit sign-off.
- [ ] **Do not test live phishing against real users** unless a social-engineering scope exists. Cross-reference the [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md) checklist for that workstream.
- [ ] **Avoid blacklisting the source IP:** sending spoof tests from a shared/corporate IP risks RBL listing. Use a disposable VPS or the agreed test infrastructure.
- [ ] **Record sending IP and reverse DNS:** so receivers can attribute and you can rule out IP-reputation noise in results.

```bash
# First-look platform fingerprint per in-scope domain
dig +short MX example.com
dig +short TXT example.com          # SPF, plus verification tokens hinting at platform
# MX -> *.mail.protection.outlook.com  = M365
# MX -> *.google.com / aspmx.l.google.com = Google Workspace
# MX -> a third party = gateway in front; test authentication at BOTH hops
```

---

## 2. Authentication Records

> Passive DNS inspection. Goal: prove whether the domain can be spoofed by anyone on the internet, and whether forensic visibility exists.

### SPF
- [ ] **Retrieve and parse the SPF record:** exactly one `v=spf1` TXT record per domain. Two SPF records = a permerror and effectively no SPF.
- [ ] **Check the all mechanism:** `-all` (hardfail) is the goal. `~all` (softfail) still allows delivery and is commonly the weak link. `?all`/`+all` provides no protection.
- [ ] **Count DNS lookups:** SPF permits a maximum of 10 DNS-resolving mechanisms (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`). Exceeding it yields permerror, which most receivers treat as no SPF.
- [ ] **Audit include chains:** flag broad/abandoned `include:` of marketing or former vendors that widen the authorized sender set. Each is a spoofing avenue.
- [ ] **Flag overly broad ranges:** large `ip4`/`ip6` CIDRs or `+all` mean shared-host neighbors can send as the domain.

```bash
checkdmarc example.com           # one-shot SPF + DKIM + DMARC + MTA-STS parse with lookup count
dig +short TXT example.com | grep spf1
```

### DKIM
- [ ] **Discover active selectors:** DKIM selectors are not listed in DNS root; enumerate known ones (`selector1`/`selector2` for M365, `google` for Workspace, `s1`/`s2`/`k1`/`default`/`mandrill`) and pull live ones from received mail headers.
- [ ] **Verify key strength:** the published `p=` public key should be 2048-bit RSA. 1024-bit is weak and 512-bit is trivially factorable. An empty `p=` means the key is revoked.
- [ ] **Check for test-mode flag:** `t=y` in the DKIM record signals testing mode, which receivers may ignore. It should not be present in production.
- [ ] **Confirm signing actually occurs:** a published selector is meaningless if outbound mail is unsigned. Inspect a real `Authentication-Results` header for `dkim=pass`.
- [ ] **Note signed-header coverage:** examine the `h=` tag. Under-signing (e.g. omitting `Subject`, `To`, `From` count, or `Content-Type`) enables DKIM replay and content-tampering (see Phase 3 and Recent Techniques).

```bash
# Pull a candidate DKIM selector key
dig +short TXT selector1._domainkey.example.com
dig +short TXT google._domainkey.example.com
```

### DMARC
- [ ] **Retrieve the DMARC record:** a single `v=DMARC1` TXT record at `_dmarc.example.com`.
- [ ] **Assess the policy:** `p=reject` is enforcement, `p=quarantine` is partial, `p=none` is monitor-only (no spoof protection, just reporting). A missing DMARC record means full spoofability.
- [ ] **Check the pct tag:** `pct=` below 100 means only a fraction of failing mail is subject to the policy. `pct=0` is effectively `p=none`.
- [ ] **Verify subdomain policy:** `sp=` governs subdomains. If absent, subdomains inherit `p`; if `sp=none` under a strict `p`, subdomains are an open spoofing lane. Test subdomain spoof explicitly.
- [ ] **Inspect alignment mode:** `aspf=` and `adkim=` default to relaxed (`r`). Strict (`s`) is harder to satisfy and harder to spoof. Relaxed alignment lets a subdomain pass for the parent.
- [ ] **Confirm reporting addresses:** `rua=` (aggregate) and `ruf=` (forensic) should point to monitored, valid mailboxes. No `rua` means the org is blind to spoofing campaigns.
- [ ] **Check cross-domain rua authorization:** if `rua`/`ruf` point to a third party's domain, that domain must publish an authorization record (`example.com._report._dmarc.<receiver>`). Missing authorization silently drops reports.

### Supplemental records
- [ ] **MTA-STS:** check for `_mta-sts.example.com` TXT and the `https://mta-sts.example.com/.well-known/mta-sts.txt` policy. `mode: enforce` prevents STARTTLS downgrade/stripping. `testing` or absent = downgradeable.
- [ ] **TLS-RPT:** check `_smtp._tls.example.com` TXT for `v=TLSRPTv1`. Absence means no visibility into TLS delivery failures or active downgrade attempts.
- [ ] **BIMI:** if `default._bimi.example.com` exists, confirm it requires `p=quarantine`/`reject` DMARC and that the VMC certificate is valid. A BIMI record on a `p=none` domain is misconfigured.
- [ ] **DNSSEC:** check whether the zone is signed (`dig +dnssec example.com`). Unsigned zones are vulnerable to DNS spoofing that undermines SPF/DKIM/DMARC lookups themselves.
- [ ] **DANE/TLSA:** for on-prem MTAs, check `_25._tcp.mail.example.com` TLSA records as an alternative/complement to MTA-STS.

| Record | Strong | Weak / spoofable |
|---|---|---|
| SPF | `-all`, <10 lookups, tight ranges | `~all`/`?all`/`+all`, permerror, broad includes |
| DKIM | 2048-bit, full `h=` coverage, no `t=y` | 1024-bit or less, under-signed, test mode, unsigned mail |
| DMARC | `p=reject`, `pct=100`, `sp` set, `rua` monitored | `p=none`, `pct<100`, no `sp`, no reporting |
| MTA-STS | `mode: enforce` | `testing` or absent |
| DNSSEC | signed zone | unsigned |

---

## 3. Spoofing and Bypass Testing

> Active. Inject crafted mail to prove whether the authentication records actually stop a spoof in delivery. Confirm authorization (Phase 1) before any send. Capture full headers of every delivered message.

### Direct domain spoofing
- [ ] **Exact-domain spoof:** send from `ceo@example.com` to a test mailbox via an unauthorized IP. Delivery to inbox (not quarantine) proves DMARC is not enforced or alignment is broken. The single highest-impact test.
- [ ] **Envelope vs header From split:** set a passing envelope (`MAIL FROM`) on an attacker domain but a spoofed header `From: example.com`. SPF passes on the envelope domain; only DMARC alignment catches the mismatch. Tests whether DMARC alignment is real.
- [ ] **Subdomain spoof:** send as `noreply@mail.example.com` or an invented subdomain. Lands if `sp=` is weak or absent. Common blind spot.

```bash
# Exact-domain spoof with swaks (header From = target, sent from unauthorized IP)
swaks --to test@example.com --from ceo@example.com \
      --header "From: CEO <ceo@example.com>" \
      --server <test-relay> --body "spoof test, ref ENGAGEMENT-ID"
# Spoofy automates SPF/DMARC spoofability classification across a domain list
```

### Display-name and look-alike
- [ ] **Display-name spoof:** send from an attacker-controlled mailbox but set `From: "Jane CEO (example.com)" <attacker@evilmail.com>`. Authentication passes legitimately; the user sees a trusted name. Tests user-facing presentation and external-tagging controls, not DNS.
- [ ] **Cousin/look-alike domain:** register or simulate `examp1e.com`, `example-corp.com`, `exarnple.com` and send. These pass their own authentication; only impersonation-protection / spoof-intelligence catches them.
- [ ] **Unicode/IDN homograph:** use look-alike Unicode (`exаmple.com` with a Cyrillic а) in the From domain. Confirm whether the gateway decodes/punycode-displays it or renders the deceptive glyph.
- [ ] **TLD swap:** `example.org`/`example.co`/`example.io` variants of a `.com` brand.

### Header manipulation
- [ ] **From/Reply-To mismatch:** spoof a trusted `From:` with an attacker `Reply-To:`. Replies silently route to the attacker. Confirm whether the platform warns or tags.
- [ ] **Multiple From headers:** inject two `From:` headers. RFC-ambiguous parsing means the auth layer and the mail client may disagree on which is authoritative.
- [ ] **Header injection via fields:** test CRLF/encoded-word injection in From/Subject to smuggle extra headers or break parsing.
- [ ] **Sender / X-Original-Sender / X-Sender confusion:** populate alternative sender headers some clients surface, to see if any UI trusts an unauthenticated field.
- [ ] **Empty/null envelope From:** `MAIL FROM:<>` (bounce form) sometimes bypasses SPF evaluation. Test whether spoofed header From still lands.

### Relay and authentication bypass
- [ ] **Open relay:** attempt to relay mail for an external sender to an external recipient through the org MTA (Phase 5). An open relay enables fully authenticated-looking third-party spoofing.
- [ ] **Internal-sender trust abuse:** if the MTA trusts mail "from inside," test whether external mail claiming an internal source is accepted without authentication.
- [ ] **Gateway-vs-backend split:** where a third-party gateway fronts M365/Workspace, send a spoof that the gateway forwards. If the backend trusts the gateway's IP and skips re-auth, a gateway bypass lands the spoof. This is the dominant 2025-2026 spoofing class (see Recent Techniques).

```
⚠️ Spoof and relay tests inject real mail into the org. Send only to authorized test
mailboxes, tag every body with the engagement ID, and notify the SOC contact in advance
so your traffic is not actioned as a live incident. Never spoof a real executive to a
real employee without explicit written sign-off.
```

---

## 4. Inbound Filtering and Anti-Phishing

> Test the receiving controls: can malicious content reach a user's inbox, and are impersonation defenses real?

### Attachment and content filtering
- [ ] **Dangerous extension policy:** send benign test files with risky extensions (`.exe`, `.scr`, `.js`, `.vbs`, `.hta`, `.iso`, `.img`, `.lnk`, `.one`). Note which are blocked, quarantined, or delivered.
- [ ] **Macro-enabled Office docs:** send `.docm`/`.xlsm`/`.xlsb` (benign macro). Confirm whether they are stripped, blocked, or marked for Protected View only.
- [ ] **Archive and nesting bypass:** test password-protected ZIP, double-zip, nested archives, and uncommon containers (`.7z`, `.rar`, `.gz`, `.cab`). Encrypted archives often evade content scanning.
- [ ] **Extension/MIME mismatch:** rename a dangerous payload with a benign extension or spoof the MIME type to test filter logic depth.
- [ ] **HTML smuggling vector:** send an HTML attachment that assembles a payload client-side. Confirm the gateway inspects rather than passes inert-looking HTML.
- [ ] **Oversized / truncated content:** very large or malformed messages that some scanners skip ("fail-open").

### Link protection
- [ ] **Link rewriting / Safe Links:** send a message with a benign-but-trackable URL. Confirm whether links are rewritten through the protection proxy (M365 Safe Links, Google enhanced pre-delivery scanning).
- [ ] **Time-of-click vs time-of-scan:** point a link at content that is benign at send and changes after delivery. Tests whether rewriting re-evaluates at click time.
- [ ] **Rewriting bypass:** test URLs that evade rewriting (already-encoded, non-standard schemes, links inside attachments or QR codes). QR-code phishing ("quishing") routinely bypasses URL scanning.
- [ ] **Redirect chains:** open-redirect through a trusted domain to a malicious endpoint, to test reputation-based link verdicts.

### Sandboxing and impersonation
- [ ] **Sandbox detonation:** send an attachment with delayed/environment-aware behavior to test whether dynamic detonation (Safe Attachments / Workspace security sandbox) runs and how long it holds mail.
- [ ] **User-impersonation protection:** spoof the display name of a configured VIP/executive (Phase 3) and confirm the impersonation policy flags it. Verify protected users are actually enrolled, not just the policy existing.
- [ ] **Domain-impersonation protection:** send from a look-alike domain and confirm detection.
- [ ] **Spoof intelligence:** review the platform's spoof-intelligence allow/block insight (M365) for stale allow entries that whitelist spoofers.
- [ ] **First-contact / unusual-sender safety tips:** confirm external/first-time-sender banners render and are not suppressed by over-broad safe-sender or connector allow-lists.
- [ ] **Allow-list audit:** enumerate connector allow-lists, IP allow-lists, and tenant allow/block lists for entries that bypass filtering entirely. A single over-broad allowed IP/domain neuters the stack.

---

## 5. Mail Server and Transport

> For on-prem Exchange and any internet-facing MTA. Enumerate the transport edge.

### SMTP edge enumeration
- [ ] **Banner and version:** grab the SMTP banner on 25/465/587. Note disclosed product/version (Exchange, Postfix, Exim, Sendmail) for CVE cross-reference.
- [ ] **EHLO capabilities:** enumerate advertised extensions (`STARTTLS`, `AUTH`, `PIPELINING`, `CHUNKING`/`BDAT`, `SIZE`, `VRFY`, `EXPN`). `CHUNKING` is relevant to SMTP smuggling.
- [ ] **VRFY / EXPN / RCPT enumeration:** test user/alias enumeration via `VRFY`, `EXPN`, or differential `RCPT TO` responses. Feeds password-spray and phishing target lists.
- [ ] **Open relay test:** attempt external-to-external relay through the MTA. The canonical mail-server misconfiguration.

```bash
swaks --server mail.example.com --quit-after RCPT \
      --from outsider@external.com --to elsewhere@external.net   # open-relay probe
nmap -p25,465,587 --script smtp-commands,smtp-open-relay,smtp-enum-users mail.example.com
```

### TLS and authentication
- [ ] **STARTTLS presence and strip resistance:** confirm STARTTLS is offered and that plaintext AUTH is refused before TLS. Test STARTTLS stripping (downgrade) where MTA-STS is not enforced.
- [ ] **TLS configuration:** check protocol versions and cipher suites (no SSLv3/TLS1.0, no weak/export ciphers, valid certificate matching the MX hostname).
- [ ] **AUTH exposure:** confirm authentication is not offered pre-TLS and that the submission service (587) requires auth. Note any `AUTH LOGIN`/`PLAIN` over cleartext.
- [ ] **Authentication abuse:** with authorization, test credential spray against SMTP AUTH / submission and any exposed autodiscover endpoint. Coordinate with the [OSINT and Reconnaissance](OSINT%20and%20Reconnaissance.md) workstream for harvested users.

### Exchange-specific
- [ ] **OWA / ECP exposure:** locate Outlook Web App and the Exchange Control Panel. Note version via `/owa/auth/logon.aspx` and headers; map to ProxyLogon/ProxyShell/ProxyNotShell families.
- [ ] **Autodiscover and EWS:** test Autodiscover for credential/config leakage and EWS for impersonation/delegation abuse.
- [ ] **MAPI/HTTP and RPC endpoints:** enumerate exposed Exchange web services for known pre-auth RCE chains; cross-reference current CVEs (Recent Techniques).
- [ ] **Patch-level mapping:** map the Exchange build number to the cumulative-update/security-update level and flag any pre-auth RCE the build is vulnerable to.

---

## 6. M365 and Exchange Online Hardening

> Tenant-side configuration review. Pairs with [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md) for identity controls.

### Anti-phishing / anti-spam policy review
- [ ] **Anti-phishing policy strength:** confirm a custom anti-phishing policy exists (not just defaults), with impersonation protection, mailbox intelligence, and spoof intelligence enabled and tuned.
- [ ] **Anti-spam inbound/outbound policies:** review thresholds, high-confidence-phish action (should be quarantine, not junk), and outbound spam limits that detect a compromised-account blast.
- [ ] **Safe Links / Safe Attachments coverage:** confirm policies cover all users, Teams, and SharePoint/OneDrive, not just a pilot group.
- [ ] **Preset security policies:** check whether Standard/Strict presets are applied, or whether weaker custom policies override them.

### Spoofing and tagging controls
- [ ] **External-sender tagging:** confirm `Set-ExternalInOutlook -Enabled $true` so external mail is visibly tagged. Often disabled.
- [ ] **DMARC honoring:** confirm the tenant honors inbound DMARC `p=reject`/`quarantine` (the anti-phish "honor DMARC policy" setting), rather than overriding to "junk".
- [ ] **Allowed-spoof review:** audit the Tenant Allow/Block List and spoof-intelligence allow entries for stale or over-broad allows.

### Transport rules and connectors
- [ ] **Transport (mail-flow) rule audit:** review rules for SCL=-1 (bypass spam filter) entries, over-broad sender/IP exceptions, or rules that strip safety banners. A single SCL=-1 rule can whitelist an attacker.
- [ ] **Inbound connector trust:** review connectors for IPs/partner domains trusted to skip authentication. Misconfigured connectors are the M365 spoof vector of 2025-2026.
- [ ] **Outbound connector review:** confirm no rogue connector exfiltrates or relays mail.

### Legacy auth and app passwords
- [ ] **Legacy / basic auth:** confirm basic auth (POP/IMAP/SMTP AUTH/EWS legacy) is blocked via authentication policies and Conditional Access. Legacy auth bypasses MFA.
- [ ] **App passwords:** confirm app passwords are disabled; they are standing MFA-bypass credentials.
- [ ] **SMTP AUTH per-mailbox:** check whether SMTP AUTH is disabled org-wide and only enabled per-mailbox where required.
- [ ] **OAuth/device-code phishing exposure:** confirm Conditional Access restricts device-code flow and risky OAuth grants (see Recent Techniques and [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md)).

---

## 7. Account and Mailbox Abuse

> Post-compromise persistence and exfiltration paths. Test with a controlled account where in scope.

### Forwarding and rules
- [ ] **External auto-forwarding:** confirm external auto-forwarding is disabled org-wide (M365 outbound anti-spam "Automatic forwarding" = Off; Workspace forwarding restriction). The classic silent-exfil channel.
- [ ] **Inbox-rule exfil:** create a test inbox rule that forwards or redirects externally and confirm whether it is blocked, alerted, or silently allowed. Attackers hide rules with blank/space names.
- [ ] **Rule-based stealth:** test rules that delete/move security alerts (e.g. auto-delete "you logged in from a new device") to mask account takeover.
- [ ] **Transport-rule vs inbox-rule layering:** confirm the org alerts on new forwarding at both tenant and mailbox level.

### Delegation and permissions
- [ ] **Mailbox permissions:** audit `FullAccess`, `SendAs`, and `SendOnBehalf` grants, especially on shared mailboxes and executive mailboxes. Over-broad SendAs enables internal spoofing that fully passes authentication.
- [ ] **Calendar/folder delegation:** review delegate access that leaks scheduling and contact intelligence.
- [ ] **Shared-mailbox sign-in:** confirm shared mailboxes have sign-in blocked; an enabled shared mailbox is an unmonitored credential.

### OAuth and app access
- [ ] **OAuth app inventory:** enumerate third-party OAuth apps granted mail scopes (`Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, full_access in Workspace). Illicit-consent grants persist through password resets and MFA.
- [ ] **Consent policy:** confirm user consent to apps is restricted and admin-consent workflow is enforced.
- [ ] **Service-account / app-registration mail access:** review app registrations with application-level mail permissions (no user context) that can read every mailbox.
- [ ] **Token/cookie theft resilience:** with AiTM phishing in scope, confirm token-protection / continuous-access-evaluation controls are present (see Recent Techniques).

---

## 8. Reporting Posture and User Workflow

- [ ] **User-reporting button:** confirm a one-click report-phish mechanism exists (M365 Report Message/Report Phishing add-in, Workspace report, or a third party) and routes to the SOC/abuse mailbox.
- [ ] **Report destination:** confirm reported mail reaches a monitored queue and feeds automated investigation (AIR in M365), not a dead `abuse@` mailbox.
- [ ] **DMARC aggregate monitoring:** confirm `rua` reports are ingested and reviewed (a DMARC analytics platform), so spoofing campaigns are visible even at `p=none`.
- [ ] **Quarantine review workflow:** confirm admins/users can review quarantine and that false-positive release does not become a blanket allow.
- [ ] **Detection of forwarding/rule changes:** confirm alerts fire on new external forwarding, suspicious inbox rules, and mass-mail behavior.
- [ ] **Incident response runbook:** confirm a documented response for reported phishing and account takeover (tenant-wide message purge, ZAP, credential reset, OAuth-grant revoke).

---

## Recent Techniques (2024-2026)

- [ ] **SMTP smuggling (CVE-2023-51764 Postfix, CVE-2023-51765 Sendmail, CVE-2023-51766 Exim):** inconsistent end-of-data parsing (`<LF>.<CR><LF>`) lets an attacker smuggle a second message that inherits the first message's passing SPF/DMARC. Test for: send a crafted message with ambiguous line endings through the MTA and confirm a smuggled spoofed message is not accepted. Mitigation is `smtpd_forbid_bare_newline=yes` (Postfix) / patched MTA.
- [ ] **M365 third-party-MX spoofing (Microsoft Jan 2026 advisory):** when MX points to a gateway and spoof protection is not strictly enforced, the backend trusts the gateway and accepts spoofed same-domain mail. Test for: spoof the tenant's own domain through the gateway path and confirm it does not inbox. Surged since May 2025.
- [ ] **DKIM replay attack:** capture a legitimately DKIM-signed message and replay it to new recipients; the signature stays valid because DKIM does not bind the envelope or sender IP. Test for: under-signed `h=` (missing key headers / partial body `l=` tag) and whether a replayed signed message re-delivers. Seen abused via signed Google/PayPal/Apple notifications.
- [ ] **Google OAuth DKIM-replay phishing (2025):** attackers had Google legitimately sign a message ("no-reply@google.com") via an OAuth/Sites path, then replayed it; DKIM passed. Test for: trust assumptions that "DKIM pass = legitimate sender."
- [ ] **Bulk-sender mandate (Google/Yahoo Feb 2024, Microsoft May 2025):** senders of >5,000/day to Gmail must have SPF + DKIM + aligned DMARC (min `p=none`), one-click List-Unsubscribe (RFC 8058), and spam rate <0.10%. By 2026 non-compliant bulk mail is rejected at SMTP. Test for: presence of `List-Unsubscribe`/`List-Unsubscribe-Post` headers and DMARC alignment on the org's outbound marketing streams.
- [ ] **AiTM / reverse-proxy phishing (Tycoon2FA, Evilginx):** transparent proxy relays the real M365/Workspace login and steals the post-MFA session cookie. Test for: token-protection, CAE, phishing-resistant MFA (FIDO2), and sign-in-frequency Conditional Access. Cross-reference [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md).
- [ ] **OAuth device-code phishing:** lure a user to authorize an attacker device-code, yielding tokens without a credential prompt and bypassing MFA. Test for: Conditional Access blocking device-code flow for untrusted contexts.
- [ ] **ARC (Authenticated Received Chain) reliance:** ARC seals authentication results across forwarders. Test for: whether the tenant trusts ARC results from non-allowlisted sealers, which can be forged to launder a failing DMARC verdict.
- [ ] **Quishing (QR-code phishing):** the malicious URL lives in a QR image, evading link rewriting and URL reputation. Test for: image/QR inspection in the gateway.
- [ ] **DMARC enforcement drift:** many orgs sit at `p=none` indefinitely after "deploying DMARC." Flag `p=none` as no enforcement, not a pass. DKIM2 is an emerging successor addressing replay; note where roadmaps reference it.

---

## Reporting and Evidence

### Evidence to capture per finding
- [ ] **Full raw headers** of every delivered spoof/test message (`Authentication-Results`, `Received`, `Received-SPF`, `ARC-*`), saved to file at test time. A spoof finding without the delivered headers is unproven.
- [ ] **The exact DNS records** quoted verbatim (SPF/DKIM/DMARC/MTA-STS) with the resolver and timestamp.
- [ ] **The sending command/transcript** (swaks invocation, SMTP conversation) and the source IP/reverse DNS used.
- [ ] **Where the message landed:** inbox vs junk vs quarantine vs rejected, plus any external/safety banner rendered, with a screenshot.
- [ ] **Config exports** for tenant findings (transport rules, connectors, anti-phish policy, forwarding settings).

### Severity guidance
| Finding | Typical severity |
|---|---|
| Exact-domain spoof inboxes (no DMARC enforcement) | High to Critical |
| Open relay | High |
| Subdomain / display-name spoof inboxes | Medium to High |
| External auto-forwarding allowed, no alerting | Medium to High |
| Legacy auth / app passwords enabled (MFA bypass) | Medium to High |
| SPF `~all`, DMARC `p=none`, missing MTA-STS | Low to Medium (combine for spoofability story) |
| Weak DKIM key / under-signing | Low to Medium |

### Common false positives to rule out
- [ ] **Junk-folder delivery counted as inbox:** delivery to Junk is partial mitigation, not a clean spoof. State the folder.
- [ ] **Your own test IP being temporarily reputation-trusted** or having been added to an allow-list during testing.
- [ ] **DMARC `p=none` with strong monitoring** mislabeled as "no protection": it is no enforcement, but the org may have visibility. State both.
- [ ] **A gateway that re-stamps authentication:** the apparent "missing SPF" may be evaluated at the gateway hop. Test at the real ingress, not just the backend.
- [ ] **SPF softfail treated as hardfail by some receivers:** result varies by receiver; report the published policy, not one receiver's verdict.

---

## Tools and References

| Tool | Use |
|---|---|
| `dig` / `nslookup` | Pull SPF/DKIM/DMARC/MTA-STS/TLS-RPT/DNSSEC records |
| `checkdmarc` | One-shot parse of all sender-auth records with SPF lookup count |
| `swaks` | Craft and send arbitrary SMTP for spoof, relay, and header tests |
| Spoofy | Classify spoofability of a domain list from SPF/DMARC posture |
| MailSniper | Exchange/OWA enumeration, password spray, mailbox search |
| mxtoolbox | Quick external SPF/DKIM/DMARC/blacklist/MX lookups |
| `nmap` smtp-* scripts | Banner, command enum, open-relay, user enum |
| Evilginx / AiTM lab | Reproduce reverse-proxy session-token theft (authorized) |

References:
- DMARC.org, RFC 7489 (DMARC), RFC 7208 (SPF), RFC 6376 (DKIM), RFC 8460 (TLS-RPT), RFC 8461 (MTA-STS), RFC 8058 (one-click List-Unsubscribe)
- Microsoft Defender for Office 365 anti-phishing and anti-spoofing documentation
- Google Workspace and Gmail bulk-sender guidelines
- Microsoft Security Blog, "Phishing actors exploit complex routing and misconfigurations to spoof domains" (Jan 2026)
- M3AAWG sender best-practices and OWASP testing guidance for mail-flow controls

---

## Related
- [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md)
- [OSINT and Reconnaissance](OSINT%20and%20Reconnaissance.md)
- [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
