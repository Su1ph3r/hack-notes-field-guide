---
tags:
  - hack-notes
  - checklist
  - osint
  - recon
---

# OSINT and Reconnaissance Testing Checklist

> Standalone passive and active external attack-surface reconnaissance methodology. Run this first on any external network, web app, phishing, or red-team engagement. It produces the target list, attack-surface map, and people/credential intel that every downstream checklist consumes. Long commands and dork syntax live in the [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md) cheatsheet; this is the ordered methodology.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Organization and Footprint](#2-organization-and-footprint)
- [3. DNS and Subdomain Enumeration](#3-dns-and-subdomain-enumeration)
- [4. Internet Asset Discovery](#4-internet-asset-discovery)
- [5. People and Identity OSINT](#5-people-and-identity-osint)
- [6. Credential and Secret Exposure](#6-credential-and-secret-exposure)
- [7. Email Security Profiling](#7-email-security-profiling)
- [8. Subdomain Takeover and Dangling Resources](#8-subdomain-takeover-and-dangling-resources)
- [9. Handoff and Documentation](#9-handoff-and-documentation)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Reconnaissance is the phase most likely to drift out of scope. Lock the rules before you query a single source.

### Authorization and Scope

- [ ] **Confirm written authorization** covers reconnaissance specifically, not just exploitation. Some statements of work authorize active testing but say nothing about OSINT collection on named individuals.
- [ ] **Classify the engagement mode:** passive-only (no packets to target infrastructure, only third-party data) vs active (DNS resolution, port probing, screenshots, brute force). Record which sources cross into "active" so you do not unknowingly touch a no-touch asset.
- [ ] **Enumerate in-scope seed identifiers:** root domains, brand names, legal entity names, ASNs, known IP ranges, GitHub/GitLab orgs, app store publisher names. Get them in writing.
- [ ] **Enumerate explicit exclusions:** no-touch hosts (shared SaaS, third-party-managed, prod payment systems), out-of-scope subsidiaries, and any person or account the client forbids targeting.
- [ ] **Resolve the subsidiary/acquisition question up front.** Does scope include acquired companies and their legacy domains? Ranges owned by a parent? Get an explicit yes/no, because footprinting (Phase 2) will surface them.

### Legal, Privacy, and Data Handling

- [ ] **Map jurisdiction and privacy boundaries.** GDPR/CCPA and similar regimes apply to collected personal data even in an authorized test. Confirm what PII you may store and for how long.
- [ ] **Define handling for collected PII.** Names, emails, phone numbers, home addresses from OSINT must be minimized, access-controlled, and deleted on engagement close. Do not retain more than the engagement needs.
- [ ] **Define handling for discovered credentials and secrets.** Treat any breach-sourced or leaked credential as live and sensitive. Never test a credential against the target without explicit authorization. Store in an encrypted, access-controlled location; never paste into tickets, chat, or screenshots unredacted.

```
⚠️ Breach-database and combolist credentials are real secrets tied to real people.
Logging into a target account with one is account compromise, not recon, and may be
a crime even under an authorized SOW. Validate authorization to USE creds separately
from authorization to FIND them. When in doubt, report the exposure, do not log in.
```

- [ ] **Agree on tradecraft constraints.** Should queries route through attribution-managed infrastructure (VPN, non-corporate accounts)? Are authenticated platform sessions (LinkedIn, GitHub) allowed, and under what identity?
- [ ] **Set a collection ledger.** One source-of-truth file recording every asset found, where it came from, when, and confidence. This becomes the handoff artifact in Phase 9.

---

## 2. Organization and Footprint

Establish the full legal and network boundary of the target before touching DNS. The goal is a list of root domains and IP ranges that genuinely belong to the org.

### Corporate and Legal Footprint

- [ ] **Map the corporate tree:** parent company, subsidiaries, acquisitions, brand names, and DBA names. Acquisitions inherit forgotten legacy infrastructure that the security team often does not monitor. Confirm each against scope (Phase 1) before adding.
- [ ] **Mine copyright and legal footers** across known properties. A shared `Copyright YYYY <LegalEntity>` string, privacy-policy operator name, or shared analytics/tag-manager ID links sibling domains to the same owner.
- [ ] **Pull trademark and business-registry records** for the legal entity to surface additional brands and domains registered to the same org.

### Network and IP Footprint

- [ ] **Resolve owned ASNs.** Look up the org name in ASN registries; an ASN gives you the netblocks the org announces directly.

```bash
# Org name to ASN to CIDR ranges (point detail to the cheatsheet)
amass intel -org "Target Legal Name"
whois -h whois.radb.net -- '-i origin AS#####' | grep route
```

- [ ] **Enumerate IP ranges via RDAP/WHOIS** for each ASN and for the IPs behind known hostnames. Distinguish org-owned ranges from cloud/CDN ranges (the latter are shared and usually out of scope for direct probing).
- [ ] **Reverse-WHOIS on registrant org, email, and nameservers** to find sibling domains registered with the same details. Prefer RDAP over legacy WHOIS where available; expect privacy-proxy redaction on newer registrations.
- [ ] **Generate TLD and typo variants** of each root domain (alternate TLDs, ccTLDs, common misspellings, brand+keyword combos). Check which resolve and who owns them; some are defensive registrations, some are forgotten, some are squatters worth flagging.
- [ ] **Build the canonical root-domain list.** Every confirmed root domain feeds Phase 3. Mark confidence (registry-confirmed vs inferred) in the ledger.

---

## 3. DNS and Subdomain Enumeration

Expand each root domain into a full host inventory. Layer passive sources, certificate transparency, and active brute/permutation, then resolve and probe.

### Passive Subdomain Sources

- [ ] **Aggregate passive sources first** (no packets to target). Use a multi-source aggregator that fans out to dozens of APIs.

```bash
subfinder -d target.com -all -recursive -o subs_passive.txt
amass enum -passive -d target.com -o subs_amass.txt
```

- [ ] **Pull certificate transparency logs.** CT is one of the highest-signal passive sources: CN and SAN fields expose staging, VPN, admin, and internal-naming hosts that never appear in public DNS. Query `crt.sh`, Certspotter, and CT-backed aggregators.
- [ ] **Scrape search engines, Wayback/CommonCrawl, and threat-intel passive DNS** for hostnames referenced in historical content and JS.

### Active Resolution and Brute Force

- [ ] **Resolve the merged candidate set** against trusted resolvers and keep only what resolves. De-duplicate with `sort -u` before resolving.

```bash
cat subs_*.txt | sort -u | dnsx -silent -a -resp -o resolved.txt
```

- [ ] **DNS brute force** with a quality wordlist for hosts that no passive source knew about.
- [ ] **Permutation/alteration generation.** Take known hosts and generate `dev-`, `-staging`, `uat`, region, and numeric variants, then resolve. This finds the siblings of hosts you already have.
- [ ] **Probe for live HTTP(S) services** across the resolved set, capturing status, title, tech, and CDN.

```bash
cat resolved.txt | httpx -silent -title -tech-detect -status-code -o live.txt
```

### DNS Hygiene and Records

- [ ] **Test for zone transfer (AXFR)** against each authoritative nameserver. Rare today, but a hit dumps the entire zone. `dig AXFR @ns1.target.com target.com`.
- [ ] **Pull full record sets:** A/AAAA, CNAME, MX, NS, TXT, SOA, SRV, CAA. TXT records leak SaaS verification tokens (which third-party services the org uses); MX reveals the mail provider (feeds Phase 7).
- [ ] **Flag dangling CNAME/NS/MX records** that point to deprovisioned or unclaimed services. These are takeover candidates for Phase 8; record them now.
- [ ] **Enumerate virtual hosts.** A single IP often serves many hostnames. Test discovered hostnames against shared IPs, and fuzz vhosts on IPs with no obvious hostname (`Host:`-header brute) to surface unlinked apps.
- [ ] **Capture wildcard DNS behavior.** A wildcard record makes brute force return false positives; detect it (resolve a random non-existent host) and filter accordingly.

---

## 4. Internet Asset Discovery

Move from "what hostnames exist" to "what is actually exposed and what is it running." Use internet-wide scan engines and your own light probing.

### Scan-Engine Discovery

- [ ] **Query internet-wide scan engines** (Shodan, Censys, FOFA) by org name, ASN, CIDR, and known hostnames to enumerate exposed services without scanning the target yourself.
- [ ] **Pivot on favicon hash.** The favicon hash is the single most reliable cross-instance fingerprint: hash a known property's favicon, then search for every other host serving the same icon to find related infrastructure the org did not advertise.

```
# Shodan / Censys / FOFA all support favicon search
shodan: http.favicon.hash:-12345678
fofa:   icon_hash="-12345678"
```

- [ ] **Pivot on TLS certificate fields.** Search scan engines by certificate CN/SAN/issuer and JARM/JA hashes to cluster hosts sharing a certificate or TLS fingerprint, including ones behind non-obvious IPs.
- [ ] **Hunt for exposed management and infra services:** RDP, SSH, SMB, databases (Mongo/Elastic/Redis/Postgres), Kubernetes API, Docker, Jenkins, GitLab, Grafana/Kibana, VPN portals, and dev panels. Cross-reference Phase 3 internal-naming hosts.

### Surface Mapping and Fingerprinting

- [ ] **Screenshot the live web surface at scale.** Visual triage of titles, login pages, default installs, and error pages is the fastest way to prioritize. Capture into a gallery for the report.
- [ ] **Fingerprint technologies** (server, framework, CMS, WAF/CDN, JS libraries) per host. Note version strings; they feed vulnerability mapping in downstream checklists.
- [ ] **Identify origin IPs behind CDN/WAF.** Use historical DNS, SAN clustering, favicon/JARM pivots, and SSRF-free OSINT to find the unprotected origin if one is exposed.

### Cloud and Storage Assets

- [ ] **Enumerate cloud storage buckets and blobs** (S3, GCS, Azure Blob) using org and brand permutations. Test for public listing/read. Treat any open bucket as a potential data-exposure finding.
- [ ] **Discover cloud-hosted assets:** App Service/CloudFront/Cloud Run endpoints, public container registries, serverless function URLs, and exposed CI/CD artifact stores tied to the org.
- [ ] **Note SaaS tenants** revealed by DNS TXT verification tokens and login-portal fingerprints (Phase 3/7) for the people and email phases.

---

## 5. People and Identity OSINT

Build the human attack surface for phishing, password attacks, and social engineering. Scope and privacy rules from Phase 1 govern everything here.

### Employee and Identity Enumeration

- [ ] **Enumerate employees** from LinkedIn, the corporate site, conference talks, GitHub commit authors, and press releases. Capture name, role, location, and tenure.
- [ ] **Build the org chart** focused on high-value targets: executives, IT/security/helpdesk, finance/AP, HR, and admins. These drive both pretext selection and privilege targeting.
- [ ] **Map team and department structure** to support pretexts ("I am from IT", "new hire onboarding") used by the phishing checklist.

### Email Format and Account Discovery

- [ ] **Derive the email naming convention** (`first.last`, `flast`, `first`) from any confirmed address, then generate candidate addresses for the full employee list.
- [ ] **Validate candidate emails** via low-noise OSINT methods (breach-data confirmation, public mentions) rather than noisy SMTP probing, unless active validation is in scope.
- [ ] **Discover usernames across platforms.** A username reused on GitHub, dev forums, social media, and gaming/dev profiles often links back to the same employee and leaks tech stack and personal data.

### Supplemental Identity Data

- [ ] **Collect phone numbers and physical locations** (offices, badges in photos, geotagged posts) where in scope, for vishing and physical pretexts.
- [ ] **Harvest document metadata.** Public PDFs, Office docs, and images often embed authors, usernames, internal paths, software versions, and printer/host names. Extract metadata across collected documents.

---

## 6. Credential and Secret Exposure

Find already-leaked credentials and secrets tied to the org. This is frequently the highest-impact recon output and the most sensitive to handle (re-read the Phase 1 warning).

### Breach and Paste Exposure

- [ ] **Query breach databases and combolists** for in-scope domains and discovered emails. Record which accounts appear, in which breach, and whether a plaintext or hashed password is present. Do not attempt logins without separate authorization.
- [ ] **Search paste sites and paste aggregators** for the org domain, internal hostnames, and project names. Leaked configs, tickets, and credentials surface here.
- [ ] **Correlate exposure to live accounts.** A breached credential matters most when the email maps to a still-active employee (Phase 5) and the org lacks MFA. Flag those for the password-attack and phishing phases.

### Public Code and Secret Scanning

- [ ] **Map the org's public code presence:** GitHub/GitLab orgs, individual employee repos (from Phase 5 usernames), gists, and forks. Personal repos leak company secrets more often than org repos.
- [ ] **Run secret scanners across discovered repos and full git history.** Use a verification-capable scanner so you know which keys are live, plus a fast regex scanner for breadth.

```bash
# Verification-first: confirms which secrets are still live
trufflehog github --org=target-org --results=verified
# Fast regex/entropy sweep of a cloned repo's full history
gitleaks detect --source ./repo --report-format json
```

- [ ] **GitHub/GitLab dorking** for the org domain, internal hostnames, and high-signal terms across all public code (not just the org's repos): `org:target password`, `"target.com" api_key`, `filename:.env target`.
- [ ] **Hunt exposed secret files specifically:** `.env`, `.git/config`, `id_rsa`, `.npmrc`, `.aws/credentials`, CI config, Terraform state, and Kubernetes manifests indexed publicly or served from web roots.
- [ ] **Triage and verify each finding.** Confirm a secret is live and tied to in-scope infrastructure before reporting; expired keys, example values, and test fixtures are common false positives.

---

## 7. Email Security Profiling

Profile the mail posture to predict spoofability and prepare phishing. Detailed record parsing and provider-specific notes live in the [Email Security](Email%20Security.md) checklist; this captures the recon decisions.

- [ ] **Resolve MX and identify the mail provider.** MX hostnames reveal Microsoft 365, Google Workspace, Proofpoint, Mimecast, or self-hosted. Provider dictates filtering behavior and phishing approach.
- [ ] **Fingerprint M365 vs Google** from MX, autodiscover/autoconfig endpoints, and login-portal behavior. This drives pretext realism and the auth-portal target for credential phishing.
- [ ] **Parse the SPF record.** Note `-all` (hard fail), `~all` (soft fail), or `?all`/missing (open to spoofing). Count DNS lookups against the 10-lookup limit; an over-limit SPF fails open in practice.
- [ ] **Check DMARC policy.** `p=reject` blocks most spoofing; `p=quarantine` is weaker; `p=none` or missing means direct-domain spoofing is viable. Record `sp=` (subdomain policy) and `pct=` too.
- [ ] **Assess DKIM presence** by enumerating common selectors. Missing or weak DKIM widens spoofing options.
- [ ] **Identify lookalike-domain opportunities** when direct spoofing is blocked. Cross-reference the typo/TLD variants from Phase 2 for registerable phishing domains.
- [ ] **Hand spoofability verdict to the phishing phase.** Summarize as "direct-spoofable / requires lookalike / hardened" so the phishing checklist starts from the right footing.

---

## 8. Subdomain Takeover and Dangling Resources

Convert the dangling records flagged in Phase 3 into confirmed takeover findings. A CNAME pointing at a deprovisioned third-party service that you can re-register yields full control of the subdomain.

- [ ] **Re-collect all CNAME, NS, and MX records** and isolate those pointing to third-party services (cloud storage, CDNs, PaaS, SaaS, ticketing, mail) rather than org-owned infrastructure.
- [ ] **Match each dangling target against known takeover signatures.** A fingerprint (specific error page or "no such bucket/app" response from the provider) plus an unclaimed resource is the takeover condition. Maintain current signatures; the service-by-service list shifts constantly.

```bash
# Pull live signatures and check dangling hosts; detail in the cheatsheet
nuclei -t http/takeovers/ -l live.txt
# Dedicated auditors that auto-sync signatures
# (e.g. BadDNS, dnsReaper, subzy, subjack)
```

- [ ] **Distinguish a real takeover from a benign dangling record.** Many providers serve a generic error without being claimable. Confirm the resource name is actually registerable on the provider before claiming a finding.
- [ ] **Verify by claiming (only if in scope and reversible).** The cleanest proof is registering the unclaimed resource and serving a benign marker. Get explicit authorization; do not host content that could be cached or indexed.

```
⚠️ Claiming a dangling resource is an active, state-changing action on third-party
infrastructure. Confirm it is in scope and authorized, serve only a harmless proof
marker, and release/document it immediately. Never serve content that could be
cached, indexed, or mistaken for a real org page.
```

- [ ] **Check for NS and dangling-MX takeover**, not just CNAME. A delegated subdomain whose nameserver is unclaimed lets you control the whole subtree; a dangling MX can let you receive the subdomain's mail.
- [ ] **Re-check after DNS changes.** Records added or removed during a long engagement can introduce new dangling conditions; re-run before handoff.

---

## 9. Handoff and Documentation

Recon is only useful if it feeds the next phase cleanly. Produce structured artifacts, not a pile of tool output.

- [ ] **Produce the canonical target list:** every confirmed root domain, resolved subdomain, live HTTP service, and in-scope IP range, with source and confidence. This is the master input for the [External Network Penetration Test](External%20Network%20Penetration%20Test.md) checklist.
- [ ] **Produce the attack-surface map:** exposed services and ports, technologies and versions, cloud assets, open buckets, and screenshots, prioritized by likely impact.
- [ ] **Produce the people/identity package:** employee list, email format, validated addresses, high-value targets, and the email-spoofability verdict. This feeds the [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md) checklist.
- [ ] **Produce the exposure register:** leaked credentials, secrets, and breach hits with handling and disclosure status, kept in the access-controlled store from Phase 1.
- [ ] **Record negative results and coverage.** Note what you enumerated and found clean (e.g. "DMARC p=reject, no zone transfer, no public buckets") so the report shows breadth and the client gets defensive credit.
- [ ] **Confirm data-handling close-out.** Schedule deletion/minimization of PII and credentials per the Phase 1 agreement at engagement end.

---

## Recent Techniques (2024-2026)

- [ ] **ProjectDiscovery pipeline as the default workflow:** test for full coverage by chaining `subfinder -all` to `dnsx` resolution to `httpx` probing to `nuclei`, replacing single-tool runs. The `amass`-only era is over for first-pass enumeration; `amass` is now used mainly for `intel`/ASN and deep active modes.
- [ ] **Deprecated-tool migration:** test that recon does not depend on retired tooling (legacy `sublist3r`, `knockpy` forks, and `amass`'s old scraping modules). Modern aggregators with maintained source lists find more with less noise.
- [ ] **TruffleHog verification-first secret scanning:** test exposed-secret findings with live verification so reports distinguish active keys from dead ones. Pair with Gitleaks for fast breadth across full git history.
- [ ] **CVE-2025-41390 (TruffleHog local clone):** when scanning attacker-supplied or untrusted local repos, test that the scanner clones to a temp dir first; a malicious `.git/config` could otherwise execute on the operator host. Use a patched version.
- [ ] **GitGuardian secret-sprawl scale (2025):** test public-code exposure thoroughly; 12.8M+ hardcoded secrets were found in public GitHub in the 2025 report (28% YoY rise), and employee personal repos are a primary leak vector. Do not stop at the org's own repos.
- [ ] **BadDNS / dnsReaper signature-synced takeover auditing:** test dangling records with auditors that auto-pull current signatures from Nuclei and dnsReaper rather than a stale hardcoded list. New takeover services appear faster than any static list tracks.
- [ ] **Favicon-hash and JARM/TLS pivoting at scale:** test for related infrastructure by clustering on `http.favicon.hash` (Shodan/Censys) and `icon_hash=""` (FOFA), plus JARM/cert-SAN clustering, to find origin servers and shadow assets behind CDNs.
- [ ] **FOFA/Censys advanced fingerprinting:** test exposed-asset coverage with body/header/cert/title operators across multiple engines (Shodan, Censys, FOFA, ZoomEye, Hunter.how); each indexes different hosts, so a single engine undercounts.
- [ ] **Certificate Transparency as primary subdomain source:** test that CT logs (crt.sh, Certspotter) are queried directly; CN/SAN fields reliably expose staging, VPN, admin, and CI/CD hosts (Jenkins/GitLab/Grafana naming) that DNS brute force misses.
- [ ] **SPF 10-lookup fail-open and Gmail bulk enforcement (Nov 2025):** test for an over-limit SPF record (it fails open and enables spoofing) and confirm DMARC posture against tightened bulk-sender enforcement.
- [ ] **AI-generated phishing pretext quality (5x growth in 2025):** recon now feeds higher-fidelity lures; capture richer per-target context (role, tone, recent public activity) for the phishing phase, and weigh lookalike-domain registration when DMARC is `p=reject`.

---

## Reporting and Evidence

### Evidence to Capture Per Finding

- [ ] **Source and timestamp for every asset and exposure.** Recon findings are challenged ("that is not ours"); record the exact source, query, and date so each item is defensible.
- [ ] **Raw tool output and queries**, saved to file at collection time, plus the derived/normalized list. Keep the query string (dork, FOFA/Shodan filter) reproducible.
- [ ] **Screenshots** of exposed panels, open buckets (with listing visible), takeover proof markers, and scan-engine result pages.
- [ ] **Redacted credential/secret evidence.** Show enough to prove validity (provider, key prefix, verification result) without exposing the full secret in the report body.

### Severity Guidance

| Finding | Typical Severity | Notes |
| --- | --- | --- |
| Live verified secret (cloud/API key) tied to prod | High to Critical | Verification + prod scope drives the rating |
| Confirmed subdomain takeover | High | Phishing, cookie theft, brand abuse; higher if on auth/cookie-scoped subdomain |
| Open cloud bucket with sensitive data | High to Critical | Severity follows data sensitivity, not the misconfig alone |
| Breached employee creds, no MFA, active account | High | Direct path to access; lower if MFA enforced |
| Direct-spoofable domain (`p=none`/missing DMARC) | Medium | Enables phishing; impact realized downstream |
| Exposed non-sensitive service / verbose metadata | Low to Info | Attack-surface context, not a standalone breach |

### Common False Positives to Rule Out

- [ ] **Shared/third-party infrastructure** misattributed to the org (CDN, SaaS, shared hosting IPs). Confirm ownership before reporting an "exposed asset."
- [ ] **Dead or example secrets.** Expired keys, rotated creds, and `EXAMPLE`/test fixtures. Verify live before rating.
- [ ] **Benign dangling records** that return a generic provider error but are not actually claimable. Confirm registerability.
- [ ] **Wildcard-DNS brute-force noise** inflating the subdomain count. Detect the wildcard and filter.
- [ ] **Squatter/defensive-registration domains** that are not org-controlled. Distinguish "owned by target" from "looks like target."

---

## Tools and References

| Tool | Use |
| --- | --- |
| `subfinder` | Passive multi-source subdomain enumeration (first pass) |
| `amass` | `intel`/ASN org-to-CIDR mapping and deep active enumeration |
| `dnsx` | Mass DNS resolution, record pulls, wildcard handling |
| `httpx` | Live-host probing, titles, tech, status, screenshots |
| `nuclei` | Takeover templates and surface tagging (see [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md)) |
| `trufflehog` | Verification-first secret scanning (repos, history, cloud) |
| `gitleaks` | Fast regex/entropy secret sweep of git history |
| Shodan / Censys / FOFA | Internet-wide exposed-service and fingerprint discovery |
| `crt.sh` / Certspotter | Certificate Transparency subdomain discovery |
| BadDNS / dnsReaper / subzy | Signature-synced subdomain-takeover auditing |
| theHarvester | Email/host/subdomain harvesting from public sources |
| `whois` / RDAP | Registration, registrant, and IP-range footprinting |

References:
- OWASP WSTG: Information Gathering (WSTG-INFO) and Test for Subdomain Takeover.
- OWASP Subdomain Takeover Prevention Cheat Sheet.
- `can-i-take-over-xyz` community takeover signature repository.
- ProjectDiscovery documentation for the subfinder/dnsx/httpx/nuclei chain.
- GitGuardian State of Secrets Sprawl (annual) for exposure baselines.
- RFC 6962 (Certificate Transparency).

---

## Related

- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- [External Network Penetration Test](External%20Network%20Penetration%20Test.md)
- [Phishing and Social Engineering](Phishing%20and%20Social%20Engineering.md)
- [Email Security](Email%20Security.md)
- [Nuclei Usage](../Cheatsheets/Nuclei%20Usage.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
