---
tags:
  - hack-notes
  - recon
---

# OSINT and Recon Cheatsheet

## Table of Contents

- [Passive Subdomain Enumeration](#passive-subdomain-enumeration)
- [Active Resolution and Probing](#active-resolution-and-probing)
- [Content and VHost Discovery](#content-and-vhost-discovery)
- [Screenshotting](#screenshotting)
- [URL Gathering](#url-gathering)
- [Secrets and Code OSINT](#secrets-and-code-osint)
- [People and Email OSINT](#people-and-email-osint)
- [Shodan and Censys](#shodan-and-censys)
- [DNS and Whois](#dns-and-whois)
- [Metadata](#metadata)
- [Frameworks](#frameworks)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Passive Subdomain Enumeration

Passive enumeration pulls subdomains from third-party data sources (cert transparency, passive DNS, search engines) without touching the target. Start here. Stay within scope.

### subfinder

```bash
# Enumerate subdomains for a single domain
subfinder -d example.com

# Quiet output (just hostnames), suitable for piping
subfinder -d example.com -silent

# Multiple domains from a file
subfinder -dL domains.txt -silent -o subs.txt

# Use all sources and show which source found each result
subfinder -d example.com -all -cs

# Recursive enumeration where supported
subfinder -d example.com -recursive
```

### amass (passive)

```bash
# Passive-only enumeration (no active resolution)
amass enum -passive -d example.com

# Write to an output file and a local results db directory
amass enum -passive -d example.com -o amass.txt

# Use a config with API keys for more sources
amass enum -passive -d example.com -config config.ini
```

### assetfinder

```bash
# Find domains and subdomains related to a target
assetfinder example.com

# Only return subdomains of the given domain
assetfinder --subs-only example.com
```

### Certificate Transparency (crt.sh)

```bash
# Pull subdomains from crt.sh JSON output and clean them up
curl -s 'https://crt.sh/?q=%25.example.com&output=json' \
  | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# Query a specific organization name instead of a domain
curl -s 'https://crt.sh/?q=Example+Inc&output=json' | jq -r '.[].name_value' | sort -u
```

### github-subdomains

```bash
# Mine GitHub code/commits for subdomains (needs a token)
github-subdomains -d example.com -t $GITHUB_TOKEN

# Output to a file
github-subdomains -d example.com -t $GITHUB_TOKEN -o gh-subs.txt
```

### Combine and Deduplicate

```bash
# Merge all passive sources into one unique list
cat subfinder.txt amass.txt assetfinder.txt crtsh.txt | sort -u > all-subs.txt
```

---

## Active Resolution and Probing

Active steps touch the target (DNS resolution, HTTP requests, port scans). Resolve the passive list, then probe what is live.

### dnsx (resolve and filter)

```bash
# Resolve a list of hosts and keep only the ones that resolve
dnsx -l all-subs.txt -silent

# Show A records
dnsx -l all-subs.txt -a -resp -silent

# Pull CNAME, useful for spotting dangling/takeover candidates
dnsx -l all-subs.txt -cname -resp -silent
```

### puredns (resolve and bruteforce)

```bash
# Mass-resolve a list using a trusted resolver set, filtering wildcards
puredns resolve all-subs.txt -r resolvers.txt -w resolved.txt

# Bruteforce subdomains from a wordlist
puredns bruteforce wordlist.txt example.com -r resolvers.txt
```

### httpx (probe live web)

```bash
# Probe which hosts serve HTTP/HTTPS
httpx -l resolved.txt -silent

# Add status code, title, web server, and tech detection
httpx -l resolved.txt -sc -title -server -td -silent

# Follow redirects, show content length and response time
httpx -l resolved.txt -fr -cl -rt -silent

# Probe specific ports beyond 80/443
httpx -l resolved.txt -ports 80,443,8080,8443 -silent

# Save matched URLs to a file
httpx -l resolved.txt -silent -o live.txt
```

### naabu (port discovery)

```bash
# Fast SYN scan of top ports across a host list
naabu -l resolved.txt -silent

# Scan a specific port set
naabu -l resolved.txt -p 80,443,8080,8443,3000 -silent

# Top 1000 ports, then pipe to httpx for web probing
naabu -l resolved.txt -top-ports 1000 -silent | httpx -silent
```

---

## Content and VHost Discovery

Find hidden paths, files, and name-based virtual hosts on a live target.

### ffuf

```bash
# Directory and file bruteforce (FUZZ marks the injection point)
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt

# Filter out a noisy default response by size, words, or status
ffuf -u https://example.com/FUZZ -w wordlist.txt -fc 404 -fs 1234

# Match only specific status codes
ffuf -u https://example.com/FUZZ -w wordlist.txt -mc 200,301,302,403

# Extensions
ffuf -u https://example.com/FUZZ -w wordlist.txt -e .php,.bak,.txt

# VHost discovery via the Host header
ffuf -u https://example.com -H "Host: FUZZ.example.com" -w subdomains.txt -fs 0

# Recursion
ffuf -u https://example.com/FUZZ -w wordlist.txt -recursion -recursion-depth 2
```

### gobuster

```bash
# Directory/file mode
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt

# Add extensions and follow redirects
gobuster dir -u https://example.com -w wordlist.txt -x php,html,txt -r

# DNS subdomain bruteforce mode
gobuster dns -d example.com -w subdomains.txt

# VHost mode
gobuster vhost -u https://example.com -w subdomains.txt --append-domain
```

---

## Screenshotting

Visual triage of large host lists quickly surfaces interesting apps, login panels, and default pages.

### gowitness

```bash
# Screenshot a single URL
gowitness scan single -u https://example.com

# Screenshot a list of URLs (from httpx output)
gowitness scan file -f live.txt

# Serve the results in a web UI for review
gowitness report serve
```

### EyeWitness

```bash
# Screenshot a list of web hosts and build an HTML report
eyewitness --web -f live.txt -d report-dir

# Also categorize and prompt for default-credential checks
eyewitness --web -f live.txt --prepend-https -d report-dir
```

### aquatone

```bash
# Pipe a list of hosts into aquatone for screenshots and an HTML report
cat live.txt | aquatone -out aquatone-report

# Feed nmap XML directly for screenshotting discovered web ports
cat nmap.xml | aquatone -nmap -out aquatone-report
```

---

## URL Gathering

Collect historical and crawled URLs to find parameters, endpoints, and old files.

### waybackurls

```bash
# Pull known URLs from the Wayback Machine for a domain
waybackurls example.com

# From a list of hosts
cat all-subs.txt | waybackurls | sort -u > wayback.txt
```

### gau (getallurls)

```bash
# Fetch URLs from Wayback, Common Crawl, OTX, and URLScan
gau example.com

# Include subdomains and filter to specific extensions
gau --subs example.com | grep -E '\.(js|json|php|aspx)' | sort -u
```

### katana (active crawler)

```bash
# Crawl a target for endpoints
katana -u https://example.com

# Headless crawl with JS parsing, depth limit
katana -u https://example.com -headless -jc -d 3

# Crawl a list and pull out JS files
katana -list live.txt -silent | grep '\.js$' | sort -u
```

---

## Secrets and Code OSINT

Hunt for leaked credentials, keys, and tokens in repos, history, and JS.

### trufflehog

```bash
# Scan a GitHub org for verified secrets
trufflehog github --org=example-org --only-verified

# Scan a single repo including its full git history
trufflehog git https://github.com/example/repo --only-verified

# Scan a local filesystem path
trufflehog filesystem ./src --only-verified
```

### gitleaks

```bash
# Detect secrets in a local repo (full history)
gitleaks detect --source . -v

# Scan only the working tree (no git history)
gitleaks detect --source . --no-git -v

# Output a JSON report
gitleaks detect --source . -f json -r gitleaks.json
```

### GitHub Dorks

```bash
# Search syntax to paste into GitHub code search (or the API):
# org:example-org password
# org:example-org "api_key"
# "example.com" filename:.env
# "example.com" AWS_SECRET_ACCESS_KEY
# org:example-org filename:config language:yaml
```

---

## People and Email OSINT

Build target lists of employees, email addresses, and the email format the org uses.

### theHarvester

```bash
# Gather emails, hosts, and names from multiple sources
theHarvester -d example.com -b all

# Limit to a single source and cap results
theHarvester -d example.com -b bing -l 500

# Write an HTML/XML report
theHarvester -d example.com -b all -f harvest
```

### Email Format

```bash
# Common corporate email formats to guess/validate:
# first.last@example.com
# flast@example.com
# firstl@example.com
# first@example.com
# hunter.io and similar services return the dominant pattern for a domain
```

### LinkedIn Enumeration

```bash
# Google dork for employees of a company
# site:linkedin.com/in "Example Inc"

# Tools like linkedin2username build name lists from a company page,
# then convert to the org email format above for spray/phish lists
```

---

## Shodan and Censys

Internet-wide scan data exposes hosts, services, banners, and certs without scanning the target yourself.

### Shodan CLI

```bash
# Authenticate the CLI with your API key
shodan init <API_KEY>

# Look up a single host
shodan host 1.2.3.4

# Search and show key fields
shodan search "org:\"Example Inc\"" --fields ip_str,port,hostnames

# Count results for a query without downloading
shodan count "ssl:example.com"

# Find all hosts in your domain's certs
shodan search "ssl.cert.subject.cn:example.com"
```

### Shodan Dorks

```bash
# org:"Example Inc"                 ; by organization
# ssl:"example.com"                 ; by TLS cert
# hostname:example.com              ; by hostname
# net:1.2.3.0/24                    ; by netblock
# http.title:"Login"                ; by page title
# port:3389 country:US              ; exposed RDP in a country
```

### Censys CLI

```bash
# Search hosts matching a query
censys search "services.tls.certificates.leaf_data.subject.common_name: example.com"

# View a specific host
censys view 1.2.3.4

# Censys dork examples:
# services.port: 22 and location.country: United States
# services.tls.certificates.leaf_data.names: example.com
```

---

## DNS and Whois

### whois

```bash
# Registration details for a domain
whois example.com

# Ownership of an IP (registrar/ASN)
whois 1.2.3.4
```

### dig

```bash
# Basic A record
dig example.com A +short

# All record types worth checking
dig example.com ANY
dig example.com MX +short
dig example.com TXT +short
dig example.com NS +short

# Attempt a zone transfer against each nameserver
dig AXFR example.com @ns1.example.com

# Reverse lookup
dig -x 1.2.3.4 +short
```

### dnsrecon

```bash
# Standard enumeration (records, SOA, MX, etc.)
dnsrecon -d example.com

# Bruteforce subdomains from a wordlist
dnsrecon -d example.com -D subdomains.txt -t brt

# Attempt zone transfer
dnsrecon -d example.com -t axfr
```

---

## Metadata

Document metadata leaks usernames, software versions, paths, and internal hostnames.

### exiftool

```bash
# Dump all metadata from a file
exiftool document.pdf

# Pull just author/creator fields
exiftool -Author -Creator -Producer document.pdf

# Recurse a directory of downloaded documents
exiftool -r -Author -Software ./downloads

# Strip metadata (useful when sanitizing your own deliverables)
exiftool -all= document.pdf
```

### Document Discovery (FOCA-style)

```bash
# Find indexed documents on a domain via search dorks, then exiftool them:
# site:example.com filetype:pdf
# site:example.com filetype:docx
# site:example.com filetype:xlsx
# Download the hits, then: exiftool -r -Author -Software ./downloads
# metagoofil automates the download + extraction of public documents
metagoofil -d example.com -t pdf,docx,xlsx -o ./downloads
```

---

## Frameworks

### spiderfoot

```bash
# Run the web UI (browse to http://127.0.0.1:5001)
spiderfoot -l 127.0.0.1:5001

# Headless scan from the CLI targeting a domain, all modules
spiderfoot -s example.com -o csv > spiderfoot.csv
```

### recon-ng

```bash
# Launch the interactive console
recon-ng

# Inside recon-ng:
# marketplace search          ; list available modules
# marketplace install all     ; install modules
# modules load recon/domains-hosts/hackertarget
# options set SOURCE example.com
# run
# show hosts                  ; view collected hosts
```

---

## Common Workflows

### Workflow: Domain to Subdomains to Live Hosts to Screenshots to URLs

```bash
# 1. Passive subdomain enumeration from multiple sources
subfinder -d example.com -all -silent > subfinder.txt
amass enum -passive -d example.com -o amass.txt
assetfinder --subs-only example.com > assetfinder.txt
curl -s 'https://crt.sh/?q=%25.example.com&output=json' \
  | jq -r '.[].name_value' | sed 's/\*\.//g' > crtsh.txt
cat subfinder.txt amass.txt assetfinder.txt crtsh.txt | sort -u > all-subs.txt

# 2. Resolve to live DNS, filtering wildcards
puredns resolve all-subs.txt -r resolvers.txt -w resolved.txt

# 3. Probe which hosts serve web, with tech detection
httpx -l resolved.txt -sc -title -td -silent -o live.txt

# 4. Screenshot everything for visual triage
gowitness scan file -f live.txt

# 5. Gather historical and crawled URLs, then mine for secrets
cat all-subs.txt | gau --subs | sort -u > urls.txt
katana -list live.txt -silent | grep '\.js$' | sort -u >> urls.txt

# 6. Code and secrets OSINT on the org
trufflehog github --org=example-org --only-verified
github-subdomains -d example.com -t $GITHUB_TOKEN
```

### Workflow: Internet Scan Data First (no target traffic)

```bash
# 1. Pull exposure from Shodan by org and cert
shodan search "ssl:example.com" --fields ip_str,port,hostnames

# 2. Cross-reference with Censys for cert-linked hosts
censys search "services.tls.certificates.leaf_data.names: example.com"

# 3. whois the netblocks that come back to confirm ownership
whois 1.2.3.4
```

---

## Quick Reference

```bash
# Passive subdomains
subfinder -d example.com -all -silent          # multi-source passive
amass enum -passive -d example.com             # passive only
assetfinder --subs-only example.com            # related subdomains
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value'

# Resolve and probe
dnsx -l subs.txt -silent                       # keep resolving hosts
puredns resolve subs.txt -r resolvers.txt      # mass resolve + wildcard filter
httpx -l resolved.txt -sc -title -td -silent   # live web + tech detect
naabu -l resolved.txt -top-ports 1000          # port discovery

# Content / vhost
ffuf -u https://x/FUZZ -w list.txt -mc 200,301,403   # dir/file fuzz
ffuf -u https://x -H "Host: FUZZ.x" -w subs.txt      # vhost fuzz
gobuster dns -d example.com -w subs.txt              # dns brute

# Screenshots
gowitness scan file -f live.txt                # screenshot list
eyewitness --web -f live.txt                   # screenshot + report
cat live.txt | aquatone                        # screenshot + HTML

# URLs
gau --subs example.com                         # historical URLs
waybackurls example.com                        # wayback URLs
katana -u https://example.com -jc              # active crawl

# Secrets
trufflehog github --org=org --only-verified    # org secrets
gitleaks detect --source . -v                  # repo secrets

# People / email
theHarvester -d example.com -b all             # emails + hosts

# Internet scan data
shodan search "ssl:example.com"                # shodan by cert
censys search "services.port: 443"             # censys query

# DNS / whois / metadata
dig AXFR example.com @ns1.example.com          # zone transfer attempt
dnsrecon -d example.com -t brt -D subs.txt     # dns brute
exiftool -r -Author ./downloads                # document metadata
```

---

## Related

- Checklists: [OSINT and Reconnaissance](../Checklists/OSINT%20and%20Reconnaissance.md), [External Network Penetration Test](../Checklists/External%20Network%20Penetration%20Test.md)
- [Web App and Payloads](Web%20App%20and%20Payloads.md)
- [API JWT and GraphQL](API%20JWT%20and%20GraphQL.md)
- [Phishing and Initial Access](Phishing%20and%20Initial%20Access.md)
- [Nuclei Usage](Nuclei%20Usage.md)
- [AWS Pentest](AWS%20Pentest.md)
- [Nmap Cheatsheet](Nmap.md)
