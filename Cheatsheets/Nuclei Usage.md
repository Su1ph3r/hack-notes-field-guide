---
tags:
  - hack-notes
  - nuclei
---

# Nuclei Usage Cheatsheet

Operator command reference for the [Nuclei](https://github.com/projectdiscovery/nuclei) template based vulnerability scanner. This focuses on running and authoring. For the upstream README dump see Nuclei, for the templates project see Nuclei Templates, and for driving Nuclei through an MCP client see Nuclei MCP and [MCP-Assisted Pentesting](MCP-Assisted%20Pentesting.md).

## Table of Contents

- [Install and Update](#install-and-update)
- [Basic Scanning](#basic-scanning)
- [Target Input](#target-input)
- [Template Selection](#template-selection)
- [Filtering](#filtering)
- [Rate and Performance](#rate-and-performance)
- [Output Formats](#output-formats)
- [Network, Headers, and Variables](#network-headers-and-variables)
- [Interactsh OOB Configuration](#interactsh-oob-configuration)
- [Template Authoring](#template-authoring)
- [Matchers](#matchers)
- [Extractors](#extractors)
- [Variables and Helper Functions](#variables-and-helper-functions)
- [Raw Requests](#raw-requests)
- [Payloads and Fuzzing](#payloads-and-fuzzing)
- [Template Validation](#template-validation)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Install and Update

```bash
# Install with Go (requires go1.23+)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

nuclei -update            # -up : update the nuclei engine to the latest release
nuclei -update-templates  # -ut : update the community templates
nuclei -ut -ud /opt/nuclei-templates  # install/update templates to a custom dir
nuclei -duc -u https://example.com    # disable the auto update check (CI)
nuclei -tv               # show the installed templates version
nuclei -hc               # run a diagnostic health check
```

---

## Basic Scanning

```bash
nuclei -u https://example.com          # single target (-target); httpx-probes non-urls
nuclei -l hosts.txt                    # target file (-list), one host/URL per line
subfinder -d example.com -silent | httpx -silent | nuclei   # pipe from another tool
nuclei -target 192.168.1.0/24          # scan a CIDR (network templates)
nuclei -u https://example.com -t http/cves/                 # a template or directory
nuclei -u https://example.com -t /path/to/template.yaml
nuclei -u https://example.com -w workflows/wordpress-workflow.yaml  # a workflow
nuclei -u https://example.com -as      # automatic scan: tech detection mapped to tags
```

---

## Target Input

```bash
-u, -target string[]      # target URLs/hosts (comma-separated or repeated)
-l, -list string          # file of targets, one per line
-eh, -exclude-hosts       # exclude ip, cidr, or hostname from the input list
-resume resume.cfg        # resume an interrupted scan (disables clustering)
-sa, -scan-all-ips        # scan every IP behind a DNS record
-iv, -ip-version 4,6      # IP version to scan

# Non-default input formats
-im, -input-mode string   # list, burp, jsonl, yaml, openapi, swagger
nuclei -l openapi.yaml -im openapi
nuclei -l burp-export.xml -im burp
```

---

## Template Selection

```bash
-t, -templates string[]       # template or directory list (comma-separated, file)
-turl, -template-url string[] # template url or list of urls
-w, -workflows string[]       # workflow or workflow directory list
-wurl, -workflow-url          # workflow url or list of urls
-nt, -new-templates           # only templates added in the latest release
-ntv, -new-templates-version  # templates added in a specific version
-as, -automatic-scan          # tech-detection driven tag mapping
-td, -template-display        # print template content
-tl                           # list all available templates
-tgl                          # list all available tags
-file                         # enable loading file protocol templates
-code                         # enable loading code protocol templates
-esc, -enable-self-contained  # enable self-contained templates
```

```bash
nuclei -u https://example.com -t http/cves/ -tl  # preview templates without scanning
nuclei -l hosts.txt -nt                          # only freshly added templates
```

---

## Filtering

```bash
-tags string[]                # run templates by tag (cve, rce, lfi, xss, panel, ...)
-etags, -exclude-tags         # exclude templates by tag
-itags, -include-tags         # force-include tags excluded by default
-id, -template-id string[]    # run by template id (supports wildcards)
-eid, -exclude-id             # exclude by template id
-it, -include-templates       # force-include a path excluded by default
-et, -exclude-templates       # exclude a template path
-em, -exclude-matchers        # exclude specific matchers from results
-a, -author string[]          # run by template author
-s, -severity value[]         # info, low, medium, high, critical, unknown
-es, -exclude-severity        # exclude by severity
-pt, -type value[]            # protocol: dns, file, http, headless, tcp, ssl, ...
-ept, -exclude-type           # exclude by protocol type
-tc, -template-condition      # run by expression condition
```

```bash
nuclei -l hosts.txt -tags cve -severity high,critical   # high+critical CVEs only
nuclei -l hosts.txt -etags dos,intrusive,fuzz           # skip intrusive/DoS checks
nuclei -u https://example.com -t http/ -et http/technologies/  # exclude noisy dir
```

---

## Rate and Performance

```bash
-rl, -rate-limit int       # max requests per second (default 150)
-rld, -rate-limit-duration # rate-limit window (default 1s)
-c, -concurrency int       # templates run in parallel (default 25)
-bs, -bulk-size int        # hosts analyzed in parallel per template (default 25)
-timeout int               # seconds before request timeout (default 10)
-retries int               # retries on a failed request (default 1)
-mhe, -max-host-error int  # errors before a host is skipped (default 30)
-ss, -scan-strategy        # auto, host-spray, template-spray
-project                   # cache requests in a project folder to dedupe
```

```bash
nuclei -u https://example.com -rl 20 -c 10 -bs 10 -timeout 15 -retries 2  # gentle
nuclei -l internal.txt -rl 500 -c 50 -bs 50                              # fast sweep
```

---

## Output Formats

```bash
-o, -output string           # write findings to a file
-silent                      # show findings only, no banners or status
-nc, -no-color               # disable ANSI coloring
-j, -jsonl                   # JSONL output stream
-je, -json-export file       # export findings as a JSON array
-jle, -jsonl-export file     # export findings as JSONL
-se, -sarif-export file      # export SARIF (for code scanning dashboards)
-me, -markdown-export dir    # export each finding as markdown into a directory
-sresp, -store-resp          # store all request/response to disk
-srd, -store-resp-dir dir    # custom store directory
-stats                       # live statistics about the running scan
-si, -stats-interval int     # seconds between stat updates (default 5)
-sj, -stats-json             # statistics as JSONL
-rd, -redact key[]           # redact keys from query, headers, and body
```

```bash
nuclei -l hosts.txt -o findings.txt -stats                    # persisted + live stats
nuclei -l hosts.txt -jsonl -silent | jq -r '.["matched-at"]'  # pipe to another tool
MARKDOWN_EXPORT_SORT_MODE=template nuclei -u https://example.com -me report/  # sorted md
```

---

## Network, Headers, and Variables

```bash
-p, -proxy string[]            # http/socks5 proxy list (comma-separated or file)
-pi, -proxy-internal           # proxy internal requests too (interactsh, etc.)
-H, -header string[]           # add header/cookie to every http request
-V, -var key=value             # custom template variable
-r, -resolvers file            # custom DNS resolver list
-sr, -system-resolvers         # fall back to system DNS on error
-cc, -client-cert file         # client cert (PEM) for mutual TLS
-ck, -client-key file          # client key (PEM)
-ca, -client-ca file           # client CA (PEM)
-sni string                    # TLS SNI hostname
-lfa, -allow-local-file-access # allow payload file access anywhere on disk
-lna, -restrict-local-network-access # block private network connections
-i, -interface string          # network interface for network templates
-sip, -source-ip string        # source IP for network scans
```

```bash
nuclei -u https://example.com -p http://127.0.0.1:8080 -H 'Authorization: Bearer T'  # via Burp + auth
nuclei -u https://example.com -V username=admin -V password=admin   # runtime template vars
```

> Note: `-lfa` lifts the sandbox on file payload access and is required by some local file templates. Use only against authorized targets.

---

## Interactsh OOB Configuration

Out-of-band (OAST) detection catches blind vulnerabilities (blind SSRF, blind RCE, blind SQLi) via callbacks to an Interactsh server.

```bash
-iserver, -interactsh-server   # self-hosted interactsh server url
-itoken, -interactsh-token     # auth token for a self-hosted server
-interactions-cache-size int   # requests kept in the interactions cache (default 5000)
-interactions-eviction int     # seconds before evicting from cache (default 60)
-interactions-poll-duration    # seconds between interaction polls (default 5)
-interactions-cooldown-period  # extra poll time before exit (default 5)
-ni, -no-interactsh            # disable OAST and exclude OAST-based templates
```

```bash
nuclei -u https://example.com -tags ssrf   # default: public oast.* servers, no flags
nuclei -l hosts.txt -iserver https://oast.mydomain.com -itoken SECRETTOKEN  # self-hosted
nuclei -l hosts.txt -ni                     # disable OAST (air-gapped / no egress)
```

In templates the OOB host is referenced with the `{{interactsh-url}}` placeholder and confirmed with an `interactsh_protocol` DSL matcher (see Matchers below).

---

## Template Authoring

A template is a YAML file with an `id`, an `info` block, and one or more protocol request blocks. Supported protocol types: `http`, `dns`, `network` (tcp), `ssl`, `websocket`, `whois`, `file`, `headless`, `code`, `javascript`.

```yaml
id: example-detect                    # unique, lowercase, hyphenated id

info:
  name: Example Service Detection     # human readable title
  author: yourhandle                  # comma-separated authors allowed
  severity: medium                    # info, low, medium, high, critical, unknown
  description: Detects the example admin panel.
  reference: ["https://example.com/advisory"]
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cvss-score: 7.5
    cwe-id: CWE-200
  metadata: { shodan-query: 'http.title:"Example Admin"' }
  tags: panel,exposure,example        # comma-separated, used by -tags filtering

http:                                 # protocol block (one of http/dns/network/...)
  - method: GET
    path: ["{{BaseURL}}/admin/login"]
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words: ["Example Admin"]
      - type: status
        status: [200]
```

```yaml
# Other protocol blocks (replace the http: block above)
dns:                                   # DNS protocol
  - name: "{{FQDN}}"
    type: A
    matchers:
      - type: word
        words: ["IN\tA"]

network:                               # raw TCP protocol
  - inputs:
      - data: "PING\r\n"
    host: ["{{Hostname}}"]
    matchers:
      - type: word
        words: ["PONG"]

file:                                  # local filesystem matching (run with -file)
  - extensions: [all]
    matchers:
      - type: regex
        regex: ["(A3T[A-Z0-9]|AKIA)[A-Z0-9]{16}"]   # AWS access key

headless:                              # browser actions (run with -headless)
  - steps:
      - action: navigate
        args: { url: "{{BaseURL}}" }
      - action: waitload
    matchers:
      - type: word
        part: body
        words: ["dashboard"]
```

---

## Matchers

Matchers decide whether a response is a hit. `matchers-condition` joins multiple matchers with `and` or `or` (default `or`). Negate a single matcher with `negative: true`.

```yaml
matchers-condition: and
matchers:
  - type: word                 # word: substring match
    part: body                 # part: body, header, all, raw, interactsh_protocol
    words: ["admin panel", "X-Powered-By: Express"]
    condition: or              # or / and across the listed words
  - type: regex                # regex: pattern match
    part: body
    regex: ["version\\s+([0-9.]+)"]
  - type: status               # status: HTTP status code
    status: [200, 302]
  - type: binary               # binary: hex byte signatures (non-HTTP protocols)
    binary: ["504b0304"]       # ZIP magic
  - type: dsl                  # dsl: expression matcher
    dsl: ["status_code == 200 && contains(body, 'root:')", "len(body) > 1000"]
  - type: word                 # OOB confirmation via interactsh
    part: interactsh_protocol
    words: ["dns"]
```

---

## Extractors

Extractors pull data out of a matched response and print it alongside the finding.

```yaml
extractors:
  - type: regex                # regex with a capture group
    part: body
    group: 1
    regex: ["Server: ([a-zA-Z0-9.]+)"]
  - type: kval                 # kval: key/value from headers or cookies
    kval: [x_powered_by]       # hyphens in header names become underscores
  - type: json                 # json: extract via JQ-style expression
    part: body
    json: [".version"]
  - type: dsl                  # dsl: build a value with helper functions
    dsl: ["concat('build: ', build_number)"]
  - type: regex                # internal: feed value into later requests, no print
    name: csrf
    part: body
    internal: true
    group: 1
    regex: ['csrf_token" value="([0-9a-f]+)"']
```

---

## Variables and Helper Functions

```yaml
# Reusable variables block, plus helper functions
variables:
  rand: "{{rand_base(8)}}"
  ts: "{{unix_time()}}"
  basic: "{{base64('user:pass')}}"
```

Common predefined template variables:

```text
{{BaseURL}}   full URL w/ scheme+host+port   {{RootURL}}  scheme+host+port (no path)
{{Hostname}}  host:port    {{Host}}  host    {{Port}}  port    {{Path}}  request path
{{FQDN}}      FQDN (dns templates)            {{interactsh-url}}  OAST callback host
```

Frequently used DSL helper functions (list them all with `nuclei -ldf`):

```text
base64(x)  base64_decode(x)  md5(x)  sha1(x)  sha256(x)  hex_encode(x)
url_encode(x)  url_decode(x)  rand_base(n)  rand_int(min,max)  rand_text_alpha(n)
to_lower(x)  to_upper(x)  contains(s,sub)  len(x)  unix_time()  concat(a,b,...)
regex(pattern,s)  trim(x)  replace(s,old,new)        # full list: nuclei -ldf
```

---

## Raw Requests

Raw mode gives full control over the request line, headers, and body. Use it for non-standard methods, smuggling, or precise byte control.

```yaml
http:
  - raw:
      - |
        POST /api/login HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"user":"admin","pass":"{{rand_base(6)}}"}
    matchers:
      - type: word
        words: ["token"]
  # Multi-step raw requests share extracted internal values (e.g. {{csrf}})
  - raw:
      - "GET /csrf HTTP/1.1\nHost: {{Hostname}}\n"
      - "POST /submit HTTP/1.1\nHost: {{Hostname}}\n\ntoken={{csrf}}"
    cookie-reuse: true          # carry cookies between the two requests
```

---

## Payloads and Fuzzing

```yaml
http:
  - raw:
      - "POST /login HTTP/1.1\nHost: {{Hostname}}\n\nuser={{user}}&pass={{pass}}"
    payloads:
      user: [admin, root]
      pass: [admin, password]
    attack: clusterbomb          # batteringram, pitchfork, clusterbomb
    matchers:
      - type: word
        words: ["Welcome"]
```

Attack types: `batteringram` (one set across all positions in lockstep), `pitchfork` (parallel sets, 1:1 by index), `clusterbomb` (cartesian product of all sets).

DAST / fuzzing flags (active parameter mutation):

```bash
-dast                         # enable and run dast (fuzz) templates
-ft, -fuzzing-type string     # replace, prefix, postfix, infix
-fm, -fuzzing-mode string     # multiple, single
-fa, -fuzz-aggression         # low, medium, high (payload count)
-cs, -fuzz-scope regex[]      # in-scope url regex for the fuzzer
-cos, -fuzz-out-scope regex[] # out-of-scope url regex
-dfp, -display-fuzz-points    # show fuzz points for debugging
-pc, -payload-concurrency int # payload concurrency per template (default 25)

# Run the dast/fuzzing template set against discovered URLs
nuclei -l urls.txt -dast -fa medium
```

```yaml
# Fuzzing block keyed off discovered parameters
http:
  - pre-condition:
      - type: dsl
        dsl: ['method == "GET"']
    fuzzing:
      - part: query
        type: replace
        mode: single
        fuzz: ["{{url_encode('\'')}}"]
```

---

## Template Validation

```bash
-validate                  # validate the passed templates without scanning
-nss, -no-strict-syntax    # relax strict syntax checking
-tl                        # list templates that would be loaded
-vv                        # display templates loaded for the scan

nuclei -t ./custom-templates/ -validate    # validate a template or directory
NUCLEI_SIGNATURE_PRIVATE_KEY=key.pem nuclei -t code-template.yaml -sign  # sign (code protocol)
nuclei -u https://example.com -t ./custom-templates/ -tl -vv  # dry-run selection + loading
```

---

## Common Workflows

### 1. Targeted scan of a known stack

```bash
# Detect tech, run only the matching templates/CVEs at medium+ severity
nuclei -u https://target.example.com -as -severity medium,high,critical \
  -o target-findings.txt -stats
```

### 2. Author and run a custom template

```bash
$EDITOR custom-templates/example-detect.yaml                       # 1. write template
nuclei -t custom-templates/example-detect.yaml -validate           # 2. validate syntax
nuclei -u https://target -t custom-templates/example-detect.yaml -tl  # 3. dry-run select
nuclei -u https://target -t custom-templates/example-detect.yaml \
  -sresp -srd ./evidence -o hit.txt                                # 4. run + save evidence
```

### 3. CI / regression usage

```bash
# Deterministic, quiet, machine readable, no update churn mid-pipeline (-duc)
nuclei -l targets.txt -duc -t http/cves/ -severity high,critical \
  -rl 100 -c 25 -se results.sarif -jle results.jsonl -silent -nc
test ! -s results.jsonl || exit 1     # fail the build on any finding
```

### 4. Driving Nuclei through MCP

For agent-driven runs (an LLM client invoking Nuclei via a server) see Nuclei MCP and [MCP-Assisted Pentesting](MCP-Assisted%20Pentesting.md). The same selection and filtering concepts apply, expressed as MCP tool arguments rather than CLI flags.

---

## Quick Reference

```bash
nuclei -up -ut                                                   # update engine + templates
nuclei -u https://example.com                                    # quick scan
nuclei -l hosts.txt -tags cve -severity high,critical -stats -o out.txt
nuclei -u https://example.com -as                                # tech-detection scan
nuclei -u https://example.com -id CVE-2021-44228                 # one template by id
nuclei -t tpl.yaml -validate && nuclei -u https://example.com -t tpl.yaml -tl
nuclei -u https://example.com -p http://127.0.0.1:8080 -H 'Authorization: Bearer T'
nuclei -u https://example.com -rl 20 -c 10 -timeout 15 -retries 2  # gentle rate
nuclei -l hosts.txt -iserver https://oast.mydomain.com -itoken TOKEN  # self-hosted OAST
nuclei -l urls.txt -dast -fa medium                              # DAST fuzzing
nuclei -l hosts.txt -duc -jle out.jsonl -se out.sarif -silent    # CI exports
nuclei -ldf                                                      # list DSL functions
```

| Flag | Long form | Purpose |
| --- | --- | --- |
| `-u` | `-target` | Single target |
| `-l` | `-list` | Target list file |
| `-t` | `-templates` | Template or directory |
| `-w` | `-workflows` | Workflow |
| `-as` | `-automatic-scan` | Tech-detection driven scan |
| `-id` | `-template-id` | Run by id |
| `-et` | `-exclude-templates` | Exclude a path |
| `-etags` | `-exclude-tags` | Exclude by tag |
| `-s` | `-severity` | Severity filter |
| `-rl` | `-rate-limit` | Requests per second |
| `-c` | `-concurrency` | Parallel templates |
| `-bs` | `-bulk-size` | Parallel hosts per template |
| `-o` | `-output` | Output file |
| `-j` | `-jsonl` | JSONL output |
| `-se` | `-sarif-export` | SARIF export |
| `-me` | `-markdown-export` | Markdown export dir |
| `-up` | `-update` | Update engine |
| `-ut` | `-update-templates` | Update templates |
| `-lfa` | `-allow-local-file-access` | Allow local file payloads |
| `-ni` | `-no-interactsh` | Disable OAST |
| `-validate` | | Validate templates |

Related notes: Nuclei (README), Nuclei Templates (templates project), Nuclei MCP and [MCP-Assisted Pentesting](MCP-Assisted%20Pentesting.md) (agent-driven runs).

---

## Related

- Checklists: [External Network Penetration Test](../Checklists/External%20Network%20Penetration%20Test.md), [Web Application](../Checklists/Web%20Application.md)
- Nuclei
- Nuclei Templates
- Nuclei MCP
- [Web App and Payloads](Web%20App%20and%20Payloads.md)
- [API JWT and GraphQL](API%20JWT%20and%20GraphQL.md)
- [MCP-Assisted Pentesting](MCP-Assisted%20Pentesting.md)
