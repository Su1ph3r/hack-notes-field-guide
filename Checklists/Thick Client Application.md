---
tags:
  - hack-notes
  - checklist
  - thick-client
  - desktop
---

# Thick Client Application Testing Checklist

> Use for desktop and thick-client engagements: Windows-centric .NET (WinForms/WPF), C/C++ native, Java (Swing/SWT/JavaFX), and Electron apps. Covers two-tier (fat client talks straight to DB) and three-tier (client to app server to DB) architectures, local artifacts, traffic interception, and runtime manipulation. Methodology-first: links out to cheatsheets for full command detail.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Information Gathering and Architecture Mapping](#2-information-gathering-and-architecture-mapping)
- [3. Binary and Static Analysis](#3-binary-and-static-analysis)
- [4. Local Storage and Privacy](#4-local-storage-and-privacy)
- [5. Network and Traffic Interception](#5-network-and-traffic-interception)
- [6. Authentication and Authorization](#6-authentication-and-authorization)
- [7. Injection and Backend](#7-injection-and-backend)
- [8. Runtime Manipulation](#8-runtime-manipulation)
- [9. DLL Hijacking and Update Mechanism](#9-dll-hijacking-and-update-mechanism)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

### Architecture and tier model
- [ ] **Classify the tier model.** Two-tier (client embeds DB credentials and connects directly to the database) versus three-tier (client to a middle API/app server to DB). Two-tier vastly widens the attack surface: the client holds connection strings and the DB trusts any client. Confirm before estimating effort.
- [ ] **Map all backend dependencies.** Database servers, REST/SOAP/gRPC APIs, message queues, file shares, license servers, auth providers (LDAP/AD, OIDC). Each is a potential in-scope endpoint or an explicit out-of-scope boundary.
- [ ] **Confirm backend scope in writing.** A thick client that talks directly to a SQL Server makes the DB part of the realistic attack surface. Get explicit yes/no on testing the DB host, the API, and any shared infrastructure (multi-tenant SaaS backends are usually out of scope).
- [ ] **Define the trust boundary under test.** State whether the engagement assumes a malicious authenticated user, a local non-admin user, or a network-positioned attacker. This sets which findings count.

### Artifacts and environment
- [ ] **Obtain installer and binaries.** Request the MSI/EXE/MSIX installer, portable build, or app bundle plus version. Note whether symbols (PDB) or source are provided (rare but huge accelerant).
- [ ] **Stand up a dedicated test host.** Disposable Windows VM (snapshot before install). Avoid testing on a host you cannot revert: runtime patching, DLL planting, and registry edits are messy.
- [ ] **Confirm admin rights on the test host.** You need local admin to attach debuggers, install root CAs, read other users' DPAPI blobs, use Process Monitor, and plant DLLs. If the engagement forbids admin, scope drops to what a standard user can reach.
- [ ] **Get test credentials at multiple privilege levels.** At minimum a low-priv and a high-priv/admin app account, to test horizontal and vertical authorization.
- [ ] **Clarify data sensitivity and reset path.** Know whether the backend is prod, staging, or a dedicated test DB, and how to restore it after destructive tests.
- [ ] **Record baseline state.** Snapshot registry, install directory, and a clean Process Monitor capture before first launch so you can diff later.

---

## 2. Information Gathering and Architecture Mapping

### Technology and framework fingerprint
- [ ] **Identify the runtime/framework.** Check for `.NET` (managed PE, `mscoree`/`clr.dll` imports, `*.config` files), Java (`*.jar`, bundled JRE, `javaw.exe`), native C/C++ (no managed header), or Electron (`resources/app.asar`, `*.pak`, `chrome_*.dll`, `ffmpeg.dll`). Tools: Detect It Easy (DiE), `CFF Explorer`, `file`.
- [ ] **Determine .NET flavour.** Framework versus .NET Core/5+, AnyCPU versus x64/x86, presence of `app.config`/`runtimeconfig.json`. Affects decompiler and gadget choice.
- [ ] **Note packers/protectors.** ConfuserEx, .NET Reactor, Themida, VMProtect, Enigma. Drives the deobfuscation effort in Phase 3.

### Process, DLL, and service enumeration
- [ ] **Enumerate running processes and module list.** Map every child process the app spawns and every loaded module. Tools: Process Explorer, `Listdlls`, `tasklist /m`.
- [ ] **Enumerate installed services and scheduled tasks.** A privileged helper service is a common privesc and IPC target. Note the service account (SYSTEM is high value), binary path, and start type.
- [ ] **Check binary path and folder ACLs.** Use `icacls` / AccessChk on the install dir, service binaries, and any auto-updater. World-writable program directories enable binary planting (Phase 8/9).

```bash
icacls "C:\Program Files\Vendor\App"
accesschk.exe -wvu "C:\Program Files\Vendor\App"
sc.exe qc VendorService
```

### Registry and filesystem footprint
- [ ] **Run Process Monitor during launch, login, and key features.** Filter on the process; capture `RegOpenKey`, `RegQueryValue`, `CreateFile`, `WriteFile`. This reveals config locations, secrets reads, temp files, and missing-DLL probes (NAME NOT FOUND = hijack candidate).
- [ ] **Enumerate registry footprint.** `HKCU`/`HKLM\Software\<Vendor>`, run keys, stored settings. Look for credentials, tokens, license keys, server URLs, feature flags.
- [ ] **Map filesystem footprint.** Install dir, `%APPDATA%`, `%LOCALAPPDATA%`, `%PROGRAMDATA%`, `%TEMP%`. Catalog config files, databases (SQLite, LocalDB), logs, caches, and crash dumps.

### Network endpoints and client-to-backend protocols
- [ ] **Inventory all network endpoints.** `netstat -anob`, Process Explorer TCP/IP tab, and Wireshark during use. Record host:port, transport, and whether traffic is TLS.
- [ ] **Identify the client-to-backend protocol.** HTTP(S) REST/SOAP, gRPC, raw TCP custom binary, database wire protocol (TDS for SQL Server, Oracle TNS, PostgreSQL), MSMQ/AMQP, or named pipes. Non-HTTP and DB-direct protocols need different interception (Phase 5).
- [ ] **Map the data flow per feature.** For each major function, document which endpoint it hits and what it sends. This anchors injection and authorization testing later.

---

## 3. Binary and Static Analysis

> Goal: recover logic, secrets, and trust decisions from the shipped binaries. See [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md) only for exfil mechanics; reversing detail lives here.

### .NET decompilation
- [ ] **Decompile managed assemblies.** Load every `*.exe`/`*.dll` into dnSpy (also supports edit-and-continue) or ILSpy/dotPeek. Recover near-source C#/VB. Map auth flows, crypto, and DB access classes.
- [ ] **Defeat obfuscation first if present.** Run de4dot / de4dot-cex against ConfuserEx and similar before reading. Note string-encryption and control-flow flattening; partial cleanup still beats raw.
- [ ] **Search decompiled code for trust decisions.** Client-side license checks, `isAdmin`/`isLicensed` booleans, role gates, and "hidden" feature toggles. Flag any security decision made on the client (re-test in Phase 6/8).

### Java decompilation
- [ ] **Decompile JARs/classes.** Use JD-GUI, Procyon, CFR, or Fernflower (via Recaf/Bytecode Viewer). Unpack the JAR (`unzip`) and review `MANIFEST.MF` for main class and classpath.
- [ ] **Check for Java obfuscation.** ProGuard/Allatori renaming. Cross-reference strings and reflection calls to recover intent.

### Native reversing
- [ ] **Disassemble native binaries.** Ghidra, IDA, or Binary Ninja for C/C++ EXEs and DLLs. Prioritise auth routines, crypto, network parsing, and any custom protocol handler.
- [ ] **Triage memory-safety sinks.** `strcpy`/`sprintf`/`memcpy`, unbounded parsers, format-string sinks in attacker-reachable input paths. Note for fuzzing if in scope.

### Secrets, config, and strings
- [ ] **Hunt hardcoded secrets and connection strings.** Grep decompiled source and run `strings` over binaries/configs for `Password=`, `Data Source=`, `Server=`, `ApiKey`, `Bearer`, `BEGIN PRIVATE KEY`, AWS/Azure keys. A DB connection string in a two-tier client is a critical finding.

```bash
strings -n 6 App.exe | grep -Ei "password=|data source=|server=|api[_-]?key|secret|bearer "
```

- [ ] **Review app/config files.** `App.exe.config`, `appsettings.json`, `web.config` fragments, `*.properties`. Look for plaintext creds, debug flags, disabled cert validation, verbose logging.
- [ ] **Assess embedded crypto.** Hardcoded AES/DES keys and IVs, ECB mode, custom "encryption" (XOR), or keys derivable from the binary. If the client can decrypt stored secrets, so can you.
- [ ] **Check signing and integrity.** Authenticode signature present and valid (`signtool verify`)? Unsigned or self-signed binaries enable tampering and planting later.

---

## 4. Local Storage and Privacy

### Config and registry secrets
- [ ] **Review every config file for sensitive data.** Credentials, tokens, session IDs, server URLs, license data. Note storage format (plaintext, base64 = not encryption, DPAPI, custom).
- [ ] **Pull registry-stored secrets.** Decode base64/hex blobs found under the vendor keys. Re-test whether "encrypted" values are reversible with keys recovered in Phase 3.

### DPAPI and credential storage
- [ ] **Identify DPAPI usage and scope.** `CryptProtectData` with user scope (`CRYPTPROTECT_*`) versus machine scope. Machine-scope blobs are decryptable by any user/process on the host: flag it.
- [ ] **Decrypt DPAPI blobs in user context.** As the logged-in user, decrypt the app's blobs with the user masterkey (Mimikatz `dpapi::`, SharpDPAPI, or a small `CryptUnprotectData` harness) to prove credential recovery without the master password.
- [ ] **Assess optional entropy.** If the app passes secondary entropy to DPAPI, recover it from the binary (Phase 3); without it, recovery is trivial. Note Windows Credential Manager (`vaultcmd`, CredEnumerate) usage too.

### Logs, temp, and cached data
- [ ] **Grep logs for secrets and PII.** App logs, crash dumps, installer logs, and Windows Event Log for cleartext passwords, tokens, full request/response bodies, SQL, or PII.
- [ ] **Inspect temp and cache artifacts.** `%TEMP%`, cache dirs, SQLite caches, exported reports. Confirm sensitive data is wiped on logout/exit (often it is not).
- [ ] **Check local databases.** SQLite/LocalDB/Realm files often store tokens and cached records unencrypted. Open with a DB browser; verify at-rest protection.

### Memory secrets
- [ ] **Dump process memory and search it.** Capture a dump (Process Explorer "Create Dump", Task Manager, or `procdump`) and grep for passwords, keys, and tokens that linger after auth. Note whether secrets are zeroed after use (`SecureString` misuse is common).

```bash
procdump.exe -ma App.exe app.dmp
strings app.dmp | grep -Ei "password|token|bearer|secret"
```

---

## 5. Network and Traffic Interception

### HTTP(S) interception
- [ ] **Determine proxy awareness.** Does the client honour the system/WinINET proxy? If yes, point it at Burp/mitmproxy. If not (raw sockets, custom HTTP stack), force traffic with Proxifier, an `/etc/hosts`-style redirect, or transparent proxying.
- [ ] **Install your CA and test TLS interception.** Add the proxy root CA to the Windows store. If traffic now decodes, proceed to the web-layer tests. See [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md) and [API Security](API%20Security.md) for endpoint testing once you are man-in-the-middle.
- [ ] **Defeat certificate pinning if present.** If TLS still fails after CA install, the client pins. Bypass via runtime hooks (Frida script on the validation callback, .NET `ServicePointManager.ServerCertificateValidationCallback`, or Java `X509TrustManager`) rather than the network. Cross-reference Phase 8.

### Non-HTTP and binary protocols
- [ ] **Capture non-HTTP traffic.** Wireshark on raw TCP/UDP custom protocols. Identify framing, length fields, opcodes, and where auth tokens sit. Replay/fuzz with `ncat`, Scapy, or a custom client.
- [ ] **Intercept legacy/binary protocols.** Use Echo Mirage or a TCP relay/MITM for non-TLS binary protocols the proxy cannot parse. Look for plaintext creds and unauthenticated commands.
- [ ] **Test for transport downgrade and weak TLS.** No TLS, TLS made optional, accepts attacker CA without pinning, or falls back to plaintext on error.

### Named pipes and IPC
- [ ] **Enumerate named pipes.** `pipelist` / `accesschk \pipe\` / PipeViewer. For each app/service pipe, check the ACL: a pipe writable by low-priv users that a SYSTEM service reads is an IPC and privesc target (Phase 8).
- [ ] **Fuzz and impersonate pipe IPC.** Connect to the app's pipe as a low-priv user and send malformed/privileged commands. Test for missing client authentication and for impersonation primitives.

### Database-direct connections
- [ ] **Confirm and abuse direct DB access (two-tier).** Using the connection string from Phase 3, connect straight to the DB with a SQL client. Enumerate your DB-account privileges: excessive rights (db_owner, xp_cmdshell) turn a recovered string into RCE on the DB host.
- [ ] **Test trust-the-client assumptions.** If the client enforces row/column filtering before querying, bypass it by querying the DB directly for other tenants' data.

---

## 6. Authentication and Authorization

### Client-side enforcement
- [ ] **Find auth decisions made on the client.** Login success, role assignment, and license validation that happen in client code (Phase 3) are bypassable. Confirm whether the backend re-validates every request or trusts a client-set flag.
- [ ] **Re-enable hidden/disabled controls.** Grey-out admin menus, hidden tabs, and disabled buttons are UI-only gates. Re-enable via runtime patching (set `Enabled=true`/`Visible=true`), then check whether the action actually succeeds server-side.
- [ ] **Bypass client-side privilege checks.** Patch `isAdmin`/`isLicensed`/`role` checks in memory (Phase 8) or flip the value, then perform the gated action. If the server honours it, that is a broken-access-control finding, not just a UI bug.

### Direct backend access
- [ ] **Bypass the client entirely.** Replay the client's API calls (or DB queries) directly with your own tooling. Anything the client "prevents" but the server allows is exploitable. This is the core thick-client test: trust must live on the server.
- [ ] **Test horizontal authorization (IDOR).** Swap object IDs, account IDs, and tenant IDs in intercepted requests/queries to reach other users' data.
- [ ] **Test vertical authorization.** Take an admin-only request captured from the high-priv account and replay it as the low-priv user. Server should reject it.
- [ ] **Assess session and token handling.** Token lifetime, revocation on logout, replayability, and whether tokens are bound to anything. Steal the token from local storage/memory (Phase 4) and replay from another host.
- [ ] **Test the auth flow itself.** Account lockout, password reset, MFA enforcement on the backend (not just in the UI), and credential-stuffing resistance.

---

## 7. Injection and Backend

> Where the client reaches a database, OS, or parser, the usual server-side injection classes apply. Use [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md) for payload depth; this phase is the thick-client-specific entry points.

### SQL injection
- [ ] **Test SQLi via direct DB connection.** With a recovered connection string, you may have raw SQL access already (Phase 5). Where the client builds dynamic SQL from user input, test those inputs for injection through the app and by replaying the query.
- [ ] **Test SQLi through the app/API layer.** Inject into every field that reaches a query: search boxes, filters, login. Error-based, boolean, and time-based. Note stacked queries and `xp_cmdshell`/`COPY ... PROGRAM` for RCE if privileges allow.

### Command and code injection
- [ ] **Test OS command injection.** Any feature that shells out (report generation, export to external tool, "open with", ping/diagnostic utilities). Inject `& whoami`, backticks, `$(...)`. Confirm with out-of-band or marker output.
- [ ] **Test path traversal and file write.** Import/export, attachment, and "save report" features. `..\..\` to escape intended directories; arbitrary write near the install dir feeds binary planting (Phase 9).

### Deserialization
- [ ] **Test .NET deserialization.** Identify `BinaryFormatter`, `LosFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `ObjectStateFormatter`, or unsafe `Json.NET` (`TypeNameHandling != None`) on attacker-controlled data: local files, registry blobs, IPC messages, or network frames. Generate gadget payloads with ysoserial.net (`ObjectDataProvider`, `TypeConfuseDelegate`, `ActivitySurrogateSelector`).

```bash
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o raw -c "calc.exe"
```

- [ ] **Test Java deserialization.** Look for `ObjectInputStream.readObject` over attacker-reachable input (RMI, custom protocol, files). Use ysoserial (Java) with CommonsCollections/Spring gadgets; confirm classpath presence first.
- [ ] **Test other unsafe formats.** `Marshal`/`pickle`-style (Python clients), YAML, and XML-based serializers.

### XML and XXE
- [ ] **Test XXE in every XML parser.** Config import, SOAP requests, document/report parsing, license files. Inject external entities for file read (`file:///`) and SSRF; test billion-laughs for DoS where allowed.

---

## 8. Runtime Manipulation

> High-blast-radius phase. Many steps modify the running process or the host. Snapshot first. For escalation chains that follow a planted binary or weak service, hand off to [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md).

### Debugger and instrumentation
- [ ] **Attach a debugger.** dnSpy debugger for .NET (set breakpoints, edit-and-continue, inspect/change variables live), x64dbg/WinDbg for native, JDB/IntelliJ remote for Java. Observe auth flow and modify decisions at runtime.
- [ ] **Hook with Frida.** Attach to the process and hook validation functions, crypto routines, and pinning callbacks. Bypass license checks, dump plaintext before encryption, and force `return true` on auth gates. See [Mobile App Testing](../Cheatsheets/Mobile%20App%20Testing.md) for shared Frida idioms.

```bash
frida-ps -ua
frida -p <pid> -l hooks.js
```

### Memory and control-flow patching
- [ ] **Patch decisions in memory.** Flip boolean results, NOP out license/integrity checks, change branch targets so gated code runs. Confirm whether the effect is local-only (UI) or persists server-side (real authz break, Phase 6).
- [ ] **Patch on disk and re-test.** Where allowed, save the patched assembly (dnSpy "Save Module") to prove a persistent bypass and to defeat integrity self-checks.

### DLL hijacking and binary planting (privesc)
- [ ] **Exploit missing-DLL probes.** From the Phase 2 Process Monitor capture, take each `NAME NOT FOUND` DLL the app/service loads from a writable or current-directory path, drop a proxy DLL there, and confirm code execution. If the loader is a SYSTEM service, this is local privesc.
- [ ] **Test DLL side-loading.** Place a malicious DLL with the legitimate name next to a signed EXE that loads it by relative name; the signed binary side-loads your DLL into its (possibly privileged) context.
- [ ] **Plant binaries in weak-ACL paths.** World-writable install dirs (Phase 2) let a low-priv user replace the EXE, a helper, or an auto-update payload that a privileged context later executes. Cross-link [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md) for unquoted-service-path and weak-service-permission chains.

```
⚠️ Runtime patching, DLL planting, and binary replacement can corrupt the install
or crash a SYSTEM service. Only on a snapshotted test host, never on production or
shared machines. Restore the snapshot after each destructive test and document the
exact change so the client can reproduce and remediate.
```

---

## 9. DLL Hijacking and Update Mechanism

### Update integrity
- [ ] **Map the update mechanism.** How the app checks for, downloads, and applies updates: URL, transport, who runs the installer, and the account it runs as (an updater service running as SYSTEM is high value).
- [ ] **Test the update transport.** Update check or download over plain HTTP, or HTTPS without cert validation/pinning, lets a network attacker (Phase 5 MITM) serve a malicious update. Replace the served payload and confirm execution.
- [ ] **Verify update signature enforcement.** Does the client check an Authenticode or vendor signature on the downloaded update before running it? Serve an unsigned or self-signed payload; if it installs and runs, that is critical (MITM to RCE, often as SYSTEM).
- [ ] **Test the update staging directory.** Updates downloaded to a world-writable temp/staging path, then executed privileged, allow a local low-priv user to swap the payload (TOCTOU). Confirm the race and the privilege gained.
- [ ] **Check rollback/downgrade.** Can you force an older, vulnerable version? Is the version pin enforced server-side?

### Signed-binary trust
- [ ] **Re-confirm signing across the chain.** EXE, DLLs, updater, and downloaded payloads. Any unsigned link enables tampering or planting. Combine with Phase 8 planting where the loader is privileged.

---

## Recent Techniques (2024-2026)

- [ ] **Electron ELECTRON_RUN_AS_NODE abuse (CVE-2024-23738 to CVE-2024-23743).** Many apps ship with the RunAsNode fuse enabled. Relaunch the app binary with `ELECTRON_RUN_AS_NODE=1` (and `--inspect-brk`) to turn it into a generic Node process that inherits the app's TCC/sandbox permissions. Test: set the env var, point at a JS payload, confirm arbitrary Node execution. Mitigation to check: the RunAsNode and EnableNodeCliInspectArguments fuses should be disabled.
- [ ] **Electron ASAR integrity bypass (CVE-2025-55305, prior CVE-2024-46992).** Integrity fuses (`embeddedAsarIntegrityValidation`, `onlyLoadAppFromAsar`) validate app JS but did not cover V8 heap snapshots. With filesystem write access, tamper the snapshot/resources to bypass integrity and run code. Test: modify `app.asar` or the snapshot, relaunch, confirm tampered code runs.
- [ ] **Electron config hardening review.** Verify the secure baseline on every `BrowserWindow`/`webPreferences`: `nodeIntegration:false`, `contextIsolation:true`, `sandbox:true`, `webSecurity:true`, `allowRunningInsecureContent:false`. A renderer with nodeIntegration plus any HTML injection equals RCE. Inspect via the unpacked `app.asar`.
- [ ] **ysoserial.net code-exec gadgets (2024-2025).** Newer gadgets execute C# in-memory (assembly load via ObjectDataProvider) instead of `Process.Start`, evading process-spawn detection. Test thick-client deserialization sinks (local blobs, IPC, network frames) with current gadget chains; try `ActivitySurrogateSelectorFromFile` and the in-memory loaders.
- [ ] **DLL search-order hijacking in live intrusions (e.g. CVE-2024-11859).** Still a top real-world technique (PlugX, ransomware crews side-loading via signed binaries like vlc.exe). Test: from Process Monitor `NAME NOT FOUND` results, plant a proxy DLL in a writable/preceding search path and confirm execution in the app's (often privileged) context.
- [ ] **DPAPI and App-Bound Encryption (2024-2025).** Chrome 127 "App-Bound" encryption added a Credential-Manager-stored key on top of DPAPI, so offline cookie/cred decryption now needs both the DPAPI masterkey and the app-bound key. For the target app, test whether stored secrets rely on user-DPAPI alone (recoverable in user context with SharpDPAPI/Mimikatz) or add app-bound entropy.
- [ ] **DPAPI domain backup-key abuse (SpecterOps 2025).** On domain-joined hosts, the DC backup key decrypts any user's DPAPI secrets domain-wide. Where in scope, note that a recovered app secret is recoverable at scale, not just locally. See [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md).
- [ ] **Named-pipe client impersonation (SeImpersonate).** A low-priv process that can create a pipe and coerce a privileged client (a SYSTEM helper service) to connect can `ImpersonateNamedPipeClient`, duplicate the token, and spawn as SYSTEM. Test the app's IPC pipes for weak ACLs and unauthenticated privileged clients. Cross-link [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md).
- [ ] **Insecure updater MITM to SYSTEM.** Recurring 2024-2025 pattern: updater fetches over plain HTTP or skips signature checks and runs as SYSTEM. Combine Phase 5 MITM with Phase 9 to serve a payload and gain SYSTEM. Test signature enforcement on the downloaded artifact explicitly.

---

## Reporting and Evidence

### Evidence to capture per finding
- [ ] **Capture the artifact and the proof.** Decompiled snippet (with file and line/method), the recovered secret/connection string (redacted in the report body, full in an appendix), Process Monitor row for a hijack, the Frida/dnSpy change that bypassed a check, and the wire capture of a replayed privileged request.
- [ ] **Show the bypass end to end.** For client-side-control findings, prove the server honoured the bypassed request, not just that the UI changed. A re-enabled button is informational; a privileged action accepted by the backend is the finding.
- [ ] **Record environment.** App version, OS build, account privilege level, and exact reproduction steps including any patch/hook used.

### Severity guidance
| Finding | Typical severity |
| --- | --- |
| Hardcoded DB connection string in two-tier client (direct DB access) | Critical / High |
| Insecure update (no signature check, MITM) to SYSTEM RCE | Critical |
| Deserialization RCE on attacker-reachable input | Critical / High |
| Broken server-side authorization (client-only enforcement) | High |
| DLL hijack / binary planting to SYSTEM | High |
| Recoverable creds/tokens at rest (user-DPAPI only, plaintext, weak crypto) | High / Medium |
| Cert pinning absent / TLS interceptable | Medium |
| Secrets in logs / memory not zeroed / temp not wiped | Medium / Low |
| UI-only control bypass with no server impact | Low / Informational |

### Common false positives to rule out
- [ ] **"Decompilable code" is not a finding.** Managed/Java apps are always decompilable; report the secret or logic exposed, not the act of decompilation.
- [ ] **Self-signed/app CA interception is expected once you trust your own CA.** The finding is absent pinning or weak validation, demonstrated without trusting an attacker-controlled CA where pinning should exist.
- [ ] **Client-side validation bypass with server-side enforcement intact is informational.** Always confirm the backend's response before rating.
- [ ] **DPAPI in correct user context is by design.** The finding is machine-scope blobs, missing entropy, or secrets recoverable by another local user, not that DPAPI decrypts for its owner.
- [ ] **A "NAME NOT FOUND" in Process Monitor is only a hijack if the path is writable/attacker-controlled and execution is confirmed.** Prove the load, do not assume it.

---

## Tools and References

| Category | Tools |
| --- | --- |
| .NET decompile/debug | dnSpy, ILSpy, dotPeek, de4dot |
| Java decompile | JD-GUI, Procyon, CFR, Recaf, Bytecode Viewer |
| Native reversing | Ghidra, IDA, Binary Ninja, x64dbg, WinDbg |
| Fingerprint/PE | Detect It Easy, CFF Explorer, PE-bear |
| Runtime/instrumentation | Frida, dnSpy debugger, Process Hacker |
| Process/host inspection | Process Monitor, Process Explorer, Listdlls, AccessChk, autoruns |
| Pipes/IPC | PipeList, PipeViewer, AccessChk `\pipe\` |
| Traffic | Burp Suite, mitmproxy, Wireshark, Echo Mirage, Proxifier |
| Secrets at rest | SharpDPAPI, Mimikatz (`dpapi::`), procdump, DB Browser for SQLite |
| Deserialization | ysoserial.net, ysoserial (Java) |
| Memory | procdump, Process Explorer dumps, strings |

References: OWASP WSTG (client-side testing), OWASP ASVS, the OWASP Thick Client Security testing guidance, MITRE ATT&CK T1574.001 (DLL hijacking) and T1574.002 (side-loading), Electron security docs and fuses guidance, Microsoft DPAPI documentation, and vendor advisories for the CVEs listed above.

---

## Related

- Playbooks: [Insecure Deserialization to RCE](../Playbooks/Insecure%20Deserialization%20to%20RCE.md)
- [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md)
- [Web App and Payloads](../Cheatsheets/Web%20App%20and%20Payloads.md)
- [API Security](API%20Security.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [Mobile App Testing](../Cheatsheets/Mobile%20App%20Testing.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
