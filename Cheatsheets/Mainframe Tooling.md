---
tags:
  - hack-notes
  - mainframe
---

# Mainframe Tooling Cheatsheet

Command reference for mainframe pentest tooling: TN3270 / z/OS and TN5250 / IBM i (AS/400). This is the tooling and syntax companion to the methodology checklists. For the full engagement checklists see 3270 Combined (z/OS) and as400_pentest_checklist (IBM i). Niche tools change their flags between versions, so where noted, defer to each tool's documented `--help`; do not assume undocumented options exist.

## Table of Contents

- [Authorization Reminder](#authorization-reminder)
- [Terminal Emulators TN3270](#terminal-emulators-tn3270)
- [Connecting and LU Selection](#connecting-and-lu-selection)
- [s3270 Scripting](#s3270-scripting)
- [Printing pr3287](#printing-pr3287)
- [Nmap NSE Mainframe Scripts](#nmap-nse-mainframe-scripts)
- [Python TN3270 Library](#python-tn3270-library)
- [Soldier of Fortran Tooling](#soldier-of-fortran-tooling)
- [Metasploit Mainframe Modules](#metasploit-mainframe-modules)
- [FTP JES JCL Submission](#ftp-jes-jcl-submission)
- [REXX](#rexx)
- [TN5250 IBM i AS400](#tn5250-ibm-i-as400)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Authorization Reminder

```text
Mainframes run critical business transactions and log every action in SMF
and security logs. Always have written authorization, a defined LPAR/region
scope, and coordination with operations before touching anything. See the
Pre-Engagement sections in [[3270 Combined]] and [[as400_pentest_checklist]].
```

---

## Terminal Emulators TN3270

The x3270 suite (x3270, c3270, s3270, pr3287, wc3270, b3270) is the open-source toolkit for 3270 access.

```bash
# Install on Debian/Kali/Ubuntu
sudo apt-get install x3270 c3270 s3270 pr3287

# Emulator variants
x3270    # GUI emulator (X11)
c3270    # curses/console emulator for the terminal
s3270    # scriptable, headless emulator (drives automation)
b3270    # back-end emulator with a structured protocol for front-ends
wc3270   # Windows console emulator
pr3287   # 3287 printer-session emulator
```

```bash
# Pick a 3270 model (screen geometry)
x3270 -model 3279-2 <host>:23      # 24x80, color
x3270 -model 3279-4 <host>:23      # 43x80
x3270 -model 3279-5 <host>:23      # 27x132

# c3270 console session
c3270 <host>:23

# Useful keys inside c3270/x3270
# PF keys: PF1..PF24      Enter: Enter      Clear: Clear/PA1..PA3
# Attention: PA1          Reset a locked keyboard: Reset
```

---

## Connecting and LU Selection

The 3270 connect string supports prefixes for TLS, LU name, and protocol options. The `L:` prefix requests TLS; a logical unit name is given as `lu@host` or with the `LU` resource.

```bash
# Plain TN3270 (cleartext, port 23 or 992 cleartext variants)
x3270 <host>:23
c3270 <host>:3270

# TLS with the L: prefix (negotiated/secure 3270, typically port 992)
x3270 L:<host>:992
c3270 L:<host>:992

# Request a specific Logical Unit (LU) name with the lu@host form
x3270 myLU@<host>:23
c3270 L:myLU@<host>:992       # TLS plus a named LU

# s3270 with explicit options for TLS verification behavior
s3270 -model 3279-2 L:<host>:992

# Manual protocol checks before bringing up an emulator
nc -nv <host> 23
openssl s_client -connect <host>:992
```

```text
Connect string anatomy (x3270 family):
  [L:][Y:][lu@]host[:port]
  L:   request TLS
  Y:   do not verify the host certificate (lab use)
  lu@  request this logical unit name
```

> The legacy SSL syntax `tn3270s://host:port` may also appear in older notes; the modern x3270 form is the `L:` prefix shown above.

---

## s3270 Scripting

s3270 reads action commands on stdin and emits status lines, which makes it the engine for credential testing and screen scraping. py3270 (below) wraps it.

```bash
# Drive s3270 from a here-doc style script piped on stdin
s3270 L:<host>:992 <<'EOF'
Connect(L:<host>:992)
Wait(InputField)
String(TSO)
Enter()
Wait(InputField)
String(IBMUSER)
Tab()
String(SYS1)
Enter()
Snap()
Ascii()
Disconnect()
Quit()
EOF
```

```text
Core s3270 actions:
  Connect(host)       open a session         Disconnect()  close it
  Wait(InputField)    block until ready      Wait(3270)    wait for 3270 mode
  String("text")      type into the field    Tab()         next field
  Enter() / PF(n)     submit / press PF key   Clear()      clear screen
  Ascii() / Ascii(r,c,len)  read screen text  Snap()       capture screen state
  PrintText(file)     dump the screen to a file
  Query(...)          query connection/state
```

---

## Printing pr3287

```bash
# Attach a 3287 printer session and write jobs to a file/command
pr3287 -model 3279-2 L:<host>:992

# Send printer output to a local file instead of a printer
pr3287 -command 'cat > spool-capture.txt' <host>:23
```

Use pr3287 to capture printed report output (often holds data not shown on the operator screen). Exact `-command`/`-printer` handling follows the pr3287 man page.

---

## Nmap NSE Mainframe Scripts

Nmap ships and community-supplies several TN3270 and z/OS scripts. Combine with `-p 23,992,1023,2323,3270` service detection.

```bash
# Screen grab and emulator info from a TN3270 service
nmap -p 23,992 --script tn3270-screen <host>
nmap -p 23,992 --script tn3270-info <host>

# TSO userid enumeration and brute force (Soldier of Fortran scripts)
nmap -p 23 --script tso-enum --script-args userdb=users.txt <host>
nmap -p 23 --script tso-brute --script-args \
  userdb=users.txt,passdb=pass.txt <host>

# VTAM application id enumeration (find selectable applids)
nmap -p 23 --script vtam-enum --script-args \
  vtam-enum.commands="logon applid(%s)",idlist=applids.txt <host>

# CICS transaction and user enumeration
nmap -p 23 --script cics-enum <host>
nmap -p 23 --script cics-info <host>
nmap -p 23 --script cics-user-enum --script-args \
  cics-user-enum.user=CICSUSER <host>
```

```text
Typical mainframe NSE scripts (verify presence with nmap --script-help <name>):
  tn3270-screen      capture the initial 3270 screen
  tn3270-info        report TN3270/TN3270E negotiation details
  tso-enum           enumerate valid TSO user IDs
  tso-brute          password-guess TSO accounts
  vtam-enum          brute the VTAM applid selection screen
  cics-enum          enumerate CICS transaction IDs
  cics-info          gather CICS region information
  cics-user-enum     enumerate CICS user IDs (CESL/CESN)
```

The tso-*, vtam-*, and cics-* scripts originate from Soldier of Fortran's nmap-mainframe-scripts repo; install them into Nmap's script directory and run `nmap --script-updatedb` so `--script` resolves them.

---

## Python TN3270 Library

py3270 wraps the s3270 binary and is the basis for the credential-testing scripts in 3270 Combined.

```bash
pip install py3270        # requires s3270 on PATH
```

```python
from py3270 import Emulator

em = Emulator(visible=False)       # headless; drives s3270
em.connect('L:host:992')           # L: prefix for TLS
em.wait_for_field()
em.send_string('TSO')
em.send_enter()
em.wait_for_field()
em.send_string('IBMUSER')
em.send_tab()
em.send_string('SYS1')
em.send_enter()
screen = em.string_get(1, 1, 80)   # row, col, length
print(screen)
em.terminate()
```

There is also a separate pure-Python `TN3270` protocol library (Soldier of Fortran) used by his tooling for direct protocol work without s3270; follow that project's README for its API.

---

## Soldier of Fortran Tooling

Soldier of Fortran (mainframed767) maintains the de-facto open-source z/OS offensive toolkit. Clone each repo and follow its documented usage; flags vary by tool.

```text
nmap-mainframe-scripts  the tso/vtam/cics NSE scripts above
CICSpwn                 enumerate and abuse CICS transactions/regions,
                        surface SPI access and command injection paths
MFSleuth               inspect and parse 3270 data streams / map fields
NJElib                 Python library for NJE (Network Job Entry) between
                        nodes; craft/inspect NJE traffic
TSO password tooling   tso-enum / tso-brute logic (also as NSE scripts)
```

```bash
# Typical pattern: clone, read the README, run with --help
git clone https://github.com/mainframed/CICSpwn
python CICSpwn.py --help          # confirm the real flags before use

git clone https://github.com/mainframed/nmap-mainframe-scripts
sudo cp *.nse /usr/share/nmap/scripts/ && sudo nmap --script-updatedb
```

> These tools change. Treat the examples as the invocation pattern, and let each repo's README/`--help` define the exact arguments.

---

## Metasploit Mainframe Modules

Metasploit carries auxiliary modules for TN3270/CICS recon and credential work.

```bash
msfconsole
# Search the mainframe-relevant modules
search tn3270
search cics
search type:auxiliary platform:mainframe

# Example flow (module names vary by framework version; use 'search' to confirm)
use auxiliary/scanner/tn3270/tn3270_emulator
set RHOSTS <host>
set RPORT 23
run

# CICS transaction enumeration auxiliary (confirm the exact path with search)
use auxiliary/scanner/tn3270/cics_enum
set RHOSTS <host>
run
```

Always resolve exact module paths with `search` in your installed Metasploit rather than assuming a path; the mainframe module set has been reorganized across releases.

---

## FTP JES JCL Submission

z/OS FTP can submit batch jobs to JES by switching the file type to JES. This turns FTP write access into job execution (a classic foothold). Authorized testing only.

```bash
ftp <host>
# After login:
quote site filetype=jes          # switch to JES submission mode
# (some systems: quote site jesjobname=* to read back all jobs)
put myjob.jcl                    # submitting the JCL runs the job via JES
quote site filetype=seq          # switch back to normal dataset transfer
```

```jcl
//PENTEST  JOB (ACCT),'TEST',CLASS=A,MSGCLASS=X
//STEP1    EXEC PGM=IEFBR14
//*  IEFBR14 is a harmless no-op program: use it to prove submission
//*  without running real work. Escalate only with explicit approval.
```

```bash
# Read job output back over FTP once filetype=jes is set
ftp> get JOB12345              # retrieve spool output by JES job id
```

---

## REXX

REXX is the z/OS scripting language (run under TSO/ISPF or batch). Useful for on-system enumeration once you have TSO access.

```rexx
/* REXX - example: list current user and a dataset, executed under TSO */
"PROFILE NOPREFIX"
ADDRESS TSO "LISTUSER" USERID()        /* show current user profile     */
ADDRESS TSO "LISTCAT LEVEL(SYS1)"      /* enumerate SYS1.* datasets      */
SAY "Running as:" USERID()
```

```bash
# Submit a REXX exec as a batch job via IKJEFT01 (TSO batch) inside JCL:
# //RUN EXEC PGM=IKJEFT01
# //SYSEXEC DD DSN=YOUR.REXX.LIB,DISP=SHR
# //SYSTSIN DD * 
#   %MYEXEC
```

Keep REXX read-only during assessment (LISTUSER/LISTCAT/LISTDSD style) unless write actions are explicitly authorized.

---

## TN5250 IBM i AS400

IBM i (AS/400, iSeries) uses the 5250 data stream over telnet (port 23) and the host-server ports (449 mapper, 8470-8476). See as400_pentest_checklist for the on-system command set (DSPSYSVAL, WRKUSRPRF, SQL via QSYS2, etc.).

```bash
# tn5250 / lib5250: open-source 5250 emulator and library
sudo apt-get install tn5250
tn5250 <host>                    # cleartext 5250 session
tn5250 ssl:<host>                # TLS session (ssl: prefix)
tn5250 env.TERM=IBM-3477-FC <host>   # set a 27x132 color terminal type
```

```text
Other 5250 emulators:
  mocha (Mocha TN5250)   commercial Windows/macOS 5250 emulator
  x5250                  X11/GTK 5250 emulator
  IBM ACS (Access Client Solutions)  official IBM Java client
```

```bash
# Nmap against IBM i: service detection across the host-server ports
nmap -sV -p 23,21,449,446,447,8470-8476,5555,5544 <host>

# AS/400-relevant NSE checks (confirm availability with --script-help)
nmap -p 23 --script telnet-encryption <host>     # is 5250 telnet encrypted
nmap -p 21 --script ftp-anon,ftp-syst <host>     # anon FTP + system type
nmap -p 449 -sV <host>                            # DDM/DRDA server mapper

# DRDA/DDM probing (DB2 for i) - confirm script presence in your Nmap
nmap -p 446,447,448 --script drda-info <host>
```

Anonymous or weakly-authenticated FTP on IBM i is high value because `QUOTE RCMD <CL command>` runs CL commands on the host (see as400_pentest_checklist).

---

## Common Workflows

### 1. TN3270 recon to access

```bash
# 1. Find the service and grab the screen
nmap -sV -p 23,992,1023,2323 --script tn3270-info,tn3270-screen <host>

# 2. Connect interactively to read the VTAM/USS screen
c3270 L:<host>:992

# 3. Enumerate selectable applications (VTAM applids)
nmap -p 23 --script vtam-enum --script-args idlist=applids.txt <host>

# 4. Enumerate then guess TSO users (scripted with s3270/py3270)
nmap -p 23 --script tso-enum --script-args userdb=users.txt <host>
```

### 2. CICS assessment

```bash
# Enumerate transactions and region info
nmap -p 23 --script cics-enum,cics-info,cics-user-enum <host>

# Deeper transaction abuse with CICSpwn (read its --help first)
python CICSpwn.py --help
```

### 3. FTP-to-JES job execution

```bash
ftp <host>                      # authenticate
ftp> quote site filetype=jes    # JES mode
ftp> put iefbr14.jcl            # submit a harmless no-op job to prove it
ftp> get JOB00001               # read spool output back
ftp> quote site filetype=seq    # restore normal mode
```

### 4. IBM i recon to CL execution

```bash
# 1. Map host-server ports
nmap -sV -p 23,21,449,8470-8476 <host>

# 2. Connect a 5250 session
tn5250 ssl:<host>

# 3. If FTP allows it, run CL remotely
ftp <host>
ftp> quote rcmd WRKACTJOB
ftp> quote rcmd DSPUSRPRF QSECOFR
```

---

## Quick Reference

```bash
# TN3270 connect (TLS, named LU)
c3270 L:myLU@<host>:992

# Scriptable 3270
s3270 L:<host>:992            # drive via stdin actions / py3270

# Nmap mainframe recon
nmap -sV -p 23,992 --script tn3270-info,tn3270-screen <host>
nmap -p 23 --script tso-enum,tso-brute --script-args userdb=u.txt,passdb=p.txt <host>
nmap -p 23 --script cics-enum,cics-info,cics-user-enum <host>

# Metasploit
msfconsole -q -x 'search tn3270; search cics'

# FTP to JES
ftp <host>; quote site filetype=jes; put job.jcl

# IBM i 5250
tn5250 ssl:<host>
nmap -sV -p 23,21,449,8470-8476 <host>
```

| Tool | Use | Note |
| --- | --- | --- |
| x3270 / c3270 | GUI / console 3270 | `L:` prefix for TLS, `lu@` for LU |
| s3270 | scriptable 3270 | engine behind py3270 |
| pr3287 | 3287 printer session | capture printed reports |
| py3270 | Python 3270 automation | wraps s3270 |
| nmap-mainframe-scripts | tso/vtam/cics NSE | Soldier of Fortran |
| CICSpwn | CICS abuse | `--help` for current flags |
| MFSleuth | 3270 datastream parsing | field mapping |
| NJElib | NJE traffic | inter-node job entry |
| Metasploit | tn3270/cics aux | `search` for real paths |
| tn5250 / lib5250 | IBM i 5250 | `ssl:` prefix for TLS |
| mocha / x5250 | other 5250 emulators | mocha commercial |

Related notes: 3270 Combined (z/OS methodology), as400_pentest_checklist (IBM i methodology).

---

## Related

- Checklists: 3270 Combined, 5250 Combined
- 3270 Combined
- 5250 Combined
- as400_pentest_checklist
- [OSINT and Recon](OSINT%20and%20Recon.md)
- [Nmap Cheatsheet](Nmap.md)
