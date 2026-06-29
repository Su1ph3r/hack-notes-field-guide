---
tags:
  - hack-notes
  - checklist
  - active-directory
  - internal
---

# Internal Network and Active Directory Testing Checklist

> Phased methodology for an internal network and Active Directory penetration test, from zero-cred or assumed-breach start through domain dominance, trust attacks, and crown-jewel access. Methodology-first: command detail lives in the linked cheatsheets.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Unauthenticated and No-Creds Phase](#2-unauthenticated-and-no-creds-phase)
- [3. Initial Credential Acquisition](#3-initial-credential-acquisition)
- [4. Authenticated Enumeration](#4-authenticated-enumeration)
- [5. Lateral Movement](#5-lateral-movement)
- [6. Privilege Escalation](#6-privilege-escalation)
- [7. Domain Dominance and Persistence](#7-domain-dominance-and-persistence)
- [8. Forest and Trust Attacks](#8-forest-and-trust-attacks)
- [9. Data and Crown-Jewel Access](#9-data-and-crown-jewel-access)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

### Engagement model
- [ ] **Confirm start posture:** zero-cred (network drop, no domain account) vs assumed-breach (low-priv domain user, workstation, or hash supplied). Drives which phases apply first. See [Assumed Breach](Assumed%20Breach.md) when creds are pre-provisioned.
- [ ] **Confirm objective:** path-to-Domain-Admin proof, specific crown-jewel data access, detection/response validation (purple), or full breadth coverage. Objective sets the stop conditions.
- [ ] **Confirm detection expectations:** is the SOC informed (announced) or is this a stealth/evasion assessment? Loud tooling (Responder, mass auth) is only acceptable when announced or explicitly authorized.
- [ ] **Get the in-scope ranges and domains in writing:** subnets, AD domains/forests, child domains, trusted forests, cloud-sync boundaries (Entra Connect). Out-of-scope hosts/segments named explicitly.

### Rules of engagement and safety
- [ ] **Identify fragile systems:** ICS/SCADA, medical devices, legacy printers/embedded, EOL servers, ESXi/storage controllers. Exclude from aggressive scanning and from any coercion/relay that could crash a service.
- [ ] **Agree on destructive-action boundaries:** no DCSync without approval, no persistence that survives the engagement, no real ticket-forging on production unless objective requires, no mass account changes.
- [ ] **Set test windows and a kill switch:** named technical contact reachable during testing, agreed pause/abort signal, and a rollback owner for any change you make.
- [ ] **Capture a clean baseline:** DC count and roles, replication health, and current lockout policy BEFORE testing, so you can prove you did not cause an outage.

```
⚠️ ACTIVE DIRECTORY SAFETY
- Account lockout: enumerate the lockout policy (threshold, window, duration) BEFORE
  any password spray. Spray one password per cycle, stay under threshold minus 1, and
  respect the observation window. A bad spray locks the whole domain.
- DC load: Kerberoasting, SharpHound (especially with ACL/LoggedOn/Session/All), and
  mass NetExec sweeps hit DCs hard. Throttle, target one DC, and avoid business hours
  on fragile environments. Never run unbounded LDAP paging against a single DC.
- Coercion and relay: PetitPotam/PrinterBug/DFSCoerce force machine auth. On fragile
  hosts (print servers, legacy spoolers) coercion can crash the service. Pre-clear targets.
- Cleanup: track every account, machine account (MAQ abuse), certificate, ticket, ACL
  edit, GPO change, and shadow-credential you add. Remove them all and confirm.
```

- [ ] **Define evidence handling:** where loot (hashes, tickets, NTDS.dit) is stored, encrypted at rest, and destroyed at engagement end. Never exfil NTDS.dit off the client estate without written approval.

---

## 2. Unauthenticated and No-Creds Phase

> Goal: turn a network cable into a first credential. Passive first, then active poisoning, then relay. Command detail in [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md).

### Passive and low-noise recon
- [ ] **Passive listen first:** run a sniffer on the drop to learn the domain name, DC IPs, naming, and broadcast/multicast chatter before sending a packet. Records who is talking LLMNR/NBT-NS/mDNS.
- [ ] **Map the segment:** host discovery and a focused port sweep (445/139/389/636/88/3389/5985/1433) across the in-scope range. Identify DCs (88/389/636 + DNS + Kerberos), file servers, SQL, and ADCS web enrollment (80/443 `/certsrv`, `/certrust`).
- [ ] **Identify the domain and DCs:** from DNS SRV records (`_ldap._tcp.dc._msdcs.<domain>`), NetBIOS, or LDAP rootDSE. Note functional level and DC OS versions.

### Name-resolution poisoning
- [ ] **LLMNR/NBT-NS/mDNS poisoning:** run Responder in analyze mode first to confirm broadcast traffic exists, then in poisoning mode to capture NetNTLMv1/v2 from hosts resolving bad names. Pass = captured hash for a domain account.
- [ ] **WPAD abuse:** answer WPAD requests to harvest proxy-auth NetNTLM. Confirm a victim actually fetched the served PAC/credential prompt.
- [ ] **Crack vs relay decision:** captured NetNTLMv2 → crack offline (hashcat) if the account looks weak, OR relay live (next subsection) if SMB signing is off on a useful target. Do not waste a relay opportunity by only cracking.

### IPv6 and DHCPv6 (mitm6)
- [ ] **IPv6 takeover (mitm6):** most AD networks run dual-stack with no IPv6 DNS defense. Spoof DHCPv6 to become the primary DNS server, then answer WPAD/name lookups to coerce auth. Pass = victim auth lands at your relay.
- [ ] **Scope mitm6 tightly:** filter to specific target hosts/domains. Unscoped mitm6 can blackhole DNS for a whole VLAN. Note this in the safety log.

### NTLM relay
- [ ] **Check signing posture first:** enumerate SMB signing across the subnet (`nxc smb <range> --gen-relay-list`). Hosts with signing not required are relay targets. LDAP signing/channel-binding state determines LDAP relay viability.
- [ ] **Relay to SMB:** relay captured/coerced NTLM to signing-off hosts for code exec, secretsdump, or session. Pass = command output or SAM dump on relayed host.
- [ ] **Relay to LDAP/LDAPS:** with LDAP signing off (or LDAPS without channel binding), relay to grant RBCD on a victim computer, add shadow credentials, or dump the directory. Highest-value relay path.
- [ ] **Relay to ADCS web enrollment (ESC8):** relay machine/user NTLM to the CA `/certsrv` HTTP endpoint, request an auth cert, then use the cert (PKINIT/UnPAC) to recover a TGT and NT hash. Pass = TGT for the relayed account.

### Roasting without creds
- [ ] **AS-REP roasting:** query for accounts with "Do not require Kerberos pre-auth" (`UF_DONT_REQUIRE_PREAUTH`) and request AS-REPs to crack offline. Needs only a username list (or anonymous LDAP). Pass = crackable AS-REP hash.
- [ ] **Build a user list cheaply:** anonymous LDAP, RID cycling over SMB null session, Kerberos username enumeration (`kerbrute userenum`), or harvested names. Feed both AS-REP roast and a careful spray.
- [ ] **Username-only spray (rare):** if a weak default password is suspected, spray one candidate under the lockout threshold. Confirm policy first (see safety block).

### Anonymous and null-session enumeration
- [ ] **Anonymous LDAP bind:** attempt unauthenticated LDAP bind on 389/636. If allowed, pull naming contexts, users, groups, and rootDSE. Note machine-account quota and password policy.
- [ ] **SMB null/guest session:** enumerate shares, users (RID cycling), and password policy via null or guest. Pass = readable share list or user enumeration without creds.
- [ ] **Network share hunting:** crawl readable shares for credentials, scripts, config files, KeePass DBs, `unattend.xml`/`sysprep`, GPP `cpassword`, and backups. A single readable share often yields the first real credential.
- [ ] **Other anonymous surfaces:** SNMP public, NFS exports, FTP anon, MSSQL/Oracle default creds, web admin panels, and IPMI/iDRAC defaults on the management VLAN.

---

## 3. Initial Credential Acquisition

> Goal: convert poisoning/coercion into a usable identity (cleartext, NT hash, or certificate/TGT).

### Capture and relay execution
- [ ] **Operate Responder + relay together:** Responder for name-resolution capture, ntlmrelayx for the relay targets list. Confirm the relay actually fires and lands an action, not just a connection.
- [ ] **Relay to LDAP → RBCD or shadow creds:** on relay, write `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) using an attacker-controlled computer (created via Machine Account Quota), or write `msDS-KeyCredentialLink` (shadow credentials) to take over the relayed object.
- [ ] **Relay to ADCS (ESC8/ESC11):** ESC8 = HTTP enrollment endpoint; ESC11 = RPC enrollment with packet privacy not enforced. Recover a cert for the relayed machine/user, then PKINIT for a TGT.

### Authentication coercion
- [ ] **PetitPotam (MS-EFSRPC):** coerce a target (often a DC) to authenticate to your relay via EFSRPC. Pair with ADCS relay for a DC machine cert → DC TGT. Pass = DC auth at relay.
- [ ] **PrinterBug (MS-RPRN / SpoolSample):** coerce via the print spooler RPC. Works where the Spooler service is reachable and running.
- [ ] **DFSCoerce (MS-DFSNM):** coerce via the DFS Namespace service on a DC. Often works when PetitPotam is patched.
- [ ] **ShadowCoerce (MS-FSRVP):** coerce via the File Server VSS Agent. Try when other coercion vectors are blocked.
- [ ] **Coercer sweep:** run Coercer to fire all known coercion methods against a target and report which RPC paths respond. Note which one fired for the report and pick the least fragile.
- [ ] **Pair coercion with a relay or capture:** coercion alone is just auth. Always have a relay (LDAP/ADCS) or capture (Responder) staged to receive it.

### Confirm and stage the credential
- [ ] **Validate every credential before using it broadly:** test one auth (`nxc smb <DC> -u <user> -p <pass>`) before spraying it estate-wide. A locked or honeypot account here is costly.
- [ ] **Note the credential type and reuse it correctly:** cleartext (any protocol), NT hash (pass-the-hash, NTLM), AES key (Kerberos), TGT/cert (PKINIT). Record which you hold for each principal.

---

## 4. Authenticated Enumeration

> Goal: with one domain identity, map the entire attack surface before touching anything. Kerberos/ticket detail in [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md); tooling in [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md).

### BloodHound collection
- [ ] **Collect with SharpHound/RustHound/bloodhound-python:** run a full collection (Group, ACL, Trusts, Sessions, LocalGroup, GPOLocalGroup, Container, CertServices). DCOnly is the low-noise option; All is loud (see safety block). Pass = importable zip.
- [ ] **Collect ADCS data:** ensure CertServices/PKI collection runs so ESC paths and CA config show up as nodes/edges. Cross-check with Certipy enumeration.
- [ ] **Import and run built-in + custom queries:** shortest paths to Domain/Enterprise Admins, paths from owned principals, Kerberoastable/AS-REP-roastable, unconstrained delegation, and ADCS escalation queries.
- [ ] **Mark owned nodes:** tag every principal you control so BloodHound computes outbound paths from your real foothold. Feed the graph to Ariadne for attack-path synthesis across findings.

### Domain and forest mapping
- [ ] **Enumerate the domain object set:** users, groups, computers, OUs, GPOs, trusts, sites, and the domain/forest functional level. Note the password and lockout policy (fine-grained PSOs too).
- [ ] **Find privileged groups and nesting:** Domain Admins, Enterprise Admins, Administrators, Account Operators, Backup Operators, Server Operators, DnsAdmins, Schema Admins, and Protected Users membership. Resolve nested membership.
- [ ] **Map trusts:** intra-forest (parent/child) and inter-forest trusts, transitivity, SID filtering state, and direction. Flags forest/trust attack paths (Phase 8).
- [ ] **Inventory machine accounts and quota:** read `ms-DS-MachineAccountQuota` (default 10). A nonzero quota is an enabler for RBCD, shadow-cred, and certifried chains.

### Access and misconfiguration enumeration
- [ ] **ACL/DACL abuse hunting:** GenericAll, GenericWrite, WriteDACL, WriteOwner, AddMember, ForceChangePassword, AllowedToAct, and AddKeyCredentialLink rights over high-value objects. These are the bread-and-butter escalation edges.
- [ ] **GPO enumeration:** find GPOs you can edit (WriteProperty/WriteDACL on the GPO) and what OUs they link to. Editable GPO linked to a privileged OU = path to code exec on those hosts.
- [ ] **Delegation enumeration:** unconstrained delegation (TrustedForDelegation), constrained delegation (`msDS-AllowedToDelegateTo`), and resource-based constrained delegation (RBCD). Each is a distinct escalation primitive.
- [ ] **LAPS readability:** identify which principals can read `ms-Mcs-AdmPwd` (legacy LAPS) or `msLAPS-Password`/`msLAPS-EncryptedPassword` (Windows LAPS). A readable LAPS password is a local admin handout.
- [ ] **Share and SQL enumeration with creds:** re-crawl shares now reachable, and enumerate MSSQL instances (links, sysadmin, xp_cmdshell, impersonation). SQL links often cross trust boundaries.

### Kerberoasting and roastable accounts
- [ ] **Kerberoast:** request TGS for accounts with SPNs and crack offline. Prioritize service accounts in privileged groups. Pass = crackable TGS-REP for a useful account.
- [ ] **AS-REP roast (authenticated):** re-confirm any `DONT_REQ_PREAUTH` accounts now that you can query reliably.
- [ ] **Targeted Kerberoast via write access:** where you hold GenericWrite/GenericAll over a user, set an SPN, roast it, then remove the SPN. Note this as an active change to revert.

---

## 5. Lateral Movement

> Goal: move from the first host/identity to additional hosts and higher-value identities. Pivoting in [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md); shells and transfer in [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md).

### Credential reuse across hosts
- [ ] **Pass-the-hash:** authenticate with an NT hash where the account has local admin (`nxc smb <targets> -u <user> -H <hash> --local-auth` or domain). Map where each owned credential grants admin.
- [ ] **Pass-the-ticket:** inject a captured/forged TGT or TGS into the session and use Kerberos auth (no password/hash needed). Useful when only a ticket is held.
- [ ] **Overpass-the-hash (pass-the-key):** turn an NT/AES hash into a Kerberos TGT, then use Kerberos. Cleaner than raw NTLM on logging-sensitive estates.
- [ ] **Spray validated creds carefully:** sweep an owned credential across the estate to find admin access, staying mindful of lockout for password-based sprays (hash/key auth does not lock the same way but still logs).

### Remote execution
- [ ] **Pick the exec channel per host:** SMB (PsExec-style, services), WMI, WinRM (5985/5986), DCOM, scheduled tasks, or remote registry. Match the channel to what is open and least likely to alert.

| Channel | Port | Notes |
|---|---|---|
| SMB service exec | 445 | Loud (service create + named pipe); reliable SYSTEM |
| WMI | 135 + dynamic | No new service; stealthier; needs DCOM reachable |
| WinRM | 5985/5986 | Clean PS remoting; needs Remote Management Users/admin |
| DCOM (MMC/ShellExec) | 135 + dynamic | Niche, evasive lateral exec |
| RDP | 3389 | Interactive; check Restricted Admin / cred exposure |

- [ ] **Confirm exec landed as expected identity:** verify `whoami`/token (SYSTEM vs the moving account). Note where you only have user, not SYSTEM.

### Credential dumping on owned hosts
- [ ] **SAM/LSA secrets:** dump local SAM and LSA secrets (cached domain creds, service-account passwords, autologon) from each admin'd host. Cached domain creds may crack to a domain password.
- [ ] **LSASS credential extraction:** harvest cleartext, NT hashes, Kerberos tickets, and DPAPI keys from LSASS where AV/PPL allow. Capture only what the objective needs; note PPL/Credential Guard blocking.
- [ ] **DPAPI loot:** decrypt browser/credential-manager/RDP secrets via DPAPI master keys (user or domain backup key). Often yields additional service or admin creds.
- [ ] **Hunt for tickets and sessions:** harvest TGTs from memory on multi-user hosts (jump boxes, RDS) for high-value session reuse. A DA logged into a jump box is a fast win.

---

## 6. Privilege Escalation

> Goal: escalate local user → local admin/SYSTEM, then any-identity → Domain Admin. Local Windows privesc in [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md); cert tooling in [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md).

### Local to SYSTEM
- [ ] **Local privesc on footholds:** unquoted service paths, weak service/file ACLs, token privileges (SeImpersonate → Potato family), AlwaysInstallElevated, and unpatched kernel/LPE. Full method in [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md).
- [ ] **Local admin to domain creds:** once SYSTEM/local admin, dump as in Phase 5 and pivot the harvested domain identities into AD escalation below.

### Delegation abuse
- [ ] **Unconstrained delegation:** compromise a host with unconstrained delegation, coerce a DC/privileged host to auth to it, capture its TGT, and reuse. DC coercion here = instant domain compromise.
- [ ] **Constrained delegation (S4U):** abuse `msDS-AllowedToDelegateTo` + S4U2Self/S4U2Proxy to impersonate any user (including DA) to the target service. Watch protocol-transition vs not.
- [ ] **Resource-based constrained delegation (RBCD):** where you can write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer, add an attacker-controlled machine (MAQ) and S4U to impersonate admin on that host. Pairs with LDAP relay.

### ACL and GPO abuse
- [ ] **ACL escalation:** exploit GenericAll/GenericWrite/WriteDACL/WriteOwner over a privileged object: reset password (ForceChangePassword), add to group, set SPN (targeted Kerberoast), or add shadow credentials. Revert all writes.
- [ ] **GPO abuse:** with edit rights on a GPO linked to a privileged OU, deploy an immediate scheduled task / startup script for code exec on linked hosts (often servers/DCs). High blast radius; pre-clear and clean up.

### ADCS escalation (ESC1-ESC16)
- [ ] **Enumerate the CA and templates (Certipy `find`):** identify vulnerable templates, EKUs, enrollment rights, manager-approval, and CA flags. Output BloodHound + JSON. This drives which ESC applies.

| ESC | Misconfiguration | One-line test/abuse |
|---|---|---|
| ESC1 | Enrollee supplies subject + client-auth EKU | Request cert as a DA via `-upn`/`-sid` |
| ESC2 | Any Purpose / no EKU template | Use cert for client auth to impersonate |
| ESC3 | Enrollment Agent template | Enroll-on-behalf-of a privileged user |
| ESC4 | Write access over a template | Rewrite template to be ESC1, enroll, restore |
| ESC5 | Control of CA-related AD objects / PKI host | Compromise the object to control issuance |
| ESC6 | CA EDITF_ATTRIBUTESUBJECTALTNAME2 | SAN-inject any UPN on enrollment |
| ESC7 | CA management rights (ManageCA/Certs) | Grant self enroll / approve own request |
| ESC8 | HTTP enrollment + NTLM relay | Relay machine NTLM to `/certsrv` for a cert |
| ESC9 | No security extension on template (szOID off) | Map via altSecID / weak binding to impersonate |
| ESC10 | Weak cert mapping (registry) | StrongCertificateBindingEnforcement abuse |
| ESC11 | RPC enrollment, no packet privacy | Relay NTLM over RPC (ICertPassage) for a cert |
| ESC12 | CA private key on YubiHSM / shell access | Recover CA key from the device, forge certs |
| ESC13 | Issuance policy linked to a group (OID→group) | Enroll template → cert grants that group |
| ESC14 | Write on altSecurityIdentities (explicit map) | Map a victim to your cert, authenticate as them |
| ESC15 | V1 template, app-policy injection (EKUwu) | Inject client-auth app policy into a CSR |
| ESC16 | CA disables security extension globally | Combine with weak mapping to impersonate |

- [ ] **Certifried (CVE-2022-26923):** with write to a computer's `dNSHostName`, create/rename a machine to collide with a DC name, enroll a machine cert, and authenticate as the DC. Patch-state dependent.
- [ ] **Golden certificate:** if you reach the CA private key (ESC7/ESC12 or DA), forge certs for any principal for long-term auth persistence. Note as persistence (Phase 7).
- [ ] **Use Certipy 5.x end to end:** `find` → request/relay → `auth` (PKINIT) → recover TGT + NT hash. Confirm the resulting TGT authenticates as the target.

---

## 7. Domain Dominance and Persistence

> Goal: prove and (only with approval) hold Domain/Enterprise Admin. Everything here is high blast radius and must be in scope.

```
⚠️ DOMAIN DOMINANCE ACTIONS
DCSync, ticket forging, DSRM, AdminSDHolder, and Skeleton Key are domain-altering or
credential-of-record operations. Run only with explicit written approval, log every
action with timestamps, and remove all persistence (tickets, ACLs, accounts, keys)
before the engagement closes. Never forge tickets or run Skeleton Key on production
without a rollback owner on the line.
```

### Credential extraction at domain scale
- [ ] **DCSync:** with replication rights (Replicating Directory Changes All), pull the krbtgt hash and any account's NT/AES keys without touching the DC disk. Pass = krbtgt hash recovered.
- [ ] **NTDS.dit extraction:** on a DC (or via VSS/IFM backup), extract the full directory hash set offline. Treat the file as crown-jewel data; do not exfil off-estate.

### Ticket-based persistence
- [ ] **Golden ticket:** forge a TGT with the krbtgt hash to impersonate any user indefinitely (until krbtgt is rotated twice). Highest-value, highest-detection persistence.
- [ ] **Silver ticket:** forge a TGS for a specific service using that service account's key. Stealthier (no DC contact) but scoped to one service/host.
- [ ] **Diamond ticket:** request a real TGT then modify its PAC in place (decrypt/re-encrypt with krbtgt key). Blends with legitimate ticket traffic better than a golden.
- [ ] **Sapphire ticket:** like diamond but inject a real privileged account's PAC (via S4U) for a more authentic ticket. Use when PAC-validation/anomaly detection is in play.

### Directory persistence
- [ ] **DCSync rights backdoor:** grant a low-priv principal replication rights (WriteDACL on the domain head) for stealth re-DCSync later. Track for removal.
- [ ] **AdminSDHolder / SDProp:** write a DACL on the AdminSDHolder object; SDProp re-applies it to all protected groups within ~60 min, re-granting your access even after cleanup elsewhere. Document and revert.
- [ ] **DSRM abuse:** set/recover the DSRM (local admin) password on a DC and configure DsrmAdminLogonBehavior for network logon as a backdoor local admin on the DC.
- [ ] **Skeleton Key:** patch LSASS on a DC to accept a master password for all accounts (memory-resident, lost on reboot). Loud and fragile: approval-only, single-DC, revert by reboot.
- [ ] **Shadow credentials / cert persistence:** add `msDS-KeyCredentialLink` on key accounts or hold a golden/forged certificate for re-entry that survives password resets. Track every key/cert added.

---

## 8. Forest and Trust Attacks

> Goal: cross from the compromised domain into parents, children, or trusting forests.

- [ ] **Map trust direction, transitivity, and SID filtering:** intra-forest trusts are not a security boundary; the forest is. Inter-forest trusts may have SID filtering that blocks SID-history abuse.
- [ ] **Child → parent (SID history):** with child-domain krbtgt (DCSync the child), forge a golden ticket with the parent's Enterprise Admins SID in SID history. Intra-forest SID filtering is off by default. Pass = EA access in parent.
- [ ] **Trust-key forging (inter-realm TGT):** extract the trust account key (`<TRUSTED>$`) and forge an inter-realm referral TGT to access the trusting domain as a chosen principal. Scope to SID-filtering state.
- [ ] **Unconstrained delegation across trusts:** coerce a DC from a trusting domain to auth to a host with unconstrained delegation you control, capturing a foreign-domain DC TGT.
- [ ] **Kerberoast/AS-REP across trusts:** SPN and roastable accounts in a trusting domain are often reachable through the trust. Enumerate before assuming isolation.
- [ ] **Foreign group membership and ACLs:** find principals from one domain with rights/membership in another (ForeignSecurityPrincipals). Common, quiet cross-domain path.
- [ ] **Cloud trust pivot:** if Entra Connect / hybrid join is present, an on-prem DA can often pivot to cloud (sync account, seamless SSO, PTA). Hand off to [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md) for the cloud side.

---

## 9. Data and Crown-Jewel Access

> Goal: tie domain compromise to real business impact for the report. Access proves risk; do not exfiltrate beyond what evidences the finding.

- [ ] **Confirm the objective targets:** the specific systems/data named in scope (finance, HR/PII, source code, secrets vaults, backups, email). Access of these is the engagement's headline impact.
- [ ] **File server and share crawl:** with elevated rights, locate sensitive document stores, PII, and IP. Capture a directory listing or a single redacted sample as proof, not bulk data.
- [ ] **Database access:** reach MSSQL/Oracle/Postgres holding crown-jewel data; demonstrate read of a sensitive table (row count + one redacted row), not a full dump.
- [ ] **Secrets and vaults:** access to CyberArk/HashiCorp Vault/Azure Key Vault, GPP/scripts/CI secrets, and service-account credential stores. A reachable vault is a high-impact finding.
- [ ] **Backup and virtualization access:** Veeam/backup consoles, ESXi/vCenter, and SAN/NAS. Backup admin frequently equals full-estate access and ransomware blast radius; call it out.
- [ ] **Email and collaboration:** Exchange/M365 admin, SharePoint, and Teams data reachable from the compromised identity. Note any path to global mailbox access.
- [ ] **Demonstrate impact safely:** screenshot access with the proving identity and a timestamp; record the exact path (graph from Ariadne) from foothold to crown jewel. Stop at proof.

---

## Recent Techniques (2024-2026)

- [ ] **CVE-2025-33073 (NTLM reflection / reflective Kerberos relay over SMB):** coerce a host to auth to a crafted marshalled name, relay its own ticket back to SMB for SYSTEM. Test for: unpatched (pre-Jun 2025) hosts with SMB signing not required; confirm with the reflective relay PoC.
- [ ] **badSuccessor / CVE-2025-53779 (dMSA abuse, Windows Server 2025):** CreateChild on any OU plus writing `msDS-ManagedAccountPrecededByLink` on a dMSA inherits a target's keys/permissions. Test for: WS2025 DCs + a principal with CreateChild on an OU; enumerate dMSA write paths in BloodHound.
- [ ] **dMSA Ouroboros (WS2025 dMSA key extraction):** self-sustaining credential extraction via dMSA migration links. Test for: WS2025 domains with dMSA enabled; check post-patch residual link-abuse paths.
- [ ] **ESC15 / EKUwu (CVE-2024-49019):** inject arbitrary application policies into a CSR against V1 schema templates, overriding the template EKU with only enrollment rights. Test for: unpatched CA (pre-Nov 2024) + any enrollable V1 template; Certipy `req` with `-application-policies`.
- [ ] **ESC16 (CA security extension disabled globally):** CA omits `szOID_NTDS_CA_SECURITY_EXT` on all certs, breaking strong binding. Test for: `Disable Extension List` containing the security-ext OID in Certipy `find`; chain with weak mapping/ESC9-style impersonation.
- [ ] **ESC13 (issuance-policy → group link):** template carries an issuance policy OID linked to an AD group; the issued cert grants that group. Test for: certificate templates with `msPKI-Certificate-Policy` mapping to a privileged group (Certipy flags it).
- [ ] **ESC14 (altSecurityIdentities weak explicit mapping):** write access to `altSecurityIdentities` lets you map a victim to your cert. Test for: principals with write over altSecurityIdentities on high-value accounts.
- [ ] **Certipy 5.x:** unified ESC1-ESC16 enum/abuse with native BloodHound output, ESC16 support, and ESC12/ESC14 post-ex. Test for: run `certipy find -bloodhound` and review the ADCS edges in BloodHound CE.
- [ ] **NTLM relay to ADCS (ESC8 HTTP / ESC11 RPC):** relay coerced machine NTLM to web or RPC enrollment for a machine cert → DC TGT. Test for: CA web enrollment reachable or RPC enrollment without packet privacy; SMB/LDAP signing posture.
- [ ] **Kerberos relay (cross-protocol):** relay Kerberos (not just NTLM) where AP-REQ can be redirected (DNS/SMB), expanding relay beyond NTLM-only defenses. Test for: coercion + a relay target reachable over a relayable Kerberos service.
- [ ] **ms-DS-MachineAccountQuota abuse:** default quota 10 lets any user create a computer account, the enabler for RBCD, shadow-cred, and certifried chains. Test for: `MachineAccountQuota > 0`; add a machine with `addcomputer`.
- [ ] **Shadow Credentials (msDS-KeyCredentialLink):** write the attribute to add a rogue key, PKINIT, and UnPAC the NT hash, no password reset. Test for: AddKeyCredentialLink/GenericWrite over a target + a PKINIT-capable DC; pyWhisker/Certipy `shadow auto`.
- [ ] **Windows LAPS abuse:** read `msLAPS-Password` / `msLAPS-EncryptedPassword` (or legacy `ms-Mcs-AdmPwd`) where ACLs allow, handing over local admin. Test for: principals with read rights on LAPS attributes (BloodHound `ReadLAPSPassword`).
- [ ] **Coercer / DFSCoerce / ShadowCoerce maturity:** multi-method coercion (MS-EFSRPC, MS-RPRN, MS-DFSNM, MS-FSRVP) to bypass single-patch mitigations. Test for: run Coercer against DCs/file servers and record which RPC path still responds.
- [ ] **BloodHound CE OpenGraph (2025):** v8 OpenGraph adds custom nodes/edges and community collectors (SCCM/ConfigMgr, identity platforms) beyond AD/Entra. Test for: ingest OpenGraph collectors and review new edge types for non-AD pivots.

---

## Reporting and Evidence

### Evidence to capture per finding
- [ ] **Reproduction path:** exact commands/tooling, source and target host, the identity used, and timestamps. One clean command-to-result capture per finding.
- [ ] **Proof artifact:** captured/cracked hash (redacted), TGT/cert, screenshot of access as the proving identity, or BloodHound path image. Redact secrets in the report; keep raw loot in the secured evidence store only.
- [ ] **Attack-path graph:** the foothold-to-impact chain (BloodHound / Ariadne) showing each edge abused. Most compelling artifact for an AD report.
- [ ] **Changes made:** every account, machine account, ACL, GPO, ticket, certificate, and shadow-cred added, with confirmation of removal.

### Severity guidance
- [ ] **Rate by realized impact and reachability:** path to Domain/Enterprise Admin from a low-priv or unauth start = Critical. Single-host local admin or a finding gated behind significant existing access = lower. Let the proven chain set the rating, not the technique's reputation.
- [ ] **Derive the CVSS vector before the label:** topology/metadata leaks are C:L, not C:H. Do not inflate; default down on the Medium/High boundary.

### Common false positives to rule out
- [ ] **Kerberoast/AS-REP on disabled or honeypot accounts:** confirm the account is enabled, privileged, and the hash actually cracks before claiming impact.
- [ ] **Relay against signing-enforced hosts:** a connection is not a compromise. Confirm the relay landed an action.
- [ ] **ADCS ESC findings that are patched:** check CA patch level and template flags at test time (ESC15/ESC16 are patch-state dependent). Prove issuance, not just a flagged template.
- [ ] **badSuccessor on patched WS2025:** confirm DC build and that the one-sided link still yields privileges post-CVE-2025-53779 patch.
- [ ] **"GenericAll" edges that are stale:** BloodHound edges can lag reality. Validate the right is still present before reporting it as exploitable.

---

## Tools and References

| Tool | Use |
|---|---|
| NetExec (nxc) | Multi-protocol sweep, spray, relay-list, exec, dumping. See [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md) |
| Impacket | secretsdump, ntlmrelayx, GetUserSPNs, GetNPUsers, getST, ticketer |
| Responder | LLMNR/NBT-NS/mDNS poisoning, WPAD capture |
| mitm6 | IPv6/DHCPv6 DNS takeover for coercion |
| BloodHound CE + SharpHound | Attack-path graphing (v8 OpenGraph), collection |
| Certipy 5.x | ADCS ESC1-ESC16 enum and abuse, shadow creds, golden certs |
| Coercer / PetitPotam / DFSCoerce | Authentication coercion (multi-RPC) |
| Rubeus / pyWhisker / Whisker | Kerberos abuse, shadow credentials |
| Mimikatz / nanodump | LSASS, DPAPI, DCSync, ticket forging |
| ldapdomaindump / windapsearch | LDAP enumeration |

- Reference: MITRE ATT&CK (Enterprise, Credential Access / Lateral Movement / Persistence), The Hacker Recipes (AD), HackTricks AD methodology, SpecterOps BloodHound docs, ly4k/Certipy wiki, Microsoft AD CS / Kerberos / LAPS docs, Akamai badSuccessor research.

---

## Related

- Playbooks: [Coercion to ADCS ESC8 to Domain Admin](../Playbooks/Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md), [Kerberoasting to Domain Admin](../Playbooks/Kerberoasting%20to%20Domain%20Admin.md), [IPv6 mitm6 Relay to RBCD Takeover](../Playbooks/IPv6%20mitm6%20Relay%20to%20RBCD%20Takeover.md), [badSuccessor dMSA to Domain Admin](../Playbooks/badSuccessor%20dMSA%20to%20Domain%20Admin.md), [DCSync to Golden Ticket Persistence](../Playbooks/DCSync%20to%20Golden%20Ticket%20Persistence.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [NetExec and Impacket](../Cheatsheets/NetExec%20and%20Impacket.md)
- [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
- [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- Ariadne
- [External Network Penetration Test](External%20Network%20Penetration%20Test.md)
- [Assumed Breach](Assumed%20Breach.md)
