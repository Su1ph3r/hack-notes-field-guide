---
tags:
  - hack-notes
  - checklist
  - cloud
  - azure
---

# Azure and M365 Entra ID Testing Checklist

> Phased methodology for assessing Microsoft Entra ID (Azure AD), Microsoft 365, and Azure Resource Manager tenants. Covers unauthenticated recon, initial access, directory enumeration, privilege escalation, ARM resource abuse, hybrid identity, and persistence. Commands live in the [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md) cheatsheet; this note is the ordered playbook.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Unauthenticated Recon](#2-unauthenticated-recon)
- [3. Initial Access](#3-initial-access)
- [4. Entra ID Enumeration](#4-entra-id-enumeration)
- [5. Privilege Escalation](#5-privilege-escalation)
- [6. Azure Resource Manager](#6-azure-resource-manager)
- [7. Lateral and Hybrid](#7-lateral-and-hybrid)
- [8. Persistence](#8-persistence)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Get the boundary in writing before touching the tenant. Entra ID actions are tenant-global, logged, and frequently trip Defender and the SOC. Know what is in scope and what is destructive before you authenticate.

### Scope definition
- [ ] **Capture the tenant ID and primary domains.** Confirm the GUID and every verified `*.onmicrosoft.com` and custom domain in scope. Cross-tenant guests and B2B relationships may be out of scope even if reachable.
- [ ] **Separate Entra ID (identity) from Azure RM (resources) scope.** A tenant can authorize identity testing but exclude subscriptions, or vice versa. Confirm which subscription IDs and management groups are in play.
- [ ] **Separate M365 from Azure.** SharePoint, Exchange Online, Teams, OneDrive, and Purview each carry their own data-handling rules. Pillaging mailboxes and SharePoint is often explicitly excluded; confirm before running GraphRunner pillage modules.
- [ ] **Enumerate provided accounts and their intended privilege.** Note whether each test identity is a cloud-only user, a synced (hybrid) user, a guest, a service principal (app + secret/cert), or a break-glass account. Record starting roles.
- [ ] **Clarify assumed-breach vs black-box.** Black-box starts at unauthenticated recon. Assumed-breach typically hands you a low-priv user or a phished token; know which.

### Rules of engagement and safety
- [ ] **Confirm password spray authorization and lockout tolerance.** Smart Lockout and on-prem AD lockout policies mean a clumsy spray can lock real users. Agree thresholds, target lists, and timing windows in writing.
- [ ] **Establish Conditional Access (CA) awareness.** Ask whether the client will whitelist your source IP / device, or whether bypassing CA (location, device compliance, MFA) is itself an objective. Do not assume.
- [ ] **Confirm phishing and consent-grant authorization.** Device-code phishing, illicit OAuth consent, and AiTM each create real attacker artifacts (registered apps, consented grants). Get explicit sign-off and a cleanup commitment. See [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md).
- [ ] **Identify break-glass / emergency-access accounts and exclude them.** Never spray, lock, or alter the accounts that the client uses to recover the tenant.
- [ ] **Agree a notification and abort path.** Decide who to call if you trigger attack disruption, a tenant-wide CA lockout, or an automated containment action.

```
⚠️ Tenant-global blast radius. Creating apps, granting admin consent, adding
credentials to service principals, editing CA policies, or registering devices
changes shared tenant state and can lock out users or break SSO. Treat every
write to Entra ID as production-impacting. Log every object you create with its
ID and timestamp so it can be removed at teardown.
```

- [ ] **Define evidence handling for tokens.** Access tokens, refresh tokens, and PRTs are live credentials. Store them encrypted, never in tickets or chat, and revoke at engagement end.

---

## 2. Unauthenticated Recon

Everything here is reachable pre-auth against public Microsoft endpoints. None of it requires a credential, but realm and OAuth endpoints do log. Map the tenant before you ever send a password.

### Tenant fingerprinting
- [ ] **Resolve the tenant ID and brand.** Pull the OpenID configuration to confirm the tenant GUID and authorization endpoints.
  ```bash
  curl -s https://login.microsoftonline.com/<domain>/.well-known/openid-configuration | jq .token_endpoint
  ```
- [ ] **Enumerate registered domains via autodiscover / GetUserRealm.** The realm endpoint reveals whether a domain is `Managed` (cloud auth) or `Federated` (on-prem IdP such as ADFS, Okta, PingFederate).
  ```bash
  curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&xml=1"
  ```
- [ ] **Pull all tenant domains with AADInternals.** `Invoke-AADIntReconAsOutsider -DomainName <domain>` returns every verified domain, the tenant ID, brand name, MX/SPF/DKIM/DMARC posture, DesktopSSO (Seamless SSO) state, and whether Sync (Entra Connect) is enabled. Record DesktopSSO=True as a hybrid attack lead.
- [ ] **Identify federation and the on-prem IdP.** A federated domain points authentication off-Microsoft; note the federation server FQDN (often `sts.<domain>` / `adfs.<domain>`) as a separate target. Managed domains validate passwords at Entra directly.

### User and resource discovery
- [ ] **Validate users via the GetCredentialType / OAuth endpoints.** `IfExistsResult` discloses whether an account exists without consuming a logon. Feed name lists from OSINT (see [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)) and the org's email format.
  ```bash
  curl -s https://login.microsoftonline.com/common/GetCredentialType -d '{"Username":"user@<domain>"}'
  ```
- [ ] **Watch for `ThrottleStatus` and IfExistsResult nuances.** Federated and some B2B accounts return ambiguous results; corroborate with AADInternals `Invoke-AADIntUserEnumerationAsOutsider`.
- [ ] **Enumerate guest and external accounts.** Note `#EXT#` UPNs surfaced during user validation; guests can be a softer initial-access path.
- [ ] **Probe for public resources.** Storage account, blob, and Azure Websites name guessing (`<name>.blob.core.windows.net`, `<name>.azurewebsites.net`), public SharePoint/OneDrive, and exposed app registrations. Tie to subdomain takeover checks on dangling `*.azureedge.net` / `*.cloudapp.azure.com`.
- [ ] **Check for legacy / basic auth surface.** Confirm whether Exchange Online still accepts legacy protocols (IMAP/POP/SMTP AUTH) and whether the `BAV2ROPC` resource-owner-password flow is reachable; both bypass interactive CA and are prime spray targets.
- [ ] **Record the CA and MFA posture you can infer.** Realm responses, Seamless SSO state, and federation type shape the entire initial-access plan. Build a target matrix before phase 3.

---

## 3. Initial Access

Goal: turn recon into a first authenticated token. Every technique here is authorized-only and creates artifacts. Coordinate timing with the client SOC contact. Detailed phishing infrastructure and pretext design live in [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md).

### Password spray (lockout-aware)
- [ ] **Spray low and slow against Smart Lockout.** One or two passwords per account per cycle, long delays, randomized order. Smart Lockout tracks familiar vs unfamiliar locations; a single source hammering many accounts is the easy detection.
- [ ] **Pick seasonal / org-themed candidates.** `Season+Year!`, company name variants, `Welcome1`. Validate the user list from phase 2 first so you only spray real accounts.
- [ ] **Prefer endpoints that reveal MFA state cleanly.** A successful password against an MFA-gated account returns an MFA-required response, which is still a confirmed credential. Note which accounts are password-valid but MFA-protected for later AiTM/consent targeting.
- [ ] **Avoid `BAV2ROPC` noise unless legacy auth is the objective.** ROPC sprays are loud and flagged; use the AADInternals / MSOLSpray-style interactive flows when stealth matters.

```
⚠️ Spraying can lock real users via on-prem AD lockout even when Entra Smart
Lockout protects the cloud side. Stay under the agreed threshold, exclude
break-glass accounts, and stop immediately if lockout events appear.
```

### Phishing-driven access
- [ ] **Device-code phishing.** Initiate a device-code flow for a first-party client (e.g. the Azure CLI / Office), send the short user-code to the target, and poll the token endpoint. A user who completes it (including MFA) hands you a refresh token. Time-boxed: the code expires in ~15 minutes.
- [ ] **Illicit OAuth app consent (consent phishing).** Register a multi-tenant app requesting Graph scopes (Mail.Read, Files.Read.All, offline_access) and lure the user to the consent screen. User consent on an unrestricted tenant yields a refresh token with the granted scopes without ever capturing a password. Test whether the tenant restricts user consent.
- [ ] **MFA fatigue / push bombing.** Where Authenticator push (non-number-matching) is in use, repeated prompts may yield an accidental approval. Number matching defeats this; record whether it is enforced.
- [ ] **AiTM token theft (Evilginx / EvilnoVNC).** Reverse-proxy the real Entra login to capture the post-MFA session cookie / token and replay it. This reuses what MFA already granted rather than bypassing it. Note that device-bound / token-protection CA and registered-device requirements break the replay.
- [ ] **Confirm what each token actually is.** Distinguish an access token (short-lived, scoped) from a refresh token (long-lived, re-mintable) from a PRT (device-bound, MFA-claim-bearing). The PRT is the highest-value artifact; see phase 7 for extraction.

### Token validation
- [ ] **Decode and triage every captured token.** Inspect `aud`, `scp`/`roles`, `tid`, `upn`/`appid`, and expiry. Confirm the audience matches your intended next step (Graph vs ARM vs Key Vault have different audiences).
- [ ] **Exchange refresh tokens for the audience you need.** Use roadtx or TokenSmith to mint Graph, ARM, or Key Vault tokens from a single captured refresh token before it expires.

---

## 4. Entra ID Enumeration

With one token, map the directory exhaustively before acting. Pull a full offline dataset, then mine it for paths. Command detail for each tool is in [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md).

### Bulk collection
- [ ] **Run roadrecon for a full offline mirror.** `roadrecon gather` dumps users, groups, roles, devices, service principals, applications, app role assignments, OAuth2 grants, and directory settings into a local SQLite DB; explore via the roadrecon web GUI. This is the backbone dataset.
- [ ] **Run AzureHound and ingest into BloodHound CE.** Collects Entra ID and Azure RM objects and computes abuse edges (AZAddSecret, AZAddOwner, AZGlobalAdmin, AZHasRole, AZRunAs, etc.). Use shortest-path queries to privileged nodes from your foothold.
- [ ] **Use GraphRunner for live Graph recon.** Modules enumerate users, groups, CA policies, app registrations, and search mail/SharePoint (pillage only if in scope).
- [ ] **Cross-check tool output.** roadrecon and AzureHound occasionally diverge on dynamic groups and app ownership; reconcile before trusting a path.

### Identity and role mapping
- [ ] **Enumerate all users and high-value attributes.** Flag `onPremisesSyncEnabled` (hybrid), admin UPNs, accounts without MFA registered, and stale/guest accounts.
- [ ] **Enumerate directory roles and active assignments.** Map who holds Global Administrator, Privileged Role Administrator, Application Administrator, Cloud Application Administrator, Authentication Administrator, Privileged Authentication Administrator, User Administrator, and Groups Administrator. These are the escalation-relevant roles.
- [ ] **Enumerate PIM (Privileged Identity Management).** Distinguish eligible vs active assignments. Eligible roles that any compromised principal can self-activate (especially without approval or MFA gating) are live escalation paths, not theoretical ones.
- [ ] **Enumerate administrative units (AUs).** Scoped admins over an AU, and restricted-management AUs, change who can touch which users. Map AU-scoped role holders.

### Groups, apps, and service principals
- [ ] **Enumerate groups, ownership, and membership type.** Record group owners (an owner can add members), security-enabled groups tied to role or resource assignments, and which groups gate CA policies.
- [ ] **Enumerate dynamic groups and their membership rules.** Read each `membershipRule`. Rules keyed on user-settable attributes (`userPrincipalName`, `mail`, `displayName`, `otherMails`, department) are injectable: if you can set that attribute on a principal you control, you can force it into the group. Flag any dynamic group that grants roles or resource access.
- [ ] **Enumerate app registrations and their owners.** App owners can add credentials. Note apps with high Graph application permissions (`RoleManagement.ReadWrite.Directory`, `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`, `Directory.ReadWrite.All`).
- [ ] **Enumerate service principals and their roles / API permissions.** Map every SP that holds a privileged directory role or dangerous Graph app role. An SP you can authenticate as (via secret/cert) inherits all of it.
- [ ] **Map app-to-SP credential surface.** For each in-scope app, note existing secrets/certs and whether your principal owns the app or the SP. This feeds the credential-abuse path in phase 5.
- [ ] **Read Conditional Access policies (if visible).** Enumerate via Graph where permitted. Map which apps, users, locations, and platforms are gated, and look for exclusions (named locations, excluded groups, report-only policies) you can land in.

---

## 5. Privilege Escalation

Walk the graph from your foothold to Global Admin or a tenant-controlling app. The dominant Entra escalation primitive is "add a credential to a privileged app/SP, then auth as it." Validate each step against real tenant state, not just the edge label.

### Application and service principal credential abuse
- [ ] **Owner-of-app to credential injection.** If your principal owns an app registration, add a new client secret or certificate, then authenticate as the app's service principal. You now hold every Graph app permission and directory role that SP has. This is the canonical Entra privesc.
  ```bash
  # conceptual: add secret to owned app, then client-credentials auth as its SP
  az ad app credential reset --id <appId>
  ```
- [ ] **Privileged SP takeover to tenant takeover.** If a reachable SP holds `RoleManagement.ReadWrite.Directory` or `AppRoleAssignment.ReadWrite.All`, use it to grant your account a privileged directory role or grant an owned app Global-Admin-equivalent app roles. Confirm the SP's permissions are admin-consented (active), not just requested.
- [ ] **Application Administrator / Cloud Application Administrator abuse.** These roles let you add credentials to *any* app/SP in the tenant. Target an SP that already holds a high-privilege Graph role, add a secret, and inherit it. This is privesc even though the role itself looks limited.
- [ ] **Account takeover via app secrets.** Hunt for plaintext app secrets / certs in code repos, pipeline variables, automation accounts, app settings, and Key Vault. A leaked SP credential is direct access at that SP's privilege.

### Role, group, and Graph abuse
- [ ] **Authentication / Privileged Authentication Administrator abuse.** These roles can reset credentials and manage MFA for users (Privileged Auth Admin covers admins too). Reset a higher-priv account's auth methods and take it over.
- [ ] **User Administrator / Groups Administrator pivots.** Reset passwords for non-admins, or add yourself to a security group that gates a role or resource.
- [ ] **Dynamic group injection.** For an injectable dynamic group found in phase 4, set the triggering attribute on a controlled user/SP (where you have the permission to write it) and let membership recalculation pull you in, inheriting whatever the group grants.
- [ ] **Group-owner self-add.** If you own a role-assignable or resource-gating group, add your principal as a member.
- [ ] **PIM self-activation.** Activate any eligible privileged role you hold, then act within the activation window. Note whether activation required approval or MFA (a gap if not).
- [ ] **Graph API direct abuse.** Where you hold the scopes, perform role assignment, app-role grant, or credential add directly against Graph rather than through the portal, which is both faster and quieter.
- [ ] **Validate every claimed path live.** Before reporting, actually mint the SP token / activate the role / trigger the membership change in a controlled way. BloodHound edges over-claim (e.g. AZAddSecret to managed identities); confirm the primitive really fires.

---

## 6. Azure Resource Manager

Pivot from identity into subscriptions. ARM RBAC is separate from Entra roles; a low Entra user can hold Owner on a subscription, and vice versa. Managed identities are the connective tissue between compute and the directory.

### RBAC and roles
- [ ] **Enumerate role assignments at every scope.** Management group, subscription, resource group, and resource. Map who holds Owner, Contributor, User Access Administrator (UAA), and Key Vault Administrator. UAA can grant itself any role, so it is effectively Owner.
- [ ] **Hunt custom roles with dangerous actions.** Look for custom role definitions containing wildcard `*` actions, `Microsoft.Authorization/*/write` (assign roles), `Microsoft.Compute/virtualMachines/runCommand/action`, or `.../extensions/write`. These grant code execution or self-escalation despite an innocuous name.
- [ ] **Identify role-assignment write paths.** Any principal with `Microsoft.Authorization/roleAssignments/write` can escalate to Owner. Flag it.

### Managed identities and IMDS
- [ ] **Enumerate managed identities (system- and user-assigned) and their roles.** A VM, Function, Automation Account, Logic App, or App Service with a broadly-scoped MI (Contributor/Owner/Key Vault Admin) is a privesc and lateral hub.
- [ ] **Steal MI tokens from IMDS once you have code execution.** From inside a VM/Function with an attached identity, request a token from the metadata endpoint and exchange it for ARM, Graph, or Key Vault audiences.
  ```bash
  curl -s -H Metadata:true \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
  ```
- [ ] **Reach IMDS via SSRF.** Any SSRF in an Azure-hosted app (App Service, Function, AKS pod) that reaches `169.254.169.254` (or the AKS/Arc variants) leaks an MI token without code execution. Test app-layer SSRF against the metadata endpoint.
- [ ] **Chain identities.** Compromising a low-value resource whose MI has rights over higher-value resources is the standard Azure lateral chain; follow the MI's role assignments.

### Compute, automation, and secrets
- [ ] **Run commands on VMs you can reach.** `Microsoft.Compute/virtualMachines/runCommand/action` or VM extensions execute as SYSTEM/root without RDP/SSH. Use to retrieve the MI token or pillage the host.
- [ ] **Abuse Automation Accounts and runbooks.** A user with runbook author/run rights on an Automation Account whose Run-As / MI holds subscription Contributor can execute arbitrary code at that privilege. Enumerate runbooks, hybrid worker groups, and stored automation credentials/connections.
- [ ] **Loot Key Vault.** With Key Vault Administrator/Secrets User (RBAC) or a permissive access policy, dump secrets, keys, and certs. MI-attached compute frequently has a vault token a metadata request away. Check both the RBAC and legacy access-policy authorization models.
- [ ] **Steal storage account keys.** `listKeys` on a storage account yields full-control keys that bypass Entra RBAC and SAS scoping. Enumerate accounts, pull keys, and access blobs/files/tables/queues directly.
- [ ] **Sweep resource configs for secrets.** App Service / Function application settings, deployment slots, ARM template parameters, and tags routinely hold connection strings and SP credentials.

---

## 7. Lateral and Hybrid

Where Entra Connect / cloud sync joins on-prem AD to the tenant, identity flows both directions. The sync server and the sync account are tenant-tier assets. On-prem AD methodology is in [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md) and [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md).

### Entra Connect / cloud sync server
- [ ] **Locate the sync server and assess its tier.** The Entra Connect (or cloud sync agent) host is effectively a Tier-0 asset: compromise of it leads to tenant compromise. Confirm whether it is treated as such.
- [ ] **Extract sync credentials with AADInternals.** On a compromised sync server, dump the configuration to recover the on-prem `ADSync`/`MSOL_` service account password and the Entra connector (sync) account credential. The MSOL account holds DCSync rights on-prem; the connector account is high-priv in the tenant.
- [ ] **Determine the sign-in method: PHS, PTA, or federation.** Each has a distinct abuse path; AADInternals recon-as-outsider and the sync config both reveal it.

### PHS, PTA, and Seamless SSO
- [ ] **PHS abuse.** With the sync account, you can read/inject synced hashes and (per AADInternals) set passwords or seed accounts in the tenant. Compromise of PHS sync gives broad credential reach across both directories.
- [ ] **PTA agent abuse.** Compromise a PTA agent, extract its certificate, and stand up a rogue agent to intercept and log every plaintext credential validated through it, or to validate arbitrary passwords (auth bypass). Test for rogue-agent registration.
- [ ] **Seamless SSO silver ticket (AZUREADSSOACC$).** The `AZUREADSSOACC$` computer account's password never rotates. With its NTLM hash / AES key (obtained via DCSync once on-prem is owned), forge a Kerberos silver ticket for any UPN, including a Global Admin, and exchange it for an Entra token. This bypasses MFA because the ticket replaces the password.
  ```bash
  # conceptual flow: DCSync AZUREADSSOACC$ -> forge ST for target UPN -> redeem for Entra token
  ```
- [ ] **Flag the non-rotating AZUREADSSOACC$ key as a standalone finding** wherever Seamless SSO is enabled; recommend periodic key rollover.

### Bidirectional movement
- [ ] **On-prem to cloud.** Domain compromise plus Seamless SSO or a stolen sync/connector credential yields tenant access. Map this path explicitly where hybrid is present.
- [ ] **Cloud to on-prem.** From the tenant, reach the sync server (it authenticates outbound), abuse Intune/management to push scripts to managed endpoints, or use hybrid-joined device PRTs. An MI or admin that can run commands on the sync host bridges back to AD.
- [ ] **PRT extraction and replay.** On a hybrid/Entra-joined Windows host you control, extract the PRT (and its session key / derived keys) and replay it to obtain tokens carrying the device and MFA claims, satisfying device-bound CA. Treat the PRT as the crown-jewel artifact.
- [ ] **Cross-tenant access settings.** Where B2B/B2C or cross-tenant sync is configured, review inbound trust (accepted MFA/device claims from partner tenants) and any cross-tenant sync configuration that could provision attacker-controlled identities. See Recent Techniques for cross-tenant sync abuse.

---

## 8. Persistence

Establish durable, stealthy access for the engagement, then document every artifact for clean teardown. Entra persistence frequently survives password resets and MFA re-registration.

### Identity and credential persistence
- [ ] **Add a secret/cert to a service principal.** A second credential on a privileged SP is a quiet long-lived backdoor that survives the owning user's password reset. Record the SP and credential ID.
- [ ] **Grant an owned multi-tenant app standing Graph permissions.** Admin-consented app roles (e.g. `Directory.ReadWrite.All`, `Mail.Read`) on an attacker-controlled app persist independent of any user and ignore user-MFA.
- [ ] **Register a backdoor authentication method.** Add a TAP, FIDO key, or authenticator app to a target/admin account where you hold the auth-admin right, giving a re-entry path that survives password reset.
- [ ] **Register or hijack a device.** A rogue registered/joined device can obtain a PRT and satisfy device-compliance CA; useful for durable token issuance.

### Federation and policy persistence
- [ ] **Federated trust backdoor (Golden SAML / token-signing).** Add a malicious federated domain or trusted token-signing certificate (AADInternals `ConvertTo-AADIntBackdoor` / `Set-AADIntDomainFederationSettings`) so you can forge SAML tokens for any user as that domain. Extremely high-impact: flag and remove carefully.
- [ ] **Conditional Access policy tampering.** Where you hold the rights, weaken or exclude on a CA policy (add an excluded group/location, flip a policy to report-only) to create a stealth bypass lane. Document the exact before/after policy state.
- [ ] **Stealthy role / AU placement.** Hide privilege in an administrative unit or a nested group rather than a direct Global Admin grant, which is the obvious thing defenders check.

```
⚠️ Federation backdoors, CA edits, and standing app grants are tenant-wide and
high-impact. Create the minimum needed to prove the path, log every object
(IDs + timestamps), and remove all of it at teardown. Never leave a forged
token-signing cert or modified CA policy in place.
```

---

## Recent Techniques (2024-2026)

- [ ] **CVE-2025-55241 (Actor token cross-tenant impersonation, CVSS 10.0).** Unsigned ACS "actor" tokens plus a tenant-validation bug in the legacy Azure AD Graph (`graph.windows.net`) let an attacker impersonate any user, including Global Admin, in any tenant, bypassing Conditional Access with no logs. Patched July 2025. Test for: any remaining reliance on / reachability of the deprecated Azure AD Graph API; confirm migration to Microsoft Graph.
- [ ] **CVE-2025-29827 (Azure Automation privesc, CVSS ~9.9).** Misconfigured role assignments and REST calls bypassing access restrictions in Azure Automation. Test for: runbook author/run rights on Automation Accounts whose identity holds subscription Contributor/Owner.
- [ ] **Storm-0558-style token forgery.** Stolen/leaked signing key plus weak consumer-vs-enterprise key validation enabled forged Entra tokens for Exchange Online. Test for: signing-key hygiene, audience/issuer validation on any custom token-consuming app.
- [ ] **Midnight Blizzard (APT29) OAuth app abuse pattern.** Password spray into a legacy test tenant, then pivot through an over-permissioned OAuth app to create more malicious apps and escalate. Test for: dormant/legacy tenants, over-privileged multi-tenant apps, unrestricted user consent.
- [ ] **Cross-tenant sync (CTS) abuse.** A compromised tenant with inbound cross-tenant sync configured can provision attacker-controlled external identities directly into the target tenant as a stealth persistence/lateral path. Test for: enabled inbound CTS, lax cross-tenant access policies, accepted partner MFA/device claims.
- [ ] **PRT theft via infostealers (Lumma/RedLine).** Malware extracts PRTs from LSASS/browser memory for replay; reuses the MFA claim rather than bypassing it. Test for: token-protection CA, device-bound sessions, and whether PRT replay from an unmanaged device is blocked.
- [ ] **AiTM phishing kits (Evilginx / EvilnoVNC) with session/token replay.** Proxy the real login to capture post-MFA cookies/tokens. Test for: phishing-resistant MFA (FIDO2/passkey/WHfB), device-registration requirements, and CAE/attack-disruption coverage.
- [ ] **Device-code phishing of first-party clients.** Still highly effective; yields refresh tokens with MFA satisfied. Test for: CA policies that restrict the device-code flow and per-app authentication-flow controls.
- [ ] **Dynamic group membership injection.** Self-settable attributes (UPN, mail, otherMails, department) in `membershipRule`s let a controlled principal force itself into role- or resource-granting groups. Test every dynamic group rule against attacker-writable attributes.
- [ ] **Modern tooling baseline.** ROADtools (`roadrecon`, `roadtx`), AADInternals, AzureHound/BloodHound CE Azure edges, GraphRunner, and TokenSmith (Entra access/refresh-token minting that drops straight into Azure post-ex tools). roadrecon's Graph-API rewrite is partial/forked as of 2025; verify collector coverage against the current tenant.
- [ ] **AzureHound seen in real intrusions.** Void Blizzard / Russia-affiliated actors observed using AzureHound for tenant mapping (2025); expect detection content tuned to it, so pace collection accordingly.

---

## Reporting and Evidence

- [ ] **Capture per finding:** the exact identity/token used (principal, appId, audience, scopes), the API call or tool command, the request/response or screenshot, and the resulting state change (role added, secret created, secret read). Save raw request:response pairs at test time, not after.
- [ ] **Record every object you created** (apps, SPs, secrets, devices, group memberships, CA edits, federation changes) with ID and timestamp in a teardown log. This is both a deliverable and your cleanup checklist.
- [ ] **Map findings to a clear privilege graph.** Show the path from starting principal to objective (e.g. low-priv user to App Admin to privileged SP to Global Admin). A BloodHound path screenshot plus a step list reads better than prose.
- [ ] **Severity guidance.** Tenant takeover (Global Admin, federation backdoor, sync-server/connector compromise, CVE-2025-55241-class) = Critical. Privileged-role escalation, broad MI/Key Vault loot, storage-key theft = High. Single-user takeover, scoped data read, info disclosure = Medium. Posture gaps (no number matching, legacy auth enabled, non-rotating AZUREADSSOACC$) = Medium/Low depending on exploitability.
- [ ] **Rule out common false positives.** A BloodHound edge is not a confirmed path: AZAddSecret to managed identities is known to over-report, "requested" Graph permissions are inert until admin-consented, eligible PIM roles may require approval/MFA, and report-only CA policies do not enforce. Confirm the primitive fires before rating it.
- [ ] **Distinguish bypassed-CA from absent-CA.** Note whether you defeated a control or whether it was never configured; the remediation differs.

---

## Tools and References

| Tool | Use |
| --- | --- |
| ROADtools (`roadrecon`, `roadlib`) | Full offline Entra dataset + web GUI exploration |
| ROADtools `roadtx` | Token exchange, refresh-token reuse, device registration, PRT workflows |
| AADInternals | Outsider recon, federation backdoor, sync-credential extraction, PTA/Seamless SSO abuse |
| AzureHound + BloodHound CE | Entra + Azure RM edge collection and attack-path queries |
| GraphRunner | Live Graph recon, persistence, and (in-scope) data pillage |
| TokenSmith | Entra access/refresh-token generation for post-ex tooling |
| MSOLSpray / o365spray style | Lockout-aware password spray and user validation |
| Azure CLI / `az`, Microsoft Graph PowerShell | Native enumeration and resource interaction |

References:
- Microsoft Entra and Azure security documentation (Learn): PRT, token protection, Conditional Access, managed identities, Smart Lockout.
- MITRE ATT&CK cloud (Azure AD / Office 365) matrix.
- HackTricks Cloud (Azure), Internal All The Things (Azure AD), AzureAD-Attack-Defense (Cloud-Architekt).
- dirkjanm research (ROADtools, actor-token CVE-2025-55241), JUMPSEC TokenSmith, SpecterOps BloodHound Azure docs.

---

## Related

- Playbooks: [Azure AiTM Token Theft to Global Admin](../Playbooks/Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md), [Device Code Phishing to M365 Takeover](../Playbooks/Device%20Code%20Phishing%20to%20M365%20Takeover.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
- [Phishing and Initial Access](../Cheatsheets/Phishing%20and%20Initial%20Access.md)
- [Internal Network and Active Directory](Internal%20Network%20and%20Active%20Directory.md)
- [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- [AWS Pentest](../Cheatsheets/AWS%20Pentest.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- Ariadne

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
