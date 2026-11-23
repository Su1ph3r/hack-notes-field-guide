---
tags:
  - hack-notes
  - checklist
  - cloud
  - gcp
---

# GCP Cloud Penetration Test Testing Checklist

> Phased methodology for an authorized Google Cloud Platform engagement: org/folder/project hierarchy, IAM and service-account abuse, compute metadata, storage and data stores, the canonical GCP privesc primitives, lateral movement, and bounded persistence. Methodology lives here; long commands live in the cheatsheets linked at the bottom.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Recon and Asset Discovery](#2-recon-and-asset-discovery)
- [3. Identity and IAM](#3-identity-and-iam)
- [4. Compute and Metadata](#4-compute-and-metadata)
- [5. Storage and Data](#5-storage-and-data)
- [6. Privilege Escalation](#6-privilege-escalation)
- [7. Lateral Movement and Pivot](#7-lateral-movement-and-pivot)
- [8. Persistence and Impact within RoE](#8-persistence-and-impact-within-roe)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

### Authorization and boundaries
- [ ] **Confirm the resource-hierarchy scope in writing:** which Organization, which Folders, which Projects, and whether the org node itself is in scope. A project ID in scope does not authorize testing its sibling or parent. Get the exact `organizations/<id>`, `folders/<id>`, and `projects/<id>` list.
- [ ] **Identify the billing account(s)** tied to in-scope projects so spend-impacting actions (new instances, egress) are pre-approved.
- [ ] **Clarify Google Workspace / Cloud Identity scope:** GCP IAM often chains into Workspace (super-admin, domain-wide delegation). Confirm whether the directory, groups, and admin console are in or out of scope.
- [ ] **Out-of-scope inventory:** production data stores, customer PII, shared-VPC host projects owned by another team, third-party SaaS reachable from the environment. Record explicitly.

### Access model
- [ ] **Define the starting position:** unauthenticated external, leaked service-account key, low-priv user principal, or assumed-breach inside a GCE/GKE workload. Each has a different first move.
- [ ] **Enumerate the credentials provided:** user accounts (`gcloud auth login`), service-account JSON keys, OAuth tokens, or Workload Identity config. Record principal email and intended role for each.
- [ ] **Read-only vs. mutate:** confirm whether IAM-policy changes, key creation, instance creation, and deployment actions are permitted, or whether the test is enumeration-only. Many GCP privesc proofs require a mutation (set IAM policy, create key, deploy function); get sign-off before triggering them.
- [ ] **Establish a dedicated tester principal** where possible, so audit logs cleanly attribute test activity and cleanup is scoped to one identity.

### Production safety and detection awareness
- [ ] **Production-safety rules of engagement:** no destructive deletes, no IAM removal of legitimate principals, no key deletion, no data exfiltration of real PII. Mark which projects are prod vs. non-prod.
- [ ] **Audit-log awareness:** Cloud Audit Logs (Admin Activity is always-on and immutable; Data Access is opt-in) will record your actions. Decide with the client whether the blue team is informed (announced) or this doubles as detection testing (unannounced). Note that minting tokens via `getAccessToken`/`signJwt` does NOT create a key-creation log, which matters for stealth tests.
- [ ] **Confirm a rollback and cleanup plan:** every created key, binding, instance, function, and bucket object gets logged for teardown. Agree on a maintenance window for any high-blast-radius step.
- [ ] **Emergency contact and abort signal** agreed for both sides.

```
⚠️ GCP actions are fast and global. resourcemanager.projects.setIamPolicy is a full
overwrite of the policy, not a merge: a naive setIamPolicy with getIamPolicy output
can strip existing bindings and lock out legitimate users. Always read-modify-write
with the current etag, and never run policy mutations on prod without sign-off.
```

---

## 2. Recon and Asset Discovery

> External and OSINT-first discovery before touching authenticated APIs. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md) for the general key-hunting and subdomain workflow.

### Public and external surface
- [ ] **Enumerate public GCS buckets** by permuting org/product names. Bucket namespace is global, so guessable names leak across orgs.
  ```bash
  python3 gcpbucketbrute.py -k <company-keyword> -u   # -u = unauthenticated check
  gsutil ls -r gs://<bucket>/                          # if listable
  ```
- [ ] **Test bucket ACL/IAM for `allUsers` and `allAuthenticatedUsers`** (anyone with any Google login). Public read, public write, and public ACL-read are distinct findings; check all three.
- [ ] **Map public IPs and exposed services:** enumerate external IPs of GCE instances, GKE LoadBalancers, Cloud Run / Cloud Functions URLs, and App Engine endpoints. GCP egress ranges are published; correlate via certificate transparency and passive DNS.
- [ ] **Cloud Run / Cloud Functions endpoints:** check for `--allow-unauthenticated` services. A `*.run.app` or `cloudfunctions.net` URL reachable without an ID token is an unauthenticated entry point.
- [ ] **Firewall exposure:** look for `0.0.0.0/0` ingress on SSH (22), RDP (3389), databases (3306/5432/27017/6379), and Kubernetes API (6443/443).

### Credential and key leakage (OSINT)
- [ ] **Hunt for leaked service-account keys** in public GitHub/GitLab, Docker images, paste sites, S3/GCS, and CI artifacts. The JSON shape is unmistakable: `"type": "service_account"`, `"private_key"`, `"client_email"`.
  ```bash
  # GitHub dork patterns
  "private_key" "service_account" "client_email" extension:json
  ```
- [ ] **Scan accessible repos and artifacts** with truffleHog / gitleaks for `AIza...` API keys, OAuth client secrets, and `gcloud` refresh tokens in `~/.config/gcloud/`.
- [ ] **Test discovered API keys for scope:** GCP API keys (`AIza...`) are often unrestricted. Probe Maps, Cloud APIs, and check for missing application/IP restriction.
- [ ] **Check container images** (Artifact Registry, Docker Hub, GCR) for baked-in keys, `.boto`, and `application_default_credentials.json`.
- [ ] **DNS and Workspace OSINT:** confirm the org's Google domain, look for `_gcp` / `googlehosted` records, and enumerate user email format for later Workspace pivoting.

### Validate found credentials
- [ ] **Identify the principal** of any obtained credential before doing anything else:
  ```bash
  gcloud auth activate-service-account --key-file=key.json
  gcloud config list account
  gcloud auth list
  ```
- [ ] **Resolve which projects the principal can see:** `gcloud projects list` and `gcloud organizations list`. An empty list does not mean no access; the principal may have project-scoped grants without `resourcemanager.projects.list`.

---

## 3. Identity and IAM

> IAM is the GCP attack surface. The goal is to map every principal, every binding, and every reachable privilege-escalation edge.

### Enumerate principals and policy
- [ ] **Pull IAM policy at every hierarchy level you can read:** org, folder, project. Bindings inherit downward, so an org-level grant applies to all children.
  ```bash
  gcloud projects get-iam-policy <project> --format=json
  gcloud organizations get-iam-policy <org-id> --format=json
  gcloud resource-manager folders get-iam-policy <folder-id>
  ```
- [ ] **Enumerate your own effective permissions** with `testIamPermissions` rather than guessing from role names. Roles are opaque; permission tests are ground truth.
  ```bash
  gcloud projects test-iam-permissions <project> \
    --permissions=iam.serviceAccounts.actAs,iam.serviceAccounts.getAccessToken,resourcemanager.projects.setIamPolicy
  ```
- [ ] **Run an automated IAM enumeration pass** (gcp_scanner, ScoutSuite, or Prowler) to dump bindings, custom roles, and flag known privesc permissions across all reachable projects.
- [ ] **Catalog custom roles** (`gcloud iam roles list --project=<p>`). Custom roles frequently bundle a dangerous permission (`setIamPolicy`, `actAs`) into an innocuous-sounding role.

### Service accounts
- [ ] **List all service accounts** and note default ones: `<project-number>-compute@developer.gserviceaccount.com` (Compute Engine default), `<project-id>@appspot.gserviceaccount.com` (App Engine), and the Cloud Build SA `<project-number>@cloudbuild.gserviceaccount.com`. Defaults are over-permissioned (often Editor).
  ```bash
  gcloud iam service-accounts list
  ```
- [ ] **For each SA, read who can act on it** (`get-iam-policy` on the SA resource). A user with `roles/iam.serviceAccountUser` or `serviceAccountTokenCreator` on a high-priv SA is a privesc edge.
- [ ] **Enumerate existing user-managed keys** per SA (`gcloud iam service-accounts keys list`). Long-lived keys are persistence and exfil risk.
- [ ] **Map SA-to-resource attachment:** which SA is attached to which GCE instance, function, Cloud Run service, or GKE node pool. The attachment is what makes `actAs` exploitable.

### Roles, bindings, and policy hygiene
- [ ] **Flag primitive roles** (`roles/owner`, `roles/editor`, `roles/viewer`) granted to users, groups, or SAs. Editor alone enables multiple privesc paths.
- [ ] **Flag dangerous bindings to broad principals:** `allAuthenticatedUsers`, `allUsers`, entire Google groups, or `domain:` grants on sensitive resources.
- [ ] **Check IAM Conditions** on bindings; a misconfigured condition (e.g. wrong resource-name prefix) may be ineffective and grant more than intended.

### Organization policies and guardrails
- [ ] **Read org policy constraints** (`gcloud org-policies list`). Check whether key guardrails are enforced: `iam.disableServiceAccountKeyCreation`, `iam.allowedPolicyMemberDomains` (domain restriction), `compute.requireOsLogin`, `storage.publicAccessPrevention`, `iam.automaticIamGrantsForDefaultServiceAccounts`.
- [ ] **A missing or unenforced org policy is itself a finding** and usually the precondition that makes a downstream attack possible (e.g. key creation allowed, public buckets allowed).

### Workload Identity Federation and OAuth
- [ ] **Enumerate Workload Identity Pools and providers** (`gcloud iam workload-identity-pools list` / `... providers list`). WIF lets external identities (GitHub Actions, AWS, OIDC) impersonate GCP service accounts without a key.
- [ ] **Inspect the provider attribute mapping and condition (`attribute-condition`).** An overly broad mapping (e.g. accepting any GitHub repo, or `assertion.sub` not pinned) lets an attacker who controls a matching external token impersonate the bound SA. This is a top WIF misconfiguration.
- [ ] **Check which SAs each pool can impersonate** (`roles/iam.workloadIdentityUser` bindings) and whether the trust condition is scoped to a specific repo/branch/subject.
- [ ] **Review OAuth scopes** on user tokens and SAs. Broad scopes (`https://www.googleapis.com/auth/cloud-platform`) on an instance grant full API reach regardless of IAM nuance; narrower scopes constrain a stolen token.
- [ ] **Domain-wide delegation:** check for SAs with DWD enabled in the Workspace admin console. A DWD SA can impersonate any Workspace user (Gmail, Drive, Directory), a full org compromise primitive if its key is obtained.

---

## 4. Compute and Metadata

> Assumed-breach on a workload is the most common pivot. The metadata server is the prize.

### Metadata server (GCE / the SSRF target)
- [ ] **Query the metadata server for tokens** from any code-exec position on an instance. No auth required; the `Metadata-Flavor: Google` header is the only gate.
  ```bash
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/scopes"
  ```
- [ ] **Pull the full recursive metadata tree** for SSH keys, startup/shutdown scripts, project attributes, and the email of the attached SA:
  ```bash
  curl -s -H "Metadata-Flavor: Google" \
    "http://169.254.169.254/computeMetadata/v1/?recursive=true&alt=json"
  ```
- [ ] **Test app-layer SSRF against the metadata IP.** Any server-side fetch primitive in a hosted app (URL preview, webhook, PDF render, image proxy) that reaches `169.254.169.254` with a settable header yields the SA token. The required `Metadata-Flavor: Google` header raises the bar vs. AWS IMDSv1, but header-injection or proxy SSRF still works.
- [ ] **Check for legacy metadata endpoints** (`/0.1/meta-data/`, `/computeMetadata/v1beta1/`) that historically did not require the custom header. Legacy endpoints disabled is the expected hardened state.
- [ ] **Take the token to the API:** set it as a bearer and enumerate what the SA can do (`gcloud` with `CLOUDSDK_AUTH_ACCESS_TOKEN`, or raw REST). Scope first (step above): a token scoped only to `storage.read` cannot mutate IAM even if the SA's role would allow it.

### Default service account and scopes
- [ ] **Determine the attached SA and access scopes.** The classic high-impact misconfig is the Compute default SA (Editor) attached with the `cloud-platform` scope. That combination is near-Owner from inside the box.
- [ ] **Confirm OS Login vs. metadata SSH keys.** OS Login disabled plus project-level SSH keys in metadata means anyone who can write instance/project metadata can add an SSH key and log in.

### Startup scripts and instance config
- [ ] **Read startup/shutdown scripts** from metadata for hardcoded secrets, internal hostnames, and bootstrap credentials.
- [ ] **Check `compute.instances.setMetadata` / `project.setCommonInstanceMetadata`.** Write access to metadata equals code execution: set a startup script or add an SSH key, then the next boot (or immediate, for SSH) runs as the instance SA. See [6. Privilege Escalation](#6-privilege-escalation).
- [ ] **Check serial-port access** (`compute.instances.getSerialPortOutput`) for leaked boot-time secrets.

### Cloud Functions and Cloud Run
- [ ] **Enumerate functions and their runtime SAs** (`gcloud functions list`, `gcloud run services list`). The runtime SA defines blast radius if you achieve code-exec inside the function.
- [ ] **Test `--allow-unauthenticated` invocation** and look for injection in the function body that reaches the metadata server (same SSRF-to-token path as GCE; functions and Cloud Run also expose `169.254.169.254`).
- [ ] **Deploy/update permission as privesc:** `cloudfunctions.functions.create`/`.update` (or Cloud Run deploy) lets you ship code that runs as the function's SA. With `actAs` on a higher-priv SA, you pick the runtime identity. See ConfusedFunction in [Recent Techniques (2024-2026)](#recent-techniques-2024-2026).
- [ ] **Inspect environment variables and mounted secrets** on functions/Run services for plaintext credentials.

### GKE (cluster, node, workload)
- [ ] **Enumerate clusters and node pools** (`gcloud container clusters list`; then `get-credentials` if you have the permission). Note the node-pool SA and its scopes.
- [ ] **From inside a pod, reach the node metadata server.** If Workload Identity is NOT enabled, pods inherit the node SA's permissions straight from `169.254.169.254`. This is the dominant GKE escalation.
- [ ] **If Workload Identity IS enabled,** the GKE metadata server (gke-metadata-server DaemonSet) filters requests; confirm whether a NetworkPolicy actually blocks `169.254.169.254` or whether the legacy metadata endpoints / `kube-env` are still reachable.
- [ ] **Check `system:authenticated` and `system:anonymous` RBAC bindings** on the cluster. Over-broad bindings to `system:authenticated` let any authenticated Google identity hit the API. (See [Kubernetes and Containers](Kubernetes%20and%20Containers.md) for cluster-internal RBAC and breakout depth.)
- [ ] **Pull `kube-env` from metadata** if reachable; it has historically leaked the kubelet bootstrap credential, enabling node-level escalation.
- [ ] **Map the GKE-to-node-to-cloud chain:** pod escape to node, node SA token from metadata, then GCP API. See [7. Lateral Movement and Pivot](#7-lateral-movement-and-pivot).

---

## 5. Storage and Data

### Cloud Storage (GCS)
- [ ] **List all buckets and per-bucket IAM/ACL** (`gsutil ls`, `gsutil iam get gs://<b>`, `gsutil acl get`). Check for `allUsers`/`allAuthenticatedUsers` at bucket and object granularity.
- [ ] **Verify `publicAccessPrevention` and uniform bucket-level access.** Legacy fine-grained ACLs are where public objects hide even when bucket IAM looks clean.
- [ ] **Test write/delete** where in scope: public-write buckets allow tampering and supply-chain poisoning if the bucket feeds a build or website.
- [ ] **Check for sensitive data**: backups, `.sql` dumps, Terraform state (`*.tfstate` leaks secrets), `.env`, key material, and logs.
- [ ] **Inspect signed-URL usage and HMAC keys** (`gsutil hmac list`); leaked HMAC keys grant S3-compatible access.

### BigQuery
- [ ] **Enumerate datasets and their ACLs** (`bq ls`, `bq show --format=prettyjson <dataset>`). Datasets shared with `allAuthenticatedUsers` or broad groups leak analytics data.
- [ ] **Check authorized views and routines** for permission bypass: an authorized view can expose rows of a table the caller cannot read directly.
- [ ] **Look for PII/regulated data** and stored credentials inside tables; query with care and minimize rows pulled.

### Cloud SQL
- [ ] **Enumerate instances** (`gcloud sql instances list`) and check `authorizedNetworks` for `0.0.0.0/0`, public IP exposure, and SSL-not-required.
- [ ] **Check IAM database authentication** and default/weak DB users. Test reachability from a compromised workload via the Cloud SQL Auth Proxy or direct connection.
- [ ] **Look for `cloudsql.instances.update`/`.connect`** in your grants; update can change root password or networking.

### Secret Manager and KMS
- [ ] **List and read secrets** you can access (`gcloud secrets list`, `gcloud secrets versions access latest --secret=<n>`). Catalog which principals/SAs hold `secretmanager.versions.access`.
- [ ] **Check KMS keys and IAM** (`gcloud kms keys list ...`). `cloudkms.cryptoKeyVersions.useToDecrypt` on a key protecting other secrets/data is a high-value grant; broad `roles/cloudkms.cryptoKeyEncrypterDecrypter` to many principals is a finding.
- [ ] **Look for secrets-in-the-clear** in function env vars, instance metadata, build configs, and Cloud Logging that should have been in Secret Manager.

---

## 6. Privilege Escalation

> The canonical GCP privesc primitives. Most reduce to: obtain a token for, or run code as, a more-privileged service account. Confirm the permission with `testIamPermissions` before attempting, and get mutation sign-off (Phase 1).

### Token-minting and impersonation primitives
- [ ] **`iam.serviceAccounts.getAccessToken`** on a higher-priv SA: mint a short-lived OAuth token directly, no key, no key-creation log.
  ```bash
  gcloud auth print-access-token \
    --impersonate-service-account=<target-sa>@<proj>.iam.gserviceaccount.com
  ```
- [ ] **`iam.serviceAccounts.getOpenIdToken` / `signJwt` / `signBlob`:** forge identity tokens or sign a JWT as the target SA, then exchange for an access token (OAuth assertion flow). Works even when `getAccessToken` is absent.
- [ ] **`iam.serviceAccounts.implicitDelegation`:** if SA-A has implicitDelegation over SA-B and SA-B has getAccessToken over SA-C, chain through to a token for SA-C.
- [ ] **`iam.serviceAccountKeys.create`:** create a persistent JSON key for any SA you have it on, then auth as that SA. Loud (key-creation log) but durable; also a persistence mechanism.

### actAs-based primitives (run code as a target SA)
- [ ] **`iam.serviceAccounts.actAs` + a deploy permission** is the core pattern. With `actAs` on a high-priv SA you attach it to a resource you create, and your code runs as it:
  - [ ] **Cloud Function deploy** (`cloudfunctions.functions.create` + actAs): deploy a function with the target SA as runtime identity; function body mints/uses the token.
  - [ ] **Cloud Run / App Engine deploy** with the target SA.
  - [ ] **GCE instance create** (`compute.instances.create` + actAs + `compute.instances.setMetadata`): launch an instance running as the SA, add a startup script that exfils the metadata token.
  - [ ] **Cloud Build** (`cloudbuild.builds.create`): submit a build that runs as the Cloud Build SA (often Editor); the build step curls the metadata token. (RCE-to-IAM, per Rhino Security Labs.)
  - [ ] **Deployment Manager** (`deploymentmanager.deployments.create`): deployments run as the Google APIs SA / Editor-level identity; craft a deployment that sets IAM policy or creates resources you otherwise cannot.

### Policy and role manipulation
- [ ] **`resourcemanager.projects.setIamPolicy`** (or folder/org equivalent): grant yourself Owner. Highest-impact single permission. Read-modify-write with etag; never blind-overwrite.
- [ ] **`iam.roles.update`** on a custom role you are granted: add a powerful permission to a role you already hold.
- [ ] **`iam.serviceAccounts.setIamPolicy`:** grant yourself `serviceAccountTokenCreator`/`User` on a high-priv SA, then impersonate it.
- [ ] **Storage/compute setIamPolicy variants** (`storage.buckets.setIamPolicy`, `compute.*.setIamPolicy`) for resource-scoped escalation and data access.

### Compute and metadata escalation (from inside a box)
- [ ] **`compute.projects.setCommonInstanceMetadata`:** inject a project-wide SSH key or OS-Login-bypassing key, then SSH into instances as a privileged user.
- [ ] **`compute.instances.setMetadata` on a running instance:** set a startup script and trigger a reset to run code as that instance's (often default-Editor) SA.

### Run the privesc scanner
- [ ] **Automate the path-finding** with the Rhino Security Labs `GCP-IAM-Privilege-Escalation` scanner or gcp_scanner: feed enumerated permissions and let it flag which of the ~40 known methods you hold. Then hand-verify each candidate edge before reporting.

```
⚠️ setIamPolicy at org or folder level is the single highest blast-radius action in GCP.
A mistake can lock out the entire organization. Treat org/folder policy mutation as a
break-glass step: snapshot the current policy JSON first, use the etag, and require
explicit written approval and a rollback file before executing.
```

---

## 7. Lateral Movement and Pivot

### Service-account impersonation chains
- [ ] **Build the impersonation graph:** for every SA you can token or actAs, repeat enumeration as that identity. Chains are common: user to SA-A (getAccessToken) to SA-B (actAs via function deploy) to project Owner.
- [ ] **Re-enumerate at each hop** with `testIamPermissions`; a new identity sees new projects, buckets, and SAs. Track the chain explicitly for the report (who to whom, via which permission).

### Cross-project and cross-org movement
- [ ] **Find SAs granted roles in other projects.** An SA in project A holding a role in project B is a deliberate or accidental bridge; the token from A works against B's APIs.
- [ ] **Shared VPC and host projects:** a service project workload can reach the host project's network; check for network-path pivots into otherwise-isolated projects.
- [ ] **Folder/org-level bindings:** a binding inherited from a folder gives one identity reach across every project under that folder. Map the hierarchy to find the widest-reaching principal.

### GKE-to-node-to-cloud
- [ ] **Pod to node:** escape the container (hostPath mount, privileged pod, host PID/network) to land on the node. See [Kubernetes and Containers](Kubernetes%20and%20Containers.md).
- [ ] **Node to cloud:** from the node, pull the node SA token from `169.254.169.254` and pivot into the GCP API as that SA.
- [ ] **Cluster to other clusters/projects:** if the node SA has cross-project roles or `container.clusters.get` elsewhere, expand to additional clusters.

### Workspace pivot
- [ ] **GCP-to-Workspace via domain-wide delegation:** if you obtain a DWD-enabled SA key, impersonate a Workspace super-admin to read mail/Drive or manage the directory. Confirm this is in scope (Phase 1) before exercising.
- [ ] **Network pivoting** from a foothold instance into private subnets and internal services: see [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md) for tunneling tradecraft.

---

## 8. Persistence and Impact within RoE

> Demonstrate impact to the agreed depth, then stop. Log every artifact for teardown. Persistence steps are loud and durable; only run those explicitly authorized.

### Demonstrating persistence (authorized only)
- [ ] **Service-account key creation:** a created JSON key survives password/session resets and is the classic durable backdoor. Record the key ID for deletion.
- [ ] **Add an IAM binding** for a tester-controlled principal at project level (scoped, logged, reversible). Prefer a clearly-named test SA over a hidden grant.
- [ ] **Workload-Identity-Federation backdoor:** add a provider/binding trusting an external OIDC identity you control: persistence with no key in the environment and minimal logging. High-value to demonstrate, high cleanup priority.
- [ ] **Startup-script / metadata implant** on an instance, or a benign scheduled Cloud Function / Cloud Scheduler job, as a re-entry mechanism.
- [ ] **OS Login / SSH-key persistence** in project metadata for a tester key.

### Impact demonstration
- [ ] **Data access proof:** read a single representative (non-PII where possible) object/row from each sensitive store to prove access; do not bulk-exfiltrate.
- [ ] **Control-plane proof:** show Owner-equivalent reach (e.g. ability to read all secrets, set IAM) without exercising destructive actions.
- [ ] **Detection check:** note which of your actions did and did not generate Cloud Audit Log / SCC findings, to feed the blue-team narrative.

### Cleanup
- [ ] **Remove every artifact:** delete created keys, IAM bindings, WIF providers, instances, functions, buckets, objects, scheduled jobs, and metadata entries. Cross-check against the Phase 1 cleanup log.
- [ ] **Confirm no residual access** by re-authenticating as the original starting principal only.

```
⚠️ Never run destructive or irreversible actions (resource deletion, IAM removal of
real principals, password rotation on prod databases) to "prove" impact. The proven
primitive is the finding. Stop at access; do not detonate.
```

---

## Recent Techniques (2024-2026)

- [ ] **ConfusedFunction (Tenable, 2024):** Cloud Function create/update attaches the default Cloud Build SA (over-permissioned). Test for: an identity with function deploy + the default Cloud Build SA still holding Editor on instances created before the mid-2024 partial fix, yielding storage/source/registry access and lateral movement.
- [ ] **ConfusedComposer (2025):** Cloud Composer variant of ConfusedFunction. Test for: an actor with Composer edit rights escalating to the default Cloud Build SA via environment build steps.
- [ ] **Cloud Composer malicious-PyPI escalation (2025):** installing a crafted PyPI package into a Composer environment runs code that reaches the build/runtime SA. Test for: write access to Composer's package set and an over-priv environment SA.
- [ ] **Vertex AI data access (2024):** consumer Vertex projects had unrestricted read to GCS buckets; producer environments exposed Google-owned Artifact Registry repos. Test for: notebook/pipeline SAs with broad `storage`/`artifactregistry` reach and tenant-isolation gaps.
- [ ] **Workload Identity Federation trust-condition abuse (ongoing 2024-2026):** WIF providers with loose `attribute-condition` (any GitHub repo, unpinned `assertion.sub`, missing audience check) let an attacker-controlled external OIDC token impersonate the bound SA with no key. Test every provider's mapping and condition.
- [ ] **GKE node-SA inheritance without Workload Identity (Datadog confirmed live 2024-2025):** pods read the node SA token from `169.254.169.254` directly. Test for: WI disabled, no NetworkPolicy blocking the metadata IP, and an over-priv node-pool SA.
- [ ] **GKE gVisor/sandbox metadata escape (Koyeb, 2024):** sandboxed pods reaching cluster metadata (`kube-env`, node identity) to break isolation. Test sandbox pods for metadata reachability.
- [ ] **`system:authenticated` over-broad RBAC on GKE:** any authenticated Google identity granted cluster access via a misapplied binding. Test cluster RBAC for bindings to `system:authenticated`/`system:anonymous`.
- [ ] **Metadata SSRF to token (still prevalent 2024-2026):** server-side fetch in hosted apps reaching `169.254.169.254` with the `Metadata-Flavor: Google` header. Test every app-layer URL-fetch sink; check legacy header-less endpoints are disabled.
- [ ] **Token-minting stealth (`getAccessToken`/`signJwt`):** impersonation that avoids key-creation audit logs. Confirm whether Data Access logs are enabled; if not, this path is low-visibility and worth flagging to the client.
- [ ] **Default-SA org-policy gaps:** projects without `iam.disableServiceAccountKeyCreation`, `iam.automaticIamGrantsForDefaultServiceAccounts` (still granting Editor to default SAs), `storage.publicAccessPrevention`, or `compute.requireOsLogin`. Each missing constraint is the enabler for a Phase 4-6 path.

---

## Reporting and Evidence

### Evidence to capture per finding
- [ ] **Identity context:** the exact principal used (`gcloud config list account`), and for chains, the full impersonation path with the permission used at each hop.
- [ ] **The permission, proven:** `testIamPermissions` output showing the grant, plus the command/request that exercised it and its response.
- [ ] **Resource identifiers:** full resource names (`projects/<id>/...`, SA emails, bucket names) so the client can locate and fix.
- [ ] **Raw request/response pairs** for API-level findings (token retrieval, setIamPolicy, bucket read) and screenshots for console-driven steps.
- [ ] **Audit-log correlation:** the log entry your action produced (or note its absence) to support the detection narrative.

### Severity guidance
| Finding | Typical severity | Note |
|---|---|---|
| Org/folder `setIamPolicy` or domain-wide-delegation key | Critical | Full org or Workspace compromise |
| Project `setIamPolicy` / actAs-to-Owner chain / public-write bucket with build impact | High | Single-project takeover or supply-chain |
| Metadata SSRF to usable token / default-SA + cloud-platform scope | High | Depends on the SA's effective role and scope |
| Readable secret / over-broad SA token / cross-project bridge | Medium-High | Rate by data sensitivity and reach |
| Missing org-policy guardrail / unrestricted API key / public-read bucket (non-sensitive) | Low-Medium | Enabler or limited exposure |

- [ ] **Rate by realized impact, not permission name.** A scary permission constrained by OAuth scope, an IAM condition, or a missing attachment may not be exploitable. Tie the rating to a CVSS-style vector and let the proven impact set the label.

### Common false positives to rule out
- [ ] **Scope-limited tokens:** an instance/SA token capped to e.g. `storage.read-only` cannot mutate IAM even if the SA's role would. Always pull `/scopes` before claiming full reach.
- [ ] **Ineffective IAM Conditions cut both ways:** a binding may look dangerous but be gated by a condition; conversely a condition may be misconfigured and not apply. Verify by actually exercising the permission.
- [ ] **Default-SA Editor that is partially remediated:** post-mid-2024 Cloud Build SAs are less privileged; confirm the actual role, do not assume the historical default.
- [ ] **Public bucket with no sensitive content:** public-read on a static-assets bucket is informational, not High. Inspect contents before rating.
- [ ] **`projects list` emptiness:** absence of list permission is not absence of access; test specific resources directly.

---

## Tools and References

| Tool | Use |
|---|---|
| `gcloud` / `gsutil` / `bq` CLI | Primary enumeration and exploitation interface |
| gcp_scanner | SA/IAM recon, privesc-chain discovery across reachable projects |
| GCPBucketBrute | Unauth/auth GCS bucket discovery and permission testing |
| ScoutSuite | Multi-cloud posture snapshot: IAM, firewall, public storage |
| Prowler (GCP) | CIS-aligned posture and misconfiguration scan |
| Rhino Security Labs GCP-IAM-Privilege-Escalation | Enumerate held permissions vs. ~40 known privesc methods + exploit scripts |
| hayat | GCP audit/log-driven recon and reporting |
| truffleHog / gitleaks | Leaked-key hunting in repos, images, artifacts |
| Cloud SQL Auth Proxy | Reach Cloud SQL from a compromised workload |

References:
- Rhino Security Labs: GCP IAM Privilege Escalation (Part 1/2) and Cloud Build RCE-to-IAM.
- HackTricks Cloud: GCP security and IAM privesc.
- Tenable Research: ConfusedFunction; subsequent ConfusedComposer disclosures.
- Google Cloud security bulletins and the GCS / IAM / GKE hardening docs (publicAccessPrevention, Workload Identity, protecting cluster metadata).
- GCP IAM permissions reference and org-policy constraint catalog.

---

## Related

- Playbooks: [GCP Service Account Impersonation to Org Admin](../Playbooks/GCP%20Service%20Account%20Impersonation%20to%20Org%20Admin.md)
- [AWS Cloud Penetration Test](AWS%20Cloud%20Penetration%20Test.md)
- [Kubernetes and Containers](Kubernetes%20and%20Containers.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- Cepheus
- Vinculum

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
