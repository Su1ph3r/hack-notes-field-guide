---
tags:
  - hack-notes
  - checklist
  - cloud
---

# Cloud Configuration Review Checklist

> Credentialed configuration and posture review of a cloud estate, read-mostly, run with a read-only audit role against the CIS benchmark for the provider. This is not an active cloud pentest: you enumerate settings and judge them, you do not exploit. Where a setting is directly exploitable (public write bucket, IMDSv1 behind an app with SSRF, a PassRole edge to admin), flag it and hand the exploitation off to [AWS Cloud Penetration Test](AWS%20Cloud%20Penetration%20Test.md), [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md), or [GCP Cloud Penetration Test](GCP%20Cloud%20Penetration%20Test.md). Command and tool detail live in the cloud cheatsheets; this note is the ordered method, the misconfig signal, and the evidence to bank.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Identity and Access Management](#2-identity-and-access-management)
- [3. Logging, Monitoring, and Audit](#3-logging-monitoring-and-audit)
- [4. Data Protection and Storage](#4-data-protection-and-storage)
- [5. Network Configuration](#5-network-configuration)
- [6. Compute and Workload](#6-compute-and-workload)
- [7. Secrets and Key Management](#7-secrets-and-key-management)
- [8. Resource Exposure Sweep](#8-resource-exposure-sweep)
- [9. CI/CD-to-Cloud Trust](#9-cicd-to-cloud-trust)
- [10. Compliance Mapping](#10-compliance-mapping)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

A posture review that touches the wrong account, or mutates one, is an incident you caused with a read-only role you promised not to exceed. Pin the scope and the role before the first API call.

### Accounts, Subscriptions, and Projects

- [ ] **Exact scope boundary:** Get the full list in writing: AWS account IDs, Azure subscription and management-group IDs, GCP project and folder IDs. A benchmark run against a sibling prod account nobody listed is out of scope, not a bonus finding.
- [ ] **Organization root in or out:** Confirm whether the org/tenant/org-node itself is in scope, not just the member accounts. Org-level controls (SCPs, Azure Policy at management group, GCP org policy) are where half the real posture lives, so getting them excluded quietly guts the review.
- [ ] **Benchmark and version target:** Agree the exact standard up front: CIS AWS Foundations, CIS Azure, CIS GCP, and which version (the control numbering shifts between releases). If the client wants NIST CSF or their own baseline mapped instead, settle that now, not in the report.
- [ ] **Read-only, nothing modified:** Put it in the RoE in one sentence: no create, modify, or delete, including no "harmless" test bucket or test user. The audit role should make that true by construction, but the written agreement is what covers you when a ticket asks why an API call appears in the log.

### Read-Only Audit Role

- [ ] **Provision the right managed role:** AWS `SecurityAudit` plus `ViewOnlyAccess` (the pair, SecurityAudit alone misses some describe/list calls). Azure `Reader` plus `Security Reader` on each subscription and the management group. GCP `roles/iam.securityReviewer` plus `roles/viewer` at the org or project. Record which principal holds it.
- [ ] **Confirm it cannot write:** Do not take the role name on trust. Check the attached policy for any create/update/delete/put verb. A role called read-only that carries `iam:PassRole` or `storage.objects.setIamPolicy` is not read-only. Revert nothing, but note it to the client as their own finding.
- [ ] **Secrets read is a scope decision:** `SecurityAudit` does not grant `secretsmanager:GetSecretValue`, Security Reader does not read Key Vault secret values, Security Reviewer does not decrypt Secret Manager payloads. Decide with the client whether you confirm a secret exists and is unrotated (metadata, in scope by default) or read its value (a mutation of trust, needs sign-off). Default to metadata.
- [ ] **Dedicated named identity:** Use a clearly named principal (`cairn-config-review-2026`) so the client's own audit log attributes every call to the review and not to an unknown actor.

### Safety and Logistics

- [ ] **Your calls are logged:** CloudTrail, Azure Activity log, and GCP Cloud Audit Logs will record every describe and list you make. This is detection-aware by default. Tell the blue team the window so they do not chase their own auditor.
- [ ] **Benchmark tooling is still API traffic:** Prowler, ScoutSuite, and Steampipe fire thousands of read calls fast. Confirm the client is fine with the volume and that it will not trip a rate-based GuardDuty/Defender alert they then page on.
- [ ] **Asset inventory completeness:** Before scoring controls, confirm you can actually see the whole estate the role is meant to cover. A review that silently missed two regions and a subscription is a partial review reported as complete. Reconcile what the tooling enumerated against the client's own account/subscription/project list.
- [ ] **Emergency contact and revoke path:** Record who to call and how to kill the audit role instantly if something looks wrong.
- [ ] **Shared-responsibility boundary:** Confirm you are reviewing the customer's configuration, not the provider's substrate. The hypervisor, control-plane internals, and the provider's own managed-service hardening are theirs; do not report a provider-owned default as a client finding.
- [ ] **Multi-cloud and connected SaaS:** If the estate spans more than one provider, or federates into SaaS (Datadog, Snowflake, a secrets vendor), note each as its own scope line with its own benchmark. A control that is tight in AWS can be undone by a loose trust into a connected tenant.

```
⚠️ A read-only review must stay read-only. Do not "quickly test" whether a public bucket is
writable, whether a weak SG actually lets you in, or whether a PassRole edge actually escalates.
That is active pentest and it belongs in the pentest checklists under a different authorization.
If the role you were given can mutate, that is a finding to report, not a capability to use.
```

---

## 2. Identity and Access Management

Identity is the control plane. In a config review you are reading who can do what, not proving you can become them. The signal is standing privilege, broad trust, and stale credentials.

### Root, Global Admin, and Break-Glass

- [ ] **Root/global-admin usage:** Confirm the root user (AWS), Global Administrator accounts (Entra ID), and org-level owners (GCP) are not used for daily work. Any recent sign-in or access-key use by the AWS root account is a finding. Check root has no active access keys at all.
- [ ] **MFA on the top of the tree:** Root MFA (hardware preferred), MFA on every Global Admin, MFA on GCP org admins and the Super Admin of the linked Workspace. Missing MFA on a top-tier identity is high severity on its own.
- [ ] **Break-glass accounts exist and are controlled:** Confirm there is a documented emergency-access path (so MFA lockout does not lock everyone out) and that those accounts are excluded from conditional-access in a controlled way, monitored, and alert on use. A break-glass account with no alerting is a backdoor, not a safeguard.

### Users, Roles, and Over-Privilege

- [ ] **Humans in roles, not long-lived users:** Count IAM users with console access and long-lived keys versus federated/SSO access to roles. A pile of standing IAM users (AWS) or static app registrations with client secrets (Entra) instead of short-lived role assumption is the posture gap.
- [ ] **Wildcard and admin policies:** Flag `Action:"*"` / `Resource:"*"` IAM policies, Azure `Owner`/`Contributor` at subscription or management-group scope handed to individuals, and GCP `roles/owner` or `roles/editor` on the project. The default `Editor` role on a GCP project is broader than almost anyone needs; call it out.
- [ ] **Over-privilege vs use:** Where the provider exposes it, compare granted permissions to permissions actually used (AWS IAM Access Analyzer unused-access / last-accessed data, GCP recommender, Entra `PIM` eligible-vs-active). Grants far wider than usage are the finding, even if nothing is wildcard.
- [ ] **Separation of duties:** Note principals that hold both a powerful role and the ability to grant roles (`iam:PutUserPolicy`, Azure `User Access Administrator`, GCP `roles/iam.securityAdmin`). Self-granting is how least privilege unravels over time.
- [ ] **Permission boundaries and SCP gaps:** Where AWS permission boundaries or GCP IAM conditions are meant to cap a principal, read them. A boundary that is attached but allows everything, or a role the SCP does not actually constrain, is a control that looks present and does nothing. A true guard with a false reason is what the next engineer deletes.
- [ ] **Disabled and orphaned accounts:** Flag disabled users still holding role assignments, departed-staff identities not deprovisioned, and guest accounts past their useful life. Deprovisioning that stops at disabling, without removing the grants, leaves the access waiting to be re-enabled.
- [ ] **Service accounts and machine identities:** Enumerate service accounts (GCP), service principals and managed identities (Azure), and service-linked and application roles (AWS). Machine identities outnumber humans and rarely get reviewed. Flag ones with Owner/Editor-equivalent scope and user-managed keys.

```bash
# AWS, list every policy statement that grants Action:* on Resource:* (anchor only; full tooling in cheatsheet)
aws accessanalyzer list-findings --analyzer-arn "$ANALYZER" 2>/dev/null
prowler aws --compliance cis_3.0_aws -s iam
```

### Credentials and Rotation

- [ ] **Access-key age:** List access keys with creation and last-used dates. Keys older than the client's rotation policy (90 days is the common CIS line) are findings. A key created years ago and used yesterday is worse than one never used.
- [ ] **Unused credentials:** Flag access keys, users, service accounts, and roles not used in 90+ days. Dormant credentials are standing attack surface with no owner watching them. GCP service-account keys deserve special attention: user-managed keys that never expire are a recurring CIS failure.
- [ ] **Password policy:** Check length, complexity, reuse, and expiry against the benchmark. This is a weak-signal finding on its own but part of the baseline.
- [ ] **Initial-key and console/programmatic split:** Flag users holding both console access and long-lived programmatic keys where one would do, and any access key created at user-creation time and never rotated since. Both are common CIS deviations that quietly widen the credential surface.

### Trust, Federation, and Org Policy

- [ ] **Cross-account / cross-tenant trust:** Read role trust policies (AWS `AssumeRolePolicyDocument`), Azure guest/B2B access and cross-tenant settings, GCP service accounts granted to external domains. A role trusting a whole external account, or `Principal:"*"`, or a third-party role with no `ExternalId`, is the confused-deputy setup. You are reading the trust document, not assuming the role.
- [ ] **Federation and SSO:** Enumerate SAML/OIDC identity providers and confirm SSO is the primary human path. In Entra, review conditional-access coverage: a policy that exempts large groups or lacks MFA for admins is a gap. In GCP, confirm Workspace/Cloud Identity is the identity source and not a sprawl of consumer Gmail accounts.
- [ ] **Legacy and weak auth protocols:** In Entra, check whether legacy authentication (which bypasses MFA) is blocked and whether security defaults or conditional access enforce it. In AWS, note any remaining SAML/console paths without MFA. Legacy auth left on is the quiet route around every MFA control above it.
- [ ] **Org management-role reachability:** In AWS, note who can assume `OrganizationAccountAccessRole` into member accounts, and the equivalent management-group owner reach in Azure and org-admin reach in GCP. A broad trust into the management path collapses the account boundary that the rest of the review assumes.
- [ ] **Guardrail policy present:** Confirm the preventive controls exist at the top: AWS SCPs on the org, Azure Policy assignments at the management group, GCP organization policy constraints. Absence of any org-level guardrail (so every account is on its own) is itself a posture finding. Check specific high-value constraints: block public IP on VMs, restrict public bucket access, enforce IMDSv2.

---

## 3. Logging, Monitoring, and Audit

If an incident happened tomorrow, what would the client be able to reconstruct? That question is the whole section. Logging off in one region is a blind spot an attacker will find.

### Audit Log Coverage

- [ ] **Trail exists and is multi-region:** AWS, confirm at least one CloudTrail trail that is multi-region and applies to all accounts (org trail). Azure, confirm the Activity log is exported (diagnostic setting) to a Log Analytics workspace or storage, not just the 90-day default. GCP, confirm Cloud Audit Logs Admin Activity is on (it is by default) and Data Access logs are enabled where the data warrants.
- [ ] **Management and data events:** A trail logging only management events misses S3 object access, Lambda data events, and the like. Note which data-event logging is off. This is exactly the gap that makes a breach uninvestigable.
- [ ] **No region left dark:** Confirm coverage across all enabled regions, not just the primary. Shadow resources and attacker activity live in the unused ones.
- [ ] **Centralized across accounts:** Confirm logs land in a central, access-restricted account or workspace, not scattered per-account where a compromise of one account also owns its own logs. An org trail or a central Log Analytics workspace is the posture you want to see.

### Integrity and Retention

- [ ] **Log integrity:** AWS, confirm CloudTrail log-file validation is enabled and the log bucket denies deletes (MFA-delete / Object Lock, restrictive bucket policy). Azure, confirm immutable or locked storage for the exported logs. GCP, confirm log buckets have retention/locking and the logging sink is protected. A log store the same compromised principal can wipe is not an audit trail.
- [ ] **Log store is not itself public:** Confirm the CloudTrail log bucket, the log-export storage account, and the GCP log sink destination are not publicly readable. A world-readable audit log hands an attacker the client's detection coverage and timing.
- [ ] **Retention meets the requirement:** Check retention against the client's compliance driver (often 1 year hot, longer cold). Default short retention silently drops the history an investigation needs.

### Detection Services

- [ ] **Threat detection enabled estate-wide:** AWS GuardDuty on in every region and account. Azure Defender for Cloud plans on for the relevant resource types (servers, storage, SQL, containers), not just the free CSPM tier. GCP Security Command Center at a tier that includes Event Threat Detection. Enabled in one region or one subscription is a partial control.
- [ ] **Config/posture recording on:** AWS Config recording resource changes, Azure Policy compliance state populated, GCP SCC asset inventory active. Without this the client has no drift history.
- [ ] **Drift from a known-good baseline:** Where the client has a baseline or landing-zone template, note resources that have drifted from it. Config review is a point-in-time read; a client with no drift detection will have drifted again by the time the report lands.
- [ ] **Alerting actually routes somewhere:** A detector with no notification channel is decoration. Confirm findings route to a monitored destination (SNS/Security Hub, Defender email/workbook, SCC notification to a SIEM). Security Hub green is not a pentest, and a GuardDuty finding nobody receives is not detection.

### Specific High-Value Alarms

- [ ] **Metric filters for sensitive events:** The CIS AWS benchmark calls for CloudWatch alarms on root usage, IAM policy changes, console sign-in without MFA, CloudTrail config changes, and SG/NACL/route-table changes. Confirm each exists or note the gap. Azure and GCP have equivalent activity-log alert expectations; check them against the benchmark rather than assuming the SIEM covers it.
- [ ] **Billing and anomaly signals:** A sudden cost spike is often the first visible sign of cryptomining or data egress. Note whether any billing/cost anomaly alerting exists. This is a weak signal on its own and a useful backstop in context.

---

## 4. Data Protection and Storage

Storage misconfig is still the most common high-impact cloud finding. Read the access settings and the encryption posture; confirm contents before you call a public bucket a breach.

### Object Storage Public Access

- [ ] **Account-level public access block:** AWS S3 Block Public Access at the account level (the master switch), Azure storage account "allow blob public access" set to disabled, GCP "enforce public access prevention" org policy. Confirm the account-wide control first; it changes how you read every per-bucket setting beneath it.
- [ ] **Per-bucket ACLs and policies:** For each bucket/container, read the ACL, resource policy, and public-access setting. Flag anonymous or all-authenticated-users read or write. On GCP the specific signal is an IAM binding to `allUsers` or `allAuthenticatedUsers`.
- [ ] **Object ownership and ACLs disabled:** On S3, confirm Object Ownership is set to bucket-owner-enforced so legacy object ACLs cannot re-grant public access underneath the bucket policy. An ACL-granted public object slips past a reviewer who only read the bucket policy.
- [ ] **A public bucket is only a finding if it holds something:** Confirm the contents before rating it. A bucket intentionally serving a static website is public by design and not a breach; a public bucket holding backups, `.env` files, or PII is. Read the object listing, do not exfiltrate, and rate by what is actually exposed.
- [ ] **Writable is worse than readable:** Anonymous or broad write enables defacement, malware staging, and supply-chain poisoning of whatever consumes the bucket. In a read-only review you confirm the grant from the policy, you do not test the upload. Flag it and hand to the pentest checklist.
- [ ] **Transport and policy conditions:** Check that bucket/container policies require TLS (`aws:SecureTransport`, Azure "secure transfer required", GCP enforced via org policy) and that no statement fails open. A policy that grants broad access unless a condition holds often grants it in practice.

```
⚠️ Read the grant, do not exercise it. Confirming a bucket is public-writable by uploading a
test object, or a database is reachable by connecting, is active testing against prod data and
outside the read-only authorization. A write that lands in a production bucket, even a benign
marker, is a change you made to the client's environment. Prove it from the policy and hand the
live proof to the matching pentest checklist.
```

### Encryption at Rest and Keys

- [ ] **Encryption on by default:** Confirm default encryption on buckets, disks, databases, and snapshots. Most providers now encrypt by default, so the real question is whether it is customer-managed where the data classification demands it (CMK/KMS, Key Vault, CMEK) versus provider-managed.
- [ ] **Key policy breadth:** Read KMS key policies, Key Vault access policies / RBAC, and Cloud KMS IAM. A key whose policy grants decrypt to a broad or wildcard principal undermines every secret and volume it protects. This is a config-review sweet spot: the key policy is readable and the over-grant is plain.
- [ ] **Key rotation:** Confirm automatic rotation is on for CMKs where the benchmark expects it. GCP CMEK and Azure Key Vault keys support rotation policies; flag keys with none.
- [ ] **Key Vault / KMS deletion protection:** Confirm soft-delete and purge protection on Azure Key Vault, and that KMS keys are not scheduled for deletion or left without a key policy that survives account changes. A key an attacker can delete is a denial-of-service against everything it encrypts.

### Databases, Disks, and Snapshots

- [ ] **Public database endpoints:** Flag RDS/Aurora, Azure SQL / managed instances, and Cloud SQL instances with a public endpoint reachable from `0.0.0.0/0`. Azure SQL, specifically check the "allow Azure services" and firewall `0.0.0.0` rules. A public DB with weak auth is the kind of posture gap that becomes an exploit the moment a pentester is allowed to push.
- [ ] **Backup and recovery posture:** Confirm automated backups are on and retained, with encryption, on the databases that matter. A database with no backups is both a resilience gap and, when paired with broad write, a ransomware target with no recovery path.
- [ ] **Public snapshots and images:** Read sharing settings on EBS/RDS snapshots, Azure managed-disk and image share scope, and GCP image IAM. A snapshot shared publicly or to a wide account list leaks whatever was on the volume. You are reading the sharing flag; confirming the contents is the pentest step.
- [ ] **Encryption in transit to data stores:** Confirm databases and caches enforce TLS on client connections (RDS `require_ssl`/parameter groups, Azure SQL minimum TLS version, Cloud SQL SSL mode). Encrypted at rest but plaintext on the wire is a half-closed door.
- [ ] **Disk/volume encryption:** Confirm boot and data disk encryption across EC2 EBS, Azure managed disks (and whether host-based or double encryption is required by policy), and GCP persistent disks.
- [ ] **Versioning and immutability on data stores:** Check bucket versioning and Object Lock / immutable blob storage on buckets holding backups and anything ransomware-relevant. A bucket with write access and no versioning is a store an attacker can overwrite in place. This is posture that matters whether or not the bucket is public.
- [ ] **Data residency and classification:** Note where regulated data lives versus where the client says it should. A storage account or bucket in an unexpected region is a compliance finding even when its access controls are sound.
- [ ] **Access logging on data stores:** Confirm server access logging on S3 buckets, diagnostic logging on storage accounts, and data access logs on GCS where the data warrants it. Without it, "who read this object" is unanswerable after the fact.

```bash
# Multi-cloud public-storage and key checks via Prowler, scoped to the data groups (anchor only; full tooling in cheatsheet)
prowler aws   --compliance cis_3.0_aws   -s s3 rds kms
prowler azure --compliance cis_2.1_azure -s storage keyvault sql
prowler gcp   --compliance cis_2.0_gcp   -s cloudstorage cloudsql kms
```

---

## 5. Network Configuration

Map the exposed surface and the controls meant to contain it. In a review you read the rules; the signal is anything open to the world on a port that should never face it. Read the whole path before rating a rule, since one open rule can be dead behind a deny somewhere else.

### Firewall and Security Group Rules

- [ ] **Ingress from 0.0.0.0/0:** Enumerate security groups (AWS), NSGs (Azure), and VPC firewall rules (GCP) permitting `0.0.0.0/0` or `::/0` to sensitive ports: 22, 3389, 3306, 5432, 1433, 6379, 9200, 27017. Open management or database ports to the internet are findings. On GCP the default network's permissive rules are a frequent CIS failure.
- [ ] **A permissive SG can be contained downstream:** Before rating an open SG, check what sits in front of it. A security group open on 22 behind a deny NACL, a subnet with no public route, or an NSG that a higher-priority deny rule overrides is not reachable. Read the full path before calling it exposed, and say so in the finding rather than letting the client discover the false positive.
- [ ] **Egress:** Unrestricted egress is a defense-in-depth gap that eases exfiltration and C2. Note it; rate it low unless the environment's data classification raises it.
- [ ] **Default-deny posture:** Confirm the baseline is deny, with explicit allows, rather than a broad allow with a few denies bolted on. A rule set that starts permissive and tries to claw access back is where the gaps hide.

### Peering and Lateral Reach

- [ ] **Peering and transit review:** Map VPC/VNet peering, transit gateways, and shared VPCs. These are the lateral-movement highways; a tightly firewalled prod VPC peered flat to a loose dev VPC inherits the dev VPC's exposure.
- [ ] **VPC/endpoint policies:** Note interface and gateway endpoint policies that are broader than needed. An over-permissive endpoint policy can widen reach to S3/DynamoDB or their equivalents regardless of the subnet's isolation.

### Topology and Exposure

- [ ] **Public IPs on sensitive resources:** Flag public IPs on databases, management hosts, Kubernetes API servers, and internal services that have no reason to face the internet. Cross-reference with the firewall rules; a public IP behind a tight allowlist is a different risk than one behind `0.0.0.0/0`.
- [ ] **Default VPC/VNet usage:** Note workloads running in the default VPC (AWS), default VNet, or default GCP network with its auto-created permissive rules. Default networks tend to carry defaults nobody revisited.
- [ ] **Flow logs:** Confirm VPC Flow Logs (AWS), NSG flow logs / VNet flow logs (Azure), and VPC Flow Logs (GCP) are enabled on the subnets that matter. Without them, network-layer investigation after an incident is guesswork.
- [ ] **Private endpoints for managed services:** Check whether storage, databases, and key stores are reachable over private endpoints / Private Link / Private Service Connect rather than public endpoints with a firewall. Private connectivity present is good posture; its absence on a sensitive data store is the finding.
- [ ] **DNS resolver and egress filtering:** Note whether outbound DNS and traffic pass through a controlled resolver or egress firewall. Unfiltered DNS is a common exfil and C2 channel that the SG review alone will miss.
- [ ] **Exposed management planes:** Note internet-facing Kubernetes API servers, container registries, and admin consoles. These tie into the resource-exposure sweep in section 8.

### DNS and Edge

- [ ] **Dangling DNS records:** Review hosted zones (Route 53, Azure DNS, Cloud DNS) for records pointing at deprovisioned resources. A CNAME aimed at a released cloud endpoint is a subdomain-takeover candidate. You are reading the record and confirming the backing resource is gone; claiming the dangling target is the pentest step.
- [ ] **WAF and DDoS posture:** Note whether public web front doors (ALB/CloudFront, Azure Front Door/App Gateway, GCP Cloud Load Balancing) sit behind a WAF and DDoS protection. Absence is a defense-in-depth gap, not a breach; rate it accordingly.
- [ ] **Direct-to-origin exposure:** Check whether origins behind a CDN/WAF are also reachable directly by IP, bypassing the edge controls entirely.

---

## 6. Compute and Workload

Read how instances and functions are configured and exposed. The metadata service is the single highest-value compute setting to get right.

### Instance Metadata

- [ ] **IMDSv2 enforced (AWS):** For each EC2 instance and launch template, check `HttpTokens`. `optional` means IMDSv1 is still allowed and any SSRF in a fronting app can read the instance role credentials; `required` closes it. IMDSv1-allowed instances are the posture finding; whether an app actually has SSRF to reach it is the pentest question. Also check the org/account default and any declarative policy enforcing v2.
- [ ] **Hop limit:** Note `HttpPutResponseHopLimit`. A hop limit above 1 lets containers on the host reach IMDS, widening what a container compromise yields.
- [ ] **Azure IMDS:** Azure IMDS has no v1/v2 toggle; the control is that workloads use managed identities scoped tightly and that the metadata endpoint is not proxied out through an app. Check managed-identity assignment scope: a VM with a subscription-Contributor managed identity is the blast-radius finding.
- [ ] **GCP metadata:** Confirm legacy metadata endpoints are disabled (`disable-legacy-endpoints`) and, where supported, that workload identity is used over long-lived service-account keys on the instance. Note instances running as the default compute service account with broad scopes.
- [ ] **SSH/key-pair management:** Check how instance access is granted: OS Login / EC2 Instance Connect / Azure AD login over static key pairs and local accounts. Project-wide SSH keys (GCP) and shared key pairs are standing access nobody rotates.

### Images, Patching, and Agents

- [ ] **Public AMIs/images/snapshots:** Read the share scope on owned AMIs, Azure images, and GCP images. Any marked public may carry baked-in secrets. Reading the flag is the review; launching one to confirm is pentest.
- [ ] **Patch and agent management:** Confirm a managed patch path (AWS SSM Patch Manager, Azure Update Manager, GCP OS patch management) and that the agent (SSM, Azure Monitor/Arc, Ops Agent) is installed on the fleet. Instances outside management are the ones that rot unpatched.
- [ ] **SSM/agent reachability:** Note SSM-managed instances and the breadth of the instance-profile role. In a review this is about over-privilege on the role, not running commands.
- [ ] **Image age and golden-image discipline:** Note how old deployed AMIs/images are and whether the fleet is rebuilt from a maintained golden image or patched in place. A fleet pinned to a two-year-old image is carrying two years of unpatched CVEs no benchmark control names directly.

### Serverless

- [ ] **Public function URLs:** Flag Lambda function URLs with `AuthType: NONE`, Azure Functions with anonymous auth level, and GCP Cloud Functions / Cloud Run allowing `allUsers` invoke. A public function endpoint is an unauthenticated entry point into whatever the function does and whatever its role can reach.
- [ ] **Execution-role scope:** Read the function execution/identity role. An over-scoped function role combined with any code-exec weakness is a privesc primitive; in the review you report the over-scope.
- [ ] **Resource policies on functions:** Check Lambda resource policies and equivalent invoke permissions for cross-account or public invoke beyond the function URL itself. A function invokable from an unexpected account is a trust finding independent of its endpoint.
- [ ] **Secrets in function config:** Covered in section 7, but note env vars on functions as you enumerate them.

### Containers

- [ ] **Image provenance and scanning:** Confirm images come from controlled registries and that vulnerability scanning runs (ECR scan-on-push, Defender for Containers, GCP Artifact Registry scanning). Note whether scan findings gate deployment or just generate a report nobody reads.
- [ ] **Privileged and host-networked workloads:** For managed Kubernetes, note workloads running privileged, as root, with `hostNetwork`, or with broad cloud identities bound to the pod. Deeper container-to-cloud posture lives in [Kubernetes and Containers](Kubernetes%20and%20Containers.md).

---

## 7. Secrets and Key Management

The finding here is secrets living where they should not: in plaintext in a config surface instead of a managed vault, and keys that never rotate. Most of this is readable with the audit role without ever reading a secret's value, which is where you want to stay by default.

- [ ] **Managed secret store in use:** Confirm the client uses Secrets Manager / SSM Parameter Store, Azure Key Vault, or GCP Secret Manager, rather than scattering credentials. A vault that exists but that half the workloads bypass is a partial control worth naming.
- [ ] **Plaintext secrets in user-data and env:** Read EC2 user-data, launch templates, Lambda/Function env vars, container task definitions, and GCP instance metadata for embedded passwords, API keys, and connection strings. This is readable with the audit role and is a recurring high-value finding. Base64 in user-data is encoding, not protection; decode and check.
- [ ] **Secrets in IaC and deployment config:** Where you can see it, flag hardcoded secrets in templates, pipeline variables, and app settings. Tie anything in a repo to section 9.
- [ ] **Rotation enabled:** Confirm rotation is configured on stored secrets and on the keys protecting them. A secret in the vault that has not rotated in years is better than plaintext but still a finding against most benchmarks.
- [ ] **IaC state and pipeline variables:** Terraform/CloudFormation state files routinely hold secrets in plaintext; check whether state lives in a locked, encrypted, access-restricted backend and not a public or broadly readable bucket. Flag pipeline variables and app settings carrying credentials that belong in a vault.
- [ ] **Keys protect the secrets:** Cross-reference each secret store with the KMS/Key Vault/Cloud KMS key that encrypts it. A tightly rotated secret under a key with a wide-open key policy is still exposed to anyone the key policy trusts.
- [ ] **Secret value read is a scope line:** Default to confirming existence and metadata (name, last-rotated, policy). Reading the value itself needs the sign-off from section 1. Never paste a live secret value into the report; reference it by name.

---

## 8. Resource Exposure Sweep

Sweep by capability across the estate, not by the one service you happened to look at. The question is: what is reachable without authentication, or shared too widely, anywhere.

- [ ] **Public functions and endpoints:** Consolidate the public Lambda/Function URLs and `allUsers`-invokable Cloud Run/Functions from section 6 into one exposure list.
- [ ] **Open databases and search clusters:** Public RDS/SQL/Cloud SQL, plus internet-facing OpenSearch/Elasticsearch, ElastiCache/Redis, and MongoDB/DocumentDB with weak or no auth. An exposed search cluster with no auth is a data breach waiting for a scanner to find it.
- [ ] **Public queues and topics:** Read resource policies on SQS/SNS, Azure Service Bus / Event Grid, and GCP Pub/Sub for `Principal:"*"` or cross-account/anonymous access. These are quiet exfil and injection channels.
- [ ] **Exposed container registries:** Check ECR repository policies, Azure Container Registry public access and anonymous pull, and GCP Artifact/Container Registry IAM for public or over-broad read. A public registry leaks images, and images leak secrets and source.
- [ ] **Public APIs and webhooks:** Note API Gateway / Azure API Management / Cloud Endpoints with no authorizer, and inbound webhook receivers with no signature verification. An unauthenticated API in front of a privileged backend is an exposure the storage sweep would miss.
- [ ] **Managed Kubernetes API exposure:** Flag EKS/AKS/GKE clusters with a public API server endpoint and no authorized-network restriction. Pivot detail lives in [Kubernetes and Containers](Kubernetes%20and%20Containers.md).
- [ ] **Exposed bastions and remote access:** Note internet-facing bastion hosts, jump boxes, and VPN/remote-desktop gateways. These are meant to be reachable, so the finding is weak auth, no MFA, or an unpatched version, not mere presence.
- [ ] **Public AI/ML and data endpoints:** Flag exposed SageMaker/Azure ML/Vertex AI endpoints, public notebook instances, and data-lake/warehouse access (Redshift, Synapse, BigQuery dataset sharing with `allAuthenticatedUsers`). These are newer surfaces that benchmarks are only starting to cover.
- [ ] **Sweep the whole table, not the one you edited:** Enumerate every region and every account in scope for each exposure class. Copies and parallel deployments are found by sweeping the service across the estate, not by checking the one resource the client mentioned.

---

## 9. CI/CD-to-Cloud Trust

The pipeline is now a cloud principal. A loose OIDC trust condition hands anyone who can run a workflow the role it assumes. Read the trust, and tie the rest to [CICD Pipeline](CICD%20Pipeline.md).

- [ ] **OIDC federation scope:** Read the trust policy on roles assumable from GitHub Actions, GitLab, and other OIDC providers. The signal is a loose `sub` condition. A condition matching `repo:org/*` or missing the branch/environment entirely lets any repo, or any branch, in the org assume the role. It should pin the exact repo and ref.
- [ ] **Audience and issuer pinned:** Confirm the trust validates the correct `aud` and the expected issuer URL, not just any token from the provider.
- [ ] **Deployment principal privilege:** Read what the deploy role can do. Pipelines often run as near-admin because it was easy; a CI role with `Owner`/`*` is one poisoned workflow away from cloud admin. Rate the standing privilege, and hand the exploit path to [Poisoned CI Pipeline to Cloud Admin](../Playbooks/Poisoned%20CI%20Pipeline%20to%20Cloud%20Admin.md).
- [ ] **Static deploy credentials:** Flag long-lived cloud keys stored as CI secrets where OIDC federation would remove them. A static `AKIA` key in a repo's CI settings is both standing credential and exfil target.
- [ ] **Artifact provenance into the cloud:** Note whether what the pipeline deploys is verified (signed images, checked artifacts) before it lands in the cloud. An unverified artifact promoted straight to a privileged environment is a supply-chain path the cloud controls will not catch.
- [ ] **Environment protection and approvals:** Where the pipeline deploys to a privileged cloud environment, confirm the CI platform gates it (GitHub environment protection rules, required reviewers, protected branches). A deploy role any contributor can trigger on any branch is a standing privilege, not a controlled one.
- [ ] **Self-hosted runner trust:** Note self-hosted runners with cloud identities and whether untrusted (fork) PRs can reach them.

---

## 10. Compliance Mapping

The deliverable of a posture review is findings mapped to controls the client already answers to, with a clear line between what is a gap and what is live risk.

- [ ] **Map each finding to a CIS control:** Tie every finding to its benchmark control number (CIS AWS/Azure/GCP at the agreed version) so the client can track remediation against the standard they report on. A finding with no control reference is harder for them to action and to re-test.
- [ ] **Map to the provider security pillar:** Cross-reference the AWS Well-Architected Security Pillar, Azure Well-Architected security guidance, or Google Cloud security foundations so the finding sits in the framework the client's architects use.
- [ ] **Carry the client's own framework too:** If the client reports to SOC 2, ISO 27001, PCI, or HIPAA, add that mapping. A finding tagged to the standard an auditor will ask about is the one that gets funded.
- [ ] **Separate posture gaps from exploitable issues:** Label each finding as a posture/compliance gap (benchmark says configure it this way, no proven live path) versus directly exploitable (public write bucket, IMDSv1 behind a known-SSRF app, OIDC trust any repo can assume). The exploitable ones carry the exploit handoff to the pentest checklists; do not inflate a benchmark deviation into a breach.
- [ ] **Chain the gaps into one path:** A pile of individually-medium gaps often lines up into a single route (public SG, then overscoped role, then readable secret). Note the chains; the client fixes the cheapest link once you have shown where it leads, and the pentest checklists pick up the proof.
- [ ] **Note what the benchmark misses:** CIS is a floor, not a ceiling. If you see a real risk the benchmark has no control for, report it as a finding on its own merit and say it is outside the standard.
- [ ] **Record a re-test baseline:** Capture the state of each finding precisely enough that a follow-up review can confirm remediation with the same read-only role. A posture review's value compounds over time only if the next run can diff against this one.
- [ ] **Prioritize by exposure, not count:** A scanner that returns 400 benchmark deviations buries the three that matter. Lead the report with the exploitable issues and the data-exposure findings; the long tail of low-signal deviations goes in an appendix, not the executive summary.

---

## Recent Techniques (2024-2026)

Config-review angles worth a specific look on a modern estate. Each is a named issue with a one-line check. No CVE is cited unless it is real.

- [ ] **IMDSv1 still allowed at scale:** SSRF-to-IMDS stayed a top cloud entry path through 2025 to 2026. Check-for: any EC2 instance or launch template with `HttpTokens: optional`, and whether an org SCP or declarative policy enforces v2. The config gap is reportable even with no app in scope to prove the SSRF.
- [ ] **Public RDS and EBS/RDS snapshots:** Snapshots shared publicly or to a wide account list remain a quiet data-leak class. Check-for: `createVolumePermission` / snapshot share scope set to public or an unexpected account.
- [ ] **Over-trusting GitHub-Actions-to-cloud OIDC roles:** A role whose trust `sub` condition is not pinned to a specific repo and ref. Check-for: `token.actions.githubusercontent.com` trust with a wildcard or missing `sub`, letting any workflow in the org assume it.
- [ ] **Confused-deputy third-party roles:** Vendor integration roles that trust an external account without an `ExternalId` or tight condition. Check-for: any cross-account trust to a SaaS/monitoring vendor with no `ExternalId` or `Condition`.
- [ ] **Public Lambda / Function URLs:** Direct function endpoints with no auth. Check-for: Lambda function URLs with `AuthType: NONE`, Azure Functions at anonymous auth level, Cloud Run/Functions allowing `allUsers`.
- [ ] **S3 account-name bucket pre-claim exposure:** Services auto-create predictably named buckets; a name un-created in some regions can be hijacked. Check-for: predictable account-scoped bucket names and whether they are pre-created across regions. (See the AWS pentest checklist for the exploitation path.)
- [ ] **Entra ID over-permissioned app registrations and consent:** Standing app registrations with broad Graph permissions and long-lived client secrets. Check-for: apps with `Application` Graph permissions far beyond need, secrets with no expiry, and tenant-wide admin-consented permissions.
- [ ] **Terraform/IaC state secrets exposure:** Remote state holding plaintext credentials in a backend that is public or broadly readable. Check-for: a state bucket/container with weak access control, since the state is a single file that unlocks much of the estate.
- [ ] **Public managed-service dashboards:** Grafana, Kibana/OpenSearch Dashboards, and similar consoles exposed without auth remain a recurring entry point. Check-for: internet-facing analytics/observability UIs with anonymous or default access.
- [ ] **Azure shared-key and SAS sprawl:** Long-lived account-level SAS tokens and shared keys hand out access that outlives any identity control. Check-for: SAS policies with long expiry and no revocation, and accounts that still permit shared-key auth.
- [ ] **Overly broad conditional-access exclusions:** Entra conditional-access policies that exclude large groups or whole apps from MFA. Check-for: exclusions that quietly remove MFA from identities that should carry it.
- [ ] **GCP default service account with Editor:** Compute instances running as the default service account with the broad default scopes. Check-for: instances not overriding the default SA and scope, a long-standing CIS failure.
- [ ] **Long-lived service-account keys:** User-managed GCP service-account keys and static Azure service-principal secrets with no expiry are credentials that outlive the people who made them. Check-for: keys/secrets older than the rotation policy, especially on identities with real privilege.
- [ ] **Azure Storage shared-key access:** Storage accounts still allowing shared-key (account-key) authorization let a leaked key bypass Entra identity controls entirely. Check-for: `allowSharedKeyAccess` not disabled on accounts holding sensitive data.
- [ ] **Public BigQuery / dataset sharing:** GCP datasets and tables shared with `allAuthenticatedUsers` or `allUsers` leak analytics data quietly. Check-for: dataset-level IAM bindings to those special identities.
- [ ] **Overbroad managed-identity scope:** Azure VMs and functions with a system- or user-assigned managed identity granted Contributor/Owner at subscription scope turn one workload compromise into subscription control. Check-for: managed identities with role assignments far above the workload's need.
- [ ] **Declarative/org enforcement absent:** Defenders can now enforce IMDSv2, block public buckets, and restrict public IPs org-wide via SCP / Azure Policy / GCP org policy. Check-for: the absence of these preventive controls, so each account relies on per-resource discipline.

---

## Reporting and Evidence

### Evidence to Capture per Finding

- [ ] **The exact resource and the setting:** Record the precise resource identifier (ARN, Azure resource ID, GCP resource name) and the exact setting that proves the finding (the policy JSON statement, the `HttpTokens` value, the public-access flag, the firewall rule). The identifier plus the setting is the finding; a screenshot of a dashboard tile is not.
- [ ] **The benchmark control:** The CIS control number (and version) the finding maps to, per section 10.
- [ ] **How it was read:** The describe/list call or tool output that surfaced it, so the client can reproduce the read with their own read-only role. Capture it at review time, not from memory.
- [ ] **Timestamp for correlation:** Record when each read was taken so the client can correlate your review traffic with their own audit log and so a later re-test knows the baseline date.
- [ ] **Account/subscription/project and region:** Tag every finding with where it lives. A finding with no location is not actionable.
- [ ] **Gap vs exploitable label:** State whether this is a posture gap or a directly exploitable issue, and for the latter, the pentest-checklist handoff.
- [ ] **No live secrets or raw data in the report:** Reference secrets by name and data by a redacted sample. A report that pastes a live key or a PII record becomes a new exposure of its own.

### Severity Guidance

| Severity | Typical cloud-config examples |
|---|---|
| Critical | Public write to a prod data bucket; secret granting admin exposed in plaintext user-data; OIDC role any repo can assume into near-admin; cross-account admin trust with no condition |
| High | Public read of a bucket holding sensitive data; IMDSv1 allowed on an instance behind an in-scope app; readable secrets/snapshots with real data; public database with weak auth; no MFA on a Global Admin / root |
| Medium | Over-permissive but non-admin role; IMDSv1 allowed with no known app exposure; public read of non-sensitive storage; missing flow logs; stale unused access keys with privilege |
| Low | Password-policy weakness, unrestricted egress, missing non-critical data-event logging, provider-managed instead of customer-managed keys where not required, defense-in-depth gaps |
| Info | Benchmark deviations with no realistic impact, version/informational notes, best-practice suggestions |

Let the actual exposure and data classification set the label, not the scariness of the control name. A benchmark deviation with no reachable impact is not automatically a High. Default to the lower band on a boundary.

### Common False Positives to Rule Out

- [ ] **Intentional static-site bucket:** A public bucket serving a static website is public by design. Confirm it holds only site assets before rating it, and say in the finding that you checked the contents.
- [ ] **Permissive SG behind a deny NACL:** An open security group is not reachable if a deny NACL, a private subnet route, or a higher-priority NSG deny rule sits in front. Read the full path before calling it exposed.
- [ ] **Out-of-scope shared-tenant services:** A config finding on a managed/shared service the provider owns, or on a tenant outside scope, is not the client's to fix. Confirm the resource is in scope and client-owned.
- [ ] **Block Public Access overrides a scary policy:** A permissive bucket policy is moot when account-level public-access block is on. Read the effective state, not just the policy.
- [ ] **Condition keys constrain the grant:** A broad-looking IAM/role statement may be tightly bound by `Condition` (source IP, MFA, tags, `ExternalId`). Read the whole statement before flagging the action.
- [ ] **Default-encrypted already:** Most providers encrypt at rest by default now. "No CMK" is only a finding where the data classification or benchmark actually requires customer-managed keys.

---

## Tools and References

| Tool | Use |
|---|---|
| Prowler | CIS/benchmark checks across AWS, Azure, and GCP; the default posture-review engine |
| ScoutSuite | Multi-cloud config audit into a single browsable HTML report |
| Steampipe / Powerpipe | SQL over cloud config plus packaged CIS benchmark mods for repeatable queries |
| CloudSploit | Open-source multi-cloud misconfiguration scanning |
| pmapper | IAM graph and privilege-path analysis (reads policy, maps standing escalation edges) |
| AWS Security Hub | Native AWS posture aggregation and CIS/FSBP standard scoring |
| Microsoft Defender for Cloud | Native Azure (and multi-cloud) secure-score and recommendations |
| GCP Security Command Center | Native GCP asset inventory, posture, and threat findings |
| cloudmapper | Network and exposure visualization for AWS environments |
| Nubicustos | Cairn's cloud posture auditing tool, used to run and consolidate the review |

Authoritative references:
- CIS Benchmarks for AWS Foundations, Microsoft Azure Foundations, and Google Cloud Platform Foundation: the control baseline this review scores against.
- AWS Well-Architected Framework Security Pillar.
- Microsoft Azure Well-Architected Framework security guidance and Microsoft cloud security benchmark.
- Google Cloud Architecture Framework security pillar and security foundations blueprint.

---

## Related

- Checklists: [AWS Cloud Penetration Test](AWS%20Cloud%20Penetration%20Test.md), [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md), [GCP Cloud Penetration Test](GCP%20Cloud%20Penetration%20Test.md), [Kubernetes and Containers](Kubernetes%20and%20Containers.md), [CICD Pipeline](CICD%20Pipeline.md)
- Cheatsheets: [AWS Pentest](../Cheatsheets/AWS%20Pentest.md), [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
- Playbooks: [AWS IMDS SSRF to Account Takeover](../Playbooks/AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md), [AWS Leaked Key to IAM Privilege Escalation](../Playbooks/AWS%20Leaked%20Key%20to%20IAM%20Privilege%20Escalation.md), [Poisoned CI Pipeline to Cloud Admin](../Playbooks/Poisoned%20CI%20Pipeline%20to%20Cloud%20Admin.md)
- Nubicustos: Cairn's cloud security auditing tool for running this review and exporting findings.

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
