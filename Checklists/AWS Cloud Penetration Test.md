---
tags:
  - hack-notes
  - checklist
  - cloud
  - aws
---

# AWS Cloud Penetration Test Testing Checklist

> Phased methodology for an authorized AWS cloud penetration test, from scoping through identity, compute, storage, network, privilege escalation, and contained persistence. Command detail and long payloads live in the [AWS Pentest](../Cheatsheets/AWS%20Pentest.md) cheatsheet; this note is the ordered method and pass/fail signals.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Recon and Asset Discovery](#2-recon-and-asset-discovery)
- [3. Identity and Access](#3-identity-and-access)
- [4. Compute and Metadata](#4-compute-and-metadata)
- [5. Storage and Data](#5-storage-and-data)
- [6. Network](#6-network)
- [7. Privilege Escalation and Lateral Movement](#7-privilege-escalation-and-lateral-movement)
- [8. Persistence and Impact](#8-persistence-and-impact)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

Get the paperwork right before touching a single API. AWS penetration testing has a permitted-services policy and a separate process for simulated events; testing outside it can breach the AWS Acceptable Use Policy and the customer contract.

### Authorization and AWS Policy

- [ ] **Written authorization:** Obtain a signed Rules of Engagement (RoE) from the account owner naming exact account IDs, regions, and services. No verbal scope.
- [ ] **AWS permitted-services check:** Confirm targets fall under the AWS Customer Support Policy for Penetration Testing (EC2, RDS, CloudFront, Aurora, API Gateway, Lambda, Lightsail, Elastic Beanstalk are permitted without prior approval). Pass = activity is on the permitted list.
- [ ] **Simulated-event approval:** For DDoS simulation, large network/load tests, or red-team simulation, submit the AWS Simulated Events form and wait for approval. Do not start until granted.
- [ ] **Prohibited activity exclusions:** Document that DNS zone walking, port flooding, protocol flooding, and request flooding against AWS-managed endpoints are out of scope per AWS policy.
- [ ] **Shared-responsibility boundary:** Confirm you are testing the customer's configuration and workloads, not the AWS substrate (hypervisor, control-plane internals). Underlying-infrastructure exploitation is out of scope.

### Test Profile and Safety

- [ ] **Credential model:** Record whether this is black-box (no creds, OSINT only), grey-box (assumed-cred / read-only audit role), or white-box (admin or SecurityAudit role). Set expectations accordingly.
- [ ] **Read-only vs mutating:** Agree which destructive actions are allowed. Default to read-only enumeration; gate any create/modify/delete behind explicit per-action approval.
- [ ] **Prod vs non-prod:** Identify which accounts are production. Prefer a dedicated test account or sandbox. If prod is in scope, agree blast-radius limits and a rollback owner.
- [ ] **Dedicated tester identity:** Use a clearly named IAM principal or role for the engagement (e.g. `pentest-2026`) so client-side CloudTrail attribution is unambiguous.
- [ ] **Source IP allow-list:** Provide testing source IPs/CIDRs so the client can distinguish test traffic from real attackers.
- [ ] **Emergency contacts and kill switch:** Record who to call, how to revoke the tester keys/role instantly, and the agreed pause signal.

### Logging and Detection Awareness

- [ ] **CloudTrail awareness:** Confirm whether CloudTrail (management and data events), GuardDuty, and Security Hub are enabled. Your actions will be logged. This is detection-aware testing, not stealth by default.
- [ ] **Detection scope decision:** Agree whether the engagement is purple (loud, full logging, validate detections) or evasion-aware (test what is detected). Most cloud pentests are purple.
- [ ] **Avoid log destruction:** Tampering with or deleting CloudTrail trails is generally out of scope unless explicitly authorized as a detection test, and even then prefer demonstrating the permission over executing it.

```
⚠️ Anti-forensic actions (StopLogging, DeleteTrail, PutBucketPolicy on a log
bucket, deleting GuardDuty detectors) are high-blast-radius and irreversible to
the client's audit trail. Demonstrate the *capability* (dry-run / permission
proof) rather than executing destruction. Get written sign-off before any
mutation of a logging or backup control.
```

---

## 2. Recon and Asset Discovery

Build the external picture and validate any creds before deep enumeration. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md) for the broader OSINT workflow and leaked-credential sourcing.

### Account and Org Footprint

- [ ] **Account ID discovery:** Resolve account IDs from any creds (`aws sts get-caller-identity`), from S3 bucket ACLs (canonical IDs), from ARNs in error messages, or from public resources.
- [ ] **Organization mapping:** If a management account or org-read role is available, enumerate accounts and OUs (`organizations:ListAccounts`, `DescribeOrganization`). Map the trust topology.
- [ ] **Region sweep:** Enumerate active regions; attackers and shadow resources hide in unused regions. Do not assume only us-east-1.

### Public Exposure and OSINT

- [ ] **Public S3 discovery:** Enumerate buckets by company name permutations and known patterns. Test listability and object read without creds. Tools: bucket brute-forcers, grayhatwarfare.
- [ ] **Public AMIs / snapshots / RDS snapshots:** Search for company-owned AMIs and EBS/RDS snapshots shared publicly or to a wide account list.
- [ ] **Exposed services:** Catalogue internet-facing EC2/ELB/CloudFront/API Gateway/Lightsail. Map DNS (Route 53, external) to public IPs and front-door endpoints.
- [ ] **Leaked credentials OSINT:** Hunt GitHub/GitLab/Postman/Docker layers/CI logs/pastes for `AKIA`/`ASIA` keys, `.aws/credentials`, and session tokens. Validate any hit with `get-caller-identity`. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md).
- [ ] **Key triage on discovery:** For each found key, immediately fingerprint it: `get-caller-identity` (who), then `enumerate-iam` (what). Record account, principal type, and whether it is long-lived (`AKIA`) or temporary (`ASIA`).
- [ ] **Public code / web app SSRF candidates:** Note any web apps in scope that could pivot to instance metadata (see Phase 4). Catalogue parameters that fetch URLs.

### Authenticated Situational Awareness

- [ ] **cloudfox baseline:** With read creds, run cloudfox `inventory` and `all-checks` to map what the principal can see across regions in minutes. Pass = full service inventory captured.
- [ ] **Config audit pass:** Run Prowler and/or ScoutSuite for a CIS-style misconfiguration baseline. Triage High/Critical first. These are findings, not exploits; validate before reporting.

---

## 3. Identity and Access

IAM is the real perimeter in AWS. Enumerate every principal, every policy, and every trust relationship.

### Principal and Policy Enumeration

- [ ] **Caller context:** `aws sts get-caller-identity` to confirm account, principal ARN, and type (user, assumed-role, root).
- [ ] **Permission enumeration:** Run `enumerate-iam` and/or Pacu `iam__enum_permissions` to brute the effective permissions when you cannot read your own policies directly.
- [ ] **Full IAM gather:** With sufficient rights, pull users, groups, roles, policies, instance profiles (`iam:GetAccountAuthorizationDetails` is the one-shot dump). Feed to a graph (PMapper, cloudfox).
- [ ] **Inline and managed policies:** Review attached managed, customer-managed, and inline policies on every principal. Inline policies are easy to miss and often over-permissive.
- [ ] **Resource policies:** Enumerate resource-based policies (S3 bucket policies, KMS key policies, Lambda resource policies, SQS/SNS, ECR). These grant cross-account access independent of IAM.
- [ ] **Wildcards and NotAction:** Flag `Action: "*"`, `Resource: "*"`, `Principal: "*"`, and `NotAction`/`NotResource` policies. These are the classic over-grants.

### Credential and Key Triage

- [ ] **Access key inventory:** List access keys per user, note age and last-used (`iam:GetAccessKeyLastUsed`). Stale active keys are findings.
- [ ] **MFA posture:** Identify users without MFA, especially those with console access or high privilege. Root MFA is mandatory.
- [ ] **Password policy:** Review the account password policy for weak length/rotation/reuse settings.
- [ ] **Temporary vs long-lived:** Distinguish `ASIA` STS sessions (expire) from `AKIA` long-lived keys. Long-lived keys on roles or service accounts are persistence-relevant.

### Trust, AssumeRole, and Federation

- [ ] **Trust policy review:** For every role, read the `AssumeRolePolicyDocument`. Flag overly broad `Principal` (whole accounts, `"*"`, external accounts) and missing `ExternalId`/`Condition` constraints.
- [ ] **AssumeRole chain mapping:** Map which principals can assume which roles, including cross-account chains. Build the directed graph of who-can-become-who.
- [ ] **Confused-deputy / ExternalId:** Test third-party trust roles for missing or guessable `ExternalId`. A vendor role trusting an external account without ExternalId is a cross-account takeover.
- [ ] **Federation and SSO:** Enumerate SAML/OIDC identity providers (`iam:ListSAMLProviders`, `ListOpenIDConnectProviders`). Review OIDC trust conditions (sub/aud) for GitHub Actions, EKS IRSA, and other federated roles. A loose `sub` condition is a cross-tenant assume.
- [ ] **Identity Center (SSO):** If AWS IAM Identity Center is in use, enumerate permission sets and account assignments. Note device-authorization phishing exposure (see Recent Techniques).
- [ ] **Privesc path scan:** Run Pacu `iam__privesc_scan` and PMapper to identify escalation edges from the current principal. Cross-check by hand; tooling produces both false positives and misses. See Phase 7 for the primitive list.

---

## 4. Compute and Metadata

Compute is where SSRF and code execution turn into cloud credentials. The instance metadata service is the pivot.

### EC2 and Instance Metadata

- [ ] **Instance inventory:** Enumerate EC2 instances, AMIs, security groups, key pairs, and attached instance profiles per region.
- [ ] **IMDS version per instance:** For each instance, determine whether IMDSv1 is still allowed (`HttpTokens: optional`) or IMDSv2 is required (`HttpTokens: required`). IMDSv1-allowed instances are the SSRF prize.
- [ ] **SSRF to credentials (IMDSv1):** Where an in-scope web app has SSRF, fetch role creds via the metadata path. Pass = valid `AccessKeyId`/`SecretAccessKey`/`Token` returned.

```http
GET /latest/meta-data/iam/security-credentials/<role-name> HTTP/1.1
Host: 169.254.169.254
```

- [ ] **IMDSv2 SSRF nuance:** IMDSv2 requires a PUT to mint a token and a custom header on the GET. Most SSRF cannot set headers, so IMDSv2 generally blocks it. Test for full-request SSRF, header-injection, or proxy gadgets that can issue the PUT and replay the token.

```http
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
```

- [ ] **Hop-limit and exfil:** Note `HttpPutResponseHopLimit`. A hop limit > 1 lets containers on the host reach IMDS, widening the blast radius.
- [ ] **Stolen-cred validation:** Take any harvested instance/role creds, set them, and run `get-caller-identity` then `enumerate-iam` to map the new identity's reach.

### User Data and Bootstrapping

- [ ] **User-data secrets:** Pull `GET /latest/user-data` (or `ec2:DescribeInstanceAttribute userData`). Bootstrapping scripts routinely embed passwords, API keys, and DB connection strings. Decode base64.
- [ ] **Launch templates / ASG configs:** Inspect launch templates and launch configurations for embedded secrets and weak IMDS defaults.

### Lambda

- [ ] **Function enumeration:** List functions, runtimes, and execution roles. Pull `GetFunction` code/layers where permitted.
- [ ] **Environment variables:** Read Lambda env vars for secrets (`lambda:GetFunctionConfiguration`). Unencrypted secrets in env vars are common.
- [ ] **Resource policy abuse:** Check Lambda resource policies for cross-account/public invoke. Note any function-URL endpoints with `AuthType: NONE`.
- [ ] **Privilege via overscoped role:** Note functions whose execution role exceeds need; combined with `lambda:UpdateFunctionCode` this is a privesc primitive (Phase 7).

### Containers, SSM, and Serverless Compute

- [ ] **ECS/Fargate task roles:** Enumerate task definitions and task roles. Containers fetch creds from the task-metadata endpoint (`169.254.170.2`); SSRF or RCE in a task yields the task role. Validate harvested creds.
- [ ] **ECR review:** Pull image inventory and scan layers for embedded secrets and over-permissive repository policies.
- [ ] **SSM-managed instances:** Enumerate `ssm:DescribeInstanceInformation`. SSM-managed instances with the right permissions allow command execution without SSH (see Phase 7 RCE-via-SSM).
- [ ] **SSM Parameter Store sweep:** Read parameters, especially `SecureString` values you can decrypt. Frequent home of DB and API credentials (covered in Phase 5).
- [ ] **EKS posture:** If EKS is in scope, enumerate clusters, access entries, and the workload-identity model (IRSA vs Pod Identity). Container-to-cloud pivots are detailed in [Kubernetes and Containers](Kubernetes%20and%20Containers.md) and Recent Techniques.

---

## 5. Storage and Data

Find the data and the keys to it. Misconfigured storage is still the most common high-impact AWS finding.

### S3

- [ ] **Bucket inventory and ACLs:** List buckets, then per bucket check the ACL, bucket policy, Block Public Access settings, and Object Ownership. Pass/fail = is any object readable or writable by anonymous or AuthenticatedUsers.
- [ ] **Public read/write test:** Test anonymous and any-authenticated-user read and write. Writable buckets enable web defacement, malware staging, and supply-chain poisoning of consumers.
- [ ] **Sensitive object hunting:** Sweep readable buckets for secrets, backups, `.env`, terraform state, DB dumps, and PII. Note versioned objects (old secrets persist in prior versions).
- [ ] **Bucket policy logic flaws:** Look for policies granting `s3:*` to broad principals, missing `aws:SecureTransport`, or conditions that fail open.

### Snapshots, Volumes, and Images

- [ ] **Public EBS snapshots:** Search for snapshots shared publicly or with the testing account. Restore to a volume, mount, and inspect for secrets and data.
- [ ] **Public RDS/Aurora snapshots:** Any account can copy a public RDS snapshot and stand up a DB from it. Test for company snapshots shared too widely. Restore in your test account if authorized.
- [ ] **Public AMIs:** Enumerate company AMIs marked public. Launch and inspect for baked-in secrets, keys, and source.
- [ ] **Snapshot permissions audit:** Review `createVolumePermission` / `restoreDbInstanceFromDbSnapshot` sharing on every snapshot.

### Secrets, Parameters, and Keys

- [ ] **Secrets Manager:** List and read secrets (`secretsmanager:GetSecretValue`). Note rotation status and resource policies allowing cross-account read.
- [ ] **SSM Parameter Store:** Read `SecureString` parameters where decrypt is allowed. Cross-reference with the KMS key that protects them.
- [ ] **KMS analysis:** Enumerate keys and key policies. A key policy granting `kms:Decrypt` to a broad principal undermines every secret it protects. Note keys whose policy lets a non-admin grant themselves use.
- [ ] **DynamoDB / RDS data:** Where read access exists, sample tables/databases for sensitive data to demonstrate impact (within RoE, minimal extraction).

---

## 6. Network

Map the exposed network surface and the controls that should be containing it.

### Security Groups and NACLs

- [ ] **Ingress audit:** Enumerate security groups for `0.0.0.0/0` ingress on sensitive ports (22, 3389, 3306, 5432, 6379, 9200, 27017). Open management/DB ports to the internet are findings.
- [ ] **Egress audit:** Review egress rules. Unrestricted egress eases exfiltration and C2; note it as a defense-in-depth gap.
- [ ] **NACL review:** Check network ACLs for overly permissive or contradictory rules that negate SG intent.

### VPC and Connectivity

- [ ] **VPC topology:** Map VPCs, subnets (public vs private), route tables, IGWs, NAT, VPC peering, and Transit Gateway. Peering/TGW are lateral-movement highways.
- [ ] **VPC endpoints:** Note interface/gateway endpoints and their policies; an over-permissive endpoint policy can broaden access to S3/DynamoDB.
- [ ] **Exposed managed services:** Identify public RDS/Aurora, ElastiCache, OpenSearch/Elasticsearch, and MQ endpoints. Test for public reachability and weak/default auth.
- [ ] **Load balancers and front doors:** Enumerate ALB/NLB/CloudFront/API Gateway. Check for direct-to-origin access bypassing WAF, and for misrouted internal services.
- [ ] **Route 53:** Review hosted zones for dangling records pointing at deprovisioned resources (subdomain takeover candidates).

---

## 7. Privilege Escalation and Lateral Movement

The core of an AWS pentest. Most escalation is an IAM permission combined with a service that runs code or assumes a role. Confirm each primitive against the current principal's actual permissions; do not just report the policy.

### PassRole-Based Primitives

`iam:PassRole` is harmless alone but lethal when paired with a service that runs the passed role. For each, the pattern is: find a privileged role you can pass, attach it to a resource you control, then harvest its credentials or run code as it.

| Primitive (required perms) | Mechanism | Proof of escalation |
| --- | --- | --- |
| `iam:PassRole` + `ec2:RunInstances` | Launch EC2 with a privileged instance profile | Pull role creds from IMDS on the new instance |
| `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Create a function with a privileged role, invoke it | Function executes AWS calls as the role |
| `iam:PassRole` + `glue:CreateDevEndpoint` / `CreateJob` | Glue endpoint/job runs as a passed role | Reverse shell or API calls as the role |
| `iam:PassRole` + `sagemaker:CreateNotebookInstance` | Notebook runs with a passed execution role | Read creds from the notebook's metadata |
| `iam:PassRole` + `ecs:RegisterTaskDefinition` + `RunTask` | Task runs with a passed task role | Harvest task role creds from task metadata |
| `iam:PassRole` + `cloudformation:CreateStack` | Stack deploys resources as a passed role | Provision a privileged resource you control |
| `iam:PassRole` + `datapipeline:CreatePipeline` | Pipeline activity runs as a passed role | Execute as the role |

### Pure-IAM Primitives

- [ ] **CreateAccessKey on another user:** `iam:CreateAccessKey` on a higher-priv user mints persistent creds for them.
- [ ] **CreateLoginProfile / UpdateLoginProfile:** Set or reset a console password for a privileged user.
- [ ] **Policy attach/put:** `iam:AttachUserPolicy` / `AttachRolePolicy` / `PutUserPolicy` to attach `AdministratorAccess` or a custom allow-all.
- [ ] **CreatePolicyVersion:** `iam:CreatePolicyVersion` with `SetAsDefault` rewrites an existing managed policy you are attached to.
- [ ] **Group manipulation:** `iam:AddUserToGroup` to join an admin group.
- [ ] **UpdateAssumeRolePolicy:** `iam:UpdateAssumeRolePolicy` to add yourself as a trusted principal on a privileged role, then assume it.

### Service and Code-Execution Primitives

- [ ] **Lambda code update:** `lambda:UpdateFunctionCode` on a function with a privileged role lets you run arbitrary code as that role.
- [ ] **RCE via SSM:** `ssm:SendCommand` (or `StartSession`) against managed instances runs commands as the SSM agent user (often root). Map managed instances and their instance-profile roles; this is both RCE and a credential-harvest path.
- [ ] **EC2 Instance Connect / serial console:** `ec2-instance-connect:SendSSHPublicKey` or serial-console access to reach an instance and its role.
- [ ] **STS chaining:** Walk the AssumeRole graph from Phase 3. Chain assume-role hops, including cross-account, to reach higher privilege. Watch for roles that can assume back into the source account.

### Cross-Account and Lateral Movement

- [ ] **Cross-account assume:** Use trust-policy weaknesses (broad Principal, missing ExternalId) to assume roles in peer/management accounts.
- [ ] **Org-wide pivot:** From a management account or a role assumable org-wide, enumerate and reach member accounts. Note `OrganizationAccountAccessRole` reachability.
- [ ] **Resource-policy lateral:** Use S3/KMS/SQS/SNS/Secrets resource policies that trust external principals to read data or assume identity across accounts.
- [ ] **Compute-to-cloud pivot:** Convert RCE on EC2/ECS/EKS into cloud creds via metadata, then re-enumerate as the new identity. Repeat the IAM enumeration loop each time identity changes. See [Kubernetes and Containers](Kubernetes%20and%20Containers.md) for EKS specifics and [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md) for network pivots.

```
⚠️ Privilege-escalation primitives that ATTACH admin policies, CREATE keys, or
REWRITE trust policies are mutating and persistent. Prefer proving the primitive
in an isolated test role/account, or demonstrate via the permission + a minimal
benign action. Always record exactly what you created so it can be cleaned up.
```

---

## 8. Persistence and Impact

Demonstrate impact within RoE, then ensure everything you created is documented for cleanup. Persistence is shown, not abandoned in the environment.

### Persistence Techniques (demonstrate, do not abandon)

- [ ] **Backdoor IAM user/key:** Show that `iam:CreateUser` + `CreateAccessKey` yields out-of-band persistence. Tag it clearly and remove it after evidence.
- [ ] **Role trust backdoor:** Show `UpdateAssumeRolePolicy` adding an attacker principal as a persistent re-entry path.
- [ ] **Lambda / EventBridge trigger:** Note that a scheduled Lambda or EventBridge rule can re-mint creds on a timer. Describe rather than deploy unless authorized.
- [ ] **Console-to-CLI / federation token:** Demonstrate minting long-lived access from a session (e.g. creating keys for an assumed identity that has the right).
- [ ] **Identity Center persistence:** Note that an IdP change or new permission-set assignment grants durable access if Identity Center is compromised.

### Impact Demonstration

- [ ] **Data access proof:** Capture minimal, sanitized evidence of access to sensitive data (object listing, redacted record). Do not exfiltrate at scale.
- [ ] **Blast-radius summary:** Document the highest privilege reached and what it could touch (delete, ransom, exfiltrate) without executing destructive actions.

### Detection-Evasion Awareness

- [ ] **CloudTrail visibility:** Note which of your actions were management vs data events and whether data-event logging was on. Gaps in data-event logging are a finding.
- [ ] **Region and service blind spots:** Note regions/services without CloudTrail or GuardDuty coverage; attackers operate there.
- [ ] **GuardDuty/Detective signal:** Where the client consents, correlate which of your actions generated GuardDuty findings (purple-team value). Report undetected high-risk actions.
- [ ] **Anti-forensic capability (do not execute):** If you hold `cloudtrail:StopLogging` or log-bucket write, report the capability. Do not destroy the audit trail. Refer to the warning in Phase 1.

### Cleanup

- [ ] **Inventory of changes:** Maintain a running list of every created/modified resource (users, keys, roles, policies, instances, functions, snapshots).
- [ ] **Tear down and confirm:** Remove all test artifacts and confirm deletion. Hand the client the change inventory for independent verification.

---

## Recent Techniques (2024-2026)

- [ ] **Identity Center / SSO device-code phishing:** Abuse `sso-oidc:CreateToken` device-authorization flow to phish an SSO access token, then list accounts/roles and assume any of them, bypassing MFA and IP allow-listing. In-the-wild since Aug 2024 (Storm-2372) and now in criminal PhaaS kits. Test for: device-auth flow enabled, no documented token revocation, users phishable.
- [ ] **`aws login` PKCE flow phishing:** The newer PKCE-based SSO login still phishable in variants. Test for: users redirected to attacker-controlled callback during the new login flow.
- [ ] **EKS Access Entries takeover:** With `eks:CreateAccessEntry` + `AssociateAccessPolicy`, attach `AmazonEKSClusterAdminPolicy` to yourself for full cluster takeover via the cloud API, bypassing aws-auth ConfigMap. Test for: Access Entries API in use and those IAM perms reachable.
- [ ] **EKS Pod Identity credential sniffing:** Pods using EKS Pod Identity with `hostNetwork: true` can sniff plaintext creds from the unencrypted local agent endpoint, or disable the legitimate endpoint and impersonate it (Wiz/researcher disclosures, 2025). Test for: hostNetwork pods, elevated NET_RAW/CAP, Pod Identity in use.
- [ ] **IRSA / Pod Identity token theft:** Service-account JWTs and projected tokens on a compromised pod filesystem assume the mapped IAM role, turning one web-app RCE into cloud takeover. Test for: readable token files, overscoped IRSA trust `sub` conditions.
- [ ] **IMDSv1-via-SSRF persistence in real breaches:** SSRF-to-IMDS remained a top EC2 vector through 2025 to 2026 (e.g. LexisNexis Feb 2026, Grafana SSRF campaigns). Test for: any IMDSv1-allowed instance behind an app with SSRF.
- [ ] **SSE-C ransomware (Codefinger):** Attackers with S3 write and compromised creds re-encrypt objects with a customer-provided key (SSE-C), holding data hostage (Jan 2025). Test for: creds with `s3:PutObject` on data buckets, no bucket versioning/Object Lock.
- [ ] **Bucket Monopoly / predictable bucket names:** Services (CloudFormation, Glue, EMR, SageMaker, ServiceCatalog, CodeStar) auto-create predictably named S3 buckets; pre-claiming the name in an unused region hijacks resources. Test for: predictable account-scoped bucket names not pre-created in all regions.
- [ ] **ECS container escape (CVE-2026-7461):** OS command injection in amazon-ecs-agent path leading to host SYSTEM on Windows EC2. Test for: vulnerable ecs-agent version, untrusted input reaching task config.
- [ ] **AWS RES critical RCE + privesc (2025):** AWS Research and Engineering Studio patched critical RCE and privilege escalation. Test for: self-managed RES deployments at vulnerable versions.
- [ ] **Bedrock / AgentCore orchestration privesc:** AI orchestration services with broad execution roles create new PassRole-style escalation surfaces. Test for: Bedrock Agents/AgentCore with overscoped service roles.
- [ ] **Org Declarative Policies for IMDSv2 (Dec 2024):** Defenders can now enforce IMDSv2 org-wide. Validate enforcement: instances should reject IMDSv1; absence of the declarative/SCP control is a finding.

---

## Reporting and Evidence

### Evidence to Capture per Finding

- [ ] **Identity proof:** `aws sts get-caller-identity` output showing the principal used, before and after escalation.
- [ ] **Permission proof:** The exact policy/permission enabling the issue (policy JSON, trust document, SG rule).
- [ ] **Reproduction:** The minimal command or request and its response. Save raw request/response pairs or screenshots; do not rely on memory.
- [ ] **Impact proof:** Redacted evidence of the data or capability reached (object listing, decrypted secret name not value where possible).
- [ ] **Account/region/ARN:** Every finding tagged with account ID, region, and resource ARN.
- [ ] **Timeline:** Action timestamps so the client can correlate with CloudTrail.

### Severity Guidance

| Severity | Examples |
| --- | --- |
| Critical | Path to org/account admin; public write to prod data bucket; cross-account takeover; cluster-admin via API; long-lived admin keys leaked |
| High | Privilege escalation to a powerful role; SSRF-to-IMDS credential theft; readable secrets/snapshots with sensitive data; public RDS with weak auth |
| Medium | Over-permissive but non-admin roles; IMDSv1 allowed without known SSRF; public read of non-sensitive S3; missing MFA on low-priv users |
| Low | Stale keys, password-policy weakness, unrestricted egress, missing data-event logging, defense-in-depth gaps |

### Common False Positives to Rule Out

- [ ] **Tool-reported privesc edges:** Pacu/PMapper edges can be false; confirm the principal actually holds every required permission and no SCP/permission-boundary/Deny blocks it.
- [ ] **SCP and permission boundaries:** An IAM allow can be overridden by an SCP, a permissions boundary, or a session policy. Validate the effective permission, not just the identity policy.
- [ ] **Block Public Access:** A permissive bucket policy is moot if account/bucket Block Public Access is on. Test the actual anonymous request.
- [ ] **IMDSv2 SSRF claims:** Do not report SSRF-to-IMDS as confirmed against an IMDSv2-required instance unless you demonstrably issued the PUT and replayed the token.
- [ ] **Public snapshot scope:** Confirm a snapshot is truly public (or shared to your account) by restoring it, not just by a sharing flag.
- [ ] **Condition keys:** A scary-looking action may be tightly constrained by `Condition` (source IP, MFA, tags). Read the whole statement.

---

## Tools and References

| Tool | Use |
| --- | --- |
| Pacu | Modular AWS exploitation framework: enum, `iam__privesc_scan`, persistence, data exfil |
| ScoutSuite | Multi-cloud config audit, single HTML report of misconfigurations |
| Prowler | CIS/NIST/compliance checks across IAM/S3/EC2 and 100+ controls |
| cloudfox | Fast situational awareness for manual pentesting (inventory, attack-path data) |
| enumerate-iam | Brute-force effective permissions of a key without reading policies |
| PMapper | IAM graph and privilege-escalation path analysis |
| awscli / aws-vault | Primary API client and safe credential handling |
| trufflehog / gitleaks | Secret hunting in repos, layers, and CI for leaked keys |

- AWS Customer Support Policy for Penetration Testing and the Simulated Events form (authoritative scope source).
- Hacking the Cloud (hackingthe.cloud) and HackTricks Cloud for AWS exploitation technique reference.
- Rhino Security Labs AWS IAM Privilege Escalation series (PassRole and pure-IAM primitives).
- AWS Security Blog (IMDSv2 defense-in-depth, Declarative Policies) for control validation.
- CIS AWS Foundations Benchmark for baseline expectations.

---

## Related

- Playbooks: [AWS IMDS SSRF to Account Takeover](../Playbooks/AWS%20IMDS%20SSRF%20to%20Account%20Takeover.md), [AWS Leaked Key to IAM Privilege Escalation](../Playbooks/AWS%20Leaked%20Key%20to%20IAM%20Privilege%20Escalation.md)
- [AWS Pentest](../Cheatsheets/AWS%20Pentest.md)
- [Azure and Entra ID](../Cheatsheets/Azure%20and%20Entra%20ID.md)
- [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md)
- [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)
- Cepheus
- Vinculum
- Caminus

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
