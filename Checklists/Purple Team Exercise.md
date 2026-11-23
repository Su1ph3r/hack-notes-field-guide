---
tags:
  - hack-notes
  - checklist
  - purple-team
---

# Purple Team Exercise Checklist

> Collaborative, detection-focused exercise built around MITRE ATT&CK. Red and blue sit in the same room and run agreed techniques to measure what the defense sees, then build and re-test detections for what it missed. The deliverable is a coverage heat map, time-to-detect / time-to-respond metrics, and tuned detections, not a list of popped boxes. Commands and payloads live in the linked cheatsheets; this is the ordered method, the per-technique pass signal, and the evidence to bank.

## Table of Contents
- [1. Scoping and Objectives](#1-scoping-and-objectives)
- [2. Planning and ATT&CK Mapping](#2-planning-and-attck-mapping)
- [3. Telemetry and Environment Prep](#3-telemetry-and-environment-prep)
- [4. Execution by ATT&CK Tactic](#4-execution-by-attck-tactic)
- [5. Detection Engineering Loop](#5-detection-engineering-loop)
- [6. Response Validation](#6-response-validation)
- [7. Scoring and Coverage](#7-scoring-and-coverage)
- [Recent Techniques (2024-2026)](#recent-techniques-2024-2026)
- [Reporting and Evidence](#reporting-and-evidence)
- [Tools and References](#tools-and-references)
- [Related](#related)

---

## 1. Scoping and Objectives

A purple team is not a red team with an audience. The point is to improve detection and response, so success is measured in detections built and coverage gained, not boxes reached. Set that framing in the kickoff or the exercise drifts into a capture-the-flag that nobody can learn from.

### Framing and Success Criteria

- [ ] **Collaborative, not adversarial:** Red narrates what it is about to do and when. Blue watches live. The goal is shared understanding of coverage, so hiding the technique defeats the purpose. Save covert operating for a separate red-team engagement.
- [ ] **Define success as coverage, not compromise:** State it in writing. Success = each planned technique exercised, its detection outcome recorded, and every gap either closed with a tuned detection or logged as an accepted risk with an owner.
- [ ] **Pick the threat model:** Emulate a specific actor relevant to the client (ransomware affiliate, Scattered Spider-style intrusion, an insider) or a tactic-by-tactic sweep. Named-actor emulation is more useful when the client has real threat intel; a tactic sweep is better for a first exercise with no baseline.
- [ ] **Agree the per-technique flag:** For each technique, define up front what counts: a raw log event, a fired alert, an analyst action, or a contain. Write it down. "We will know it when we see it" produces arguments at scoring time.
- [ ] **Set the time budget realistically:** The detection-engineering loop is the slow part. A plan with sixty techniques and no time to build and re-test detections produces a findings list, not improvement. Cut the technique count before you cut the loop.

### Stakeholders and Logistics

- [ ] **Name the participants:** Red operators, blue/SOC analysts, a detection engineer who can write and deploy rules during the exercise, and a white-cell lead who adjudicates. A purple exercise with no detection engineer in the room cannot close gaps; it only finds them.
- [ ] **Confirm authorization and window:** Written, dated, signed by someone with authority over the systems and the SIEM/EDR. Agree the dates, hours, and whether this runs in a lab, in prod, or both.
- [ ] **Agree a stop condition:** When does a technique get paused (prod instability, a real incident surfaces, an uncontrolled alert storm reaching on-call)? A purple exercise can still break things; name the off-ramp before you start.
- [ ] **Agree what the blue team may NOT do in advance:** Pre-tuning detections for the exact techniques on the plan inflates coverage. If the aim is to measure the current posture, freeze detection content until a baseline run is recorded.

### Known Pitfalls at Scoping

- [ ] **Logged is not detected:** Decide now that a technique producing only raw telemetry with no alert scores as logged-only, not detected. Conflating the two is the single most common way a purple report overstates coverage.
- [ ] **A green lab is not a green prod:** A detection proven in a test tenant tells you nothing about prod unless prod ingests the same data source. Track lab and prod outcomes separately from the first technique.
- [ ] **Agree the benign stand-in for every harmful step:** Decide now how each destructive or sensitive technique is emulated without the harm (marker files for encryption, a disposable account for manipulation, a consenting mailbox for collection). Settling this at scoping avoids a mid-run argument about whether a step is safe to fire.

---

## 2. Planning and ATT&CK Mapping

Turn the threat model into a concrete, ordered test plan where every technique names the detection it is meant to trigger and the data source that detection reads. A plan that lists techniques but not their intended detections cannot be scored; it is a to-do list, not an experiment.

### Technique Selection and Mapping

- [ ] **Select techniques from the threat model:** Pull the actor's known TTPs from ATT&CK (or the group page) and the client's own incident history. Favor techniques the client is likely to face over an exhaustive matrix; depth on a realistic chain beats one shallow test per cell.
- [ ] **Map each technique to its intended detection and data source:** For every planned technique, record the ATT&CK ID, the data source that should capture it (process creation, EDR telemetry, Windows Security / Sysmon channel, cloud audit log, network/NDR), and the specific rule expected to fire. This table is the backbone of scoring.
- [ ] **Flag techniques with no planned detection:** If a technique has no mapped detection, that is a known coverage gap before you run anything. Mark it; it is a candidate for the detection-engineering loop, not a surprise at scoring.
- [ ] **Agree the run order:** Sequence techniques so the exercise reads as a plausible intrusion (initial access, execution, persistence, privesc, and on) rather than random cells. A coherent chain also tests whether the SOC correlates related alerts into one incident.

### Test Plan and Atomics

- [ ] **Cross-check the plan against available data sources:** For each planned detection, confirm the data source it reads is one the environment collects. A plan full of detections that depend on uncollected logs measures the logging program, not the SOC. Reconcile this with Phase 3 before you run.
- [ ] **Build the plan in VECTR (or equivalent):** Record each technique, the atomic test or procedure that executes it, the expected detection, and a blank outcome field. VECTR is purpose-built for tracking purple results technique-by-technique over repeat exercises; a shared spreadsheet works for a one-off.
- [ ] **Pick the execution procedure per technique:** Atomic Red Team test, a Caldera ability, a Prelude Operator chain, or a hand-run procedure. Prefer a named Atomic over a bespoke script so the test is reproducible on the re-run.
- [ ] **Pin procedure variants to the real behavior:** One ATT&CK technique has many procedures. A detection that catches `reg.exe` adding a Run key may miss the same key written through a direct registry API. Note which variant you ran so coverage is not overclaimed for the whole technique.
- [ ] **Agree a rollback and cleanup step per technique:** Every atomic that writes a key, creates a task, or adds an account needs a teardown. Atomic Red Team ships cleanup commands; confirm they ran. An orphaned persistence artifact from the exercise is a finding you caused.

```bash
# Anchor only; full tooling in cheatsheet.
# Atomic Red Team: run one test for a mapped technique, then check telemetry.
Invoke-AtomicTest T1547.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1547.001 -TestNumbers 1
# Record: did process-creation logging capture it, did a rule fire, when.
```

---

## 3. Telemetry and Environment Prep

Confirm the defense can actually see before you spend a day proving it cannot. A missed technique caused by a broken log pipeline is a data-collection bug, not a detection gap, and the two have different owners and different fixes.

### Ingest and Visibility Validation

- [ ] **Confirm each mapped data source is actually ingesting:** Generate one benign event per planned data source and confirm it lands in the SIEM/EDR within the expected delay. A source that silently stopped forwarding last month will read as a detection gap across every technique that depends on it.
- [ ] **Check log scope and retention:** Confirm command-line capture, PowerShell script-block logging, Sysmon (or the EDR equivalent), and cloud audit logs are on for the hosts and accounts in scope, with retention long enough to query during scoring.
- [ ] **Map visibility gaps before you start:** List hosts, network segments, and identity planes with no EDR or no log forwarding. Techniques run there will be invisible for a reason that has nothing to do with rule quality. Record these as collection gaps separate from detection gaps.
- [ ] **Baseline the noise:** Capture what normal looks like on the target hosts so a tuned rule can be checked against benign activity later. A rule that fires on the technique and on everyday admin work is not a detection you can ship.
- [ ] **Confirm time sync and clock skew:** MTTD is action time to alert time. If the operator host, the endpoint, and the SIEM disagree on the clock, every metric is wrong. Confirm NTP sync across the measured systems before the first technique.
- [ ] **Verify the detection platform is in a measurable state:** No suppression rules, maintenance windows, or bulk auto-close jobs silently swallowing alerts during the exercise. A suppressed alert reads as a miss for a reason unrelated to the rule.

### Environment and Deconfliction

- [ ] **Decide lab vs prod per technique:** Destructive or high-blast-radius techniques (anything in Impact, driver loading, credential-store access on a DC) belong in a representative lab unless the client explicitly accepts prod risk. Low-risk telemetry tests can run in prod to measure the real pipeline.
- [ ] **Stand up a live deconfliction channel:** An out-of-band channel (Signal, a dedicated bridge) where red announces each technique as it fires and blue confirms receipt. This is also the real-time activity log: source host, account, timestamp, ATT&CK ID per action.
- [ ] **Agree who is read-in:** In a true purple exercise the SOC analysts in the room are aware. If part of the floor is kept blind to also measure unprimed response, name exactly who is and is not read-in, and keep the deconfliction channel off the blind analysts' systems.

```
⚠️ Run Impact-tactic techniques (encryption, service stop, recovery inhibition, account
removal) only in a lab or against disposable hosts with written sign-off. Emulate the behavior
with a benign marker; never encrypt or delete real data to "test the detection".
```

---

## 4. Execution by ATT&CK Tactic

Run the plan tactic by tactic. For every technique the loop is the same: fire it, confirm telemetry captured it, check whether a detection fired, record the time-to-detect, and note the response action. Each checkbox below pairs the attacker action with that detection question. A technique that produced a log but no alert is logged-only, and that distinction is the whole point of the exercise.

### Initial Access (TA0001)

- [ ] **Spearphishing link/attachment (T1566.001 / T1566.002):** Deliver a benign tracked lure to a consenting mailbox, then confirm mail-security telemetry captured it, whether a detection fired on delivery or click, time-to-detect, and whether the user-report path was exercised.
- [ ] **Valid accounts against external auth (T1078):** Log in to VPN/M365/SSO with a provisioned test credential, then confirm sign-in logs captured it, whether impossible-travel or new-device logic fired, time-to-detect, and the response action.
- [ ] **Exploit public-facing application (T1190):** Run an agreed, non-destructive exploit against an in-scope edge service in the lab, then confirm WAF/app/EDR telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **External remote services (T1133):** Access an exposed RDP/VPN/gateway with test creds, then confirm the auth and session telemetry captured it, whether a rule fired, time-to-detect, and the response.
- [ ] **Trusted-relationship / supply-chain access (T1199):** Enter through an agreed contractor or managed-provider path, then confirm the third-party access telemetry captured it, whether a detection fired on the unusual source, time-to-detect, and the response.

### Execution (TA0002)

- [ ] **PowerShell (T1059.001):** Run an encoded and a plain post-ex command, then confirm script-block logging captured both, whether a detection fired on either, time-to-detect, and the response. Test both variants; a rule keying on `-enc` misses the plain form.
- [ ] **Windows command shell / scripting (T1059.003):** Execute a representative `cmd.exe` chain, then confirm command-line logging captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **User execution of a loader (T1204):** Detonate a benign loader as a user would, then confirm process-creation and EDR telemetry captured the parent/child chain, whether a detection fired, time-to-detect, and the response.
- [ ] **WMI / scripting execution (T1047):** Run a WMI-based command, then confirm WMI-activity and command-line telemetry captured it, whether a detection fired, time-to-detect, and the response. Default logging misses a lot of WMI; this is a common blind spot.

### Persistence (TA0003)

- [ ] **Registry Run key / startup folder (T1547.001):** Write the key, then confirm registry/process telemetry captured it, whether a detection fired, time-to-detect, and the response. Run both the `reg.exe` and the direct-API variant.
- [ ] **Scheduled task (T1053.005):** Create a task, then confirm task-creation (event ID / EDR) telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Windows service (T1543.003):** Install a service, then confirm service-install telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **WMI event subscription (T1546.003):** Register the subscription, then confirm WMI-activity telemetry captured it, whether a detection fired (these often slip through default logging), time-to-detect, and the response.
- [ ] **Create account (T1136):** Add a local or domain account, then confirm account-creation telemetry (EID 4720 / 4728) captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Account manipulation (T1098):** Add an account to a privileged group or register a new credential/app secret, then confirm the directory/identity audit log captured it, whether a detection fired, time-to-detect, and the response.

### Privilege Escalation (TA0004)

- [ ] **Bypass UAC (T1548.002):** Run an agreed UAC-bypass procedure, then confirm the elevation telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Access token manipulation (T1134):** Perform token theft/impersonation, then confirm EDR captured the token operation, whether a detection fired, time-to-detect, and the response.
- [ ] **Exploitation for privilege escalation (T1068):** Run an agreed local exploit in the lab, then confirm telemetry captured the crash/behavior, whether a detection fired, time-to-detect, and the response.

### Defense Evasion (TA0005)

- [ ] **Impair defenses / disable tools (T1562.001):** Attempt to stop or blind the EDR/AV or a log source, then confirm tamper telemetry captured it, whether a detection fired, time-to-detect, and the response. A tamper attempt that produces no alert is a priority gap.
- [ ] **Clear Windows event logs (T1070.001):** Clear a log, then confirm the log-cleared event (EID 1102 / 104) was captured upstream before deletion, whether a detection fired, time-to-detect, and the response.
- [ ] **Signed binary proxy execution / LOLBins (T1218):** Execute via `rundll32`, `regsvr32`, `mshta`, or `msbuild`, then confirm command-line and module-load telemetry captured it, whether a detection fired on the specific binary and args, time-to-detect, and the response.
- [ ] **Process injection (T1055):** Run an agreed injection procedure, then confirm EDR captured the cross-process operation, whether a detection fired, time-to-detect, and the response.
- [ ] **Deobfuscate / decode files (T1140):** Stage and decode an obfuscated payload, then confirm telemetry captured the decode step and the written artifact, whether a detection fired, time-to-detect, and the response.

### Credential Access (TA0006)

- [ ] **LSASS memory access (T1003.001):** Access LSASS with an agreed method, then confirm process-access telemetry captured the handle to lsass.exe, whether a detection fired, time-to-detect, and the response. This is one of the most-monitored actions in a modern stack; a miss here is significant.
- [ ] **Kerberoasting (T1558.003):** Request service tickets for roastable accounts, then confirm Kerberos TGS telemetry (EID 4769, encryption type) captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Credentials from browsers (T1555.003):** Harvest browser-stored secrets, then confirm file/process telemetry captured the access, whether a detection fired, time-to-detect, and the response.
- [ ] **MFA request generation / push bombing (T1621):** Trigger repeated MFA prompts against a test account, then confirm identity-provider logs captured the burst, whether a detection fired, time-to-detect, and the response.
- [ ] **Password spraying (T1110.003):** Spray a small, slow set against in-scope auth, then confirm auth logs captured the pattern, whether a detection fired across accounts (not just per-account lockout), time-to-detect, and the response.
- [ ] **Unsecured credentials (T1552):** Hunt for creds in files, scripts, registry, and CI/CD config on a target host, then confirm file/process telemetry captured the access, whether a detection fired, time-to-detect, and the response. Usually logged-only; prove it either way.
- [ ] **Steal application access token (T1528):** Request or replay an OAuth/app token against a test tenant, then confirm identity-provider telemetry captured it, whether a detection fired on the grant, time-to-detect, and the response. Token theft sidesteps MFA, so detection here matters more than password-focused rules.

### Discovery (TA0007)

- [ ] **System information / process discovery (T1082, T1057):** Run host and process enumeration, then confirm command-line telemetry captured it, whether a detection fired (usually logged-only), time-to-detect, and the response. Record it as a baseline for later behavioral correlation.
- [ ] **Account / domain discovery (T1087, T1482):** Enumerate users, groups, and trusts, then confirm the directory-query telemetry captured it, whether a detection fired (discovery is usually logged-only, and that is worth proving), time-to-detect, and the response.
- [ ] **Remote system / network service discovery (T1018, T1046):** Run a quiet host/port sweep on a monitored segment, then confirm network/NDR telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Permission groups discovery (T1069):** Enumerate local and domain group membership, then confirm the query telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **AD mapping (BloodHound-class collection):** Run SharpHound-style collection, then confirm LDAP/query telemetry captured the volume, whether a detection fired, time-to-detect, and the response.

### Lateral Movement (TA0008)

- [ ] **Remote services: RDP/SMB/WinRM (T1021.001 / .002 / .006):** Move host to host with the agreed primitive, then confirm logon-type and remote-exec telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Pass the hash / pass the ticket (T1550.002 / T1550.003):** Reuse credential material to authenticate, then confirm the logon telemetry captured the anomaly, whether a detection fired, time-to-detect, and the response.
- [ ] **Exploitation of remote services (T1210):** Run an agreed internal service exploit in the lab, then confirm telemetry captured the behavior, whether a detection fired, time-to-detect, and the response.
- [ ] **Lateral tool transfer (T1570):** Copy tooling to the next host, then confirm file-write/network telemetry captured it, whether a detection fired, time-to-detect, and the response.

### Collection (TA0009)

- [ ] **Data from local system / repositories (T1005, T1213):** Stage benign marker files from a target host or share, then confirm file-access telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Archive collected data (T1560):** Compress the staged marker set, then confirm process/file telemetry captured the archive step, whether a detection fired, time-to-detect, and the response.
- [ ] **Data from cloud storage / SaaS (T1530):** Pull a benign marker from an in-scope cloud bucket or SaaS store, then confirm the cloud audit log captured the access, whether a detection fired, time-to-detect, and the response.
- [ ] **Email collection (T1114):** Pull from a consenting test mailbox, then confirm mailbox-audit telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Steal web session cookie (T1539):** Lift a session cookie from a consenting test browser, then confirm the telemetry captured the access, whether a detection fired, time-to-detect, and the response.

### Command and Control (TA0011)

- [ ] **Web-protocol C2 (T1071.001):** Beacon over HTTPS through a redirector, then confirm proxy/NDR telemetry captured the pattern, whether a detection fired on beacon cadence or destination reputation, time-to-detect, and the response.
- [ ] **DNS C2 (T1071.004):** Run a DNS channel, then confirm DNS logging captured the query volume/entropy, whether a detection fired, time-to-detect, and the response.
- [ ] **Domain fronting / reputable-domain C2 (T1090.004):** Front beacon traffic behind a high-reputation domain, then confirm egress telemetry captured the SNI/Host mismatch, whether a detection fired, time-to-detect, and the response.
- [ ] **Protocol tunneling / encrypted channel (T1572, T1573):** Tunnel traffic through an allowed protocol, then confirm egress telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Ingress tool transfer (T1105):** Pull a benign tool down over the channel, then confirm file-write/network telemetry captured it, whether a detection fired, time-to-detect, and the response.

### Exfiltration (TA0010)

- [ ] **Exfil over C2 channel (T1041):** Send a benign marker file out over the beacon, then confirm DLP/egress telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Exfil to cloud storage (T1567.002):** Upload the marker to attacker-controlled cloud storage, then confirm proxy/CASB telemetry captured it, whether DLP blocked or alerted, time-to-detect, and the response. Whether DLP fired is itself a primary result.
- [ ] **Exfil over alternative protocol (T1048):** Push the marker over DNS or an alternate port, then confirm egress telemetry captured it, whether a detection fired, time-to-detect, and the response.

### Impact (TA0040): lab or disposable hosts only

- [ ] **Data encrypted for impact (T1486), emulated:** Run a benign ransomware-behavior emulation (mass read/write of marker files, no real encryption), then confirm EDR captured the behavioral pattern, whether a detection fired, time-to-detect, and the response.
- [ ] **Inhibit system recovery (T1490):** Attempt an agreed recovery-inhibition action on a disposable host (shadow-copy deletion), then confirm telemetry captured the command, whether a detection fired, time-to-detect, and the response.
- [ ] **Service stop (T1489):** Stop an agreed service on a lab host, then confirm telemetry captured it, whether a detection fired, time-to-detect, and the response.
- [ ] **Account access removal (T1531):** Disable or lock a disposable test account, then confirm identity telemetry captured it, whether a detection fired, time-to-detect, and the response.

---

## 5. Detection Engineering Loop

For every gap, build or tune a detection, then re-run the exact technique to prove the rule fires on the real activity and stays quiet on the baseline. A detection you wrote but did not re-run is a hypothesis, not a control. This loop is where a purple exercise produces value a vulnerability scan cannot.

- [ ] **Prefer behavioral over brittle string matches:** A rule keyed on a tool name or a single string dies the moment the attacker renames the binary. Where the telemetry allows, key on the behavior (parent/child chain, API sequence, event combination) so the detection survives a trivial variant. Close the technique class, not the one spelling you happened to run.
- [ ] **Write the detection against the observed telemetry:** Build the rule from the fields the technique actually produced (process ancestry, command-line tokens, event IDs, destination), not from a blog example that assumes a data source this environment may not have.
- [ ] **Deploy to the live detection platform:** Push the rule to the client SIEM/EDR, not a notebook. A rule that never reached production is not coverage.
- [ ] **Re-run the exact technique and variant:** Fire the same Atomic/procedure again and confirm the new rule alerts. Same variant: a rule proven against `reg.exe` has not been proven against the direct-API variant you also ran.
- [ ] **Test against the benign baseline:** Replay the normal-activity sample captured in Phase 3 and confirm the rule does not fire on it. A rule that catches the technique and daily admin work will be disabled by the SOC within a week.
- [ ] **Record the before/after:** Capture the technique with no alert, the rule, and the technique with the alert firing. That triplet is the evidence that the gap is closed.
- [ ] **Revert-test the rule (optional but strong):** Disable the rule and confirm the technique goes undetected again, then re-enable. This proves the alert came from your rule and not from unrelated content that was already present.
- [ ] **Hand off ownership:** Assign each shipped detection to a named owner with a maintenance note (data-source dependency, expected false-positive sources). An orphaned rule rots.
- [ ] **Decide detect vs prevent per gap:** Some gaps close better with a control change (block the LOLBin, enforce number-matching, disable the legacy auth path) than a detection. Record which gaps the client chose to prevent rather than detect, so the heat map reflects the real posture.
- [ ] **Capture the data-source dependency explicitly:** A rule that silently depends on a log source someone may turn off is fragile. Note the dependency on the rule so a later pipeline change does not quietly reopen the gap.
- [ ] **Convert Sigma to the real query language and check it there:** A Sigma rule is portable intent, not a deployed control. Convert it to the client's SIEM query, run it against live data, and confirm it matches before counting the gap closed. Field names and parsing differ per platform and silently break naive conversions.

```
⚠️ A rule tuned only against the atomic test is unproven against the real procedure. If you
narrowed the rule to make a noisy alert quiet, re-run the full technique, not just the atomic,
before calling the gap closed. "Quieted the alert" and "still detects the attack" are different
claims.
```

---

## 6. Response Validation

Detection is half the exercise. A fired alert that no analyst triaged inside SLA is a response gap, not a detection win. This phase measures the human and playbook response, not just whether the SIEM lit up.

- [ ] **Triage reached:** For each alert that fired, confirm an analyst actually opened and triaged it, and record the time from alert to triage. An alert sitting unworked in a queue is logged-and-alerted, not responded.
- [ ] **Escalation followed the playbook:** Confirm the analyst escalated per the documented runbook (severity assignment, hand-off, notification). Note where the playbook was skipped, wrong, or missing.
- [ ] **Containment within SLA:** For techniques that should trigger containment (host isolation, account disable, token revocation), confirm the action was taken and record time-to-respond against the agreed SLA.
- [ ] **Correlation into one incident:** Confirm related alerts across the chain were correlated into a single incident rather than worked as isolated events. A SOC that sees ten alerts but not one intrusion has a correlation gap.
- [ ] **Run a replay walkthrough on the misses:** For techniques that produced no response, replay the telemetry with the analysts so they can see what the attack looked like and build the triage muscle, not just receive a rule.
- [ ] **Measure MTTD and MTTR per technique:** Record mean time-to-detect (action to alert) and mean time-to-respond (alert to containment) for every technique that fired. These numbers, not anecdotes, are what the client acts on.
- [ ] **Capture response gaps separately:** A technique that was detected but not acted on is a response finding with a different owner (SOC process, staffing, runbook) than a detection finding. Do not fold the two together.
- [ ] **Note alert fatigue and routing:** Record whether the alert reached the analyst at all, or was buried under noise, auto-closed, or routed to the wrong queue. A good detection that never surfaces to a human is a response gap, not a detection win.
- [ ] **Test the out-of-hours path:** If the exercise runs in business hours, note that the response you measured may not hold at 3am. Where it matters, fire at least one technique off-hours or confirm the on-call escalation path by walkthrough.
- [ ] **Confirm the contain action actually worked:** Isolation and account-disable sometimes fail quietly (agent offline, replication delay). Verify the host was really cut off or the account really locked, not just that the button was pressed.

---

## 7. Scoring and Coverage

Convert the run into a coverage picture the client can act on. Every technique lands in one of three states: detected (alert fired and was actionable), logged-only (telemetry present, no alert), or missed (no telemetry at all). The gap between the second and third states drives different fixes, so keep them distinct.

### Build the Coverage Map

- [ ] **Score every technique detected / logged-only / missed:** One row per technique, with the ATT&CK ID, the data source, the detection outcome, MTTD, MTTR, and the response result. This table is the deliverable's spine.
- [ ] **Score the variant you ran, not the technique in the abstract:** A single sub-technique procedure detected does not color the whole parent green on the heat map. Mark the specific coverage so the picture stays honest across re-runs.
- [ ] **Render an ATT&CK Navigator heat map:** Color each exercised technique by outcome and export the layer. The heat map is how a client sees coverage and gaps in one glance and how progress is tracked across repeat exercises.
- [ ] **Separate collection gaps from detection gaps:** A missed technique on a host with no EDR is a telemetry/onboarding fix; a missed technique on a fully logged host is a detection-content fix. The owners differ.
- [ ] **Record MTTD and MTTR distribution, not just the mean:** One slow outlier drags the mean; a median plus the worst case tells the client more about a real intrusion than an average does. Report both where the data supports it.
- [ ] **Compute coverage honestly:** Coverage percentage is detected over exercised, counting logged-only as not detected. State the denominator (techniques exercised, not the whole matrix) so the number is not inflated.
- [ ] **Compare against the prior exercise:** If this client has run before, diff the heat map against the last layer. Improvement (gaps closed, MTTD down) is the real measure; a single snapshot hides whether the program is moving.

### Prioritize and Report Out

- [ ] **Rank gaps by where they break the chain earliest:** A missed Initial Access or first-privesc technique matters more than a missed late-stage step, because catching it earlier stops everything downstream. Prioritize by chain position and actor relevance, not by raw count.
- [ ] **List the tuned detections produced:** Enumerate every rule built or tuned during the exercise, with its data source, the technique it covers, and its re-test result. This is the concrete output that distinguishes a purple exercise from an assessment.
- [ ] **Assign an owner and a date to every gap:** A ranked gap with no owner is a gap next quarter too. Each open item leaves the exercise with a name and a target date, split between detection-content owners and log-onboarding owners.
- [ ] **Credit what the blue team caught:** Record the detections that fired and the responses that met SLA. The report measures defense; a scorecard that only lists misses is both inaccurate and demoralizing.
- [ ] **Write the executive summary in coverage terms:** Lead with coverage moved, MTTD/MTTR change, and detections shipped, not with the attack path reached. A purple report that reads like a red-team win story has lost its own framing.
- [ ] **Schedule the re-test:** Agree a date to re-run the missed and tuned techniques to confirm the fixes held in production. A one-time green run is not a durable control.

---

## Recent Techniques (2024-2026)

Current actor TTPs worth emulating, each with the detection to validate. Emulate the behavior with benign stand-ins; the aim is to prove the detection, not to cause the harm.

- [ ] **Scattered Spider / Octo Tempest help-desk social engineering (G1015):** Vishing the service desk to drive a password reset or MFA re-enrollment to an attacker device. Validate: identity-verification rigor at the help desk, and detection on MFA-device registration and reset events for privileged accounts.
- [ ] **MFA fatigue / push bombing (T1621):** Repeated push prompts to coax an approval, often paired with the vishing pretext above. Validate: number-matching enforced, push-volume throttling, and an alert on a burst of denied prompts.
- [ ] **Device-code phishing (OAuth device authorization grant abuse):** Luring a user to complete a device-code flow so the attacker receives tokens. (Named in words; emulate the flow and) validate: sign-in-log detection for device-code grants from unexpected clients and conditional-access on that grant type.
- [ ] **AiTM session-cookie theft (T1539):** Reverse-proxy phishing (evilginx-style) that relays the real login and steals the post-MFA session cookie. Validate: token-binding / session anomaly detection and impossible-travel on the replayed cookie, since MFA alone does not stop this.
- [ ] **EDR tampering and BYOVD (T1562.001, with T1068):** Loading a signed-but-vulnerable driver to blind or kill the EDR. Validate: Microsoft Vulnerable Driver Blocklist enabled, HVCI on, a driver-load/tamper alert, and whether telemetry survives the tamper attempt. Lab and authorized hosts only; high blast radius.
- [ ] **Living-off-the-land via signed binaries (T1218):** `rundll32`, `regsvr32`, `mshta`, `msbuild`, `msiexec` proxying execution to blend with admin activity. Validate: detections keyed on the binary plus its arguments and parent, not on an unsigned-binary heuristic that these defeat.
- [ ] **Token theft and replay (T1528 / T1539):** Stealing OAuth/refresh tokens and session cookies to reach cloud/SaaS without a password. Validate: conditional-access on token reuse, impossible-travel, and risky-sign-in detection in the identity provider.
- [ ] **Kerberoasting at scale (T1558.003):** Still high-yield against AD. Validate: TGS-request alerts keyed on weak encryption types and request volume per account (EID 4769), not just presence of the event.
- [ ] **Open-source C2 beaconing (Sliver / Mythic / Havoc):** Increasingly replacing Cobalt Strike. Validate: behavioral and JA3/profile-anomaly detections rather than Cobalt-Strike-only signatures.
- [ ] **Identity-first cloud attack paths (T1098, T1078.004):** Federation / Entra / Okta role abuse and app-registration or app-consent persistence, bypassing host-based detection entirely. Validate: cloud audit-log coverage, risky-consent monitoring, and alerts on new credentials added to service principals.
- [ ] **Internal phishing via Teams / collaboration apps (T1534):** Lateral spearphishing from a compromised internal account over Teams or chat. Validate: whether collaboration-app telemetry is ingested at all, and detection on external-federated or anomalous internal messaging.
- [ ] **CI/CD pipeline abuse:** Poisoned build steps, secret exfiltration from runners, and dependency/trusted-relationship abuse where pipelines are in scope. Validate: runner audit logging, secret-access alerts, and build-step change detection. Emulate pipeline TTPs with Caminus (see tools).

---

## Reporting and Evidence

### Evidence to Capture per Technique

- [ ] **Execution record:** The procedure/atomic run, the exact variant, the host and account, the ATT&CK ID, and the timestamp. This ties the deconfliction log to the scoring table.
- [ ] **Telemetry proof:** The raw log event the technique produced (or a note that none was produced), captured at test time. "Logged" is a claim about a specific event you can show, not a memory of one.
- [ ] **Detection outcome:** Whether an alert fired, its name, the time from action to alert (MTTD), and whether the alert was actionable or noise.
- [ ] **Response outcome:** Whether an analyst triaged and contained, and the time from alert to response (MTTR), against the agreed SLA.
- [ ] **Deconfliction log:** The running record of host, account, ATT&CK ID, and timestamp per action, reconciled against what the blue team saw. It ties telemetry to execution and resolves any "was this you?" question.
- [ ] **Tuned-detection artifact:** For each gap closed, the before (no alert), the rule, and the after (alert firing on the re-run plus clean on baseline).

### The Deliverable

- [ ] **ATT&CK Navigator coverage heat map:** The exported layer scoring each exercised technique detected / logged-only / missed. This is the headline artifact.
- [ ] **MTTD and MTTR metrics:** Per technique and rolled up, with the baseline from this exercise set as the number future exercises improve against.
- [ ] **Tuned detections list:** Every rule built or tuned, its data source, its technique, its owner, and its re-test result.
- [ ] **Collection-gap and onboarding list:** The hosts, segments, and identity planes that need log forwarding or EDR before any detection is even possible. This list often matters more than the rules, because no rule fires on data you do not have.
- [ ] **Exported Navigator layer and VECTR data:** Ship the machine-readable artifacts, not just a screenshot, so the next exercise diffs against this run instead of starting blind.

### Severity by Detection Gap

| Priority | Meaning |
|---|---|
| Critical | A high-impact technique (credential-store access, EDR tamper, ransomware behavior, cloud token abuse) that was missed entirely, on a fully logged host, early in the chain. |
| High | A relevant technique missed or logged-only where a reasonable detection is achievable, or a detection that fired but response missed SLA. |
| Medium | Logged-only on a mid-chain technique with a detection now built and re-tested, or a response-process gap with a documented fix. |
| Low / Informational | Minor telemetry gaps, plus detections that fired and responses that met SLA (credit the blue team). |

Prioritize by where a fix breaks the attack chain earliest and by actor relevance, not by raw gap count.

### Common False Positives and Pitfalls

- [ ] **Lab-proven, prod-unproven:** A detection that fired in the lab was never shown to fire on the real technique in prod telemetry. Confirm the prod data source exists and re-test there before claiming coverage.
- [ ] **Logged counted as detected:** Raw telemetry with no alert is logged-only. Counting it as detected is the most common way a purple report overstates coverage.
- [ ] **A tuned rule never re-tested:** A rule written after the run but not re-fired against the technique is a hypothesis. Re-run it, or do not list it as closed.
- [ ] **Variant overclaim:** A detection proven against one procedure variant does not cover the technique's other variants. Scope the claim to what you ran.
- [ ] **Detection credited as response:** An alert that fired but was never triaged is not a response win. Keep detection and response outcomes in separate columns.
- [ ] **Self-inflicted noise:** Exclude alerts caused by deconfliction chatter or the exercise's own setup from the client's true detection rate.

---

## Tools and References

| Tool | Use |
|---|---|
| Atomic Red Team | Library of per-technique atomic tests mapped to ATT&CK; the default way to fire a single, reproducible technique |
| MITRE Caldera | Automated adversary emulation, chained abilities, and ATT&CK-mapped operations |
| Prelude Operator | Adversary emulation and chained procedures for guided purple runs |
| VECTR | Purple-team planning and scoring; tracks per-technique outcomes across repeat exercises |
| ATT&CK Navigator | Coverage heat map; color techniques by outcome and export the layer as the deliverable |
| Sigma | Vendor-neutral detection rules; author once and convert to the client SIEM query language |
| Client SIEM / EDR | Where detections are deployed and re-tested; coverage proven anywhere else is not coverage |
| Caminus | Cairn's CI/CD pipeline attack framework; emulate pipeline-stage TTPs where build systems are in scope |

A Sigma rule is a portable statement of intent; convert and deploy it to the client platform, then re-test, before counting it as coverage.

```yaml
# Sigma snippet (anchor only; full rule and field tuning in the detection cheatsheet).
title: Suspicious Rundll32 Proxy Execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains:
      - 'javascript:'
      - 'url.dll,OpenURL'
  condition: selection
level: medium
```

Authoritative references:
- MITRE ATT&CK (attack.mitre.org): the technique catalogue, data sources, and group pages that anchor the plan.
- MITRE Engenuity (ATT&CK Evaluations, Center for Threat-Informed Defense): emulation plans and detection methodology.
- SANS purple-team guidance and the ATT&CK-based purple-team methodology for exercise structure and scoring discipline.

---

## Related

- Checklists: [Red Team Operation](Red%20Team%20Operation.md), [Assumed Breach](Assumed%20Breach.md), [Compromise Assessment](Compromise%20Assessment.md)
- Cheatsheets: [Windows Privilege Escalation](../Cheatsheets/Windows%20Privilege%20Escalation.md), [Active Directory and Kerberos](../Cheatsheets/Active%20Directory%20and%20Kerberos.md)
- Playbooks: [Attack Graph](../Playbooks/Attack%20Graph.md), [Kerberoasting to Domain Admin](../Playbooks/Kerberoasting%20to%20Domain%20Admin.md), [DCSync to Golden Ticket Persistence](../Playbooks/DCSync%20to%20Golden%20Ticket%20Persistence.md)

---
*Part of the [Pentest Field Guide](https://github.com/Su1ph3r/hack-notes-field-guide), maintained by [Cairn Security](https://cairnsecurity.com). Independent penetration testing.*
