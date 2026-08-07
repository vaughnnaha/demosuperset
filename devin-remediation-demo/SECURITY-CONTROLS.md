<!--
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
-->
# Security controls

Control set for the automated remediation pipeline, mapped to NIST SP 800-53
Rev. 5. The governing principle: **the agent is a privileged non-person entity
(NPE) and is controlled like one** — its authorization is checked before it
acts, its actions are attributable to a named human, and its activity is
recorded in a retained audit trail.

## Trust boundary

```
        UNTRUSTED                   |          CONTROLLED               | EXTERNAL
 issue authors, issue body content  |  GitHub Actions runner            | api.devin.ai
                                    |  (repo secrets, GITHUB_TOKEN)     |
   ─────────────── issue payload ──►|── authorize ──► redact ──► fence ─►|
                                    |                                   |
                                    |◄── session id, PR url ────────────|
                                    |                                   |
                                    |── audit JSONL ──► retained artifact
```

Data crossing to `api.devin.ai`: repository URL, default branch, issue URL,
issue title, and issue body — after secret redaction and truncation. No
repository secrets, no `GITHUB_TOKEN`, and no source code are transmitted by
this automation.

## Implemented

| # | Control | Implementation | 800-53 Rev. 5 |
| --- | --- | --- | --- |
| 1 | Separate classification from authorization | `devin-remediation` labels candidate work; only `devin-approved` can start a session, and the automation re-verifies the classification label server-side | AC-3, CM-3 |
| 2 | Actor authorization | `authorize()` requires a named sender, allowlist membership when `ACTOR_ALLOWLIST` is set, and `write`/`admin` from `GET /repos/{repo}/collaborators/{login}/permission` | AC-2, AC-3, AC-6 |
| 3 | Bot actors denied by default | Senders of type `Bot` are refused unless explicitly allowlisted | AC-2, AC-6 |
| 4 | Approval gate before execution | Job binds to the `devin-remediation` GitHub Environment with required reviewers; GitHub records the approver | AC-3, AC-6(9), CM-5 |
| 5 | Fail closed | Every authorization failure comments the reason on the issue, emits `authorization.denied`, and exits non-zero without creating a session | AC-3, SI-11 |
| 6 | Least-privilege workflow token | `permissions:` limited to `issues: write`, `contents: read`; checkout runs with `persist-credentials: false` | AC-6, CM-7 |
| 7 | Least-privilege runtime | Container runs `--read-only`, `--user 65534:65534`, `--cap-drop ALL`, `--security-opt no-new-privileges`; image declares `USER 65534` | AC-6, CM-7, SC-2 |
| 8 | Audit event content | Each record carries UTC timestamp, event type, actor login **and numeric id** (logins are renameable), actor type, resolved permission, decision, reason, repository, issue number, run id and URL | AU-2, AU-3, AU-8 |
| 9 | Agent session lifecycle accounting | `session.started` records `session_started_at`; with polling enabled `session.ended` records `session_ended_at`, `session_duration_seconds`, terminal status, and pull-request URL — the NPE equivalent of logon/logoff records | AU-3, AU-12, AC-12 |
| 10 | Audit retention | Audit JSONL uploaded as a workflow artifact `if: always()`, so denials and failures are retained too. Retention is set to the 90-day public-repository ceiling; raising the repository Actions retention limit extends it | AU-9, AU-11 |
| 10a | Audit failure is not silent | A ledger append failure logs at `ERROR`, and the workflow fails the run if the ledger is empty, so a run cannot appear audited when it is not | AU-5 |
| 11 | Untrusted input isolation | Issue body is delimited and explicitly declared data-not-instructions in the prompt, and truncated at 20,000 characters | SI-10 |
| 12 | Secret redaction before egress | Token-shaped strings (GitHub PAT/OAuth, Devin, AWS, OpenAI, PEM private keys) are stripped from the title, body, and any logged API response before transmission or logging | SI-10, SC-8, MP-6 |
| 13 | Supply-chain pinning | Actions pinned to full commit SHAs; base image pinned by `sha256:` digest; dependencies installed with `--require-hashes` from a compiled lockfile | CM-2, SR-11, SI-7 |
| 14 | Concurrency limit | `concurrency` group per issue prevents duplicate in-flight sessions; the Devin API call is `idempotent` | SC-5 |
| 15 | Automation self-test in CI | `devin-remediation-automation.yml` runs the unit suite, `ruff`, and `pip-audit` on any change to the automation | CA-2, RA-5, SA-11 |
| 16 | Transport security | All API traffic is HTTPS with explicit 30-second timeouts | SC-8, SC-5 |
| 17 | Periodic audit review | `devin-remediation-report.yml` runs weekly and on demand: `report.py` folds the retained ledgers into authorization outcomes (allow/deny counts, denial rate, denials by reason, actors) and remediation outcomes (sessions, terminal statuses, pull requests opened/merged, yield, mean duration), published to the job summary and retained as an artifact | AU-6, CA-7, PM-6 |

## Recommended next (not implemented)

| Control | Why | 800-53 Rev. 5 |
| --- | --- | --- |
| Short-lived credentials via OIDC in place of the static `DEVIN_API_KEY`; interim ≤90-day documented rotation | The API key is currently long-lived with no expiry | IA-5, IA-2 |
| Egress allowlist on the container (`api.devin.ai`, `api.github.com` only) | A compromised dependency could otherwise call out freely | SC-7 |
| Branch protection + CODEOWNERS requiring one human approval on agent-authored PRs; `ai-authored` provenance label | Nothing currently prevents an agent PR from merging unreviewed | AC-5, AC-6(9) |
| Kill switch (`REMEDIATION_ENABLED=false`) plus documented key-revocation and session-termination runbook | No documented way to stop the pipeline mid-incident | IR-4, IR-6 |
| Ship the audit JSONL to a SIEM and/or append to a signed ledger in-repo | Artifacts are admin-deletable; a SIEM copy makes the trail tamper-evident | AU-9(2), AU-6 |
| SBOM (CycloneDX) and build provenance attestation for the automation image | Supply-chain evidence beyond pinning | SR-4, SA-15 |
| Signed commits required on protected branches | Integrity of what the agent lands | SI-7 |
| Daily session cap | Cost and abuse ceiling beyond per-issue concurrency | SC-5 |
| Alerting on denial spikes or repeated unauthorized attempts | The report is periodic, not real-time | AU-6(1), IR-5, SI-4 |

## Residual risk

- The Devin session itself operates with repository write access under its own
  credentials; the controls here govern **who may start it and what context it
  receives**, not what it does once running. Branch protection and required
  human review are the compensating controls, and are not yet enabled.
- Redaction is pattern-based and will not catch every secret or CUI format. It
  reduces accidental exposure; it is not a data-loss-prevention system.
- Artifact retention is enforced by GitHub and deletable by a repository admin.
  Meeting a strict AU-9 requirement needs an external, append-only store.
- The report is bounded by artifact retention: expired artifacts leave gaps, and
  it counts only what the ledger recorded. With polling disabled it cannot
  observe session duration or terminal status, and attributes pull requests by
  issue reference instead of from the session; those rows are marked `inferred`.
