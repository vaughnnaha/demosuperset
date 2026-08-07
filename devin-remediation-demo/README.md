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
# devin-remediation-demo

Event-driven maintenance remediation: an authorized reviewer labels a
`devin-remediation` issue `devin-approved`, and a Devin session fixes the issue
and opens a pull request. Every decision is written to a structured audit trail.

See [SECURITY-CONTROLS.md](SECURITY-CONTROLS.md) for the control set and its
NIST SP 800-53 Rev. 5 mapping.

## What it does

1. A GitHub Actions workflow fires on `issues: [labeled]`.
2. The job ignores every label except `devin-approved`, then pauses for approval
   from a reviewer configured on the `devin-remediation` environment.
3. A Dockerized Python script reads the event payload and authorizes the actor:
   the issue must already carry `devin-remediation`, the actor must be on
   `ACTOR_ALLOWLIST` when one is set, and the actor must hold `write` or `admin`
   permission on the repository. A refusal comments on the issue and exits 1.
4. The script builds a remediation prompt with the issue body fenced as
   untrusted data and secret-shaped strings redacted, then calls the Devin API.
   The prompt's directives are issue-agnostic — scope, acceptance criteria, and
   validation commands come from the issue itself — so any labeled issue works.
5. The script comments the session link and workflow-run link on the issue.
6. Devin works the issue autonomously and opens a pull request.
7. Every authorization decision and session lifecycle transition is appended to
   a JSONL audit log, retained as a workflow artifact.
8. A scheduled report job folds those retained ledgers into an effectiveness
   report: authorization outcomes, session outcomes, and pull-request results.

## Architecture

```
GitHub Issue  (labeled devin-remediation = candidate work)
    ↓ authorized reviewer adds label: devin-approved
GitHub Action  (.github/workflows/devin-remediation.yml)
    ↓ environment approval gate
Dockerized Python Script  (src/main.py)
    ↓ authorize actor → audit
Devin API  (POST /v1/sessions)
    ↓
Devin Session
    ↓
Pull Request                     audit JSONL → workflow artifact
                                     ↓ weekly
                                 src/report.py → effectiveness report
```

## Two-label model

| Label | Meaning | Starts a session |
| --- | --- | --- |
| `devin-remediation` | Classification: this issue is candidate remediation work | No |
| `devin-approved` | Authorization: an approved reviewer released it for remediation | Yes, if the actor passes authorization |

Separating the two keeps triage labeling free of execution side effects, and
means neither label alone is sufficient to spend an agent session.

## Required secret

| Secret | Where | Purpose |
| --- | --- | --- |
| `DEVIN_API_KEY` | Repo → Settings → Secrets and variables → Actions | Authenticates against the Devin API. Create one at https://app.devin.ai/settings/api-keys |

`GITHUB_TOKEN` is provided automatically by Actions; the workflow requests only
`issues: write` and `contents: read`.

Optional repository variables:

| Variable | Default | Effect |
| --- | --- | --- |
| `ACTOR_ALLOWLIST` | unset | Comma-separated logins permitted to trigger remediation. Unset means "any collaborator with write or admin". |
| `POLL_TIMEOUT_SECONDS` | `0` | When greater than zero, poll the session for that many seconds, comment the pull-request URL, and record session end time and duration in the audit log. Set it (e.g. `1800`) for session-duration and outcome metrics in the report. |
| `EXTRA_PROMPT_DIRECTIVES` | unset | Extra bullet directives appended to every remediation prompt, for repository-wide rules the issues do not restate. |

## Required repository settings

1. **Environment** `devin-remediation` with *required reviewers* (Settings →
   Environments). The job will not start until a reviewer approves; GitHub
   records the approver identity.
2. **Labels** `devin-remediation` and `devin-approved`.
3. **Dependency graph** enabled (Settings → Code security) so `dependency-review`
   and Dependabot can run.
4. Optional: raise the **artifact retention limit** (Settings → Actions →
   General). Public repositories cap it at 90 days, which caps how far back the
   effectiveness report can see.

## Build the Docker image

```bash
docker build -t devin-remediation-demo .
```

The base image is pinned by digest and dependencies install with
`--require-hashes`, so the build is reproducible.

## Run locally with a sample event

```bash
cp .env.example .env   # fill in DEVIN_API_KEY and GITHUB_TOKEN
set -a && source .env && set +a

# The container runs as uid 65534, so the mounted ledger must be writable by it
# or audit appends are dropped.
mkdir -p audit && sudo chown -R 65534:65534 audit

docker run --rm \
  --read-only --tmpfs /tmp --user 65534:65534 \
  --cap-drop ALL --security-opt no-new-privileges \
  -e DEVIN_API_KEY -e GITHUB_TOKEN -e ACTOR_ALLOWLIST \
  -e GITHUB_EVENT_PATH=/event.json \
  -e AUDIT_LOG_PATH=/audit/remediation-audit.jsonl \
  -v "$PWD/sample_event.json:/event.json:ro" \
  -v "$PWD/audit:/audit" \
  devin-remediation-demo
```

Or without Docker:

```bash
pip install -r requirements.txt
GITHUB_EVENT_PATH=sample_event.json DEVIN_API_KEY=... GITHUB_TOKEN=... python src/main.py
```

Note: this really does create a Devin session and really does comment on the
issue named in the payload. Point `sample_event.json` at a throwaway issue when
experimenting.

## Install the workflow in another repository

1. Copy this directory into the target repo as `devin-remediation-demo/`.
2. Copy `.github/workflows/devin-remediation.yml` into the target repo's
   `.github/workflows/`.
3. Add the `DEVIN_API_KEY` secret.
4. Create both labels and the `devin-remediation` environment with reviewers.

The workflow sparse-checks-out only `devin-remediation-demo/`, builds the image,
and mounts the event payload read-only into an unprivileged, read-only container.

## Trigger the demo

```bash
gh issue edit <number> --add-label devin-remediation   # classify (no session)
gh issue edit <number> --add-label devin-approved      # authorize (session)
```

## Expected output

- A **Devin Remediation** workflow run awaiting environment approval, then logs
  showing the authorization decision, the created session ID, and the comment.
- An issue comment: `Devin remediation started` with the session URL, session
  ID, authorizing actor and permission level, and workflow-run link.
- A `remediation-audit-<issue>-<run>` artifact containing the JSONL audit trail.
- A pull request opened by Devin referencing the issue (and, with polling on, a
  follow-up comment linking it).

An unauthorized attempt instead produces a `Devin remediation refused` comment,
an `authorization.denied` audit record, and a failed job.

## Audit record

One JSON object per line. Example (`session.started`):

```json
{
  "timestamp": "2026-08-07T01:12:44+00:00",
  "event": "session.started",
  "actor": "vaughnnaha",
  "actor_id": 4242,
  "actor_type": "User",
  "actor_permission": "admin",
  "repository": "vaughnnaha/demosuperset",
  "issue_number": 4,
  "trigger_label": "devin-approved",
  "run_id": "31131815922",
  "run_url": "https://github.com/vaughnnaha/demosuperset/actions/runs/31131815922",
  "session_id": "devin-34c7a00acbb64d6bada84bcbdbe73ef9",
  "session_started_at": "2026-08-07T01:12:44+00:00"
}
```

Event types: `authorization.granted`, `authorization.denied`,
`authorization.error`, `session.started`, `session.ended`, `session.failed`,
`comment.failed`. With polling enabled, `session.ended` carries
`session_ended_at`, `session_duration_seconds`, `session_status`, and
`pull_request`.

## Effectiveness report

`.github/workflows/devin-remediation-report.yml` runs weekly and on demand. It
downloads every unexpired `remediation-audit-*` artifact, folds the event stream
into one row per authorization decision, and writes the report to the job summary
plus a `remediation-report-<run>` artifact (Markdown and JSON).

```bash
python src/report.py audit --markdown report.md --json report.json
```

Metrics: authorized vs. denied counts, denial rate, denials by reason, actors,
sessions started, sessions that failed to start, sessions reaching a terminal
status, pull requests opened and merged, pull-request yield, merge rate, and mean
session duration. Pull-request state is resolved through the GitHub API; when
polling was disabled the report falls back to the earliest pull request that
references the issue and was opened after the session started, and marks the
attribution `inferred`. Pass `--no-enrich` to stay offline.

## Tests

```bash
pip install -r requirements.txt pytest
pytest tests/ -v
```

Covers: only `devin-approved` triggers; a valid event produces the expected
Devin API request and issue comment; insufficient permission, an actor off the
allowlist, and a missing classification label are each refused without creating
a session; an authorized run writes the expected audit records; the issue body
is fenced as untrusted data with secrets redacted; and missing key / missing
payload / Devin API failure all exit nonzero.

`tests/test_report.py` covers the report: folding the event stream into one row
per run, later records superseding earlier ones, the computed metrics, both paths
appearing in the Markdown, pull-request state resolution and search fallback, and
nonzero exit on an empty ledger.
