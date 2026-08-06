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

Event-driven maintenance remediation: labeling a GitHub issue `devin-remediation`
launches a Devin session that fixes the issue and opens a pull request.

## What it does

1. A GitHub Actions workflow fires on `issues: [labeled]`.
2. The job ignores everything except the `devin-remediation` label.
3. A Dockerized Python script reads the event payload, builds a remediation
   prompt from the full issue, and calls the Devin API to create a session.
4. The script comments the session link and workflow-run link on the issue.
5. Devin works the issue autonomously and opens a pull request.

## Architecture

```
GitHub Issue
    ↓ label: devin-remediation
GitHub Action  (.github/workflows/devin-remediation.yml)
    ↓
Dockerized Python Script  (src/main.py)
    ↓
Devin API  (POST /v1/sessions)
    ↓
Devin Session
    ↓
Pull Request
```

## Required secret

| Secret | Where | Purpose |
| --- | --- | --- |
| `DEVIN_API_KEY` | Repo → Settings → Secrets and variables → Actions | Authenticates against the Devin API. Create one at https://app.devin.ai/settings/api-keys |

`GITHUB_TOKEN` is provided automatically by Actions; the workflow requests only
`issues: write` and `contents: read`.

Optional repository variable `POLL_TIMEOUT_SECONDS` (default `0`): when greater
than zero the script polls the session for that many seconds and posts a second
comment with the pull-request URL once Devin opens one.

## Build the Docker image

```bash
docker build -t devin-remediation-demo .
```

## Run locally with a sample event

```bash
cp .env.example .env   # fill in DEVIN_API_KEY and GITHUB_TOKEN
set -a && source .env && set +a

docker run --rm \
  -e DEVIN_API_KEY -e GITHUB_TOKEN \
  -e GITHUB_EVENT_PATH=/event.json \
  -v "$PWD/sample_event.json:/event.json:ro" \
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
2. Copy `.github/workflows/devin-remediation.yml` from that repo (or from this
   README's architecture section) into the target repo's `.github/workflows/`.
3. Add the `DEVIN_API_KEY` secret.
4. Create the `devin-remediation` label.

The workflow sparse-checks-out only `devin-remediation-demo/`, builds the image,
and mounts the event payload read-only into the container.

## Trigger the demo

Add the `devin-remediation` label to any issue in the repo:

```bash
gh issue edit <number> --add-label devin-remediation
```

## Expected output

- A **Devin Remediation** workflow run in the Actions tab with logs showing the
  created session ID and the posted comment.
- An issue comment: `🤖 Devin remediation started` with the session URL, session
  ID, and workflow-run link.
- A pull request opened by Devin referencing the issue (and, with polling on, a
  follow-up comment linking it).

## Tests

```bash
pip install -r requirements.txt pytest
pytest tests/ -v
```

Covers: irrelevant labels and non-`labeled` actions are ignored, a valid event
produces the expected Devin API request and issue comment, and missing key /
missing payload / Devin API failure all exit nonzero.
