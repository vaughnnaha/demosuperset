# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Launch a Devin session to remediate a labeled GitHub issue.

Reads the GitHub Actions `issues.labeled` event payload, creates a Devin
session via the Devin API, and comments the session link back on the issue.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from typing import Any

import requests

TRIGGER_LABEL = "devin-remediation"
DEVIN_API_BASE = os.environ.get("DEVIN_API_BASE", "https://api.devin.ai/v1")
GITHUB_API_BASE = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REQUEST_TIMEOUT = 30

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("devin-remediation")


class RemediationError(Exception):
    """A failure that should fail the workflow run."""


def load_event(path: str | None) -> dict[str, Any]:
    if not path or not os.path.isfile(path):
        raise RemediationError(f"GitHub event payload not found at {path!r}")
    with open(path, encoding="utf-8") as handle:
        event = json.load(handle)
    if not isinstance(event, dict) or "issue" not in event:
        raise RemediationError("Event payload is not an issue event")
    return event


def is_trigger_event(event: dict[str, Any]) -> bool:
    """True only for `labeled` events that added the remediation label."""
    if event.get("action") != "labeled":
        logger.info("Ignoring action %r (expected 'labeled')", event.get("action"))
        return False
    if (label := (event.get("label") or {}).get("name")) != TRIGGER_LABEL:
        logger.info("Ignoring label %r (expected %r)", label, TRIGGER_LABEL)
        return False
    return True


def build_prompt(event: dict[str, Any]) -> str:
    issue = event["issue"]
    repo = event.get("repository") or {}
    return f"""You are remediating the following GitHub issue in the Apache \
Superset fork:

Repository: {repo.get("html_url", "")}
Default branch: {repo.get("default_branch", "main")}
Issue: {issue.get("html_url", "")}
Title: {issue.get("title", "")}

Issue body:
{issue.get("body") or "(empty)"}

Complete the issue exactly as written.

For this issue:
- Read the repository instructions (AGENTS.md / CLAUDE.md) before editing.
- Add the missing Jest and React Testing Library coverage.
- Modify test files only.
- Do not modify production code.
- Cover checkIsMissingRequiredValue with defaultToFirstItem.
- Test that an explicit user clear remains cleared.
- Test that clearAllTrigger allows auto-selection again.
- Run the targeted tests listed in the issue.
- Follow the repository's existing frontend test conventions.
- Create a focused branch.
- Open a pull request against the default branch.
- Reference the GitHub issue in the pull-request description.
- Include the validation commands and results.
- Do not merge the pull request.
- Do not claim tests passed unless they were actually executed successfully.

Work autonomously and make reasonable implementation decisions."""


def create_devin_session(prompt: str, api_key: str, title: str) -> dict[str, Any]:
    response = requests.post(
        f"{DEVIN_API_BASE}/sessions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "prompt": prompt,
            "title": title,
            "idempotent": True,
            "tags": ["devin-remediation"],
        },
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code >= 400:
        raise RemediationError(
            f"Devin API returned {response.status_code}: {response.text[:500]}"
        )
    return response.json()


def get_devin_session(session_id: str, api_key: str) -> dict[str, Any]:
    response = requests.get(
        f"{DEVIN_API_BASE}/sessions/{session_id}",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=REQUEST_TIMEOUT,
    )
    response.raise_for_status()
    return response.json()


def comment_on_issue(repo_full_name: str, issue_number: int, body: str) -> None:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise RemediationError("GITHUB_TOKEN is not set; cannot comment on the issue")
    response = requests.post(
        f"{GITHUB_API_BASE}/repos/{repo_full_name}/issues/{issue_number}/comments",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
        },
        json={"body": body},
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code >= 400:
        raise RemediationError(
            f"Failed to comment on issue: {response.status_code} {response.text[:500]}"
        )


def actions_run_url() -> str | None:
    server = os.environ.get("GITHUB_SERVER_URL")
    repo = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server and repo and run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return None


def poll_for_pull_request(session_id: str, api_key: str, timeout: int) -> str | None:
    """Poll the session until it reports a pull request or the budget runs out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        time.sleep(20)
        try:
            session = get_devin_session(session_id, api_key)
        except requests.RequestException as exc:
            logger.warning("Polling failed (continuing): %s", exc)
            continue
        pull_request = session.get("pull_request") or {}
        url = pull_request.get("url")
        logger.info("Session status=%s pull_request=%s", session.get("status"), url)
        if url:
            return url
        if session.get("status_enum") in {"finished", "expired"}:
            return None
    logger.info("Polling budget exhausted without a pull request")
    return None


def main() -> int:
    api_key = os.environ.get("DEVIN_API_KEY")
    if not api_key:
        logger.error("DEVIN_API_KEY is not set")
        return 1

    try:
        event = load_event(os.environ.get("GITHUB_EVENT_PATH"))
    except RemediationError as exc:
        logger.error("%s", exc)
        return 1

    if not is_trigger_event(event):
        return 0

    issue = event["issue"]
    repo_full_name = (event.get("repository") or {}).get("full_name")
    if not repo_full_name:
        logger.error("Event payload is missing repository.full_name")
        return 1
    issue_number = issue["number"]

    logger.info("Creating Devin session for %s#%s", repo_full_name, issue_number)
    title = f"Remediate {repo_full_name}#{issue_number}: {issue.get('title', '')}"
    title = title[:200]
    try:
        session = create_devin_session(
            build_prompt(event),
            api_key,
            title=title,
        )
    except (RemediationError, requests.RequestException) as exc:
        logger.error("Could not create Devin session: %s", exc)
        return 1

    session_id = session.get("session_id", "")
    session_url = session.get("url") or f"https://app.devin.ai/sessions/{session_id}"
    logger.info("Devin session created: %s (%s)", session_id, session_url)

    body = (
        f"**Devin remediation started** for the `{TRIGGER_LABEL}` label.\n\n"
        f"- Session: {session_url}\n"
        f"- Session ID: `{session_id}`\n"
    )
    if run_url := actions_run_url():
        body += f"- Workflow run: {run_url}\n"
    body += "\nDevin will open a pull request referencing this issue when it finishes."

    try:
        comment_on_issue(repo_full_name, issue_number, body)
        logger.info("Posted status comment on issue #%s", issue_number)
    except (RemediationError, requests.RequestException) as exc:
        logger.error("Could not comment on the issue: %s", exc)
        return 1

    report_pull_request(repo_full_name, issue_number, session_id, api_key)
    return 0


def report_pull_request(
    repo_full_name: str, issue_number: int, session_id: str, api_key: str
) -> None:
    """Optionally poll the session and comment the pull-request link."""
    poll_timeout = int(os.environ.get("POLL_TIMEOUT_SECONDS") or 0)
    if poll_timeout <= 0 or not session_id:
        return
    logger.info("Polling session for up to %ss", poll_timeout)
    pr_url = poll_for_pull_request(session_id, api_key, poll_timeout)
    if not pr_url:
        return
    logger.info("Pull request: %s", pr_url)
    try:
        comment_on_issue(
            repo_full_name, issue_number, f"Devin opened a pull request: {pr_url}"
        )
    except (RemediationError, requests.RequestException) as exc:
        logger.warning("Could not post pull-request comment: %s", exc)


if __name__ == "__main__":
    sys.exit(main())
