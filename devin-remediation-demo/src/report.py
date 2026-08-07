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
"""Summarize remediation effectiveness from the audit ledger.

Reads the append-only JSON Lines audit records emitted by `main.py`, folds them
into one row per remediation request, optionally resolves the current state of
each pull request through the GitHub API, and renders a Markdown report plus a
machine-readable JSON summary.

Usage:
    python src/report.py audit/ --markdown report.md --json report.json

Paths may be JSON Lines files or directories, which are searched recursively.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Iterable, Sequence

import requests

GITHUB_API_BASE = os.environ.get("GITHUB_API_URL", "https://api.github.com")
REQUEST_TIMEOUT = 30

# Session statuses that mean Devin stopped working, whatever the outcome.
TERMINAL_STATUSES = {"finished", "expired", "blocked"}


@dataclass
class Request:
    """One authorization decision and everything that followed it.

    Keyed by the Actions run that handled a single `devin-approved` event, so a
    denied request is as much a row as a successful one.
    """

    run_id: str
    decided_at: str | None = None
    last_event_at: str | None = None
    issue_number: int | None = None
    repository: str | None = None
    actor: str | None = None
    actor_id: int | None = None
    actor_type: str | None = None
    actor_permission: str | None = None
    decision: str | None = None
    reason: str | None = None
    run_url: str | None = None
    session_id: str | None = None
    session_url: str | None = None
    session_started_at: str | None = None
    session_ended_at: str | None = None
    session_duration_seconds: int | None = None
    session_status: str | None = None
    pull_request: str | None = None
    pull_request_state: str | None = None
    pull_request_source: str | None = None
    events: list[str] = field(default_factory=list)


def parse_timestamp(value: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp, accepting the `Z` suffix the GitHub API uses."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def expand_paths(paths: Iterable[str]) -> list[str]:
    """Resolve each argument to ledger files, walking directories recursively.

    Taking a directory keeps the caller off the shell's argument list, which a
    long retention window would otherwise overflow and silently split.
    """
    resolved: list[str] = []
    for path in paths:
        if os.path.isdir(path):
            for root, _, names in os.walk(path):
                resolved += [
                    os.path.join(root, name)
                    for name in sorted(names)
                    if name.endswith(".jsonl")
                ]
        elif os.path.isfile(path):
            resolved.append(path)
    return resolved


def load_records(paths: Iterable[str]) -> list[dict[str, Any]]:
    """Read audit records from JSON Lines files, skipping unparsable lines."""
    records: list[dict[str, Any]] = []
    for path in expand_paths(paths):
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if not (line := line.strip()):
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict) and record.get("event"):
                    records.append(record)
    records.sort(key=lambda record: str(record.get("timestamp", "")))
    return records


def fold_requests(records: Sequence[dict[str, Any]]) -> list[Request]:
    """Collapse the event stream into one `Request` per Actions run.

    Later records win, so `session.ended` supersedes `session.started` for the
    fields they share. Records with no run id fall back to the issue number so
    locally generated ledgers still group.
    """
    fields = set(Request.__dataclass_fields__) - {
        "run_id",
        "events",
        "decided_at",
        "last_event_at",
    }
    folded: dict[str, dict[str, Any]] = {}
    events: dict[str, list[str]] = {}
    for record in records:
        key = str(record.get("run_id") or f"issue-{record.get('issue_number')}")
        state = folded.setdefault(key, {})
        events.setdefault(key, []).append(str(record["event"]))
        if timestamp := record.get("timestamp"):
            state.setdefault("decided_at", str(timestamp))
            state["last_event_at"] = str(timestamp)
        state.update(
            {
                name: value
                for name, value in record.items()
                if name in fields and value is not None
            }
        )
        if record["event"] in {"session.failed", "comment.failed"}:
            state["session_status"] = record["event"]
    return [
        Request(run_id=key, events=events[key], **state)
        for key, state in folded.items()
    ]


def find_linked_pull_requests(requests_: Sequence[Request], token: str | None) -> None:
    """Attribute a pull request to a session the ledger has no PR link for.

    The ledger only records `pull_request` when polling is enabled, so fall back
    to the earliest pull request that references the issue and was opened after
    the session started. Without that lower bound a later pull request merely
    mentioning the issue would be misattributed to the session.
    """
    if not token:
        return
    for request in requests_:
        if request.pull_request or not request.session_id or not request.repository:
            continue
        query = f'repo:{request.repository} type:pr in:body "#{request.issue_number}"'
        try:
            response = requests.get(
                f"{GITHUB_API_BASE}/search/issues",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
                params={
                    "q": query,
                    "per_page": "20",
                    "sort": "created",
                    "order": "asc",
                },
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code >= 400:
                continue
            items = response.json().get("items") or []
        except (requests.RequestException, ValueError):
            continue
        started = parse_timestamp(request.session_started_at)
        for item in items:
            created = parse_timestamp(item.get("created_at"))
            if started and (created is None or created < started):
                continue
            request.pull_request = item.get("html_url")
            request.pull_request_source = "search"
            break


def enrich_pull_requests(requests_: Sequence[Request], token: str | None) -> None:
    """Resolve each pull request's current state (open, merged, or closed)."""
    if not token:
        return
    for request in requests_:
        if not request.pull_request:
            continue
        api_url = request.pull_request.replace(
            "https://github.com/", f"{GITHUB_API_BASE}/repos/", 1
        ).replace("/pull/", "/pulls/", 1)
        try:
            response = requests.get(
                api_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                },
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code >= 400:
                continue
            payload = response.json()
        except (requests.RequestException, ValueError):
            continue
        request.pull_request_state = (
            "merged" if payload.get("merged_at") else str(payload.get("state", ""))
        )


def summarize(requests_: Sequence[Request]) -> dict[str, Any]:
    """Compute the effectiveness and access-control metrics."""
    allowed = [r for r in requests_ if r.decision == "allow"]
    denied = [r for r in requests_ if r.decision == "deny"]
    sessions = [r for r in allowed if r.session_id]
    with_pr = [r for r in sessions if r.pull_request]
    merged = [r for r in with_pr if r.pull_request_state == "merged"]
    durations = [
        r.session_duration_seconds
        for r in sessions
        if isinstance(r.session_duration_seconds, int)
    ]
    starts = [
        ts
        for ts in (parse_timestamp(r.decided_at) for r in requests_)
        if ts is not None
    ]
    ends = [
        ts
        for ts in (parse_timestamp(r.last_event_at) for r in requests_)
        if ts is not None
    ]
    return {
        "requests": len(requests_),
        "authorized": len(allowed),
        "denied": len(denied),
        "denial_rate": _ratio(len(denied), len(requests_)),
        "denial_reasons": dict(
            Counter(r.reason for r in denied if r.reason).most_common()
        ),
        "actors": dict(Counter(r.actor for r in requests_ if r.actor).most_common()),
        "sessions_started": len(sessions),
        "sessions_failed_to_start": len(
            [r for r in allowed if r.session_status == "session.failed"]
        ),
        "sessions_terminal": len(
            [r for r in sessions if r.session_status in TERMINAL_STATUSES]
        ),
        "pull_requests_opened": len(with_pr),
        "pull_requests_merged": len(merged),
        "pull_request_yield": _ratio(len(with_pr), len(sessions)),
        "merge_rate": _ratio(len(merged), len(with_pr)),
        "mean_session_seconds": round(sum(durations) / len(durations))
        if durations
        else None,
        "issues_touched": sorted(
            {r.issue_number for r in requests_ if r.issue_number is not None}
        ),
        "window_start": min(starts).isoformat() if starts else None,
        "window_end": max(ends).isoformat() if ends else None,
    }


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 3) if denominator else None


def render_markdown(requests_: Sequence[Request], metrics: dict[str, Any]) -> str:
    """Render the report, sized for a GitHub Actions job summary."""
    lines = [
        "# Devin remediation effectiveness report",
        "",
        f"Window: `{metrics['window_start'] or 'n/a'}` .. "
        f"`{metrics['window_end'] or 'n/a'}` "
        f"({metrics['requests']} authorization decisions)",
        "",
        "## Access control",
        "",
        "| metric | value |",
        "| --- | --- |",
        f"| Authorized | {metrics['authorized']} |",
        f"| Denied | {metrics['denied']} |",
        f"| Denial rate | {_percent(metrics['denial_rate'])} |",
        "",
    ]
    if metrics["denial_reasons"]:
        lines += ["Denials by reason:", ""]
        lines += [
            f"- `{count}x` {reason}"
            for reason, count in metrics["denial_reasons"].items()
        ]
        lines.append("")
    lines += [
        "## Remediation effectiveness",
        "",
        "| metric | value |",
        "| --- | --- |",
        f"| Sessions started | {metrics['sessions_started']} |",
        f"| Sessions that failed to start | {metrics['sessions_failed_to_start']} |",
        f"| Sessions reaching a terminal status | {metrics['sessions_terminal']} |",
        f"| Pull requests opened | {metrics['pull_requests_opened']} |",
        f"| Pull requests merged | {metrics['pull_requests_merged']} |",
        f"| Pull-request yield | {_percent(metrics['pull_request_yield'])} |",
        f"| Merge rate | {_percent(metrics['merge_rate'])} |",
        f"| Mean observed session duration | "
        f"{_duration(metrics['mean_session_seconds'])} |",
        "",
        "## Requests",
        "",
        "| issue | actor | permission | decision | session | outcome |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for request in sorted(requests_, key=lambda r: str(r.decided_at or "")):
        lines.append(
            f"| {_issue(request)} | {request.actor or '?'}"
            f"{' (bot)' if request.actor_type == 'Bot' else ''} "
            f"| {request.actor_permission or '-'} | {request.decision or '?'} "
            f"| {_session(request)} | {_outcome(request)} |"
        )
    lines += [
        "",
        "Generated from the append-only audit ledger; every row is traceable to "
        "an Actions run and the actor who authorized it.",
        "",
    ]
    return "\n".join(lines)


def _percent(ratio: float | None) -> str:
    return f"{ratio * 100:.0f}%" if ratio is not None else "n/a"


def _duration(seconds: int | None) -> str:
    if seconds is None:
        return "not measured (polling disabled)"
    return f"{seconds // 60}m {seconds % 60}s"


def _issue(request: Request) -> str:
    if request.issue_number is None:
        return "?"
    label = f"#{request.issue_number}"
    if request.repository:
        return f"[{label}](https://github.com/{request.repository}/issues/{request.issue_number})"
    return label


def _session(request: Request) -> str:
    if not request.session_id:
        return "none"
    if request.session_url:
        return f"[{request.session_id[:14]}…]({request.session_url})"
    return request.session_id


def _outcome(request: Request) -> str:
    if request.decision == "deny":
        return f"refused: {request.reason or 'unspecified'}"
    if request.pull_request:
        state = request.pull_request_state or "open"
        inferred = ", inferred" if request.pull_request_source == "search" else ""
        return f"[PR]({request.pull_request}) ({state}{inferred})"
    if request.session_status:
        return str(request.session_status)
    return "session running or outcome not polled"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "paths", nargs="+", help="audit JSON Lines files or directories of them"
    )
    parser.add_argument("--markdown", help="write the Markdown report here")
    parser.add_argument("--json", dest="json_path", help="write the JSON summary here")
    parser.add_argument(
        "--no-enrich",
        action="store_true",
        help="skip resolving pull-request state through the GitHub API",
    )
    args = parser.parse_args(argv)

    records = load_records(args.paths)
    if not records:
        print("No audit records found; nothing to report.", file=sys.stderr)
        return 1
    requests_ = fold_requests(records)
    if not args.no_enrich:
        token = os.environ.get("GITHUB_TOKEN")
        find_linked_pull_requests(requests_, token)
        enrich_pull_requests(requests_, token)
    metrics = summarize(requests_)
    markdown = render_markdown(requests_, metrics)

    print(markdown)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as handle:
            handle.write(markdown)
    if args.json_path:
        payload = {
            "metrics": metrics,
            "requests": [asdict(request) for request in requests_],
        }
        with open(args.json_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
