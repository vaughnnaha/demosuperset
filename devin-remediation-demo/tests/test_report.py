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
import json
import os
import sys
from pathlib import Path
from typing import Any
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import report  # noqa: E402

DENIED = {
    "timestamp": "2026-08-07T19:49:08+00:00",
    "event": "authorization.denied",
    "decision": "deny",
    "reason": "bot actor `devin-ai-integration[bot]` is not allowlisted",
    "repository": "vaughnnaha/demosuperset",
    "issue_number": 3,
    "actor": "devin-ai-integration[bot]",
    "actor_id": 158243242,
    "actor_type": "Bot",
    "run_id": "31212220974",
}
GRANTED = {
    "timestamp": "2026-08-07T20:04:12+00:00",
    "event": "authorization.granted",
    "decision": "allow",
    "repository": "vaughnnaha/demosuperset",
    "issue_number": 3,
    "actor": "vaughnnaha",
    "actor_id": 313640057,
    "actor_type": "User",
    "actor_permission": "admin",
    "run_id": "31214186321",
}
STARTED = {
    "timestamp": "2026-08-07T20:04:14+00:00",
    "event": "session.started",
    "decision": "allow",
    "repository": "vaughnnaha/demosuperset",
    "issue_number": 3,
    "actor": "vaughnnaha",
    "actor_permission": "admin",
    "run_id": "31214186321",
    "session_id": "devin-f73bd27a79f94b919b1172bb215d3127",
    "session_url": "https://app.devin.ai/sessions/f73bd27a79f94b919b1172bb215d3127",
    "session_started_at": "2026-08-07T20:04:12+00:00",
}
ENDED = {
    "timestamp": "2026-08-07T20:24:00+00:00",
    "event": "session.ended",
    "decision": "allow",
    "repository": "vaughnnaha/demosuperset",
    "issue_number": 3,
    "actor": "vaughnnaha",
    "actor_permission": "admin",
    "run_id": "31214186321",
    "session_id": "devin-f73bd27a79f94b919b1172bb215d3127",
    "session_started_at": "2026-08-07T20:04:12+00:00",
    "session_ended_at": "2026-08-07T20:24:00+00:00",
    "session_duration_seconds": 1188,
    "session_status": "finished",
    "pull_request": "https://github.com/vaughnnaha/demosuperset/pull/7",
}


def write_ledger(tmp_path: Path, records: list[dict[str, Any]]) -> str:
    path = tmp_path / "remediation-audit.jsonl"
    with open(path, "w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")
        handle.write("not json\n")  # a truncated line must not break the report
    return str(path)


def test_folds_event_stream_into_one_request_per_run(tmp_path: Path) -> None:
    records = report.load_records([write_ledger(tmp_path, [DENIED, GRANTED, STARTED])])
    assert len(records) == 3

    requests_ = {request.run_id: request for request in report.fold_requests(records)}
    assert set(requests_) == {"31212220974", "31214186321"}

    denied = requests_["31212220974"]
    assert denied.decision == "deny"
    assert denied.actor_type == "Bot"
    assert denied.session_id is None

    allowed = requests_["31214186321"]
    assert allowed.decision == "allow"
    assert allowed.actor_permission == "admin"
    assert allowed.session_id == "devin-f73bd27a79f94b919b1172bb215d3127"


def test_later_records_supersede_earlier_ones(tmp_path: Path) -> None:
    records = report.load_records([write_ledger(tmp_path, [STARTED, ENDED])])
    (request,) = report.fold_requests(records)
    assert request.session_status == "finished"
    assert request.session_duration_seconds == 1188
    assert request.pull_request == "https://github.com/vaughnnaha/demosuperset/pull/7"
    assert request.events == ["session.started", "session.ended"]


def test_summarize_counts_decisions_and_outcomes(tmp_path: Path) -> None:
    records = report.load_records(
        [write_ledger(tmp_path, [DENIED, GRANTED, STARTED, ENDED])]
    )
    requests_ = report.fold_requests(records)
    for request in requests_:
        if request.pull_request:
            request.pull_request_state = "merged"

    metrics = report.summarize(requests_)
    assert metrics["requests"] == 2
    assert metrics["authorized"] == 1
    assert metrics["denied"] == 1
    assert metrics["denial_rate"] == 0.5
    assert metrics["sessions_started"] == 1
    assert metrics["sessions_terminal"] == 1
    assert metrics["pull_requests_opened"] == 1
    assert metrics["pull_requests_merged"] == 1
    assert metrics["merge_rate"] == 1.0
    assert metrics["mean_session_seconds"] == 1188
    assert metrics["issues_touched"] == [3]
    assert DENIED["reason"] in metrics["denial_reasons"]
    assert metrics["actors"]["vaughnnaha"] == 1
    assert metrics["window_start"] == "2026-08-07T19:49:08+00:00"
    assert metrics["window_end"] == "2026-08-07T20:24:00+00:00"


def test_markdown_reports_both_paths(tmp_path: Path) -> None:
    records = report.load_records(
        [write_ledger(tmp_path, [DENIED, GRANTED, STARTED, ENDED])]
    )
    requests_ = report.fold_requests(records)
    markdown = report.render_markdown(requests_, report.summarize(requests_))

    assert "Denial rate | 50%" in markdown
    assert "not allowlisted" in markdown
    assert "devin-ai-integration[bot] (bot)" in markdown
    assert "https://github.com/vaughnnaha/demosuperset/pull/7" in markdown
    assert "19m 48s" in markdown


def test_enrichment_marks_merged_pull_requests(tmp_path: Path) -> None:
    records = report.load_records([write_ledger(tmp_path, [GRANTED, STARTED, ENDED])])
    requests_ = report.fold_requests(records)
    with mock.patch.object(report.requests, "get") as get:
        get.return_value = mock.Mock(
            status_code=200,
            json=lambda: {"state": "closed", "merged_at": "2026-08-07T21:00:00Z"},
        )
        report.enrich_pull_requests(requests_, "token")

    assert get.call_args.args[0] == (
        "https://api.github.com/repos/vaughnnaha/demosuperset/pulls/7"
    )
    assert requests_[0].pull_request_state == "merged"


def test_search_attributes_a_pull_request_when_polling_was_off(tmp_path: Path) -> None:
    requests_ = report.fold_requests(
        report.load_records([write_ledger(tmp_path, [GRANTED, STARTED])])
    )
    assert requests_[0].pull_request is None

    with mock.patch.object(report.requests, "get") as get:
        get.return_value = mock.Mock(
            status_code=200,
            json=lambda: {
                "items": [
                    {
                        "html_url": "https://github.com/vaughnnaha/demosuperset/pull/1",
                        "created_at": "2026-08-06T00:00:00Z",
                    },
                    {
                        "html_url": "https://github.com/vaughnnaha/demosuperset/pull/7",
                        "created_at": "2026-08-07T20:20:00Z",
                    },
                ]
            },
        )
        report.find_linked_pull_requests(requests_, "token")

    assert get.call_args.kwargs["params"]["q"] == (
        'repo:vaughnnaha/demosuperset type:pr in:body "#3"'
    )
    assert (
        requests_[0].pull_request == "https://github.com/vaughnnaha/demosuperset/pull/7"
    )
    assert requests_[0].pull_request_source == "search"
    assert "inferred" in report._outcome(requests_[0])


def test_search_skips_denied_requests(tmp_path: Path) -> None:
    requests_ = report.fold_requests(
        report.load_records([write_ledger(tmp_path, [DENIED])])
    )
    with mock.patch.object(report.requests, "get") as get:
        report.find_linked_pull_requests(requests_, "token")
    get.assert_not_called()


def test_enrichment_is_skipped_without_a_token(tmp_path: Path) -> None:
    requests_ = report.fold_requests(
        report.load_records([write_ledger(tmp_path, [GRANTED, STARTED, ENDED])])
    )
    with mock.patch.object(report.requests, "get") as get:
        report.enrich_pull_requests(requests_, None)
    get.assert_not_called()
    assert requests_[0].pull_request_state is None


def test_main_writes_both_artifacts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ledger = write_ledger(tmp_path, [DENIED, GRANTED, STARTED, ENDED])
    markdown_path = tmp_path / "report.md"
    json_path = tmp_path / "report.json"

    exit_code = report.main(
        [
            ledger,
            "--no-enrich",
            "--markdown",
            str(markdown_path),
            "--json",
            str(json_path),
        ]
    )

    assert exit_code == 0
    assert "Devin remediation effectiveness report" in capsys.readouterr().out
    assert "Sessions started | 1" in markdown_path.read_text()
    payload = json.loads(json_path.read_text())
    assert payload["metrics"]["authorized"] == 1
    assert len(payload["requests"]) == 2


def test_main_exits_nonzero_without_records(tmp_path: Path) -> None:
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert report.main([str(empty), "--no-enrich"]) == 1
