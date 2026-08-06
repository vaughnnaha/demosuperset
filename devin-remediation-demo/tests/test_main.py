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

import main  # noqa: E402


def make_event(
    label: str = "devin-remediation", action: str = "labeled"
) -> dict[str, Any]:
    return {
        "action": action,
        "label": {"name": label},
        "issue": {
            "number": 3,
            "title": "test(native-filters): cover defaultToFirstItem clear",
            "body": "## Problem\nMissing regression coverage.",
            "html_url": "https://github.com/vaughnnaha/demosuperset/issues/3",
        },
        "repository": {
            "full_name": "vaughnnaha/demosuperset",
            "html_url": "https://github.com/vaughnnaha/demosuperset",
            "default_branch": "master",
        },
    }


def test_ignores_irrelevant_label() -> None:
    assert main.is_trigger_event(make_event(label="bug")) is False
    assert main.is_trigger_event(make_event(action="opened")) is False
    assert main.is_trigger_event(make_event()) is True


def test_valid_event_produces_expected_devin_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(make_event()))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("DEVIN_API_KEY", "test-key")
    monkeypatch.setenv("GITHUB_TOKEN", "gh-token")
    monkeypatch.setenv("POLL_TIMEOUT_SECONDS", "0")

    post = mock.Mock()
    post.return_value = mock.Mock(
        status_code=200,
        json=lambda: {
            "session_id": "devin-abc123",
            "url": "https://app.devin.ai/sessions/abc123",
        },
    )
    with mock.patch.object(main.requests, "post", post):
        assert main.main() == 0

    devin_call, comment_call = post.call_args_list
    assert devin_call.args[0] == "https://api.devin.ai/v1/sessions"
    assert devin_call.kwargs["headers"]["Authorization"] == "Bearer test-key"
    prompt = devin_call.kwargs["json"]["prompt"]
    assert "https://github.com/vaughnnaha/demosuperset/issues/3" in prompt
    assert "Do not modify production code." in prompt
    assert "Missing regression coverage." in prompt

    assert comment_call.args[0] == (
        "https://api.github.com/repos/vaughnnaha/demosuperset/issues/3/comments"
    )
    assert "https://app.devin.ai/sessions/abc123" in comment_call.kwargs["json"]["body"]


def test_missing_api_key_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEVIN_API_KEY", raising=False)
    assert main.main() == 1


def test_missing_event_payload_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEVIN_API_KEY", "test-key")
    monkeypatch.setenv("GITHUB_EVENT_PATH", "/nonexistent/event.json")
    assert main.main() == 1


def test_devin_api_failure_exits_nonzero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text(json.dumps(make_event()))
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))
    monkeypatch.setenv("DEVIN_API_KEY", "test-key")

    with mock.patch.object(
        main.requests,
        "post",
        mock.Mock(return_value=mock.Mock(status_code=401, text="unauthorized")),
    ):
        assert main.main() == 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
