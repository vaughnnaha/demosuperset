# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain
# a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import time
from collections.abc import Iterator
from datetime import datetime, timezone

import pytest
from sqlalchemy.orm.session import Session

from superset.models.task_subscribers import TaskSubscriber

TASK_ID = 42


@pytest.fixture
def session_with_subscribers(session: Session) -> Iterator[Session]:
    """Create a session with the ``task_subscribers`` table."""
    TaskSubscriber.metadata.create_all(session.get_bind())

    yield session
    session.rollback()


def test_subscribed_at_default_is_callable() -> None:
    """The column default must be evaluated per insert, not at import time"""
    default = TaskSubscriber.__table__.c.subscribed_at.default
    assert default is not None
    assert default.is_callable


def test_subscribed_at_evaluated_per_insert(session_with_subscribers: Session) -> None:
    """Rows inserted at different times get different naive UTC timestamps"""
    before = datetime.now(timezone.utc).replace(tzinfo=None)

    first = TaskSubscriber(task_id=TASK_ID, user_id=1)
    session_with_subscribers.add(first)
    session_with_subscribers.flush()

    time.sleep(0.01)

    second = TaskSubscriber(task_id=TASK_ID, user_id=2)
    session_with_subscribers.add(second)
    session_with_subscribers.flush()

    after = datetime.now(timezone.utc).replace(tzinfo=None)

    assert first.subscribed_at != second.subscribed_at
    assert first.subscribed_at < second.subscribed_at
    for subscriber in (first, second):
        assert subscriber.subscribed_at.tzinfo is None
        assert before <= subscriber.subscribed_at <= after
