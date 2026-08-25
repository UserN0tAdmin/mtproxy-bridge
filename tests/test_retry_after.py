#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Регрессии Retry-After (SECURITY_AUDIT F-3).

До фикса мусорный заголовок релея (``Retry-After: garbage!!``) ронял всю
WEB-сессию необработанным ``ValueError``/``TypeError`` из
``email.utils.parsedate_to_datetime``: исключение выходило из ``_request``
мимо сетевого except-блока и через ``_guarded`` приводило к ``_fail``.
Контракт после фикса: непарсируемый заголовок ≡ «заголовка нет» → 0.0 →
обычный backoff.
"""

import asyncio

import pytest

from mtproxy_bridge.web.http_api import WebApi, parse_retry_after


class TestParseRetryAfter:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            pytest.param("30", 30.0, id="seconds"),
            pytest.param("7", 7.0, id="small-honored"),
            pytest.param("0", 0.0, id="zero"),
            pytest.param("-5", 0.0, id="negative-clamped"),
            pytest.param("99999999999999", 30.0, id="huge-capped"),
            pytest.param(None, 0.0, id="missing-header"),
            pytest.param("", 0.0, id="empty-string"),
            pytest.param("   ", 0.0, id="whitespace-only"),
            # Краш-кейсы до фикса (TypeError на py<=3.9, ValueError на 3.10+):
            pytest.param("garbage!!", 0.0, id="garbage-text"),
            pytest.param("next tuesday", 0.0, id="prose"),
            pytest.param("Thu, 99 Foo 2026 00:00:00 GMT", 0.0, id="bad-date"),
        ],
    )
    def test_never_raises(self, value, expected):
        assert parse_retry_after(value) == expected

    def test_future_http_date_capped(self):
        import email.utils
        import time

        future = email.utils.formatdate(time.time() + 3600, usegmt=True)
        assert parse_retry_after(future) == 30.0

    def test_past_http_date_is_zero(self):
        import email.utils
        import time

        past = email.utils.formatdate(time.time() - 3600, usegmt=True)
        assert parse_retry_after(past) == 0.0


# ---------------------------------------------------------------------------
# 503-loop в WebApi._request с подменённой сессией: мусорный Retry-After
# должен приводить к backoff-паузе и повтору, а не к исключению.
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, status, headers=None, body=b""):
        self.status = status
        self.headers = dict(headers or {})
        self._body = body

    async def read(self):
        return self._body


class _Ctx:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *exc_info):
        return False


class _FakeSession:
    closed = False

    def __init__(self, responses):
        self._responses = list(responses)
        self.requests = []

    def request(self, method, url, **kwargs):
        self.requests.append((method, url))
        return _Ctx(self._responses.pop(0))

    async def close(self):
        self.closed = True


async def _run_down(api, session, monkeypatch, sleeps):
    async def fake_sleep(delay):
        sleeps.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    api._session = session  # type: ignore[assignment]
    return await api.down("tok", 0)


async def test_503_garbage_retry_after_falls_back_to_backoff(monkeypatch):
    api = WebApi("https://relay.example")
    session = _FakeSession(
        [
            _Resp(503, {"Retry-After": "garbage!!"}),
            _Resp(204, {"X-Down-Cursor": "0"}),
        ]
    )
    sleeps: list[float] = []
    result = await _run_down(api, session, monkeypatch, sleeps)

    assert result.has_data is False
    assert len(session.requests) == 2            # повтор после паузы
    assert len(sleeps) == 1 and sleeps[0] > 0    # backoff, а не крах
    await api.close()


async def test_503_retry_after_seconds_is_honored(monkeypatch):
    api = WebApi("https://relay.example")
    session = _FakeSession(
        [
            _Resp(503, {"Retry-After": "7"}),
            _Resp(204, {"X-Down-Cursor": "0"}),
        ]
    )
    sleeps: list[float] = []
    await _run_down(api, session, monkeypatch, sleeps)

    assert len(session.requests) == 2
    assert sleeps[0] == pytest.approx(7.0)
