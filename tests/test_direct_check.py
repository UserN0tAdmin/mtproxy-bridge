#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Тесты ``check_link`` для классического MTProxy (direct-режим).

``test_check.py`` покрывает парсер ответа и один happy-path для bare-секрета.
Здесь — все три типа секрета против независимого фейкового MTProxy, стадии
отказов (connect / handshake / ping), тайм-бюджет и текстовый вывод CLI.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import struct
import time

import pytest
from direct_fakes import (  # noqa: F401
    DOMAIN,
    SECRET_DD,
    SECRET_EE,
    SECRET_PLAIN,
    TAG_ABRIDGED,
    TAG_PADDED,
    LoopThread,
    frame,
    free_port,
    make_link,
    parse_frame,
    parse_req_pq_multi,
    respq_handler,
)

from mtproxy_bridge import check_link, check_link_sync
from mtproxy_bridge.check import CheckResult, StageResult, _FrameReader, frame_payload
from mtproxy_bridge.cli import _render_check_text


@dataclasses.dataclass(frozen=True)
class Mode:
    id: str
    secret_hex: str
    domain: str | None
    transport: str  # как его называет CheckResult.transport
    stages: tuple  # ожидаемые стадии успешной проверки


MODES = [
    Mode("bare", SECRET_PLAIN, None, "abridged", ("parse", "connect", "ping")),
    Mode("dd", SECRET_DD, None, "padded intermediate", ("parse", "connect", "ping")),
    Mode(
        "ee",
        SECRET_EE,
        DOMAIN,
        "padded intermediate",
        ("parse", "connect", "handshake", "ping"),
    ),
]


@pytest.fixture(params=MODES, ids=[m.id for m in MODES])
def mode(request):
    return request.param


# ============================================================================
# Успех
# ============================================================================


class TestAlive:
    async def test_ok_for_every_secret_type(self, mode, proxy_factory):
        proxy = await proxy_factory(domain=mode.domain, handler=respq_handler())
        result = await check_link(make_link(proxy.port, mode.secret_hex), timeout=10)
        assert result.ok, f"{result.stage}: {result.error}"
        assert result.mode == "direct"
        assert result.transport == mode.transport
        assert tuple(s.name for s in result.stages) == mode.stages
        assert all(s.ok for s in result.stages)
        assert result.stage == "ping"
        assert result.error is None and result.mtproto_error is None
        assert result.carrier is None
        assert result.rtt_ms is not None and 0 <= result.rtt_ms <= result.total_ms

    async def test_dc_id_reaches_the_proxy(self, mode, proxy_factory):
        proxy = await proxy_factory(domain=mode.domain, handler=respq_handler())
        result = await check_link(make_link(proxy.port, mode.secret_hex), dc_id=4)
        assert result.ok and result.dc_id == 4
        assert proxy.connections[0].dc == 4

    async def test_default_dc_is_2(self, mode, proxy_factory):
        proxy = await proxy_factory(domain=mode.domain, handler=respq_handler())
        result = await check_link(make_link(proxy.port, mode.secret_hex))
        assert result.dc_id == 2 and proxy.connections[0].dc == 2

    async def test_proxy_sees_a_well_formed_req_pq_multi(self, mode, proxy_factory):
        # respq_handler строго разбирает пакет (auth_key_id=0, inner_len кратен
        # 16, constructor req_pq_multi) и падает на любом нарушении.
        seen = []

        async def spy(conn):
            buf = bytearray()
            while True:
                data = await conn.read()
                if not data:
                    return
                buf += data
                msg = parse_frame(conn.tag, buf)
                if msg is not None:
                    seen.append(parse_req_pq_multi(msg))
                    return

        proxy = await proxy_factory(domain=mode.domain, handler=spy)
        await check_link(make_link(proxy.port, mode.secret_hex), timeout=2)
        assert len(seen) == 1 and len(seen[0]) == 16

    async def test_every_check_uses_a_fresh_nonce(self, proxy_factory):
        nonces = []

        async def spy(conn):
            buf = bytearray()
            while True:
                data = await conn.read()
                if not data:
                    return
                buf += data
                msg = parse_frame(conn.tag, buf)
                if msg is not None:
                    nonces.append(parse_req_pq_multi(msg))
                    return

        proxy = await proxy_factory(domain=None, handler=spy)
        for _ in range(5):
            await check_link(make_link(proxy.port, SECRET_PLAIN), timeout=1)
        assert len(set(nonces)) == 5

    async def test_nop_and_quick_ack_before_the_answer_are_skipped(
        self, mode, proxy_factory
    ):
        proxy = await proxy_factory(
            domain=mode.domain, handler=respq_handler("nop_then_respq")
        )
        result = await check_link(make_link(proxy.port, mode.secret_hex), timeout=10)
        assert result.ok, f"{result.stage}: {result.error}"

    @pytest.mark.parametrize(("m", "e"), [(True, True), (False, False)])
    async def test_faketls_flags_do_not_break_the_check(self, proxy_factory, m, e):
        proxy = await proxy_factory(domain=DOMAIN, handler=respq_handler())
        result = await check_link(
            make_link(proxy.port, SECRET_EE), use_block_m=m, use_block_e=e
        )
        assert result.ok, result.error

    async def test_no_ccs_flag(self, proxy_factory):
        proxy = await proxy_factory(domain=DOMAIN, handler=respq_handler())
        result = await check_link(make_link(proxy.port, SECRET_EE), send_ccs=False)
        assert result.ok
        assert not proxy.connections[0].saw_ccs

    async def test_ccs_by_default(self, proxy_factory):
        proxy = await proxy_factory(domain=DOMAIN, handler=respq_handler())
        await check_link(make_link(proxy.port, SECRET_EE))
        assert proxy.connections[0].saw_ccs

    async def test_connection_is_closed_after_the_check(self, mode, proxy_factory):
        proxy = await proxy_factory(domain=mode.domain, handler=respq_handler())
        await check_link(make_link(proxy.port, mode.secret_hex))
        await asyncio.wait_for(proxy.connections[0].closed.wait(), 5)

    async def test_stage_timings_are_consistent(self, mode, proxy_factory):
        proxy = await proxy_factory(domain=mode.domain, handler=respq_handler())
        result = await check_link(make_link(proxy.port, mode.secret_hex))
        timed = [s.ms for s in result.stages if s.ms is not None]
        assert all(ms >= 0 for ms in timed)
        assert sum(timed) <= result.total_ms + 5  # стадии — части общего времени


# ============================================================================
# Отказы на стадии ping
# ============================================================================


class TestPingFailures:
    @pytest.mark.parametrize(
        ("scenario", "expected_error", "mtproto_error"),
        [
            ("wrong_nonce", "nonce mismatch", None),
            ("echo", "unknown response constructor", None),
            ("error404", "-404", -404),
        ],
    )
    async def test_bad_answers(
        self, mode, proxy_factory, scenario, expected_error, mtproto_error
    ):
        proxy = await proxy_factory(domain=mode.domain, handler=respq_handler(scenario))
        result = await check_link(make_link(proxy.port, mode.secret_hex), timeout=10)
        assert not result.ok
        assert result.stage == "ping"
        assert result.stages[-1] == StageResult(
            "ping", False, None, result.stages[-1].detail
        )
        assert expected_error in (result.error or "")
        assert result.mtproto_error == mtproto_error
        assert result.rtt_ms is None

    async def test_proxy_closes_without_answering(self, mode, proxy_factory):
        proxy = await proxy_factory(domain=mode.domain, handler=respq_handler("close"))
        result = await check_link(make_link(proxy.port, mode.secret_hex), timeout=10)
        assert not result.ok and result.stage == "ping"
        assert "closed" in (result.error or "")

    async def test_silent_proxy_times_out_within_the_budget(self, mode, proxy_factory):
        proxy = await proxy_factory(domain=mode.domain, handler=respq_handler("silent"))
        started = time.monotonic()
        result = await check_link(make_link(proxy.port, mode.secret_hex), timeout=0.8)
        elapsed = time.monotonic() - started
        assert not result.ok and result.stage == "ping"
        assert "timed out" in (result.error or "")
        assert elapsed < 3.0

    async def test_wrong_secret_plain_looks_like_a_dead_ping(self, proxy_factory):
        # Прокси с другим секретом не может разобрать init и закрывает сокет.
        proxy = await proxy_factory(
            secret=bytes(16), domain=None, handler=respq_handler()
        )
        result = await check_link(make_link(proxy.port, SECRET_PLAIN), timeout=5)
        assert not result.ok and result.stage == "ping"
        assert [s.name for s in result.stages] == ["parse", "connect", "ping"]


# ============================================================================
# Отказы на стадиях connect / handshake
# ============================================================================


class TestEarlyFailures:
    async def test_connection_refused(self, mode):
        result = await check_link(make_link(free_port(), mode.secret_hex), timeout=5)
        assert not result.ok and result.stage == "connect"
        assert [s.name for s in result.stages] == ["parse", "connect"]
        assert result.stages[0].ok and not result.stages[1].ok
        assert result.error and result.error != "None"
        assert result.mtproto_error is None and result.rtt_ms is None

    async def test_connect_timeout(self, mode, monkeypatch):
        blackhole = "10.255.255.1"
        real_open = asyncio.open_connection

        async def fake_open(host, port, *args, **kwargs):
            if host == blackhole:
                await asyncio.sleep(3600)
            return await real_open(host, port, *args, **kwargs)

        monkeypatch.setattr(asyncio, "open_connection", fake_open)
        started = time.monotonic()
        result = await check_link(
            make_link(443, mode.secret_hex, host=blackhole), timeout=0.3
        )
        assert not result.ok and result.stage == "connect"
        assert "timeout" in (result.error or "")
        assert time.monotonic() - started < 3

    async def test_faketls_wrong_secret_fails_at_handshake(self, proxy_factory):
        proxy = await proxy_factory(secret=bytes(16), domain=DOMAIN)
        result = await check_link(make_link(proxy.port, SECRET_EE), timeout=5)
        assert not result.ok and result.stage == "handshake"
        assert [s.name for s in result.stages] == ["parse", "connect", "handshake"]
        assert "FakeTLS handshake" in (result.error or "")
        assert proxy.connections[0].fallback_served

    async def test_faketls_server_that_never_answers(self, scripted_factory):
        server = await scripted_factory(None, after="hang")
        started = time.monotonic()
        result = await check_link(make_link(server.port, SECRET_EE), timeout=0.6)
        assert not result.ok and result.stage == "handshake"
        assert time.monotonic() - started < 3

    async def test_plain_server_for_faketls_link(self, scripted_factory):
        # Ссылка с ee-секретом, а сервер отвечает обычным HTTP.
        server = await scripted_factory(lambda _h: b"HTTP/1.1 400 Bad Request\r\n\r\n")
        result = await check_link(make_link(server.port, SECRET_EE), timeout=5)
        assert not result.ok and result.stage == "handshake"

    @pytest.mark.parametrize(
        "link",
        [
            "tg://proxy?server=h.io&port=443",  # нет секрета
            "tg://proxy?server=h.io&port=443&secret=" + "00" * 15,  # длина
            "tg://proxy?server=h.io&port=abc&secret=" + "00" * 16,  # порт
            "",
        ],
        ids=["no-secret", "bad-length", "bad-port", "empty"],
    )
    async def test_invalid_link_is_a_result_not_an_exception(self, link):
        result = await check_link(link)
        assert not result.ok and result.stage == "parse"
        assert [s.name for s in result.stages] == ["parse"]
        assert (result.error or "").startswith("invalid link")

    async def test_total_budget_is_shared_between_stages(self, scripted_factory):
        # Сервер отвечает на ClientHello корректно «по виду», но медленно:
        # весь check укладывается в общий timeout, а не в сумму таймаутов.
        server = await scripted_factory(None, after="hang")
        started = time.monotonic()
        await check_link(make_link(server.port, SECRET_EE), timeout=1.0)
        assert time.monotonic() - started < 2.5


# ============================================================================
# Фрейминг check (frame_payload / _FrameReader): байты на проводе
# ============================================================================


class TestFraming:
    """Точная раскладка фреймов; сравнение — с независимым ``direct_fakes``."""

    def test_abridged_short_header_is_one_byte(self):
        payload = bytes(range(8))
        assert frame_payload(TAG_ABRIDGED, payload) == b"\x02" + payload

    @pytest.mark.parametrize(
        ("ints", "header"),
        [
            (1, b"\x01"),
            (125, b"\x7d"),
            (126, b"\x7e"),  # последняя длина с однобайтным заголовком
            (127, b"\x7f\x7f\x00\x00"),  # первая с расширенным: 0x7F + 3 байта LE
            (128, b"\x7f\x80\x00\x00"),
            (1000, b"\x7f\xe8\x03\x00"),
            (65536, b"\x7f\x00\x00\x01"),
        ],
    )
    def test_abridged_length_boundaries(self, ints, header):
        payload = os.urandom(4 * ints)
        assert frame_payload(TAG_ABRIDGED, payload) == header + payload

    def test_padded_header_counts_the_padding(self):
        payload = os.urandom(40)
        pads = set()
        for _ in range(600):
            framed = frame_payload(TAG_PADDED, payload)
            size = struct.unpack("<I", framed[:4])[0]
            pad = size - len(payload)
            assert 0 <= pad <= 15
            assert len(framed) == 4 + size
            assert framed[4 : 4 + len(payload)] == payload
            pads.add(pad)
        assert pads == set(range(16))  # паддинг действительно случаен во всём диапазоне

    @pytest.mark.parametrize("size", [1, 2, 3, 5, 10])
    @pytest.mark.parametrize(
        "tag", [TAG_ABRIDGED, TAG_PADDED], ids=["abridged", "padded"]
    )
    def test_payload_must_be_a_multiple_of_four(self, tag, size):
        with pytest.raises(ValueError):
            frame_payload(tag, bytes(size))

    @pytest.mark.parametrize(
        "tag", [TAG_ABRIDGED, TAG_PADDED], ids=["abridged", "padded"]
    )
    @pytest.mark.parametrize("ints", [1, 2, 126, 127, 128, 5000])
    def test_both_implementations_agree(self, tag, ints):
        payload = os.urandom(4 * ints)
        # Независимый разбор из direct_fakes понимает то, что собрал мост...
        buf = bytearray(frame_payload(tag, payload))
        msg = parse_frame(tag, buf)
        assert msg.startswith(payload)
        # ...а читатель моста — то, что собрал независимый код.
        reader = _FrameReader(tag)
        reader.feed(
            frame(tag, payload, pad=0) if tag == TAG_PADDED else frame(tag, payload)
        )
        assert reader.next_message() == payload

    @pytest.mark.parametrize(
        "tag", [TAG_ABRIDGED, TAG_PADDED], ids=["abridged", "padded"]
    )
    def test_reader_assembles_partial_input(self, tag):
        payload = os.urandom(200)
        wire = frame(tag, payload, pad=0) if tag == TAG_PADDED else frame(tag, payload)
        reader = _FrameReader(tag)
        for i in range(len(wire) - 1):
            reader.feed(wire[i : i + 1])
            assert reader.next_message() is None
        reader.feed(wire[-1:])
        assert reader.next_message() == payload
        assert reader.next_message() is None

    @pytest.mark.parametrize(
        "tag", [TAG_ABRIDGED, TAG_PADDED], ids=["abridged", "padded"]
    )
    def test_reader_splits_back_to_back_frames(self, tag):
        first, second = os.urandom(16), os.urandom(32)
        mk = (
            (lambda p: frame(tag, p, pad=0))
            if tag == TAG_PADDED
            else (lambda p: frame(tag, p))
        )
        reader = _FrameReader(tag)
        reader.feed(mk(first) + mk(second))
        assert reader.next_message() == first
        assert reader.next_message() == second
        assert reader.next_message() is None

    def test_abridged_zero_length_is_a_protocol_error(self):
        reader = _FrameReader(TAG_ABRIDGED)
        reader.feed(b"\x00")
        with pytest.raises(Exception, match="invalid frame length"):
            reader.next_message()

    def test_padded_quick_ack_word_alone_is_skipped(self):
        reader = _FrameReader(TAG_PADDED)
        reader.feed(struct.pack("<I", 0x80000001))
        assert reader.next_message() is None
        payload = os.urandom(16)
        reader.feed(frame(TAG_PADDED, payload, pad=0))
        assert reader.next_message() == payload

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "_FrameReader.next_message() после пропуска quick-ack слова возвращает None, "
            "хотя в буфере уже целый фрейм; вызывающий код трактует None как «нужны ещё "
            "данные». Нужен `continue` вместо `return None`. Малозначимо: на req_pq "
            "(plain-пакет) quick-ack от DC не приходит. Снимите маркер после исправления."
        ),
    )
    def test_padded_quick_ack_followed_by_a_frame_in_one_chunk(self):
        reader = _FrameReader(TAG_PADDED)
        payload = os.urandom(16)
        reader.feed(struct.pack("<I", 0x80000001) + frame(TAG_PADDED, payload, pad=0))
        assert reader.next_message() == payload  # сразу, без нового feed()

    @pytest.mark.xfail(
        strict=True,
        reason="Следствие бага выше на уровне check_link (см. test_padded_quick_ack_*).",
    )
    async def test_check_survives_quick_ack_glued_to_the_answer(self, proxy_factory):
        async def handler(conn):
            buf = bytearray()
            while True:
                data = await conn.read()
                if not data:
                    return
                buf += data
                msg = parse_frame(conn.tag, buf)
                if msg is not None:
                    nonce = parse_req_pq_multi(msg)
                    from direct_fakes import build_respq

                    # quick-ack и resPQ уходят одной записью — одним TCP-сегментом.
                    await conn.write(
                        struct.pack("<I", 0x80000001)
                        + frame(conn.tag, build_respq(nonce))
                    )
                    return

        proxy = await proxy_factory(domain=None, handler=handler)
        result = await check_link(make_link(proxy.port, SECRET_DD), timeout=1.0)
        assert result.ok, f"{result.stage}: {result.error}"


# ============================================================================
# Результат и sync-обёртка
# ============================================================================


class TestResultShape:
    async def test_json_roundtrip(self, mode, proxy_factory):
        proxy = await proxy_factory(domain=mode.domain, handler=respq_handler())
        result = await check_link(make_link(proxy.port, mode.secret_hex))
        data = json.loads(result.to_json())
        assert data == result.to_dict()
        assert data["ok"] is True and data["mode"] == "direct"
        assert tuple(s["name"] for s in data["stages"]) == mode.stages
        assert set(data["stages"][0]) == {"name", "ok", "ms", "detail"}

    async def test_failure_json_keeps_the_error_code(self, proxy_factory):
        proxy = await proxy_factory(domain=None, handler=respq_handler("error404"))
        data = json.loads(
            (await check_link(make_link(proxy.port, SECRET_PLAIN))).to_json()
        )
        assert data["ok"] is False and data["mtproto_error"] == -404
        assert data["stage"] == "ping" and data["error"]

    def test_check_link_sync_from_plain_code(self):
        loop = LoopThread().start()
        try:

            async def start():
                from direct_fakes import FakeMTProxy

                proxy = FakeMTProxy(domain=None, handler=respq_handler())
                await proxy.start()
                return proxy

            proxy = loop.call(start())
            result = check_link_sync(make_link(proxy.port, SECRET_PLAIN), timeout=10)
            assert result.ok, result.error
            loop.call(proxy.stop())
        finally:
            loop.stop()

    def test_check_link_sync_reports_invalid_link(self):
        result = check_link_sync("tg://proxy?server=h.io")
        assert not result.ok and result.stage == "parse"


# ============================================================================
# Текстовый вывод CLI (_render_check_text)
# ============================================================================


def _result(ok=True, **kw) -> CheckResult:
    stages = kw.pop(
        "stages",
        (
            StageResult("parse", True, 0.0, "tg://proxy, transport: abridged"),
            StageResult("connect", True, 84.2, "1.2.3.4:443"),
            StageResult(
                "ping",
                ok,
                158.4 if ok else None,
                "resPQ, nonce matched" if ok else "boom",
            ),
        ),
    )
    base = dict(
        ok=ok,
        mode="direct",
        stage="ping",
        error=None if ok else "boom",
        mtproto_error=None,
        rtt_ms=158.4 if ok else None,
        total_ms=243.0,
        dc_id=2,
        transport="abridged",
        stages=stages,
    )
    base.update(kw)
    return CheckResult(**base)


class TestRenderText:
    def test_alive(self, capsys):
        _render_check_text(_result())
        out = capsys.readouterr().out.splitlines()
        assert out[0].startswith("[1/3] Link") and out[0].endswith(
            "tg://proxy, transport: abridged"
        )
        assert (
            out[1].startswith("[2/3] TCP connect")
            and "OK" in out[1]
            and "84 ms" in out[1]
        )
        assert out[2].startswith("[3/3] MTProto ping") and "158 ms" in out[2]
        assert out[-1] == "Proxy works (total 243 ms, ping 158 ms)"

    def test_dead(self, capsys):
        _render_check_text(_result(ok=False))
        out = capsys.readouterr().out.splitlines()
        assert "FAIL" in out[2]
        assert out[-1] == 'Proxy is NOT working — stage "MTProto ping": boom'

    def test_faketls_stage_label(self, capsys):
        stages = (
            StageResult("parse", True, 0.0, ""),
            StageResult("connect", True, 1.0, ""),
            StageResult("handshake", False, None, "HMAC mismatch"),
        )
        _render_check_text(
            _result(ok=False, stage="handshake", error="HMAC mismatch", stages=stages)
        )
        out = capsys.readouterr().out
        assert "FakeTLS handshake" in out and "FAIL" in out
        assert 'stage "FakeTLS handshake": HMAC mismatch' in out

    def test_alive_without_rtt(self, capsys):
        _render_check_text(_result(rtt_ms=None))
        assert capsys.readouterr().out.splitlines()[-1] == "Proxy works (total 243 ms)"
