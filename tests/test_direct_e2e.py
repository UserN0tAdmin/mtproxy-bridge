#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Сквозные тесты классического MTProxy: SOCKS5-клиент → мост → фейковый прокси.

Зеркало ``test_web_e2e.py`` для direct-режима. Фейковый MTProxy
(``direct_fakes.FakeMTProxy``) реализует серверную сторону независимо от
моста и ведёт журнал соединений, поэтому тесты проверяют именно то, что
видит прокси: транспортный тег, DC ID, TLS-записи, CCS, digest ClientHello.

Каждый сценарий, где это уместно, прогоняется для всех трёх типов секрета:
``bare`` (obfuscated2 + abridged), ``dd`` (obfuscated2 + padded) и ``ee``
(FakeTLS + padded).
"""

from __future__ import annotations

import asyncio
import dataclasses
import os
import struct
import time

import pytest
from direct_fakes import (  # noqa: F401
    CDN_IP,
    DC2_IP,
    DC3_IP,
    DC4_IP,
    DOMAIN,
    SECRET_DD,
    SECRET_EE,
    SECRET_PLAIN,
    TAG_ABRIDGED,
    TAG_PADDED,
    Conn,
    FakeMTProxy,
    close_writer,
    drain_to_eof,
    echo_handler,
    eventually,
    free_port,
    make_link,
    read_exactly,
    socks5_connect,
)

from mtproxy_bridge import faketls
from mtproxy_bridge import relay as relay_mod
from mtproxy_bridge import server as server_mod

# ============================================================================
# Параметризация по типу секрета
# ============================================================================


@dataclasses.dataclass(frozen=True)
class Mode:
    id: str
    secret_hex: str
    client_tag: bytes  # что клиент (Kurigram) шлёт первым после SOCKS5
    server_tag: bytes  # тег, который прокси должен увидеть в obfuscated2 init
    domain: str | None  # SNI для FakeTLS; None — голый obfuscated2

    @property
    def tls(self) -> bool:
        return self.domain is not None


MODES = [
    Mode("bare", SECRET_PLAIN, b"\xef", TAG_ABRIDGED, None),
    Mode("dd", SECRET_DD, b"\xdd\xdd\xdd\xdd", TAG_PADDED, None),
    Mode("ee", SECRET_EE, b"\xdd\xdd\xdd\xdd", TAG_PADDED, DOMAIN),
]
TLS_MODE = MODES[2]

# Первую нагрузку делаем не короче 4 байт: для bare-секрета мост читает сразу
# 4 байта (тег 0xEF + 3 байта данных), а настоящий клиент всегда начинает
# с req_pq (десятки байт). См. TestClientValidation.test_abridged_*.
PING = b"ping"


@dataclasses.dataclass
class Env:
    mode: Mode
    proxy: FakeMTProxy
    port: int  # локальный порт моста

    async def connect(self, target: str = DC2_IP, **kw):
        return await socks5_connect(self.port, target, **kw)

    async def session(self, first: bytes = b"", target: str = DC2_IP):
        """SOCKS5 CONNECT + транспортный тег + первые байты нагрузки."""
        reader, writer = await self.connect(target)
        writer.write(self.mode.client_tag + first)
        return reader, writer


@pytest.fixture(params=MODES, ids=[m.id for m in MODES])
def mode(request):
    return request.param


@pytest.fixture
async def env_factory(mode, proxy_factory, bridge_factory):
    """``await make(handler=..., proxy_kwargs={...}, **bridge_kwargs) -> Env``."""

    async def make(handler=echo_handler, *, proxy_kwargs=None, **bridge_kwargs) -> Env:
        proxy = await proxy_factory(
            domain=mode.domain, handler=handler, **(proxy_kwargs or {})
        )
        port = await bridge_factory(
            make_link(proxy.port, mode.secret_hex), **bridge_kwargs
        )
        return Env(mode, proxy, port)

    return make


@pytest.fixture
async def env(env_factory):
    return await env_factory()


@pytest.fixture
async def tls_env(proxy_factory, bridge_factory):
    """Окружение только для FakeTLS-проверок (ee-секрет)."""

    async def make(handler=echo_handler, *, proxy_kwargs=None, **bridge_kwargs) -> Env:
        proxy = await proxy_factory(
            domain=DOMAIN, handler=handler, **(proxy_kwargs or {})
        )
        port = await bridge_factory(
            make_link(proxy.port, TLS_MODE.secret_hex), **bridge_kwargs
        )
        return Env(TLS_MODE, proxy, port)

    return make


async def _read_until(
    reader: asyncio.StreamReader, n: int, timeout: float = 20.0
) -> bytes:
    return await read_exactly(reader, n, timeout)


# ============================================================================
# Основной релей
# ============================================================================


class TestRelay:
    async def test_echo_roundtrip(self, env):
        reader, writer = await env.session(b"hello telegram")
        assert await _read_until(reader, 14) == b"hello telegram"
        await close_writer(writer)

    async def test_proxy_sees_the_transport_tag_and_dc(self, env):
        reader, writer = await env.session(b"ping")
        await _read_until(reader, 4)
        rec = env.proxy.connections[0]
        assert rec.handshake_ok
        assert rec.tag == env.mode.server_tag
        assert rec.dc == 2
        assert bytes(rec.received) == b"ping"  # тег до прокси не доходит
        await close_writer(writer)

    async def test_tag_in_its_own_write(self, env):
        reader, writer = await env.connect()
        writer.write(env.mode.client_tag[:1])
        await writer.drain()
        await asyncio.sleep(0.05)
        writer.write(env.mode.client_tag[1:] + b"after-tag")
        assert await _read_until(reader, 9) == b"after-tag"
        await close_writer(writer)

    async def test_payload_in_many_small_writes_keeps_order(self, env):
        reader, writer = await env.session()
        expected = bytearray()
        for i in range(200):
            piece = struct.pack("<I", i) + b"abc"
            expected += piece
            writer.write(piece)
            if i % 20 == 0:
                await writer.drain()
        got = await _read_until(reader, len(expected))
        assert got == bytes(expected)
        await close_writer(writer)

    async def test_large_bidirectional_transfer(self, env):
        payload = os.urandom(1_500_000)
        reader, writer = await env.session()

        async def send():
            for i in range(0, len(payload), 65536):
                writer.write(payload[i : i + 65536])
                await writer.drain()

        sender = asyncio.ensure_future(send())
        got = await _read_until(reader, len(payload), timeout=60)
        await sender
        assert got == payload
        await close_writer(writer)

    async def test_server_can_speak_first(self, env_factory):
        async def greeter(conn: Conn) -> None:
            await conn.write(b"welcome!")
            await echo_handler(conn)

        env = await env_factory(greeter)
        reader, writer = await env.session(b"abc")
        assert await _read_until(reader, 8 + 3) == b"welcome!abc"
        await close_writer(writer)

    async def test_upstream_close_ends_the_client_connection(self, env_factory):
        async def one_shot(conn: Conn) -> None:
            await conn.read()

        env = await env_factory(one_shot)
        reader, writer = await env.session(b"bye")
        assert await drain_to_eof(reader) == b""
        await close_writer(writer)

    async def test_client_close_closes_the_upstream_connection(self, env):
        reader, writer = await env.session(PING)
        await _read_until(reader, 4)
        await close_writer(writer)
        rec = env.proxy.connections[0]
        await asyncio.wait_for(rec.closed.wait(), 5)
        assert rec.client_eof

    async def test_each_connection_gets_its_own_obfuscated2_init(self, env):
        sessions = [await env.session(PING) for _ in range(5)]
        for reader, _w in sessions:
            await _read_until(reader, 4)
        inits = [rec.init for rec in env.proxy.connections]
        assert len(inits) == 5 and len(set(inits)) == 5
        assert all(init[0] != 0xEF for init in inits)
        for _r, w in sessions:
            await close_writer(w)

    async def test_many_concurrent_clients(self, env):
        async def one(i: int) -> bool:
            payload = os.urandom(300) + struct.pack("<I", i)
            reader, writer = await env.session(payload)
            ok = await _read_until(reader, len(payload)) == payload
            await close_writer(writer)
            return ok

        results = await asyncio.gather(*(one(i) for i in range(25)))
        assert all(results)
        assert len(env.proxy.connections) == 25
        assert all(rec.handshake_ok for rec in env.proxy.connections)

    async def test_connection_bookkeeping_is_released(self, env):
        reader, writer = await env.session(PING)
        await _read_until(reader, 4)
        ((active, _tunnel),) = server_mod._running_bridges.values()
        assert len(active) == 1
        await close_writer(writer)
        await eventually(lambda: not active)


# ============================================================================
# Определение DC по цели SOCKS5-запроса
# ============================================================================


class TestDcSelection:
    @pytest.mark.parametrize(
        ("target", "dc"),
        [
            (DC2_IP, 2),
            (DC3_IP, 3),
            (DC4_IP, 4),
            ("149.154.171.5", 5),
            ("149.154.175.10", 10001),
            (CDN_IP, -203),
            ("2001:b28:f23f:f005::a", 5),
            ("2a0a:f280:203:a:5000::100", -203),
        ],
    )
    async def test_dc_follows_the_connect_target(self, env_factory, target, dc):
        env = await env_factory()
        reader, writer = await env.session(b"xxxx", target)
        await _read_until(reader, 4)
        assert env.proxy.connections[0].dc == dc
        await close_writer(writer)

    async def test_hostname_target_is_resolved(self, env_factory, monkeypatch):
        async def fake_getaddrinfo(host, port, **_kw):
            assert host == "dc4.telegram.example"
            return [(2, 1, 6, "", ("149.154.167.91", 443))]

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake_getaddrinfo)
        env = await env_factory()
        reader, writer = await env.connect("dc4.telegram.example", as_domain=True)
        writer.write(env.mode.client_tag + PING)
        await _read_until(reader, 4)
        assert env.proxy.connections[0].dc == 4
        await close_writer(writer)

    async def test_unknown_target_is_refused_without_connecting_upstream(self, env):
        reader, writer = await env.session(b"xxxx", "8.8.8.8")
        assert await drain_to_eof(reader) == b""
        assert env.proxy.connections == []
        await close_writer(writer)

    async def test_override_applies_to_unknown_targets(self, env_factory):
        env = await env_factory(dc_id_override=7)
        reader, writer = await env.session(b"xxxx", "8.8.8.8")
        await _read_until(reader, 4)
        assert env.proxy.connections[0].dc == 7
        await close_writer(writer)

    async def test_override_wins_over_the_table(self, env_factory):
        env = await env_factory(dc_id_override=5)
        reader, writer = await env.session(b"xxxx", DC2_IP)
        await _read_until(reader, 4)
        assert env.proxy.connections[0].dc == 5
        await close_writer(writer)

    async def test_same_bridge_serves_different_dcs(self, env):
        for target in (DC2_IP, DC4_IP, DC3_IP):
            reader, writer = await env.session(b"xxxx", target)
            await _read_until(reader, 4)
            await close_writer(writer)
        assert [rec.dc for rec in env.proxy.connections] == [2, 4, 3]


# ============================================================================
# Проверка транспорта клиента и мусор до тега
# ============================================================================


class TestClientValidation:
    async def test_transport_must_match_the_secret(self, env):
        wrong = (
            b"\xdd\xdd\xdd\xdd"
            if env.mode.client_tag == b"\xef"
            else b"\xef\x00\x00\x00"
        )
        reader, writer = await env.connect()
        writer.write(wrong + b"payload")
        assert await drain_to_eof(reader) == b""
        assert env.proxy.connections == []  # до прокси дело не дошло
        await close_writer(writer)

    @pytest.mark.parametrize(
        "junk",
        [b"GET ", b"\x16\x03\x01\x02", b"\xee\xee\xee\xee", b"\x00\x00\x00\x00"],
        ids=["http", "tls", "intermediate", "zeros"],
    )
    async def test_unsupported_first_bytes(self, env, junk):
        reader, writer = await env.connect()
        writer.write(junk)
        assert await drain_to_eof(reader) == b""
        assert env.proxy.connections == []
        await close_writer(writer)

    async def test_incomplete_tag_times_out(self, env, monkeypatch):
        monkeypatch.setattr(relay_mod, "SOCKS5_HANDSHAKE_TIMEOUT_SECS", 0.2)
        reader, writer = await env.connect()
        writer.write(b"\xef" if env.mode.client_tag != b"\xef" else b"")
        # bare: тег — 1 байт, но мост ждёт 4 (тег + 3 байта данных).
        assert await drain_to_eof(reader, timeout=3) == b""
        assert env.proxy.connections == []
        await close_writer(writer)

    async def test_abridged_waits_for_four_bytes_before_connecting(
        self, proxy_factory, bridge_factory
    ):
        # Мост читает первые 4 байта клиента целиком (тег + до 3 байт данных).
        # Для abridged это значит: пока не пришёл 4-й байт, до прокси ничего
        # не доходит (настоящий клиент шлёт req_pq сразу, так что на практике
        # это не проявляется). Тест фиксирует это поведение.
        proxy = await proxy_factory(domain=None)
        port = await bridge_factory(make_link(proxy.port, SECRET_PLAIN))
        reader, writer = await socks5_connect(port)
        writer.write(b"\xefab")  # тег + 2 байта = 3 < 4
        await writer.drain()
        await asyncio.sleep(0.3)
        assert proxy.connections == []
        writer.write(b"c")  # 4-й байт
        assert await _read_until(reader, 3) == b"abc"
        await close_writer(writer)

    async def test_client_silent_after_socks5(self, env, monkeypatch):
        monkeypatch.setattr(relay_mod, "SOCKS5_HANDSHAKE_TIMEOUT_SECS", 0.2)
        reader, writer = await env.connect()
        assert await drain_to_eof(reader, timeout=3) == b""
        assert env.proxy.connections == []
        await close_writer(writer)

    async def test_client_hangs_up_right_after_socks5(self, env):
        _reader, writer = await env.connect()
        await close_writer(writer)
        await asyncio.sleep(0.1)
        assert env.proxy.connections == []
        # Мост продолжает обслуживать остальных.
        reader, writer = await env.session(b"still alive")
        assert await _read_until(reader, 11) == b"still alive"
        await close_writer(writer)

    async def test_socks5_udp_associate_is_refused(self, env):
        reader, writer = await asyncio.open_connection("127.0.0.1", env.port)
        writer.write(b"\x05\x01\x00")
        assert await read_exactly(reader, 2) == b"\x05\x00"
        writer.write(b"\x05\x03\x00\x01" + bytes(6))  # UDP ASSOCIATE
        reply = await read_exactly(reader, 10)
        assert reply[:2] == b"\x05\x07"
        assert await drain_to_eof(reader) == b""
        assert env.proxy.connections == []
        await close_writer(writer)

    async def test_socks5_auth_required_is_refused(self, env):
        reader, writer = await asyncio.open_connection("127.0.0.1", env.port)
        writer.write(b"\x05\x01\x02")  # только user/pass
        assert await read_exactly(reader, 2) == b"\x05\xff"
        assert await drain_to_eof(reader) == b""
        assert env.proxy.connections == []
        await close_writer(writer)


# ============================================================================
# Отказы upstream
# ============================================================================


class TestUpstreamFailures:
    async def test_connection_refused(self, mode, bridge_factory):
        port = await bridge_factory(make_link(free_port(), mode.secret_hex))
        for _ in range(2):  # мост не «залипает» после отказа
            reader, writer = await socks5_connect(port)
            writer.write(mode.client_tag + PING)
            assert await drain_to_eof(reader) == b""
            await close_writer(writer)

    async def test_connect_timeout(self, mode, bridge_factory, monkeypatch):
        blackhole = "10.255.255.1"
        real_open = asyncio.open_connection

        async def fake_open(host, port, *args, **kwargs):
            if host == blackhole:
                await asyncio.sleep(3600)
            return await real_open(host, port, *args, **kwargs)

        monkeypatch.setattr(asyncio, "open_connection", fake_open)
        monkeypatch.setattr(relay_mod, "UPSTREAM_CONNECT_TIMEOUT_SECS", 0.2)
        port = await bridge_factory(make_link(443, mode.secret_hex, host=blackhole))
        reader, writer = await socks5_connect(port)
        writer.write(mode.client_tag + PING)
        started = time.monotonic()
        assert await drain_to_eof(reader, timeout=5) == b""
        assert time.monotonic() - started < 3
        await close_writer(writer)

    async def test_upstream_accepts_and_closes_immediately(self, mode, bridge_factory):
        async def slam(_reader, writer):
            writer.close()

        server = await asyncio.start_server(slam, "127.0.0.1", 0)
        try:
            port = await bridge_factory(
                make_link(server.sockets[0].getsockname()[1], mode.secret_hex)
            )
            reader, writer = await socks5_connect(port)
            writer.write(mode.client_tag + PING)
            assert await drain_to_eof(reader) == b""
            await close_writer(writer)
        finally:
            server.close()

    async def test_wrong_secret_on_plain_obfuscated2(
        self, proxy_factory, bridge_factory
    ):
        # Прокси ждёт другой секрет: тег в init расшифровывается в мусор,
        # прокси рвёт соединение, мост закрывает клиента.
        proxy = await proxy_factory(secret=bytes(16), domain=None)
        port = await bridge_factory(make_link(proxy.port, SECRET_PLAIN))
        reader, writer = await socks5_connect(port)
        writer.write(b"\xef" + b"xyz")
        assert await drain_to_eof(reader) == b""
        rec = proxy.connections[0]
        assert not rec.handshake_ok
        assert rec.error and rec.error.startswith("bad transport tag")
        await close_writer(writer)

    async def test_wrong_secret_on_faketls_gets_the_fallback_site(
        self, proxy_factory, bridge_factory
    ):
        proxy = await proxy_factory(secret=bytes(16), domain=DOMAIN)
        port = await bridge_factory(make_link(proxy.port, SECRET_EE))
        reader, writer = await socks5_connect(port)
        writer.write(b"\xdd\xdd\xdd\xdd" + b"payload")
        assert await drain_to_eof(reader) == b""
        rec = proxy.connections[0]
        assert rec.fallback_served and not rec.handshake_ok
        assert rec.received == b""  # ни одного байта obfuscated2
        await close_writer(writer)

    async def test_faketls_handshake_timeout(self, bridge_factory, monkeypatch):
        monkeypatch.setattr(faketls._read_exactly_logged, "__defaults__", (0.2,))
        silent = await asyncio.start_server(
            lambda r, w: asyncio.ensure_future(_hang(r, w)), "127.0.0.1", 0
        )
        try:
            port = await bridge_factory(
                make_link(silent.sockets[0].getsockname()[1], SECRET_EE)
            )
            reader, writer = await socks5_connect(port)
            writer.write(b"\xdd\xdd\xdd\xdd")
            started = time.monotonic()
            assert await drain_to_eof(reader, timeout=5) == b""
            assert time.monotonic() - started < 3
            await close_writer(writer)
        finally:
            silent.close()


async def _hang(reader, writer) -> None:
    try:
        while await reader.read(65536):
            pass
    finally:
        writer.close()


# ============================================================================
# Ошибки на стороне upstream посреди сессии (FakeTLS)
# ============================================================================


class TestTlsStreamErrors:
    @pytest.mark.parametrize(
        "record",
        [
            b"\x15\x03\x03\x00\x02\x02\x28",  # Alert
            b"\x14\x03\x03\x00\x01\x01",  # CCS посреди сессии
            b"\x16\x03\x03\x00\x01\x00",  # handshake-запись
            b"\x17\x03\x01\x00\x01\x00",  # AppData с версией 0301
        ],
        ids=["alert", "ccs", "handshake", "wrong-version"],
    )
    async def test_bad_record_closes_the_client(self, tls_env, record):
        async def poison(conn: Conn) -> None:
            await conn.read()
            conn.writer.write(record)
            await conn.writer.drain()
            await conn.read()  # ждём, пока мост закроет соединение

        env = await tls_env(poison)
        reader, writer = await env.session(PING)
        assert await drain_to_eof(reader) == b""
        await asyncio.wait_for(env.proxy.connections[0].closed.wait(), 5)
        await close_writer(writer)

    @pytest.mark.parametrize("chunk", [1, 7, 100, 2878, 16000])
    async def test_server_record_sizes(self, tls_env, chunk):
        env = await tls_env(proxy_kwargs={"tls_chunk": chunk})
        payload = os.urandom(40_000)
        reader, writer = await env.session()
        writer.write(payload)
        assert await _read_until(reader, len(payload), 60) == payload
        await close_writer(writer)

    async def test_data_in_the_servers_handshake_appdata_is_not_forwarded(
        self, tls_env
    ):
        # Тело AppData из ответа на ClientHello — шум handshake'а; клиенту
        # оно уйти не должно, иначе первый же ответ окажется испорченным.
        env = await tls_env(proxy_kwargs={"appdata_len": 4000})
        reader, writer = await env.session(b"clean")
        assert await _read_until(reader, 5) == b"clean"
        await close_writer(writer)


# ============================================================================
# Что видит FakeTLS-прокси на проводе
# ============================================================================


class TestFakeTlsWire:
    async def test_client_hello_is_valid_for_the_secret(self, tls_env):
        env = await tls_env()
        reader, writer = await env.session(PING)
        await _read_until(reader, 4)
        rec = env.proxy.connections[0]
        assert rec.hello_timestamp is not None
        assert abs(rec.hello_timestamp - time.time()) < 10
        assert rec.hello.sni == DOMAIN
        await close_writer(writer)

    async def test_ccs_is_sent_by_default(self, tls_env):
        env = await tls_env()
        reader, writer = await env.session(PING)
        await _read_until(reader, 4)
        rec = env.proxy.connections[0]
        assert rec.saw_ccs
        assert rec.record_types[0] == 0x14  # CCS — перед первой AppData
        assert rec.record_types.count(0x14) == 1
        await close_writer(writer)

    async def test_no_ccs_flag(self, tls_env):
        env = await tls_env(send_ccs=False)
        reader, writer = await env.session(PING)
        assert await _read_until(reader, 4) == PING
        rec = env.proxy.connections[0]
        assert not rec.saw_ccs
        assert set(rec.record_types) == {0x17}
        await close_writer(writer)

    async def test_obfuscated2_header_travels_alone_in_the_first_record(self, tls_env):
        env = await tls_env()
        reader, writer = await env.session(PING)
        await _read_until(reader, 4)
        # Тег (4 байта) — первое, что читает мост, поэтому leftover пуст и
        # заголовок уходит отдельной 64-байтной записью.
        assert env.proxy.connections[0].first_record_len == 64
        await close_writer(writer)

    async def test_records_respect_the_max_size(self, tls_env):
        env = await tls_env()
        payload = os.urandom(120_000)
        reader, writer = await env.session()
        writer.write(payload)
        await _read_until(reader, len(payload), 60)
        rec = env.proxy.connections[0]
        assert rec.protocol_errors == []
        assert rec.record_lengths and max(rec.record_lengths) <= 2878
        assert set(rec.record_types) <= {0x14, 0x17}
        assert bytes(rec.received) == payload
        await close_writer(writer)

    @pytest.mark.parametrize(
        ("m", "e"), [(True, True), (False, False), (True, False), (False, True)]
    )
    async def test_hello_block_flags_reach_the_proxy(self, tls_env, m, e):
        env = await tls_env(use_block_m=m, use_block_e=e)
        reader, writer = await env.session(PING)
        await _read_until(reader, 4)
        body = env.proxy.connections[0].hello.ext(0x0033)  # key_share
        key_sizes = []
        pos = 2
        while pos < len(body):
            _g, ln = struct.unpack_from(">HH", body, pos)
            key_sizes.append(ln)
            pos += 4 + ln
        assert (1216 in key_sizes) is m
        esni = env.proxy.connections[0].hello.ext(0xFE0D)
        assert (len(esni) > 5 + 1 + 2 + 32) is e
        await close_writer(writer)

    async def test_each_connection_sends_a_fresh_hello(self, tls_env):
        env = await tls_env()
        for _ in range(3):
            reader, writer = await env.session(PING)
            await _read_until(reader, 4)
            await close_writer(writer)
        randoms = {rec.hello.random for rec in env.proxy.connections}
        assert len(randoms) == 3


# ============================================================================
# Таймауты неактивности
# ============================================================================


class TestActivityTimeout:
    async def test_idle_connection_is_closed(self, env, monkeypatch):
        monkeypatch.setattr(relay_mod, "ACTIVITY_TIMEOUT_SECS", 0.3)
        reader, writer = await env.session(PING)
        await _read_until(reader, 4)
        started = time.monotonic()
        assert await drain_to_eof(reader, timeout=5) == b""
        assert time.monotonic() - started < 3
        await asyncio.wait_for(env.proxy.connections[0].closed.wait(), 5)
        await close_writer(writer)

    async def test_active_connection_is_not_closed(self, env, monkeypatch):
        monkeypatch.setattr(relay_mod, "ACTIVITY_TIMEOUT_SECS", 0.5)
        reader, writer = await env.session(PING)
        await _read_until(reader, 4)
        for i in range(8):  # суммарно ~1.6 c > 0.5 c таймаута
            await asyncio.sleep(0.2)
            writer.write(b"k")
            assert await _read_until(reader, 1, 3) == b"k"
        await close_writer(writer)

    async def test_server_push_keeps_a_silent_client_alive(
        self, env_factory, monkeypatch
    ):
        # Контракт из config.py: достаточно одного байта за интервал В ЛЮБОМ
        # направлении. Клиент молчит, но прокси шлёт апдейты — соединение
        # должно жить. Сейчас оно рвётся по таймеру молчащего направления.
        monkeypatch.setattr(relay_mod, "ACTIVITY_TIMEOUT_SECS", 0.5)

        async def pusher(conn: Conn) -> None:
            await conn.read()
            for _ in range(10):
                await conn.write(b"u")
                await asyncio.sleep(0.2)

        env = await env_factory(pusher)
        reader, writer = await env.session(PING)
        try:
            got = await _read_until(reader, 10, 5)  # ~2 c: четыре таймаута клиента
            assert got == b"u" * 10
        finally:
            await close_writer(writer)
