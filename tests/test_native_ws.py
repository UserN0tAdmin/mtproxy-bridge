#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Совместимость с релеем mtproto.zig (режим ``native-websocket``).

Фейковый релей повторяет правила ``src/web/relay.zig`` / ``page.zig`` /
``capability.zig`` / ``tokens.zig`` реального сервера:

- ``GET /?bridge=<capability>`` отдаёт страницу с ``<meta name="tproxy-token">``
  и ``<meta name="tproxy-ws-path">`` (REST-сессии нет вовсе);
- WebSocket на ``ws_path`` с subprotocol ``tproxy-v1.<token>``; токен
  одноразовый, повтор/просрочка → апгрейд отвергнут (404);
- первое сообщение клиента — ровно один HELLO, ответ — ровно один WELCOME;
- WS-сообщение крупнее 1 МиБ + 8 байт → протокольная ошибка;
- PING по stream 0, клиент обязан ответить PONG с тем же payload;
- OPEN сверх ``max_streams`` → CLOSE этого потока (а не обрыв carrier'а).

Сеть не нужна: ``WebApi`` подменяется дубликатом с теми же методами.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import struct
from collections import namedtuple

import aiohttp

from mtproxy_bridge.links import parse_web_link
from mtproxy_bridge.web import frames as f
from mtproxy_bridge.web.bootstrap import (
    NATIVE_BATCH_LIMIT,
    NATIVE_WS_MODE,
    parse_bridge_page,
)
from mtproxy_bridge.web.http_api import (
    ApiResponse,
    BootstrapRejected,
    ProtocolViolation,
)
from mtproxy_bridge.web.tunnel import WebTunnel

HOST = "proxy.example.com"
SECRET = bytes(range(16))
WS_PATH = "/api/v1/socket"
RELAY_MAX_MESSAGE = 1024 * 1024 + 8  # ws.max_message в релее

Msg = namedtuple("Msg", "type data extra")


# ── страница (дословно по шаблону page.zig: head + meta + script) ─────────────


def zig_bridge_page(
    token: str, ws_path: str = WS_PATH, nonce: str = "nonce_123"
) -> str:
    escaped = (
        ws_path.replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return (
        '<!doctype html>\n<html lang="en"><head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
        f'<meta name="tproxy-token" content="{token}">\n'
        f'<meta name="tproxy-ws-path" content="{escaped}">\n'
        f'<title>Connection</title>\n</head><body>\n<script nonce="{nonce}">\n'
        f'(function(){{"use strict";\nvar WS_PATH="{ws_path}",TOKEN="{token}";\n'
        'var match=/^#android=([A-Za-z0-9_-]{43})$/.exec(location.hash||"");\n'
        'new WebSocket("wss://"+location.host+WS_PATH,"tproxy-v1."+TOKEN);\n'
        "})();\n</script>\n</body></html>"
    )


def _capability(host: str, secret16: bytes) -> str:
    """Независимая реализация ``deriveForPaddedSecret`` из capability.zig."""
    mac = hmac.new(
        b"\xdd" + secret16,
        b"tdesktop-web-proxy-bridge-v1\n" + host.encode(),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def _frame(ftype: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        bytes((ftype,))
        + stream_id.to_bytes(3, "big")
        + struct.pack(">I", len(payload))
        + payload
    )


def _split(data: bytes) -> list[tuple[int, int, bytes]]:
    """Независимый разбор батча (как ``validateCarrierMessage`` релея)."""
    out, off = [], 0
    assert data, "empty carrier message"
    while off < len(data):
        assert len(data) - off >= 8, "truncated header"
        length = struct.unpack_from(">I", data, off + 4)[0]
        end = off + 8 + length
        assert end <= len(data), "truncated payload"
        out.append(
            (
                data[off],
                int.from_bytes(data[off + 1 : off + 4], "big"),
                data[off + 8 : end],
            )
        )
        off = end
    return out


# ── фейковый релей ────────────────────────────────────────────────────────────


class FakeWs:
    def __init__(self, relay: "FakeZigRelay", protocol: str) -> None:
        self._relay = relay
        self.protocol = protocol
        self.closed = False
        self.close_code: int | None = None
        self._inbound: asyncio.Queue[Msg] = asyncio.Queue()

    # --- сторона клиента (то, что вызывает мост) ---
    async def send_bytes(self, data: bytes) -> None:
        if self.closed:
            raise ConnectionResetError("websocket closed")
        self._relay.on_client_message(self, bytes(data))

    async def receive(self) -> Msg:
        return await self._inbound.get()

    def __aiter__(self) -> "FakeWs":
        return self

    async def __anext__(self) -> Msg:
        msg = await self._inbound.get()
        if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
            raise StopAsyncIteration
        return msg

    async def close(self, *, code: int = 1000) -> None:
        if not self.closed:
            self.closed = True
            self.close_code = code
            self._inbound.put_nowait(Msg(aiohttp.WSMsgType.CLOSED, None, None))

    # --- сторона релея ---
    def push(self, data: bytes) -> None:
        self._inbound.put_nowait(Msg(aiohttp.WSMsgType.BINARY, data, None))

    def relay_close(self, code: int = 1000) -> None:
        self.close_code = code
        self._inbound.put_nowait(Msg(aiohttp.WSMsgType.CLOSE, code, None))


class FakeZigRelay:
    def __init__(self, *, max_streams: int = 32, welcome: str = "ok") -> None:
        self.capability = _capability(HOST, SECRET)
        self.max_streams = max_streams
        self.welcome = welcome  # "ok" | "wrong"
        self.expire_tokens = False
        self.issued: dict[str, bool] = {}  # token -> уже использован
        self.ws: FakeWs | None = None
        self.welcomed = False
        self.sessions_started = 0
        self.rest_calls: list[str] = []
        self.client_messages: list[bytes] = []
        self.protocol_errors: list[str] = []
        self.pongs: list[bytes] = []
        self.pong_event = asyncio.Event()
        self.streams: dict[int, int] = {}  # id -> recv_window
        self.closed_ids: set[int] = set()
        self.refused = 0

    # --- HTTP-часть ---
    def serve_page(self, capability: str) -> ApiResponse:
        if capability != self.capability:
            return ApiResponse(status=404, headers={}, body=b"<html>cover</html>")
        token = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
        self.issued[token] = False
        return ApiResponse(status=200, headers={}, body=zig_bridge_page(token).encode())

    def upgrade(self, protocol: str, path: str) -> FakeWs:
        prefix = "tproxy-v1."
        token = protocol[len(prefix) :] if protocol.startswith(prefix) else ""
        if (
            path != WS_PATH
            or token not in self.issued
            or self.issued[token]
            or self.expire_tokens
        ):
            raise aiohttp.WSServerHandshakeError(
                None, (), status=404, message="Invalid response status"
            )
        self.issued[token] = True
        self.sessions_started += 1
        self.welcomed = False
        self.streams.clear()
        self.ws = FakeWs(self, protocol)
        return self.ws

    # --- WebSocket-часть: правила handleCarrierMessage / validateClientFrameShape ---
    def _fail(self, reason: str, code: int = 1002) -> None:
        self.protocol_errors.append(reason)
        assert self.ws is not None
        self.ws.relay_close(code)

    def on_client_message(self, ws: FakeWs, data: bytes) -> None:
        self.client_messages.append(data)
        if len(data) > RELAY_MAX_MESSAGE:
            return self._fail("message too big", 1009)
        frames = _split(data)
        if not self.welcomed:
            if (
                len(frames) != 1
                or frames[0][:2] != (0x10, 0)
                or frames[0][2] != b"\x01"
            ):
                return self._fail("first message must be a lone HELLO")
            self.welcomed = True
            if self.welcome == "ok":
                ws.push(_frame(0x11, 0))
            else:
                ws.push(_frame(0x05, 0, b"nope"))  # PING вместо WELCOME
            return
        for ftype, sid, payload in frames:
            if sid == 0:
                if ftype == 0x06 and len(payload) <= 64:
                    self.pongs.append(payload)
                    self.pong_event.set()
                    continue
                return self._fail(f"bad stream-0 frame 0x{ftype:02x}")
            if ftype == 0x01:
                if payload:
                    return self._fail("OPEN with payload")
                if sid in self.streams or sid in self.closed_ids:
                    return self._fail("stream id reused")
                if len(self.streams) >= self.max_streams:
                    self.refused += 1
                    self.closed_ids.add(sid)
                    ws.push(_frame(0x03, sid))  # отказ одному потоку, carrier жив
                    continue
                self.streams[sid] = f.INITIAL_STREAM_WINDOW
            elif ftype == 0x02:
                if not payload or sid not in self.streams:
                    if sid in self.closed_ids:
                        continue
                    return self._fail("DATA on unknown stream / empty DATA")
                if len(payload) > self.streams[sid]:
                    return self._fail("DATA over window")
                # эхо + возврат кредита одним сообщением (батч DATA…WINDOW)
                out = b"".join(
                    _frame(0x02, sid, payload[i : i + 65536])
                    for i in range(0, len(payload), 65536)
                )
                ws.push(out + _frame(0x04, sid, struct.pack(">I", len(payload))))
            elif ftype == 0x04:
                if len(payload) != 4 or struct.unpack(">I", payload)[0] == 0:
                    return self._fail("bad WINDOW")
            elif ftype == 0x03:
                if payload:
                    return self._fail("CLOSE with payload")
                self.streams.pop(sid, None)
                self.closed_ids.add(sid)
            else:
                return self._fail(f"unexpected frame 0x{ftype:02x}")

    # --- управление из тестов ---
    def ping(self, payload: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08") -> None:
        assert self.ws is not None
        self.ws.push(_frame(0x05, 0, payload))


class FakeApi:
    """Подмена ``WebApi``: только то, чего касается native-путь."""

    def __init__(self, relay: FakeZigRelay) -> None:
        self._relay = relay
        self.origin = f"https://{HOST}"
        self.ws_calls: list[dict] = []

    async def get_bridge_page(self, capability: str) -> ApiResponse:
        return self._relay.serve_page(capability)

    async def ws_connect(
        self, subprotocol: str, *, path: str = "/api/v1/ws", compress=None
    ):
        self.ws_calls.append(
            {"subprotocol": subprotocol, "path": path, "compress": compress}
        )
        return self._relay.upgrade(subprotocol, path)

    async def create_session(self, *a, **k):  # REST-сессии у mtproto.zig нет
        self._relay.rest_calls.append("POST /api/v1/session")
        raise AssertionError("native-websocket must not create a REST session")

    async def delete_session(self, *a, **k):
        self._relay.rest_calls.append("DELETE /api/v1/session")
        raise AssertionError("native-websocket must not DELETE a session")

    async def close(self) -> None:
        return None


def _tunnel(relay: FakeZigRelay, secret_hex: str | None = None) -> WebTunnel:
    link = parse_web_link(
        f"tg://webproxy?server={HOST}&secret=dd{secret_hex or SECRET.hex()}"
    )
    tunnel = WebTunnel(link)
    tunnel._api = FakeApi(relay)  # type: ignore[assignment]
    return tunnel


async def _roundtrip(stream, data: bytes, timeout: float = 20.0) -> bytes:
    writer = asyncio.create_task(stream.write(data))
    got = bytearray()
    try:
        while len(got) < len(data):
            chunk = await asyncio.wait_for(stream.read(), timeout)
            assert chunk, "unexpected EOF"
            got += chunk
        await asyncio.wait_for(writer, timeout)
    finally:
        if not writer.done():
            writer.cancel()
    return bytes(got)


# ── разбор страницы ───────────────────────────────────────────────────────────

TOKEN = "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA"


def test_parse_zig_page_native_mode():
    page = parse_bridge_page(zig_bridge_page(TOKEN))
    assert page.carrier_mode == NATIVE_WS_MODE
    assert page.token == TOKEN
    assert page.ws_path == WS_PATH
    assert page.allowed_modes == frozenset({NATIVE_WS_MODE})
    # потолок WS-сообщения релея — 1 МиБ + 8, а не 2 МиБ по умолчанию
    assert page.batch_limit == NATIVE_BATCH_LIMIT <= RELAY_MAX_MESSAGE


def test_parse_zig_page_unescapes_ws_path():
    page = parse_bridge_page(zig_bridge_page(TOKEN, ws_path="/a&b/socket"))
    assert page.ws_path == "/a&b/socket"


def test_parse_zig_page_rejects_foreign_ws_paths():
    for bad in ("//evil.example/x", "socket", "/a?b=1", "/a#frag", "/a\\b"):
        try:
            parse_bridge_page(zig_bridge_page(TOKEN, ws_path=bad))
        except BootstrapRejected:
            continue
        raise AssertionError(f"ws path {bad!r} must be rejected")


def test_parse_zig_page_rejects_bad_token_and_missing_path():
    for html in (
        zig_bridge_page("short"),
        zig_bridge_page(TOKEN).replace('<meta name="tproxy-ws-path"', '<meta name="x"'),
    ):
        try:
            parse_bridge_page(html)
        except BootstrapRejected:
            continue
        raise AssertionError("malformed Zig page must be rejected")


def test_capability_matches_server_vector():
    link = parse_web_link(f"tg://webproxy?server={HOST}&secret=dd{SECRET.hex()}")
    assert link.capability == "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA"
    assert link.capability == _capability(HOST, SECRET)


# ── туннель против фейкового релея ────────────────────────────────────────────


async def test_roundtrip_native_session():
    relay = FakeZigRelay()
    tunnel = _tunnel(relay)
    try:
        stream = await tunnel.open_stream()
        assert tunnel.carrier_mode == NATIVE_WS_MODE
        assert await _roundtrip(stream, b"hello zig") == b"hello zig"
        # 5 МиБ > стартового окна 4 МиБ: проходит только при честных WINDOW в обе стороны
        blob = os.urandom(5 * 1024 * 1024)
        assert await _roundtrip(stream, blob) == blob
    finally:
        await tunnel.aclose()
    assert relay.protocol_errors == []
    assert relay.rest_calls == []  # ни POST /session, ни DELETE


async def test_handshake_shape_and_ws_arguments():
    relay = FakeZigRelay()
    tunnel = _tunnel(relay)
    try:
        await tunnel.open_stream()
        # HELLO — единственный фрейм первого сообщения
        first = relay.client_messages[0]
        assert _split(first) == [(0x10, 0, b"\x01")]
        call = tunnel._api.ws_calls[0]  # type: ignore[attr-defined]
        assert call["path"] == WS_PATH  # путь из страницы, а не /api/v1/ws
        assert call["subprotocol"].startswith("tproxy-v1.")
        assert call["compress"] == 0  # permessage-deflate не предлагаем
    finally:
        await tunnel.aclose()
    assert relay.protocol_errors == []


async def test_ping_is_answered_with_matching_pong():
    relay = FakeZigRelay()
    tunnel = _tunnel(relay)
    try:
        await tunnel.open_stream()
        payload = bytes(range(64))  # максимум по спецификации
        relay.ping(payload)
        await asyncio.wait_for(relay.pong_event.wait(), 5)
        assert relay.pongs == [payload]
        assert relay.protocol_errors == []
    finally:
        await tunnel.aclose()


async def test_batches_stay_under_relay_message_limit():
    relay = FakeZigRelay()
    tunnel = _tunnel(relay)
    try:
        streams = [await tunnel.open_stream() for _ in range(8)]
        blobs = [os.urandom(1024 * 1024) for _ in streams]
        results = await asyncio.gather(
            *(_roundtrip(s, b) for s, b in zip(streams, blobs))
        )
        assert results == blobs
    finally:
        await tunnel.aclose()
    assert relay.protocol_errors == []
    assert (
        max(len(m) for m in relay.client_messages)
        <= NATIVE_BATCH_LIMIT
        <= RELAY_MAX_MESSAGE
    )


async def test_stream_over_max_streams_is_refused_individually():
    relay = FakeZigRelay(max_streams=2)
    tunnel = _tunnel(relay)
    try:
        a = await tunnel.open_stream()
        b = await tunnel.open_stream()
        c = await tunnel.open_stream()
        assert await asyncio.wait_for(c.read(), 5) == b""  # CLOSE → EOF только для c
        assert await _roundtrip(a, b"still alive") == b"still alive"
        assert await _roundtrip(b, b"me too") == b"me too"
    finally:
        await tunnel.aclose()
    assert relay.refused == 1
    assert relay.protocol_errors == []


async def test_session_is_recreated_with_fresh_token_after_relay_close():
    relay = FakeZigRelay()
    tunnel = _tunnel(relay)
    try:
        s1 = await tunnel.open_stream()
        assert relay.ws is not None
        relay.ws.relay_close(1000)
        try:
            await asyncio.wait_for(s1.read(), 5)
        except ConnectionError:
            pass
        else:
            raise AssertionError("stream must fail when the carrier dies")
        s2 = await tunnel.open_stream()
        assert await _roundtrip(s2, b"again") == b"again"
        assert relay.sessions_started == 2
        assert len(relay.issued) == 2  # на каждую сессию — своя страница и свой токен
    finally:
        await tunnel.aclose()


# ── отказы ────────────────────────────────────────────────────────────────────


async def test_wrong_secret_gets_cover_page_and_clear_error():
    relay = FakeZigRelay()
    tunnel = _tunnel(relay, secret_hex=bytes(range(1, 17)).hex())
    try:
        try:
            await tunnel.open_stream()
        except BootstrapRejected as exc:
            assert "HTTP 404" in str(exc) and "capability" in str(exc)
        else:
            raise AssertionError("must be rejected")
    finally:
        await tunnel.aclose()


async def test_expired_or_used_token_is_bootstrap_rejected():
    relay = FakeZigRelay()
    relay.expire_tokens = True
    tunnel = _tunnel(relay)
    try:
        try:
            await tunnel.open_stream()
        except BootstrapRejected as exc:
            assert "upgrade" in str(exc) and "404" in str(exc)
        else:
            raise AssertionError("must be rejected")
    finally:
        await tunnel.aclose()
    assert relay.sessions_started == 0


async def test_first_message_other_than_welcome_is_protocol_violation():
    relay = FakeZigRelay(welcome="wrong")
    tunnel = _tunnel(relay)
    try:
        try:
            await tunnel.open_stream()
        except ProtocolViolation:
            pass
        else:
            raise AssertionError("must be rejected")
    finally:
        await tunnel.aclose()
