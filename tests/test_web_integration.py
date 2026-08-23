#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Интеграционные тесты WEB-туннеля против mock-релея (все 4 carrier-режима).

Mock-релей реализует контракт PROTOCOL.md v1: bridge-страница, сессия
HELLO/WELCOME, сериализованный https / lanes с X-Lane-ID и X-Lane-Closed,
WebSocket- carriers с bearer в subprotocol. Бэкенд — локальный эхо-TCP;
если задан ``mtproto_secret``, между релеем и бэкендом действует настоящий
server-side obfuscated2 (как официальный MTProxy).
"""

import asyncio
import base64
import hashlib
import os
from collections import deque

import pytest
from aiohttp import WSMsgType, web
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from mtproxy_bridge.links import parse_web_link
from mtproxy_bridge.web import frames as f
from mtproxy_bridge.web.bootstrap import fetch_bridge_page
from mtproxy_bridge.web.http_api import BootstrapRejected, WebApi
from mtproxy_bridge.web.tunnel import WebTunnel

HOST = "proxy.example.com"
SECRET_HEX = "000102030405060708090a0b0c0d0e0f"

_LONG_POLL_SECS = 3.0
_WS_IDLE_PING_SECS = 5.0

ALL_MODES = ["https", "https-lanes", "websocket", "websocket-lanes"]


def _random_token() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()


class _Lane:
    """Даунклинк-очередь одного лейна (+ признак закрытия потока)."""

    def __init__(self, *, awaiting_open: bool = False) -> None:
        self.queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.dead = False  # CLOSE уже ушёл/пришёл — после осушения шлём X-Lane-Closed
        # websocket-lanes: лейн появляется при коннекте сокета, а OPEN
        # приходит первым сообщением уже поверх него.
        self.awaiting_open = awaiting_open


class _Session:
    def __init__(self, token: str, mode: str) -> None:
        self.token = token
        self.mode = mode
        self.backend_tasks: set[asyncio.Task] = set()
        self.writers: dict[int, asyncio.StreamWriter] = {}  # stream -> backend
        self.lanes: dict[int, _Lane] | None = None
        self.down_queue: asyncio.Queue[bytes] | None = None
        self.ws_tasks: set[asyncio.Task] = set()
        if mode in ("https-lanes", "websocket-lanes"):
            self.lanes = {0: _Lane()}  # lane 0 — session control
        else:
            self.down_queue = asyncio.Queue()

    # Маршрутизация исходящих фреймов к carrier'у клиента.
    def push(self, stream_id: int, payload: bytes) -> None:
        if self.lanes is not None:
            lane = self.lanes.get(stream_id)
            if lane is None:
                return  # поздний фрейм неизвестного/закрытого лейна
            lane.queue.put_nowait(payload)
        else:
            assert self.down_queue is not None
            self.down_queue.put_nowait(payload)

    def mark_dead(self, stream_id: int) -> None:
        if self.lanes is not None:
            lane = self.lanes.get(stream_id)
            if lane is not None:
                lane.dead = True

    def ensure_lane(self, stream_id: int) -> bool:
        """OPEN обязан быть первым фреймом нового ненулевого лейна."""
        if self.lanes is None:
            return True
        if stream_id == 0:
            return False
        lane = self.lanes.get(stream_id)
        if lane is None:
            self.lanes[stream_id] = _Lane()
            return True
        if lane.awaiting_open:
            lane.awaiting_open = False
            return True
        return False

    def teardown(self) -> None:
        """Полная уборка: задачи pump'ов, бэкенд-сокеты, лейны."""
        for task in self.ws_tasks:
            task.cancel()
        self.ws_tasks.clear()
        for task in self.backend_tasks:
            task.cancel()
        self.backend_tasks.clear()
        for writer in self.writers.values():
            writer.close()
        self.writers.clear()
        if self.lanes is not None:
            for lane in self.lanes.values():
                lane.dead = True


class MockRelay:
    """Минимальный релей: bridge page + session/up/down/ws, бэкенд-эхо."""

    def __init__(
        self,
        backend_port: int,
        carrier_mode: str = "https",
        mtproto_secret: bytes | None = None,
    ) -> None:
        assert carrier_mode in ("https", "https-lanes", "websocket",
                                "websocket-lanes")
        self.backend_port = backend_port
        self.carrier_mode = carrier_mode
        self.mtproto_secret = mtproto_secret
        self.port: int | None = None
        self.capability: str | None = None
        self.bootstrap_token = _random_token()
        self.session_token = _random_token()
        self.session: _Session | None = None

    def make_app(self) -> web.Application:
        app = web.Application(client_max_size=8 * 1024 * 1024)
        app.router.add_get("/", self.handle_root)
        app.router.add_post("/api/v1/session", self.handle_session)
        app.router.add_post("/api/v1/up", self.handle_up)
        app.router.add_post("/api/v1/down", self.handle_down)
        app.router.add_delete("/api/v1/session", self.handle_delete)
        app.router.add_get("/api/v1/ws", self.handle_ws)
        return app

    # ------------------------------------------------------------------
    # HTTP endpoints

    async def handle_root(self, request: web.Request) -> web.Response:
        if request.query.get("bridge") != self.capability or len(request.query) != 1:
            return web.Response(status=404, text="decoy")
        html = (
            "<!doctype html><script>"
            f'const relayOrigin="https://{HOST}",'
            f'bootstrap="{self.bootstrap_token}",'
            f'carrierMode="{self.carrier_mode}";'
            "</script><script>let batchLimit=2097152;</script>"
        )
        return web.Response(text=html, content_type="text/html")

    async def handle_session(self, request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {self.bootstrap_token}":
            return web.Response(status=404)
        hello = f.parse_batch(await request.read())
        if not (
            len(hello) == 1
            and hello[0].type is f.FrameType.HELLO
            and hello[0].payload == b"\x01"
        ):
            return web.Response(status=404)
        assert self.session is None, "mock supports one session per relay"
        self.session = _Session(self.session_token, self.carrier_mode)
        return web.Response(
            status=200,
            headers={
                "X-Session-Token": self.session_token,
                "X-Carrier-Mode": self.carrier_mode,
                "X-Down-Cursor": "0",
            },
            body=f.encode(f.FrameType.WELCOME, 0),
        )

    async def handle_up(self, request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization", "")
        seq = request.headers.get("X-Up-Seq", "")
        session = self.session
        if auth != f"Bearer {self.session_token}" or session is None:
            return web.Response(status=404)
        for frame in f.parse_batch(await request.read()):
            stream_id = frame.stream_id
            if stream_id == 0:
                continue  # PONG/WINDOW-control на нулевом потоке игнорируем
            if frame.type is f.FrameType.OPEN:
                if not session.ensure_lane(stream_id):
                    return web.Response(status=404)
                # Подключаемся синхронно относительно батча, чтобы DATA из
                # того же тела гарантированно нашёл writer.
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", self.backend_port
                )
                session.writers[stream_id] = writer
                if self.mtproto_secret is not None:
                    coro = self._pipe_obf(
                        session, stream_id, reader, writer, self.mtproto_secret
                    )
                else:
                    coro = self._pipe(session, stream_id, reader, writer)
                task = asyncio.create_task(coro)
                session.backend_tasks.add(task)
                task.add_done_callback(session.backend_tasks.discard)
            elif frame.type is f.FrameType.DATA:
                writer = session.writers[stream_id]
                writer.write(frame.payload)
                # Как настоящий релей: WINDOW-кредит возвращаем только после
                # фактической записи байт в бэкенд-сокет (backendDrained).
                await writer.drain()
                session.push(
                    stream_id,
                    f.encode(
                        f.FrameType.WINDOW,
                        stream_id,
                        f.window_payload(len(frame.payload)),
                    ),
                )
            elif frame.type is f.FrameType.CLOSE:
                writer = session.writers.pop(stream_id, None)
                if writer is not None:
                    writer.close()
                session.mark_dead(stream_id)
        return web.Response(status=204, headers={"X-Up-Ack": seq})

    async def handle_down(self, request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization", "")
        cursor = request.headers.get("X-Down-Cursor", "")
        session = self.session
        if auth != f"Bearer {self.session_token}" or session is None:
            return web.Response(status=404)

        lane: _Lane | None = None
        if session.lanes is not None:
            raw_lane = request.headers.get("X-Lane-ID", "")
            try:
                lane_id = int(raw_lane)
            except ValueError:
                return web.Response(status=404)
            lane = session.lanes.get(lane_id)
            if lane is None:
                return web.Response(status=404)
            queue = lane.queue
        else:
            queue = session.down_queue

        headers = {"X-Down-Cursor": cursor}
        try:
            first = await asyncio.wait_for(queue.get(), timeout=_LONG_POLL_SECS)
        except asyncio.TimeoutError:
            if lane is not None and lane.dead:
                headers["X-Lane-Closed"] = "1"
            return web.Response(status=204, headers=headers)

        chunks = deque([first])
        while not queue.empty():
            chunks.append(queue.get_nowait())
        body = b"".join(chunks)
        return web.Response(
            status=200,
            headers={
                "X-Down-Cursor": str(int(cursor) + 1),
                "Content-Type": "application/octet-stream",
            },
            body=body,
        )

    async def handle_delete(self, request: web.Request) -> web.Response:
        if request.headers.get("Authorization") != f"Bearer {self.session_token}":
            return web.Response(status=404)
        if self.session is not None:
            self.session.teardown()
        return web.Response(status=204)

    # ------------------------------------------------------------------
    # WebSocket carriers

    async def handle_ws(self, request: web.Request) -> web.StreamResponse:
        session = self.session
        if (
            request.method != "GET"
            or request.headers.get("Authorization")
            or session is None
        ):
            return web.Response(status=404)
        offered = request.headers.get("Sec-WebSocket-Protocol", "")
        sub = offered.split(",")[0].strip()

        lane: _Lane | None = None
        lane_id: int | None = None
        if self.carrier_mode == "websocket":
            expected = f"tproxy-v1.{self.session_token}"
            if sub != expected:
                return web.Response(status=404)
            queue = session.down_queue
        elif self.carrier_mode == "websocket-lanes":
            prefix = f"tproxy-lane-v1.{self.session_token}."
            if not sub.startswith(prefix):
                return web.Response(status=404)
            try:
                lane_id = int(sub[len(prefix):])
            except ValueError:
                return web.Response(status=404)
            # lane 0 не существует, повторное использование id запрещено.
            if lane_id == 0 or lane_id in session.lanes:
                return web.Response(status=404)
            lane = _Lane(awaiting_open=True)
            session.lanes[lane_id] = lane
            queue = lane.queue
        else:
            return web.Response(status=404)

        ws = web.WebSocketResponse(protocols=(sub,), autoping=True)
        await ws.prepare(request)

        async def pump() -> None:
            while True:
                try:
                    first = await asyncio.wait_for(
                        queue.get(), timeout=_WS_IDLE_PING_SECS
                    )
                except asyncio.TimeoutError:
                    await ws.ping()
                    continue
                items = [first]
                while not queue.empty():
                    items.append(queue.get_nowait())
                await ws.send_bytes(b"".join(items))

        pump_task = asyncio.create_task(pump())
        session.ws_tasks.add(pump_task)
        try:
            async for msg in ws:
                if msg.type != WSMsgType.BINARY:
                    break
                if msg.data:
                    ok = await self._process_batch(session, msg.data)
                    if not ok:
                        break
        finally:
            pump_task.cancel()
            session.ws_tasks.discard(pump_task)
            if lane_id is not None and session.lanes.get(lane_id) is lane:
                del session.lanes[lane_id]
                lane.dead = True
                writer = session.writers.pop(lane_id, None)
                if writer is not None:
                    writer.close()
        return ws

    async def _process_batch(self, session: _Session, batch: bytes) -> bool:
        """Общая обработка аплинк-батча для HTTP /up и WebSocket.

        Возвращает False при нарушении протокола (сокет закрывается).
        """
        for frame in f.parse_batch(batch):
            stream_id = frame.stream_id
            if stream_id == 0:
                continue
            if frame.type is f.FrameType.OPEN:
                if not session.ensure_lane(stream_id):
                    return False
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", self.backend_port
                )
                session.writers[stream_id] = writer
                if self.mtproto_secret is not None:
                    coro = self._pipe_obf(
                        session, stream_id, reader, writer, self.mtproto_secret
                    )
                else:
                    coro = self._pipe(session, stream_id, reader, writer)
                task = asyncio.create_task(coro)
                session.backend_tasks.add(task)
                task.add_done_callback(session.backend_tasks.discard)
            elif frame.type is f.FrameType.DATA:
                writer = session.writers[stream_id]
                writer.write(frame.payload)
                await writer.drain()
                session.push(
                    stream_id,
                    f.encode(
                        f.FrameType.WINDOW,
                        stream_id,
                        f.window_payload(len(frame.payload)),
                    ),
                )
            elif frame.type is f.FrameType.CLOSE:
                writer = session.writers.pop(stream_id, None)
                if writer is not None:
                    writer.close()
                session.mark_dead(stream_id)
        return True

    # ------------------------------------------------------------------
    # Бэкенд: по потоку — TCP-соединение с эхо-сервером

    @staticmethod
    def _ctr(key: bytes, iv: bytes):
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        return cipher.encryptor(), cipher.decryptor()

    async def _pipe_obf(
        self,
        session: _Session,
        stream_id: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        secret: bytes,
    ) -> None:
        """Бэкенд с server-side obfuscated2 (порт поведения MTProxy).

        В obfuscated2 обмен handshake односторонний: клиент шлёт 64-байтный
        init, а ВСЕ серверные ключи выводятся из него же — прямой порядок
        (init[8:56] + SHA-256 с секретом) для расшифровки входящего и
        развёрнутый init[8:56][::-1] для шифрования исходящего. Второй init
        сервер не отправляет: мост расшифровывает ответ своим decryptor,
        выведенным ровно из этих развёрнутых байт.
        """
        try:
            init = await reader.readexactly(64)
            dec_key = hashlib.sha256(init[8:40] + secret).digest()
            dec_iv = init[40:56]
            _, srv_decryptor = self._ctr(dec_key, dec_iv)
            # Синхронизация счётчика keystream: клиентский шифратор уже
            # «прогнал» через себя весь 64-байтный init (шифруя хвост),
            # поэтому сервер обязан прогнать handshake через расшифровщик,
            # прежде чем читать фреймы — иначе сдвиг на 64 байта.
            srv_decryptor.update(init)

            rev = bytes(init[8:56])[::-1]
            enc_key = hashlib.sha256(rev[:32] + secret).digest()
            srv_encryptor, _ = self._ctr(enc_key, rev[32:48])

            while True:
                data = await reader.read(65536)
                if not data:
                    break
                plain = srv_decryptor.update(data)
                session.push(
                    stream_id,
                    f.encode(
                        f.FrameType.DATA,
                        stream_id,
                        srv_encryptor.update(plain),
                    ),
                )
        finally:
            session.writers.pop(stream_id, None)
            writer.close()
            session.push(stream_id, f.encode(f.FrameType.CLOSE, stream_id))
            session.mark_dead(stream_id)

    async def _pipe(
        self,
        session: _Session,
        stream_id: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Читает эхо бэкенда и кладёт DATA/CLOSE в downlink-очередь."""
        try:
            while True:
                data = await reader.read(262144)
                if not data:
                    break
                session.push(
                    stream_id,
                    f.encode(f.FrameType.DATA, stream_id, data),
                )
        finally:
            session.writers.pop(stream_id, None)
            writer.close()
            session.push(stream_id, f.encode(f.FrameType.CLOSE, stream_id))
            session.mark_dead(stream_id)


@pytest.fixture
async def echo_server():
    async def handle(reader, writer):
        try:
            while True:
                data = await reader.read(262144)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


@pytest.fixture(params=ALL_MODES)
async def relay(request, echo_server):
    mock = MockRelay(echo_server, carrier_mode=request.param)
    runner = web.AppRunner(mock.make_app(), shutdown_timeout=2)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    mock.port = runner.addresses[0][1]
    yield mock
    await runner.cleanup()


def _make_tunnel(relay: MockRelay) -> WebTunnel:
    link = parse_web_link(f"tg://webproxy?server={HOST}&secret={SECRET_HEX}")
    relay.capability = link.capability
    return WebTunnel(link, origin=f"http://127.0.0.1:{relay.port}")


async def test_roundtrip_small(relay):
    tunnel = _make_tunnel(relay)
    assert tunnel.carrier_mode == ""  # ещё не установлена
    stream = await tunnel.open_stream()
    assert tunnel.carrier_mode == relay.carrier_mode
    await stream.write(b"ping")
    assert await stream.read() == b"ping"
    await tunnel.close_stream(stream.stream_id)
    await tunnel.aclose()


async def test_roundtrip_large_crosses_initial_window(relay):
    tunnel = _make_tunnel(relay)
    stream = await tunnel.open_stream()
    payload = bytes(range(256)) * (1024 * 18)  # ~4.5 MiB > окна в 4 MiB
    received = bytearray()

    async def reader():
        while len(received) < len(payload):
            chunk = await stream.read()
            if not chunk:
                break
            received.extend(chunk)

    read_task = asyncio.create_task(reader())
    await stream.write(payload)
    await asyncio.wait_for(read_task, timeout=60)
    assert bytes(received) == payload
    await tunnel.close_stream(stream.stream_id)
    await tunnel.aclose()


async def test_two_streams_interleave(relay):
    tunnel = _make_tunnel(relay)
    s1 = await tunnel.open_stream()
    s2 = await tunnel.open_stream()
    assert s1.stream_id != s2.stream_id

    await s1.write(b"alpha")
    await s2.write(b"beta")
    assert await s1.read() == b"alpha"
    assert await s2.read() == b"beta"
    await tunnel.close_stream(s1.stream_id)
    await tunnel.close_stream(s2.stream_id)
    await tunnel.aclose()


async def test_close_propagates_eof(relay):
    tunnel = _make_tunnel(relay)
    stream = await tunnel.open_stream()
    await stream.write(b"bye-test")
    assert await stream.read() == b"bye-test"
    await tunnel.close_stream(stream.stream_id)
    # Бэкенд закрылся → релей прислал CLOSE → read() вернёт b"".
    assert await asyncio.wait_for(stream.read(), timeout=15) == b""
    await tunnel.aclose()


async def test_wrong_capability_gets_decoy(relay):
    api = WebApi(f"http://127.0.0.1:{relay.port}")
    with pytest.raises(BootstrapRejected):
        await fetch_bridge_page(api, "A" * 43)
    await api.close()
