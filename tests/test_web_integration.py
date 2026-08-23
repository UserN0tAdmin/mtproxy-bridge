#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Интеграционный тест WEB-туннеля против mock-релея (режим https).

Mock-релей реализует минимальный контракт PROTOCOL.md v1: bridge-страница,
сессия HELLO/WELCOME, сериализованные /up и long-poll /down; каждый
логический поток подключается к локальному эхо-TCP-бэкенду — как настоящий
tproxy-server к официальному MTProxy.
"""

import asyncio
import base64
import os
from collections import deque

import pytest
from aiohttp import web

from mtproxy_bridge.links import parse_web_link
from mtproxy_bridge.web import frames as f
from mtproxy_bridge.web.bootstrap import fetch_bridge_page
from mtproxy_bridge.web.http_api import BootstrapRejected, WebApi
from mtproxy_bridge.web.tunnel import WebTunnel

HOST = "proxy.example.com"
SECRET_HEX = "000102030405060708090a0b0c0d0e0f"

_LONG_POLL_SECS = 3.0


def _random_token() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()


class _Session:
    def __init__(self, token: str) -> None:
        self.token = token
        self.down_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self.backend_tasks: set[asyncio.Task] = set()
        self.writers: dict[int, asyncio.StreamWriter] = {}


class MockRelay:
    """Минимальный релей: bridge page + session/up/down, бэкенд-эхо."""

    def __init__(self, backend_port: int) -> None:
        self.backend_port = backend_port
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
        return app

    # ------------------------------------------------------------------

    async def handle_root(self, request: web.Request) -> web.Response:
        if request.query.get("bridge") != self.capability or len(request.query) != 1:
            return web.Response(status=404, text="decoy")
        html = (
            "<!doctype html><script>"
            f'const relayOrigin="https://{HOST}",'
            f'bootstrap="{self.bootstrap_token}",'
            'carrierMode="https";'
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
        self.session = _Session(self.session_token)
        return web.Response(
            status=200,
            headers={
                "X-Session-Token": self.session_token,
                "X-Carrier-Mode": "https",
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
                continue  # WINDOW/PONG на нулевом потоке игнорируем
            if frame.type is f.FrameType.OPEN:
                # Подключаемся синхронно относительно батча, чтобы DATA из
                # того же тела гарантированно нашёл writer.
                reader, writer = await asyncio.open_connection(
                    "127.0.0.1", self.backend_port
                )
                session.writers[stream_id] = writer
                task = asyncio.create_task(
                    self._pipe(session, stream_id, reader, writer)
                )
                session.backend_tasks.add(task)
                task.add_done_callback(session.backend_tasks.discard)
            elif frame.type is f.FrameType.DATA:
                writer = session.writers[stream_id]
                writer.write(frame.payload)
                # Как настоящий релей: WINDOW-кредит возвращаем только после
                # фактической записи байт в бэкенд-сокет (backendDrained).
                await writer.drain()
                await session.down_queue.put(
                    f.encode(
                        f.FrameType.WINDOW,
                        stream_id,
                        f.window_payload(len(frame.payload)),
                    )
                )
            elif frame.type is f.FrameType.CLOSE:
                writer = session.writers.pop(stream_id, None)
                if writer is not None:
                    writer.close()
        return web.Response(status=204, headers={"X-Up-Ack": seq})

    async def handle_down(self, request: web.Request) -> web.Response:
        auth = request.headers.get("Authorization", "")
        cursor = request.headers.get("X-Down-Cursor", "")
        session = self.session
        if auth != f"Bearer {self.session_token}" or session is None:
            return web.Response(status=404)
        queue = session.down_queue
        try:
            first = await asyncio.wait_for(queue.get(), timeout=_LONG_POLL_SECS)
        except asyncio.TimeoutError:
            return web.Response(
                status=204, headers={"X-Down-Cursor": cursor}
            )
        chunks = deque([first])
        while not queue.empty():
            chunks.append(queue.get_nowait())
        return web.Response(
            status=200,
            headers={
                "X-Down-Cursor": str(int(cursor) + 1),
                "Content-Type": "application/octet-stream",
            },
            body=b"".join(chunks),
        )

    async def handle_delete(self, request: web.Request) -> web.Response:
        if request.headers.get("Authorization") != f"Bearer {self.session_token}":
            return web.Response(status=404)
        return web.Response(status=204)

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
                await session.down_queue.put(
                    f.encode(f.FrameType.DATA, stream_id, data)
                )
        finally:
            session.writers.pop(stream_id, None)
            writer.close()
            await session.down_queue.put(f.encode(f.FrameType.CLOSE, stream_id))


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


@pytest.fixture
async def relay(echo_server):
    mock = MockRelay(echo_server)
    # shutdown_timeout маленький: после отмены long-poll'ов у клиента остаются
    # полуоткрытые keep-alive соединения, и дефолтные 60 с ожидания релея
    # превращаются в «зависший» teardown.
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
    stream = await tunnel.open_stream()
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
    stream.close()
    # Бэкенд закрылся → релей прислал CLOSE → read() вернёт b"".
    assert await asyncio.wait_for(stream.read(), timeout=15) == b""
    await tunnel.aclose()


async def test_wrong_capability_gets_decoy(relay):
    api = WebApi(f"http://127.0.0.1:{relay.port}")
    with pytest.raises(BootstrapRejected):
        await fetch_bridge_page(api, "A" * 43)
    await api.close()
