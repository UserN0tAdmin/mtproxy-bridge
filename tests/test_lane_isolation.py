#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  mtproxy-bridge is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with mtproxy-bridge.  If not, see <http://www.gnu.org/licenses/>.

"""Изоляция лейнов в websocket-lanes и https-lanes.

Регламент протокола (PROTOCOL.md:309-311, :390-392):

* «For a nonzero lane, every frame in an uplink body and every frame
  returned by its downlink poll must have a ``stream_id`` equal to
  ``X-Lane-ID``».
* «The relay closes only the affected established lane for a text,
  oversized, malformed, or cross-lane **client** message; **the bridge
  treats an invalid relay message as parent-carrier failure**».

Обе проверки в клиенте отсутствовали: батч уходил в ``_on_inbound``,
который маршрутизирует чисто по ``frame.stream_id`` без контекста лейна,
а пустой BINARY молча глошился (``if msg.data:``).
"""

from __future__ import annotations

import asyncio
import contextlib
import random

import pytest
from aiohttp import web

from mtproxy_bridge.links import parse_web_link
from mtproxy_bridge.web import frames as f
from mtproxy_bridge.web.carriers import CarrierFailure
from mtproxy_bridge.web.tunnel import WebTunnel

HOST = "proxy.example.com"
SECRET_HEX = "00112233445566778899aabbccddeeff"
TOKEN = "A" * 43


def _random_token() -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
    return "".join(random.choice(alphabet) for _ in range(43))


class _HostileRelay:
    """Релей websocket-lanes, который шлет в лейн требуемый мусор.

    ``behaviour`` выбирает, что именно сервер положит в первый принятый
    лейн-сокет: небинарное сообщение, пустой BINARY либо кадр чужого
    потока.
    """

    def __init__(self, behaviour: str, variant: str = "ws-lanes") -> None:
        assert behaviour in (
            "text",
            "empty-binary",
            "cross-lane",
            "graceful-close",
            "pass",
        )
        assert variant in ("ws-lanes", "http-lanes")
        self.behaviour = behaviour
        self.variant = variant
        self.bootstrap = _random_token()
        self.session_token = _random_token()
        self.sockets: list[web.WebSocketResponse] = []
        self.lane_payload = b""
        self.lane_ready = asyncio.Event()
        self.capability = ""

    def make_app(self) -> web.Application:
        relay = self
        carrier_mode = (
            "websocket-lanes" if relay.variant == "ws-lanes" else "https-lanes"
        )

        async def handle_root(request: web.Request) -> web.Response:
            if (
                request.query.get("bridge") != relay.capability
                or len(request.query) != 1
            ):
                return web.Response(status=404, text="decoy")
            return web.Response(
                text=(
                    "<!doctype html><script>"
                    f'const relayOrigin="https://{HOST}",'
                    f'bootstrap="{relay.bootstrap}",'
                    f'carrierMode="{carrier_mode}";'
                    "</script>"
                ),
                content_type="text/html",
            )

        async def handle_session(request: web.Request) -> web.Response:
            if request.headers.get("Authorization", "") != f"Bearer {relay.bootstrap}":
                return web.Response(status=404)
            hello = f.parse_batch(await request.read())
            if not (
                len(hello) == 1
                and hello[0].type is f.FrameType.HELLO
                and hello[0].payload == b"\x01"
            ):
                return web.Response(status=404)
            return web.Response(
                status=200,
                headers={
                    "X-Session-Token": relay.session_token,
                    "X-Carrier-Mode": carrier_mode,
                    "X-Down-Cursor": "0",
                },
                body=f.encode(f.FrameType.WELCOME, 0),
            )

        async def handle_up(request: web.Request) -> web.Response:
            # Аплинк только квитируем: лейн в тестах создаётся OPEN-ом.
            return web.Response(status=204, headers={"X-Up-Ack": "1"})

        async def handle_down(request: web.Request) -> web.Response:
            lane_id = int(request.headers.get("X-Lane-ID", "0"))
            if relay.behaviour == "cross-lane":
                return web.Response(
                    status=200,
                    headers={"X-Down-Cursor": "1"},
                    body=f.encode(f.FrameType.DATA, lane_id + 100, b"misrouted"),
                )
            if relay.behaviour == "text":
                # Мусорный батч: _on_inbound убьёт сессию — это не наш путь.
                return web.Response(status=200, body=b"\x00\x00")
            # Штатный (позитивный) случай: кадр этого же лейна.
            await relay.lane_ready.wait()
            return web.Response(
                status=200,
                headers={"X-Down-Cursor": "1"},
                body=f.encode(f.FrameType.DATA, lane_id, relay.lane_payload),
            )

        async def handle_ws(request: web.Request) -> web.WebSocketResponse:
            prefix = f"tproxy-lane-v1.{relay.session_token}."
            sub = (
                request.headers.get("Sec-WebSocket-Protocol", "").split(",")[0].strip()
            )
            if not sub.startswith(prefix):
                return web.Response(status=404)
            try:
                lane_id = int(sub[len(prefix) :])
            except ValueError:
                return web.Response(status=404)
            if lane_id == 0:
                return web.Response(status=404)

            ws = web.WebSocketResponse(protocols=(sub,))
            await ws.prepare(request)
            relay.sockets.append(ws)

            if relay.behaviour == "text":
                await ws.send_str("not a frame batch")
            elif relay.behaviour == "empty-binary":
                await ws.send_bytes(b"")
            elif relay.behaviour == "cross-lane":
                # OPEN чужого потока в лейне этого: клиент обязан отвергнуть.
                await ws.send_bytes(
                    f.encode(f.FrameType.OPEN, lane_id + 100)
                    + f.encode(f.FrameType.DATA, lane_id + 100, b"misrouted")
                )
            elif relay.behaviour == "graceful-close":
                # Штатный сценарий: CLOSE этого же лейна, затем разрыв.
                await ws.send_bytes(f.encode(f.FrameType.CLOSE, lane_id))
                await ws.close()
            else:
                # Позитив: кадр ровно того потока, что у лейна.
                await relay.lane_ready.wait()
                await ws.send_bytes(
                    f.encode(f.FrameType.DATA, lane_id, relay.lane_payload)
                )
                await ws.close()

            try:
                async for _ in ws:
                    pass
            finally:
                pass
            return ws

        app = web.Application()
        app.router.add_get("/", handle_root)
        app.router.add_post("/api/v1/session", handle_session)
        app.router.add_post("/api/v1/up", handle_up)
        app.router.add_post("/api/v1/down", handle_down)
        app.router.add_get("/api/v1/ws", handle_ws)
        return app


async def _serve(relay: _HostileRelay) -> web.AppRunner:
    runner = web.AppRunner(relay.make_app(), shutdown_timeout=2)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner


async def _open_session(relay: _HostileRelay, runner: web.AppRunner) -> WebTunnel:
    link = parse_web_link(f"tg://webproxy?server={HOST}&secret={SECRET_HEX}")
    relay.capability = link.capability
    tunnel = WebTunnel(link, origin=f"http://127.0.0.1:{runner.addresses[0][1]}")
    await tunnel.open_stream()
    return tunnel


@pytest.mark.parametrize("behaviour", ["text", "empty-binary", "cross-lane"])
async def test_relay_violation_kills_parent_carrier(behaviour):
    """Невалидное relay-сообщение на лейне — отказ carrier'а, не сброс стрима."""
    relay = _HostileRelay(behaviour)
    runner = await _serve(relay)
    try:
        tunnel = await _open_session(relay, runner)
        carrier = tunnel._carrier
        assert carrier is not None, "сессия не установилась"

        # Дожидаемся, пока враждебный батч дойдёт до клиента.
        for _ in range(200):
            if carrier.failed is not None:
                break
            await asyncio.sleep(0.02)

        assert carrier.failed is not None, (
            f"{behaviour}: carrier пережил нарушение контракта relay'ом"
        )
        assert isinstance(carrier.failed, CarrierFailure)
        # Смерть carrier'а = смерть сессии: открытые стримы сброшены.
        assert tunnel._streams == {} or all(s.closed for s in tunnel._streams.values())
        if behaviour == "cross-lane":
            # Причина обязана приходить из lane-проверки, а не из общего
            # _kill_session: иначе тест проходил бы и без неё.
            assert "cross-lane" in str(carrier.failed)
    finally:
        if tunnel is not None:
            with contextlib.suppress(Exception):
                await tunnel.aclose()
        await runner.cleanup()


async def test_graceful_lane_close_resets_only_that_stream():
    """Контроль: штатный CLOSE лейна не должен валить родительский carrier."""
    relay = _HostileRelay("graceful-close")
    runner = await _serve(relay)
    tunnel = None
    try:
        tunnel = await _open_session(relay, runner)
        carrier = tunnel._carrier
        assert carrier is not None

        for _ in range(200):
            if not carrier._lanes:
                break
            await asyncio.sleep(0.02)

        assert carrier.failed is None, "штатный CLOSE лейна не есть отказ carrier'а"
        # Лейн вычищен, кадры для него больше не приходят.
        assert 1 not in carrier._lanes
    finally:
        if tunnel is not None:
            await tunnel.aclose()
        await runner.cleanup()


async def test_https_lanes_cross_lane_frame_kills_carrier():
    """Тот же контракт в https-lanes: чужой кадр в /down лейна."""
    relay = _HostileRelay("cross-lane", variant="http-lanes")
    runner = await _serve(relay)
    tunnel = None
    try:
        tunnel = await _open_session(relay, runner)
        carrier = tunnel._carrier
        assert carrier is not None
        assert tunnel.carrier_mode == "https-lanes"

        for _ in range(300):
            if carrier.failed is not None:
                break
            await asyncio.sleep(0.02)

        assert carrier.failed is not None
        assert "cross-lane" in str(carrier.failed)
    finally:
        if tunnel is not None:
            with contextlib.suppress(Exception):
                await tunnel.aclose()
        await runner.cleanup()


async def test_correct_lane_frames_pass_through():
    """Позитив: кадры с совпадающим lane_id не отклоняются проверкой.

    Без него проверка могла бы отвергать легитимный трафик.
    """
    for variant in ("ws-lanes", "http-lanes"):
        relay = _HostileRelay("text", variant=variant)
        relay.behaviour = "pass"
        runner = await _serve(relay)
        tunnel = None
        try:
            tunnel = await _open_session(relay, runner)
            carrier = tunnel._carrier
            assert carrier is not None

            stream = await asyncio.wait_for(tunnel.open_stream(), timeout=10)
            relay.lane_payload = b"payload"
            relay.lane_ready.set()

            assert await asyncio.wait_for(stream.read(), timeout=10) == b"payload", (
                variant
            )
            assert carrier.failed is None, variant
        finally:
            if tunnel is not None:
                with contextlib.suppress(Exception):
                    await tunnel.aclose()
            await runner.cleanup()


async def test_lane_zero_stream_zero_frames_are_not_cross_lane():
    """Lane 0 несёт stream-0 кадры — проверка не должна их отвергать."""
    carrier_mode_ok = [
        (f.encode(f.FrameType.PONG, 0, b"token"), 0),
        (f.encode(f.FrameType.DATA, 7, b"x"), 7),
        (f.encode(f.FrameType.WELCOME, 0), 0),
    ]
    from mtproxy_bridge.web.carriers import WsLanesCarrier

    carrier = object.__new__(
        WsLanesCarrier
    )  # без инициализации: тестируем только хелпер
    for batch, lane_id in carrier_mode_ok:
        assert carrier._reject_cross_lane(batch, lane_id) is None

    # Битый батч проверка пропускает — формой займётся _on_inbound.
    assert carrier._reject_cross_lane(b"\xff", 1) is None
    with pytest.raises(CarrierFailure):
        carrier._reject_cross_lane(f.encode(f.FrameType.DATA, 9, b"x"), 1)
