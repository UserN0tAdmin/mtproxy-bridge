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

"""Регрессия: смерть/замена carrier'а websocket-lanes закрывает лейн-сокеты.

До фикса ``_teardown_transport`` у ``WsLanesCarrier`` наследовался no-op
из BaseCarrier, а лейн-таски никто не отменяет (``_cancel_tasks`` снимает
лишь ``self._tasks``, транспорт лейна живёт в ``lane.tasks``), поэтому
после ``carrier._fail()`` и после ``carrier.aclose()`` сервер продолжал
видеть живые WS-соединения лейнов; они переживали carrier до конца
aiohttp-сессии туннеля (утечка FD на каждый цикл смерти сессии).
"""

import asyncio
import contextlib

import pytest
from aiohttp import web

from mtproxy_bridge.web.carriers import CarrierFailure, WsLanesCarrier
from mtproxy_bridge.web.http_api import WebApi


async def _noop(*args: object, **kwargs: object) -> None:
    return None


async def _make_relay() -> tuple[WebApi, set[web.WebSocketResponse], web.AppRunner]:
    """Мок-релей: WS-upgrade с эхом subprotocol; считаем живые соединения."""
    active: set[web.WebSocketResponse] = set()

    async def ws_handler(request: web.Request) -> web.WebSocketResponse:
        proto = request.headers.get("Sec-WebSocket-Protocol", "")
        ws = web.WebSocketResponse(protocols=[proto] if proto else [])
        await ws.prepare(request)
        active.add(ws)
        try:
            async for _ in ws:
                pass
        finally:
            active.discard(ws)
        return ws

    app = web.Application()
    app.router.add_get("/api/v1/ws", ws_handler)
    # shutdown_timeout обязателен: без него teardown теста виснет на
    # Python 3.12+ (wait_closed ждёт все соединения) — см. HANDOFF п.10.
    runner = web.AppRunner(app, shutdown_timeout=2)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = runner.addresses[0][1]
    return WebApi(f"http://127.0.0.1:{port}"), active, runner


async def _open_two_lanes(api: WebApi) -> WsLanesCarrier:
    carrier = WsLanesCarrier(
        api, "tok", batch_limit=65536,
        on_inbound=_noop, on_failure=_noop, on_stream_reset=_noop,
    )
    for lane_id in (1, 2):
        await carrier.ensure_lane(lane_id)
    for _ in range(100):
        if all(carrier._lanes[i].socket_ready.is_set() for i in (1, 2)):
            return carrier
        await asyncio.sleep(0.05)
    raise AssertionError("лейн-сокеты не установились за отведённое время")


async def _wait_drained(
    active: set[web.WebSocketResponse], timeout: float = 2.0
) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while active:
        if loop.time() > deadline:
            return False
        await asyncio.sleep(0.05)
    return True


@pytest.mark.parametrize("kill", ["fail", "aclose"])
async def test_lane_sockets_closed_on_carrier_death(kill: str) -> None:
    api, active, runner = await _make_relay()
    try:
        carrier = await _open_two_lanes(api)
        assert len(active) == 2

        if kill == "fail":
            await carrier._fail(CarrierFailure("simulated session death"))
        else:
            await carrier.aclose(grace=0)

        assert await _wait_drained(active), (
            f"лейн-сокеты пережили смерть carrier'а ({kill}): "
            f"{len(active)} шт. ещё живы"
        )
        assert all(lane.socket is None for lane in carrier._lanes.values())
    finally:
        with contextlib.suppress(Exception):
            await api.close()
        await runner.cleanup()
