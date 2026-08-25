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

"""Carrier'ы WEB Proxy v1: транспорт фрейм-батчей до релея и обратно.

Четыре режима из PROTOCOL.md («Carrier modes»):

- ``https`` — один сериализованный ``POST /up`` (``X-Up-Seq`` с единицы)
  и long poll ``/down`` (``X-Down-Cursor``);
- ``https-lanes`` — то же, но независимые последовательности на каждый
  логический поток (``X-Lane-ID``), lane 0 отведена session-control;
- ``websocket`` — один мультиплексирующий сокет, bearer в subprotocol
  ``tproxy-v1.<token>``;
- ``websocket-lanes`` — отдельный сокет на поток
  ``tproxy-lane-v1.<token>.<id>``; падение установленного сокета закрывает
  только его поток, неудача установки нового лейна роняет всю сессию.

Ограничения очередей повторяют референсный bridge: глобально 32 МиБ /
16384 элементов, на lane 8 МиБ / 1024 элементов. Батчи упаковываются по
правилам ``joinPending`` референса: целые элементы, а чрезмерно крупная
голова режется строго по границе фреймов.
"""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Awaitable, Callable, ClassVar

import aiohttp

from ..utils import log
from . import frames as f
from .frames import FrameError
from .http_api import WebApi

UPLINK_QUEUE_BYTES = 32 * 1024 * 1024
UPLINK_QUEUE_ITEMS = 16384
LANE_QUEUE_BYTES = 8 * 1024 * 1024
LANE_QUEUE_ITEMS = 1024

InboundCallback = Callable[[bytes], Awaitable[None]]
FailureCallback = Callable[[BaseException], Awaitable[None]]
StreamResetCallback = Callable[[int], Awaitable[None]]


class CarrierFailure(RuntimeError):
    """Родительский carrier мёртв — сессию нужно пересоздавать."""


def frame_bound(data: bytes, max_bytes: int) -> tuple[int, int]:
    """Сканирует префикс данных из полных фреймов.

    Возвращает ``(число_фреймов, число_байт)``. Первый фрейм учитывается
    всегда (как в референсном ``frameBound``), добавление последующих
    останавливается при превышении лимитов.

    Raises:
        FrameError: обрезанный фрейм во входных данных.
    """
    offset = 0
    n_frames = 0
    total = len(data)
    while offset < total:
        if total - offset < f.HEADER_SIZE:
            raise FrameError("truncated frame header")
        length = int.from_bytes(data[offset + 4 : offset + 8], "big")
        end = offset + f.HEADER_SIZE + length
        if end > total:
            raise FrameError("truncated frame payload")
        if n_frames > 0 and (n_frames >= f.MAX_BATCH_FRAMES or end > max_bytes):
            break
        n_frames += 1
        offset = end
    return n_frames, offset


def pack_batch(
    queue: deque[bytes],
    batch_limit: int,
    *,
    on_head_split: Callable[[], None] | None = None,
) -> tuple[bytes, int, int]:
    """Собирает батч: целые элементы в пределах лимитов.

    Слишком крупная голова (несколько фреймов больше лимита) режется по
    границе фреймов; остаток остаётся первым элементом очереди. Одиночный
    фрейм крупнее лимита целиком — ошибка упаковки (наши DATA ≤ 64 КиБ,
    лимит ≥ 64 КиБ, так что это внутренний баг, а не транспортное событие).

    ``on_head_split`` вызывается в момент разрезания головы: референсный
    ``joinPending`` учитывает голову новым элементом очереди
    (``queuedItems++``, остаток занимает старый слот). Без этого хука
    баланс элементов после цикла enqueue/release уходит в минус.

    Returns:
        ``(тело, байты, число_элементов)`` — элементы уже сняты с очереди.
    """
    total = 0
    frames = 0
    count = 0
    size = len(queue)
    while count < size:
        payload = queue[count]
        fr, nb = frame_bound(payload, batch_limit)
        whole = nb == len(payload)
        if count == 0:
            if whole and fr == 1 and len(payload) > batch_limit:
                # Резать нечего: одиночный фрейм крупнее лимита — падаем сразу.
                raise FrameError(
                    f"frame of {len(payload)} bytes exceeds batch limit"
                )
            if not whole:
                head = payload[:nb]
                queue[0] = payload[nb:]
                if on_head_split is not None:
                    on_head_split()
                return head, nb, 1
        if count > 0 and (
            total + len(payload) > batch_limit or frames + fr > f.MAX_BATCH_FRAMES
        ):
            break
        total += len(payload)
        frames += fr
        count += 1
    body = b"".join(queue.popleft() for _ in range(count))
    return body, total, count


class _LaneState:
    """Состояние одного лейна (https-lanes / websocket-lanes)."""

    __slots__ = (
        "lane_id",
        "sequence",
        "cursor",
        "pending",
        "bytes",
        "items",
        "closed",
        "wake",
        "tasks",
        "socket",
        "socket_ready",
        "poller_started",
    )

    def __init__(self, lane_id: int) -> None:
        self.lane_id = lane_id
        self.sequence = 1
        self.cursor = 0
        self.pending: deque[bytes] = deque()
        self.bytes = 0
        self.items = 0
        self.closed = False
        self.wake = asyncio.Event()
        self.tasks: list[asyncio.Task] = []
        self.socket: aiohttp.ClientWebSocketResponse | None = None
        self.socket_ready = asyncio.Event()
        # Даунклинк-поллер лейна стартует только после первого успешного
        # аплинка: сервер создаёт лейн по OPEN, и более ранний long poll
        # получил бы 404 (как в референсном bridge).
        self.poller_started = False


class BaseCarrier:
    """Общий каркас: глобальная очередь аплинка, задачи, аварийный останов.

    Плоские режимы (https/websocket) используют очередь напрямую;
    lanes-режимы переопределяют ``enqueue``, распределяя байты по лейнам,
    но разделяют глобальный бюджет и служебный каркас.
    """

    mode: ClassVar[str] = ""

    def __init__(
        self,
        api: WebApi,
        session_token: str,
        *,
        batch_limit: int,
        on_inbound: InboundCallback,
        on_failure: FailureCallback,
        on_stream_reset: StreamResetCallback | None = None,
    ) -> None:
        self._api = api
        self._token = session_token
        self._batch_limit = max(64 * 1024, min(batch_limit, 2 * 1024 * 1024))
        self._on_inbound = on_inbound
        self._on_failure = on_failure
        self._on_stream_reset = on_stream_reset

        self._pending: deque[bytes] = deque()
        self._queued_bytes = 0
        self._queued_items = 0
        self._not_empty = asyncio.Event()
        self._not_full = asyncio.Event()
        self._not_full.set()

        self._tasks: list[asyncio.Task] = []
        self._stopping = False
        self._failed_exc: BaseException | None = None

    # ------------------------------------------------------------------
    # Публичный интерфейс

    @property
    def failed(self) -> BaseException | None:
        return self._failed_exc

    async def start(self) -> None:
        """Запускает фоновые задачи carrier'а."""

    async def enqueue(self, payload: bytes, *, lane_id: int = 0) -> None:
        """Ставит батч полных фреймов в очередь аплинка (с backpressure)."""
        del lane_id  # плоские режимы не различают потоки
        while not self._stopping and (
            self._queued_bytes + len(payload) > UPLINK_QUEUE_BYTES
            or self._queued_items >= UPLINK_QUEUE_ITEMS
        ):
            self._not_full.clear()
            await self._not_full.wait()
        if self._stopping:
            raise CarrierFailure("carrier is shutting down")
        self._pending.append(payload)
        self._queued_bytes += len(payload)
        self._queued_items += 1
        self._not_empty.set()

    async def ensure_lane(self, lane_id: int) -> None:
        """Гарантирует готовность транспорта потока (нет-op для плоских)."""

    async def forget_lane(self, lane_id: int) -> None:
        """Локально закрывает транспорт потока (нет-op для плоских)."""

    def _has_pending(self) -> bool:
        """Есть ли неотправленные аплинк-байты."""
        return bool(self._pending)

    async def aclose(self, *, grace: float = 0.5) -> None:
        """Останавливает задачи и закрывает транспорт.

        ``grace`` — короткое окно, за которое отправитель успевает вытолкнуть
        уже поставленные в очередь кадры (например, CLOSE при закрытии
        потока непосредственно перед остановкой туннеля).
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, grace)
        while (
            self._failed_exc is None
            and self._has_pending()
            and loop.time() < deadline
        ):
            await asyncio.sleep(0.02)
        self._stopping = True
        self._wake_all()
        await self._cancel_tasks()
        await self._teardown_transport()
        self._drop_pending("shutdown")

    # ------------------------------------------------------------------
    # Очередь и бюджет

    def _wake_all(self) -> None:
        self._not_empty.set()
        self._not_full.set()

    def _drop_pending(self, reason: str) -> None:
        if self._queued_items:
            log.debug(
                "[web-carrier %s] dropped %d queued uplink item(s) (%s)",
                self.mode,
                self._queued_items,
                reason,
            )
        self._pending.clear()
        self._queued_bytes = 0
        self._queued_items = 0
        self._wake_all()

    def _release(self, nbytes: int, nitems: int) -> None:
        self._queued_bytes -= nbytes
        self._queued_items -= nitems
        if (
            self._queued_bytes <= UPLINK_QUEUE_BYTES
            and self._queued_items < UPLINK_QUEUE_ITEMS
        ):
            self._not_full.set()

    def _charge_split_head(self, lane: "_LaneState | None" = None) -> None:
        """Учитывает голову сплита новым элементом (как joinPending).

        enqueue начислил один элемент за весь payload; после разрезания в
        очереди живут голова-батч И остаток, поэтому при сплите элемент
        добавляется, а ``release(count=1)`` позже списывает только голову.
        """
        self._queued_items += 1
        if lane is not None:
            lane.items += 1

    async def _drain_flat(self) -> tuple[bytes, int, int] | None:
        """Ждёт данные и снимает очередной батч плоской очереди."""
        while True:
            if self._pending:
                return pack_batch(
                    self._pending,
                    self._batch_limit,
                    on_head_split=self._charge_split_head,
                )
            if self._stopping:
                return None
            self._not_empty.clear()
            if self._pending or self._stopping:
                continue
            await self._not_empty.wait()
            if self._stopping and not self._pending:
                return None

    # ------------------------------------------------------------------
    # Каркас задач

    def _spawn(self, coro: Awaitable[None]) -> None:
        task = asyncio.create_task(coro)  # type: ignore[arg-type]
        self._tasks.append(task)

    async def _cancel_tasks(self) -> None:
        mine = [t for t in self._tasks if t is not asyncio.current_task()]
        for t in mine:
            t.cancel()
        if mine:
            await asyncio.gather(*mine, return_exceptions=True)
        self._tasks.clear()

    async def _teardown_transport(self) -> None:
        return

    async def _fail(self, exc: BaseException) -> None:
        if self._failed_exc is not None or self._stopping:
            return
        self._failed_exc = exc
        self._stopping = True
        self._drop_pending("carrier failure")
        await self._cancel_tasks()
        await self._teardown_transport()
        try:
            await self._on_failure(exc)
        except Exception:
            log.exception("[web-carrier %s] on_failure raised", self.mode)

    async def _guarded(
        self, label: str, coro_factory: Callable[[], Awaitable[None]]
    ) -> None:
        try:
            await coro_factory()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("[web-carrier %s] %s failed: %r", self.mode, label, exc)
            await self._fail(exc)


class HttpsCarrier(BaseCarrier):
    """Serialized HTTPS: один активный POST /up, один long poll /down."""

    mode = "https"

    async def start(self) -> None:
        self._spawn(self._guarded("uplink", self._sender_loop))
        self._spawn(self._guarded("downlink", self._poll_loop))

    async def _sender_loop(self) -> None:
        sequence = 1
        while True:
            packed = await self._drain_flat()
            if packed is None:
                return
            body, nbytes, count = packed
            await self._api.up(self._token, sequence, body)
            self._release(nbytes, count)
            sequence += 1

    async def _poll_loop(self) -> None:
        cursor = 0
        while not self._stopping:
            result = await self._api.down(self._token, cursor)
            if result.lane_closed:
                raise CarrierFailure("unexpected X-Lane-Closed outside lanes mode")
            if result.has_data:
                await self._on_inbound(result.body)
            cursor = result.next_cursor


class WsCarrier(BaseCarrier):
    """websocket: один мультиплексирующий сокет, bearer в subprotocol."""

    mode = "websocket"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._socket: aiohttp.ClientWebSocketResponse | None = None
        self._socket_ready = asyncio.Event()

    async def start(self) -> None:
        self._spawn(self._guarded("reader", self._reader_loop))
        self._spawn(self._guarded("writer", self._writer_loop))

    async def _reader_loop(self) -> None:
        expected = f"tproxy-v1.{self._token}"
        ws = await self._api.ws_connect(expected)
        if ws.protocol != expected:
            await ws.close()
            raise CarrierFailure(
                f"relay echoed unexpected websocket subprotocol {ws.protocol!r}"
            )
        self._socket = ws
        self._socket_ready.set()
        try:
            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.BINARY:
                    raise CarrierFailure(
                        f"relay sent {msg.type.name.lower()} websocket message"
                    )
                if not msg.data:
                    raise CarrierFailure("empty websocket message")
                await self._on_inbound(msg.data)
        finally:
            self._socket = None
            self._socket_ready.clear()
        raise CarrierFailure("websocket closed by relay")

    async def _writer_loop(self) -> None:
        while True:
            packed = await self._drain_flat()
            if packed is None:
                return
            body, nbytes, count = packed
            await self._socket_ready.wait()
            socket = self._socket
            if socket is None:
                raise CarrierFailure("websocket lost before write")
            await socket.send_bytes(body)
            self._release(nbytes, count)

    async def _teardown_transport(self) -> None:
        socket = self._socket
        self._socket = None
        self._socket_ready.clear()
        if socket is not None and not socket.closed:
            await socket.close()


class LaneBasedCarrier(BaseCarrier):
    """Общая механика lanes-режимов: состояние лейнов + маршрутизация."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._lanes: dict[int, _LaneState] = {}

    async def enqueue(self, payload: bytes, *, lane_id: int = 0) -> None:
        lane = self._lanes.get(lane_id)
        if lane is None or lane.closed:
            # Поздние фреймы закрытого лейна отбрасываем (семантика tombstone).
            log.debug("[web-carrier %s] drop late frame(s) for lane %d",
                      self.mode, lane_id)
            return
        while True:
            if self._stopping:
                raise CarrierFailure("carrier is shutting down")
            # forget_lane мог отсоединить лейн, пока enqueue спал: identity-
            # сравнение не даёт протечь счётчикам в мёртвый объект.
            live = self._lanes.get(lane_id)
            if live is not lane or lane.closed:
                log.debug("[web-carrier %s] drop late frame(s) for lane %d",
                          self.mode, lane_id)
                return
            if not (
                self._queued_bytes + len(payload) > UPLINK_QUEUE_BYTES
                or self._queued_items >= UPLINK_QUEUE_ITEMS
                or lane.bytes + len(payload) > LANE_QUEUE_BYTES
                or lane.items >= LANE_QUEUE_ITEMS
            ):
                break
            lane.wake.set()  # проснуться, если виноват был бюджет лейна
            self._not_full.clear()
            await self._not_full.wait()
        lane.pending.append(payload)
        lane.bytes += len(payload)
        lane.items += 1
        self._queued_bytes += len(payload)
        self._queued_items += 1
        lane.wake.set()
        self._not_empty.set()

    async def ensure_lane(self, lane_id: int) -> None:
        if lane_id in self._lanes:
            return
        lane = _LaneState(lane_id)
        self._lanes[lane_id] = lane
        self._spawn_lane_transport(lane)

    async def forget_lane(self, lane_id: int) -> None:
        lane = self._lanes.pop(lane_id, None)
        if lane is None:
            return
        lane.closed = True
        lane.wake.set()
        # Задача, вызвавшая forget_lane (например, reader умершего сокета),
        # сама себя не отменяет — иначе застряла бы в gather ниже.
        current = asyncio.current_task()
        mine = [t for t in lane.tasks if t is not current]
        for t in mine:
            t.cancel()
        if mine:
            await asyncio.gather(*mine, return_exceptions=True)
        lane.tasks = [t for t in lane.tasks if t is current]
        socket = lane.socket
        lane.socket = None
        if socket is not None and not socket.closed:
            await socket.close()
        if lane.bytes or lane.items:
            self._queued_bytes -= lane.bytes
            self._queued_items -= lane.items
        # Будим безусловно: спящий enqueue обязан увидеть tombstone.
        self._not_full.set()
        lane.pending.clear()
        lane.bytes = 0
        lane.items = 0

    def _has_pending(self) -> bool:
        """Есть ли неотправленные аплинк-байты (по всем лейнам)."""
        return bool(self._pending) or any(lane.pending for lane in self._lanes.values())

    def _spawn_lane_transport(self, lane: _LaneState) -> None:
        raise NotImplementedError

    async def _pack_lane(self, lane: _LaneState) -> tuple[bytes, int, int] | None:
        while True:
            if lane.pending:
                return pack_batch(
                    lane.pending,
                    self._batch_limit,
                    on_head_split=lambda ln=lane: self._charge_split_head(ln),
                )
            if lane.closed or self._stopping:
                return None
            lane.wake.clear()
            if lane.pending or lane.closed or self._stopping:
                continue
            await lane.wake.wait()


class HttpsLanesCarrier(LaneBasedCarrier):
    """https-lanes: независимые up/down последовательности на каждый поток."""

    mode = "https-lanes"

    async def start(self) -> None:
        await self.ensure_lane(0)  # control-lane (PONG/служебные фреймы)

    def _spawn_lane_transport(self, lane: _LaneState) -> None:
        # Даунклинк-поллер добавит сам sender после первого ack (см. ниже).
        lane.tasks.append(
            asyncio.create_task(
                self._guarded(f"lane {lane.lane_id} uplink",
                              lambda ln=lane: self._lane_sender(ln))
            )
        )

    async def _lane_sender(self, lane: _LaneState) -> None:
        while True:
            packed = await self._pack_lane(lane)
            if packed is None:
                return
            body, nbytes, count = packed
            await self._api.up(
                self._token, lane.sequence, body, lane_id=lane.lane_id
            )
            lane.sequence += 1
            lane.bytes -= nbytes
            lane.items -= count
            self._release(nbytes, count)
            self._not_full.set()
            if not lane.poller_started:
                lane.poller_started = True
                lane.tasks.append(
                    asyncio.create_task(
                        self._guarded(
                            f"lane {lane.lane_id} downlink",
                            lambda ln=lane: self._lane_poller(ln),
                        )
                    )
                )

    async def _lane_poller(self, lane: _LaneState) -> None:
        while not lane.closed and not self._stopping:
            result = await self._api.down(
                self._token, lane.cursor, lane_id=lane.lane_id
            )
            if result.lane_closed:
                await self.forget_lane(lane.lane_id)
                return
            if result.has_data:
                await self._on_inbound(result.body)
            lane.cursor = result.next_cursor


class WsLanesCarrier(LaneBasedCarrier):
    """websocket-lanes: отдельный сокет на каждый ненулевой поток.

    Падение установленного сокета закрывает только его поток (стрим
    сбрасывается через ``on_stream_reset``); неудача установки нового лейна
    трактуется как отказ родительского carrier'а.
    """

    mode = "websocket-lanes"

    def _spawn_lane_transport(self, lane: _LaneState) -> None:
        lane.tasks.append(
            asyncio.create_task(
                self._guarded(f"lane {lane.lane_id} socket",
                              lambda ln=lane: self._lane_socket(ln))
            )
        )
        lane.tasks.append(
            asyncio.create_task(
                self._guarded(f"lane {lane.lane_id} writer",
                              lambda ln=lane: self._lane_writer(ln))
            )
        )

    async def _lane_socket(self, lane: _LaneState) -> None:
        expected = f"tproxy-lane-v1.{self._token}.{lane.lane_id}"
        ws = await self._api.ws_connect(expected)
        if ws.protocol != expected:
            await ws.close()
            raise CarrierFailure(
                f"relay echoed unexpected lane subprotocol {ws.protocol!r}"
            )
        lane.socket = ws
        lane.socket_ready.set()
        established = True
        try:
            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.BINARY:
                    raise CarrierFailure(
                        f"relay sent {msg.type.name.lower()} on lane socket"
                    )
                if msg.data:
                    await self._on_inbound(msg.data)
        except asyncio.CancelledError:
            established = False
            raise
        except Exception:
            # Установленный сокет умер — роняем только этот поток.
            established = False
            await self.forget_lane(lane.lane_id)
            reset = self._on_stream_reset
            if reset is not None:
                await reset(lane.lane_id)
            return
        finally:
            lane.socket = None
            lane.socket_ready.clear()
        if established and not lane.closed:
            # Релей закрыл сокет штатно (например после CLOSE) — поток завершён.
            await self.forget_lane(lane.lane_id)
            reset = self._on_stream_reset
            if reset is not None:
                await reset(lane.lane_id)

    async def _lane_writer(self, lane: _LaneState) -> None:
        while True:
            packed = await self._pack_lane(lane)
            if packed is None:
                return
            body, nbytes, count = packed
            await lane.socket_ready.wait()
            socket = lane.socket
            if socket is None:
                raise CarrierFailure("lane websocket lost before write")
            await socket.send_bytes(body)
            lane.bytes -= nbytes
            lane.items -= count
            self._release(nbytes, count)
            self._not_full.set()


def build_carrier(
    mode: str,
    api: WebApi,
    session_token: str,
    *,
    batch_limit: int,
    on_inbound: InboundCallback,
    on_failure: FailureCallback,
    on_stream_reset: StreamResetCallback | None = None,
) -> BaseCarrier:
    """Фабрика carrier'а по режиму, объявленному релеем."""
    kwargs = dict(
        batch_limit=batch_limit,
        on_inbound=on_inbound,
        on_failure=on_failure,
        on_stream_reset=on_stream_reset,
    )
    if mode == "https":
        return HttpsCarrier(api, session_token, **kwargs)
    if mode == "https-lanes":
        return HttpsLanesCarrier(api, session_token, **kwargs)
    if mode == "websocket":
        return WsCarrier(api, session_token, **kwargs)
    if mode == "websocket-lanes":
        return WsLanesCarrier(api, session_token, **kwargs)
    raise ValueError(f"unknown carrier mode {mode!r}")
