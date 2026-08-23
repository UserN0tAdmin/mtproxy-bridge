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

"""WebTunnel — мультиплексированная WEB Proxy сессия поверх carrier'а.

Жизненный цикл (PROTOCOL.md «Client stream lifecycle»):

1. bootstrap-страница → одноразовый токен;
2. ``POST /api/v1/session`` (HELLO) → сессия + WELCOME, режим carrier'а
   фиксирован ответом ``X-Carrier-Mode``;
3. каждое клиентское соединение — новый непереиспользуемый ненулевой
   stream id и один OPEN;
4. байты клиента едут DATA в пределах выданного кредита окна; прочитанные
   наверх байты возвращаются WINDOW-кредитом релею;
5. EOF/сбой любой стороны — CLOSE этого потока; остальные живут.

При смерти carrier'а вся сессия считается потерянной (как в референсном
bridge): активные потоки сбрасываются, новая сессия создаётся лениво при
следующем :meth:`WebTunnel.open_stream`.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections import deque

from ..links import WebProxyLink
from ..utils import log
from . import frames as f
from .bootstrap import fetch_bridge_page
from .carriers import BaseCarrier, CarrierFailure, build_carrier
from .frames import FrameError
from .http_api import BootstrapRejected, ProtocolViolation, WebApi


class TunnelClosed(RuntimeError):
    """Туннель закрыт и больше не выдаёт потоки."""


class WebStream:
    """Один логический MTProxy-поток внутри WEB-сессии.

    Контракт для relay-слоя моста: :meth:`write` блокируется до появления
    кредита окна (backpressure доходит до клиентского TCP), :meth:`read`
    возвращает накопленный батч или ``b""`` при штатном закрытии и бросает
    :class:`ConnectionError` при сбое сессии/потока.
    """

    __slots__ = (
        "stream_id",
        "_tunnel",
        "_rx",
        "_rx_event",
        "_credit",
        "_credit_event",
        "_eof",
        "_error",
        "_unacked_rx",
    )

    def __init__(self, tunnel: "WebTunnel", stream_id: int) -> None:
        self.stream_id = stream_id
        self._tunnel = tunnel
        self._rx: deque[bytes] = deque()
        self._rx_event = asyncio.Event()
        self._credit = f.INITIAL_STREAM_WINDOW
        self._credit_event = asyncio.Event()
        self._credit_event.set()
        self._eof = False
        self._error: ConnectionError | None = None
        self._unacked_rx = 0

    # ------------------------------------------------------------------
    # Сторона приложения

    async def write(self, data: bytes) -> None:
        """Отправляет DATA в пределах кредита окна (режется по 64 КиБ)."""
        view = memoryview(data)
        while len(view):
            size = min(f.DATA_CHUNK, len(view))
            while self._credit < size:
                if self._error is not None:
                    raise self._error
                if self._eof:
                    raise ConnectionError(
                        f"stream {self.stream_id} is closed"
                    )
                self._credit_event.clear()
                if self._credit < size:
                    await self._credit_event.wait()
            chunk = view[:size]
            self._credit -= size
            await self._tunnel._stream_data(self.stream_id, bytes(chunk))
            view = view[size:]

    async def read(self) -> bytes:
        """Читает накопленные DATA; ``b""`` — EOF, исключение — сбой."""
        while True:
            if self._rx:
                data = b"".join(self._rx)
                self._rx.clear()
                self._unacked_rx -= len(data)
                with contextlib.suppress(Exception):
                    await self._tunnel._return_window(self.stream_id, len(data))
                return data
            if self._error is not None:
                raise self._error
            if self._eof:
                return b""
            self._rx_event.clear()
            if self._rx or self._error is not None or self._eof:
                continue
            await self._rx_event.wait()

    def close(self) -> None:
        """Планирует закрытие потока (идемпотентно, без ожидания CLOSE).

        Для детерминированного тестирования/остановки используйте
        :meth:`WebTunnel.close_stream`.
        """
        self._tunnel.close_stream_nowait(self.stream_id)

    # ------------------------------------------------------------------
    # Внутреннее (вызывается только WebTunnel)

    def _feed(self, payload: bytes) -> None:
        self._unacked_rx += len(payload)
        self._rx.append(payload)
        self._rx_event.set()

    def _grant_credit(self, amount: int) -> None:
        self._credit = min(self._credit + amount, 0xFFFFFFFF)
        self._credit_event.set()

    def _mark_eof(self) -> None:
        self._eof = True
        self._rx_event.set()
        self._credit_event.set()

    def _reset(self, error: ConnectionError | None) -> None:
        if error is not None:
            self._error = error
        else:
            self._eof = True
        self._rx.clear()
        self._unacked_rx = 0
        self._rx_event.set()
        self._credit_event.set()


class WebTunnel:
    """Сессия WEB Proxy: bootstrap, стримы, диспетчеризация входящих."""

    def __init__(self, link: WebProxyLink, *, origin: str | None = None) -> None:
        self._link = link
        self._origin = origin or f"https://{link.host}"
        self._api = WebApi(self._origin)
        self._carrier: BaseCarrier | None = None
        self._session_token = ""
        self._carrier_mode = ""
        self._streams: dict[int, WebStream] = {}
        self._next_stream_id = 1
        self._setup_lock = asyncio.Lock()
        self._closed = False
        self._bg_tasks: set[asyncio.Task] = set()

    @property
    def carrier_mode(self) -> str:
        return self._carrier_mode

    @property
    def alive_streams(self) -> int:
        return len(self._streams)

    # ------------------------------------------------------------------
    # Потоки

    async def open_stream(self) -> WebStream:
        """Открывает новый логический поток (OPEN уходит после регистрации)."""
        async with self._setup_lock:
            if self._closed:
                raise TunnelClosed("web tunnel is closed")
            await self._ensure_session()
            stream_id = self._alloc_stream_id()
            stream = WebStream(self, stream_id)
            self._streams[stream_id] = stream
        try:
            carrier = self._require_carrier()
            await carrier.enqueue(
                f.encode(f.FrameType.OPEN, stream_id), lane_id=stream_id
            )
        except CarrierFailure as exc:
            self._streams.pop(stream_id, None)
            raise ConnectionError("web session lost") from exc
        except BaseException:
            self._streams.pop(stream_id, None)
            raise
        log.debug("[web-tunnel] opened stream %d", stream_id)
        return stream

    async def close_stream(self, stream_id: int) -> None:
        """Закрывает поток: CLOSE наружу, локальный EOF читателям."""
        stream = self._streams.pop(stream_id, None)
        if stream is None:
            return
        stream._mark_eof()
        carrier = self._carrier
        if carrier is not None and carrier.failed is None:
            with contextlib.suppress(Exception):
                await carrier.enqueue(
                    f.encode(f.FrameType.CLOSE, stream_id), lane_id=stream_id
                )
            with contextlib.suppress(Exception):
                await carrier.forget_lane(stream_id)

    def close_stream_nowait(self, stream_id: int) -> None:
        """Планирует :meth:`close_stream` фоновой задачей."""
        if stream_id not in self._streams:
            return

        async def _finish() -> None:
            await self.close_stream(stream_id)

        task = asyncio.get_running_loop().create_task(_finish())
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)

    async def aclose(self) -> None:
        """Полностью закрывает туннель: DELETE сессии, сброс всех потоков."""
        if self._closed:
            return
        self._closed = True
        streams = list(self._streams.values())
        self._streams.clear()
        for stream in streams:
            stream._reset(ConnectionError("web tunnel closed"))
        await self._teardown_carrier(grace=1.0)
        for task in list(self._bg_tasks):
            task.cancel()
        if self._bg_tasks:
            await asyncio.gather(*self._bg_tasks, return_exceptions=True)
        if self._session_token:
            with contextlib.suppress(Exception):
                await self._api.delete_session(self._session_token)
            self._session_token = ""
        await self._api.close()

    # ------------------------------------------------------------------
    # Отправка (используется WebStream)

    async def _stream_data(self, stream_id: int, data: bytes) -> None:
        if stream_id not in self._streams:
            raise ConnectionError(f"stream {stream_id} is already closed")
        carrier = self._require_carrier()
        try:
            await carrier.enqueue(f.encode(f.FrameType.DATA, stream_id, data),
                                  lane_id=stream_id)
        except CarrierFailure as exc:
            raise ConnectionError("web session lost") from exc

    async def _return_window(self, stream_id: int, amount: int) -> None:
        if stream_id not in self._streams or amount <= 0:
            return
        carrier = self._carrier
        if carrier is None:
            return
        with contextlib.suppress(Exception):
            await carrier.enqueue(
                f.encode(f.FrameType.WINDOW, stream_id, f.window_payload(amount)),
                lane_id=stream_id,
            )

    def _require_carrier(self) -> BaseCarrier:
        carrier = self._carrier
        if carrier is None or carrier.failed is not None:
            raise ConnectionError("web session is not established")
        return carrier

    # ------------------------------------------------------------------
    # Приём и сессия

    async def _on_inbound(self, batch: bytes) -> None:
        try:
            frames = f.parse_batch(batch)
        except FrameError as exc:
            await self._kill_session(f"malformed inbound batch: {exc}")
            return
        for frame in frames:
            try:
                f.validate_relay_frame(frame)
            except FrameError as exc:
                await self._kill_session(f"bad relay frame shape: {exc}")
                return
            ftype = frame.type
            if ftype in (f.FrameType.WELCOME, f.FrameType.PING):
                # WELCOME уже проверен при создании сессии; PING не используем.
                continue
            if ftype is f.FrameType.BYE:
                await self._kill_session("relay sent BYE")
                return
            stream = self._streams.get(frame.stream_id)
            if stream is None:
                continue  # поздний фрейм закрытого потока (tombstone)
            if ftype is f.FrameType.DATA:
                if stream._unacked_rx + len(frame.payload) > (
                    f.INITIAL_STREAM_WINDOW
                ):
                    await self._kill_session(
                        f"relay exceeded receive window on stream "
                        f"{frame.stream_id}"
                    )
                    return
                stream._feed(frame.payload)
            elif ftype is f.FrameType.WINDOW:
                try:
                    amount = f.parse_window_amount(frame.payload)
                except FrameError:
                    await self._kill_session("invalid WINDOW payload")
                    return
                stream._grant_credit(amount)
            elif ftype is f.FrameType.CLOSE:
                self._streams.pop(frame.stream_id, None)
                stream._mark_eof()

    async def _on_stream_reset(self, stream_id: int) -> None:
        """Падение установленного lane-сокета (websocket-lanes)."""
        stream = self._streams.pop(stream_id, None)
        if stream is not None:
            stream._reset(ConnectionError(f"stream {stream_id} reset"))

    async def _on_carrier_failure(self, exc: BaseException) -> None:
        log.warning("[web-tunnel] carrier died (%r); session dropped", exc)
        self._session_token = ""
        streams = list(self._streams.values())
        self._streams.clear()
        for stream in streams:
            stream._reset(ConnectionError("web session lost"))

    async def _kill_session(self, reason: str) -> None:
        log.warning("[web-tunnel] killing session: %s", reason)
        carrier = self._carrier
        if carrier is not None and carrier.failed is None:
            await carrier._fail(CarrierFailure(reason))

    def _alloc_stream_id(self) -> int:
        total = f.MAX_STREAM_ID
        for _ in range(total):
            candidate = self._next_stream_id
            self._next_stream_id += 1
            if self._next_stream_id > total:
                self._next_stream_id = 1
            if candidate not in self._streams:
                return candidate
        raise RuntimeError("no free stream ids")

    async def _teardown_carrier(self, grace: float = 0.0) -> None:
        carrier = self._carrier
        self._carrier = None
        if carrier is not None:
            with contextlib.suppress(Exception):
                await carrier.aclose(grace=grace)

    async def _ensure_session(self) -> None:
        """Гарантирует живую сессию (лениво пересоздаёт после сбоя)."""
        if (
            self._carrier is not None
            and self._carrier.failed is None
            and not self._closed
        ):
            return
        await self._teardown_carrier()
        self._session_token = ""

        log.info(
            "[web-tunnel] fetching bridge page from %s (capability %s...)",
            self._origin,
            self._link.capability[:8],
        )
        page = await fetch_bridge_page(self._api, self._link.capability)
        resp = await self._api.create_session(page.token, f.hello_frame())
        if resp.status != 200:
            raise BootstrapRejected(
                f"session creation rejected: HTTP {resp.status}"
            )
        token = resp.headers.get("X-Session-Token")
        if not token:
            raise ProtocolViolation("missing X-Session-Token header")
        announced_mode = resp.headers.get("X-Carrier-Mode") or ""
        if announced_mode != page.carrier_mode:
            raise ProtocolViolation(
                f"carrier mode mismatch: page={page.carrier_mode!r}, "
                f"header={announced_mode!r}"
            )
        try:
            welcome = f.parse_batch(resp.body)
        except FrameError as exc:
            raise ProtocolViolation(f"bad WELCOME batch: {exc}") from exc
        if not f.is_welcome(welcome):
            raise ProtocolViolation("session body is not a single WELCOME")

        carrier = build_carrier(
            announced_mode,
            self._api,
            token,
            batch_limit=page.batch_limit,
            on_inbound=self._on_inbound,
            on_failure=self._on_carrier_failure,
            on_stream_reset=self._on_stream_reset,
        )
        await carrier.start()
        self._carrier = carrier
        self._session_token = token
        self._carrier_mode = announced_mode
        self._next_stream_id = 1
        log.info(
            "[web-tunnel] web session established via %s "
            "(mode=%s, batch_limit=%d)",
            self._origin,
            announced_mode,
            page.batch_limit,
        )
