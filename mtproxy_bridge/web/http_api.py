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

"""HTTP API релея WEB Proxy (``/api/v1/*``) с политикой повторов.

Семантика повторов повторяет референсный bridge (tproxy-server
internal/bridge/page.go, функция ``request``):

- сетевые ошибки — экспоненциальный backoff 250 мс → 5 c с джиттером,
  максимум 9 попыток на запрос;
- ``503 Service Unavailable`` — ожидание из ``Retry-After`` (не больше
  30 c) и байт-в-байт повтор того же запроса; суммарный бюджет 90 c;
- прочие ответы возвращаются как есть — разбор статуса делает вызывающий
  слой (404 от релея всегда означает отказ авторизации/протокола).

Cookies никогда не хранятся и не отправляются: релей отвергает
cookie-bearing API-запросы, а bearer-токены ходят только в заголовках.
"""

from __future__ import annotations

import asyncio
import email.utils
import random
import time
from dataclasses import dataclass

import aiohttp

_ATTEMPT_TIMEOUT_SECS = 90.0  # per-attempt; должен превышать long-poll сервера
_CONNECT_TIMEOUT_SECS = 10.0
_MAX_ATTEMPTS = 9
_RETRY_BUDGET_SECS = 90.0
_BACKOFF_BASE_SECS = 0.25
_BACKOFF_CAP_SECS = 5.0
_RETRY_AFTER_CAP_SECS = 30.0
_WS_MAX_MSG_SIZE = 4 * 1024 * 1024


class WebApiError(Exception):
    """Базовая ошибка обмена с релеем."""


class NetworkError(WebApiError):
    """Релей недостижим после исчерпания попыток."""


class ProtocolViolation(WebApiError):
    """Релей ответил нарушением контракта протокола."""


class BootstrapRejected(WebApiError):
    """Релей отверг capability/bootstrap (404 и т.п.)."""


@dataclass(frozen=True)
class ApiResponse:
    status: int
    headers: aiohttp.CIMultiDict[str]
    body: bytes


@dataclass(frozen=True)
class DownResult:
    """Результат POST /api/v1/down."""

    has_data: bool  # 200 с телом (иначе 204)
    next_cursor: int
    body: bytes
    lane_closed: bool  # X-Lane-Closed: 1


def parse_retry_after(value: str | None) -> float:
    """Разбирает ``Retry-After`` (секунды или HTTP-date), ограничивая сверху."""
    if not value:
        return 0.0
    value = value.strip()
    try:
        seconds = int(value)
    except ValueError:
        parsed = email.utils.parsedate_to_datetime(value)
        if parsed is None:
            return 0.0
        delta = parsed.timestamp() - time.time()
        return max(0.0, min(delta, _RETRY_AFTER_CAP_SECS))
    return max(0.0, min(float(seconds), _RETRY_AFTER_CAP_SECS))


def canonical_uint(value: str) -> int:
    """Строго каноничный десятичный uint (без ведущих нулей и плюсов)."""
    if not value or (len(value) > 1 and value[0] == "0") or value.startswith("+"):
        raise ProtocolViolation(f"non-canonical uint header {value!r}")
    try:
        parsed = int(value)
    except ValueError as e:
        raise ProtocolViolation(f"non-canonical uint header {value!r}") from e
    if str(parsed) != value:
        raise ProtocolViolation(f"non-canonical uint header {value!r}")
    return parsed


class WebApi:
    """Тонкий клиент carrier-API одного релея.

    ``origin`` передаётся явно (в продакшене ``https://<host>``, в тестах
    — http://127.0.0.1:<port>); все пути строятся от него.
    """

    def __init__(self, origin: str) -> None:
        self._origin = origin.rstrip("/")
        self._session: aiohttp.ClientSession | None = None

    @property
    def origin(self) -> str:
        return self._origin

    async def _http(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            jar = aiohttp.DummyCookieJar()
            timeout = aiohttp.ClientTimeout(
                total=None,
                connect=_CONNECT_TIMEOUT_SECS,
                sock_connect=_CONNECT_TIMEOUT_SECS,
                sock_read=_ATTEMPT_TIMEOUT_SECS,
            )
            self._session = aiohttp.ClientSession(
                timeout=timeout, cookie_jar=jar
            )
        return self._session

    async def ws_connect(self, subprotocol: str) -> aiohttp.ClientWebSocketResponse:
        """Открывает WebSocket /api/v1/ws с точным subprotocol.

        Liveness-пинги релея отвечаются автоматически (autoping); текстовые
        сообщения и превышение размера ловятся на чтении.
        """
        session = await self._http()
        url = self._origin + "/api/v1/ws"
        if self._origin.startswith("https://"):
            url = "wss://" + self._origin[len("https://") :] + "/api/v1/ws"
        elif not self._origin.startswith("http://"):
            raise WebApiError(f"unsupported origin {self._origin!r}")
        return await session.ws_connect(
            url,
            protocols=[subprotocol],
            max_msg_size=_WS_MAX_MSG_SIZE,
            autoping=True,
        )

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()

    # ------------------------------------------------------------------
    # Ядро retry-политики

    async def _request(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        data: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
        query: dict[str, str] | None = None,
    ) -> ApiResponse:
        session = await self._http()
        url = self._origin + path
        headers: dict[str, str] = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        if data is not None:
            headers["Content-Type"] = "application/octet-stream"
        if extra_headers:
            headers.update(extra_headers)

        attempt = 0
        delay = _BACKOFF_BASE_SECS
        retry_deadline: float | None = None
        while True:
            try:
                async with session.request(
                    method,
                    url,
                    params=query,
                    data=data,
                    headers=headers or None,
                    allow_redirects=False,
                ) as resp:
                    body = await resp.read()
                    status = resp.status
                    resp_headers = resp.headers
            except asyncio.CancelledError:
                raise
            except (
                aiohttp.ClientError,
                asyncio.TimeoutError,
                ConnectionError,
                OSError,
            ):
                attempt += 1
                if attempt >= _MAX_ATTEMPTS:
                    raise NetworkError(
                        f"{method} {path}: relay unreachable "
                        f"after {_MAX_ATTEMPTS} attempts"
                    )
                wait = delay + random.uniform(0.0, max(delay / 4.0, 0.05))
                await asyncio.sleep(wait)
                delay = min(delay * 2.0, _BACKOFF_CAP_SECS)
                continue

            if status == 503:
                now = time.monotonic()
                if retry_deadline is None:
                    retry_deadline = now + _RETRY_BUDGET_SECS
                if now >= retry_deadline:
                    raise NetworkError(
                        f"{method} {path}: 503 persists beyond retry budget"
                    )
                await asyncio.sleep(parse_retry_after(resp_headers.get("Retry-After")))
                continue
            return ApiResponse(status=status, headers=resp_headers, body=body)

    # ------------------------------------------------------------------
    # Эндпоинты протокола v1

    async def get_bridge_page(self, capability: str) -> ApiResponse:
        """``GET /?bridge=<capability>`` — ровно один query-параметр."""
        return await self._request("GET", "/", query={"bridge": capability})

    async def create_session(
        self, bootstrap_token: str, hello_body: bytes
    ) -> ApiResponse:
        return await self._request(
            "POST", "/api/v1/session", token=bootstrap_token, data=hello_body
        )

    async def delete_session(self, session_token: str) -> ApiResponse:
        return await self._request(
            "DELETE", "/api/v1/session", token=session_token, data=None
        )

    async def up(
        self,
        session_token: str,
        sequence: int,
        body: bytes,
        *,
        lane_id: int | None = None,
    ) -> None:
        """``POST /api/v1/up``; подтверждает 204 + каноничный ``X-Up-Ack``."""
        headers = {"X-Up-Seq": str(sequence)}
        if lane_id is not None:
            headers["X-Lane-ID"] = str(lane_id)
        resp = await self._request(
            "POST",
            "/api/v1/up",
            token=session_token,
            data=body,
            extra_headers=headers,
        )
        if resp.status != 204:
            raise ProtocolViolation(
                f"uplink rejected: HTTP {resp.status} (seq={sequence})"
            )
        ack_raw = resp.headers.get("X-Up-Ack")
        try:
            ack = canonical_uint(ack_raw or "")
        except ProtocolViolation as e:
            raise ProtocolViolation(f"bad X-Up-Ack {ack_raw!r}") from e
        if ack != sequence:
            raise ProtocolViolation(
                f"X-Up-Ack mismatch: expected {sequence}, got {ack}"
            )

    async def down(
        self,
        session_token: str,
        cursor: int,
        *,
        lane_id: int | None = None,
    ) -> DownResult:
        """``POST /api/v1/down`` — long poll; 204 = пусто, 200 = батч."""
        headers = {"X-Down-Cursor": str(cursor)}
        if lane_id is not None:
            headers["X-Lane-ID"] = str(lane_id)
        resp = await self._request(
            "POST",
            "/api/v1/down",
            token=session_token,
            data=None,
            extra_headers=headers,
        )
        next_cursor = canonical_uint(resp.headers.get("X-Down-Cursor") or "")
        lane_closed = resp.headers.get("X-Lane-Closed") == "1"
        if resp.status == 204:
            if resp.body:
                raise ProtocolViolation("204 down poll carried a body")
            return DownResult(False, next_cursor, b"", lane_closed)
        if resp.status != 200:
            raise ProtocolViolation(
                f"downlink rejected: HTTP {resp.status} (cursor={cursor})"
            )
        if not resp.body:
            raise ProtocolViolation("200 down poll without body")
        return DownResult(True, next_cursor, resp.body, lane_closed)
