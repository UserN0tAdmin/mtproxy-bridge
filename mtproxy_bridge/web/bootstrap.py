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

"""Bridge-страница: одноразовый bootstrap-токен и параметры carrier'а.

Релей выдаёт bootstrap только на точный ``GET /?bridge=<capability>``;
токен (2 минуты жизни) встроен в JavaScript страницы. Браузерный bridge
исполняет этот JS — мост вместо этого извлекает значения регулярками.

Поддерживаемые форматы страницы:

1. Классический tproxy-server (``internal/bridge/page.go``)::

       const relayOrigin="https://H",bootstrap="<token>",carrierMode="<mode>";

   Свежий tproxy-server с base path отдаёт ``relayBase="https://H/P/"``
   вместо ``relayOrigin``; парсер этих значений не читает — origin
   (вместе с путём) берётся из ссылки.

2. Старый Telemt (фиксированный carrier)::

       const relayOrigin='https://H',bootstrap='<token>',carrier='<mode>';

3. Новый Telemt / tproxy с carrier negotiation (``carrierCapabilities``)::

       const bootstrap="<token>";
       const relayOrigin='https://H',carrierCapabilities='https,https-lanes,...';
       const negotiationEnabled=false,...;
       let ... carrier='';

   При отсутствии фиксированного ``carrierMode``/``carrier`` парсер берёт
   список из ``carrierCapabilities`` и выбирает предпочтительный режим
   в порядке: websocket-lanes → websocket → https-lanes → https.
   Сервер при ``negotiationEnabled=false`` сам назначает режим в
   ``X-Carrier-Mode`` ответа ``POST /api/v1/session``; клиент принимает
   любой режим из объявленных capabilities.

4. mtproto.zig (``src/web/page.zig``, ``renderSessionBridge``) — страница
   без ``bootstrap``/``carrierMode``: токен WebSocket-carrier'а лежит прямо
   в метаданных, REST-сессии (``/api/v1/session``, ``/up``, ``/down``) нет::

       <meta name="tproxy-token" content="<43 символа base64url>">
       <meta name="tproxy-ws-path" content="/api/v1/socket">

   Режим ``native-websocket``: одноразовый токен (TTL 120 с) уходит в
   subprotocol ``tproxy-v1.<token>``, HELLO/WELCOME идут уже внутри
   сокета. Проверяется ПЕРВЫМ — это самый специфичный признак.

Парсер терпим к регистру, разделителям (``=``/``:``) и кавычкам, но строг
к формату значений; строки вида ``carrier==='websocket'`` (сравнение)
не матчатся из-за двойного ``=`` перед значением.
"""

from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass

from .http_api import BootstrapRejected, WebApi

DEFAULT_BATCH_LIMIT = 2 * 1024 * 1024
MAX_BATCH_LIMIT = 2 * 1024 * 1024  # потолок desktop-клиента (loopback fallback)

CARRIER_MODES = frozenset({"https", "https-lanes", "websocket", "websocket-lanes"})

# mtproto.zig: один WebSocket, токен берётся прямо из страницы (без REST-сессии).
NATIVE_WS_MODE = "native-websocket"
# Релей отбрасывает WS-сообщение крупнее 1 МиБ + 8 байт (ws.max_message), а
# общий потолок моста — 2 МиБ. Берём половину лимита релея с запасом.
NATIVE_BATCH_LIMIT = 512 * 1024

# Предпочтительный порядок при разборе carrierCapabilities (новый формат).
PREFERRED_CARRIER_ORDER = (
    "websocket-lanes",
    "websocket",
    "https-lanes",
    "https",
)

_TOKEN_RE = re.compile(
    r"""bootstrap["']?\s*[:=]\s*["']([A-Za-z0-9_-]{43})["']""", re.IGNORECASE
)
# Фиксированный режим: carrierMode='…' / carrier='…' (не пустая строка).
# Не матчит carrier='' и сравнения carrier==='…'.
_CARRIER_MODE_RE = re.compile(
    r"""carrier(?:[_-]?mode)?["']?\s*[:=]\s*["']([a-z-]+)["']""",
    re.IGNORECASE,
)
_CAPABILITIES_RE = re.compile(
    r"""carrierCapabilities["']?\s*[:=]\s*["']([^"']+)["']""",
    re.IGNORECASE,
)
_BATCH_LIMIT_RE = re.compile(
    r"""batch[a-z_-]{0,3}limit["']?\s*[:=]\s*(\d{1,12})""", re.IGNORECASE
)
# mtproto.zig: <meta name="tproxy-token" content="..."> / tproxy-ws-path.
# Значение ws-path HTML-экранировано (appendHtmlAttribute), поэтому кавычки
# внутри него встречаются только как &quot; и ``[^"]*`` безопасен.
_META_TOKEN_RE = re.compile(
    r"""<meta\s+name\s*=\s*["']tproxy-token["']\s+content\s*=\s*["']([^"']*)["']""",
    re.IGNORECASE,
)
_META_WS_PATH_RE = re.compile(
    r'''<meta\s+name\s*=\s*["']tproxy-ws-path["']\s+content\s*=\s*"([^"]*)"''',
    re.IGNORECASE,
)
_TOKEN_VALUE_RE = re.compile(r"[A-Za-z0-9_-]{43}")


@dataclass(frozen=True)
class BridgePage:
    """Параметры, извлечённые из bridge-страницы."""

    token: str  # одноразовый bearer для POST /api/v1/session
    carrier_mode: str  # предпочтительный / объявленный режим
    batch_limit: int
    # Допустимые режимы с точки зрения страницы. Для старого формата —
    # один элемент; для carrierCapabilities — все распознанные режимы.
    # Сервер может выбрать любой из них (см. X-Carrier-Mode).
    allowed_modes: frozenset[str] = frozenset()
    # Только для native-websocket: same-origin путь WebSocket-эндпоинта.
    ws_path: str = ""


def _select_preferred_mode(available: set[str]) -> str:
    """Выбирает режим по PREFERRED_CARRIER_ORDER из пересечения с available."""
    for mode in PREFERRED_CARRIER_ORDER:
        if mode in available:
            return mode
    # available уже отфильтрован по CARRIER_MODES, но на всякий случай.
    raise BootstrapRejected(
        "bridge page declares no supported carrier modes in capabilities"
    )


def _parse_capabilities(raw: str) -> set[str]:
    """Разбирает CSV carrierCapabilities → множество известных режимов."""
    modes: set[str] = set()
    for part in raw.split(","):
        mode = part.strip().lower()
        if mode in CARRIER_MODES:
            modes.add(mode)
    return modes


def _validate_ws_path(path: str) -> str:
    """Те же правила, что ``validateWsPath`` релея: same-origin абсолютный путь."""
    if (
        not path.startswith("/")
        or path.startswith("//")
        or any(ch in path for ch in "?#\\")
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path)
    ):
        raise BootstrapRejected(
            f"bridge page announces unusable websocket path {path!r}"
        )
    return path


def _parse_native_page(html: str) -> BridgePage | None:
    """Разбирает страницу mtproto.zig; ``None`` — это не она."""
    token_match = _META_TOKEN_RE.search(html)
    if token_match is None:
        return None
    token = token_match.group(1)
    if _TOKEN_VALUE_RE.fullmatch(token) is None:
        raise BootstrapRejected("bridge page carries a malformed tproxy-token")
    path_match = _META_WS_PATH_RE.search(html)
    if path_match is None:
        raise BootstrapRejected("bridge page has tproxy-token but no tproxy-ws-path")
    ws_path = _validate_ws_path(_html.unescape(path_match.group(1)))
    return BridgePage(
        token=token,
        carrier_mode=NATIVE_WS_MODE,
        batch_limit=NATIVE_BATCH_LIMIT,
        allowed_modes=frozenset({NATIVE_WS_MODE}),
        ws_path=ws_path,
    )


def parse_bridge_page(html: str) -> BridgePage:
    """Извлекает bootstrap/carrier-mode/batch-limit из HTML страницы.

    Raises:
        BootstrapRejected: страница не содержит корректного токена или
            не объявляет ни фиксированный carrier-режим, ни capabilities.
    """
    native = _parse_native_page(html)
    if native is not None:
        return native

    token_match = _TOKEN_RE.search(html)
    if token_match is None:
        raise BootstrapRejected(
            "bridge page does not contain a valid bootstrap token "
            "(wrong capability or incompatible relay?)"
        )

    mode_match = _CARRIER_MODE_RE.search(html)
    capabilities_match = _CAPABILITIES_RE.search(html)

    if mode_match is not None:
        carrier_mode = mode_match.group(1).lower()
        if carrier_mode not in CARRIER_MODES:
            raise BootstrapRejected(
                f"bridge page announces unknown carrier mode {carrier_mode!r}"
            )
        allowed = frozenset({carrier_mode})
        if capabilities_match is not None:
            caps = _parse_capabilities(capabilities_match.group(1))
            if caps:
                allowed = frozenset(caps | {carrier_mode})
    elif capabilities_match is not None:
        caps = _parse_capabilities(capabilities_match.group(1))
        if not caps:
            raise BootstrapRejected(
                "bridge page carrierCapabilities contain no known modes"
            )
        carrier_mode = _select_preferred_mode(caps)
        allowed = frozenset(caps)
    else:
        raise BootstrapRejected("bridge page does not declare a carrier mode")

    batch_limit = DEFAULT_BATCH_LIMIT
    limit_match = _BATCH_LIMIT_RE.search(html)
    if limit_match is not None:
        batch_limit = min(int(limit_match.group(1)), MAX_BATCH_LIMIT)
    batch_limit = max(batch_limit, 64 * 1024)

    return BridgePage(
        token=token_match.group(1),
        carrier_mode=carrier_mode,
        batch_limit=batch_limit,
        allowed_modes=allowed,
    )


async def fetch_bridge_page(api: WebApi, capability: str) -> BridgePage:
    """Загружает bridge-страницу и разбирает её.

    Raises:
        BootstrapRejected: не-200 ответ или нераспознанная страница.
    """
    resp = await api.get_bridge_page(capability)
    if resp.status != 200 or not resp.body:
        hint = ""
        if resp.status == 404:
            # И mtproto.zig, и tproxy-server отвечают на чужую capability
            # обычной страницей-прикрытием/404, а не явной ошибкой.
            hint = (
                " (capability not recognised: wrong secret/host, or WEB relay disabled)"
            )
        raise BootstrapRejected(f"bridge page request failed: HTTP {resp.status}{hint}")
    html = resp.body.decode("utf-8", errors="replace")
    return parse_bridge_page(html)
