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

Формат референсной страницы (tproxy-server internal/bridge/page.go):

    const relayOrigin="https://H",bootstrap="<token>",carrierMode="<mode>";

Telemt рендерит совместимую страницу с теми же эндпоинтами; парсер сделан
терпимым к регистру и разделителям (``=``/``:``), но строгим к формату
значений.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .http_api import BootstrapRejected, WebApi

DEFAULT_BATCH_LIMIT = 2 * 1024 * 1024
MAX_BATCH_LIMIT = 2 * 1024 * 1024  # потолок desktop-клиента (loopback fallback)

CARRIER_MODES = frozenset(
    {"https", "https-lanes", "websocket", "websocket-lanes"}
)

_TOKEN_RE = re.compile(
    r"""bootstrap["']?\s*[:=]\s*["']([A-Za-z0-9_-]{43})["']""", re.IGNORECASE
)
_CARRIER_MODE_RE = re.compile(
    r"""carrier[a-z_-]{0,3}mode["']?\s*[:=]\s*["']([a-z-]+)["']""",
    re.IGNORECASE,
)
_BATCH_LIMIT_RE = re.compile(
    r"""batch[a-z_-]{0,3}limit["']?\s*[:=]\s*(\d{1,12})""", re.IGNORECASE
)


@dataclass(frozen=True)
class BridgePage:
    """Параметры, извлечённые из bridge-страницы."""

    token: str  # одноразовый bearer для POST /api/v1/session
    carrier_mode: str
    batch_limit: int


def parse_bridge_page(html: str) -> BridgePage:
    """Извлекает bootstrap/carrier-mode/batch-limit из HTML страницы.

    Raises:
        BootstrapRejected: страница не содержит корректного токена или
            объявляет неизвестный carrier-режим.
    """
    token_match = _TOKEN_RE.search(html)
    if token_match is None:
        raise BootstrapRejected(
            "bridge page does not contain a valid bootstrap token "
            "(wrong capability or incompatible relay?)"
        )
    mode_match = _CARRIER_MODE_RE.search(html)
    if mode_match is None:
        raise BootstrapRejected("bridge page does not declare a carrier mode")
    carrier_mode = mode_match.group(1).lower()
    if carrier_mode not in CARRIER_MODES:
        raise BootstrapRejected(
            f"bridge page announces unknown carrier mode {carrier_mode!r}"
        )

    batch_limit = DEFAULT_BATCH_LIMIT
    limit_match = _BATCH_LIMIT_RE.search(html)
    if limit_match is not None:
        batch_limit = min(int(limit_match.group(1)), MAX_BATCH_LIMIT)
    batch_limit = max(batch_limit, 64 * 1024)

    return BridgePage(
        token=token_match.group(1),
        carrier_mode=carrier_mode,
        batch_limit=batch_limit,
    )


async def fetch_bridge_page(api: WebApi, capability: str) -> BridgePage:
    """Загружает bridge-страницу и разбирает её.

    Raises:
        BootstrapRejected: не-200 ответ или нераспознанная страница.
    """
    resp = await api.get_bridge_page(capability)
    if resp.status != 200 or not resp.body:
        raise BootstrapRejected(
            f"bridge page request failed: HTTP {resp.status}"
        )
    html = resp.body.decode("utf-8", errors="replace")
    return parse_bridge_page(html)
