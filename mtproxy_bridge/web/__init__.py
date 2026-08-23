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

"""WEB Proxy (tg://webproxy): клиентская сторона carrier-протокола v1.

Публичная точка входа — :class:`WebTunnel` (мультиплексированная сессия
с потоками :class:`WebStream`); детали протокола живут в субмодулях.
"""

from __future__ import annotations

from .bootstrap import BridgePage, fetch_bridge_page, parse_bridge_page
from .carriers import CarrierFailure, build_carrier
from .http_api import WebApi, WebApiError
from .tunnel import TunnelClosed, WebStream, WebTunnel

__all__ = [
    "BridgePage",
    "CarrierFailure",
    "TunnelClosed",
    "WebApi",
    "WebApiError",
    "WebStream",
    "WebTunnel",
    "build_carrier",
    "fetch_bridge_page",
    "parse_bridge_page",
]

