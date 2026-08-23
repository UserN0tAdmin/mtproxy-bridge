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

"""Конфигурация моста и константы таймаутов."""

from __future__ import annotations

from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from .links import WebProxyLink


class BridgeConfig(NamedTuple):
    """Конфигурация моста: listen + upstream + опции FakeTLS/obfuscated2.

    Два режима туннеля:

    - direct (по умолчанию): TCP до ``upstream_host:upstream_port``,
      при ee-секрете — FakeTLS;
    - WEB (``web_link`` не None): мультиплексированная сессия через
      WEB-релей (см. :mod:`mtproxy_bridge.web`); поля upstream/FakeTLS
      не используются, ``expected_tag`` выводится из типа секрета.
    """

    listen_host: str
    listen_port: int
    upstream_host: str
    upstream_port: int
    secret_key: bytes
    domain: str
    is_fake_tls: bool
    expected_tag: bytes
    dc_id_override: int = 0
    send_ccs: bool = True
    use_block_m: bool = True
    use_block_e: bool = True
    # --- WEB-режим (tg://webproxy) ---
    web_link: WebProxyLink | None = None
    # Override origin для WebTunnel (http://127.0.0.1:port в тестах);
    # None → https://<host> из ссылки.
    web_origin: str | None = None


# ============================================================================
# Activity timeout для relay
# ============================================================================

# Хоть один байт за этот интервал, иначе оба направления разрываются.
# Защита от зависших клиентов/upstream и утечки FD при idle-коннектах.
ACTIVITY_TIMEOUT_SECS = 1800  # 30 минут

# Таймаут на каждый readexactly внутри SOCKS5 handshake (slowloris-защита).
SOCKS5_HANDSHAKE_TIMEOUT_SECS = 15.0

# Таймаут на TCP-connect к upstream (молчаливый drop без RST иначе вешает
# корутину на OS-level timeout ~127 c).
UPSTREAM_CONNECT_TIMEOUT_SECS = 5.0

# Грейс-период для уже открытых соединений при остановке сервера.
SHUTDOWN_GRACE_SECS = 5.0



