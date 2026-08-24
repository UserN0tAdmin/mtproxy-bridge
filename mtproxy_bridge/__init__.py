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

"""
Local MTProto Proxy bridge.

Starts a SOCKS5 server on 127.0.0.1:<port> and tunnels bytes between the
client (Kurigram) and Telegram via an MTProto proxy (FakeTLS or obfuscated2).

Transport framing is determined by the secret type (mirrors TDLib
``ObfuscatedTransport::init`` / ``ProxySecret``):

   - 0xEE + 16 bytes + domain → FakeTLS + padded        (0xDDDDDDDD)
   - 0xDD + 16 bytes          → obfuscated2 + padded    (0xDDDDDDDD)
   - bare 16 bytes            → obfuscated2 + abridged  (0xEF)

The bridge does NOT translate framing: the client must use the transport
matching the secret (``TCPIntermediatePadded`` for ee/dd, ``TCPAbridged`` for
bare 16-byte secrets). After the handshake, bytes are relayed end-to-end as-is.
"""

from __future__ import annotations

__version__ = "0.3.2"

from .check import CheckResult, StageResult, check_link, check_link_sync
from .config import BridgeConfig
from .links import (
    ProxyLink,
    WebProxyLink,
    is_mtproto_link,
    is_web_proxy_link,
    needs_padded_transport,
    parse_secret,
    parse_tg_link,
    parse_web_link,
)
from .server import start_local_bridge, stop_all_bridges

__all__ = [
    "BridgeConfig",
    "CheckResult",
    "ProxyLink",
    "StageResult",
    "WebProxyLink",
    "__version__",
    "check_link",
    "check_link_sync",
    "is_mtproto_link",
    "is_web_proxy_link",
    "needs_padded_transport",
    "parse_secret",
    "parse_tg_link",
    "parse_web_link",
    "start_local_bridge",
    "stop_all_bridges",
]
