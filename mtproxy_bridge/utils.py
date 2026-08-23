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

"""Вспомогательные утилиты: логгер, hex-срезы, TCP-тюнинг сокетов."""

from __future__ import annotations

import asyncio
import logging
import socket

# ============================================================================
# Логирование
# ============================================================================

log = logging.getLogger("mtproxy_bridge")


def _hex(data: bytes, limit: int = 64) -> str:
    """Короткое hex-представление для логов; длинные буферы усекаются."""
    if len(data) <= limit:
        return data.hex()
    return data[:limit].hex() + f"...({len(data)} bytes)"


# ============================================================================
# TCP-тюнинг upstream-сокета (TCP_NODELAY + keepalive)
# ============================================================================

_TCP_KEEPALIVE_TIME = 10  # секунд до первого keepalive-проба
_TCP_KEEPALIVE_INTERVAL = 5  # секунд между пробами
_TCP_KEEPALIVE_PROBES = 3  # проб до разрыва


def _apply_tcp_tuning(writer: asyncio.StreamWriter, peer_label: object) -> None:
    """Включает TCP_NODELAY + keepalive на сокете writer'а (best-effort).

    TCP_NODELAY критичен для мелких MTProto-фреймов (ack/ping/rpc_result) —
    иначе Nagle коагулирует их ~40ms. Keepalive защищает от зависших
    NAT-сессий. Недоступность опции на конкретной платформе логируется, но
    не рвёт соединение.
    """
    sock = writer.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError as e:
        log.warning(f"[client {peer_label}] TCP_NODELAY not set: {e}")
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError as e:
        log.debug(f"[client {peer_label}] SO_KEEPALIVE not set: {e}")
        return
    for opt_name, value in (
        ("TCP_KEEPIDLE", _TCP_KEEPALIVE_TIME),
        ("TCP_KEEPINTVL", _TCP_KEEPALIVE_INTERVAL),
        ("TCP_KEEPCNT", _TCP_KEEPALIVE_PROBES),
    ):
        opt = getattr(socket, opt_name, None)
        if opt is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, opt, value)
        except OSError as e:
            log.debug(f"[client {peer_label}] {opt_name}={value} not set: {e}")
