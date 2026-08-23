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

"""SOCKS5-handshake локального сервера (no-auth, CONNECT)."""

from __future__ import annotations

import asyncio
import ipaddress
import struct

from .config import SOCKS5_HANDSHAKE_TIMEOUT_SECS


async def _socks5_handshake(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> tuple[str, int]:
    """Проводит SOCKS5 handshake и возвращает (target_host, target_port).

    Поддерживаются: no-auth метод (0x00), CONNECT-команда, ATYP IPv4 /
    domainname / IPv6. VER сверяется в greeting и в request; CMD != CONNECT
    получает reply 0x07 (Command not supported), после чего соединение
    рвётся; прочие отклонения рвут соединение без reply.

    Raises:
        ConnectionError: клиент требует auth, неподдерживаемый ATYP, таймаут.
        asyncio.IncompleteReadError: клиент закрыл соединение до завершения
            handshake.
    """

    async def _rx(n: int, what: str) -> bytes:
        """readexactly с таймаутом; по timeout кидает ConnectionError."""
        try:
            return await asyncio.wait_for(
                reader.readexactly(n), timeout=SOCKS5_HANDSHAKE_TIMEOUT_SECS
            )
        except asyncio.TimeoutError:
            raise ConnectionError(
                f"SOCKS5 handshake timeout reading {what} "
                f"({SOCKS5_HANDSHAKE_TIMEOUT_SECS}s, need {n} bytes)"
            )

    greeting = await _rx(2, "greeting (VER+NMETHODS)")
    if greeting[0] != 0x05:
        raise ValueError(f"Unsupported SOCKS version in greeting: {greeting[0]:#x}")
    nmethods = greeting[1]
    methods = await _rx(nmethods, "methods")

    if 0x00 not in methods:
        writer.write(b"\x05\xff")
        await writer.drain()
        raise ConnectionError(
            "Client requires SOCKS5 authentication, which is not supported"
        )

    writer.write(b"\x05\x00")
    await writer.drain()

    req = await _rx(4, "request (VER+CMD+RSV+ATYP)")
    ver, cmd, _, atyp = req
    if ver != 0x05:
        raise ValueError(f"Unsupported SOCKS version in request: {ver:#x}")
    if cmd != 0x01:  # поддерживается только CONNECT
        writer.write(b"\x05\x07\x00\x01" + b"\x00" * 4 + b"\x00\x00")
        await writer.drain()
        raise ValueError(
            f"Unsupported SOCKS5 CMD={cmd:#x} (only CONNECT/0x01 is supported)"
        )
    if atyp == 0x01:
        addr_bytes = await _rx(4, "IPv4 address")
        host = ".".join(str(b) for b in addr_bytes)
    elif atyp == 0x03:
        length = (await _rx(1, "domain length"))[0]
        host = (await _rx(length, "domain")).decode("ascii")
    elif atyp == 0x04:
        addr_bytes = await _rx(16, "IPv6 address")
        host = str(ipaddress.IPv6Address(addr_bytes))
    else:
        raise ValueError(f"Unsupported ATYP={atyp}")
    port = struct.unpack(">H", await _rx(2, "port"))[0]

    writer.write(b"\x05\x00\x00\x01" + b"\x00" * 4 + b"\x00\x00")
    await writer.drain()
    return host, port
