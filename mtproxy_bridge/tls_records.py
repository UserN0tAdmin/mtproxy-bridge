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

"""Обёртка/распаковка TLS Application Data records (FakeTLS-режим)."""

from __future__ import annotations

import struct

from .utils import _hex, log

# ============================================================================
# TLS Application Data — запись
# ============================================================================

_CLIENT_PREFIX = b"\x14\x03\x03\x00\x01\x01"  # ChangeCipherSpec record
_CLIENT_HEADER = b"\x17\x03\x03"  # ApplicationData record header
_MAX_TLS_PACKET_LENGTH = 2878  # td/mtproto/TcpTransport.h:162


class TLSRecordWriter:
    """Обёртка байт в TLS Application Data records.

    При ``send_ccs=True`` (по умолчанию) отправляет TDLib ``first_prefix``
    перед первой записью, как TDLib (``ObfuscatedTransport::do_write_tls``,
    td/mtproto/TcpTransport.cpp:206-210: ``Slice first_prefix("\x14\x03\x03\x00\x01\x01")``).
    Opt-out через ``--no-ccs`` для прокси, не требующих CCS.
    """

    def __init__(self, send_ccs: bool = True) -> None:
        self._prefix_sent = False
        self._send_ccs = send_ccs

    def wrap(self, prefix: bytes, data: bytes) -> bytes:
        """Упаковывает ``prefix`` + ``data`` в TLS Application Data records.

        ``prefix`` — необязательные служебные байты (например, остаток
        заголовка obfuscated2), которые приклеиваются к началу ``data`` в
        первой TLS-записи. ``data`` дробится на куски не более
        ``_MAX_TLS_PACKET_LENGTH`` байт.

        Returns:
            Готовые к отправке байты (CCS + один или несколько AppData records).
        """
        out = bytearray()

        if self._send_ccs and prefix and not self._prefix_sent:
            out += _CLIENT_PREFIX
            self._prefix_sent = True
            log.debug("  [tls-write] CCS prefix sent (6 bytes)")

        if not data:
            if prefix:
                record = prefix
                out += _CLIENT_HEADER + struct.pack(">H", len(record)) + record
                log.debug(
                    f"  [tls-write] AppData record: prefix={len(prefix)} bytes "
                    f"(no data)"
                )
            return bytes(out)

        buf = data
        cur_prefix = prefix
        first_record = True
        while buf:
            if cur_prefix:
                write_size = min(_MAX_TLS_PACKET_LENGTH - len(cur_prefix), len(buf))
                record = cur_prefix + buf[:write_size]
                buf = buf[write_size:]
                cur_prefix = b""
            else:
                write_size = min(_MAX_TLS_PACKET_LENGTH, len(buf))
                record = buf[:write_size]
                buf = buf[write_size:]

            out += _CLIENT_HEADER + struct.pack(">H", len(record)) + record

            if first_record:
                log.debug(
                    f"  [tls-write] AppData record #1: prefix={len(prefix)} + "
                    f"data={write_size} = {len(record)} bytes"
                )
                first_record = False
            else:
                log.debug(f"  [tls-write] AppData record: data={write_size} bytes")

        return bytes(out)


# ============================================================================
# TLS Application Data — чтение
# ============================================================================

_SERVER_HEADER = b"\x17\x03\x03"


class TLSRecordUnwrapper:
    """Инкрементальный парсер TLS Application Data records.

    Принимает произвольные порции байт через :meth:`feed`, разбирает TLS
    record framing (5-байтный header + payload) и возвращает «чистый»
    payload AppData records. Alert / неожиданный CCS / неизвестные типы
    рвут соединение.
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self._total_in = 0
        self._total_out = 0

    def feed(self, data: bytes) -> bytes:
        """Добавляет ``data`` во внутренний буфер и возвращает накопленный payload.

        Накопленные неполные record'ы остаются в буфере до следующих вызовов.

        Raises:
            ConnectionError: получен TLS Alert, неожиданный post-hello CCS
                или record неизвестного типа.
        """
        self._buf += data
        self._total_in += len(data)

        buf = self._buf
        pos = 0
        n = len(buf)
        out = bytearray()

        while n - pos >= 5:
            rtype = buf[pos]
            length = struct.unpack_from(">H", buf, pos + 3)[0]

            if n - pos < 5 + length:
                log.debug(
                    f"  [tls-read] Buffer {n - pos} < need {5 + length}, "
                    f"waiting for more data"
                )
                break

            if rtype == 0x17:
                if buf[pos + 1] != 0x03 or buf[pos + 2] != 0x03:
                    version = bytes(buf[pos + 1 : pos + 3])
                    log.error(
                        f"  [tls-read] Invalid TLS record version: "
                        f"{version.hex()} (expected 0303)"
                    )
                    raise ConnectionError(
                        f"Invalid TLS record version: {version.hex()}"
                    )
                out += buf[pos + 5 : pos + 5 + length]
            elif rtype == 0x15:
                payload = bytes(buf[pos + 5 : pos + 5 + length])
                log.error(f"  [tls-read] TLS Alert received: {_hex(payload)}")
                raise ConnectionError(f"TLS Alert received from proxy: {payload.hex()}")
            elif rtype == 0x14:
                log.error("  [tls-read] Unexpected post-hello CCS record")
                raise ConnectionError("Unexpected post-hello CCS record")
            else:
                log.error(f"  [tls-read] Unknown record type: 0x{rtype:02x}")
                raise ConnectionError(f"Unknown TLS record type: 0x{rtype:02x}")

            pos += 5 + length

        if pos:
            del self._buf[:pos]

        self._total_out += len(out)
        if out:
            log.debug(
                f"  [tls-read] Extracted {len(out)} bytes of AppData "
                f"(totals: in={self._total_in}, out={self._total_out})"
            )
        return bytes(out)
