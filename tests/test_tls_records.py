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

"""Тесты TLS-записей FakeTLS: TLSRecordWriter и TLSRecordUnwrapper.

Разбор записей в проверках сделан отдельной простой функцией
(:func:`_split_records`), а не через ``TLSRecordUnwrapper``, чтобы писатель
проверялся независимо от читателя.
"""

from __future__ import annotations

import os
import random
import struct

import pytest

from mtproxy_bridge.tls_records import (
    _CLIENT_PREFIX,
    _MAX_TLS_PACKET_LENGTH,
    TLSRecordUnwrapper,
    TLSRecordWriter,
)

CCS = b"\x14\x03\x03\x00\x01\x01"
HEADER = b"\x17\x03\x03"
MAX = 2878  # td/mtproto/TcpTransport.h


def _split_records(blob: bytes) -> list[tuple[int, bytes, bytes]]:
    """[(type, version, payload), ...]; ValueError на рваном хвосте."""
    out, pos = [], 0
    while pos < len(blob):
        if len(blob) - pos < 5:
            raise ValueError("truncated record header")
        rtype, ver, length = (
            blob[pos],
            blob[pos + 1 : pos + 3],
            struct.unpack_from(">H", blob, pos + 3)[0],
        )
        payload = blob[pos + 5 : pos + 5 + length]
        if len(payload) != length:
            raise ValueError("truncated record payload")
        out.append((rtype, ver, payload))
        pos += 5 + length
    return out


def _app_records(blob: bytes) -> list[bytes]:
    return [p for t, _v, p in _split_records(blob) if t == 0x17]


def _record(payload: bytes, rtype: int = 0x17, version: bytes = b"\x03\x03") -> bytes:
    return bytes([rtype]) + version + struct.pack(">H", len(payload)) + payload


# ============================================================================
# TLSRecordWriter
# ============================================================================


class TestWriter:
    def test_constants(self):
        assert _CLIENT_PREFIX == CCS
        assert _MAX_TLS_PACKET_LENGTH == MAX

    def test_first_wrap_with_prefix_emits_ccs_then_record(self):
        out = TLSRecordWriter().wrap(b"P" * 64, b"data")
        assert out.startswith(CCS)
        records = _split_records(out[len(CCS) :])
        assert records == [(0x17, b"\x03\x03", b"P" * 64 + b"data")]

    def test_ccs_sent_only_once(self):
        writer = TLSRecordWriter()
        first = writer.wrap(b"P" * 64, b"a")
        second = writer.wrap(b"", b"b")
        third = writer.wrap(b"P" * 64, b"c")  # даже с prefix повторно CCS нет
        assert first.startswith(CCS)
        assert second == _record(b"b")
        assert third == _record(b"P" * 64 + b"c")

    def test_send_ccs_false_never_emits_ccs(self):
        out = TLSRecordWriter(send_ccs=False).wrap(b"P" * 64, b"data")
        assert out == _record(b"P" * 64 + b"data")
        assert CCS not in out

    def test_no_prefix_means_no_ccs(self):
        # CCS привязан к первой записи, несущей prefix (заголовок obfuscated2).
        assert TLSRecordWriter().wrap(b"", b"data") == _record(b"data")

    def test_prefix_without_data_is_one_record(self):
        out = TLSRecordWriter().wrap(b"H" * 64, b"")
        assert out == CCS + _record(b"H" * 64)

    def test_empty_everything_is_empty(self):
        assert TLSRecordWriter().wrap(b"", b"") == b""

    @pytest.mark.parametrize(
        "size",
        [1, 100, MAX - 1, MAX, MAX + 1, 2 * MAX, 2 * MAX + 1, 10 * MAX + 7, 100_000],
    )
    def test_chunking_without_prefix(self, size):
        data = os.urandom(size)
        records = _app_records(TLSRecordWriter(send_ccs=False).wrap(b"", data))
        assert all(0 < len(r) <= MAX for r in records)
        assert b"".join(records) == data
        assert len(records) == -(-size // MAX)  # ceil
        # Все записи, кроме последней, заполнены до предела.
        assert all(len(r) == MAX for r in records[:-1])

    @pytest.mark.parametrize(
        "size",
        [0, 1, MAX - 64 - 1, MAX - 64, MAX - 64 + 1, MAX, 5 * MAX, 50_000],
    )
    def test_chunking_with_prefix(self, size):
        prefix, data = os.urandom(64), os.urandom(size)
        out = TLSRecordWriter().wrap(prefix, data)
        assert out.startswith(CCS)
        records = _app_records(out[len(CCS) :])
        assert all(0 < len(r) <= MAX for r in records)
        assert b"".join(records) == prefix + data
        assert records[0].startswith(prefix)  # заголовок — в первой записи
        assert len(records) == -(-(64 + size) // MAX)

    def test_all_records_use_tls12_application_data_header(self):
        out = TLSRecordWriter().wrap(b"P" * 64, os.urandom(9000))
        records = _split_records(out)
        assert records[0][0] == 0x14  # CCS
        assert all((t, v) == (0x17, b"\x03\x03") for t, v, _p in records[1:])


# ============================================================================
# TLSRecordUnwrapper
# ============================================================================


class TestUnwrapper:
    def test_single_record(self):
        assert TLSRecordUnwrapper().feed(_record(b"hello")) == b"hello"

    def test_several_records_in_one_feed(self):
        blob = _record(b"one") + _record(b"two") + _record(b"three")
        assert TLSRecordUnwrapper().feed(blob) == b"onetwothree"

    def test_partial_header_is_buffered(self):
        unwrapper = TLSRecordUnwrapper()
        blob = _record(b"payload")
        assert unwrapper.feed(blob[:3]) == b""
        assert unwrapper.feed(blob[3:5]) == b""  # заголовок целиком, тела нет
        assert unwrapper.feed(blob[5:]) == b"payload"

    def test_partial_body_is_buffered(self):
        unwrapper = TLSRecordUnwrapper()
        blob = _record(b"x" * 100)
        assert unwrapper.feed(blob[:50]) == b""
        assert unwrapper.feed(blob[50:]) == b"x" * 100

    def test_complete_record_followed_by_partial_one(self):
        unwrapper = TLSRecordUnwrapper()
        second = _record(b"second")
        assert unwrapper.feed(_record(b"first") + second[:4]) == b"first"
        assert unwrapper.feed(second[4:]) == b"second"

    def test_byte_by_byte(self):
        payloads = [os.urandom(n) for n in (1, 17, 300, 0, 5)]
        blob = b"".join(_record(p) for p in payloads)
        unwrapper = TLSRecordUnwrapper()
        out = b"".join(unwrapper.feed(blob[i : i + 1]) for i in range(len(blob)))
        assert out == b"".join(payloads)

    def test_random_split_points(self):
        rnd = random.Random(1234)
        payloads = [os.urandom(rnd.randint(0, 5000)) for _ in range(40)]
        blob = b"".join(_record(p) for p in payloads)
        unwrapper, out, pos = TLSRecordUnwrapper(), bytearray(), 0
        while pos < len(blob):
            step = rnd.randint(1, 3000)
            out += unwrapper.feed(blob[pos : pos + step])
            pos += step
        assert bytes(out) == b"".join(payloads)

    def test_empty_application_record_is_allowed(self):
        assert TLSRecordUnwrapper().feed(_record(b"")) == b""

    def test_max_size_record(self):
        payload = os.urandom(65535)
        assert TLSRecordUnwrapper().feed(_record(payload)) == payload

    def test_feed_nothing(self):
        assert TLSRecordUnwrapper().feed(b"") == b""

    def test_alert_raises(self):
        with pytest.raises(ConnectionError, match="TLS Alert"):
            TLSRecordUnwrapper().feed(_record(b"\x02\x28", rtype=0x15))

    def test_post_hello_ccs_raises(self):
        with pytest.raises(ConnectionError, match="CCS"):
            TLSRecordUnwrapper().feed(_record(b"\x01", rtype=0x14))

    @pytest.mark.parametrize("rtype", [0x16, 0x18, 0x00, 0xFF])
    def test_unknown_record_type_raises(self, rtype):
        with pytest.raises(ConnectionError, match="Unknown TLS record type"):
            TLSRecordUnwrapper().feed(_record(b"abc", rtype=rtype))

    @pytest.mark.parametrize("version", [b"\x03\x01", b"\x03\x04", b"\x00\x00"])
    def test_wrong_record_version_raises(self, version):
        with pytest.raises(ConnectionError, match="version"):
            TLSRecordUnwrapper().feed(_record(b"abc", version=version))

    def test_alert_after_normal_record_still_raises(self):
        # Нормальная запись отдаётся, а следующий Alert не проглатывается.
        unwrapper = TLSRecordUnwrapper()
        assert unwrapper.feed(_record(b"ok")) == b"ok"
        with pytest.raises(ConnectionError):
            unwrapper.feed(_record(b"\x02\x28", rtype=0x15))


# ============================================================================
# Писатель ↔ читатель
# ============================================================================


@pytest.mark.parametrize("size", [0, 1, 64, MAX, MAX + 1, 20_000, 300_000])
def test_writer_to_unwrapper_roundtrip(size):
    prefix, data = os.urandom(64), os.urandom(size)
    wire = TLSRecordWriter().wrap(prefix, data)
    assert wire.startswith(CCS)
    # Читатель моста принимает только серверный поток (без клиентского CCS).
    assert TLSRecordUnwrapper().feed(wire[len(CCS) :]) == prefix + data
