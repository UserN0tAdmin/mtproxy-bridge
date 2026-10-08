#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Тесты obfuscated2: init-пакет, ключи AES-CTR, транспортные теги.

Серверная половина (``direct_fakes.ServerObfuscated2``) написана независимо
от моста, поэтому round-trip здесь — настоящая проверка совместимости, а не
сравнение кода с самим собой.
"""

from __future__ import annotations

import struct

import pytest
from direct_fakes import SECRET, ServerObfuscated2

from mtproxy_bridge import obfuscated2
from mtproxy_bridge.obfuscated2 import (
    TAG_ABRIDGED,
    TAG_PADDED_INTERMEDIATE,
    _generate_init,
    build_obfuscated2_header,
    detect_client_transport_tag,
)

_GOOD_INIT = b"\x01\x02\x03\x04\x05\x06\x07\x08" + bytes(range(8, 64))


class TestTags:
    def test_tag_values(self):
        assert TAG_ABRIDGED == b"\xef\xef\xef\xef"
        assert TAG_PADDED_INTERMEDIATE == b"\xdd\xdd\xdd\xdd"


# ============================================================================
# Заголовок и ключи
# ============================================================================


class TestHeaderRoundtrip:
    @pytest.mark.parametrize(
        "tag", [TAG_ABRIDGED, TAG_PADDED_INTERMEDIATE], ids=["abridged", "padded"]
    )
    @pytest.mark.parametrize("dc", [1, 2, 5, 10001, -203, 0, 32767, -32768])
    def test_server_reads_tag_and_dc(self, tag, dc):
        keys = build_obfuscated2_header(tag, dc, SECRET)
        assert len(keys.header) == 64
        server = ServerObfuscated2(keys.header, SECRET)
        assert server.tag == tag
        assert server.dc == dc

    def test_client_to_server_stream_continues_after_header(self):
        keys = build_obfuscated2_header(TAG_ABRIDGED, 2, SECRET)
        server = ServerObfuscated2(keys.header, SECRET)
        # Заголовок уже «съел» 64 байта keystream'а на обеих сторонах.
        first, second = b"hello, telegram", b"x" * 1000
        assert server.decrypt(keys.encryptor.update(first)) == first
        assert server.decrypt(keys.encryptor.update(second)) == second

    def test_server_to_client_stream(self):
        keys = build_obfuscated2_header(TAG_PADDED_INTERMEDIATE, 4, SECRET)
        server = ServerObfuscated2(keys.header, SECRET)
        payload = bytes(range(256)) * 20
        assert keys.decryptor.update(server.encrypt(payload)) == payload

    def test_directions_use_different_keystreams(self):
        keys = build_obfuscated2_header(TAG_ABRIDGED, 2, SECRET)
        zeros = bytes(64)
        assert keys.encryptor.update(zeros) != keys.decryptor.update(zeros)

    def test_without_secret_mixing(self):
        keys = build_obfuscated2_header(TAG_ABRIDGED, 2, None)
        server = ServerObfuscated2(keys.header, None)
        assert (server.tag, server.dc) == (TAG_ABRIDGED, 2)
        assert server.decrypt(keys.encryptor.update(b"plain")) == b"plain"

    def test_wrong_secret_cannot_read_header(self):
        keys = build_obfuscated2_header(TAG_ABRIDGED, 2, SECRET)
        other = ServerObfuscated2(keys.header, bytes(16))
        # Вероятность случайного совпадения 4 байт тега — 2**-32.
        assert other.tag != TAG_ABRIDGED

    def test_secret_is_actually_mixed_into_keys(self):
        # Один и тот же init с секретом и без него даёт разные ключи.
        init = _GOOD_INIT
        with_secret = ServerObfuscated2(init, SECRET)
        without = ServerObfuscated2(init, None)
        assert with_secret.decrypt(bytes(32)) != without.decrypt(bytes(32))

    def test_only_first_16_bytes_of_secret_are_used(self):
        # Секрет подмешивается как secret[:16]: хвост игнорируется.
        keys = build_obfuscated2_header(TAG_ABRIDGED, 2, SECRET + b"tail")
        server = ServerObfuscated2(keys.header, SECRET)
        assert server.tag == TAG_ABRIDGED

    def test_headers_are_random(self):
        headers = {
            build_obfuscated2_header(TAG_ABRIDGED, 2, SECRET).header for _ in range(20)
        }
        assert len(headers) == 20

    @pytest.mark.parametrize("dc", [32768, -32769, 100000])
    def test_dc_out_of_int16_range_rejected(self, dc):
        with pytest.raises(ValueError, match="int16"):
            build_obfuscated2_header(TAG_ABRIDGED, dc, SECRET)


# ============================================================================
# Генерация init (isGoodStartNonce)
# ============================================================================


def _script_token_bytes(monkeypatch, blobs):
    """Подменяет secrets.token_bytes последовательностью заранее заданных блобов."""
    queue = list(blobs)
    calls = []

    def fake(n):
        calls.append(n)
        return queue.pop(0)

    monkeypatch.setattr(obfuscated2.secrets, "token_bytes", fake)
    return calls


class TestGenerateInit:
    def test_random_inits_satisfy_constraints(self):
        for _ in range(500):
            init = _generate_init()
            assert len(init) == 64
            assert init[0] != 0xEF
            assert struct.unpack("<I", init[:4])[0] not in obfuscated2._RESERVED_FIRST4
            assert struct.unpack("<I", init[4:8])[0] != 0

    def test_reserved_set_is_the_tdlib_one(self):
        expected = {
            int.from_bytes(b"HEAD", "little"),
            int.from_bytes(b"POST", "little"),
            int.from_bytes(b"GET ", "little"),
            int.from_bytes(b"OPTI", "little"),
            0x02010316,  # первые байты TLS ClientHello
            0xDDDDDDDD,
            0xEEEEEEEE,
        }
        assert obfuscated2._RESERVED_FIRST4 == expected

    @pytest.mark.parametrize(
        "first4",
        sorted(obfuscated2._RESERVED_FIRST4),
        ids=lambda v: f"{v:#010x}",
    )
    def test_reserved_first_word_is_rejected(self, monkeypatch, first4):
        bad = struct.pack("<I", first4) + b"\x01" * 60
        calls = _script_token_bytes(monkeypatch, [bad, _GOOD_INIT])
        assert _generate_init() == _GOOD_INIT
        assert calls == [64, 64]

    def test_first_byte_ef_is_rejected(self, monkeypatch):
        bad = b"\xef" + b"\x01" * 63
        calls = _script_token_bytes(monkeypatch, [bad, _GOOD_INIT])
        assert _generate_init() == _GOOD_INIT
        assert len(calls) == 2

    def test_zero_second_word_is_rejected(self, monkeypatch):
        bad = b"\x01\x02\x03\x04" + bytes(4) + b"\x01" * 56
        calls = _script_token_bytes(monkeypatch, [bad, _GOOD_INIT])
        assert _generate_init() == _GOOD_INIT
        assert len(calls) == 2

    def test_header_building_survives_rejected_candidates(self, monkeypatch):
        bad = [b"\xef" + b"\x01" * 63, b"GET " + b"\x01" * 60]
        _script_token_bytes(monkeypatch, bad + [_GOOD_INIT])
        keys = build_obfuscated2_header(TAG_PADDED_INTERMEDIATE, 3, SECRET)
        server = ServerObfuscated2(keys.header, SECRET)
        assert (server.tag, server.dc) == (TAG_PADDED_INTERMEDIATE, 3)
        # Первые 56 байт заголовка — открытый init (без шифрования).
        assert keys.header[:56] == _GOOD_INIT[:56]


# ============================================================================
# Определение транспорта по первым байтам клиента
# ============================================================================


class TestDetectClientTransportTag:
    def test_padded_intermediate_consumes_four_bytes(self):
        assert detect_client_transport_tag(b"\xdd\xdd\xdd\xdd") == (
            TAG_PADDED_INTERMEDIATE,
            4,
        )

    def test_abridged_consumes_one_byte(self):
        assert detect_client_transport_tag(b"\xef\x01\x02\x03") == (TAG_ABRIDGED, 1)

    @pytest.mark.parametrize(
        "first",
        [
            b"\xee\xee\xee\xee",  # intermediate без паддинга — не поддерживается
            b"GET ",
            b"\x16\x03\x01\x02",  # TLS
            b"\xdd\xdd\xdd\x00",  # не полный тег DD
            b"\x00\x00\x00\x00",
            b"",
        ],
        ids=["intermediate", "http-get", "tls", "partial-dd", "zeros", "empty"],
    )
    def test_unsupported_transport_raises(self, first):
        with pytest.raises(ValueError, match="Unsupported transport"):
            detect_client_transport_tag(first)
