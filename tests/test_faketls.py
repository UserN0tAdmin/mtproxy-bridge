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

"""Тесты FakeTLS: структура ClientHello и клиентский handshake.

ClientHello разбирается независимым парсером из ``direct_fakes`` и
проверяется так, как это делает сервер MTProxy: digest = HMAC-SHA256(secret,
hello с нулями в слоте), последние 4 байта XOR'ятся с unix-временем.
Handshake гоняется против серверов, отвечающих корректно и по-разному
неправильно (сайт-прикрытие, битый HMAC, рваные записи, тишина).
"""

from __future__ import annotations

import asyncio
import struct
import time

import pytest
from direct_fakes import (  # noqa: F401
    CCS_APPDATA_PREFIX,
    build_server_hello,
    parse_client_hello,
    verify_client_digest,
)

from mtproxy_bridge import faketls
from mtproxy_bridge.faketls import (
    _HELLO_DIGEST_LENGTH,
    _prepare_client_hello,
    _prepare_greases,
    async_faketls_handshake,
)

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
OTHER_KEY = bytes.fromhex("ffeeddccbbaa99887766554433221100")
DOMAIN = b"example.com"

EXPECTED_SUITES = [
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
    0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
]  # fmt: skip

# Все расширения ClientHello кроме GREASE и padding (по TlsHello::get_default).
EXPECTED_EXTENSIONS = {
    0x0000,  # server_name
    0x0005,  # status_request
    0x000A,  # supported_groups
    0x000B,  # ec_point_formats
    0x000D,  # signature_algorithms
    0x0010,  # ALPN
    0x0012,  # signed_certificate_timestamp
    0x0017,  # extended_master_secret
    0x001B,  # compress_certificate
    0x0023,  # session_ticket
    0x002B,  # supported_versions
    0x002D,  # psk_key_exchange_modes
    0x0033,  # key_share
    0x44CD,  # application_settings
    0xFE0D,  # encrypted_client_hello
    0xFF01,  # renegotiation_info
}


def _hello(domain=DOMAIN, key=KEY, m=True, e=True):
    return _prepare_client_hello(domain, key, use_block_m=m, use_block_e=e)


def _is_grease(value: int) -> bool:
    hi, lo = value >> 8, value & 0xFF
    return hi == lo and (lo & 0x0F) == 0x0A


def _key_shares(body: bytes):
    """key_share → [(group, key_bytes), ...]."""
    total = struct.unpack_from(">H", body, 0)[0]
    assert total == len(body) - 2
    out, pos = [], 2
    while pos < len(body):
        group, length = struct.unpack_from(">HH", body, pos)
        out.append((group, body[pos + 4 : pos + 4 + length]))
        pos += 4 + length
    assert pos == len(body)
    return out


def _mlkem_coefficients_ok(blob: bytes) -> bool:
    """1152 байта = 384 пары 12-битных коэффициентов < 3329 (форма ML-KEM-768)."""
    assert len(blob) == 1184
    for i in range(384):
        b0, b1, b2 = blob[i * 3 : i * 3 + 3]
        a = b0 | ((b1 & 0x0F) << 8)
        b = (b1 >> 4) | (b2 << 4)
        if a >= 3329 or b >= 3329:
            return False
    return True


def _esni_payload_len(body: bytes):
    """encrypted_client_hello → длина payload либо None, если блока E нет."""
    fixed = 5 + 1 + 2 + 32  # kdf/aead, config_id, enc_len, enc
    if len(body) == fixed:
        return None
    assert len(body) > fixed
    declared = struct.unpack_from(">H", body, fixed)[0]
    assert declared == len(body) - fixed - 2
    return declared


# ============================================================================
# GREASE
# ============================================================================


def test_greases_have_grease_shape_and_distinct_pairs():
    for _ in range(500):  # хватит, чтобы многократно пройти ветку коллизии пары
        g = _prepare_greases()
        assert len(g) == 8
        assert all((b & 0x0F) == 0x0A for b in g)
        for i in range(0, 8, 2):
            assert g[i] != g[i + 1]


# ============================================================================
# Структура ClientHello
# ============================================================================


class TestClientHelloStructure:
    def test_parses_strictly(self):
        data = _hello().data
        info = parse_client_hello(data)  # ValueError при любом нарушении длин
        assert data[:3] == b"\x16\x03\x01"
        assert info.compression == b"\x00"
        assert len(info.session_id) == 32

    def test_digest_field_is_exposed(self):
        hello = _hello()
        assert hello.digest == hello.data[11:43]
        assert len(hello.digest) == _HELLO_DIGEST_LENGTH

    def test_cipher_suites(self):
        suites = parse_client_hello(_hello().data).cipher_suites
        assert len(suites) == 16
        assert _is_grease(suites[0])
        assert suites[1:] == EXPECTED_SUITES

    def test_extension_set(self):
        info = parse_client_hello(_hello().data)
        types = {t for t, _b in info.extensions if not _is_grease(t)}
        assert types == EXPECTED_EXTENSIONS

    def test_grease_extensions_frame_the_list(self):
        for _ in range(20):
            exts = parse_client_hello(_hello().data).extensions
            first_type, first_body = exts[0]
            assert _is_grease(first_type) and first_body == b""
            tail = [(t, b) for t, b in exts if _is_grease(t)][1:]
            assert len(tail) == 1
            last_type, last_body = tail[0]
            assert last_body == b"\x00"
            assert last_type != first_type
            # GREASE-хвост — последний (при padding — перед ним).
            assert exts[-1][0] in (last_type, 0x0015)

    def test_sni_carries_the_domain(self):
        for domain in (b"example.com", b"a", b"x" * 182):
            assert parse_client_hello(_hello(domain=domain).data).sni == domain.decode()

    def test_supported_versions_offers_tls13(self):
        body = parse_client_hello(_hello().data).ext(0x002B)
        assert body[0] == 6 and len(body) == 7
        assert _is_grease(struct.unpack_from(">H", body, 1)[0])
        assert body[3:] == b"\x03\x04\x03\x03"

    def test_alpn_offers_h2_and_http11(self):
        body = parse_client_hello(_hello().data).ext(0x0010)
        assert body == bytes.fromhex("000c02683208687474702f312e31")

    def test_grease_values_are_consistent_across_the_hello(self):
        for _ in range(20):
            info = parse_client_hello(_hello().data)
            groups = info.ext(0x000A)
            first_group = struct.unpack_from(">H", groups, 2)[0]
            share_group = _key_shares(info.ext(0x0033))[0][0]
            # Одно и то же GREASE-значение в supported_groups и key_share.
            assert _is_grease(first_group)
            assert first_group == share_group
            assert groups[4:] == bytes.fromhex("11ec001d00170018")

    def test_extension_order_is_shuffled_but_content_is_stable(self):
        orders = set()
        for _ in range(40):
            exts = parse_client_hello(_hello().data).extensions
            middle = [t for t, _b in exts if not _is_grease(t) and t != 0x0015]
            assert set(middle) == EXPECTED_EXTENSIONS
            orders.add(tuple(middle))
        assert len(orders) > 1

    def test_hello_is_randomized(self):
        hellos = [_hello() for _ in range(10)]
        assert len({h.digest for h in hellos}) == 10
        assert len({parse_client_hello(h.data).session_id for h in hellos}) == 10
        shares = {
            _key_shares(parse_client_hello(h.data).ext(0x0033))[-1][1] for h in hellos
        }
        assert len(shares) == 10  # X25519-ключ свой в каждом hello


# ============================================================================
# Digest ClientHello (то, что проверяет сервер MTProxy)
# ============================================================================


class TestClientHelloDigest:
    def test_server_side_verification_with_the_right_secret(self):
        ts = verify_client_digest(KEY, _hello().data)
        assert ts is not None
        assert abs(ts - time.time()) < 5

    def test_wrong_secret_fails_verification(self):
        assert verify_client_digest(OTHER_KEY, _hello().data) is None

    def test_tampered_hello_fails_verification(self):
        data = bytearray(_hello().data)
        data[100] ^= 0x01
        assert verify_client_digest(KEY, bytes(data)) is None

    def test_timestamp_is_xored_into_the_last_four_digest_bytes(self, monkeypatch):
        monkeypatch.setattr(faketls.time, "time", lambda: 1_700_000_000.9)
        for m, e in [(True, True), (False, False)]:
            assert verify_client_digest(KEY, _hello(m=m, e=e).data) == 1_700_000_000

    def test_digest_covers_the_domain(self):
        # Подмена SNI после построения ломает digest.
        data = _hello(domain=b"example.com").data
        forged = data.replace(b"example.com", b"example.org")
        assert verify_client_digest(KEY, forged) is None


# ============================================================================
# Блоки M и E, padding
# ============================================================================


class TestBlocks:
    def test_block_m_adds_a_mlkem_shaped_key_share(self):
        for _ in range(10):
            shares = _key_shares(parse_client_hello(_hello(m=True).data).ext(0x0033))
            assert [len(k) for _g, k in shares] == [1, 1216, 32]
            assert _is_grease(shares[0][0])
            assert shares[1][0] == 0x11EC and shares[2][0] == 0x001D
            assert _mlkem_coefficients_ok(shares[1][1][:1184])

    def test_without_block_m_the_key_share_is_small(self):
        shares = _key_shares(parse_client_hello(_hello(m=False).data).ext(0x0033))
        assert [len(k) for _g, k in shares] == [1, 32, 32]
        assert shares[1][0] == 0x11EC and shares[2][0] == 0x001D

    def test_block_e_payload_length_is_one_of_four(self):
        seen = set()
        for _ in range(80):
            body = parse_client_hello(_hello(e=True).data).ext(0xFE0D)
            seen.add(_esni_payload_len(body))
        assert seen <= {144, 176, 208, 240}
        assert len(seen) > 1

    def test_without_block_e_there_is_no_payload(self):
        body = parse_client_hello(_hello(e=False).data).ext(0xFE0D)
        assert _esni_payload_len(body) is None

    def test_small_hello_is_padded_to_512_byte_handshake(self):
        # Без M и E ClientHello короткий: добивается padding-расширением до
        # 512 байт handshake-сообщения (как Chrome), т.е. 517 с заголовком записи.
        data = _hello(m=False, e=False).data
        info = parse_client_hello(data)
        assert len(data) - 5 == 512
        assert info.extensions[-1][0] == 0x0015
        assert set(info.extensions[-1][1]) == {0}

    @pytest.mark.parametrize(("m", "e"), [(True, True), (True, False), (False, True)])
    def test_large_hello_has_no_padding(self, m, e):
        for _ in range(20):
            info = parse_client_hello(_hello(m=m, e=e).data)
            assert info.ext(0x0015) is None

    def test_block_sizes_order(self):
        both = len(_hello(m=True, e=True).data)
        only_m = len(_hello(m=True, e=False).data)
        only_e = len(_hello(m=False, e=True).data)
        neither = len(_hello(m=False, e=False).data)
        assert both > only_m > only_e > neither

    @pytest.mark.parametrize(
        ("m", "e"),
        [(True, True), (True, False), (False, True), (False, False)],
        ids=["M+E", "M", "E", "plain"],
    )
    def test_longest_allowed_domain_fits_the_hello_limit(self, m, e):
        # 182 байта — максимум домена в секрете (ProxySecret::MAX_DOMAIN_LENGTH).
        # Худший случай: самый длинный блок E; прогоняем много раз.
        for _ in range(150):
            data = _hello(domain=b"d" * 182, m=m, e=e).data
            assert len(data) <= faketls._CLIENT_HELLO_LIMIT

    def test_empty_domain_fails_cleanly(self):
        with pytest.raises(ValueError, match="Failed to generate ClientHello"):
            _hello(domain=b"")


# ============================================================================
# Клиентский handshake
# ============================================================================


async def _handshake(port: int, *, key: bytes = KEY, **kwargs):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        return await async_faketls_handshake(
            reader, writer, DOMAIN.decode(), key, **kwargs
        )
    finally:
        writer.close()


def _good(**kw):
    return lambda hello: build_server_hello(KEY, hello, **kw)


class TestHandshakeSuccess:
    async def test_returns_server_appdata_body(self, scripted_factory):
        server = await scripted_factory(_good(appdata_len=1369))
        body = await _handshake(server.port)
        assert len(body) == 1369

    async def test_empty_appdata_is_valid(self, scripted_factory):
        server = await scripted_factory(_good(appdata_len=0))
        assert await _handshake(server.port) == b""

    @pytest.mark.parametrize("size", [1, 2048, 16000])
    async def test_appdata_sizes(self, scripted_factory, size):
        server = await scripted_factory(_good(appdata_len=size))
        assert len(await _handshake(server.port)) == size

    async def test_sends_a_valid_hello_for_the_secret_and_domain(
        self, scripted_factory
    ):
        server = await scripted_factory(_good())
        await _handshake(server.port)
        assert len(server.hellos) == 1
        hello = server.hellos[0]
        assert verify_client_digest(KEY, hello) is not None
        assert parse_client_hello(hello).sni == DOMAIN.decode()

    @pytest.mark.parametrize(("m", "e"), [(True, True), (False, False), (True, False)])
    async def test_block_flags_reach_the_wire(self, scripted_factory, m, e):
        server = await scripted_factory(_good())
        await _handshake(server.port, use_block_m=m, use_block_e=e)
        info = parse_client_hello(server.hellos[0])
        shares = _key_shares(info.ext(0x0033))
        assert (len(shares[1][1]) == 1216) is m
        assert (_esni_payload_len(info.ext(0xFE0D)) is not None) is e

    async def test_server_response_split_into_tiny_tcp_segments(self, scripted_factory):
        # Ответ приходит по кусочкам: _read_exactly_logged обязан собрать его.
        async def serve(reader, writer):
            hello = b""
            hdr = await reader.readexactly(5)
            hello = hdr + await reader.readexactly(struct.unpack(">H", hdr[3:5])[0])
            for i, byte in enumerate(build_server_hello(KEY, hello, appdata_len=300)):
                writer.write(bytes([byte]))
                if i % 40 == 0:
                    await writer.drain()
                    await asyncio.sleep(0)
            await writer.drain()
            await asyncio.sleep(0.2)
            writer.close()

        server = await asyncio.start_server(serve, "127.0.0.1", 0)
        try:
            body = await _handshake(server.sockets[0].getsockname()[1])
            assert len(body) == 300
        finally:
            server.close()


class TestHandshakeFailures:
    async def test_wrong_secret_hmac_mismatch(self, scripted_factory):
        server = await scripted_factory(_good(digest_key=OTHER_KEY))
        with pytest.raises(ConnectionError, match="HMAC mismatch"):
            await _handshake(server.port)

    async def test_client_uses_a_different_secret_than_server(self, scripted_factory):
        server = await scripted_factory(_good())
        with pytest.raises(ConnectionError, match="HMAC mismatch"):
            await _handshake(server.port, key=OTHER_KEY)

    async def test_response_is_bound_to_this_clients_hello(self, scripted_factory):
        # Ответ, посчитанный для ДРУГОГО hello (replay), проверку не проходит.
        stale = _hello().data
        server = await scripted_factory(lambda _hello: build_server_hello(KEY, stale))
        with pytest.raises(ConnectionError, match="HMAC mismatch"):
            await _handshake(server.port)

    async def test_fallback_site_is_detected(self, scripted_factory):
        site = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        server = await scripted_factory(lambda _h: site)
        with pytest.raises(ConnectionError, match="not a TLS handshake record"):
            await _handshake(server.port)

    async def test_tls_alert_instead_of_server_hello(self, scripted_factory):
        server = await scripted_factory(lambda _h: b"\x15\x03\x03\x00\x02\x02\x28")
        with pytest.raises(ConnectionError, match="not a TLS handshake record"):
            await _handshake(server.port)

    async def test_handshake_message_is_not_a_server_hello(self, scripted_factory):
        server = await scripted_factory(_good(sh_type=0x0B))
        with pytest.raises(ConnectionError, match="does not start with 0x02"):
            await _handshake(server.port)

    async def test_missing_ccs_after_server_hello(self, scripted_factory):
        bad_prefix = b"\x17\x03\x03\x00\x01\x01\x17\x03\x03"
        assert bad_prefix != CCS_APPDATA_PREFIX
        server = await scripted_factory(_good(tail_prefix=bad_prefix))
        with pytest.raises(ConnectionError, match="CCS\\+AppData header not found"):
            await _handshake(server.port)

    @pytest.mark.parametrize("length", [0, 65535])
    async def test_invalid_server_hello_length(self, scripted_factory, length):
        server = await scripted_factory(
            lambda _h: b"\x16\x03\x03" + struct.pack(">H", length) + b"\x02" * 8
        )
        with pytest.raises(ConnectionError, match="Invalid ServerHello body length"):
            await _handshake(server.port)

    async def test_oversized_total_response(self, scripted_factory):
        def respond(_hello):
            body = b"\x02" + bytes(64999)
            return (
                b"\x16\x03\x03" + struct.pack(">H", len(body)) + body
                + CCS_APPDATA_PREFIX + struct.pack(">H", 2000)
            )  # fmt: skip

        server = await scripted_factory(respond)
        with pytest.raises(ConnectionError, match="ServerHello too large"):
            await _handshake(server.port)

    async def test_response_too_short_to_hold_a_digest(self, scripted_factory):
        def respond(_hello):
            body = b"\x02"
            return (
                b"\x16\x03\x03" + struct.pack(">H", len(body)) + body
                + CCS_APPDATA_PREFIX + b"\x00\x00"
            )  # fmt: skip

        server = await scripted_factory(respond)
        with pytest.raises(ConnectionError, match="too short"):
            await _handshake(server.port)

    @pytest.mark.parametrize("keep", [3, 5, 20, 140, 160])
    async def test_connection_closed_mid_response(self, scripted_factory, keep):
        server = await scripted_factory(
            lambda hello: build_server_hello(KEY, hello)[:keep]
        )
        with pytest.raises(ConnectionError, match="Connection closed"):
            await _handshake(server.port)

    async def test_server_closes_without_answering(self, scripted_factory):
        server = await scripted_factory(None)  # прочёл hello и закрыл
        with pytest.raises(ConnectionError, match="Connection closed"):
            await _handshake(server.port)

    async def test_silent_server_times_out(self, scripted_factory, monkeypatch):
        # Таймаут чтения зашит в значение по умолчанию _read_exactly_logged.
        monkeypatch.setattr(faketls._read_exactly_logged, "__defaults__", (0.2,))
        server = await scripted_factory(None, after="hang")
        started = time.monotonic()
        with pytest.raises(
            ConnectionError, match="Timeout reading ServerHello record header"
        ):
            await _handshake(server.port)
        assert time.monotonic() - started < 3

    async def test_stall_after_server_hello_times_out(
        self, scripted_factory, monkeypatch
    ):
        monkeypatch.setattr(faketls._read_exactly_logged, "__defaults__", (0.2,))
        # Присылаем только ServerHello-запись и замолкаем.
        server = await scripted_factory(
            lambda hello: build_server_hello(KEY, hello)[: 5 + 122], after="hang"
        )
        with pytest.raises(
            ConnectionError, match="Timeout reading CCS\\+AppData header"
        ):
            await _handshake(server.port)
