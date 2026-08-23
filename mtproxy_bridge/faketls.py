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

"""FakeTLS: ClientHello (порт TlsHello из TDLib) и handshake."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import struct
import time
from typing import NamedTuple

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
    )
except ImportError as e:
    raise SystemExit(
        "Required package 'cryptography' is missing (pip install cryptography)"
    ) from e

from .utils import _hex, log

# ============================================================================
# FakeTLS ClientHello — декларативная схема (порт TlsHello::get_default из TDLib)
# ============================================================================

_HELLO_DIGEST_LENGTH = 32
_CLIENT_HELLO_LIMIT = 2048
_MAX_GREASE = 8


class _Blk:
    pass


class _BlkStr(_Blk):
    def __init__(self, data: bytes):
        self.data = data


class _BlkZero(_Blk):
    def __init__(self, length: int):
        self.length = length


class _BlkGrease(_Blk):
    def __init__(self, seed: int):
        self.seed = seed


class _BlkRandom(_Blk):
    def __init__(self, length: int):
        self.length = length


class _BlkDomain(_Blk):
    pass


class _BlkPubKey(_Blk):
    pass


class _BlkScope(_Blk):
    def __init__(self, entries: list):
        self.entries = entries


class _BlkPerm(_Blk):
    def __init__(self, elements: list):
        self.elements = elements


class _BlkM(_Blk):
    pass


class _BlkE(_Blk):
    pass


class _BlkPadding(_Blk):
    pass


def _prepare_client_hello_rules(
    use_block_m: bool = True, use_block_e: bool = True
) -> list:
    """Строит декларативную схему ClientHello (порт ``TlsHello::get_default``
    из TDLib, td/mtproto/TlsInit.cpp:139-241).

    Args:
        use_block_m: включить блок M (Kyber-like key share).
        use_block_e: включить блок E (random extra в encrypted_server_name).
    """

    def S(d: bytes) -> _BlkStr:
        return _BlkStr(d)

    def Z(n: int) -> _BlkZero:
        return _BlkZero(n)

    def G(s: int) -> _BlkGrease:
        return _BlkGrease(s)

    def R(n: int) -> _BlkRandom:
        return _BlkRandom(n)

    def D() -> _BlkDomain:
        return _BlkDomain()

    def K() -> _BlkPubKey:
        return _BlkPubKey()

    def M() -> _BlkM:
        return _BlkM()

    def E() -> _BlkE:
        return _BlkE()

    def P() -> _BlkPadding:
        return _BlkPadding()

    def Scope(*entries: _Blk) -> _BlkScope:
        return _BlkScope(list(entries))

    def Perm(*elements: list) -> _BlkPerm:
        return _BlkPerm(list(elements))

    # key_share extension
    if use_block_m:
        key_share_entries = [
            S(b"\x00\x33\x04\xef\x04\xed"),
            G(4),
            S(b"\x00\x01\x00\x11\xec\x04\xc0"),
            M(),
            K(),
            S(b"\x00\x1d\x00\x20"),
            K(),
        ]
    else:
        key_share_entries = [
            S(b"\x00\x33\x00\x4f\x00\x4d"),
            G(4),
            S(b"\x00\x01\x00\x11\xec\x00\x20"),
            K(),
            S(b"\x00\x1d\x00\x20"),
            K(),
        ]

    # encrypted_server_name (fe0d) extension
    if use_block_e:
        esni_entries = [
            S(b"\xfe\x0d"),
            Scope(S(b"\x00\x00\x01\x00\x01"), R(1), S(b"\x00\x20"), R(32), Scope(E())),
        ]
    else:
        esni_entries = [
            S(b"\xfe\x0d"),
            Scope(S(b"\x00\x00\x01\x00\x01"), R(1), S(b"\x00\x20"), R(32)),
        ]

    return [
        S(b"\x16\x03\x01"),
        Scope(
            S(b"\x01\x00"),
            Scope(
                S(b"\x03\x03"),
                Z(_HELLO_DIGEST_LENGTH),
                S(b"\x20"),
                R(32),
                S(b"\x00\x20"),
                G(0),
                S(
                    bytes.fromhex(
                        "130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035"
                    )
                ),
                S(b"\x01\x00"),
                Scope(
                    G(2),
                    S(b"\x00\x00"),
                    Perm(
                        [S(b"\x00\x00"), Scope(Scope(S(b"\x00"), Scope(D())))],
                        [S(b"\x00\x05\x00\x05\x01\x00\x00\x00\x00")],
                        [
                            S(b"\x00\x0a\x00\x0c\x00\x0a"),
                            G(4),
                            S(b"\x11\xec\x00\x1d\x00\x17\x00\x18"),
                        ],
                        [S(b"\x00\x0b\x00\x02\x01\x00")],
                        [
                            S(
                                bytes.fromhex(
                                    "000d0012001004030804040105030805050108060601"
                                )
                            )
                        ],
                        [S(bytes.fromhex("0010000e000c02683208687474702f312e31"))],
                        [S(b"\x00\x12\x00\x00")],
                        [S(b"\x00\x17\x00\x00")],
                        [S(b"\x00\x1b\x00\x03\x02\x00\x02")],
                        [S(b"\x00\x23\x00\x00")],
                        [S(b"\x00\x2b\x00\x07\x06"), G(6), S(b"\x03\x04\x03\x03")],
                        [S(b"\x00\x2d\x00\x02\x01\x01")],
                        key_share_entries,
                        [S(b"\x44\xcd\x00\x05\x00\x03\x02\x68\x32")],
                        esni_entries,
                        [S(b"\xff\x01\x00\x01\x00")],
                    ),
                    G(3),
                    S(b"\x00\x01\x00"),
                    P(),
                ),
            ),
        ),
    ]


def _prepare_greases() -> bytes:
    """Генерирует 8 байт GREASE-значений (порт ``Grease::init`` из TDLib,
    td/mtproto/TlsInit.cpp:28-38)."""
    result = bytearray(secrets.token_bytes(_MAX_GREASE))
    for i in range(_MAX_GREASE):
        result[i] = (result[i] & 0xF0) + 0x0A
    for i in range(0, _MAX_GREASE, 2):
        if result[i] == result[i + 1]:
            result[i + 1] ^= 0x10
    return bytes(result)


class _HelloPart:
    """Рендерер блоков ClientHello (порт ``TlsHelloStore::do_op`` из TDLib,
    td/mtproto/TlsInit.cpp:386-508)."""

    def __init__(self, domain: bytes, greases: bytes):
        self._domain = domain
        self._greases = greases
        self._result = bytearray()
        self._digest_position = -1
        self._error = False

    def render_blocks(self, blocks: list) -> None:
        """Последовательно рендерит список блоков в ``self._result``."""
        for blk in blocks:
            if self._error:
                return
            self._render_block(blk)

    def _grow(self, n: int) -> bool:
        """Проверяет, что ``self._result`` можно расширить на ``n`` байт.

        При превышении лимита (2048 байт) устанавливает ``self._error``
        и возвращает False (порт ``TlsHelloStore::do_op`` grow-логики;
        TDLib использует отдельный класс ``TlsHelloCalcLength`` для расчёта
        и ``CHECK(size < (1 << 14))`` для per-scope лимита, но мосту это не
        нужно — глобальный cap 2048 < 16384 страхует строже).
        """
        if n <= 0 or len(self._result) + n > _CLIENT_HELLO_LIMIT:
            self._error = True
            return False
        return True

    def _render_block(self, blk: _Blk) -> None:
        if isinstance(blk, _BlkStr):
            if not self._grow(len(blk.data)):
                return
            self._result.extend(blk.data)

        elif isinstance(blk, _BlkZero):
            if not self._grow(blk.length):
                return
            start = len(self._result)
            self._result.extend(b"\x00" * blk.length)
            if blk.length == _HELLO_DIGEST_LENGTH and self._digest_position < 0:
                self._digest_position = start

        elif isinstance(blk, _BlkGrease):
            if blk.seed < 0 or blk.seed >= len(self._greases):
                self._error = True
                return
            if not self._grow(2):
                return
            g = self._greases[blk.seed]
            self._result.extend(bytes([g, g]))

        elif isinstance(blk, _BlkRandom):
            if not self._grow(blk.length):
                return
            self._result.extend(secrets.token_bytes(blk.length))

        elif isinstance(blk, _BlkDomain):
            if not self._grow(len(self._domain)):
                return
            self._result.extend(self._domain)

        elif isinstance(blk, _BlkPubKey):
            if not self._grow(32):
                return
            priv = X25519PrivateKey.generate()
            self._result.extend(priv.public_key().public_bytes_raw())

        elif isinstance(blk, _BlkScope):
            if not self._grow(2):
                return
            length_pos = len(self._result)
            self._result.extend(b"\x00\x00")
            body_start = len(self._result)
            self.render_blocks(blk.entries)
            body_len = len(self._result) - body_start
            self._result[length_pos : length_pos + 2] = body_len.to_bytes(2, "big")

        elif isinstance(blk, _BlkPerm):
            parts = []
            for element in blk.elements:
                part = _HelloPart(self._domain, self._greases)
                part.render_blocks(element)
                if part._error:
                    self._error = True
                    return
                parts.append(part.take())
            secrets.SystemRandom().shuffle(parts)
            for part in parts:
                if not self._grow(len(part)):
                    return
                self._result.extend(part)

        elif isinstance(blk, _BlkM):
            self._render_block_M()

        elif isinstance(blk, _BlkE):
            lengths = [144, 176, 208, 240]
            length = secrets.choice(lengths)
            if not self._grow(length):
                return
            self._result.extend(secrets.token_bytes(length))

        elif isinstance(blk, _BlkPadding):
            self._render_padding()

        else:
            self._error = True

    def _render_block_M(self) -> None:
        """Рендерит Kyber-like блок M (порт ``Op::MlKem768Key`` из TDLib,
        td/mtproto/TlsInit.cpp:441-451)."""
        k_elements = 384
        k_added = 32
        output_len = k_elements * 3 + k_added  # 1184
        if not self._grow(output_len):
            return
        random_data = secrets.token_bytes(k_elements * 8 + k_added)
        ints = struct.unpack(f"<{k_elements * 2}I", random_data[: k_elements * 8])
        chars = bytearray(k_elements * 3 + k_added)
        idx = 0
        for i in range(k_elements):
            a = ints[i * 2] % 3329
            b = ints[i * 2 + 1] % 3329
            chars[idx] = a & 0xFF
            chars[idx + 1] = ((a >> 8) + ((b & 0x0F) << 4)) & 0xFF
            chars[idx + 2] = (b >> 4) & 0xFF
            idx += 3
        chars[idx:] = random_data[k_elements * 8 :]
        self._result.extend(chars)

    def _render_padding(self) -> None:
        """Дополняет ClientHello до 513 байт extension-записью с zero padding.

        Порт ``Op::Padding`` из TDLib (td/mtproto/TlsInit.cpp:495-504).
        """
        length = len(self._result)
        if length < 513:
            needed = 513 - length
            # 2 байта (\x00\x15) + 2 байта length + needed нулей = needed + 4
            if not self._grow(needed + 4):
                return
            self._result.extend(b"\x00\x15")
            self._result.extend(needed.to_bytes(2, "big"))
            self._result.extend(b"\x00" * needed)

    def finalize(self, key: bytes) -> None:
        """Записывает HMAC-SHA256 digest и инжектирует timestamp в последние 4 байта."""
        if self._error or self._digest_position < 0:
            self._error = True
            return
        self._write_digest(key)
        self._inject_timestamp()

    def _write_digest(self, key: bytes) -> None:
        """Вычисляет HMAC-SHA256 от текущего буфера и пишет в digest-слот."""
        digest = hmac.new(key, bytes(self._result), hashlib.sha256).digest()
        self._result[
            self._digest_position : self._digest_position + _HELLO_DIGEST_LENGTH
        ] = digest

    def _inject_timestamp(self) -> None:
        """XOR-ит текущие 4 байта digest-слота с unix-временем (anti-replay)."""
        ts_pos = self._digest_position + _HELLO_DIGEST_LENGTH - 4
        existing = int.from_bytes(self._result[ts_pos : ts_pos + 4], "little")
        ts = int(time.time())
        new_val = (existing ^ ts) & 0xFFFFFFFF
        self._result[ts_pos : ts_pos + 4] = new_val.to_bytes(4, "little")

    def take(self) -> bytes:
        """Возвращает готовый ClientHello или пустые байты при ошибке рендера."""
        if self._error:
            return b""
        return bytes(self._result)

    def extract_digest(self) -> bytes:
        """Возвращает bytes digest-слота (пусто, если позиция ещё не определена)."""
        if self._digest_position < 0:
            return b""
        return bytes(
            self._result[
                self._digest_position : self._digest_position + _HELLO_DIGEST_LENGTH
            ]
        )


class ClientHello(NamedTuple):
    """Сгенерированный ClientHello: payload + digest для проверки ответа."""

    data: bytes
    digest: bytes


def _prepare_client_hello(
    domain: bytes, key: bytes, use_block_m: bool = True, use_block_e: bool = True
) -> ClientHello:
    """Генерирует ClientHello + digest для FakeTLS handshake.

    Args:
        domain: SNI-домен (ASCII).
        key: 16-байтный секрет прокси (HMAC key).
        use_block_m: флаг блока M (см. :func:`_prepare_client_hello_rules`).
        use_block_e: флаг блока E.

    Raises:
        ValueError: не удалось сгенерировать ClientHello (превышен лимит
            размера или нет digest-слота).
    """
    rules = _prepare_client_hello_rules(
        use_block_m=use_block_m, use_block_e=use_block_e
    )
    part = _HelloPart(domain, _prepare_greases())
    part.render_blocks(rules)
    part.finalize(key)
    data = part.take()
    if not data:
        raise ValueError("Failed to generate ClientHello")
    return ClientHello(data=data, digest=part.extract_digest())


# ============================================================================
# FakeTLS handshake — инкрементальный парсер ServerHello
# ============================================================================

_TLS_HANDSHAKE_PREFIX = b"\x16\x03\x03"
_CCS_APPDATA_PREFIX = b"\x14\x03\x03\x00\x01\x01\x17\x03\x03"
_SERVER_HELLO_DIGEST_POSITION = 11
_MAX_SERVER_HELLO_LENGTH = 65536


async def _read_exactly_logged(
    reader: asyncio.StreamReader, n: int, what: str, timeout: float = 15.0
) -> bytes:
    """``readexactly`` с логированием и таймаутом.

    Raises:
        ConnectionError: таймаут или обрыв соединения до получения ``n`` байт.
    """
    try:
        data = await asyncio.wait_for(reader.readexactly(n), timeout=timeout)
    except asyncio.TimeoutError:
        log.error(
            f"  [handshake] Timeout reading {what} (need {n} bytes, {timeout}s)"
        )
        raise ConnectionError(f"Timeout reading {what}")
    except asyncio.IncompleteReadError as e:
        log.error(
            f"  [handshake] Connection closed while reading {what}: "
            f"got {len(e.partial)}/{n} bytes"
        )
        raise ConnectionError(
            f"Connection closed while reading {what}: {len(e.partial)}/{n}"
        )
    log.debug(f"  [handshake] Read {n} bytes for '{what}': {_hex(data)}")
    return data


async def async_faketls_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    domain: str,
    secret_key: bytes,
    use_block_m: bool = True,
    use_block_e: bool = True,
) -> bytes:
    """Асинхронный клиентский FakeTLS handshake.

    Отправляет ClientHello, читает ServerHello + CCS + AppData, проверяет
    server-side HMAC-SHA256 (соответствует TDLib ``TlsInit::send_hello`` и
    ``TlsInit::wait_hello_response``, td/mtproto/TlsInit.cpp:599-648).

    Args:
        reader: поток чтения от upstream-прокси.
        writer: поток записи к upstream-прокси.
        domain: SNI-домен из ee-секрета.
        secret_key: 16-байтный секрет прокси.
        use_block_m: флаг блока M (Kyber-like key share) в ClientHello.
        use_block_e: флаг блока E в ClientHello.

    Returns:
        Байты первого AppData body от сервера (может быть пустым).

    Raises:
        ConnectionError: любая ошибка handshake (неверный формат ответа,
            несовпадение HMAC, таймаут).
    """
    log.info(f"  [handshake] FakeTLS handshake starting, domain='{domain}'")

    # Шаг 1: ClientHello
    hello = _prepare_client_hello(
        domain.encode("ascii"),
        secret_key,
        use_block_m=use_block_m,
        use_block_e=use_block_e,
    )
    log.debug(f"  [handshake] ClientHello generated: {len(hello.data)} bytes")
    log.debug(f"  [handshake] ClientHello first 32 bytes: {_hex(hello.data, 32)}")
    log.debug(f"  [handshake] ClientHello digest: {_hex(hello.digest, 32)}")

    writer.write(hello.data)
    await writer.drain()
    log.debug("  [handshake] ClientHello sent")

    # Шаг 2: ServerHello record header (5 байт)
    log.debug("  [handshake] Waiting for ServerHello record header (5 bytes)...")
    hdr = await _read_exactly_logged(reader, 5, "ServerHello record header")

    if hdr[0:3] != _TLS_HANDSHAKE_PREFIX:
        log.error(
            f"  [handshake] Expected 16 03 03, got {hdr[0:3].hex()} — "
            f"looks like a fallback site (proxy did not recognize the secret)"
        )
        raise ConnectionError(
            f"Server response is not a TLS handshake record (expected 16 03 03, "
            f"got {hdr[0:3].hex()}). Proxy did not recognize the secret?"
        )

    sh_body_len = struct.unpack(">H", hdr[3:5])[0]
    log.debug(f"  [handshake] ServerHello record header OK, body length={sh_body_len}")

    # parts123Size = 5 + L1 + 9 + 2 = 16 + L1; проверка > kMaxServerHelloLength.
    if sh_body_len <= 0 or sh_body_len > _MAX_SERVER_HELLO_LENGTH - 16:
        log.error(f"  [handshake] Invalid ServerHello body length: {sh_body_len}")
        raise ConnectionError(f"Invalid ServerHello body length: {sh_body_len}")

    # Шаг 3: ServerHello body
    log.debug(f"  [handshake] Waiting for ServerHello body ({sh_body_len} bytes)...")
    sh_body = await _read_exactly_logged(reader, sh_body_len, "ServerHello body")

    if not sh_body or sh_body[0] != 0x02:
        log.error(
            f"  [handshake] ServerHello body does not start with 0x02: "
            f"{sh_body[0] if sh_body else 'empty'}"
        )
        raise ConnectionError("ServerHello body does not start with 0x02 (not a ServerHello)")
    log.debug("  [handshake] ServerHello body OK (type=0x02)")

    # Шаг 4: CCS + начало AppData (второй prefix из wait_hello_response, 9 байт) + 2 байта длины
    log.debug("  [handshake] Waiting for CCS+AppData header (second prefix, 9 bytes)...")
    ccs_appdata_prefix = await _read_exactly_logged(
        reader, len(_CCS_APPDATA_PREFIX), "CCS+AppData header"
    )
    if ccs_appdata_prefix != _CCS_APPDATA_PREFIX:
        log.error(
            f"  [handshake] CCS+AppData header (second prefix) not found, "
            f"got {_hex(ccs_appdata_prefix)}"
        )
        raise ConnectionError(
            f"CCS+AppData header not found (expected {_CCS_APPDATA_PREFIX.hex()}, "
            f"got {ccs_appdata_prefix.hex()})"
        )
    log.debug("  [handshake] CCS+AppData header OK (second prefix)")

    remaining_len_bytes = await _read_exactly_logged(reader, 2, "AppData length")
    appdata_body_len = struct.unpack(">H", remaining_len_bytes)[0]
    log.debug(f"  [handshake] AppData body length={appdata_body_len}")

    # full = parts123Size + part4Size = (16 + L1) + (2 + L2) ≤ 65536.
    full_size = 16 + sh_body_len + 2 + appdata_body_len
    if full_size > _MAX_SERVER_HELLO_LENGTH:
        log.error(
            f"  [handshake] Total ServerHello size {full_size} > "
            f"{_MAX_SERVER_HELLO_LENGTH} (L1={sh_body_len}, L2={appdata_body_len})"
        )
        raise ConnectionError(
            f"ServerHello too large: {full_size} > {_MAX_SERVER_HELLO_LENGTH}"
        )

    # Шаг 5: AppData body
    if appdata_body_len > 0:
        log.debug(f"  [handshake] Waiting for AppData body ({appdata_body_len} bytes)...")
        appdata_body = await _read_exactly_logged(
            reader, appdata_body_len, "AppData body"
        )
        log.debug(f"  [handshake] AppData body received: {len(appdata_body)} bytes")
    else:
        appdata_body = b""
        log.debug("  [handshake] AppData body empty (len=0)")

    # Шаг 6: проверка server digest
    log.debug("  [handshake] Verifying server digest (over full response)...")

    server_full_response = (
        hdr + sh_body + ccs_appdata_prefix + remaining_len_bytes + appdata_body
    )
    log.debug(f"  [handshake] Server full response: {len(server_full_response)} bytes")

    if (
        len(server_full_response)
        < _SERVER_HELLO_DIGEST_POSITION + _HELLO_DIGEST_LENGTH
    ):
        log.error(
            f"  [handshake] Server response too short for digest: "
            f"{len(server_full_response)} bytes"
        )
        raise ConnectionError("Server response too short to verify digest")

    server_digest = server_full_response[
        _SERVER_HELLO_DIGEST_POSITION : _SERVER_HELLO_DIGEST_POSITION
        + _HELLO_DIGEST_LENGTH
    ]
    log.debug(f"  [handshake] Server digest (pos 11): {_hex(server_digest, 32)}")

    server_response_zeroed = (
        server_full_response[:_SERVER_HELLO_DIGEST_POSITION]
        + b"\x00" * _HELLO_DIGEST_LENGTH
        + server_full_response[_SERVER_HELLO_DIGEST_POSITION + _HELLO_DIGEST_LENGTH :]
    )

    fulldata = hello.digest + server_response_zeroed
    expected = hmac.new(secret_key, fulldata, hashlib.sha256).digest()
    log.debug(f"  [handshake] Expected digest: {_hex(expected, 32)}")

    if not hmac.compare_digest(expected, server_digest):
        log.error("  [handshake] Server HMAC mismatch!")
        log.error(f"  [handshake]   server:   {_hex(server_digest, 32)}")
        log.error(f"  [handshake]   expected: {_hex(expected, 32)}")
        raise ConnectionError(
            "Server HMAC mismatch — proxy did not recognize the secret "
            "(connection went to a domain-fronting fallback)"
        )

    log.info("  [handshake] FakeTLS handshake completed successfully")
    return appdata_body
