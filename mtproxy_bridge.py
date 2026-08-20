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

import argparse
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
import signal
import socket
import struct
import time
from typing import Callable, NamedTuple
from urllib.parse import urlparse, parse_qs

try:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher,
        algorithms,
        modes,
        CipherContext,
    )
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
except ImportError as e:
    raise SystemExit(
        "Required package 'cryptography' is missing (pip install cryptography)"
    ) from e

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


# ============================================================================
# Разбор tg://proxy?server=...&port=...&secret=... и секрета
# ============================================================================

# Transport-теги (см. ObfuscatedTransport::init в td/mtproto/TcpTransport.cpp).
TAG_ABRIDGED = b"\xef\xef\xef\xef"
TAG_PADDED_INTERMEDIATE = b"\xdd\xdd\xdd\xdd"

# TDLib ProxySecret::MAX_DOMAIN_LENGTH (td/mtproto/ProxySecret.h:18). Домен
# длиннее обрезается в ProxySecret::get_domain() → substr(0, MAX_DOMAIN_LENGTH).
_MAX_DOMAIN_LENGTH = 182


class ProxyLink(NamedTuple):
    """Parsed MTProto link."""

    server: str
    port: int
    secret_key: bytes  # 16 байт
    domain: str  # SNI-домен (только для FakeTLS / ee-секретов)
    is_fake_tls: bool
    expected_tag: bytes  # транспортный тег, соответствующий типу секрета


def parse_secret(secret_str: str) -> tuple[bytes, str, bool, bytes]:
    """Parse an MTProto secret in hex or base64url form.

    Semantics (mirrors TDLib ``ProxySecret::from_binary``,
    td/mtproto/ProxySecret.cpp:29-46, + ``ObfuscatedTransport::init``
    из td/mtproto/TcpTransport.cpp):
        - bare 16 bytes            → obfuscated2 + abridged
        - 0xEE + 16 + domain (≥18) → FakeTLS + padded intermediate
        - 0xDD + 16 (len == 17)    → obfuscated2 + padded intermediate

    Empty secret (TDLib plain TCP, ProxySecret size 0) is NOT supported.

    Raises:
        ValueError: empty secret, unrecognized format, or invalid length.
    """
    s = secret_str.strip()
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        raw = bytes.fromhex(s)
    else:
        b64 = s.replace("-", "+").replace("_", "/")
        b64 += "=" * (-len(b64) % 4)
        raw = base64.b64decode(b64)

    if not raw:
        raise ValueError(
            "Empty secret — TDLib plain TCP (ProxySecret size 0) is not supported "
            "by this bridge; provide a 16-byte / 0xDD / 0xEE secret"
        )

    if len(raw) == 16:
        return raw, "", False, TAG_ABRIDGED

    if raw[0] == 0xEE:
        # TDLib: ProxySecret::emulate_tls() → secret.size() ≥ 17 (0xEE + 16 + domain).
        # ProxySecret::from_binary (td/mtproto/ProxySecret.cpp:39) принимает size ≥ 18
        # (домен ≥ 1 байт). Мост следует TDLib-семантике.
        if len(raw) < 18:
            raise ValueError(
                f"FakeTLS (ee) secret must be ≥18 bytes "
                f"(0xEE + 16-byte key + ≥1-byte domain), got {len(raw)}"
            )
        # TDLib: ProxySecret::get_domain() возвращает secret_.substr(17)
        # (td/mtproto/ProxySecret.h:18).
        if len(raw) > 17 + _MAX_DOMAIN_LENGTH:
            raise ValueError(
                f"FakeTLS domain too long ({len(raw) - 17} bytes), "
                f"maximum allowed is {_MAX_DOMAIN_LENGTH} bytes"
            )
        # Preserve as ASCII only, refuse anything else so we don't silently corrupt SNI
        domain_bytes = raw[17:]
        try:
            domain = domain_bytes.decode("ascii")
        except UnicodeDecodeError as e:
            raise ValueError(
                f"FakeTLS domain must be ASCII, got non-ASCII bytes: {e}"
            ) from e
        return raw[1:17], domain, True, TAG_PADDED_INTERMEDIATE

    if raw[0] == 0xDD:
        # TDLib: ProxySecret::use_random_padding() → secret.size() == 17
        # (0xDD + 16-byte key).
        if len(raw) != 17:
            raise ValueError(
                f"dd-secret must be exactly 17 bytes (0xDD + 16-byte key), "
                f"got {len(raw)}"
            )
        return raw[1:17], "", False, TAG_PADDED_INTERMEDIATE

    raise ValueError(
        f"Unrecognized secret format (first byte=0x{raw[0]:02x}, "
        f"len={len(raw)}); expected 16 bytes (bare), 0xDD + 16 bytes, "
        f"or 0xEE + 16 bytes + ASCII domain (≥4 bytes)"
    )


def parse_tg_link(link: str) -> ProxyLink:
    """Parse ``tg://proxy?server=...&port=...&secret=...`` into a :class:`ProxyLink`.

    Raises:
        ValueError: required parameters server/port/secret are missing.
    """
    parsed = urlparse(link)
    params = parse_qs(parsed.query)

    if not params.get("server") or not params.get("port") or not params.get("secret"):
        raise ValueError("Invalid link: server, port or secret is missing")

    server = params["server"][0]
    port = int(params["port"][0])
    secret_str = params["secret"][0]

    key, domain, is_fake_tls, expected_tag = parse_secret(secret_str)
    return ProxyLink(server, port, key, domain, is_fake_tls, expected_tag)


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


# ============================================================================
# obfuscated2 — транспортное шифрование (AES-256-CTR)
# ============================================================================

# Зарезервированные значения first4 байт init (TDLib ``ObfuscatedTransport::init``,
# td/mtproto/TcpTransport.cpp:99-102):
#   0x44414548 = "DAEH" (HTTP-ответ, little-endian "HEAD")
#   0x54534F50 = "TSOP" (little-endian "POST")
#   0x20544547 = " GET" (little-endian "GET ")
#   0x4954504f = "ITPO" (little-endian "OPTI" — HTTP OPTIONS)
#   0x02010316 = первые 4 байта TLS 1.0 ClientHello-фрейма
#   0xDDDDDDDD / 0xEEEEEEEE = транспортные теги (anti-self-spoofing)
# Anti-self-spoofing: init packet не должен выглядеть как чужой протокол.
_RESERVED_FIRST4 = {
    0x44414548,
    0x54534F50,
    0x20544547,
    0x4954504f,
    0x02010316,
    0xDDDDDDDD,
    0xEEEEEEEE,
}


def _generate_init() -> bytes:
    """Генерирует 64-байтный init packet для obfuscated2.

    Перебирает случайные 64-байтные блоки до тех пор, пока первый байт ≠ 0xEF,
    первые 4 байта не входят в ``_RESERVED_FIRST4``, а байты 4..8 не равны
    нулю (требования ``isGoodStartNonce``).
    """
    while True:
        init = bytearray(secrets.token_bytes(64))
        if init[0] == 0xEF:
            continue
        first4 = struct.unpack("<I", init[0:4])[0]
        if first4 in _RESERVED_FIRST4:
            continue
        if struct.unpack("<I", init[4:8])[0] == 0:
            continue
        return bytes(init)
    raise RuntimeError("unreachable")


def _ctr_stream(key: bytes, iv: bytes):
    """Создаёт пару (encryptor, decryptor) AES-256-CTR с общим key/iv."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    return cipher.encryptor(), cipher.decryptor()


class Obfuscated2Keys(NamedTuple):
    """Результат :func:`build_obfuscated2_header`: заголовок + AES-CTR контексты."""

    header: bytes
    encryptor: CipherContext
    decryptor: CipherContext


def build_obfuscated2_header(
    protocol_tag: bytes, dc: int, secret: bytes | None
) -> Obfuscated2Keys:
    """Строит 64-байтный obfuscated2 init + AES-CTR контексты для шифрования.

    Args:
        protocol_tag: 4-байтный транспортный тег (``TAG_ABRIDGED`` или
            ``TAG_PADDED_INTERMEDIATE``). Записывается в байты 56..60 init.
        dc: ID дата-центра как signed int16. Положительный для обычных DC,
            отрицательный для CDN (TDLib: ``DcId::external()`` +
            ``DcOption::Flags::Cdn``, кодируется как ``-dc_id`` в int16 protocolDcId).
        secret: 16-байтный секрет прокси (подмешивается в ключи AES через
            SHA-256). ``None`` — без secret-mixing.

    Raises:
        ValueError: ``dc`` вне диапазона signed int16.

    Returns:
        :class:`Obfuscated2Keys`: 64-байтный заголовок + AES-CTR контексты
        для направлений client→server и server→client.
    """
    # *reinterpret_cast<int16*>(nonce+60) = _protocolDcId — signed int16.
    if not -32768 <= dc <= 32767:
        raise ValueError(f"DC ID {dc} out of int16 range [-32768, 32767]")

    init = bytearray(_generate_init())

    encrypt_key = bytes(init[8:40])
    encrypt_iv = bytes(init[40:56])

    init_rev = bytes(init[8:56])[::-1]
    decrypt_key = init_rev[:32]
    decrypt_iv = init_rev[32:48]

    if secret:
        encrypt_key = hashlib.sha256(encrypt_key + secret[:16]).digest()
        decrypt_key = hashlib.sha256(decrypt_key + secret[:16]).digest()

    encryptor, _ = _ctr_stream(encrypt_key, encrypt_iv)
    _, decryptor = _ctr_stream(decrypt_key, decrypt_iv)

    init[56:60] = protocol_tag
    struct.pack_into("<h", init, 60, dc)  # signed int16, как TDLib: as<int16>(header+60)=dc_id_

    encrypted_tail = encryptor.update(bytes(init))[56:64]
    header = bytes(init[0:56]) + encrypted_tail
    return Obfuscated2Keys(header=header, encryptor=encryptor, decryptor=decryptor)


# ============================================================================
# Определение protocol-тега и DC ID
# ============================================================================


def detect_client_transport_tag(first_bytes: bytes) -> tuple[bytes, int]:
    """Распознаёт транспортный тег от клиента по первым байтам потока.

    Поддерживаются (как в TDLib ``ObfuscatedTransport::init``):
        - ``0xDDDDDDDD`` (4 байта) — padded intermediate;
        - ``0xEF`` (1 байт) — abridged.

    Returns:
        Кортеж ``(tag, consumed_bytes)`` — тег и сколько байт из
        ``first_bytes`` он занимает.

    Raises:
        ValueError: тег не распознан. Валидация тега против ожидаемого из
            секрета делается отдельно в :func:`_handle_client`.
    """
    if first_bytes[:4] == TAG_PADDED_INTERMEDIATE:
        return TAG_PADDED_INTERMEDIATE, 4
    if first_bytes[:1] == b"\xef":
        return TAG_ABRIDGED, 1
    raise ValueError(
        f"Unsupported transport: got {first_bytes[:4].hex()!r}. "
        f"Expected padded intermediate (0xDDDDDDDD) for ee/dd secrets "
        f"or abridged (0xEF) for bare 16-byte secrets."
    )


# Built-in Telegram DC IPs. Источник: TDLib ``ConnectionCreator::get_default_dc_options``
# (td/telegram/net/ConnectionCreator.cpp:1257-1277) + актуальный getConfig dcOptions
# (snapshot 2026-07).
#
# Мост — SOCKS5-прокси, из которого DC ID не виден напрямую, поэтому делается
# reverse-mapping target_host → DC по IP-таблице.
#
# Production DCs: IDs 1-5. Test DCs: dc_id + 10000.
# IPv6 записаны в canonical compressed form (ipaddress.ip_address).
#
# ВНИМАНИЕ — расхождение с TDLib по protocolDcId для media_only:
#   TDLib (td/telegram/net/ConnectionCreator.cpp:634) кодирует media_only DC как
#   `is_media_only() ? -int_dc_id : int_dc_id`, т.е. ОТРИЦАТЕЛЬНЫЙ.
#   Мост кодирует media_only DC как ПОЛОЖИТЕЛЬНЫЙ (см. значения ниже с
#   media_only=True) — это намеренное решение, проверенное на практике.
#   Если прокси, реализованный строго по TDLib-спецификации, начнёт
#   отклонять соединения к media_only endpoints, поменяйте значения
#   149.154.167.222 / 2001:67c:4e8:f002::b / 149.154.165.120 /
#   2001:67c:4e8:f004::b на отрицательные (-2 и -4 соответственно).
KNOWN_DC_IPS: dict[str, int] = {
    # ===== DC 1 — Miami (auth + API) =====
    "149.154.175.50": 1,  # TDLib bootstrap (legacy)
    "149.154.175.57": 1,  # getConfig: текущий primary
    "149.154.175.53": 1,  # getConfig: static=True
    "2001:b28:f23d:f001::a": 1,  # IPv6 primary
    # ===== DC 2 — Amsterdam (auth + API + media) =====
    "149.154.167.51": 2,  # TDLib bootstrap (legacy)
    "95.161.76.100": 2,  # TDLib bootstrap (legacy)
    "149.154.167.41": 2,  # getConfig: primary, static=True
    "149.154.167.222": 2,  # getConfig: media_only=True
    "2001:67c:4e8:f002::a": 2,  # IPv6 primary
    "2001:67c:4e8:f002::b": 2,  # IPv6 media_only=True
    # ===== DC 3 — Miami (auth + API) =====
    "149.154.175.100": 3,  # getConfig: primary, static=True
    "2001:b28:f23d:f003::a": 3,  # IPv6 primary
    # ===== DC 4 — Amsterdam (auth + API + media) =====
    "149.154.167.91": 4,  # getConfig: primary, static=True
    "149.154.165.120": 4,  # getConfig: media_only=True
    "2001:67c:4e8:f004::a": 4,  # IPv6 primary
    "2001:67c:4e8:f004::b": 4,  # IPv6 media_only=True
    # ===== DC 5 — Singapore (auth + API) =====
    "149.154.171.5": 5,  # TDLib bootstrap (legacy)
    "91.108.56.101": 5,  # getConfig: primary, static=True
    "2001:b28:f23f:f005::a": 5,  # IPv6 primary
    # ===== Test DCs (TDLib test-mode bootstrap) — dc ID = 10000 + id =====
    "149.154.175.10": 10001,
    "149.154.167.40": 10002,
    "149.154.175.117": 10003,
    # IPv6 test DCs (TDLib test-mode bootstrap, IPv6)
    "2001:b28:f23d:f001::e": 10001,
    "2001:67c:4e8:f002::e": 10002,
    "2001:b28:f23d:f003::e": 10003,
}

# CDN DCs (help.getConfig dcOptions с cdn=True). protocolDcId кодируется как
# отрицательный int16 (TDLib: DcId::external() → protocolDcId = -dc_id).
# Мост релеит байты end-to-end после obfuscated2 handshake; CDN-fileToken
# handshake делает клиент через туннель.
KNOWN_CDN_IPS: dict[str, int] = {
    # DC 203 — CDN (IPv4 + IPv6)
    "91.105.192.100": 203,
    "2a0a:f280:203:a:5000::100": 203,
}


def _normalize_ip(s: str) -> str:
    """Нормализует IP-строку к canonical form для dict lookup.

    Не-IP строки возвращаются как есть (для hostname-lookup через DNS).
    """
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s


async def guess_dc_id_async(target_host: str) -> int:
    """Определяет Data Center ID по IP-адресу или hostname.

    Сначала пробует прямой lookup в :data:`KNOWN_CDN_IPS` /
    :data:`KNOWN_DC_IPS`. Если ``target_host`` — hostname, делает DNS-resolve
    и ищет полученные IP в тех же таблицах.

    Args:
        target_host: IP-адрес или hostname клиента (из SOCKS5 CONNECT).

    Returns:
        Положительный DC ID (1..5, 10001..10003) для обычных/test DC,
        отрицательный (-203) для CDN DC.

    Raises:
        ValueError: IP не найден в таблицах или DNS-resolve упал. Fallback
            на DC 2 НЕ делается — неправильный DC ID хуже отказа. Escape
            hatch: ``--dc-id-override``.
    """
    normalized = _normalize_ip(target_host)

    # 1. Прямой lookup: target_host может быть IP-адресом.
    # 1a. CDN-проверка — отдельной таблицей, чтобы вернуть -dc_id.
    if normalized in KNOWN_CDN_IPS:
        cdn_dc = KNOWN_CDN_IPS[normalized]
        log.info(f"  [dc-id] CDN endpoint {target_host} -> DC -{cdn_dc}")
        return -cdn_dc

    if normalized in KNOWN_DC_IPS:
        dc = KNOWN_DC_IPS[normalized]
        log.debug(f"  [dc-id] Found by IP: {target_host} -> DC {dc}")
        return dc

    # 2. DNS-resolve hostname → IP → lookup.
    dns_error: Exception | None = None
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(target_host, 443)
        for info in infos:
            ip = info[4][0]
            normalized_ip = _normalize_ip(ip)
            if normalized_ip in KNOWN_CDN_IPS:
                cdn_dc = KNOWN_CDN_IPS[normalized_ip]
                log.info(f"  [dc-id] CDN resolved {target_host} -> {ip} -> DC -{cdn_dc}")
                return -cdn_dc
            if normalized_ip in KNOWN_DC_IPS:
                dc = KNOWN_DC_IPS[normalized_ip]
                log.debug(f"  [dc-id] Resolved {target_host} -> {ip} -> DC {dc}")
                return dc
    except (socket.gaierror, OSError) as e:
        dns_error = e

    if dns_error:
        raise ValueError(
            f"Could not determine DC ID for {target_host}: "
            f"DNS-resolve failed ({dns_error}). "
            f"Use --dc-id-override."
        ) from dns_error
    raise ValueError(
        f"Could not determine DC ID for {target_host}: "
        f"IP not found in the built-in DC table (TDLib ConnectionCreator + getConfig). "
        f"If the target is a non-standard DC, use --dc-id-override."
    )


# ============================================================================
# asyncio SOCKS5-сервер + релей
# ============================================================================


class BridgeConfig(NamedTuple):
    """Конфигурация моста: listen + upstream + опции FakeTLS/obfuscated2."""

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


async def _handle_client(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cfg: BridgeConfig
) -> None:
    """Обрабатывает одно клиентское соединение: SOCKS5 → tunnel → relay.

    Pipeline:
        1. SOCKS5 handshake, вычисление DC ID;
        2. TCP-подключение к upstream;
        3. FakeTLS handshake (если ee-секрет);
        4. obfuscated2 header + первые байты клиента;
        5. bidirectional relay с activity timeout.

    Любая ошибка на этапах 1-4 рвёт соединение без relay.
    """
    upstream_writer = None
    client_addr = writer.get_extra_info("peername")
    log.info(f"[client {client_addr}] New connection")

    # TCP_NODELAY на клиентский сокет — симметрично с upstream.
    _apply_tcp_tuning(writer, client_addr)

    try:
        try:
            target_host, _target_port = await _socks5_handshake(reader, writer)
            log.info(
                f"[client {client_addr}] SOCKS5 handshake OK, target={target_host}:{_target_port}"
            )
        except Exception as e:
            log.error(f"[client {client_addr}] SOCKS5 handshake failed: {e}")
            writer.close()
            return

        try:
            first_chunk = await asyncio.wait_for(
                reader.readexactly(4), timeout=SOCKS5_HANDSHAKE_TIMEOUT_SECS
            )
        except asyncio.TimeoutError:
            log.error(
                f"[client {client_addr}] Timeout reading transport tag "
                f"({SOCKS5_HANDSHAKE_TIMEOUT_SECS}s) — client connected but sent nothing "
                f"after SOCKS5 handshake"
            )
            writer.close()
            return
        except asyncio.IncompleteReadError as e:
            log.error(
                f"[client {client_addr}] Failed to read transport tag: "
                f"got {len(e.partial)}/4 bytes"
            )
            writer.close()
            return

        try:
            protocol_tag, consumed = detect_client_transport_tag(first_chunk)
        except ValueError as e:
            log.error(f"[client {client_addr}] {e}")
            writer.close()
            return
        leftover = first_chunk[consumed:]

        # Валидация: транспорт клиента должен соответствовать типу секрета.
        # Нарушение ломает obfuscated2 handshake (тег сверяется сервером).
        tag_names = {
            TAG_ABRIDGED: "abridged (0xEF)",
            TAG_PADDED_INTERMEDIATE: "padded intermediate (0xDD)",
        }
        if protocol_tag != cfg.expected_tag:
            log.error(
                f"[client {client_addr}] Transport/secret mismatch: "
                f"client uses {tag_names.get(protocol_tag, 'unknown')}, "
                f"secret requires {tag_names.get(cfg.expected_tag, 'unknown')}. "
                f"Use protocol_factory={'TCPIntermediatePadded' if cfg.expected_tag == TAG_PADDED_INTERMEDIATE else 'TCPAbridged'}."
            )
            writer.close()
            return

        log.debug(
            f"[client {client_addr}] Transport tag: {tag_names.get(protocol_tag, 'unknown')} (matches secret)"
        )
        log.debug(f"[client {client_addr}] First chunk: {_hex(first_chunk)}")
        log.debug(f"[client {client_addr}] Leftover after tag: {len(leftover)} bytes")

        # DC ID определяется до подключения к upstream — незачем открывать TCP,
        # если не можем заполнить obfuscated2-заголовок.
        if cfg.dc_id_override:
            dc = cfg.dc_id_override
            log.info(f"[client {client_addr}] DC ID override: {dc}")
        else:
            try:
                dc = await guess_dc_id_async(target_host)
            except ValueError as e:
                log.error(f"[client {client_addr}] {e}")
                writer.close()
                return
            log.info(f"[client {client_addr}] DC ID resolved: {dc}")

        try:
            log.info(
                f"[client {client_addr}] Connecting to upstream {cfg.upstream_host}:{cfg.upstream_port}..."
            )
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        cfg.upstream_host, cfg.upstream_port
                    ),
                    timeout=UPSTREAM_CONNECT_TIMEOUT_SECS,
                )
            except asyncio.TimeoutError:
                raise OSError(
                    f"upstream connect timeout ({UPSTREAM_CONNECT_TIMEOUT_SECS}s) "
                    f"to {cfg.upstream_host}:{cfg.upstream_port}"
                )
            _apply_tcp_tuning(upstream_writer, client_addr)
            log.info(f"[client {client_addr}] TCP connection to upstream established")
        except OSError as e:
            log.error(f"[client {client_addr}] Failed to connect to upstream: {e}")
            writer.close()
            return

        tls_writer: TLSRecordWriter | None = None
        server_initial_appdata = b""

        try:
            if cfg.is_fake_tls:
                log.info(f"[client {client_addr}] Starting FakeTLS handshake...")
                server_initial_appdata = await async_faketls_handshake(
                    upstream_reader, upstream_writer, cfg.domain, cfg.secret_key,
                    use_block_m=cfg.use_block_m, use_block_e=cfg.use_block_e,
                )
                tls_writer = TLSRecordWriter(send_ccs=cfg.send_ccs)
                log.info(
                    f"[client {client_addr}] FakeTLS handshake completed, "
                    f"server_initial_appdata={len(server_initial_appdata)} bytes, "
                    f"send_ccs={cfg.send_ccs}"
                )

            keys = build_obfuscated2_header(protocol_tag, dc, cfg.secret_key)
            log.debug(
                f"[client {client_addr}] Obfuscated2 header built: "
                f"{len(keys.header)} bytes, tag={protocol_tag.hex()}, dc={dc}"
            )

            # Leftover (байты после transport-тега) шифруем и отправляем как есть —
            # framing не транслируется, релеится end-to-end.
            first_encrypted = keys.encryptor.update(leftover) if leftover else b""
            log.debug(
                f"[client {client_addr}] First encrypted chunk: {len(first_encrypted)} bytes"
            )

            if cfg.is_fake_tls:
                wrapped = tls_writer.wrap(keys.header, first_encrypted)
                upstream_writer.write(wrapped)
                log.debug(
                    f"[client {client_addr}] Sent upstream (TLS-wrapped): "
                    f"{len(wrapped)} bytes"
                )
            else:
                upstream_writer.write(keys.header)
                if first_encrypted:
                    upstream_writer.write(first_encrypted)
                log.debug(
                    f"[client {client_addr}] Sent upstream (raw): "
                    f"{len(keys.header) + len(first_encrypted)} bytes"
                )
            await upstream_writer.drain()
        except Exception as e:
            log.exception(f"[client {client_addr}] Tunnel setup error: {e}")
            if upstream_writer:
                upstream_writer.close()
            writer.close()
            return

        unwrapper = TLSRecordUnwrapper() if cfg.is_fake_tls else None

        # server_initial_appdata — это AppData-body из FakeTLS handshake
        # (HMAC-верификация), НЕ obfuscated2 данные. TDLib также не
        # использует эти байты после проверки; скармливать unwrapper'у
        # нельзя — это сломает его буфер.
        if server_initial_appdata:
            log.debug(
                f"[client {client_addr}] Discarded server_initial_appdata: "
                f"{len(server_initial_appdata)} bytes (handshake noise)"
            )

        log.info(f"[client {client_addr}] Tunnel established, starting relay")

        async def client_to_upstream() -> None:
            """Relay: client → obfuscated2 encrypt → upstream (TLS-wrapped если FakeTLS)."""
            try:
                while True:
                    try:
                        data = await asyncio.wait_for(
                            reader.read(65536), timeout=ACTIVITY_TIMEOUT_SECS
                        )
                    except asyncio.TimeoutError:
                        log.warning(
                            f"[client {client_addr}] client->upstream: no activity for "
                            f"{ACTIVITY_TIMEOUT_SECS}s — closing by activity timeout"
                        )
                        break
                    if not data:
                        log.info(
                            f"[client {client_addr}] Client closed connection (read returned empty)"
                        )
                        break
                    enc = keys.encryptor.update(data)
                    if cfg.is_fake_tls and tls_writer:
                        upstream_writer.write(tls_writer.wrap(b"", enc))
                    else:
                        upstream_writer.write(enc)
                    await upstream_writer.drain()
                    log.debug(f"[client {client_addr}] client->upstream: {len(data)} bytes")
            except (ConnectionResetError, BrokenPipeError) as e:
                log.debug(f"[client {client_addr}] client->upstream: {e}")
            except Exception as e:
                log.exception(f"[client {client_addr}] client->upstream error: {e}")
            finally:
                try:
                    upstream_writer.close()
                except Exception:
                    pass

        async def upstream_to_client() -> None:
            """Relay: upstream → TLS-unwrap (если FakeTLS) → obfuscated2 decrypt → client."""
            try:
                while True:
                    try:
                        data = await asyncio.wait_for(
                            upstream_reader.read(65536), timeout=ACTIVITY_TIMEOUT_SECS
                        )
                    except asyncio.TimeoutError:
                        log.warning(
                            f"[client {client_addr}] upstream->client: no activity for "
                            f"{ACTIVITY_TIMEOUT_SECS}s — closing by activity timeout"
                        )
                        break
                    if not data:
                        log.info(
                            f"[client {client_addr}] Upstream closed connection (read returned empty)"
                        )
                        break
                    plain_wire = unwrapper.feed(data) if unwrapper else data
                    if plain_wire:
                        dec = keys.decryptor.update(plain_wire)
                        writer.write(dec)
                        await writer.drain()
                        log.debug(
                            f"[client {client_addr}] upstream->client: {len(dec)} bytes"
                        )
            except (ConnectionResetError, BrokenPipeError) as e:
                log.debug(f"[client {client_addr}] upstream->client: {e}")
            except Exception as e:
                log.exception(f"[client {client_addr}] upstream->client error: {e}")
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        await asyncio.gather(
            client_to_upstream(), upstream_to_client(), return_exceptions=True
        )
    except asyncio.CancelledError:
        log.info(f"[client {client_addr}] Connection interrupted (server shutting down)")
        raise
    finally:
        log.info(f"[client {client_addr}] Connection closed")
        try:
            writer.close()
            if upstream_writer:
                upstream_writer.close()
        except Exception:
            pass


# ============================================================================
# Корректное (graceful) завершение
# ============================================================================
#
# Не полагаемся на дефолтное поведение asyncio.run() при SIGINT (отмена
# главной задачи → CancelledError всплывает из serve_forever() →
# KeyboardInterrupt с трассировкой). Вместо этого сами перехватываем
# SIGINT/SIGTERM через loop.add_signal_handler, останавливаем listener и
# ждём уже открытые соединения — run_bridge() в итоге просто возвращается
# с exit code 0.


def _make_connection_tracker(
    cfg: BridgeConfig,
) -> tuple[
    Callable[[asyncio.StreamReader, asyncio.StreamWriter], None],
    set[asyncio.Task],
]:
    """Строит client_connected_cb для asyncio.start_server + множество
    активных задач-обработчиков для отслеживания при shutdown.

    asyncio.start_server оборачивает коллбэк в Task, но не сохраняет ссылку,
    поэтому отменить конкретное соединение снаружи нельзя. Здесь мы явно
    регистрируем каждую задачу и убираем её из множества по завершении —
    чтобы _shutdown_server видел актуальный список того, что ещё нужно закрыть.
    """
    active: set[asyncio.Task] = set()

    def _client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(_handle_client(reader, writer, cfg))

        def _on_done(t: asyncio.Task) -> None:
            active.discard(t)
            if not t.cancelled():
                exc = t.exception()
                if exc is not None:
                    log.error(
                        f"Unhandled error in client connection task: {exc!r}",
                        exc_info=exc,
                    )

        active.add(task)
        task.add_done_callback(_on_done)

    return _client_connected, active


async def _shutdown_server(
    server: asyncio.Server,
    active_connections: set[asyncio.Task],
    *,
    grace: float = SHUTDOWN_GRACE_SECS,
) -> None:
    """Останавливает listener и корректно закрывает уже открытые соединения.

    Порядок важен: сначала ``server.close()`` (снимает listener), потом
    ``task.cancel()`` для всех отслеживаемых задач, и только потом ждём их
    через ``asyncio.wait``. ``wait_closed()`` здесь НЕ вызывается — начиная
    с Python 3.12.1 он ждёт закрытия всех активных соединений сервера, что
    дало бы deadlock (сервер ждёт соединения, соединения ждут отмены).

    Каждая отменённая задача — это ``_handle_client()`` с единым
    try/except CancelledError/finally на весь пайплайн, так что оба сокета
    гарантированно закрываются на любой стадии отмены. ``grace`` — верхняя
    граница ожидания на случай зависшей задачи.
    """
    server.close()

    if not active_connections:
        return

    log.info(
        f"Closing {len(active_connections)} active connection(s) "
        f"(up to {grace:.0f}s)..."
    )
    for task in active_connections:
        task.cancel()

    _done, pending = await asyncio.wait(active_connections, timeout=grace)
    if pending:
        log.warning(
            f"{len(pending)} connection(s) did not close within {grace:.0f}s "
            f"and were left running to shut down on their own"
        )


def _install_shutdown_handler(stop_event: asyncio.Event) -> None:
    """Регистрирует SIGINT/SIGTERM: по сигналу выставляется stop_event,
    что будит run_bridge() и запускает штатную процедуру остановки.

    Повторный сигнал во время завершения — форсирует немедленный выход через
    ``os._exit`` (компромисс в пользу отзывчивости Ctrl+C, relay всё равно
    не буферизует).

    На Windows ``add_signal_handler`` не реализован — откатываемся на
    ``signal.signal()`` (ловит хотя бы SIGINT/Ctrl+C).
    """
    loop = asyncio.get_running_loop()

    def _on_signal(sig_name: str) -> None:
        if stop_event.is_set():
            log.warning(f"Second {sig_name} received — forcing immediate exit")
            os._exit(130 if sig_name == "SIGINT" else 143)
        log.info(
            f"{sig_name} received, shutting down gracefully "
            f"(Ctrl+C again to force-quit)..."
        )
        stop_event.set()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _on_signal, sig.name)
    except NotImplementedError:

        def _sync_handler(signum: int, _frame: object) -> None:
            loop.call_soon_threadsafe(_on_signal, signal.Signals(signum).name)

        signal.signal(signal.SIGINT, _sync_handler)


async def run_bridge(cfg: BridgeConfig) -> None:
    """Start a blocking SOCKS5 server (CLI mode).

    Runs until SIGINT/SIGTERM, then shuts down gracefully: stops accepting
    new connections, cancels and waits (up to SHUTDOWN_GRACE_SECS) for
    already-open ones, and returns normally — no exception leaves this
    function as part of a normal shutdown.
    """
    stop_event = asyncio.Event()
    _install_shutdown_handler(stop_event)

    client_connected_cb, active_connections = _make_connection_tracker(cfg)
    server = await asyncio.start_server(
        client_connected_cb, cfg.listen_host, cfg.listen_port
    )
    transport_name = (
        "padded intermediate (0xDD)"
        if cfg.expected_tag == TAG_PADDED_INTERMEDIATE
        else (
            "abridged (0xEF)"
            if cfg.expected_tag == TAG_ABRIDGED
            else f"unknown ({cfg.expected_tag.hex()})"
        )
    )
    print(
        f"SOCKS5 bridge listening on \n\nsocks5://{cfg.listen_host}:{cfg.listen_port}\n\n"
        f"tunnel to {cfg.upstream_host}:{cfg.upstream_port} "
        f"({'FakeTLS' if cfg.is_fake_tls else 'plain obfuscated2'})"
    )
    print(
        f"transport={transport_name}, "
        f"send_ccs={cfg.send_ccs}, use_block_m={cfg.use_block_m}, "
        f"use_block_e={cfg.use_block_e}"
    )

    await stop_event.wait()
    log.info("Stopping listener, no new connections will be accepted...")
    await _shutdown_server(server, active_connections)
    log.info("Bridge stopped.")


def is_mtproto_link(url: str) -> bool:
    """Check whether ``url`` is a ``tg://proxy`` or ``t.me/proxy`` link."""
    url = url.strip().lower()
    return url.startswith("tg://proxy") or "t.me/proxy" in url


def needs_padded_transport(url: str) -> bool:
    """Determine whether an MTProto link requires the padded intermediate transport.

    Secret-type to transport mapping (mirrors TDLib ``ObfuscatedTransport::init``
    + ``ProxySecret::emulate_tls`` / ``use_random_padding``):
        - 0xEE + 16 + domain → FakeTLS + padded      → True
        - 0xDD + 16          → obfuscated2 + padded   → True
        - bare 16 bytes      → obfuscated2 + abridged → False

    For non-MTProto URLs always returns False (direct transport).

    Args:
        url: ``tg://proxy?...`` or ``https://t.me/proxy?...`` link.

    Returns:
        True if the client should use ``TCPIntermediatePadded``; False if
        ``TCPAbridged`` (or direct transport for non-MTProto URLs).

    Raises:
        ValueError: the link is invalid or the secret is unrecognized
            (propagated from :func:`parse_tg_link` / :func:`parse_secret`).
    """
    if not is_mtproto_link(url):
        return False
    link = parse_tg_link(url)
    return link.expected_tag == TAG_PADDED_INTERMEDIATE


# Сервер → множество активных задач-обработчиков (см. _make_connection_tracker).
# Хранятся именно клиентские задачи, чтобы stop_all_bridges могла дождаться каждой.
_running_servers: dict[asyncio.Server, set[asyncio.Task]] = {}


async def start_local_bridge(
    tg_link: str,
    listen_host: str = "127.0.0.1",
    listen_port: int = 0,
    dc_id_override: int = 0,
    send_ccs: bool = True,
    use_block_m: bool = True,
    use_block_e: bool = True,
) -> int:
    """Start the bridge as a background asyncio task and return the local port.

    Intended for embedding into an application (e.g. before starting a
    Pyrogram/Kurigram client). To stop all background bridges, call
    :func:`stop_all_bridges` — e.g. from your own SIGINT/SIGTERM handler or
    shutdown path; this module does not install signal handlers of its own
    in library mode, so as not to clobber a host application's handlers.

    Args:
        tg_link: ``tg://proxy?server=...&port=...&secret=...``.
        listen_host: SOCKS5 host (default 127.0.0.1).
        listen_port: port; 0 = pick a free one automatically.
        dc_id_override: explicit DC ID (escape hatch; 0 = auto).
        send_ccs: Send CCS (TDLib ``first_prefix``) before the first AppData record.
        use_block_m: Use block M (Kyber-like) in ClientHello.
        use_block_e: Use block E (random extra) in ClientHello.

    Returns:
        The actual port the bridge is listening on.
    """
    link = parse_tg_link(tg_link)
    cfg = BridgeConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        upstream_host=link.server,
        upstream_port=link.port,
        secret_key=link.secret_key,
        domain=link.domain,
        is_fake_tls=link.is_fake_tls,
        expected_tag=link.expected_tag,
        dc_id_override=dc_id_override,
        send_ccs=send_ccs,
        use_block_m=use_block_m,
        use_block_e=use_block_e,
    )
    client_connected_cb, active_connections = _make_connection_tracker(cfg)
    server = await asyncio.start_server(client_connected_cb, listen_host, listen_port)
    actual_port = server.sockets[0].getsockname()[1]

    _running_servers[server] = active_connections

    return actual_port


async def stop_all_bridges() -> None:
    """Gracefully stop all background bridges started via :func:`start_local_bridge`.

    For each bridge: stops accepting new connections, then cancels and
    waits (up to ``SHUTDOWN_GRACE_SECS`` per bridge, all bridges in
    parallel) for already-open client connections to close their sockets.
    """
    if not _running_servers:
        return

    await asyncio.gather(
        *(
            _shutdown_server(server, active_connections)
            for server, active_connections in _running_servers.items()
        ),
        return_exceptions=True,
    )
    _running_servers.clear()


def main() -> None:
    """CLI entry point: parse arguments and start a blocking bridge."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tg_link", help="tg://proxy?server=...&port=...&secret=...")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=1080)
    parser.add_argument("--dc-id-override", type=int, default=0)
    parser.add_argument(
        "--no-ccs",
        action="store_true",
        default=False,
        help="Do not send CCS (TDLib first_prefix) before the first AppData record "
        "(sent by default, like TDLib ObfuscatedTransport::do_write_tls)",
    )
    parser.add_argument(
        "--no-block-m",
        action="store_true",
        default=False,
        help="Disable block M (Kyber-like) in ClientHello",
    )
    parser.add_argument(
        "--no-block-e",
        action="store_true",
        default=False,
        help="Disable block E in ClientHello",
    )
    parser.add_argument(
        "--debug", action="store_true", default=False, help="Enable DEBUG logging"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    link = parse_tg_link(args.tg_link)
    cfg = BridgeConfig(
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        upstream_host=link.server,
        upstream_port=link.port,
        secret_key=link.secret_key,
        domain=link.domain,
        is_fake_tls=link.is_fake_tls,
        expected_tag=link.expected_tag,
        dc_id_override=args.dc_id_override,
        send_ccs=not args.no_ccs,
        use_block_m=not args.no_block_m,
        use_block_e=not args.no_block_e,
    )
    try:
        asyncio.run(run_bridge(cfg))
    except KeyboardInterrupt:
        # Защитная сетка: run_bridge() сама ловит SIGINT через
        # loop.add_signal_handler. Сюда попадаем только если Ctrl+C пришёл
        # до регистрации обработчика (узкое окно на старте) или на
        # платформе, где add_signal_handler недоступен.
        print("\nInterrupted before startup completed.")


if __name__ == "__main__":
    main()
