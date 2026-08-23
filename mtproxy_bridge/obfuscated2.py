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

"""obfuscated2 — транспортное шифрование MTProto (AES-256-CTR),
транспортные теги и построение init-пакета (порт TDLib).
"""

from __future__ import annotations

import hashlib
import secrets
import struct
from typing import NamedTuple

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import (
        Cipher,
        CipherContext,
        algorithms,
        modes,
    )
except ImportError as e:
    raise SystemExit(
        "Required package 'cryptography' is missing (pip install cryptography)"
    ) from e



# Transport-теги (см. ObfuscatedTransport::init в td/mtproto/TcpTransport.cpp).
TAG_ABRIDGED = b"\xef\xef\xef\xef"
TAG_PADDED_INTERMEDIATE = b"\xdd\xdd\xdd\xdd"


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
