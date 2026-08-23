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

"""Разбор tg://proxy и tg://proxy-ссылок, секретов MTProto."""

from __future__ import annotations

import base64
from typing import NamedTuple
from urllib.parse import parse_qs, urlparse

from .obfuscated2 import TAG_ABRIDGED, TAG_PADDED_INTERMEDIATE

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
