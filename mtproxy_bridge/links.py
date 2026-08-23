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

"""Разбор tg://proxy и tg://webproxy ссылок, секретов MTProto,
вывод bridge-capability для WEB Proxy v1."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from typing import NamedTuple
from urllib.parse import parse_qs, urlparse

from .obfuscated2 import TAG_ABRIDGED, TAG_PADDED_INTERMEDIATE

# TDLib ProxySecret::MAX_DOMAIN_LENGTH (td/mtproto/ProxySecret.h:18). Домен
# длиннее обрезается в ProxySecret::get_domain() → substr(0, MAX_DOMAIN_LENGTH).
_MAX_DOMAIN_LENGTH = 182

# Frozen v1 domain-separation label из PROTOCOL.md («Bridge URL»).
# Имя сохранено протоколом для совместимости и не привязывает режим к
# Telegram Desktop.
_WEB_BRIDGE_LABEL = "tdesktop-web-proxy-bridge-v1"

# Канонический lowercase ASCII/A-label hostname (PROTOCOL.md: «canonical
# lowercase ASCII/IDNA hostname»). Каждый label: буквы/цифры, дефисы внутри.
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ProxyLink(NamedTuple):
    """Parsed MTProto link."""

    server: str
    port: int
    secret_key: bytes  # 16 байт
    domain: str  # SNI-домен (только для FakeTLS / ee-секретов)
    is_fake_tls: bool
    expected_tag: bytes  # транспортный тег, соответствующий типу секрета


def _decode_secret_bytes(secret_str: str) -> bytes:
    """Декодирует секрет в hex или base64url форме в сырые байты.

    Общая часть :func:`parse_secret` и WEB-секретов (семантика TDLib
    ``ProxySecret::from_binary``).
    """
    s = secret_str.strip()
    if all(c in "0123456789abcdefABCDEF" for c in s) and len(s) % 2 == 0:
        return bytes.fromhex(s)
    b64 = s.replace("-", "+").replace("_", "/")
    b64 += "=" * (-len(b64) % 4)
    return base64.b64decode(b64)


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
    raw = _decode_secret_bytes(secret_str)

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
# WEB Proxy (tg://webproxy) — ссылки и bridge-capability
#
# В отличие от классического MTProxy-типа, у WEB-ссылок нет порта: клиент
# требует ровно 443 (PROTOCOL.md «Bridge URL», WEB_PROXY.ru.md). Секрет —
# только plain (16 байт) или dd (0xDD + 16); ee/FakeTLS в WEB-режиме
# не поддерживается. Capability выводится локально из hostname и секрета.
# ============================================================================


class WebProxyLink(NamedTuple):
    """Parsed WEB proxy link."""

    host: str  # канонический lowercase ASCII/A-label hostname
    port: int  # всегда 443 (фиксирован типом прокси WEB)
    secret: bytes  # секрет как в ссылке: 16 байт или 0xDD + 16 (ключ HMAC)
    secret_key: bytes  # 16-байтный ключ MTProxy без префикса (для obfuscated2)
    is_padded: bool  # dd-режим → клиенту нужен TCPIntermediatePadded
    capability: str  # 43-символьная base64url bridge-capability


def _normalize_web_host(host: str) -> str:
    """Приводит hostname к каноническому A-label виду и валидирует его.

    Unicode-имена кодируются IDNA (клиенты хранят A-label и выводят из него
    capability — см. tproxy-server README про ACE-форму). Строка с пробелами,
    схемой или путью отвергается.

    Raises:
        ValueError: пустое имя или не соответствует правилам hostname.
    """
    h = host.strip().lower().rstrip(".")
    if not h:
        raise ValueError("Empty WEB proxy hostname")
    if not h.isascii():
        try:
            h = h.encode("idna").decode("ascii").lower()
        except UnicodeError as e:
            raise ValueError(f"Invalid WEB proxy hostname: {host!r}") from e
    labels = h.split(".")
    if len(h) > 253 or not all(_HOST_LABEL_RE.match(lbl) for lbl in labels):
        raise ValueError(f"Invalid WEB proxy hostname: {host!r}")
    return h


def derive_web_capability(host: str, secret: bytes) -> str:
    """Выводит bridge-capability (PROTOCOL.md, «Bridge URL»).

        context = UTF-8("tdesktop-web-proxy-bridge-v1\\n" + H)
        capability = base64url-nopad(HMAC-SHA256(key=S, message=context))

    ``secret`` — сырые байты секрета как в ссылке: для dd-режима префикс
    0xDD сохраняется (это подтверждено официальными тестовыми векторами).

    Args:
        host: канонический lowercase ASCII hostname.
        secret: 16 либо 17 (dd-prefixed) байт секрета.

    Returns:
        43-символьная canonical unpadded base64url строка.
    """
    context = (_WEB_BRIDGE_LABEL + "\n" + host).encode("utf-8")
    digest = hmac.new(secret, context, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _decode_web_secret(secret_str: str) -> tuple[bytes, bytes]:
    """Декодирует WEB-секрет → ``(сырые байты с dd-префиксом, ключ 16 байт)``.

    Raises:
        ValueError: пустой секрет, неподдерживаемая длина или ee-FakeTLS.
    """
    raw = _decode_secret_bytes(secret_str)
    if len(raw) == 16:
        # plain: MTProxy-аутентификация без случайного паддинга.
        return raw, raw
    if len(raw) == 17 and raw[0] == 0xDD:
        # use_random_padding(): префикс сохраняется в HMAC-выводе capability.
        return raw, raw[1:]
    if raw[:1] == b"\xee":
        raise ValueError(
            "FakeTLS (ee) secrets are not supported in WEB mode: the relay "
            "terminates plain/dd MTProxy streams; use a direct tg://proxy link"
        )
    raise ValueError(
        f"Unrecognized WEB secret format (len={len(raw)}): expected "
        f"16 bytes (plain) or 17 bytes (0xDD + key)"
    )


def parse_web_link(link: str) -> WebProxyLink:
    """Parse ``tg://webproxy?server=...&secret=...`` into a :class:`WebProxyLink`.

    Порт в ссылке отсутствует (или равен 443); HTTPS фиксирован типом прокси.

    Raises:
        ValueError: server/secret отсутствуют, порт ≠ 443, невалидный
            hostname или секрет неподдерживаемого формата.
    """
    parsed = urlparse(link.strip())
    params = parse_qs(parsed.query)

    if not params.get("server") or not params.get("secret"):
        raise ValueError(
            "Invalid WEB proxy link: server or secret is missing"
        )

    host = _normalize_web_host(params["server"][0])

    if params.get("port"):
        try:
            port = int(params["port"][0])
        except ValueError as e:
            raise ValueError(
                f"Invalid WEB proxy link port: {params['port'][0]!r}"
            ) from e
        if port != 443:
            raise ValueError(
                f"WEB proxy endpoint is always https on port 443, got {port}"
            )

    secret, key = _decode_web_secret(params["secret"][0])
    capability = derive_web_capability(host, secret)
    return WebProxyLink(
        host=host,
        port=443,
        secret=secret,
        secret_key=key,
        is_padded=len(secret) == 17,
        capability=capability,
    )


def is_web_proxy_link(url: str) -> bool:
    """Check whether ``url`` is a ``tg://webproxy`` / ``t.me/webproxy`` link."""
    url = url.strip().lower()
    return url.startswith("tg://webproxy") or "t.me/webproxy" in url


def is_mtproto_link(url: str) -> bool:
    """Check whether ``url`` is an MTProto proxy link of either type.

    Covers classic ``tg://proxy`` / ``t.me/proxy`` and WEB-type
    ``tg://webproxy`` / ``t.me/webproxy`` links.
    """
    url = url.strip().lower()
    if url.startswith("tg://proxy") or "t.me/proxy" in url:
        return True
    return is_web_proxy_link(url)


def needs_padded_transport(url: str) -> bool:
    """Determine whether an MTProto link requires the padded intermediate transport.

    Secret-type to transport mapping (mirrors TDLib ``ObfuscatedTransport::init``
    + ``ProxySecret::emulate_tls`` / ``use_random_padding``):
        - 0xEE + 16 + domain → FakeTLS + padded      → True
        - 0xDD + 16          → obfuscated2 + padded   → True
        - bare 16 bytes      → obfuscated2 + abridged → False

    For WEB links only plain/dd secrets exist: dd → True (padded),
    plain → False (abridged).

    For non-MTProto URLs always returns False (direct transport).

    Args:
        url: ``tg://proxy?...``, ``https://t.me/proxy?...``,
             ``tg://webproxy?...`` or ``https://t.me/webproxy?...`` link.

    Returns:
        True if the client should use ``TCPIntermediatePadded``; False if
        ``TCPAbridged`` (or direct transport for non-MTProto URLs).

    Raises:
        ValueError: the link is invalid or the secret is unrecognized
            (propagated from :func:`parse_tg_link` / :func:`parse_web_link`
            / :func:`parse_secret`).
    """
    if is_web_proxy_link(url):
        return parse_web_link(url).is_padded
    if not is_mtproto_link(url):
        return False
    link = parse_tg_link(url)
    return link.expected_tag == TAG_PADDED_INTERMEDIATE
