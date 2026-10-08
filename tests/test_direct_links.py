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

"""Тесты разбора классических ссылок/секретов MTProxy (tg://proxy).

Покрывают: все три типа секрета (bare / dd / ee), hex и base64url формы,
границы длин (в т.ч. «16 байт, начинающиеся с 0xDD, — это bare-ключ»),
ссылки ``tg://`` и ``https://t.me/``, детекторы ``is_mtproto_link`` /
``needs_padded_transport`` и обещание README «direct-режим работает без
extra ``[web]``» (проверка в отдельном процессе с заблокированным aiohttp).
"""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import mtproxy_bridge
from mtproxy_bridge.links import (
    ProxyLink,
    is_mtproto_link,
    is_web_proxy_link,
    needs_padded_transport,
    parse_secret,
    parse_tg_link,
)
from mtproxy_bridge.obfuscated2 import TAG_ABRIDGED, TAG_PADDED_INTERMEDIATE

ROOT = Path(__file__).resolve().parent.parent

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
DOMAIN = "cdn.example.com"

BARE_HEX = KEY.hex()
DD_HEX = "dd" + KEY.hex()
EE_HEX = "ee" + KEY.hex() + DOMAIN.encode().hex()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# ============================================================================
# parse_secret
# ============================================================================


class TestParseSecretTypes:
    def test_bare_16_bytes_is_abridged(self):
        key, domain, fake_tls, tag = parse_secret(BARE_HEX)
        assert (key, domain, fake_tls, tag) == (KEY, "", False, TAG_ABRIDGED)

    def test_dd_is_padded_intermediate(self):
        key, domain, fake_tls, tag = parse_secret(DD_HEX)
        assert (key, domain, fake_tls, tag) == (KEY, "", False, TAG_PADDED_INTERMEDIATE)

    def test_ee_is_faketls_with_domain(self):
        key, domain, fake_tls, tag = parse_secret(EE_HEX)
        assert key == KEY
        assert domain == DOMAIN
        assert fake_tls is True
        assert tag == TAG_PADDED_INTERMEDIATE

    def test_uppercase_hex_and_whitespace(self):
        assert parse_secret(f"  {BARE_HEX.upper()}\n")[0] == KEY

    @pytest.mark.parametrize(
        "hex_secret", [BARE_HEX, DD_HEX, EE_HEX], ids=["bare", "dd", "ee"]
    )
    def test_base64url_equals_hex(self, hex_secret):
        encoded = _b64url(bytes.fromhex(hex_secret))
        # Охранное условие: строка не должна случайно оказаться «hex-подобной»,
        # иначе парсер (как и TDLib) по эвристике прочитает её как hex.
        assert not set(encoded) <= set("0123456789abcdefABCDEF")
        assert parse_secret(encoded) == parse_secret(hex_secret)

    def test_base64_with_padding_accepted(self):
        padded = base64.urlsafe_b64encode(bytes.fromhex(EE_HEX)).decode()
        assert parse_secret(padded) == parse_secret(EE_HEX)


class TestParseSecretBoundaries:
    def test_16_bytes_starting_with_dd_is_a_bare_key(self):
        # Тип секрета определяется длиной: ровно 16 байт — всегда bare,
        # даже если первый байт случайно равен 0xDD (семантика TDLib).
        raw = b"\xdd" + bytes(15)
        key, _domain, fake_tls, tag = parse_secret(raw.hex())
        assert (key, fake_tls, tag) == (raw, False, TAG_ABRIDGED)

    def test_16_bytes_starting_with_ee_is_a_bare_key(self):
        raw = b"\xee" + bytes(15)
        key, _domain, fake_tls, tag = parse_secret(raw.hex())
        assert (key, fake_tls, tag) == (raw, False, TAG_ABRIDGED)

    def test_ee_with_one_byte_domain_is_minimum(self):
        key, domain, fake_tls, _tag = parse_secret("ee" + KEY.hex() + "61")
        assert (key, domain, fake_tls) == (KEY, "a", True)

    def test_ee_domain_of_182_bytes_accepted(self):
        domain = "a" * 182
        assert parse_secret("ee" + KEY.hex() + domain.encode().hex())[1] == domain

    @pytest.mark.parametrize(
        ("secret", "message"),
        [
            ("", "Empty secret"),
            ("%%%%", "Empty secret"),
            ("00" * 15, "Unrecognized secret format"),
            ("11" + "00" * 16, "Unrecognized secret format"),
            ("00" * 32, "Unrecognized secret format"),
            ("dd" + "00" * 17, "exactly 17"),
            ("ee" + "00" * 16, "≥18 bytes"),
            ("ee" + "00" * 16 + "c3a9", "ASCII"),
            ("ee" + "00" * 16 + "61" * 183, "too long"),
        ],
        ids=[
            "empty",
            "garbage-base64",
            "15-bytes",
            "17-bytes-wrong-prefix",
            "32-bytes-wrong-prefix",
            "dd-too-long",
            "ee-no-domain",
            "ee-non-ascii-domain",
            "ee-domain-183",
        ],
    )
    def test_invalid_secrets_raise_value_error(self, secret, message):
        with pytest.raises(ValueError, match=message):
            parse_secret(secret)


# ============================================================================
# parse_tg_link
# ============================================================================


class TestParseTgLink:
    @pytest.mark.parametrize(
        ("secret", "fake_tls", "tag"),
        [
            (BARE_HEX, False, TAG_ABRIDGED),
            (DD_HEX, False, TAG_PADDED_INTERMEDIATE),
            (EE_HEX, True, TAG_PADDED_INTERMEDIATE),
        ],
        ids=["bare", "dd", "ee"],
    )
    @pytest.mark.parametrize(
        "template",
        [
            "tg://proxy?server=proxy.example.org&port=8443&secret={s}",
            "https://t.me/proxy?server=proxy.example.org&port=8443&secret={s}",
            "TG://PROXY?server=proxy.example.org&port=8443&secret={s}",
        ],
        ids=["tg", "tme", "uppercase-scheme"],
    )
    def test_fields(self, template, secret, fake_tls, tag):
        link = parse_tg_link(template.format(s=secret))
        assert isinstance(link, ProxyLink)
        assert link.server == "proxy.example.org"
        assert link.port == 8443
        assert link.secret_key == KEY
        assert link.is_fake_tls is fake_tls
        assert link.expected_tag == tag
        assert link.domain == (DOMAIN if fake_tls else "")

    def test_parameter_order_and_extra_params_do_not_matter(self):
        link = parse_tg_link(f"tg://proxy?secret={BARE_HEX}&utm=x&port=443&server=h.io")
        assert (link.server, link.port, link.secret_key) == ("h.io", 443, KEY)

    def test_base64url_secret_in_link(self):
        link = parse_tg_link(
            f"tg://proxy?server=h.io&port=443&secret={_b64url(bytes.fromhex(EE_HEX))}"
        )
        assert link.is_fake_tls and link.domain == DOMAIN

    @pytest.mark.parametrize(
        "query",
        [
            f"port=443&secret={BARE_HEX}",
            f"server=h.io&secret={BARE_HEX}",
            "server=h.io&port=443",
            "server=h.io&port=443&secret=",
            "",
        ],
        ids=["no-server", "no-port", "no-secret", "empty-secret", "no-query"],
    )
    def test_missing_parameters(self, query):
        with pytest.raises(ValueError, match="missing"):
            parse_tg_link(f"tg://proxy?{query}")

    def test_non_numeric_port(self):
        with pytest.raises(ValueError):
            parse_tg_link(f"tg://proxy?server=h.io&port=abc&secret={BARE_HEX}")

    def test_bad_secret_propagates_value_error(self):
        with pytest.raises(ValueError, match="Unrecognized"):
            parse_tg_link("tg://proxy?server=h.io&port=443&secret=" + "00" * 15)


# ============================================================================
# Детекторы
# ============================================================================


class TestDetectors:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("tg://proxy?server=h&port=1&secret=00", True),
            ("https://t.me/proxy?server=h&port=1&secret=00", True),
            ("TG://Proxy?server=h", True),
            ("  tg://proxy?server=h", True),
            ("tg://webproxy?server=h&secret=00", True),
            ("https://t.me/webproxy?server=h&secret=00", True),
            ("socks5://127.0.0.1:1080", False),
            ("http://example.com/proxy", False),
            ("tg://socks?server=h&port=1", False),
            ("", False),
        ],
    )
    def test_is_mtproto_link(self, url, expected):
        assert is_mtproto_link(url) is expected

    def test_classic_links_are_not_web_links(self):
        assert not is_web_proxy_link(f"tg://proxy?server=h&port=443&secret={BARE_HEX}")
        assert not is_web_proxy_link(
            f"https://t.me/proxy?server=h&port=443&secret={BARE_HEX}"
        )

    @pytest.mark.parametrize(
        ("secret", "expected"),
        [(BARE_HEX, False), (DD_HEX, True), (EE_HEX, True)],
        ids=["bare-abridged", "dd-padded", "ee-padded"],
    )
    @pytest.mark.parametrize(
        "scheme", ["tg://proxy", "https://t.me/proxy"], ids=["tg", "tme"]
    )
    def test_needs_padded_transport(self, scheme, secret, expected):
        url = f"{scheme}?server=h.io&port=443&secret={secret}"
        assert needs_padded_transport(url) is expected

    def test_non_mtproto_url_never_needs_padded(self):
        assert needs_padded_transport("socks5://127.0.0.1:1080") is False

    def test_invalid_secret_raises(self):
        with pytest.raises(ValueError):
            needs_padded_transport(
                "tg://proxy?server=h.io&port=443&secret=" + "00" * 15
            )

    def test_transport_agrees_with_parsed_expected_tag(self):
        for secret in (BARE_HEX, DD_HEX, EE_HEX):
            url = f"tg://proxy?server=h.io&port=443&secret={secret}"
            padded = parse_tg_link(url).expected_tag == TAG_PADDED_INTERMEDIATE
            assert needs_padded_transport(url) is padded


# ============================================================================
# Публичный API
# ============================================================================


def test_public_api_names_are_importable():
    for name in mtproxy_bridge.__all__:
        assert hasattr(mtproxy_bridge, name), name


_NO_AIOHTTP_SCRIPT = textwrap.dedent(
    """
    import asyncio, sys

    sys.modules["aiohttp"] = None  # import aiohttp -> ImportError

    import mtproxy_bridge
    from mtproxy_bridge import needs_padded_transport, start_local_bridge, stop_all_bridges

    assert needs_padded_transport(
        "tg://proxy?server=1.2.3.4&port=443&secret=dd" + "00" * 16
    ) is True

    async def main():
        port = await start_local_bridge(
            "tg://proxy?server=127.0.0.1&port=1&secret=" + "00" * 16
        )
        assert isinstance(port, int) and port > 0
        await stop_all_bridges()

    asyncio.run(main())
    leaked = [m for m in sys.modules if m.startswith("mtproxy_bridge.web")]
    assert not leaked, leaked
    print("OK")
    """
)


def test_direct_mode_works_without_web_extra():
    """README: «Direct mode (tg://proxy) always works» — без aiohttp."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-c", _NO_AIOHTTP_SCRIPT],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0 and "OK" in proc.stdout, proc.stderr
