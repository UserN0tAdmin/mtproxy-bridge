#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Тесты разбора WEB Proxy ссылок и bridge-capability.

Capability-векторы — официальные из PROTOCOL.md («Bridge URL»).
"""

import base64
import hashlib
import hmac

import pytest

from mtproxy_bridge import (
    is_mtproto_link,
    is_web_proxy_link,
    needs_padded_transport,
)
from mtproxy_bridge.links import (
    derive_web_capability,
    parse_tg_link,
    parse_web_link,
)

HOST = "proxy.example.com"
PLAIN_HEX = "000102030405060708090a0b0c0d0e0f"
DD_HEX = "dd" + PLAIN_HEX
CAP_PLAIN = "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"
CAP_DD = "IpJrt3e7sKtzPyoXy6w-Zj6GGEvsvclN66JzQEfPYLA"


class TestCapabilityVectors:
    """Официальные тестовые векторы протокола v1."""

    def test_plain_secret(self):
        assert derive_web_capability(HOST, bytes.fromhex(PLAIN_HEX)) == CAP_PLAIN

    def test_dd_secret_keeps_prefix_in_hmac(self):
        assert derive_web_capability(HOST, bytes.fromhex(DD_HEX)) == CAP_DD

    def test_reference_construction_matches_spec_formula(self):
        # Независимая сборка формулы из PROTOCOL.md.
        secret = bytes.fromhex(DD_HEX)
        context = f"tdesktop-web-proxy-bridge-v1\n{HOST}".encode()
        digest = hmac.new(secret, context, hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        assert derive_web_capability(HOST, secret) == expected


class TestParseWebLink:
    def test_tg_scheme_plain(self):
        link = f"tg://webproxy?server={HOST}&secret={PLAIN_HEX}"
        parsed = parse_web_link(link)
        assert parsed.host == HOST
        assert parsed.port == 443
        assert parsed.secret == bytes.fromhex(PLAIN_HEX)
        assert parsed.secret_key == parsed.secret
        assert not parsed.is_padded
        assert parsed.capability == CAP_PLAIN

    def test_tme_scheme_dd(self):
        link = f"https://t.me/webproxy?server={HOST}&secret={DD_HEX}"
        parsed = parse_web_link(link)
        assert parsed.is_padded
        assert parsed.secret_key == bytes.fromhex(PLAIN_HEX)
        assert parsed.capability == CAP_DD

    def test_port_443_tolerated(self):
        link = f"tg://webproxy?server={HOST}&port=443&secret={PLAIN_HEX}"
        assert parse_web_link(link).port == 443

    def test_non_443_port_rejected(self):
        link = f"tg://webproxy?server={HOST}&port=8443&secret={PLAIN_HEX}"
        with pytest.raises(ValueError, match="443"):
            parse_web_link(link)

    def test_missing_params_rejected(self):
        with pytest.raises(ValueError, match="missing"):
            parse_web_link(f"tg://webproxy?server={HOST}")
        with pytest.raises(ValueError, match="missing"):
            parse_web_link("tg://webproxy?secret=aa")

    def test_ee_secret_rejected_for_web(self):
        ee = "ee" + "00" * 16 + b"example.com".hex()
        link = f"tg://webproxy?server={HOST}&secret={ee}"
        with pytest.raises(ValueError, match="FakeTLS"):
            parse_web_link(link)

    def test_short_secret_rejected(self):
        link = f"tg://webproxy?server={HOST}&secret=aabb"
        with pytest.raises(ValueError, match="WEB secret"):
            parse_web_link(link)

    def test_empty_secret_rejected(self):
        link = f"tg://webproxy?server={HOST}&secret="
        with pytest.raises(ValueError):
            parse_web_link(link)


class TestHostnameNormalization:
    def test_unicode_host_idna_encoded(self):
        # Кириллический домен → A-label; capability обязан считаться от A-label.
        parsed = parse_web_link(
            f"tg://webproxy?server=прокси.рф&secret={PLAIN_HEX}"
        )
        assert parsed.host.startswith("xn--")
        assert parsed.capability == derive_web_capability(
            parsed.host, bytes.fromhex(PLAIN_HEX)
        )

    def test_uppercase_and_trailing_dot_normalized(self):
        parsed = parse_web_link(
            f"tg://webproxy?server=Proxy.Example.COM.&secret={PLAIN_HEX}"
        )
        assert parsed.host == HOST

    def test_invalid_hostname_rejected(self):
        for bad in ("bad host", "-lead", "under_score.example", "", "x" * 300):
            link = f"tg://webproxy?server={bad}&secret={PLAIN_HEX}"
            if bad:
                with pytest.raises(ValueError, match="hostname"):
                    parse_web_link(link)

    def test_base64url_secret_accepted(self):
        raw = bytes.fromhex(DD_HEX)
        b64 = base64.urlsafe_b64encode(raw).decode()  # с паддингом '='
        parsed = parse_web_link(f"tg://webproxy?server={HOST}&secret={b64}")
        assert parsed.secret == raw
        assert parsed.capability == CAP_DD


class TestLinkDetectors:
    def test_is_web_proxy_link(self):
        assert is_web_proxy_link(f"tg://webproxy?server=x&secret={PLAIN_HEX}")
        assert is_web_proxy_link("https://t.me/webproxy?server=x&secret=y")
        assert not is_web_proxy_link("tg://proxy?server=x")
        assert not is_web_proxy_link("socks5://1.2.3.4:1080")

    def test_is_mtproto_link_covers_both_types(self):
        assert is_mtproto_link(f"tg://proxy?server=x&port=443&secret={DD_HEX}")
        assert is_mtproto_link(f"tg://webproxy?server=x&secret={PLAIN_HEX}")

    def test_needs_padded_transport_matrix(self):
        plain = f"tg://webproxy?server={HOST}&secret={PLAIN_HEX}"
        dd = f"https://t.me/webproxy?server={HOST}&secret={DD_HEX}"
        assert needs_padded_transport(dd) is True
        assert needs_padded_transport(plain) is False

    def test_classic_links_still_work(self):
        classic_dd = (
            "tg://proxy?server=1.2.3.4&port=443&secret="
            + DD_HEX
        )
        classic_plain = (
            "tg://proxy?server=1.2.3.4&port=443&secret=" + PLAIN_HEX
        )
        assert needs_padded_transport(classic_dd) is True
        assert needs_padded_transport(classic_plain) is False
        assert len(parse_tg_link(classic_plain).secret_key) == 16
