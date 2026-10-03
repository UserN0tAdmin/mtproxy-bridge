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


class TestWebLinkWithPath:
    """WEB-релей под путём (``server=host/path``): v2-capability и 0x70-секрет."""

    PATH_HOST = "wow.shipfasterlabs.com"
    PATH = "api/stream"
    KEY_HEX = "f8861a4ae3f60879a73f33afdc4eeccb"
    DD_KEY_HEX = "dd" + KEY_HEX

    @staticmethod
    def _mark(secret_hex: str) -> str:
        raw = b"\x70" + bytes.fromhex(secret_hex)
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def test_real_world_link_parses(self):
        link = (
            "tg://webproxy?server=wow.shipfasterlabs.com%2Fapi%2Fstream"
            "&secret=cN34hhpK4_YIeac_M6_cTuzL"
        )
        parsed = parse_web_link(link)
        assert parsed.host == self.PATH_HOST
        assert parsed.path == self.PATH
        assert parsed.address == f"{self.PATH_HOST}/{self.PATH}"
        assert parsed.origin == f"https://{self.PATH_HOST}/{self.PATH}"
        assert parsed.secret == bytes.fromhex(self.DD_KEY_HEX)
        assert parsed.secret_key == bytes.fromhex(self.KEY_HEX)
        assert parsed.is_padded is True

    def test_capability_uses_v2_context(self):
        secret = bytes.fromhex(self.DD_KEY_HEX)
        context = (
            f"tdesktop-web-proxy-bridge-v2\n{self.PATH_HOST}\n{self.PATH}"
        ).encode()
        digest = hmac.new(secret, context, hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        link = (
            f"tg://webproxy?server={self.PATH_HOST}/{self.PATH}"
            f"&secret={self._mark(self.DD_KEY_HEX)}"
        )
        parsed = parse_web_link(link)
        assert parsed.capability == expected
        assert derive_web_capability(
            self.PATH_HOST, secret, self.PATH
        ) == expected

    def test_plain_marked_secret(self):
        link = (
            f"tg://webproxy?server={self.PATH_HOST}/a/b"
            f"&secret={self._mark(self.KEY_HEX)}"
        )
        parsed = parse_web_link(link)
        assert parsed.path == "a/b"
        assert parsed.is_padded is False
        assert parsed.secret == bytes.fromhex(self.KEY_HEX)

    def test_path_without_marker_rejected(self):
        for secret in (self.KEY_HEX, self.DD_KEY_HEX):
            link = (
                f"tg://webproxy?server={self.PATH_HOST}/{self.PATH}"
                f"&secret={secret}"
            )
            with pytest.raises(ValueError, match="marked secret"):
                parse_web_link(link)

    def test_invalid_paths_rejected(self):
        secret = self._mark(self.DD_KEY_HEX)
        for bad in ("a/", "/a", "a//b", "-a", "a b", "a." + "x", "x" * 129):
            link = f"tg://webproxy?server={self.PATH_HOST}/{bad}&secret={secret}"
            with pytest.raises(ValueError, match="path"):
                parse_web_link(link)

    def test_root_link_unchanged(self):
        parsed = parse_web_link(
            f"tg://webproxy?server={HOST}&secret={PLAIN_HEX}"
        )
        assert parsed.path == ""
        assert parsed.origin == f"https://{HOST}"
        assert parsed.capability == CAP_PLAIN


class TestBasePathOfficialVectors:
    """Векторы и пример из tproxy-server BASE_PATH.md §1 и §3."""

    H = "proxy.example.com"
    P = "dobry-cola-super-app"
    PLAIN = bytes.fromhex(PLAIN_HEX)

    def test_v2_plain_vector(self):
        assert derive_web_capability(self.H, self.PLAIN, self.P) == (
            "hHz99Xs93EN1j91G9gpNepXwGNNt5YdAFkEVk_LlqdQ"
        )

    def test_v2_dd_vector(self):
        assert derive_web_capability(
            self.H, b"\xdd" + self.PLAIN, self.P
        ) == "TGUkZaevsavLbHvlNWipnRoYxgzZ51ioWvbxgGT3wHo"

    def test_link_end_to_end_matches_vector(self):
        marked = (
            base64.urlsafe_b64encode(b"\x70" + b"\xdd" + self.PLAIN)
            .rstrip(b"=")
            .decode()
        )
        parsed = parse_web_link(
            f"tg://webproxy?server={self.H}%2F{self.P}&secret={marked}"
        )
        assert parsed.capability == (
            "TGUkZaevsavLbHvlNWipnRoYxgzZ51ioWvbxgGT3wHo"
        )

    def test_documented_marked_secret_example(self):
        parsed = parse_web_link(
            "tg://webproxy?server=example.com%2Fphcf2vfe7zgbrslg"
            "&secret=cIVhlEBk_HMMv6RHNWLY7Fk"
        )
        assert parsed.secret == bytes.fromhex(
            "8561944064fc730cbfa4473562d8ec59"
        )

    def test_path_is_case_sensitive(self):
        marked = "cIVhlEBk_HMMv6RHNWLY7Fk"
        a = parse_web_link(f"tg://webproxy?server=example.com/AbC&secret={marked}")
        b = parse_web_link(f"tg://webproxy?server=example.com/abc&secret={marked}")
        assert a.path == "AbC" and b.path == "abc"
        assert a.capability != b.capability

    def test_newline_inside_path_rejected(self):
        marked = "cIVhlEBk_HMMv6RHNWLY7Fk"
        with pytest.raises(ValueError, match="path"):
            parse_web_link(
                f"tg://webproxy?server=example.com%2Fabc%0Adef&secret={marked}"
            )
