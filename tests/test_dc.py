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

"""Тесты определения DC ID (``dc.py``) и целостности встроенной таблицы.

DNS в тестах не используется: числовые адреса резолвятся без сети, а для
имён подменяется ``loop.getaddrinfo``.
"""

from __future__ import annotations

import ast
import asyncio
import ipaddress
import socket
from pathlib import Path

import pytest

from mtproxy_bridge import dc
from mtproxy_bridge.dc import KNOWN_CDN_IPS, KNOWN_DC_IPS, guess_dc_id_async

_TABLE_NAMES = ("KNOWN_DC_IPS", "KNOWN_CDN_IPS")


def _addrinfo(*ips: str):
    return [
        (
            socket.AF_INET6 if ":" in ip else socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            (ip, 443),
        )
        for ip in ips
    ]


def _patch_dns(monkeypatch, result=None, error=None):
    """Подменяет getaddrinfo текущего loop'а; возвращает журнал вызовов."""
    calls = []

    async def fake(host, port, **_kw):
        calls.append((host, port))
        if error is not None:
            raise error
        return result

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", fake)
    return calls


# ============================================================================
# Прямой lookup по IP
# ============================================================================


class TestKnownIps:
    @pytest.mark.parametrize(
        ("ip", "dc_id"),
        [
            ("149.154.175.50", 1),
            ("149.154.175.55", 1),
            ("149.154.167.51", 2),
            ("149.154.167.41", 2),
            ("149.154.175.100", 3),
            ("149.154.167.91", 4),
            ("149.154.167.92", 4),
            ("149.154.171.5", 5),
            ("91.108.56.168", 5),
        ],
    )
    async def test_production_ipv4(self, ip, dc_id):
        assert await guess_dc_id_async(ip) == dc_id

    @pytest.mark.parametrize(
        ("ip", "dc_id"),
        [
            ("2001:b28:f23d:f001::a", 1),
            ("2001:67c:4e8:f002::a", 2),
            ("2001:b28:f23d:f003::a", 3),
            ("2001:67c:4e8:f004::a", 4),
            ("2001:b28:f23f:f005::a", 5),
        ],
    )
    async def test_production_ipv6(self, ip, dc_id):
        assert await guess_dc_id_async(ip) == dc_id

    @pytest.mark.parametrize(
        "spelling",
        [
            "2001:067c:04e8:f002:0000:0000:0000:000a",
            "2001:67C:4E8:F002::A",
            "2001:67c:4e8:f002:0:0:0:a",
        ],
        ids=["zero-padded", "uppercase", "partially-compressed"],
    )
    async def test_ipv6_spellings_are_normalized(self, spelling):
        assert await guess_dc_id_async(spelling) == 2

    @pytest.mark.parametrize(
        ("ip", "dc_id"),
        [
            ("149.154.175.10", 10001),
            ("149.154.167.40", 10002),
            ("149.154.175.117", 10003),
            ("2001:b28:f23d:f001::e", 10001),
        ],
    )
    async def test_test_dcs_are_offset_by_10000(self, ip, dc_id):
        assert await guess_dc_id_async(ip) == dc_id

    @pytest.mark.parametrize("ip", ["91.105.192.100", "2a0a:f280:203:a:5000::100"])
    async def test_cdn_dc_is_negative(self, ip):
        assert await guess_dc_id_async(ip) == -203

    async def test_media_only_endpoints_are_positive(self):
        # Намеренное расхождение с TDLib (см. комментарий в dc.py): media_only
        # адреса кодируются ПОЛОЖИТЕЛЬНЫМ DC ID. Тест фиксирует решение, чтобы
        # оно не сменилось незаметно.
        assert await guess_dc_id_async("149.154.167.222") == 2
        assert await guess_dc_id_async("149.154.165.120") == 4
        assert await guess_dc_id_async("2001:67c:4e8:f002::b") == 2
        assert await guess_dc_id_async("2001:67c:4e8:f004::b") == 4

    async def test_known_ip_does_not_touch_dns(self, monkeypatch):
        calls = _patch_dns(monkeypatch, error=AssertionError("DNS must not be used"))
        assert await guess_dc_id_async("149.154.167.51") == 2
        assert await guess_dc_id_async("91.105.192.100") == -203
        assert calls == []


# ============================================================================
# Неизвестные цели и DNS
# ============================================================================


class TestUnknownTargets:
    async def test_unknown_ip_raises_without_fallback_to_dc2(self):
        with pytest.raises(
            ValueError, match="not found in the built-in DC table"
        ) as exc:
            await guess_dc_id_async("8.8.8.8")
        assert "dc-id-override" in str(exc.value)

    async def test_unknown_ipv6_raises(self):
        with pytest.raises(ValueError, match="not found"):
            await guess_dc_id_async("2001:db8::1")

    async def test_hostname_resolving_to_known_ip(self, monkeypatch):
        calls = _patch_dns(monkeypatch, _addrinfo("1.1.1.1", "149.154.167.51"))
        assert await guess_dc_id_async("dc2.example.org") == 2
        assert calls == [("dc2.example.org", 443)]

    async def test_hostname_resolving_to_cdn_ip(self, monkeypatch):
        _patch_dns(monkeypatch, _addrinfo("91.105.192.100"))
        assert await guess_dc_id_async("cdn.example.org") == -203

    async def test_hostname_resolving_to_ipv6_known_ip(self, monkeypatch):
        _patch_dns(monkeypatch, _addrinfo("2001:b28:f23f:f005::a"))
        assert await guess_dc_id_async("dc5-v6.example.org") == 5

    async def test_hostname_resolving_to_unknown_ip(self, monkeypatch):
        _patch_dns(monkeypatch, _addrinfo("1.1.1.1", "8.8.8.8"))
        with pytest.raises(ValueError, match="not found in the built-in DC table"):
            await guess_dc_id_async("example.org")

    async def test_dns_failure_is_value_error_with_hint(self, monkeypatch):
        _patch_dns(monkeypatch, error=socket.gaierror(-2, "Name or service not known"))
        with pytest.raises(ValueError, match="DNS-resolve failed") as exc:
            await guess_dc_id_async("no-such-host.invalid")
        assert "dc_id_override" in str(exc.value)
        assert isinstance(exc.value.__cause__, socket.gaierror)

    async def test_oserror_from_resolver_is_value_error(self, monkeypatch):
        _patch_dns(monkeypatch, error=OSError("resolver unavailable"))
        with pytest.raises(ValueError, match="DNS-resolve failed"):
            await guess_dc_id_async("example.org")


# ============================================================================
# Целостность таблиц
# ============================================================================


class TestTableIntegrity:
    def test_keys_are_valid_canonical_ips(self):
        for table in (KNOWN_DC_IPS, KNOWN_CDN_IPS):
            for key in table:
                # Ключи должны совпадать с формой, к которой lookup нормализует
                # запрос, иначе запись недостижима.
                assert str(ipaddress.ip_address(key)) == key, key

    def test_dc_values_are_known_ids(self):
        allowed = {1, 2, 3, 4, 5, 10001, 10002, 10003}
        assert set(KNOWN_DC_IPS.values()) <= allowed

    def test_every_production_dc_has_ipv4_and_ipv6(self):
        for dc_id in (1, 2, 3, 4, 5):
            ips = [
                ipaddress.ip_address(ip) for ip, d in KNOWN_DC_IPS.items() if d == dc_id
            ]
            assert any(ip.version == 4 for ip in ips), dc_id
            assert any(ip.version == 6 for ip in ips), dc_id

    def test_cdn_table_values_are_cdn_ids(self):
        assert set(KNOWN_CDN_IPS.values()) == {203}

    def test_tables_do_not_overlap(self):
        assert not set(KNOWN_DC_IPS) & set(KNOWN_CDN_IPS)

    @pytest.mark.parametrize("table_name", _TABLE_NAMES)
    def test_no_duplicate_keys_in_source(self, table_name):
        # Дубликат ключа в литерале dict молча перезаписывается; значит, один
        # IP мог бы «переехать» в другой DC при неудачном копипасте.
        tree = ast.parse(Path(dc.__file__).read_text(encoding="utf-8"))
        literal = None
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.AnnAssign)
                and isinstance(node.target, ast.Name)
                and node.target.id == table_name
            ):
                literal = node.value
        assert isinstance(literal, ast.Dict), table_name
        keys = [k.value for k in literal.keys if isinstance(k, ast.Constant)]
        duplicates = sorted({k for k in keys if keys.count(k) > 1})
        assert not duplicates, duplicates
