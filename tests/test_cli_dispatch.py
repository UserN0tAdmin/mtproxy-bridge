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

"""Диспетчер CLI и check: тип ссылки обязан определяться одним предикатом.

Регрессия: cli.py и check.py дублировали ``is_web_proxy_link`` узким
``startswith(("tg://webproxy", "https://t.me/webproxy"))``, из-за чего
``t.me/webproxy?...``, ``http://t.me/webproxy?...`` и ссылки с путём
падали в classic-путь и умирали с «Invalid link: server, port or secret
is missing», хотя библиотечный start_local_bridge() их принимал.
"""

from __future__ import annotations

import asyncio
import base64
import sys

import pytest

from mtproxy_bridge import check as check_mod
from mtproxy_bridge import cli
from mtproxy_bridge.check import check_link
from mtproxy_bridge.links import is_web_proxy_link, parse_tg_link

HOST = "proxy.example.com"
PLAIN_HEX = "00112233445566778899aabbccddeeff"
DD_HEX = "dd" + PLAIN_HEX

# Маркированный секрет для ссылки с путём: base64url-nopad(0x70 + secret).
# Android-расширение шлёт именно его — обычный dd/plain префикс релей
# под путём отвергает.
_MARKED_SECRET = (
    base64.urlsafe_b64encode(b"\x70" + bytes.fromhex(PLAIN_HEX))
    .rstrip(b"=")
    .decode("ascii")
)

# Все формы WEB-ссылки, встречающиеся в природе: схема tg://, схемы t.me
# (включая http, которым делятся в мессенджерах), schemeless-форма и
# ссылка с путём релея.
WEB_LINKS = [
    f"tg://webproxy?server={HOST}&secret={DD_HEX}",
    f"https://t.me/webproxy?server={HOST}&secret={DD_HEX}",
    f"http://t.me/webproxy?server={HOST}&secret={DD_HEX}",
    f"t.me/webproxy?server={HOST}&secret={DD_HEX}",
    f"tg://webproxy?server={HOST}/bridge&secret={_MARKED_SECRET}",
]

DIRECT_LINK = f"tg://proxy?server=1.2.3.4&port=443&secret={DD_HEX}"


@pytest.mark.parametrize("link", WEB_LINKS)
def test_cli_routes_web_links_to_web_mode(link, monkeypatch):
    """CLI: WEB-ссылка обязана дать BridgeConfig с web_link и туннель."""
    captured: dict = {}

    async def fake_run_bridge(cfg, *, web_tunnel=None):
        captured["cfg"] = cfg
        captured["tunnel"] = web_tunnel

    monkeypatch.setattr(cli, "run_bridge", fake_run_bridge)
    monkeypatch.setattr(sys, "argv", ["mtproxy-bridge", link, "--listen-port", "0"])

    cli.main()

    cfg = captured["cfg"]
    assert cfg.web_link is not None, "CLI не распознал WEB-ссылку"
    assert cfg.upstream_host == "", "WEB-режим не должен иметь upstream TCP"
    # Туннель создаётся ровно тогда, когда ссылка WEB — иначе relay.py
    # упадёт с «WEB link without an initialized tunnel».
    assert captured["tunnel"] is not None


def test_cli_routes_direct_links_to_direct_mode(monkeypatch):
    """Контроль: classic tg://proxy остаётся в direct-пути."""
    captured: dict = {}

    async def fake_run_bridge(cfg, *, web_tunnel=None):
        captured["cfg"] = cfg
        captured["tunnel"] = web_tunnel

    monkeypatch.setattr(cli, "run_bridge", fake_run_bridge)
    monkeypatch.setattr(
        sys, "argv", ["mtproxy-bridge", DIRECT_LINK, "--listen-port", "0"]
    )

    cli.main()

    cfg = captured["cfg"]
    assert cfg.web_link is None
    assert cfg.upstream_host == "1.2.3.4"
    assert cfg.upstream_port == 443
    assert captured["tunnel"] is None


@pytest.mark.parametrize("link", WEB_LINKS)
def test_check_dispatch_agrees_with_library(link, monkeypatch):
    """check_link: режим определяется тем же предикатом, что и библиотека.

    _run_web/_run_direct подменяем заглушками — важен только вызванный
    режим, не сетевой обмен.
    """
    calls: list[str] = []

    async def fake_run_web(parsed, collector, **kwargs):
        calls.append("web")

    async def fake_run_direct(parsed, collector, **kwargs):
        calls.append("direct")

    monkeypatch.setattr(check_mod, "_run_web", fake_run_web)
    monkeypatch.setattr(check_mod, "_run_direct", fake_run_direct)

    result = asyncio.run(check_link(link))

    assert calls == ["web"], f"check ушёл не в WEB-путь для {link}"
    assert result.mode == "web"


def test_check_direct_mode_for_proxy_links(monkeypatch):
    calls: list[str] = []

    async def fake_run_web(parsed, collector, **kwargs):
        calls.append("web")

    async def fake_run_direct(parsed, collector, **kwargs):
        calls.append("direct")

    monkeypatch.setattr(check_mod, "_run_web", fake_run_web)
    monkeypatch.setattr(check_mod, "_run_direct", fake_run_direct)

    result = asyncio.run(check_link(DIRECT_LINK))

    assert calls == ["direct"]
    assert result.mode == "direct"


@pytest.mark.parametrize(
    "link",
    [
        *WEB_LINKS,
        # Регистр и пробелы: предикат нормализует, диспетчер обязан согласиться.
        f"TG://WEBPROXY?server={HOST}&secret={DD_HEX}",
        f"  https://t.me/webproxy?server={HOST}&secret={DD_HEX}  ",
        DIRECT_LINK,
        "https://t.me/proxy?server=1.2.3.4&port=443&secret=" + DD_HEX,
    ],
)
def test_predicate_and_dispatcher_never_disagree(link):
    """Где предикат сказал «WEB», классический парсер не должен вызываться.

    Именно это расхождение и было багом: dispatcher гнал t.me/webproxy в
    parse_tg_link, тот падал на отсутствующем port.
    """
    if not is_web_proxy_link(link):
        pytest.skip("не WEB-ссылка — поведение dispatcher'а проверяется выше")
    with pytest.raises(ValueError):
        parse_tg_link(link)
