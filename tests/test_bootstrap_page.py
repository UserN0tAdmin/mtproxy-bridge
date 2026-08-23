#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Тесты разбора bridge-страницы (bootstrap/carrier-mode/batch-limit).

Шаблоны воспроизводят реальные рендеры обоих серверов:
tproxy-server (internal/bridge/page.go) и Telemt (src/web/bridge.rs).
"""

import pytest

from mtproxy_bridge.web.bootstrap import parse_bridge_page
from mtproxy_bridge.web.http_api import BootstrapRejected

TOKEN = "MHLEY5PmW1GWqJkSrlmJpvJUiLhBH_QKy6yKg8a0JPk"


def _go_page(mode: str, token: str = TOKEN) -> str:
    # Рендер tproxy-server: двойные кавычки, имя carrierMode.
    return (
        "<!doctype html><script>"
        f'const relayOrigin="https://proxy.example.com",'
        f'bootstrap="{token}",carrierMode="{mode}";'
        "</script><script>let batchLimit=2097152;</script>"
    )


def _telemt_page(mode: str, token: str = TOKEN) -> str:
    # Рендер Telemt: одинарные кавычки, имя без «mode», плюс queueLimit.
    return (
        "<!doctype html><script>"
        "const relayOrigin='https://proxy.example.com',"
        f"bootstrap='{token}',carrier='{mode}';"
        "const batchLimit=2097152,queueLimit=33554432,queueItemLimit=16384;"
        "</script>"
    )


class TestCarrierModes:
    @pytest.mark.parametrize(
        "page_factory",
        [_go_page, _telemt_page],
        ids=["tproxy-server", "telemt"],
    )
    @pytest.mark.parametrize(
        "mode",
        ["https", "https-lanes", "websocket", "websocket-lanes"],
    )
    def test_both_server_templates(self, page_factory, mode):
        page = parse_bridge_page(page_factory(mode))
        assert page.token == TOKEN
        assert page.carrier_mode == mode
        assert page.batch_limit == 2 * 1024 * 1024

    def test_comparison_lines_do_not_hijack(self):
        # Сравнения в JS обеих страниц не должны перехватывать поиск:
        # тройной '=' и закрывающая скобка ломают шаблон значения.
        html = (
            _telemt_page("websocket-lanes")
            + "<script>if(carrier==='websocket')x();"
            "if(response.headers.get('X-Carrier-Mode')!==carrier)"
            "throw new Error('session creation rejected');</script>"
        )
        assert parse_bridge_page(html).carrier_mode == "websocket-lanes"

    def test_unknown_mode_rejected(self):
        with pytest.raises(BootstrapRejected, match="unknown carrier mode"):
            parse_bridge_page(_go_page("smtp"))

    def test_missing_mode_rejected(self):
        html = f'const relayOrigin="https://h",bootstrap="{TOKEN}";'
        with pytest.raises(BootstrapRejected, match="carrier mode"):
            parse_bridge_page(html)


class TestBatchLimit:
    def test_go_style_assignment(self):
        assert parse_bridge_page(_go_page("https")).batch_limit == 2 * 1024 * 1024

    def test_snake_case_json_tolerated(self):
        html = (
            f"bootstrap: '{TOKEN}', 'carrier_mode': 'https', "
            '"batch_limit": 262144'
        )
        assert parse_bridge_page(html).batch_limit == 256 * 1024

    def test_missing_defaults_to_2mib(self):
        html = f'const bootstrap="{TOKEN}",carrierMode="https";'
        assert parse_bridge_page(html).batch_limit == 2 * 1024 * 1024

    def test_clamped_to_desktop_ceiling_and_floor(self):
        big = f'let batchLimit={16 * 1024 * 1024};' + _go_page("https")
        assert parse_bridge_page(big).batch_limit == 2 * 1024 * 1024
        small = 'let batchLimit=1024;' + _go_page("https")
        assert parse_bridge_page(small).batch_limit == 64 * 1024


class TestTokenExtraction:
    def test_single_quotes_and_double_quotes(self):
        for page in (_go_page("https"), _telemt_page("https")):
            assert parse_bridge_page(page).token == TOKEN

    def test_wrong_token_shape_rejected(self):
        with pytest.raises(BootstrapRejected, match="bootstrap token"):
            parse_bridge_page(_go_page("https", token="short"))
