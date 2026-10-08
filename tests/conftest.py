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

"""Общие фикстуры для тестов классического MTProxy (direct-режим).

Живут здесь, а не в ``direct_fakes``: фикстура, импортированная в тестовый
модуль по имени, затеняется параметрами тестовых функций с тем же именем
(ruff F811). Из conftest'а она видна всем тестам каталога без импорта.
"""

from __future__ import annotations

import pytest
from direct_fakes import FakeMTProxy, ScriptedServer

from mtproxy_bridge.server import start_local_bridge, stop_all_bridges


@pytest.fixture
async def proxy_factory():
    """Фабрика FakeMTProxy; все созданные серверы останавливаются в teardown."""
    proxies: list[FakeMTProxy] = []

    async def make(**kwargs) -> FakeMTProxy:
        proxy = FakeMTProxy(**kwargs)
        await proxy.start()
        proxies.append(proxy)
        return proxy

    yield make
    for proxy in proxies:
        await proxy.stop()


@pytest.fixture
async def scripted_factory():
    servers: list[ScriptedServer] = []

    async def make(*args, **kwargs) -> ScriptedServer:
        server = ScriptedServer(*args, **kwargs)
        await server.start()
        servers.append(server)
        return server

    yield make
    for server in servers:
        await server.stop()


@pytest.fixture
async def bridge_factory():
    """``await start(link, **kw) -> port``; в teardown — stop_all_bridges()."""
    yield start_local_bridge
    await stop_all_bridges()
