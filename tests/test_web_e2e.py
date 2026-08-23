#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Сквозной тест: SOCKS5-клиент → мост (tg://webproxy) → mock-релей → эхо.

Проверяет полный путь шага 4: разбор ссылки, подъём start_local_bridge,
SOCKS5-handshake, определение DC по CONNECT-цели, obfuscated2-заголовок,
WEB-поток до релея и обратную дорогу.

Эхо-бэкенд возвращает байты как есть, поэтому клиент получает свой же
трафик: obfuscated2-заголовок (64 байта) после расшифровки превращается в
мусорный префикс фиксированной длины, а всё отправленное после него —
байт-в-байт оригинал.
"""

import asyncio
import os
import time

from test_web_integration import (  # noqa: F401
    HOST,
    echo_server,
    relay,
)

from mtproxy_bridge.links import parse_web_link
from mtproxy_bridge.server import start_local_bridge, stop_all_bridges

_DD_HEX = "dd00112233445566778899aabbccddeeff"


async def test_socks5_web_bridge_end_to_end(relay):  # noqa: F811
    link_str = f"tg://webproxy?server={HOST}&secret={_DD_HEX}"
    # Мок отдаёт bridge-страницу только на точную capability этой ссылки,
    # а бэкенду нужен 16-байтный ключ для server-side obfuscated2.
    web_link = parse_web_link(link_str)
    relay.capability = web_link.capability
    relay.mtproto_secret = web_link.secret_key

    port = await start_local_bridge(
        link_str, listen_port=0,
        web_origin=f"http://127.0.0.1:{relay.port}",
    )
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        # SOCKS5: greeting (no-auth) → CONNECT на настоящий IP DC2.
        writer.write(b"\x05\x01\x00")
        assert await reader.readexactly(2) == b"\x05\x00"
        dc2_ip = bytes([149, 154, 167, 51])
        writer.write(
            b"\x05\x01\x00\x01" + dc2_ip + (443).to_bytes(2, "big")
        )
        reply = await reader.readexactly(10)
        assert reply[:3] == b"\x05\x00\x00"  # succeeded

        # Транспорт padded intermediate (dd-секрет) + нагрузка > 64 КиБ,
        # чтобы пройти через несколько DATA-чанков и WINDOW-грантов.
        payload = os.urandom(70000)
        writer.write(bytes.fromhex("dddddddd") + payload)

        # В obfuscated2 handshake односторонний: сервер шифрует ответ
        # ключами из развёрнутого клиентского init, поэтому мост отдаёт
        # клиенту чистую нагрузку без всякого префикса. Тег транспорта мост
        # не релеит (он закодирован в init-заголовке), как и в прямом режиме.
        received = bytearray()
        while len(received) < len(payload):
            chunk = await asyncio.wait_for(reader.read(262144), timeout=30)
            if not chunk:
                break
            received.extend(chunk)
        assert bytes(received) == payload

        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionResetError, BrokenPipeError):
            pass
    finally:
        await stop_all_bridges()


async def test_socks5_plain_secret_abridged(relay):  # noqa: F401, F811
    """plain-секрет → транспорт abridged (тег 0xEF, leftover = 3 байта)."""
    link_str = f"tg://webproxy?server={HOST}&secret=00112233445566778899aabbccddeeff"
    web_link = parse_web_link(link_str)
    relay.capability = web_link.capability
    relay.mtproto_secret = web_link.secret_key

    port = await start_local_bridge(
        link_str, listen_port=0,
        web_origin=f"http://127.0.0.1:{relay.port}",
    )
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x05\x02\x00\x01")  # предлагаем два метода
        assert await reader.readexactly(2) == b"\x05\x00"
        dc2_ip = bytes([149, 154, 167, 51])
        writer.write(b"\x05\x01\x00\x01" + dc2_ip + (443).to_bytes(2, "big"))
        reply = await reader.readexactly(10)
        assert reply[:3] == b"\x05\x00\x00"

        payload = b"abridged-ping-" * 100
        writer.write(bytes.fromhex("ef") + payload)  # тег EF + данные

        received = bytearray()
        while len(received) < len(payload):
            chunk = await asyncio.wait_for(reader.read(65536), timeout=30)
            if not chunk:
                break
            received.extend(chunk)
        assert bytes(received) == payload

        writer.close()
    finally:
        await stop_all_bridges()


async def test_socks5_client_dies_on_web_open_deadline(relay, monkeypatch):  # noqa: F811
    """Регрессия «плодятся серверы»: при недоступном релее клиент закрывается
    по дедлайну открытия WEB-стрима, а не висит в очереди к bootstrap'у."""
    link_str = f"tg://webproxy?server={HOST}&secret={_DD_HEX}"
    web_link = parse_web_link(link_str)
    relay.capability = web_link.capability
    relay.hold_page = asyncio.Event()  # bootstrap никогда не завершается

    monkeypatch.setattr("mtproxy_bridge.relay.WEB_STREAM_OPEN_TIMEOUT_SECS", 0.3)

    port = await start_local_bridge(
        link_str, listen_port=0,
        web_origin=f"http://127.0.0.1:{relay.port}",
    )
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x05\x01\x00")
        assert await reader.readexactly(2) == b"\x05\x00"
        dc2_ip = bytes([149, 154, 167, 51])
        writer.write(b"\x05\x01\x00\x01" + dc2_ip + (443).to_bytes(2, "big"))
        reply = await reader.readexactly(10)
        assert reply[:3] == b"\x05\x00\x00"
        writer.write(bytes.fromhex("dddddddd") + b"x" * 16)

        started = time.monotonic()
        chunk = await asyncio.wait_for(reader.read(1024), timeout=10)
        elapsed = time.monotonic() - started
        assert chunk == b""  # мост сам закрыл соединение (EOF)
        assert elapsed < 5   # быстро, а не после минут retry-циклов
    finally:
        relay.hold_page.set()  # отпускаем обработчик релея перед уборкой
        await stop_all_bridges()
