#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Тесты SOCKS5-handshake локального сервера (no-auth, только CONNECT)."""

from __future__ import annotations

import asyncio
import ipaddress

import pytest

from mtproxy_bridge import socks5
from mtproxy_bridge.socks5 import _socks5_handshake

GREETING = b"\x05\x01\x00"
OK_REPLY = b"\x05\x00\x00\x01" + bytes(4) + bytes(2)
UNSUPPORTED_CMD_REPLY = b"\x05\x07\x00\x01" + bytes(4) + bytes(2)


class _FakeWriter:
    """Минимальный writer: копит отправленное, drain ничего не делает."""

    def __init__(self) -> None:
        self.sent = bytearray()

    def write(self, data: bytes) -> None:
        self.sent += data

    async def drain(self) -> None:
        pass


def _reader(data: bytes, *, eof: bool = True) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    if eof:
        reader.feed_eof()
    return reader


def _connect_ipv4(ip: str, port: int) -> bytes:
    return (
        b"\x05\x01\x00\x01" + ipaddress.IPv4Address(ip).packed + port.to_bytes(2, "big")
    )


def _connect_domain(name: bytes, port: int) -> bytes:
    return b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big")


def _connect_ipv6(ip: str, port: int) -> bytes:
    return (
        b"\x05\x01\x00\x04" + ipaddress.IPv6Address(ip).packed + port.to_bytes(2, "big")
    )


async def _run(data: bytes):
    writer = _FakeWriter()
    result = await _socks5_handshake(_reader(data), writer)
    return result, bytes(writer.sent)


# ============================================================================
# Успешные сценарии
# ============================================================================


class TestSuccess:
    async def test_ipv4_connect(self):
        result, sent = await _run(GREETING + _connect_ipv4("149.154.167.51", 443))
        assert result == ("149.154.167.51", 443)
        assert sent == b"\x05\x00" + OK_REPLY

    async def test_domain_connect(self):
        result, sent = await _run(GREETING + _connect_domain(b"dc2.example.org", 8443))
        assert result == ("dc2.example.org", 8443)
        assert sent == b"\x05\x00" + OK_REPLY

    async def test_ipv6_connect_is_returned_in_compressed_form(self):
        result, _sent = await _run(
            GREETING + _connect_ipv6("2001:67c:4e8:f002::a", 443)
        )
        assert result == ("2001:67c:4e8:f002::a", 443)

    @pytest.mark.parametrize("port", [0, 1, 443, 65535])
    async def test_port_range(self, port):
        (_host, got), _sent = await _run(GREETING + _connect_ipv4("1.2.3.4", port))
        assert got == port

    async def test_no_auth_method_may_be_anywhere_in_the_list(self):
        greeting = b"\x05\x03\x02\x01\x00"
        result, sent = await _run(greeting + _connect_ipv4("1.2.3.4", 1))
        assert result == ("1.2.3.4", 1)
        assert sent.startswith(b"\x05\x00")  # выбран именно no-auth

    async def test_empty_domain_name(self):
        result, _sent = await _run(GREETING + _connect_domain(b"", 80))
        assert result == ("", 80)

    async def test_longest_domain_name(self):
        name = b"a" * 255
        result, _sent = await _run(GREETING + _connect_domain(name, 80))
        assert result[0] == name.decode()

    async def test_bytes_after_request_are_left_in_the_stream(self):
        # Всё, что идёт после CONNECT (транспортный тег и MTProto), остаётся
        # в reader'е нетронутым — мост читает это следующим шагом.
        reader = _reader(GREETING + _connect_ipv4("1.2.3.4", 443) + b"\xef\x01\x02")
        await _socks5_handshake(reader, _FakeWriter())
        assert await reader.read() == b"\xef\x01\x02"

    async def test_reply_is_sent_only_after_the_full_request_is_read(self):
        writer = _FakeWriter()
        reader = asyncio.StreamReader()
        reader.feed_data(GREETING + b"\x05\x01\x00\x01\x01")  # адрес неполный
        task = asyncio.ensure_future(_socks5_handshake(reader, writer))
        await asyncio.sleep(0.05)
        assert bytes(writer.sent) == b"\x05\x00"  # только ответ на greeting
        reader.feed_data(b"\x02\x03\x04\x01\xbb")
        assert await asyncio.wait_for(task, 2) == ("1.2.3.4", 443)
        assert bytes(writer.sent) == b"\x05\x00" + OK_REPLY


# ============================================================================
# Отказы
# ============================================================================


class TestRejections:
    @pytest.mark.parametrize(
        "greeting",
        [b"\x05\x01\x02", b"\x05\x02\x01\x02", b"\x05\x00"],
        ids=["user-pass-only", "gssapi+user-pass", "no-methods"],
    )
    async def test_no_acceptable_method(self, greeting):
        writer = _FakeWriter()
        with pytest.raises(ConnectionError, match="authentication"):
            await _socks5_handshake(_reader(greeting), writer)
        assert bytes(writer.sent) == b"\x05\xff"

    async def test_socks4_greeting(self):
        writer = _FakeWriter()
        with pytest.raises(ValueError, match="greeting"):
            await _socks5_handshake(_reader(b"\x04\x01\x00"), writer)
        assert bytes(writer.sent) == b""

    async def test_wrong_version_in_request(self):
        writer = _FakeWriter()
        bad = b"\x04\x01\x00\x01" + bytes(4) + bytes(2)
        with pytest.raises(ValueError, match="request"):
            await _socks5_handshake(_reader(GREETING + bad), writer)
        assert bytes(writer.sent) == b"\x05\x00"

    @pytest.mark.parametrize("cmd", [0x02, 0x03], ids=["bind", "udp-associate"])
    async def test_unsupported_command_gets_reply_07(self, cmd):
        writer = _FakeWriter()
        request = bytes([5, cmd, 0, 1]) + bytes(4) + bytes(2)
        with pytest.raises(ValueError, match="CMD"):
            await _socks5_handshake(_reader(GREETING + request), writer)
        assert bytes(writer.sent) == b"\x05\x00" + UNSUPPORTED_CMD_REPLY

    @pytest.mark.parametrize("atyp", [0x00, 0x02, 0x05, 0xFF])
    async def test_unsupported_address_type(self, atyp):
        request = bytes([5, 1, 0, atyp]) + bytes(8)
        with pytest.raises(ValueError, match="ATYP"):
            await _socks5_handshake(_reader(GREETING + request), _FakeWriter())

    async def test_non_ascii_domain_is_rejected(self):
        with pytest.raises(ValueError):
            await _socks5_handshake(
                _reader(GREETING + _connect_domain("пример".encode(), 443)),
                _FakeWriter(),
            )

    @pytest.mark.parametrize("cut", range(1, 10))
    async def test_truncated_stream(self, cut):
        data = (GREETING + _connect_ipv4("1.2.3.4", 443))[:-cut]
        with pytest.raises(asyncio.IncompleteReadError):
            await _socks5_handshake(_reader(data), _FakeWriter())

    async def test_empty_stream(self):
        with pytest.raises(asyncio.IncompleteReadError):
            await _socks5_handshake(_reader(b""), _FakeWriter())


# ============================================================================
# Таймауты (защита от slowloris)
# ============================================================================


class TestTimeouts:
    async def test_silent_client_times_out(self, monkeypatch):
        monkeypatch.setattr(socks5, "SOCKS5_HANDSHAKE_TIMEOUT_SECS", 0.1)
        with pytest.raises(ConnectionError, match="timeout"):
            await _socks5_handshake(_reader(b"", eof=False), _FakeWriter())

    async def test_client_stalling_after_greeting_times_out(self, monkeypatch):
        monkeypatch.setattr(socks5, "SOCKS5_HANDSHAKE_TIMEOUT_SECS", 0.1)
        writer = _FakeWriter()
        with pytest.raises(ConnectionError, match="request"):
            await _socks5_handshake(_reader(GREETING, eof=False), writer)
        assert bytes(writer.sent) == b"\x05\x00"

    async def test_client_stalling_inside_the_address_times_out(self, monkeypatch):
        monkeypatch.setattr(socks5, "SOCKS5_HANDSHAKE_TIMEOUT_SECS", 0.1)
        data = GREETING + b"\x05\x01\x00\x01\x01\x02"
        with pytest.raises(ConnectionError, match="IPv4 address"):
            await _socks5_handshake(_reader(data, eof=False), _FakeWriter())


# ============================================================================
# Реальный сокет: клиент, пишущий по одному байту
# ============================================================================


async def test_handshake_over_a_real_socket_with_one_byte_writes():
    results = []

    async def on_client(reader, writer):
        try:
            results.append(await _socks5_handshake(reader, writer))
        finally:
            writer.close()

    server = await asyncio.start_server(on_client, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        request = GREETING + _connect_domain(b"dc4.example.org", 443)
        for i, byte in enumerate(request):
            writer.write(bytes([byte]))
            await writer.drain()
            if i % 5 == 0:
                await asyncio.sleep(0.001)
        reply = await asyncio.wait_for(reader.readexactly(2 + 10), 5)
        assert reply == b"\x05\x00" + OK_REPLY
        assert results == [("dc4.example.org", 443)]
        writer.close()
    finally:
        server.close()
