#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Тесты команды/библиотеки check (минимальный набор).

Покрывают: фрейминг обоих транспортов, парсер resPQ/ошибок MTProto,
direct-E2E против фейкового MTProxy (server-side obfuscated2 + resPQ)
и WEB-E2E через MockRelay (carrier https) с MTProto-бэкендом.
"""

import asyncio
import hashlib
import secrets
import struct

import pytest
from aiohttp import web
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from test_web_integration import HOST, MockRelay

from mtproxy_bridge.check import (
    _RESPQ_ID,
    _FrameReader,
    build_req_pq_multi,
    check_link,
    frame_payload,
    parse_response,
)
from mtproxy_bridge.links import parse_web_link
from mtproxy_bridge.obfuscated2 import TAG_ABRIDGED, TAG_PADDED_INTERMEDIATE
from mtproxy_bridge.web import frames as f

_DIRECT_SECRET_HEX = "00112233445566778899aabbccddeeff"
_WEB_SECRET_HEX = "dd00112233445566778899aabbccddeeff"


# ============================================================================
# Юниты: фрейминг и парсер ответа
# ============================================================================


@pytest.mark.parametrize("tag", [TAG_ABRIDGED, TAG_PADDED_INTERMEDIATE],
                         ids=["abridged", "padded"])
def test_frame_roundtrip(tag):
    payload = build_req_pq_multi(secrets.token_bytes(16))
    framed = frame_payload(tag, payload)
    framer = _FrameReader(tag)
    msg = None
    # Кормим по одному байту — проверяем инкрементальную сборку фрейма.
    for byte in framed:
        framer.feed(bytes([byte]))
        msg = framer.next_message()
        if msg is not None:
            break
    if tag == TAG_ABRIDGED:
        assert msg == payload
    else:
        # Intermediate-транспорт: длина включает паддинг, поэтому фрейм
        # отдаёт payload+pad целиком; тело отрезается позже по inner_size
        # (см. Transport::read_no_crypto) — сверяем префикс и длину.
        size = struct.unpack_from("<I", framed, 0)[0]
        assert len(msg) == size and msg[: len(payload)] == payload


def test_parse_respq_ok():
    nonce = secrets.token_bytes(16)

    def _respq(nonce16):
        pq = secrets.token_bytes(8)
        body = (
            struct.pack("<I", _RESPQ_ID) + nonce16 + secrets.token_bytes(16)
            + struct.pack("<i", len(pq)) + pq
            + struct.pack("<i", 1) + struct.pack("<q", 0xC0FFEE)
        )
        return struct.pack("<Q", 0) + struct.pack("<q", 2) \
            + struct.pack("<i", len(body)) + body

    error, detail = parse_response(_respq(nonce), nonce)
    assert error is None and detail == "resPQ, nonce matched"


def test_parse_mtproto_error_404():
    error, detail = parse_response(struct.pack("<i", -404), b"x" * 16)
    assert error == -404
    assert "wrong secret" in detail


def test_check_invalid_link_is_result_not_exception():
    result = asyncio.run(check_link("tg://proxy?nonsense=1"))
    assert not result.ok
    assert result.stage == "parse"
    assert result.error is not None


def test_check_result_serialization():
    result = asyncio.run(check_link("tg://webproxy?server=x&secret=zz"))
    d = result.to_dict()
    assert set(d) == {
        "ok", "mode", "stage", "error", "mtproto_error", "rtt_ms",
        "total_ms", "dc_id", "transport", "stages",
    }
    assert '"ok": false' in result.to_json(indent=2)


# ============================================================================
# Фейковый MTProxy: server-side obfuscated2 + resPQ-ответчик
# ============================================================================


def _build_respq(nonce: bytes) -> bytes:
    """Канонический resPQ с эхом nonce (раскладка scheme TDLib)."""
    pq = secrets.token_bytes(8)
    body = (
        struct.pack("<I", _RESPQ_ID)
        + nonce
        + secrets.token_bytes(16)  # server_nonce
        + struct.pack("<i", len(pq)) + pq  # pq:string (%4 — паддинг не нужен)
        + struct.pack("<i", 1) + struct.pack("<q", 0x123456789ABCDEF0)
    )
    return (
        struct.pack("<Q", 0)      # auth_key_id
        + struct.pack("<q", 42)   # msg_id сервера
        + struct.pack("<i", len(body))
        + body
    )


class _ServerObf:
    """Серверная половина obfuscated2 (ключи выводятся из клиентского init)."""

    def __init__(self, init: bytes, secret: bytes) -> None:
        dec_key = hashlib.sha256(init[8:40] + secret).digest()
        _, self.decryptor = self._ctr(dec_key, init[40:56])
        self.decryptor.update(init)  # синхронизация счётчика CTR (см. HANDOFF §4.1)
        rev = bytes(init[8:56])[::-1]
        enc_key = hashlib.sha256(rev[:32] + secret).digest()
        self.encryptor, _ = self._ctr(enc_key, rev[32:48])

    @staticmethod
    def _ctr(key: bytes, iv: bytes):
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        return cipher.encryptor(), cipher.decryptor()


async def _serve_respq(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    secret: bytes,
    tag: bytes,
) -> None:
    """Читает один framed req_pq_multi, отвечает resPQ тем же транспортом."""
    try:
        obf = _ServerObf(await reader.readexactly(64), secret)
        framer = _FrameReader(tag)
        while True:
            data = await reader.read(65536)
            if not data:
                return
            framer.feed(obf.decryptor.update(data))
            msg = framer.next_message()
            if msg is not None:
                nonce = msg[24:40]  # auth(8)+msg_id(8)+size(4)+ctor(4)
                writer.write(obf.encryptor.update(frame_payload(tag, _build_respq(nonce))))
                await writer.drain()
                return
    finally:
        writer.close()


@pytest.fixture
async def fake_mtproxy():
    server = await asyncio.start_server(
        lambda r, w: _serve_respq(r, w, bytes.fromhex(_DIRECT_SECRET_HEX),
                                   TAG_ABRIDGED),
        "127.0.0.1", 0,
    )
    port = server.sockets[0].getsockname()[1]
    yield port
    server.close()
    await server.wait_closed()


class ResPQRelay(MockRelay):
    """MockRelay с MTProto-бэкендом вместо эха (для WEB-check)."""

    async def _pipe_obf(self, session, stream_id, reader, writer, secret):
        try:
            obf = _ServerObf(await reader.readexactly(64), secret)
            framer = _FrameReader(TAG_PADDED_INTERMEDIATE)
            while True:
                data = await reader.read(65536)
                if not data:
                    return
                framer.feed(obf.decryptor.update(data))
                msg = framer.next_message()
                if msg is not None:
                    nonce = msg[24:40]
                    session.push(stream_id, f.encode(
                        f.FrameType.DATA, stream_id,
                        obf.encryptor.update(
                            frame_payload(TAG_PADDED_INTERMEDIATE,
                                          _build_respq(nonce))),
                    ))
                    return
        finally:
            session.writers.pop(stream_id, None)
            writer.close()
            session.push(stream_id, f.encode(f.FrameType.CLOSE, stream_id))
            session.mark_dead(stream_id)


@pytest.fixture
async def web_relay():
    # Эхо-бэкенд (как в test_web_integration): через него _pipe_obf читает
    # то, что мост отправил в релей — эхо возвращает байты на сокет релея.
    async def echo(reader, writer):
        try:
            while True:
                data = await reader.read(262144)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()

    echo_srv = await asyncio.start_server(echo, "127.0.0.1", 0)
    backend_port = echo_srv.sockets[0].getsockname()[1]

    mock = ResPQRelay(backend_port)
    runner = web.AppRunner(mock.make_app(), shutdown_timeout=2)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    mock.port = runner.addresses[0][1]
    yield mock
    await runner.cleanup()
    echo_srv.close()
    await echo_srv.wait_closed()


# ============================================================================
# E2E: direct и WEB
# ============================================================================


async def test_check_direct_ok(fake_mtproxy):
    link = (
        f"tg://proxy?server=127.0.0.1&port={fake_mtproxy}"
        f"&secret={_DIRECT_SECRET_HEX}"
    )
    result = await check_link(link, timeout=10.0)
    assert result.ok, f"{result.stage}: {result.error}"
    assert [s.name for s in result.stages] == ["parse", "connect", "ping"]
    assert result.rtt_ms is not None and result.rtt_ms >= 0
    assert result.mtproto_error is None
    assert result.transport == "abridged"
    assert result.to_dict()["ok"] is True


async def test_check_web_ok(web_relay):
    link_str = f"tg://webproxy?server={HOST}&secret={_WEB_SECRET_HEX}"
    web_link = parse_web_link(link_str)
    web_relay.capability = web_link.capability
    web_relay.mtproto_secret = web_link.secret_key  # включает ветку _pipe_obf

    origin = f"http://127.0.0.1:{web_relay.port}"
    result = await check_link(link_str, timeout=15.0, web_origin=origin)
    assert result.ok, f"{result.stage}: {result.error}"
    assert [s.name for s in result.stages] == ["parse", "session", "ping"]
    assert result.mode == "web"
    assert result.transport == "padded intermediate"
