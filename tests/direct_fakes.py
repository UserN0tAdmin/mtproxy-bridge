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

"""Общие фейки для тестов классического MTProxy (direct-режим).

Модуль НЕ собирается pytest'ом (имя без ``test_``) и не требует aiohttp.

Серверная часть obfuscated2 / FakeTLS / транспортного фрейминга написана
здесь заново, по спецификации и НЕЗАВИСИМО от кода моста: если тесты
сравнивали бы мост с его же реализацией, ошибка, симметричная на обеих
сторонах, осталась бы незамеченной.

Содержимое:

- :class:`ServerObfuscated2` — серверная половина obfuscated2;
- :func:`frame` / :func:`parse_frame` — abridged / padded intermediate;
- :func:`build_respq` / :func:`parse_req_pq_multi` — MTProto plain-пакеты;
- :func:`parse_client_hello` / :func:`build_server_hello` — FakeTLS;
- :class:`FakeMTProxy` — настоящий по поведению MTProxy (plain или FakeTLS)
  с подключаемым обработчиком соединения и журналом :class:`ConnRecord`;
- :class:`ScriptedServer` — сервер с заданным (в т.ч. кривым) ответом;
- :class:`LoopThread` — event loop в потоке (для sync-тестов CLI);
- клиентские хелперы SOCKS5 (pytest-фикстуры ``proxy_factory`` /
  ``scripted_factory`` / ``bridge_factory`` — в ``tests/conftest.py``).
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import threading
from typing import Any, Awaitable, Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ============================================================================
# Константы
# ============================================================================

TAG_ABRIDGED = b"\xef\xef\xef\xef"
TAG_PADDED = b"\xdd\xdd\xdd\xdd"
VALID_TAGS = (TAG_ABRIDGED, TAG_PADDED)

CCS = b"\x14\x03\x03\x00\x01\x01"
CCS_APPDATA_PREFIX = CCS + b"\x17\x03\x03"

SECRET = bytes.fromhex("00112233445566778899aabbccddeeff")
DOMAIN = "tls.example.com"

SECRET_PLAIN = SECRET.hex()
SECRET_DD = "dd" + SECRET.hex()
SECRET_EE = "ee" + SECRET.hex() + DOMAIN.encode().hex()

DC2_IP = "149.154.167.51"
DC4_IP = "149.154.167.91"
DC3_IP = "149.154.175.100"
CDN_IP = "91.105.192.100"

_REQ_PQ_MULTI = 0xBE7E8EF1
_RESPQ = 0x05162463


def make_link(port: int, secret_hex: str, host: str = "127.0.0.1") -> str:
    return f"tg://proxy?server={host}&port={port}&secret={secret_hex}"


def free_port() -> int:
    """Порт, на котором (с высокой вероятностью) никто не слушает."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ============================================================================
# obfuscated2: серверная половина
# ============================================================================


class ServerObfuscated2:
    """Серверная половина obfuscated2 (ключи выводятся из клиентского init)."""

    def __init__(self, init: bytes, secret: bytes | None) -> None:
        assert len(init) == 64
        dec_key, dec_iv = init[8:40], init[40:56]
        rev = init[8:56][::-1]
        enc_key, enc_iv = rev[:32], rev[32:48]
        if secret:
            dec_key = hashlib.sha256(dec_key + secret).digest()
            enc_key = hashlib.sha256(enc_key + secret).digest()
        self._dec = Cipher(algorithms.AES(dec_key), modes.CTR(dec_iv)).decryptor()
        self._enc = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()
        # Расшифровка всего init двигает счётчик CTR на 64 байта и даёт
        # открытые tag (56..60) и dc (60..62, int16 LE).
        plain = self._dec.update(init)
        self.tag = plain[56:60]
        self.dc = struct.unpack("<h", plain[60:62])[0]

    def decrypt(self, data: bytes) -> bytes:
        return self._dec.update(data)

    def encrypt(self, data: bytes) -> bytes:
        return self._enc.update(data)


# ============================================================================
# Транспортный фрейминг и MTProto plain-пакеты
# ============================================================================


def frame(tag: bytes, payload: bytes, pad: int | None = None) -> bytes:
    """Фрейм abridged (tag=EF) либо padded intermediate (tag=DD)."""
    assert len(payload) % 4 == 0
    if tag == TAG_ABRIDGED:
        n = len(payload) // 4
        head = bytes([n]) if n < 0x7F else b"\x7f" + n.to_bytes(3, "little")
        return head + payload
    if pad is None:
        pad = os.urandom(1)[0] % 16
    return struct.pack("<I", len(payload) + pad) + payload + os.urandom(pad)


def parse_frame(tag: bytes, buf: bytearray) -> bytes | None:
    """Достаёт первое сообщение из буфера (``None`` — фрейм неполный)."""
    if tag == TAG_ABRIDGED:
        if not buf:
            return None
        n, hdr = buf[0], 1
        if n == 0x7F:
            if len(buf) < 4:
                return None
            n, hdr = int.from_bytes(buf[1:4], "little"), 4
        total = hdr + n * 4
        if len(buf) < total:
            return None
        msg = bytes(buf[hdr:total])
        del buf[:total]
        return msg
    if len(buf) < 4:
        return None
    size = struct.unpack("<I", buf[:4])[0]
    if len(buf) < 4 + size:
        return None
    msg = bytes(buf[4 : 4 + size])
    del buf[: 4 + size]
    return msg


def parse_req_pq_multi(msg: bytes) -> bytes:
    """Проверяет plain-пакет req_pq_multi и возвращает nonce.

    Раскладка: auth_key_id=0 (u64) | msg_id (i64) | inner_len (i32) | body.
    body = ctor (4) + nonce (16) + паддинг; (inner_len кратен 16).
    """
    auth_key_id, _msg_id, inner_len = struct.unpack_from("<Qqi", msg, 0)
    if auth_key_id != 0:
        raise ValueError(f"auth_key_id != 0: {auth_key_id}")
    if inner_len < 20 or inner_len % 16 or len(msg) < 20 + inner_len:
        raise ValueError(f"bad inner_len {inner_len} for message of {len(msg)}")
    ctor = struct.unpack_from("<I", msg, 20)[0]
    if ctor != _REQ_PQ_MULTI:
        raise ValueError(f"unexpected constructor {ctor:#x}")
    return msg[24:40]


def build_respq(nonce: bytes) -> bytes:
    """resPQ с эхом nonce (TL: pq:string и Vector<long> фингерпринтов)."""
    pq_tl = bytes([8]) + os.urandom(8) + b"\x00\x00\x00"  # string 8 байт + паддинг
    body = (
        struct.pack("<I", _RESPQ)
        + nonce
        + os.urandom(16)  # server_nonce
        + pq_tl
        + struct.pack("<Ii", 0x1CB5C415, 1)  # Vector, count=1
        + struct.pack("<q", 0x123456789ABCDEF0)
    )
    return struct.pack("<Qqi", 0, 0x5F00000001, len(body)) + body


# ============================================================================
# FakeTLS: разбор ClientHello и построение ответа сервера
# ============================================================================


@dataclasses.dataclass
class ClientHelloInfo:
    raw: bytes
    random: bytes  # 32 байта: HMAC-digest ^ timestamp
    session_id: bytes
    cipher_suites: list
    compression: bytes
    extensions: list  # [(type, body), ...] в порядке следования

    def ext(self, ext_type: int) -> bytes | None:
        for t, body in self.extensions:
            if t == ext_type:
                return body
        return None

    @property
    def sni(self) -> str | None:
        body = self.ext(0)
        if body is None:
            return None
        # server_name_list: len(2) | type(1) | name_len(2) | name
        name_len = struct.unpack_from(">H", body, 3)[0]
        return body[5 : 5 + name_len].decode("ascii")


def parse_client_hello(data: bytes) -> ClientHelloInfo:
    """Строгий разбор ClientHello (ValueError при любом несоответствии)."""
    if data[:3] != b"\x16\x03\x01":
        raise ValueError(f"bad record header {data[:3].hex()}")
    if struct.unpack_from(">H", data, 3)[0] != len(data) - 5:
        raise ValueError("record length mismatch")
    if data[5] != 0x01:
        raise ValueError("not a ClientHello handshake")
    if int.from_bytes(data[6:9], "big") != len(data) - 9:
        raise ValueError("handshake length mismatch")
    if data[9:11] != b"\x03\x03":
        raise ValueError("client_version != 0303")
    pos = 11
    random = data[pos : pos + 32]
    pos += 32
    sid_len = data[pos]
    pos += 1
    sid = data[pos : pos + sid_len]
    pos += sid_len
    cs_len = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    suites = [struct.unpack_from(">H", data, pos + i)[0] for i in range(0, cs_len, 2)]
    pos += cs_len
    comp_len = data[pos]
    pos += 1
    comp = data[pos : pos + comp_len]
    pos += comp_len
    ext_len = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    end = pos + ext_len
    if end != len(data):
        raise ValueError("extensions length mismatch")
    exts = []
    while pos < end:
        etype, elen = struct.unpack_from(">HH", data, pos)
        pos += 4
        if pos + elen > end:
            raise ValueError("extension overruns hello")
        exts.append((etype, data[pos : pos + elen]))
        pos += elen
    return ClientHelloInfo(data, random, sid, suites, comp, exts)


def verify_client_digest(secret: bytes, hello: bytes) -> int | None:
    """Серверная проверка digest'а ClientHello (как у настоящего MTProxy).

    Возвращает timestamp (unix, из последних 4 байт digest'а) либо ``None``,
    если digest не подходит к секрету.
    """
    zeroed = hello[:11] + bytes(32) + hello[43:]
    expected = hmac.new(secret, zeroed, hashlib.sha256).digest()
    diff = bytes(a ^ b for a, b in zip(hello[11:43], expected))
    if diff[:28] != bytes(28):
        return None
    return int.from_bytes(diff[28:], "little")


def build_server_hello(
    secret: bytes,
    client_hello: bytes,
    *,
    appdata_len: int = 1369,
    digest_key: bytes | None = None,
    sh_type: int = 0x02,
    tail_prefix: bytes = CCS_APPDATA_PREFIX,
) -> bytes:
    """Ответ FakeTLS-сервера: ServerHello + CCS + AppData (с HMAC в random).

    ``digest_key`` — подменить ключ HMAC (имитация неверного секрета);
    ``sh_type`` и ``tail_prefix`` — испортить соответствующие поля.
    """
    info = parse_client_hello(client_hello)
    exts = b"\x00\x2b\x00\x02\x03\x04" + b"\x00\x33\x00\x24\x00\x1d\x00\x20"
    exts += os.urandom(32)
    body = (
        b"\x03\x03"
        + bytes(32)  # сюда встанет digest (offset 11 в записи)
        + bytes([len(info.session_id)])
        + info.session_id
        + b"\x13\x01\x00"
        + struct.pack(">H", len(exts))
        + exts
    )
    handshake = bytes([sh_type]) + len(body).to_bytes(3, "big") + body
    sh_record = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    resp = (
        sh_record
        + tail_prefix
        + struct.pack(">H", appdata_len)
        + os.urandom(appdata_len)
    )
    key = secret if digest_key is None else digest_key
    digest = hmac.new(key, info.random + resp, hashlib.sha256).digest()
    return resp[:11] + digest + resp[43:]


async def read_client_hello(reader: asyncio.StreamReader) -> bytes:
    hdr = await reader.readexactly(5)
    return hdr + await reader.readexactly(struct.unpack(">H", hdr[3:5])[0])


# ============================================================================
# Фейковый MTProxy
# ============================================================================


@dataclasses.dataclass
class ConnRecord:
    """Журнал одного входящего соединения (для проверок в тестах)."""

    handshake_ok: bool = False
    error: str | None = None
    tag: bytes | None = None
    dc: int | None = None
    received: bytearray = dataclasses.field(default_factory=bytearray)
    client_eof: bool = False
    closed: asyncio.Event = dataclasses.field(default_factory=asyncio.Event)
    # --- FakeTLS ---
    hello: ClientHelloInfo | None = None
    hello_timestamp: int | None = None
    fallback_served: bool = False
    saw_ccs: bool = False
    record_types: list = dataclasses.field(default_factory=list)
    record_lengths: list = dataclasses.field(default_factory=list)
    protocol_errors: list = dataclasses.field(default_factory=list)
    first_record_len: int | None = None
    init: bytes | None = None
    writer: Any = None


class Conn:
    """Расшифрованный (obfuscated2 [+ TLS-записи]) канал к клиенту."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        obf: ServerObfuscated2,
        rec: ConnRecord,
        *,
        tls: bool,
        tls_chunk: int,
        pending_raw: bytes = b"",
    ) -> None:
        self.reader, self.writer, self.obf, self.record = reader, writer, obf, rec
        self.tag, self.dc = obf.tag, obf.dc
        self._tls, self._chunk = tls, tls_chunk
        self._pending_raw = pending_raw

    async def _read_raw(self) -> bytes:
        if self._pending_raw:
            raw, self._pending_raw = self._pending_raw, b""
            return raw
        if not self._tls:
            return await self.reader.read(65536)
        rec = self.record
        while True:
            try:
                hdr = await self.reader.readexactly(5)
            except asyncio.IncompleteReadError as e:
                if e.partial:
                    rec.protocol_errors.append("truncated TLS record header")
                return b""
            rtype, ver = hdr[0], hdr[1:3]
            length = struct.unpack(">H", hdr[3:5])[0]
            try:
                payload = await self.reader.readexactly(length)
            except asyncio.IncompleteReadError:
                rec.protocol_errors.append("truncated TLS record body")
                return b""
            rec.record_types.append(rtype)
            if rtype == 0x14:
                rec.saw_ccs = True
                continue
            if rtype != 0x17 or ver != b"\x03\x03":
                rec.protocol_errors.append(f"unexpected TLS record {hdr.hex()}")
                return b""
            rec.record_lengths.append(length)
            return payload

    async def read(self) -> bytes:
        """Следующая порция открытых байт от клиента (``b""`` — EOF)."""
        try:
            raw = await self._read_raw()
        except (ConnectionError, OSError):
            raw = b""
        if not raw:
            self.record.client_eof = True
            return b""
        data = self.obf.decrypt(raw)
        self.record.received += data
        return data

    async def write(self, data: bytes) -> None:
        enc = self.obf.encrypt(data)
        if self._tls:
            for i in range(0, len(enc), self._chunk):
                piece = enc[i : i + self._chunk]
                self.writer.write(
                    b"\x17\x03\x03" + struct.pack(">H", len(piece)) + piece
                )
        else:
            self.writer.write(enc)
        await self.writer.drain()


Handler = Callable[[Conn], Awaitable[None]]


async def echo_handler(conn: Conn) -> None:
    """Возвращает клиенту всё, что от него пришло."""
    while True:
        data = await conn.read()
        if not data:
            return
        await conn.write(data)


def respq_handler(mode: str = "respq") -> Handler:
    """Обработчик «DC»: читает один req_pq_multi и отвечает по сценарию.

    Сценарии: ``respq`` — норма; ``nop_then_respq`` — сначала nop и quick-ack
    (клиент обязан читать дальше), затем resPQ; ``wrong_nonce``; ``echo``
    (вернуть присланное как есть); ``error404``; ``close`` — закрыть, не
    ответив; ``silent`` — ничего не отвечать.
    """

    async def handler(conn: Conn) -> None:
        buf = bytearray()
        while True:
            data = await conn.read()
            if not data:
                return
            buf += data
            msg = parse_frame(conn.tag, buf)
            if msg is None:
                continue
            if mode == "silent":
                continue
            if mode == "close":
                return
            nonce = parse_req_pq_multi(msg)
            if mode == "echo":
                answer = msg + b"\x00" * (-len(msg) % 4)
            elif mode == "wrong_nonce":
                answer = build_respq(os.urandom(16))
            elif mode == "error404":
                answer = struct.pack("<i", -404)
            else:
                answer = build_respq(nonce)
            # Служебные пакеты (код ошибки, nop, quick-ack) шлём БЕЗ паддинга:
            # парсер отличает их от plain-пакетов по длине (< 16 байт), а
            # случайный паддинг 0..15 байт делал бы тесты недетерминированными.
            pad = 0 if mode in ("error404", "nop_then_respq") else None
            if mode == "nop_then_respq":
                await conn.write(frame(conn.tag, struct.pack("<i", 0), pad=0))
                await conn.write(frame(conn.tag, struct.pack("<ii", -1, 7), pad=0))
                pad = None  # настоящий resPQ — с обычным паддингом
            await conn.write(frame(conn.tag, answer, pad=pad))
            return

    return handler


class FakeMTProxy:
    """MTProxy-сервер: obfuscated2 с секретом, опционально FakeTLS.

    ``domain=None`` — голый obfuscated2 поверх TCP; иначе FakeTLS: сервер
    проверяет digest ClientHello секретом и отвечает ServerHello с HMAC.
    На неверный digest отдаёт «сайт-прикрытие» (как настоящий MTProxy).
    ``tls_chunk`` — размер TLS-записей в ответах сервера (проверка сборки
    записей на стороне моста).
    """

    FALLBACK = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"

    def __init__(
        self,
        secret: bytes = SECRET,
        *,
        domain: str | None = None,
        handler: Handler = echo_handler,
        tls_chunk: int = 1400,
        appdata_len: int = 1369,
    ) -> None:
        self.secret = secret
        self.domain = domain
        self.handler = handler
        self.tls_chunk = tls_chunk
        self.appdata_len = appdata_len
        self.connections: list[ConnRecord] = []
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> "FakeMTProxy":
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        for rec in self.connections:
            if rec.writer is not None:
                rec.writer.close()
        for rec in self.connections:
            try:
                await asyncio.wait_for(rec.closed.wait(), 3)
            except asyncio.TimeoutError:
                pass

    async def wait_connections(self, n: int = 1, timeout: float = 5.0) -> None:
        await eventually(lambda: len(self.connections) >= n, timeout)

    async def _tls_handshake(self, reader, writer, rec: ConnRecord) -> bool:
        try:
            hello = await asyncio.wait_for(read_client_hello(reader), 5)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError):
            rec.error = "no ClientHello"
            return False
        rec.hello_timestamp = (
            verify_client_digest(self.secret, hello)
            if hello[:3] == b"\x16\x03\x01"
            else None
        )
        if rec.hello_timestamp is None:
            rec.error = "ClientHello digest does not match the secret"
            rec.fallback_served = True
            writer.write(self.FALLBACK)
            await writer.drain()
            return False
        rec.hello = parse_client_hello(hello)
        writer.write(
            build_server_hello(self.secret, hello, appdata_len=self.appdata_len)
        )
        await writer.drain()
        return True

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        rec = ConnRecord()
        rec.writer = writer
        self.connections.append(rec)
        try:
            tls = self.domain is not None
            pending = b""
            if tls:
                if not await self._tls_handshake(reader, writer, rec):
                    return
                # init (64 байта) приходит в первой(ых) AppData-записи(ях)
                # вместе с возможным «хвостом» полезной нагрузки.
                probe = Conn(reader, writer, _NullObf(), rec, tls=True, tls_chunk=0)
                first = bytearray()
                while len(first) < 64:
                    chunk = await probe._read_raw()
                    if not chunk:
                        rec.error = "EOF before obfuscated2 init"
                        return
                    if rec.first_record_len is None:
                        rec.first_record_len = rec.record_lengths[0]
                    first += chunk
                init, pending = bytes(first[:64]), bytes(first[64:])
            else:
                init = await reader.readexactly(64)
            rec.init = init
            obf = ServerObfuscated2(init, self.secret)
            rec.tag, rec.dc = obf.tag, obf.dc
            if obf.tag not in VALID_TAGS:
                rec.error = f"bad transport tag {obf.tag.hex()}"
                return
            rec.handshake_ok = True
            conn = Conn(
                reader,
                writer,
                obf,
                rec,
                tls=tls,
                tls_chunk=self.tls_chunk,
                pending_raw=pending,
            )
            await self.handler(conn)
        except asyncio.IncompleteReadError:
            rec.error = rec.error or "client closed during handshake"
        except (ConnectionError, OSError) as e:
            rec.error = rec.error or repr(e)
        finally:
            writer.close()
            rec.closed.set()


class _NullObf:
    """Заглушка: чтение сырых TLS-записей до готовности obfuscated2."""

    tag = b""
    dc = 0

    def decrypt(self, data: bytes) -> bytes:  # pragma: no cover
        return data


class ScriptedServer:
    """TCP-сервер с заданным ответом на ClientHello.

    ``responder(hello) -> bytes`` — что отправить (``None`` — молчать);
    ``after``: ``"close"`` закрыть соединение, ``"hang"`` держать открытым.
    ``read_hello=False`` — не читать ничего, сразу отвечать.
    """

    def __init__(
        self,
        responder: Callable[[bytes], bytes] | None = None,
        *,
        after: str = "close",
        read_hello: bool = True,
    ) -> None:
        self.responder = responder
        self.after = after
        self.read_hello = read_hello
        self.hellos: list[bytes] = []
        self.port = 0
        self._server: asyncio.AbstractServer | None = None
        self._writers: list[asyncio.StreamWriter] = []

    async def start(self) -> "ScriptedServer":
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        assert self._server is not None
        self._server.close()
        for w in self._writers:
            w.close()

    async def _serve(self, reader, writer) -> None:
        self._writers.append(writer)
        try:
            hello = b""
            if self.read_hello:
                hello = await read_client_hello(reader)
                self.hellos.append(hello)
            if self.responder is not None:
                writer.write(self.responder(hello))
                await writer.drain()
            if self.after == "hang":
                while await reader.read(65536):
                    pass
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            writer.close()


class LoopThread:
    """Event loop в отдельном потоке — для sync-тестов (CLI зовёт asyncio.run)."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def start(self) -> "LoopThread":
        self._thread.start()
        return self

    def call(self, coro, timeout: float = 10.0):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self._thread.join(5)
        self.loop.close()


# ============================================================================
# Клиентские хелперы
# ============================================================================


async def eventually(
    predicate: Callable[[], bool], timeout: float = 5.0, interval: float = 0.02
) -> None:
    """Ждёт истинности predicate (иначе AssertionError вместо вечного зависания)."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if loop.time() > deadline:
            raise AssertionError(f"condition not met within {timeout}s")
        await asyncio.sleep(interval)


async def read_exactly(reader: asyncio.StreamReader, n: int, timeout: float = 10.0):
    return await asyncio.wait_for(reader.readexactly(n), timeout)


async def drain_to_eof(reader: asyncio.StreamReader, timeout: float = 5.0) -> bytes:
    """Читает до закрытия соединения; AssertionError, если оно не закрылось."""
    buf = bytearray()

    async def _go() -> None:
        while True:
            try:
                chunk = await reader.read(65536)
            except (ConnectionResetError, BrokenPipeError):
                return
            if not chunk:
                return
            buf.extend(chunk)

    try:
        await asyncio.wait_for(_go(), timeout)
    except asyncio.TimeoutError:
        raise AssertionError(
            f"connection was not closed within {timeout}s (read {len(buf)} bytes)"
        ) from None
    return bytes(buf)


def socks5_request(host: str, port: int = 443, *, as_domain: bool = False) -> bytes:
    """SOCKS5 CONNECT-запрос: IPv4 / IPv6 / доменное имя."""
    if not as_domain:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            ip = None
        if isinstance(ip, ipaddress.IPv4Address):
            return b"\x05\x01\x00\x01" + ip.packed + port.to_bytes(2, "big")
        if isinstance(ip, ipaddress.IPv6Address):
            return b"\x05\x01\x00\x04" + ip.packed + port.to_bytes(2, "big")
    name = host.encode("ascii")
    return b"\x05\x01\x00\x03" + bytes([len(name)]) + name + port.to_bytes(2, "big")


async def socks5_connect(
    port: int, host: str = DC2_IP, dport: int = 443, *, as_domain: bool = False
):
    """Клиент SOCKS5 → мост: возвращает (reader, writer) после успешного CONNECT."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05\x01\x00")
    assert await read_exactly(reader, 2) == b"\x05\x00"
    writer.write(socks5_request(host, dport, as_domain=as_domain))
    reply = await read_exactly(reader, 10)
    assert reply[:2] == b"\x05\x00", reply.hex()
    return reader, writer


async def close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 3)
    except (ConnectionError, OSError, asyncio.TimeoutError):
        pass
