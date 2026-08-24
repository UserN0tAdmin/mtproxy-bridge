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

"""Проверка работоспособности прокси-ссылки: полный MTProto-ping.

Библиотечный API (:func:`check_link`, :func:`check_link_sync`) первичен,
CLI ``mtproxy-bridge check`` — тонкая обёртка над ним. Проверка выполняет
настоящий обмен ``req_pq_multi`` → ``resPQ`` с Telegram DC через туннель
(direct TCP или WEB-релей) и сверяет эхо nonce — единственный способ
доказать, что секрет верен и прокси реально релеит до DC.

Референсы раскладки (папка ``_spec_for_add_web_proxy``, untracked):
    - TDLib (приоритет): ``td/mtproto/Transport.cpp`` (NoCryptoHeader,
      read_no_crypto, коды ошибок в пакетах <16 байт),
      ``td/mtproto/NoCryptoStorer.h`` (PlainPkt + паддинг),
      ``td/mtproto/PingConnection.cpp:31-91`` (статический msg_id=1),
      ``td/generate/scheme/mtproto_api.tl`` (req_pq_multi#be7e8ef1,
      resPQ#05162463);
    - tdesktop: ``connection_tcp.cpp`` Version0/VersionD (фрейминг
      abridged / padded intermediate).
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import secrets
import struct
import time
from collections.abc import Awaitable, Callable

from .config import UPSTREAM_CONNECT_TIMEOUT_SECS
from .faketls import async_faketls_handshake
from .links import ProxyLink, WebProxyLink, parse_tg_link, parse_web_link
from .obfuscated2 import (
    TAG_ABRIDGED,
    TAG_PADDED_INTERMEDIATE,
    build_obfuscated2_header,
)
from .tls_records import TLSRecordUnwrapper, TLSRecordWriter
from .utils import log

# ============================================================================
# Константы MTProto (см. scheme-файлы TDLib/tdesktop в шапке модуля)
# ============================================================================

_REQ_PQ_MULTI_ID = 0xBE7E8EF1  # req_pq_multi#be7e8ef1 nonce:int128 = ResPQ
_RESPQ_ID = 0x05162463         # resPQ#05162463 nonce server_nonce pq fingerprints
_RPC_RESULT_ID = 0xF35C6D01    # rpc_result#f35c6d01 req_msg_id result:Object
_BAD_MSG_NOTIFICATION_ID = 0xA7EFF811

# Статический msg_id ровно как в TDLib PingConnectionReqPQ (MessageId(1)):
# соединение свежее, монотонность внутри него соблюдена.
_PING_MSG_ID = 1


class _CheckError(Exception):
    """Провал стадии проверки (не покидает :func:`check_link`).

    Несёт имя стадии для фиксации провала в CheckResult.stages.
    """

    def __init__(self, stage: str, message: str) -> None:
        super().__init__(message)
        self.stage = stage
        self.message = message


class _PingOK(Exception):
    """Внутренний сигнал успеха обмена: несёт detail и RTT."""

    def __init__(self, detail: str, rtt_ms: float) -> None:
        super().__init__(detail)
        self.detail = detail
        self.rtt_ms = rtt_ms


# ============================================================================
# Результат проверки — публичные типы
# ============================================================================


@dataclasses.dataclass(frozen=True)
class StageResult:
    """Outcome of a single check stage."""

    name: str  # stage id: parse|connect|handshake|session|ping
    ok: bool
    ms: float | None
    detail: str = ""  # human-readable detail


@dataclasses.dataclass(frozen=True)
class CheckResult:
    """Structured result of :func:`check_link`.

    All fields are serialization-safe: :meth:`to_dict` / :meth:`to_json`
    feed the CLI (--json) and can be consumed by integrations directly.
    """

    ok: bool
    mode: str  # "direct" | "web"
    stage: str  # last stage reached
    error: str | None  # failure reason (None when ok=True)
    mtproto_error: int | None  # numeric DC error code (-404 etc.)
    rtt_ms: float | None  # req_pq_multi → resPQ
    total_ms: float
    dc_id: int
    transport: str  # "abridged" | "padded intermediate"
    stages: tuple[StageResult, ...]
    # Carrier mode chosen by the relay ("https" | "websocket-lanes" | ...);
    # populated in WEB mode only, None for direct links / failed sessions.
    carrier: str | None = None

    def to_dict(self) -> dict:
        """Flat JSON-compatible structure of the result."""
        return {
            "ok": self.ok,
            "mode": self.mode,
            "stage": self.stage,
            "error": self.error,
            "mtproto_error": self.mtproto_error,
            "rtt_ms": self.rtt_ms,
            "total_ms": self.total_ms,
            "dc_id": self.dc_id,
            "transport": self.transport,
            "carrier": self.carrier,
            "stages": [dataclasses.asdict(s) for s in self.stages],
        }

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize the result to a JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


def _transport_name(tag: bytes) -> str:
    return "padded intermediate" if tag == TAG_PADDED_INTERMEDIATE else "abridged"


class _Collector:
    """Накопитель стадий; строит итоговый CheckResult."""

    def __init__(self, mode: str, dc_id: int, transport: str) -> None:
        self._mode = mode
        self._dc_id = dc_id
        self._transport = transport
        self._stages: list[StageResult] = []
        self.mtproto_error: int | None = None
        self.rtt_ms: float | None = None
        self.carrier: str | None = None
        self._t0 = time.monotonic()

    @property
    def stage(self) -> str:
        return self._stages[-1].name if self._stages else "parse"

    def add(self, name: str, ok: bool, ms: float | None, detail: str = "") -> bool:
        self._stages.append(StageResult(name=name, ok=ok, ms=ms, detail=detail))
        if ok:
            log.debug(f"[check] Stage '{name}' OK ({ms:.0f} ms)")
        else:
            log.info(f"[check] Stage '{name}' failed: {detail}")
        return ok

    def finish(self, error: str | None) -> CheckResult:
        return CheckResult(
            ok=error is None,
            mode=self._mode,
            stage=self.stage,
            error=error,
            mtproto_error=self.mtproto_error,
            rtt_ms=self.rtt_ms,
            total_ms=(time.monotonic() - self._t0) * 1000.0,
            dc_id=self._dc_id,
            transport=self._transport,
            stages=tuple(self._stages),
            carrier=self.carrier,
        )


# ============================================================================
# Транспортный фрейминг (TDLib TcpTransport.cpp / tdesktop connection_tcp.cpp)
# ============================================================================


def frame_payload(tag: bytes, payload: bytes) -> bytes:
    """Кладёт MTProto-сообщение в транспортный фрейм выбранного типа."""
    if len(payload) % 4:
        raise ValueError(f"payload не кратен 4: {len(payload)}")
    ints = len(payload) // 4
    if tag == TAG_PADDED_INTERMEDIATE:
        # VersionD::finalizePacket: uint32 LE = payload + паддинг 0..15 байт.
        pad_len = secrets.randbelow(16)
        return struct.pack("<I", len(payload) + pad_len) + payload + secrets.token_bytes(pad_len)
    # Version0::finalizePacket: ints < 0x7F → 1 байт; иначе 0x7F + 3 байта LE.
    if ints < 0x7F:
        return bytes([ints]) + payload
    return b"\x7f" + struct.pack("<I", ints)[:3] + payload


class _FrameReader:
    """Инкрементальный сборщик фреймов из расшифрованного потока."""

    def __init__(self, tag: bytes) -> None:
        self._tag = tag
        self._buf = bytearray()

    def feed(self, plain: bytes) -> None:
        self._buf += plain

    def next_message(self) -> bytes | None:
        """Возвращает готовое сообщение или None, если фрейм неполный."""
        buf = self._buf
        if self._tag == TAG_PADDED_INTERMEDIATE:
            # IntermediateTransport::read_from_stream: uint32 LE длина payload;
            # старший бит = quick-ack (в этом сценарии пропускаем как nop).
            if len(buf) < 4:
                return None
            size = struct.unpack_from("<I", buf, 0)[0]
            if size & 0x80000000:
                del buf[:4]
                return None
            if len(buf) < 4 + size:
                return None
            del buf[:4]
            msg = bytes(buf[:size])
            del buf[:size]
            return msg
        # Abridged: 1 байт числа int'ов либо 0x7F + 3 байта LE (tdesktop V0).
        if not buf:
            return None
        first = buf[0]
        if first == 0x7F:
            if len(buf) < 4:
                return None
            ints = int.from_bytes(buf[1:4], "little")
            header = 4
        else:
            ints = first
            header = 1
        if ints < 1:
            raise _CheckError("ping", f"abridged: invalid frame length ({ints})")
        total = header + ints * 4
        if len(buf) < total:
            return None
        msg = bytes(buf[header:total])
        del buf[:total]
        return msg


# ============================================================================
# Plain-пакет req_pq_multi и разбор ответа
# ============================================================================


def build_req_pq_multi(nonce: bytes) -> bytes:
    """Строит PlainPkt c req_pq_multi (NoCryptoHeader + NoCryptoImpl TDLib).

    Раскладка: auth_key_id=0 (uint64) | msg_id (int64) | inner_size (int32,
    body+pad) | body | случайный паддинг до кратности 16 (+16*(rand%16)).
    """
    if len(nonce) != 16:
        raise ValueError("nonce должен быть ровно 16 байтами")
    body = struct.pack("<I", _REQ_PQ_MULTI_ID) + nonce
    pad_size = (-len(body)) & 15
    pad_size += 16 * secrets.randbelow(16)
    return (
        struct.pack("<Q", 0)  # auth_key_id: no-crypto пакеты всегда с нулём
        + struct.pack("<q", _PING_MSG_ID)
        + struct.pack("<i", len(body) + pad_size)
        + body
        + secrets.token_bytes(pad_size)
    )


def parse_response(message: bytes, nonce: bytes) -> tuple[int | None, str]:
    """Разбирает расшифрованное сообщение-ответ DC.

    Семантика Transport::read + PingConnectionReqPQ.on_raw_packet (TDLib):
        - короткий (<16 байт) пакет — числовой код ошибки MTProto;
        - auth_key_id != 0 → ответ не похож на MTProto (мусор/эхо);
        - иначе plain-пакет: msg_id | size | body; тело может быть
          обёрнуто в rpc_result (обрабатываем на всякий случай).

    Returns:
        ``(mtproto_error, detail)``: код ошибки DC (если это ошибка) и
        человекочитаемый итог. Успех: ``(None, "resPQ, nonce совпал")``.
    """
    if len(message) < 16:
        if len(message) >= 4:
            code = struct.unpack_from("<i", message, 0)[0]
            if code == 0:
                return None, "empty packet from server"
            hint = (
                "usually a wrong secret or transport tag"
                if code == -404
                else "DC error"
            )
            return code, f"MTProto error {code} ({hint})"
        return None, f"response too short ({len(message)} bytes)"

    if struct.unpack_from("<Q", message, 0)[0] != 0:
        return None, "auth_key_id != 0 — response does not look like MTProto"
    if len(message) < 20:
        return None, "truncated plain packet"

    inner_size = struct.unpack_from("<i", message, 16)[0]
    body = memoryview(message)[20 : 20 + max(inner_size, 0)]

    # rpc_result-обёртка: constructor(4) + req_msg_id(8) → вложенный объект.
    if len(body) >= 12 and struct.unpack_from("<I", body, 0)[0] == _RPC_RESULT_ID:
        body = body[12:]
    if (
        len(body) >= 12
        and struct.unpack_from("<I", body, 0)[0] == _BAD_MSG_NOTIFICATION_ID
    ):
        return None, "bad_msg_notification received from server"

    if len(body) < 20 or struct.unpack_from("<I", body, 0)[0] != _RESPQ_ID:
        ctor = bytes(body[:4]).hex() if len(body) >= 4 else "<short>"
        return None, f"unknown response constructor {ctor}"
    if bytes(body[4:20]) != nonce:
        return None, "resPQ received but nonce mismatch (spoofing/echo backend?)"
    return None, "resPQ, nonce matched"


# ============================================================================
# Общий обмен пингом
# ============================================================================


async def _ping_exchange(
    *,
    send_plain: Callable[[bytes], Awaitable[None]],
    keys_decryptor,
    expected_tag: bytes,
    collector: _Collector,
    recv_chunk: Callable[[], Awaitable[bytes]],
    remaining: float,
) -> None:
    """Шлёт framed req_pq_multi и собирает первый фрейм-ответ.

    ``send_plain`` получает уже зафреймленный plain-пакет и отвечает за
    приклейку obfuscated2-заголовка/обёртки TLS (см. вызовы в _run_*).
    Всегда завершается исключением _PingOK/_CheckError.
    """
    loop = asyncio.get_running_loop()
    nonce = secrets.token_bytes(16)
    packet = frame_payload(expected_tag, build_req_pq_multi(nonce))

    t0 = time.monotonic()
    try:
        await send_plain(packet)
    except (ConnectionError, BrokenPipeError, OSError) as e:
        raise _CheckError("ping", f"failed to send request: {e}") from e

    framer = _FrameReader(expected_tag)
    deadline = loop.time() + remaining
    while True:
        msg = framer.next_message()
        if msg is not None:
            break
        budget = deadline - loop.time()
        if budget <= 0:
            raise _CheckError("ping", "timed out waiting for MTProto response")
        try:
            chunk = await asyncio.wait_for(recv_chunk(), timeout=budget)
        except asyncio.TimeoutError as e:
            raise _CheckError("ping", "timed out waiting for MTProto response") from e
        except (ConnectionError, OSError) as e:
            raise _CheckError("ping", f"connection dropped while reading response: {e}") from e
        if not chunk:
            raise _CheckError("ping", "connection closed before MTProto response")
        framer.feed(keys_decryptor.update(chunk))

    rtt_ms = (time.monotonic() - t0) * 1000.0
    mtproto_error, detail = parse_response(msg, nonce)
    if mtproto_error is not None:
        collector.mtproto_error = mtproto_error
        raise _CheckError("ping", detail)
    raise _PingOK(detail, rtt_ms)


# ============================================================================
# Режимы: direct TCP и WEB-релей
# ============================================================================


async def _run_direct(
    link: ProxyLink,
    collector: _Collector,
    *,
    dc_id: int,
    timeout: float,
    send_ccs: bool,
    use_block_m: bool,
    use_block_e: bool,
) -> None:
    """Проверка direct-ссылки: TCP → FakeTLS? → obfuscated2 → ping."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout

    reader = writer = None
    try:
        t0 = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(link.server, link.port),
                timeout=min(UPSTREAM_CONNECT_TIMEOUT_SECS, timeout),
            )
        except asyncio.TimeoutError as e:
            raise _CheckError(
                "connect", f"timeout connecting to {link.server}:{link.port}"
            ) from e
        except OSError as e:
            raise _CheckError(
                "connect", f"{link.server}:{link.port}: {e.strerror or e}"
            ) from e
        if not collector.add(
            "connect",
            True,
            (time.monotonic() - t0) * 1000.0,
            f"{link.server}:{link.port}",
        ):
            return

        unwrapper: TLSRecordUnwrapper | None = None
        tls_writer: TLSRecordWriter | None = None
        if link.is_fake_tls:
            t0 = time.monotonic()
            try:
                await asyncio.wait_for(
                    async_faketls_handshake(
                        reader, writer, link.domain, link.secret_key,
                        use_block_m=use_block_m, use_block_e=use_block_e,
                    ),
                    timeout=max(deadline - loop.time(), 0.1),
                )
            except asyncio.TimeoutError as e:
                raise _CheckError("handshake", "FakeTLS handshake timed out") from e
            except Exception as e:
                raise _CheckError("handshake", f"FakeTLS handshake: {e}") from e
            unwrapper = TLSRecordUnwrapper()
            tls_writer = TLSRecordWriter(send_ccs=send_ccs)
            if not collector.add(
                "handshake",
                True,
                (time.monotonic() - t0) * 1000.0,
                f"secret verified (HMAC), domain={link.domain}",
            ):
                return

        keys = build_obfuscated2_header(link.expected_tag, dc_id, link.secret_key)

        async def send_plain(blob: bytes) -> None:
            # Весь трафик после 64-байтного init шифруется (как в relay.py).
            enc = keys.encryptor.update(blob)
            if tls_writer is not None:
                # Как в relay.py: заголовок + нагрузка одной TLS-записью
                # (CCS уходит перед первой AppData автоматически).
                writer.write(tls_writer.wrap(keys.header, enc))
            else:
                writer.write(keys.header + enc)
            await writer.drain()

        async def recv_chunk() -> bytes:
            raw = await reader.read(65536)
            return unwrapper.feed(raw) if unwrapper is not None else raw

        try:
            await _ping_exchange(
                send_plain=send_plain,
                keys_decryptor=keys.decryptor,
                expected_tag=link.expected_tag,
                collector=collector,
                recv_chunk=recv_chunk,
                remaining=max(deadline - loop.time(), 0.1),
            )
        except _PingOK as ok:
            collector.rtt_ms = ok.rtt_ms
            collector.add("ping", True, ok.rtt_ms, ok.detail)
    finally:
        if writer is not None:
            try:
                writer.close()
            except Exception:
                pass


async def _run_web(
    link: WebProxyLink,
    collector: _Collector,
    *,
    dc_id: int,
    timeout: float,
    web_origin: str | None,
) -> None:
    """Проверка WEB-ссылки: bootstrap → стрим → obfuscated2 → ping."""
    try:
        from .web.tunnel import WebTunnel
    except ImportError as e:
        raise _CheckError(
            "session",
            'WEB proxy mode requires the [web] extra: '
            'pip install "mtproxy-bridge[web]"',
        ) from e

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    tunnel: WebTunnel | None = None
    stream = None
    try:
        tunnel = WebTunnel(link, origin=web_origin)
        t0 = time.monotonic()
        try:
            stream = await asyncio.wait_for(
                tunnel.open_stream(), timeout=max(deadline - loop.time(), 0.1)
            )
        except asyncio.TimeoutError as e:
            raise _CheckError("session", "timed out opening web session/stream") from e
        except Exception as e:
            raise _CheckError("session", f"web session: {e}") from e
        if not collector.add(
            "session",
            True,
            (time.monotonic() - t0) * 1000.0,
            f"bootstrap+stream {stream.stream_id}, carrier={tunnel.carrier_mode}",
        ):
            return
        collector.carrier = tunnel.carrier_mode or None

        expected_tag = TAG_PADDED_INTERMEDIATE if link.is_padded else TAG_ABRIDGED
        keys = build_obfuscated2_header(expected_tag, dc_id, link.secret_key)

        async def send_plain(blob: bytes) -> None:
            # Всё одним DATA-потоком: заголовок идёт в первой записи,
            # нагрузка после него шифруется (как в relay.py).
            await stream.write(keys.header + keys.encryptor.update(blob))

        try:
            await _ping_exchange(
                send_plain=send_plain,
                keys_decryptor=keys.decryptor,
                expected_tag=expected_tag,
                collector=collector,
                recv_chunk=stream.read,
                remaining=max(deadline - loop.time(), 0.1),
            )
        except _PingOK as ok:
            collector.rtt_ms = ok.rtt_ms
            collector.add("ping", True, ok.rtt_ms, ok.detail)
    finally:
        if stream is not None:
            try:
                await tunnel.close_stream(stream.stream_id)
            except Exception:
                pass
        if tunnel is not None:
            try:
                await tunnel.aclose()
            except Exception:
                pass


# ============================================================================
# Публичные функции
# ============================================================================


async def check_link(
    link: str,
    *,
    timeout: float = 15.0,
    dc_id: int = 2,
    send_ccs: bool = True,
    use_block_m: bool = True,
    use_block_e: bool = True,
    web_origin: str | None = None,
) -> CheckResult:
    """Fully check a proxy link: ``req_pq_multi`` → ``resPQ`` roundtrip to a DC.

    Never raises for "proxy unreachable / wrong secret" outcomes — every
    result is described in :class:`CheckResult` (including the ``parse``
    stage for an invalid link). Exceptions are only possible on programming
    errors (wrong argument types).

    Args:
        link: ``tg://proxy?...`` / ``tg://webproxy?...`` link.
        timeout: total budget for all stages, seconds.
        dc_id: Data center ID for the obfuscated2 header (default 2;
            check mode has no SOCKS5 target host, so auto-detection from
            :mod:`mtproxy_bridge.dc` does not apply here).
        send_ccs: Send CCS before the first AppData record (direct FakeTLS).
        use_block_m: Block M (Kyber-like) in ClientHello (direct FakeTLS).
        use_block_e: Block E in ClientHello (direct FakeTLS).
        web_origin: Override the WEB relay origin (tests/non-standard deploys).

    Returns:
        :class:`CheckResult` with stages, timings and failure reason.
    """
    started = time.monotonic()
    is_web = link.strip().lower().startswith(
        ("tg://webproxy", "https://t.me/webproxy")
    )

    parse_error: str | None = None
    parsed_link: ProxyLink | WebProxyLink | None = None
    transport = ""
    if is_web:
        mode = "web"
        try:
            web = parse_web_link(link)
            parsed_link = web
            transport = _transport_name(
                TAG_PADDED_INTERMEDIATE if web.is_padded else TAG_ABRIDGED
            )
        except ValueError as e:
            parse_error = str(e)
    else:
        mode = "direct"
        try:
            direct = parse_tg_link(link)
            parsed_link = direct
            transport = _transport_name(direct.expected_tag)
        except ValueError as e:
            parse_error = str(e)

    collector = _Collector(mode, dc_id, transport or "unknown")
    if parsed_link is None:
        collector.add("parse", False, None, parse_error or "")
        return collector.finish(f"invalid link: {parse_error}")
    if not collector.add(
        "parse",
        True,
        (time.monotonic() - started) * 1000.0,
        ("tg://webproxy" if is_web else "tg://proxy") + f", transport: {transport}",
    ):
        return collector.finish(None)

    try:
        if is_web:
            await _run_web(
                parsed_link, collector,  # type: ignore[arg-type]
                dc_id=dc_id, timeout=timeout, web_origin=web_origin,
            )
        else:
            await _run_direct(
                parsed_link, collector,  # type: ignore[arg-type]
                dc_id=dc_id, timeout=timeout,
                send_ccs=send_ccs, use_block_m=use_block_m,
                use_block_e=use_block_e,
            )
    except asyncio.CancelledError:
        raise
    except _CheckError as e:
        # Провал стадии фиксируем явно — иначе в stages останется только
        # последняя успешная стадия и итог будет вводить в заблуждение.
        collector.add(e.stage, False, None, e.message)
        return collector.finish(e.message)
    except Exception as e:  # защита: проверка никогда не падает наружу
        log.exception("[check] неожиданная ошибка")
        return collector.finish(f"внутренняя ошибка проверки: {e!r}")
    return collector.finish(None)


def check_link_sync(link: str, **kwargs) -> CheckResult:
    """Synchronous wrapper around :func:`check_link` (uses asyncio.run).

    Do NOT call it from an already running event loop / coroutine — use
    ``await check_link(...)`` there. See its docstring for the parameters.
    """
    return asyncio.run(check_link(link, **kwargs))
