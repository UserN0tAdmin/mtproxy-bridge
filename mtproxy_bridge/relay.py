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

"""Пайплайн клиентского соединения: SOCKS5 -> tunnel -> relay."""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from .config import (
    ACTIVITY_TIMEOUT_SECS,
    SOCKS5_HANDSHAKE_TIMEOUT_SECS,
    UPSTREAM_CONNECT_TIMEOUT_SECS,
    BridgeConfig,
)
from .dc import guess_dc_id_async
from .faketls import async_faketls_handshake
from .obfuscated2 import (
    TAG_ABRIDGED,
    TAG_PADDED_INTERMEDIATE,
    build_obfuscated2_header,
    detect_client_transport_tag,
)
from .socks5 import _socks5_handshake
from .tls_records import TLSRecordUnwrapper, TLSRecordWriter
from .utils import _apply_tcp_tuning, _hex, log

if TYPE_CHECKING:
    from .web.tunnel import WebStream, WebTunnel


async def _handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: BridgeConfig,
    web_tunnel: "WebTunnel | None" = None,
) -> None:
    """Обрабатывает одно клиентское соединение: SOCKS5 → tunnel → relay.

    Pipeline:
        1. SOCKS5 handshake, вычисление DC ID;
        2. туннель до MTProxy — прямой TCP либо WEB-поток релея;
        3. FakeTLS handshake (если ee-секрет; только для прямого режима);
        4. obfuscated2 header + первые байты клиента;
        5. bidirectional relay с activity timeout.

    Любая ошибка на этапах 1-4 рвёт соединение без relay.
    """
    upstream_writer = None
    stream: WebStream | None = None
    client_addr = writer.get_extra_info("peername")
    log.info(f"[client {client_addr}] New connection")

    # TCP_NODELAY на клиентский сокет — симметрично с upstream.
    _apply_tcp_tuning(writer, client_addr)

    try:
        try:
            target_host, _target_port = await _socks5_handshake(reader, writer)
            log.info(
                f"[client {client_addr}] SOCKS5 handshake OK, target={target_host}:{_target_port}"
            )
        except Exception as e:
            log.error(f"[client {client_addr}] SOCKS5 handshake failed: {e}")
            writer.close()
            return

        try:
            first_chunk = await asyncio.wait_for(
                reader.readexactly(4), timeout=SOCKS5_HANDSHAKE_TIMEOUT_SECS
            )
        except asyncio.TimeoutError:
            log.error(
                f"[client {client_addr}] Timeout reading transport tag "
                f"({SOCKS5_HANDSHAKE_TIMEOUT_SECS}s) — client connected but sent nothing "
                f"after SOCKS5 handshake"
            )
            writer.close()
            return
        except asyncio.IncompleteReadError as e:
            log.error(
                f"[client {client_addr}] Failed to read transport tag: "
                f"got {len(e.partial)}/4 bytes"
            )
            writer.close()
            return

        try:
            protocol_tag, consumed = detect_client_transport_tag(first_chunk)
        except ValueError as e:
            log.error(f"[client {client_addr}] {e}")
            writer.close()
            return
        leftover = first_chunk[consumed:]

        # Валидация: транспорт клиента должен соответствовать типу секрета.
        # Нарушение ломает obfuscated2 handshake (тег сверяется сервером).
        tag_names = {
            TAG_ABRIDGED: "abridged (0xEF)",
            TAG_PADDED_INTERMEDIATE: "padded intermediate (0xDD)",
        }
        if protocol_tag != cfg.expected_tag:
            log.error(
                f"[client {client_addr}] Transport/secret mismatch: "
                f"client uses {tag_names.get(protocol_tag, 'unknown')}, "
                f"secret requires {tag_names.get(cfg.expected_tag, 'unknown')}. "
                f"Use protocol_factory={'TCPIntermediatePadded' if cfg.expected_tag == TAG_PADDED_INTERMEDIATE else 'TCPAbridged'}."
            )
            writer.close()
            return

        log.debug(
            f"[client {client_addr}] Transport tag: {tag_names.get(protocol_tag, 'unknown')} (matches secret)"
        )
        log.debug(f"[client {client_addr}] First chunk: {_hex(first_chunk)}")
        log.debug(f"[client {client_addr}] Leftover after tag: {len(leftover)} bytes")

        # DC ID определяется до подключения к upstream — незачем открывать TCP,
        # если не можем заполнить obfuscated2-заголовок.
        if cfg.dc_id_override:
            dc = cfg.dc_id_override
            log.info(f"[client {client_addr}] DC ID override: {dc}")
        else:
            try:
                dc = await guess_dc_id_async(target_host)
            except ValueError as e:
                log.error(f"[client {client_addr}] {e}")
                writer.close()
                return
            log.info(f"[client {client_addr}] DC ID resolved: {dc}")

        # --- Туннель до MTProxy -------------------------------------------
        if cfg.web_link is not None:
            # WEB-режим: вместо TCP-соединения — логический поток в
            # мультиплексированной WEB-сессии (создаётся лениво).
            if web_tunnel is None:
                log.error(
                    f"[client {client_addr}] Internal error: "
                    f"WEB link without an initialized tunnel"
                )
                writer.close()
                return
            try:
                log.info(f"[client {client_addr}] Opening WEB stream...")
                stream = await web_tunnel.open_stream()
            except Exception as e:
                log.error(
                    f"[client {client_addr}] WEB stream open failed: {e}"
                )
                writer.close()
                return
            log.info(
                f"[client {client_addr}] WEB stream {stream.stream_id} opened"
            )
        else:
            try:
                log.info(
                    f"[client {client_addr}] Connecting to upstream {cfg.upstream_host}:{cfg.upstream_port}..."
                )
                try:
                    upstream_reader, upstream_writer = await asyncio.wait_for(
                        asyncio.open_connection(
                            cfg.upstream_host, cfg.upstream_port
                        ),
                        timeout=UPSTREAM_CONNECT_TIMEOUT_SECS,
                    )
                except asyncio.TimeoutError:
                    raise OSError(
                        f"upstream connect timeout ({UPSTREAM_CONNECT_TIMEOUT_SECS}s) "
                        f"to {cfg.upstream_host}:{cfg.upstream_port}"
                    )
                _apply_tcp_tuning(upstream_writer, client_addr)
                log.info(f"[client {client_addr}] TCP connection to upstream established")
            except OSError as e:
                log.error(f"[client {client_addr}] Failed to connect to upstream: {e}")
                writer.close()
                return

        tls_writer: TLSRecordWriter | None = None
        server_initial_appdata = b""

        try:
            if stream is not None and cfg.web_link is not None:
                pass  # WEB-режим: FakeTLS невозможен (только plain/dd секреты)
            elif cfg.is_fake_tls:
                log.info(f"[client {client_addr}] Starting FakeTLS handshake...")
                server_initial_appdata = await async_faketls_handshake(
                    upstream_reader, upstream_writer, cfg.domain, cfg.secret_key,
                    use_block_m=cfg.use_block_m, use_block_e=cfg.use_block_e,
                )
                tls_writer = TLSRecordWriter(send_ccs=cfg.send_ccs)
                log.info(
                    f"[client {client_addr}] FakeTLS handshake completed, "
                    f"server_initial_appdata={len(server_initial_appdata)} bytes, "
                    f"send_ccs={cfg.send_ccs}"
                )

            keys = build_obfuscated2_header(protocol_tag, dc, cfg.secret_key)
            log.debug(
                f"[client {client_addr}] Obfuscated2 header built: "
                f"{len(keys.header)} bytes, tag={protocol_tag.hex()}, dc={dc}"
            )

            # Leftover (байты после transport-тега) шифруем и отправляем как есть —
            # framing не транслируется, релеится end-to-end.
            first_encrypted = keys.encryptor.update(leftover) if leftover else b""
            log.debug(
                f"[client {client_addr}] First encrypted chunk: {len(first_encrypted)} bytes"
            )

            if stream is not None:
                # Всё уходит одним DATA-потоком: header идёт в первой записи.
                await stream.write(keys.header + first_encrypted)
                log.debug(
                    f"[client {client_addr}] Sent via WEB stream: "
                    f"{len(keys.header) + len(first_encrypted)} bytes"
                )
            elif cfg.is_fake_tls:
                wrapped = tls_writer.wrap(keys.header, first_encrypted)
                upstream_writer.write(wrapped)
                log.debug(
                    f"[client {client_addr}] Sent upstream (TLS-wrapped): "
                    f"{len(wrapped)} bytes"
                )
                await upstream_writer.drain()
            else:
                upstream_writer.write(keys.header)
                if first_encrypted:
                    upstream_writer.write(first_encrypted)
                log.debug(
                    f"[client {client_addr}] Sent upstream (raw): "
                    f"{len(keys.header) + len(first_encrypted)} bytes"
                )
                await upstream_writer.drain()
        except Exception as e:
            log.exception(f"[client {client_addr}] Tunnel setup error: {e}")
            if upstream_writer:
                upstream_writer.close()
            writer.close()
            return

        unwrapper = TLSRecordUnwrapper() if (cfg.is_fake_tls and stream is None) else None

        # server_initial_appdata — это AppData-body из FakeTLS handshake
        # (HMAC-верификация), НЕ obfuscated2 данные. TDLib также не
        # использует эти байты после проверки; скармливать unwrapper'у
        # нельзя — это сломает его буфер.
        if server_initial_appdata:
            log.debug(
                f"[client {client_addr}] Discarded server_initial_appdata: "
                f"{len(server_initial_appdata)} bytes (handshake noise)"
            )

        log.info(f"[client {client_addr}] Tunnel established, starting relay")

        # --- Адаптеры транспорта (direct TCP или WEB-поток) ----------------
        if stream is not None:

            async def send_upstream(encrypted: bytes) -> None:
                await stream.write(encrypted)

            async def recv_upstream() -> tuple[bytes, bool]:
                """Возвращает ``(расшифрованные_байты, eof)``."""
                try:
                    chunk = await asyncio.wait_for(
                        stream.read(), timeout=ACTIVITY_TIMEOUT_SECS
                    )
                except asyncio.TimeoutError:
                    raise
                return chunk, not chunk  # b"" ⇒ CLOSE/EOF потока

        else:

            async def send_upstream(encrypted: bytes) -> None:
                if cfg.is_fake_tls and tls_writer:
                    upstream_writer.write(tls_writer.wrap(b"", encrypted))
                else:
                    upstream_writer.write(encrypted)
                await upstream_writer.drain()

            async def recv_upstream() -> tuple[bytes, bool]:
                data = await asyncio.wait_for(
                    upstream_reader.read(65536), timeout=ACTIVITY_TIMEOUT_SECS
                )
                if not data:
                    return b"", True
                plain_wire = unwrapper.feed(data) if unwrapper else data
                return plain_wire, False

        async def client_to_upstream() -> None:
            """Relay: client → obfuscated2 encrypt → tunnel (TLS-wrapped если FakeTLS)."""
            try:
                while True:
                    try:
                        data = await asyncio.wait_for(
                            reader.read(65536), timeout=ACTIVITY_TIMEOUT_SECS
                        )
                    except asyncio.TimeoutError:
                        log.warning(
                            f"[client {client_addr}] client->upstream: no activity for "
                            f"{ACTIVITY_TIMEOUT_SECS}s — closing by activity timeout"
                        )
                        break
                    if not data:
                        log.info(
                            f"[client {client_addr}] Client closed connection (read returned empty)"
                        )
                        break
                    enc = keys.encryptor.update(data)
                    await send_upstream(enc)
                    log.debug(f"[client {client_addr}] client->upstream: {len(data)} bytes")
            except (ConnectionResetError, BrokenPipeError) as e:
                log.debug(f"[client {client_addr}] client->upstream: {e}")
            except Exception as e:
                log.exception(f"[client {client_addr}] client->upstream error: {e}")
            finally:
                if stream is not None:
                    stream.close()
                elif upstream_writer is not None:
                    try:
                        upstream_writer.close()
                    except Exception:
                        pass

        async def upstream_to_client() -> None:
            """Relay: tunnel → TLS-unwrap (если FakeTLS) → obfuscated2 decrypt → client."""
            try:
                while True:
                    try:
                        plain_wire, eof = await recv_upstream()
                    except asyncio.TimeoutError:
                        log.warning(
                            f"[client {client_addr}] upstream->client: no activity for "
                            f"{ACTIVITY_TIMEOUT_SECS}s — closing by activity timeout"
                        )
                        break
                    if eof:
                        log.info(
                            f"[client {client_addr}] Upstream closed connection "
                            f"(read returned empty)"
                        )
                        break
                    if plain_wire:
                        dec = keys.decryptor.update(plain_wire)
                        writer.write(dec)
                        await writer.drain()
                        log.debug(
                            f"[client {client_addr}] upstream->client: {len(dec)} bytes"
                        )
            except (ConnectionResetError, BrokenPipeError) as e:
                log.debug(f"[client {client_addr}] upstream->client: {e}")
            except Exception as e:
                log.exception(f"[client {client_addr}] upstream->client error: {e}")
            finally:
                try:
                    writer.close()
                except Exception:
                    pass

        await asyncio.gather(
            client_to_upstream(), upstream_to_client(), return_exceptions=True
        )
    except asyncio.CancelledError:
        log.info(f"[client {client_addr}] Connection interrupted (server shutting down)")
        raise
    finally:
        log.info(f"[client {client_addr}] Connection closed")
        try:
            writer.close()
            if stream is not None:
                stream.close()  # CLOSE наружу — best-effort
            elif upstream_writer is not None:
                upstream_writer.close()
        except Exception:
            pass
