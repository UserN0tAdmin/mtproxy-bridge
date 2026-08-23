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

"""Запуск/остановка мостов: CLI-сервер и библиотечный режим."""

from __future__ import annotations

import asyncio
import os
import signal
from typing import Callable

from .config import SHUTDOWN_GRACE_SECS, BridgeConfig
from .links import parse_tg_link
from .obfuscated2 import TAG_ABRIDGED, TAG_PADDED_INTERMEDIATE
from .relay import _handle_client
from .utils import log

# ============================================================================
# Корректное (graceful) завершение
# ============================================================================
#
# Не полагаемся на дефолтное поведение asyncio.run() при SIGINT (отмена
# главной задачи → CancelledError всплывает из serve_forever() →
# KeyboardInterrupt с трассировкой). Вместо этого сами перехватываем
# SIGINT/SIGTERM через loop.add_signal_handler, останавливаем listener и
# ждём уже открытые соединения — run_bridge() в итоге просто возвращается
# с exit code 0.


def _make_connection_tracker(
    cfg: BridgeConfig,
) -> tuple[
    Callable[[asyncio.StreamReader, asyncio.StreamWriter], None],
    set[asyncio.Task],
]:
    """Строит client_connected_cb для asyncio.start_server + множество
    активных задач-обработчиков для отслеживания при shutdown.

    asyncio.start_server оборачивает коллбэк в Task, но не сохраняет ссылку,
    поэтому отменить конкретное соединение снаружи нельзя. Здесь мы явно
    регистрируем каждую задачу и убираем её из множества по завершении —
    чтобы _shutdown_server видел актуальный список того, что ещё нужно закрыть.
    """
    active: set[asyncio.Task] = set()

    def _client_connected(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(_handle_client(reader, writer, cfg))

        def _on_done(t: asyncio.Task) -> None:
            active.discard(t)
            if not t.cancelled():
                exc = t.exception()
                if exc is not None:
                    log.error(
                        f"Unhandled error in client connection task: {exc!r}",
                        exc_info=exc,
                    )

        active.add(task)
        task.add_done_callback(_on_done)

    return _client_connected, active


async def _shutdown_server(
    server: asyncio.Server,
    active_connections: set[asyncio.Task],
    *,
    grace: float = SHUTDOWN_GRACE_SECS,
) -> None:
    """Останавливает listener и корректно закрывает уже открытые соединения.

    Порядок важен: сначала ``server.close()`` (снимает listener), потом
    ``task.cancel()`` для всех отслеживаемых задач, и только потом ждём их
    через ``asyncio.wait``. ``wait_closed()`` здесь НЕ вызывается — начиная
    с Python 3.12.1 он ждёт закрытия всех активных соединений сервера, что
    дало бы deadlock (сервер ждёт соединения, соединения ждут отмены).

    Каждая отменённая задача — это ``_handle_client()`` с единым
    try/except CancelledError/finally на весь пайплайн, так что оба сокета
    гарантированно закрываются на любой стадии отмены. ``grace`` — верхняя
    граница ожидания на случай зависшей задачи.
    """
    server.close()

    if not active_connections:
        return

    log.info(
        f"Closing {len(active_connections)} active connection(s) "
        f"(up to {grace:.0f}s)..."
    )
    for task in active_connections:
        task.cancel()

    _done, pending = await asyncio.wait(active_connections, timeout=grace)
    if pending:
        log.warning(
            f"{len(pending)} connection(s) did not close within {grace:.0f}s "
            f"and were left running to shut down on their own"
        )


def _install_shutdown_handler(stop_event: asyncio.Event) -> None:
    """Регистрирует SIGINT/SIGTERM: по сигналу выставляется stop_event,
    что будит run_bridge() и запускает штатную процедуру остановки.

    Повторный сигнал во время завершения — форсирует немедленный выход через
    ``os._exit`` (компромисс в пользу отзывчивости Ctrl+C, relay всё равно
    не буферизует).

    На Windows ``add_signal_handler`` не реализован — откатываемся на
    ``signal.signal()`` (ловит хотя бы SIGINT/Ctrl+C).
    """
    loop = asyncio.get_running_loop()

    def _on_signal(sig_name: str) -> None:
        if stop_event.is_set():
            log.warning(f"Second {sig_name} received — forcing immediate exit")
            os._exit(130 if sig_name == "SIGINT" else 143)
        log.info(
            f"{sig_name} received, shutting down gracefully "
            f"(Ctrl+C again to force-quit)..."
        )
        stop_event.set()

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _on_signal, sig.name)
    except NotImplementedError:

        def _sync_handler(signum: int, _frame: object) -> None:
            loop.call_soon_threadsafe(_on_signal, signal.Signals(signum).name)

        signal.signal(signal.SIGINT, _sync_handler)


async def run_bridge(cfg: BridgeConfig) -> None:
    """Start a blocking SOCKS5 server (CLI mode).

    Runs until SIGINT/SIGTERM, then shuts down gracefully: stops accepting
    new connections, cancels and waits (up to SHUTDOWN_GRACE_SECS) for
    already-open ones, and returns normally — no exception leaves this
    function as part of a normal shutdown.
    """
    stop_event = asyncio.Event()
    _install_shutdown_handler(stop_event)

    client_connected_cb, active_connections = _make_connection_tracker(cfg)
    server = await asyncio.start_server(
        client_connected_cb, cfg.listen_host, cfg.listen_port
    )
    transport_name = (
        "padded intermediate (0xDD)"
        if cfg.expected_tag == TAG_PADDED_INTERMEDIATE
        else (
            "abridged (0xEF)"
            if cfg.expected_tag == TAG_ABRIDGED
            else f"unknown ({cfg.expected_tag.hex()})"
        )
    )
    print(
        f"SOCKS5 bridge listening on \n\nsocks5://{cfg.listen_host}:{cfg.listen_port}\n\n"
        f"tunnel to {cfg.upstream_host}:{cfg.upstream_port} "
        f"({'FakeTLS' if cfg.is_fake_tls else 'plain obfuscated2'})"
    )
    print(
        f"transport={transport_name}, "
        f"send_ccs={cfg.send_ccs}, use_block_m={cfg.use_block_m}, "
        f"use_block_e={cfg.use_block_e}"
    )

    await stop_event.wait()
    log.info("Stopping listener, no new connections will be accepted...")
    await _shutdown_server(server, active_connections)
    log.info("Bridge stopped.")


# Сервер → множество активных задач-обработчиков (см. _make_connection_tracker).
# Хранятся именно клиентские задачи, чтобы stop_all_bridges могла дождаться каждой.
_running_servers: dict[asyncio.Server, set[asyncio.Task]] = {}


async def start_local_bridge(
    tg_link: str,
    listen_host: str = "127.0.0.1",
    listen_port: int = 0,
    dc_id_override: int = 0,
    send_ccs: bool = True,
    use_block_m: bool = True,
    use_block_e: bool = True,
) -> int:
    """Start the bridge as a background asyncio task and return the local port.

    Intended for embedding into an application (e.g. before starting a
    Pyrogram/Kurigram client). To stop all background bridges, call
    :func:`stop_all_bridges` — e.g. from your own SIGINT/SIGTERM handler or
    shutdown path; this module does not install signal handlers of its own
    in library mode, so as not to clobber a host application's handlers.

    Args:
        tg_link: ``tg://proxy?server=...&port=...&secret=...``.
        listen_host: SOCKS5 host (default 127.0.0.1).
        listen_port: port; 0 = pick a free one automatically.
        dc_id_override: explicit DC ID (escape hatch; 0 = auto).
        send_ccs: Send CCS (TDLib ``first_prefix``) before the first AppData record.
        use_block_m: Use block M (Kyber-like) in ClientHello.
        use_block_e: Use block E (random extra) in ClientHello.

    Returns:
        The actual port the bridge is listening on.
    """
    link = parse_tg_link(tg_link)
    cfg = BridgeConfig(
        listen_host=listen_host,
        listen_port=listen_port,
        upstream_host=link.server,
        upstream_port=link.port,
        secret_key=link.secret_key,
        domain=link.domain,
        is_fake_tls=link.is_fake_tls,
        expected_tag=link.expected_tag,
        dc_id_override=dc_id_override,
        send_ccs=send_ccs,
        use_block_m=use_block_m,
        use_block_e=use_block_e,
    )
    client_connected_cb, active_connections = _make_connection_tracker(cfg)
    server = await asyncio.start_server(client_connected_cb, listen_host, listen_port)
    actual_port = server.sockets[0].getsockname()[1]

    _running_servers[server] = active_connections

    return actual_port


async def stop_all_bridges() -> None:
    """Gracefully stop all background bridges started via :func:`start_local_bridge`.

    For each bridge: stops accepting new connections, then cancels and
    waits (up to ``SHUTDOWN_GRACE_SECS`` per bridge, all bridges in
    parallel) for already-open client connections to close their sockets.
    """
    if not _running_servers:
        return

    await asyncio.gather(
        *(
            _shutdown_server(server, active_connections)
            for server, active_connections in _running_servers.items()
        ),
        return_exceptions=True,
    )
    _running_servers.clear()
