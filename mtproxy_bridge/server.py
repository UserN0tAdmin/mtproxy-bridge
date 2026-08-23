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
from typing import TYPE_CHECKING, Callable

from .config import SHUTDOWN_GRACE_SECS, BridgeConfig
from .links import is_web_proxy_link, parse_tg_link, parse_web_link
from .obfuscated2 import TAG_ABRIDGED, TAG_PADDED_INTERMEDIATE
from .relay import _handle_client
from .utils import log

if TYPE_CHECKING:
    from .web.tunnel import WebTunnel

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
    web_tunnel: WebTunnel | None = None,
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
        task = asyncio.create_task(
            _handle_client(reader, writer, cfg, web_tunnel)
        )

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


async def run_bridge(
    cfg: BridgeConfig, *, web_tunnel: WebTunnel | None = None
) -> None:
    """Start a blocking SOCKS5 server (CLI mode).

    Runs until SIGINT/SIGTERM, then shuts down gracefully: stops accepting
    new connections, cancels and waits (up to SHUTDOWN_GRACE_SECS) for
    already-open ones, and returns normally — no exception leaves this
    function as part of a normal shutdown.
    """
    stop_event = asyncio.Event()
    _install_shutdown_handler(stop_event)

    client_connected_cb, active_connections = _make_connection_tracker(
        cfg, web_tunnel
    )
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
    print(f"SOCKS5 bridge listening on \n\nsocks5://{cfg.listen_host}:{cfg.listen_port}\n")
    if cfg.web_link is not None:
        secret_mode = "dd (random padding)" if cfg.web_link.is_padded else "plain"
        print(
            f"WEB proxy tunnel via https://{cfg.web_link.host} "
            f"(secret={secret_mode})"
        )
    else:
        print(
            f"tunnel to {cfg.upstream_host}:{cfg.upstream_port} "
            f"({'FakeTLS' if cfg.is_fake_tls else 'plain obfuscated2'})"
        )
    print(f"transport={transport_name}")

    await stop_event.wait()
    log.info("Stopping listener, no new connections will be accepted...")
    await _shutdown_server(server, active_connections)
    if web_tunnel is not None:
        log.info("Closing WEB tunnel...")
        try:
            await web_tunnel.aclose()
        except Exception as exc:  # pragma: no cover - защита остановки
            log.warning(f"WEB tunnel close error: {exc!r}")
    log.info("Bridge stopped.")


# Сервер → (множество активных задач-обработчиков, WEB-туннель или None).
# Хранятся именно клиентские задачи, чтобы stop_all_bridges могла дождаться
# каждой; WEB-туннель закрывается вместе со своим сервером.
_running_bridges: dict[asyncio.Server, tuple[set[asyncio.Task], WebTunnel | None]] = {}


def _build_bridge_config(
    tg_link: str,
    listen_host: str,
    listen_port: int,
    dc_id_override: int,
    send_ccs: bool,
    use_block_m: bool,
    use_block_e: bool,
    web_origin: str | None,
) -> BridgeConfig:
    """Разбирает ссылку (tg://proxy либо tg://webproxy) в BridgeConfig."""
    if is_web_proxy_link(tg_link):
        web_link = parse_web_link(tg_link)
        return BridgeConfig(
            listen_host=listen_host,
            listen_port=listen_port,
            upstream_host="",
            upstream_port=0,
            secret_key=web_link.secret_key,
            domain="",
            is_fake_tls=False,
            expected_tag=(
                TAG_PADDED_INTERMEDIATE if web_link.is_padded else TAG_ABRIDGED
            ),
            dc_id_override=dc_id_override,
            send_ccs=send_ccs,
            use_block_m=use_block_m,
            use_block_e=use_block_e,
            web_link=web_link,
            web_origin=web_origin,
        )
    link = parse_tg_link(tg_link)
    return BridgeConfig(
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


async def start_local_bridge(
    tg_link: str,
    listen_host: str = "127.0.0.1",
    listen_port: int = 0,
    dc_id_override: int = 0,
    send_ccs: bool = True,
    use_block_m: bool = True,
    use_block_e: bool = True,
    web_origin: str | None = None,
) -> int:
    """Start the bridge as a background asyncio task and return the local port.

    Intended for embedding into an application (e.g. before starting a
    Pyrogram/Kurigram client). Accepts both classic MTProto links
    (``tg://proxy?server=...&port=...&secret=...``) and WEB proxy links
    (``tg://webproxy?server=...&secret=...``). To stop all background
    bridges, call :func:`stop_all_bridges` — e.g. from your own
    SIGINT/SIGTERM handler or shutdown path; this module does not install
    signal handlers of its own in library mode, so as not to clobber a host
    application's handlers.

    Args:
        tg_link: MTProto or WEB proxy link.
        listen_host: SOCKS5 host (default 127.0.0.1).
        listen_port: port; 0 = pick a free one automatically.
        dc_id_override: explicit DC ID (escape hatch; 0 = auto).
        send_ccs: Send CCS (TDLib ``first_prefix``) before the first AppData
            record (direct FakeTLS mode only).
        use_block_m: Use block M (Kyber-like) in ClientHello (direct mode).
        use_block_e: Use block E (random extra) in ClientHello (direct mode).
        web_origin: override the WEB relay origin (default
            ``https://<host>``); useful for tests and non-standard deploys.

    Returns:
        The actual port the bridge is listening on.
    """
    cfg = _build_bridge_config(
        tg_link, listen_host, listen_port, dc_id_override,
        send_ccs, use_block_m, use_block_e, web_origin,
    )
    tunnel: WebTunnel | None = None
    if cfg.web_link is not None:
        from .web.tunnel import WebTunnel

        tunnel = WebTunnel(cfg.web_link, origin=cfg.web_origin)
    client_connected_cb, active_connections = _make_connection_tracker(
        cfg, tunnel
    )
    server = await asyncio.start_server(client_connected_cb, listen_host, listen_port)
    actual_port = server.sockets[0].getsockname()[1]

    _running_bridges[server] = (active_connections, tunnel)

    return actual_port


async def stop_all_bridges() -> None:
    """Gracefully stop all background bridges started via :func:`start_local_bridge`.

    For each bridge: stops accepting new connections, cancels and waits
    (up to ``SHUTDOWN_GRACE_SECS`` per bridge, all bridges in parallel)
    for already-open client connections, then closes the WEB tunnel (if any).
    """
    if not _running_bridges:
        return

    async def _stop_one(
        server: asyncio.Server,
        active_connections: set[asyncio.Task],
        tunnel: WebTunnel | None,
    ) -> None:
        await _shutdown_server(server, active_connections)
        if tunnel is not None:
            try:
                await tunnel.aclose()
            except Exception as exc:
                log.warning(f"WEB tunnel close error: {exc!r}")

    bridges = list(_running_bridges.items())
    _running_bridges.clear()
    await asyncio.gather(
        *(_stop_one(server, conns, tunnel) for server, (conns, tunnel) in bridges),
        return_exceptions=True,
    )
