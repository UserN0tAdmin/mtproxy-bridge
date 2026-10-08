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

"""Тесты жизненного цикла моста (``server.py``) и утилит (``utils.py``).

Реальные сигналы процессу pytest НЕ отправляются: регистрацию обработчиков
SIGINT/SIGTERM проверяем подменой ``loop.add_signal_handler`` и вызовом
захваченного колбэка. Настоящая доставка сигнала проверяется на
отдельном процессе в ``test_direct_cli.py``.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import socket
import time

import pytest
from direct_fakes import (  # noqa: F401
    SECRET_DD,
    SECRET_EE,
    SECRET_PLAIN,
    close_writer,
    drain_to_eof,
    eventually,
    free_port,
    make_link,
    read_exactly,
    socks5_connect,
)

from mtproxy_bridge import relay as relay_mod
from mtproxy_bridge import server as server_mod
from mtproxy_bridge import utils
from mtproxy_bridge.config import BridgeConfig
from mtproxy_bridge.obfuscated2 import TAG_ABRIDGED, TAG_PADDED_INTERMEDIATE
from mtproxy_bridge.server import (
    _build_bridge_config,
    _install_shutdown_handler,
    _make_connection_tracker,
    _shutdown_server,
    run_bridge,
    start_local_bridge,
    stop_all_bridges,
)

KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


async def _can_connect(port: int) -> bool:
    try:
        _r, w = await asyncio.open_connection("127.0.0.1", port)
    except OSError:
        return False
    w.close()
    return True


async def _echo_via_bridge(
    port: int, tag: bytes = b"\xef", payload: bytes = b"ping-pong"
) -> bool:
    reader, writer = await socks5_connect(port)
    writer.write(tag + payload)
    ok = await read_exactly(reader, len(payload), 10) == payload
    await close_writer(writer)
    return ok


# ============================================================================
# _build_bridge_config
# ============================================================================


class TestBuildBridgeConfig:
    @pytest.mark.parametrize(
        ("secret", "fake_tls", "domain", "tag"),
        [
            (SECRET_PLAIN, False, "", TAG_ABRIDGED),
            (SECRET_DD, False, "", TAG_PADDED_INTERMEDIATE),
            (SECRET_EE, True, "tls.example.com", TAG_PADDED_INTERMEDIATE),
        ],
        ids=["bare", "dd", "ee"],
    )
    def test_direct_config(self, secret, fake_tls, domain, tag):
        cfg = _build_bridge_config(
            f"tg://proxy?server=h.example.org&port=8443&secret={secret}",
            "127.0.0.1", 1081, 3, False, False, True, None,
        )  # fmt: skip
        assert cfg == BridgeConfig(
            listen_host="127.0.0.1",
            listen_port=1081,
            upstream_host="h.example.org",
            upstream_port=8443,
            secret_key=KEY,
            domain=domain,
            is_fake_tls=fake_tls,
            expected_tag=tag,
            dc_id_override=3,
            send_ccs=False,
            use_block_m=False,
            use_block_e=True,
            web_link=None,
            web_origin=None,
        )

    def test_invalid_link_raises_value_error(self):
        with pytest.raises(ValueError):
            _build_bridge_config(
                "tg://proxy?server=h&port=1&secret=" + "00" * 15,
                "127.0.0.1", 0, 0, True, True, True, None,
            )  # fmt: skip


# ============================================================================
# start_local_bridge / stop_all_bridges
# ============================================================================


class TestStartStop:
    async def test_start_returns_a_working_port(self, proxy_factory, bridge_factory):
        proxy = await proxy_factory(domain=None)
        port = await bridge_factory(make_link(proxy.port, SECRET_PLAIN))
        assert isinstance(port, int) and 0 < port < 65536
        assert await _echo_via_bridge(port)

    async def test_port_zero_picks_distinct_free_ports(
        self, proxy_factory, bridge_factory
    ):
        proxy = await proxy_factory(domain=None)
        link = make_link(proxy.port, SECRET_PLAIN)
        ports = {await bridge_factory(link) for _ in range(3)}
        assert len(ports) == 3

    async def test_explicit_port(self, proxy_factory, bridge_factory):
        proxy = await proxy_factory(domain=None)
        wanted = free_port()
        port = await bridge_factory(
            make_link(proxy.port, SECRET_PLAIN), listen_port=wanted
        )
        assert port == wanted
        assert await _echo_via_bridge(wanted)

    async def test_port_in_use_raises_and_registers_nothing(
        self, proxy_factory, bridge_factory
    ):
        proxy = await proxy_factory(domain=None)
        link = make_link(proxy.port, SECRET_PLAIN)
        port = await bridge_factory(link)
        before = len(server_mod._running_bridges)
        with pytest.raises(OSError):
            await start_local_bridge(link, listen_port=port)
        assert len(server_mod._running_bridges) == before

    @pytest.mark.parametrize(
        "link",
        [
            "tg://proxy?server=h.io&port=443",
            "tg://proxy?server=h.io&port=443&secret=" + "00" * 15,
            "tg://proxy?server=h.io&port=x&secret=" + "00" * 16,
            "",
        ],
        ids=["no-secret", "bad-secret", "bad-port", "empty"],
    )
    async def test_invalid_link_raises_without_starting_anything(
        self, bridge_factory, link
    ):
        before = len(server_mod._running_bridges)
        with pytest.raises(ValueError):
            await start_local_bridge(link)
        assert len(server_mod._running_bridges) == before

    async def test_stop_closes_the_listener(self, proxy_factory):
        proxy = await proxy_factory(domain=None)
        port = await start_local_bridge(make_link(proxy.port, SECRET_PLAIN))
        assert await _can_connect(port)
        await stop_all_bridges()
        assert not await _can_connect(port)
        assert not server_mod._running_bridges

    async def test_stop_is_idempotent_and_safe_when_nothing_runs(self):
        await stop_all_bridges()
        await stop_all_bridges()

    async def test_stop_closes_active_connections_quickly(self, proxy_factory):
        proxy = await proxy_factory(domain=None)
        port = await start_local_bridge(make_link(proxy.port, SECRET_PLAIN))
        sessions = []
        for _ in range(3):
            reader, writer = await socks5_connect(port)
            writer.write(b"\xefabcd")
            await read_exactly(reader, 4, 10)
            sessions.append((reader, writer))
        started = time.monotonic()
        await stop_all_bridges()
        assert time.monotonic() - started < 3
        for reader, writer in sessions:
            assert await drain_to_eof(reader) == b""
            await close_writer(writer)
        for rec in proxy.connections:  # и upstream-сторона тоже закрыта
            await asyncio.wait_for(rec.closed.wait(), 5)

    async def test_stop_while_a_client_is_still_in_the_socks5_handshake(
        self, proxy_factory
    ):
        proxy = await proxy_factory(domain=None)
        port = await start_local_bridge(make_link(proxy.port, SECRET_PLAIN))
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"\x05")  # недописанный greeting
        await writer.drain()
        await asyncio.sleep(0.05)
        started = time.monotonic()
        await stop_all_bridges()
        assert time.monotonic() - started < 3
        assert await drain_to_eof(reader) == b""
        await close_writer(writer)

    async def test_several_bridges_stop_together(self, proxy_factory):
        proxy = await proxy_factory(domain=None)
        link = make_link(proxy.port, SECRET_PLAIN)
        ports = [await start_local_bridge(link) for _ in range(3)]
        assert len(server_mod._running_bridges) == 3
        await stop_all_bridges()
        for port in ports:
            assert not await _can_connect(port)

    async def test_bridges_are_independent(self, proxy_factory, bridge_factory):
        plain = await proxy_factory(domain=None)
        tls = await proxy_factory(domain="tls.example.com")
        port_a = await bridge_factory(make_link(plain.port, SECRET_PLAIN))
        port_b = await bridge_factory(make_link(tls.port, SECRET_EE))
        assert await _echo_via_bridge(port_a, b"\xef")
        assert await _echo_via_bridge(port_b, b"\xdd\xdd\xdd\xdd")
        assert len(plain.connections) == 1 and len(tls.connections) == 1

    async def test_restart_after_stop(self, proxy_factory):
        proxy = await proxy_factory(domain=None)
        link = make_link(proxy.port, SECRET_PLAIN)
        first = await start_local_bridge(link)
        assert await _echo_via_bridge(first)
        await stop_all_bridges()
        second = await start_local_bridge(link)
        try:
            assert await _echo_via_bridge(second)
        finally:
            await stop_all_bridges()

    async def test_listen_host_is_loopback_by_default(
        self, proxy_factory, bridge_factory
    ):
        proxy = await proxy_factory(domain=None)
        await bridge_factory(make_link(proxy.port, SECRET_PLAIN))
        ((server, _value),) = server_mod._running_bridges.items()
        assert [s.getsockname()[0] for s in server.sockets] == ["127.0.0.1"]

    async def test_tcp_tuning_is_applied_to_both_sockets(
        self, proxy_factory, bridge_factory, monkeypatch
    ):
        calls = []
        real = relay_mod._apply_tcp_tuning
        monkeypatch.setattr(
            relay_mod,
            "_apply_tcp_tuning",
            lambda writer, label: (calls.append(writer), real(writer, label))[1],
        )
        proxy = await proxy_factory(domain=None)
        port = await bridge_factory(make_link(proxy.port, SECRET_PLAIN))
        assert await _echo_via_bridge(port)
        assert len(calls) == 2  # клиентский и upstream-сокеты


# ============================================================================
# _make_connection_tracker и _shutdown_server
# ============================================================================


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class TestConnectionTracker:
    async def test_unhandled_error_is_logged_and_task_is_forgotten(self, monkeypatch):
        async def boom(*_args):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(server_mod, "_handle_client", boom)
        handler = _ListHandler()
        logger = logging.getLogger("mtproxy_bridge")
        logger.addHandler(handler)
        try:
            cb, active = _make_connection_tracker(
                None
            )  # cfg не нужен: boom его не читает
            cb(None, None)
            assert len(active) == 1
            await eventually(lambda: not active)
        finally:
            logger.removeHandler(handler)
        assert any("kaboom" in r.getMessage() for r in handler.records)

    async def test_cancelled_task_is_forgotten_quietly(self, monkeypatch):
        started = asyncio.Event()

        async def sleeper(*_args):
            started.set()
            await asyncio.sleep(3600)

        monkeypatch.setattr(server_mod, "_handle_client", sleeper)
        handler = _ListHandler()
        logger = logging.getLogger("mtproxy_bridge")
        logger.addHandler(handler)
        try:
            cb, active = _make_connection_tracker(None)
            cb(None, None)
            await started.wait()
            (task,) = tuple(active)
            task.cancel()
            await eventually(lambda: not active)
        finally:
            logger.removeHandler(handler)
        assert not [r for r in handler.records if r.levelno >= logging.ERROR]


class TestShutdownServer:
    async def test_closes_listener_and_cancels_tasks(self):
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        task = asyncio.ensure_future(asyncio.sleep(3600))
        await _shutdown_server(server, {task}, grace=2)
        assert task.cancelled()
        assert not await _can_connect(port)

    async def test_no_connections_returns_immediately(self):
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        started = time.monotonic()
        await _shutdown_server(server, set())
        assert time.monotonic() - started < 0.5

    async def test_stubborn_task_does_not_block_shutdown_forever(self):
        server = await asyncio.start_server(lambda r, w: None, "127.0.0.1", 0)
        release = asyncio.Event()

        async def stubborn():
            while not release.is_set():
                try:
                    await asyncio.sleep(0.05)
                except asyncio.CancelledError:
                    pass  # игнорирует отмену

        task = asyncio.ensure_future(stubborn())
        await asyncio.sleep(0)
        handler = _ListHandler()
        logger = logging.getLogger("mtproxy_bridge")
        logger.addHandler(handler)
        try:
            started = time.monotonic()
            await _shutdown_server(server, {task}, grace=0.3)
            assert 0.2 < time.monotonic() - started < 2
        finally:
            logger.removeHandler(handler)
            release.set()
            await task
        assert any("did not close" in r.getMessage() for r in handler.records)


# ============================================================================
# Обработчики сигналов
# ============================================================================


class TestShutdownHandler:
    @pytest.fixture
    async def signals(self, monkeypatch):
        """Перехватывает loop.add_signal_handler: настоящих сигналов нет.

        Фикстура async намеренно: ``get_running_loop()`` работает только
        внутри цикла, а синхронные фикстуры pytest-asyncio исполняет вне его.
        """
        registered: dict = {}
        loop = asyncio.get_running_loop()
        monkeypatch.setattr(
            loop,
            "add_signal_handler",
            lambda sig, cb, *args: registered.__setitem__(sig, (cb, args)),
        )
        exits: list = []
        monkeypatch.setattr(server_mod.os, "_exit", lambda code: exits.append(code))
        return registered, exits

    async def test_sigint_and_sigterm_are_registered(self, signals):
        registered, _exits = signals
        _install_shutdown_handler(asyncio.Event())
        assert set(registered) == {signal.SIGINT, signal.SIGTERM}

    @pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM])
    async def test_first_signal_requests_graceful_stop(self, signals, sig):
        registered, exits = signals
        stop = asyncio.Event()
        _install_shutdown_handler(stop)
        cb, args = registered[sig]
        cb(*args)
        assert stop.is_set()
        assert exits == []

    @pytest.mark.parametrize(
        ("sig", "code"), [(signal.SIGINT, 130), (signal.SIGTERM, 143)]
    )
    async def test_second_signal_forces_exit(self, signals, sig, code):
        registered, exits = signals
        _install_shutdown_handler(asyncio.Event())
        cb, args = registered[sig]
        cb(*args)
        cb(*args)
        assert exits == [code]

    async def test_fallback_when_add_signal_handler_is_unavailable(self, monkeypatch):
        loop = asyncio.get_running_loop()

        def unsupported(*_a, **_k):
            raise NotImplementedError

        monkeypatch.setattr(loop, "add_signal_handler", unsupported)
        installed = {}
        monkeypatch.setattr(
            server_mod.signal, "signal", lambda sig, h: installed.__setitem__(sig, h)
        )
        stop = asyncio.Event()
        _install_shutdown_handler(stop)
        assert signal.SIGINT in installed
        installed[signal.SIGINT](signal.SIGINT, None)  # как если бы пришёл Ctrl+C
        await asyncio.wait_for(stop.wait(), 2)


# ============================================================================
# run_bridge (блокирующий режим CLI)
# ============================================================================


class TestRunBridge:
    @pytest.fixture
    def stop_events(self, monkeypatch):
        """Список stop_event'ов, которые run_bridge передаёт в установку сигналов.

        Настоящие обработчики не ставятся; тест сам «шлёт сигнал» через
        ``stop_events[0].set()``.
        """
        events: list[asyncio.Event] = []
        monkeypatch.setattr(server_mod, "_install_shutdown_handler", events.append)
        return events

    @pytest.mark.parametrize(
        ("secret", "domain", "banner_tunnel", "banner_transport", "tag"),
        [
            (SECRET_PLAIN, None, "(plain obfuscated2)", "abridged (0xEF)", b"\xef"),
            (
                SECRET_DD,
                None,
                "(plain obfuscated2)",
                "padded intermediate (0xDD)",
                b"\xdd" * 4,
            ),
            (
                SECRET_EE,
                "tls.example.com",
                "(FakeTLS)",
                "padded intermediate (0xDD)",
                b"\xdd" * 4,
            ),
        ],
        ids=["bare", "dd", "ee"],
    )
    async def test_serves_until_stopped_and_prints_the_banner(
        self,
        proxy_factory,
        stop_events,
        capsys,
        secret,
        domain,
        banner_tunnel,
        banner_transport,
        tag,
    ):
        proxy = await proxy_factory(domain=domain)
        port = free_port()
        cfg = _build_bridge_config(
            make_link(proxy.port, secret), "127.0.0.1", port, 0, True, True, True, None
        )
        task = asyncio.ensure_future(run_bridge(cfg))
        await eventually(lambda: stop_events and port_open_sync(port))
        assert not task.done()
        assert await _echo_via_bridge(port, tag)

        stop_events[0].set()  # «пришёл SIGTERM»
        assert await asyncio.wait_for(task, 10) is None  # завершился без исключения
        assert not await _can_connect(port)

        out = capsys.readouterr().out
        assert f"socks5://127.0.0.1:{port}" in out
        assert f"tunnel to 127.0.0.1:{proxy.port} {banner_tunnel}" in out
        assert f"transport={banner_transport}" in out

    async def test_active_connections_are_closed_on_stop(
        self, proxy_factory, stop_events
    ):
        proxy = await proxy_factory(domain=None)
        port = free_port()
        cfg = _build_bridge_config(
            make_link(proxy.port, SECRET_PLAIN),
            "127.0.0.1",
            port,
            0,
            True,
            True,
            True,
            None,
        )
        task = asyncio.ensure_future(run_bridge(cfg))
        await eventually(lambda: stop_events and port_open_sync(port))
        reader, writer = await socks5_connect(port)
        writer.write(b"\xefabcd")
        await read_exactly(reader, 4, 10)

        stop_events[0].set()
        await asyncio.wait_for(task, 10)
        assert await drain_to_eof(reader) == b""
        await close_writer(writer)


def port_open_sync(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex(("127.0.0.1", port)) == 0


# ============================================================================
# utils
# ============================================================================


class _Sock:
    def __init__(self, fail: set[tuple[int, int]] = frozenset()) -> None:
        self.calls: list[tuple[int, int, int]] = []
        self._fail = fail

    def setsockopt(self, level: int, opt: int, value: int) -> None:
        if (level, opt) in self._fail:
            raise OSError("not supported")
        self.calls.append((level, opt, value))


class _Writer:
    def __init__(self, sock) -> None:
        self._sock = sock

    def get_extra_info(self, name: str):
        return self._sock if name == "socket" else None


class TestHexHelper:
    def test_short_buffer_is_fully_hex(self):
        assert utils._hex(b"\x01\xab") == "01ab"

    def test_buffer_at_the_limit_is_not_truncated(self):
        assert utils._hex(bytes(64)) == "00" * 64

    def test_long_buffer_is_truncated_with_length(self):
        text = utils._hex(bytes(range(100)), limit=4)
        assert text == "00010203...(100 bytes)"

    def test_empty(self):
        assert utils._hex(b"") == ""


class TestTcpTuning:
    def test_sets_nodelay_keepalive_and_timers(self):
        sock = _Sock()
        utils._apply_tcp_tuning(_Writer(sock), "peer")
        by_opt = {opt: value for _lvl, opt, value in sock.calls}
        assert by_opt[socket.TCP_NODELAY] == 1
        assert by_opt[socket.SO_KEEPALIVE] == 1
        for name, value in (
            ("TCP_KEEPIDLE", 10),
            ("TCP_KEEPINTVL", 5),
            ("TCP_KEEPCNT", 3),
        ):
            if hasattr(socket, name):
                assert by_opt[getattr(socket, name)] == value, name

    def test_no_socket_is_a_noop(self):
        utils._apply_tcp_tuning(_Writer(None), "peer")  # не падает

    def test_nodelay_failure_is_not_fatal(self):
        sock = _Sock(fail={(socket.IPPROTO_TCP, socket.TCP_NODELAY)})
        utils._apply_tcp_tuning(_Writer(sock), "peer")
        assert any(opt == socket.SO_KEEPALIVE for _l, opt, _v in sock.calls)

    def test_keepalive_failure_skips_the_timers(self):
        sock = _Sock(fail={(socket.SOL_SOCKET, socket.SO_KEEPALIVE)})
        utils._apply_tcp_tuning(_Writer(sock), "peer")
        assert [opt for _l, opt, _v in sock.calls] == [socket.TCP_NODELAY]

    def test_unavailable_timer_options_are_skipped(self, monkeypatch):
        for name in ("TCP_KEEPIDLE", "TCP_KEEPINTVL", "TCP_KEEPCNT"):
            monkeypatch.setattr(socket, name, None, raising=False)
        sock = _Sock()
        utils._apply_tcp_tuning(_Writer(sock), "peer")
        assert {opt for _l, opt, _v in sock.calls} == {
            socket.TCP_NODELAY,
            socket.SO_KEEPALIVE,
        }

    def test_single_timer_failure_does_not_stop_the_others(self):
        if not hasattr(socket, "TCP_KEEPIDLE"):
            pytest.skip("platform has no TCP_KEEPIDLE")
        sock = _Sock(fail={(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE)})
        utils._apply_tcp_tuning(_Writer(sock), "peer")
        opts = {opt for _l, opt, _v in sock.calls}
        assert socket.TCP_KEEPIDLE not in opts
        assert socket.TCP_KEEPINTVL in opts and socket.TCP_KEEPCNT in opts

    async def test_real_socket(self):
        async def on_client(_r, w):
            w.close()

        server = await asyncio.start_server(on_client, "127.0.0.1", 0)
        try:
            _r, writer = await asyncio.open_connection(
                "127.0.0.1", server.sockets[0].getsockname()[1]
            )
            utils._apply_tcp_tuning(writer, "peer")
            sock = writer.get_extra_info("socket")
            assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0
            assert sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE) != 0
            if hasattr(socket, "TCP_KEEPIDLE"):
                assert sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE) == 10
            writer.close()
        finally:
            server.close()
