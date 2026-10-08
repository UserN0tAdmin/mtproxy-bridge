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

"""Тесты CLI классического MTProxy в отдельном процессе.

Запускается настоящий ``python -m mtproxy_bridge``: аргументы, коды выхода,
баннер, ``check`` (текст и ``--json``) и корректное завершение по
SIGINT/SIGTERM. Фейковый MTProxy живёт в процессе теста, мост и ``check``
— в подпроцессе, то есть путь клиента полностью реальный.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

import pytest
from direct_fakes import (  # noqa: F401
    DOMAIN,
    SECRET_DD,
    SECRET_EE,
    SECRET_PLAIN,
    close_writer,
    free_port,
    make_link,
    read_exactly,
    respq_handler,
    socks5_connect,
)

ROOT = Path(__file__).resolve().parent.parent
ENV = dict(
    os.environ,
    PYTHONPATH=str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""),
    PYTHONUNBUFFERED="1",
)
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX signals")

MODES = [
    ("bare", SECRET_PLAIN, None, b"\xef"),
    ("dd", SECRET_DD, None, b"\xdd" * 4),
    ("ee", SECRET_EE, DOMAIN, b"\xdd" * 4),
]
MODE_IDS = [m[0] for m in MODES]


async def _spawn(*args: str) -> asyncio.subprocess.Process:
    return await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "mtproxy_bridge",
        *args,
        env=ENV,
        cwd=str(ROOT),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def _run(*args: str, timeout: float = 60.0):
    proc = await _spawn(*args)
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode, out.decode(), err.decode()


async def _wait_banner(proc: asyncio.subprocess.Process, timeout: float = 20.0) -> str:
    """Читает stdout до строки ``transport=...`` (последняя строка баннера)."""
    seen = []

    async def _go() -> None:
        while True:
            line = await proc.stdout.readline()
            if not line:
                raise AssertionError(f"process exited before the banner: {seen!r}")
            seen.append(line.decode())
            if line.startswith(b"transport="):
                return

    await asyncio.wait_for(_go(), timeout)
    return "".join(seen)


# ============================================================================
# Аргументы и коды выхода
# ============================================================================


class TestArguments:
    async def test_help(self):
        code, out, _err = await _run("--help")
        assert code == 0
        for flag in ("--listen-host", "--listen-port", "--dc-id-override", "--no-ccs",
                     "--no-block-m", "--no-block-e", "--debug"):  # fmt: skip
            assert flag in out

    async def test_check_help(self):
        code, out, _err = await _run("check", "--help")
        assert code == 0
        for flag in ("--timeout", "--dc-id", "--json", "--debug"):
            assert flag in out

    async def test_missing_link_is_a_usage_error(self):
        code, _out, err = await _run()
        assert code == 2 and "tg_link" in err

    async def test_check_without_link_is_a_usage_error(self):
        code, _out, err = await _run("check")
        assert code == 2 and "tg_link" in err

    async def test_unknown_option(self):
        code, _out, err = await _run(
            "tg://proxy?server=h&port=1&secret=" + "00" * 16, "--nope"
        )
        assert code == 2 and "--nope" in err

    async def test_invalid_secret_fails_with_a_clear_message(self):
        code, out, err = await _run(
            "tg://proxy?server=h.io&port=443&secret=" + "00" * 15, "--listen-port", "0"
        )
        assert code != 0
        assert "Unrecognized secret format" in err
        assert "listening" not in out  # до старта сервера не дошли


# ============================================================================
# mtproxy-bridge check
# ============================================================================


class TestCheckCommand:
    @pytest.mark.parametrize(("_id", "secret", "domain", "_tag"), MODES, ids=MODE_IDS)
    async def test_alive_proxy(self, proxy_factory, _id, secret, domain, _tag):
        proxy = await proxy_factory(domain=domain, handler=respq_handler())
        code, out, _err = await _run(
            "check", make_link(proxy.port, secret), "--timeout", "10"
        )
        assert code == 0, out
        assert out.splitlines()[0].startswith("[1/")
        assert "MTProto ping" in out and "OK" in out
        assert "Proxy works" in out

    async def test_json_output_for_scripts(self, proxy_factory):
        proxy = await proxy_factory(domain=None, handler=respq_handler())
        code, out, _err = await _run(
            "check", make_link(proxy.port, SECRET_PLAIN), "--json"
        )
        assert code == 0
        data = json.loads(out)  # stdout — только JSON, без примесей
        assert data["ok"] is True and data["mode"] == "direct"
        assert [s["name"] for s in data["stages"]] == ["parse", "connect", "ping"]

    async def test_dead_proxy_exit_code_and_message(self):
        code, out, _err = await _run("check", make_link(free_port(), SECRET_PLAIN))
        assert code == 1
        assert 'Proxy is NOT working — stage "TCP connect"' in out

    async def test_dead_proxy_json(self):
        code, out, _err = await _run(
            "check", make_link(free_port(), SECRET_EE), "--json"
        )
        assert code == 1
        data = json.loads(out)
        assert data["ok"] is False and data["stage"] == "connect" and data["error"]

    async def test_mtproto_error_in_json(self, proxy_factory):
        proxy = await proxy_factory(domain=None, handler=respq_handler("error404"))
        code, out, _err = await _run(
            "check", make_link(proxy.port, SECRET_PLAIN), "--json"
        )
        assert code == 1
        assert json.loads(out)["mtproto_error"] == -404

    async def test_invalid_link(self):
        code, out, _err = await _run("check", "tg://proxy?server=h.io")
        assert code == 1
        assert 'stage "Link"' in out

    async def test_dc_id_flag(self, proxy_factory):
        proxy = await proxy_factory(domain=None, handler=respq_handler())
        code, _out, _err = await _run(
            "check", make_link(proxy.port, SECRET_PLAIN), "--dc-id", "5"
        )
        assert code == 0
        assert proxy.connections[0].dc == 5

    async def test_no_ccs_flag(self, proxy_factory):
        proxy = await proxy_factory(domain=DOMAIN, handler=respq_handler())
        code, _out, _err = await _run(
            "check", make_link(proxy.port, SECRET_EE), "--no-ccs"
        )
        assert code == 0
        assert not proxy.connections[0].saw_ccs

    async def test_ccs_by_default(self, proxy_factory):
        proxy = await proxy_factory(domain=DOMAIN, handler=respq_handler())
        code, _out, _err = await _run("check", make_link(proxy.port, SECRET_EE))
        assert code == 0 and proxy.connections[0].saw_ccs

    async def test_block_flags_change_the_hello_size(self, proxy_factory):
        proxy = await proxy_factory(domain=DOMAIN, handler=respq_handler())
        link = make_link(proxy.port, SECRET_EE)
        assert (await _run("check", link))[0] == 0
        assert (await _run("check", link, "--no-block-m", "--no-block-e"))[0] == 0
        full, slim = (len(rec.hello.raw) for rec in proxy.connections)
        assert full > 1500 and slim == 517

    async def test_timeout_flag_bounds_the_wait(self, proxy_factory):
        proxy = await proxy_factory(domain=None, handler=respq_handler("silent"))
        loop = asyncio.get_running_loop()
        started = loop.time()
        code, out, _err = await _run(
            "check", make_link(proxy.port, SECRET_PLAIN), "--timeout", "1"
        )
        assert code == 1 and "timed out" in out
        assert loop.time() - started < 10  # с учётом старта интерпретатора


# ============================================================================
# Режим моста: баннер, relay, флаги и завершение по сигналу
# ============================================================================


@posix_only
class TestBridgeProcess:
    async def _start(self, *args: str):
        proc = await _spawn(*args)
        banner = await _wait_banner(proc)
        return proc, banner

    @staticmethod
    async def _stop(proc, sig=signal.SIGTERM, timeout=15.0):
        proc.send_signal(sig)
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
        return proc.returncode, out.decode(), err.decode()

    @pytest.mark.parametrize(("_id", "secret", "domain", "tag"), MODES, ids=MODE_IDS)
    async def test_serves_traffic_and_stops_gracefully_on_sigterm(
        self, proxy_factory, _id, secret, domain, tag
    ):
        proxy = await proxy_factory(domain=domain)
        port = free_port()
        proc, banner = await self._start(
            make_link(proxy.port, secret), "--listen-port", str(port)
        )
        try:
            assert f"socks5://127.0.0.1:{port}" in banner
            assert f"tunnel to 127.0.0.1:{proxy.port}" in banner

            reader, writer = await socks5_connect(port)
            writer.write(tag + b"through-the-cli")
            assert await read_exactly(reader, 15, 15) == b"through-the-cli"
            rec = proxy.connections[0]
            assert rec.handshake_ok and rec.dc == 2

            code, _out, err = await self._stop(proc)
            assert code == 0
            assert "Bridge stopped." in err
            assert await reader.read() == b""  # открытое соединение закрыто
            await close_writer(writer)
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()

    async def test_sigint_also_stops_gracefully(self, proxy_factory):
        proxy = await proxy_factory(domain=None)
        proc, _banner = await self._start(
            make_link(proxy.port, SECRET_PLAIN), "--listen-port", str(free_port())
        )
        try:
            code, _out, err = await self._stop(proc, signal.SIGINT)
            assert code == 0 and "Bridge stopped." in err
            assert "Traceback" not in err  # без KeyboardInterrupt-трассировки
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()

    async def test_listener_is_released_after_exit(self, proxy_factory):
        proxy = await proxy_factory(domain=None)
        port = free_port()
        proc, _banner = await self._start(
            make_link(proxy.port, SECRET_PLAIN), "--listen-port", str(port)
        )
        try:
            await self._stop(proc)
            with pytest.raises(OSError):
                await asyncio.open_connection("127.0.0.1", port)
        finally:
            if proc.returncode is None:
                proc.kill()
                await proc.wait()

    async def test_dc_id_override_flag(self, proxy_factory):
        proxy = await proxy_factory(domain=None)
        port = free_port()
        proc, _banner = await self._start(
            make_link(proxy.port, SECRET_PLAIN),
            "--listen-port",
            str(port),
            "--dc-id-override",
            "4",
        )
        try:
            reader, writer = await socks5_connect(port, "8.8.8.8")  # вне таблицы DC
            writer.write(b"\xefabcd")
            assert await read_exactly(reader, 4, 15) == b"abcd"
            assert proxy.connections[0].dc == 4
            await close_writer(writer)
        finally:
            await self._stop(proc)

    async def test_without_override_unknown_target_is_refused(self, proxy_factory):
        proxy = await proxy_factory(domain=None)
        port = free_port()
        proc, _banner = await self._start(
            make_link(proxy.port, SECRET_PLAIN), "--listen-port", str(port)
        )
        try:
            reader, writer = await socks5_connect(port, "8.8.8.8")
            writer.write(b"\xefabcd")
            assert await asyncio.wait_for(reader.read(), 10) == b""
            assert proxy.connections == []
            await close_writer(writer)
        finally:
            await self._stop(proc)

    async def test_faketls_flags(self, proxy_factory):
        proxy = await proxy_factory(domain=DOMAIN)
        port = free_port()
        proc, _banner = await self._start(
            make_link(proxy.port, SECRET_EE), "--listen-port", str(port),
            "--no-ccs", "--no-block-m", "--no-block-e",
        )  # fmt: skip
        try:
            reader, writer = await socks5_connect(port)
            writer.write(b"\xdd" * 4 + b"abcd")
            assert await read_exactly(reader, 4, 15) == b"abcd"
            rec = proxy.connections[0]
            assert not rec.saw_ccs
            assert len(rec.hello.raw) == 517  # без M и E hello минимальный
            await close_writer(writer)
        finally:
            await self._stop(proc)

    async def test_listen_host_option(self, proxy_factory):
        import socket

        with socket.socket() as probe:  # на macOS 127.0.0.2 по умолчанию не настроен
            try:
                probe.bind(("127.0.0.2", 0))
            except OSError:
                pytest.skip("127.0.0.2 is not available on this host")
        proxy = await proxy_factory(domain=None)
        port = free_port()
        proc, banner = await self._start(
            make_link(proxy.port, SECRET_PLAIN),
            "--listen-host",
            "127.0.0.2",
            "--listen-port",
            str(port),
        )
        try:
            assert f"socks5://127.0.0.2:{port}" in banner
        finally:
            await self._stop(proc)

    async def test_debug_flag_enables_verbose_logging(self, proxy_factory):
        proxy = await proxy_factory(domain=None)
        port = free_port()
        proc, _banner = await self._start(
            make_link(proxy.port, SECRET_PLAIN), "--listen-port", str(port), "--debug"
        )
        try:
            reader, writer = await socks5_connect(port)
            writer.write(b"\xefabcd")
            await read_exactly(reader, 4, 15)
            await close_writer(writer)
        finally:
            code, _out, err = await self._stop(proc)
        assert code == 0 and "[DEBUG]" in err

    async def test_default_logging_is_info_without_debug(self, proxy_factory):
        proxy = await proxy_factory(domain=None)
        port = free_port()
        proc, _banner = await self._start(
            make_link(proxy.port, SECRET_PLAIN), "--listen-port", str(port)
        )
        try:
            reader, writer = await socks5_connect(port)
            writer.write(b"\xefabcd")
            await read_exactly(reader, 4, 15)
            await close_writer(writer)
        finally:
            _code, _out, err = await self._stop(proc)
        assert "[INFO]" in err and "[DEBUG]" not in err
