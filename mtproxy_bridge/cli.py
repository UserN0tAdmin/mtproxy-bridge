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

"""CLI-точка входа mtproxy-bridge."""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from typing import TYPE_CHECKING

from .config import BridgeConfig
from .links import parse_tg_link, parse_web_link
from .obfuscated2 import TAG_ABRIDGED, TAG_PADDED_INTERMEDIATE
from .server import run_bridge

if TYPE_CHECKING:
    from .web.tunnel import WebTunnel


# ============================================================================
# Подкоманда check (mtproxy-bridge check "<link>")
# ============================================================================

# Человекочитаемые подписи стадий для текстового вывода (публичный вывод —
# на английском; см. также HANDOFF §4.13 про язык комментариев).
_STAGE_LABELS = {
    "parse": "Link",
    "connect": "TCP connect",
    "handshake": "FakeTLS handshake",
    "session": "Web session",
    "ping": "MTProto ping",
}


def _render_check_text(result) -> None:
    """Поэтапный человекочитаемый вывод результата проверки."""
    total = len(result.stages)
    for i, st in enumerate(result.stages, 1):
        label = _STAGE_LABELS.get(st.name, st.name)
        status = "OK  " if st.ok else "FAIL"
        line = f"[{i}/{total}] {label:<18} {status}"
        if st.ms is not None:
            line += f" {st.ms:.0f} ms"
        if st.detail:
            line += f" — {st.detail}"
        print(line)
    if result.ok:
        rtt = f", ping {result.rtt_ms:.0f} ms" if result.rtt_ms is not None else ""
        print(f"\nProxy works (total {result.total_ms:.0f} ms{rtt})")
    else:
        error = f": {result.error}" if result.error else ""
        label = _STAGE_LABELS.get(result.stage, result.stage)
        print(f"\nProxy is NOT working — stage \"{label}\"{error}")


def _main_check(argv: list[str]) -> None:
    """Точка входа подкоманды check: тонкая обёртка над check_link()."""
    from .check import check_link

    parser = argparse.ArgumentParser(
        prog="mtproxy-bridge check",
        description="Check whether an MTProto/WEB proxy link is alive "
        "(full MTProto ping req_pq_multi → resPQ against a Telegram DC)",
    )
    parser.add_argument(
        "tg_link",
        help="tg://proxy?server=...&port=...&secret=... or "
        "tg://webproxy?server=...&secret=...",
    )
    parser.add_argument("--timeout", type=float, default=15.0,
                        help="total budget for all stages, seconds (default 15)")
    parser.add_argument("--dc-id", type=int, default=2,
                        help="data center ID for the obfuscated2 header (default 2)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable JSON output to stdout")
    parser.add_argument("--debug", action="store_true", default=False,
                        help="Enable DEBUG logging")
    parser.add_argument("--no-ccs", action="store_true", default=False,
                        help="Do not send CCS before the first AppData record "
                        "(direct FakeTLS mode only)")
    parser.add_argument("--no-block-m", action="store_true", default=False,
                        help="Disable block M in ClientHello (direct FakeTLS mode only)")
    parser.add_argument("--no-block-e", action="store_true", default=False,
                        help="Disable block E in ClientHello (direct FakeTLS mode only)")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    result = asyncio.run(check_link(
        args.tg_link,
        timeout=args.timeout,
        dc_id=args.dc_id,
        send_ccs=not args.no_ccs,
        use_block_m=not args.no_block_m,
        use_block_e=not args.no_block_e,
    ))

    if args.json:
        print(result.to_json(indent=2))
    else:
        _render_check_text(result)
    sys.exit(0 if result.ok else 1)


def main() -> None:
    """CLI entry point: parse arguments and start a blocking bridge."""
    # Диспетчер подкоманд: 'check' → отдельный парсер; иначе legacy-режим
    # (первый позиционный аргумент — сама ссылка), обратная совместимость.
    argv = sys.argv[1:]
    if argv and argv[0] == "check":
        _main_check(argv[1:])
        return

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "tg_link",
        help="tg://proxy?server=...&port=...&secret=... or "
        "tg://webproxy?server=...&secret=...",
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=1080)
    parser.add_argument("--dc-id-override", type=int, default=0)
    parser.add_argument(
        "--no-ccs",
        action="store_true",
        default=False,
        help="Do not send CCS (TDLib first_prefix) before the first AppData record "
        "(direct FakeTLS mode only; sent by default, like TDLib "
        "ObfuscatedTransport::do_write_tls)",
    )
    parser.add_argument(
        "--no-block-m",
        action="store_true",
        default=False,
        help="Disable block M (Kyber-like) in ClientHello (direct mode only)",
    )
    parser.add_argument(
        "--no-block-e",
        action="store_true",
        default=False,
        help="Disable block E in ClientHello (direct mode only)",
    )
    parser.add_argument(
        "--debug", action="store_true", default=False, help="Enable DEBUG logging"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    tunnel: WebTunnel | None = None
    if args.tg_link.strip().lower().startswith(("tg://webproxy", "https://t.me/webproxy")):
        web_link = parse_web_link(args.tg_link)
        cfg = BridgeConfig(
            listen_host=args.listen_host,
            listen_port=args.listen_port,
            upstream_host="",
            upstream_port=0,
            secret_key=web_link.secret_key,
            domain="",
            is_fake_tls=False,
            expected_tag=(
                TAG_PADDED_INTERMEDIATE if web_link.is_padded else TAG_ABRIDGED
            ),
            dc_id_override=args.dc_id_override,
            send_ccs=True,
            use_block_m=True,
            use_block_e=True,
            web_link=web_link,
        )
        # Ленивый импорт: WEB-режиму нужен extra [web] (aiohttp), direct-режим
        # должен работать без него. TYPE_CHECKING-аннотация — в шапке модуля.
        try:
            from .web.tunnel import WebTunnel
        except ImportError as exc:
            raise SystemExit(
                "WEB proxy mode requires the [web] extra, reinstall with:\n"
                '    pip install "mtproxy-bridge[web] '
                '@ git+https://github.com/UserN0tAdmin/mtproxy-bridge.git"\n'
                "(или та же команда без @…, когда пакет появится на PyPI)"
            ) from exc
        tunnel = WebTunnel(web_link)
    else:
        link = parse_tg_link(args.tg_link)
        cfg = BridgeConfig(
            listen_host=args.listen_host,
            listen_port=args.listen_port,
            upstream_host=link.server,
            upstream_port=link.port,
            secret_key=link.secret_key,
            domain=link.domain,
            is_fake_tls=link.is_fake_tls,
            expected_tag=link.expected_tag,
            dc_id_override=args.dc_id_override,
            send_ccs=not args.no_ccs,
            use_block_m=not args.no_block_m,
            use_block_e=not args.no_block_e,
        )
    try:
        asyncio.run(run_bridge(cfg, web_tunnel=tunnel))
    except KeyboardInterrupt:
        # Защитная сетка: run_bridge() сама ловит SIGINT через
        # loop.add_signal_handler. Сюда попадаем только если Ctrl+C пришёл
        # до регистрации обработчика (узкое окно на старте) или на
        # платформе, где add_signal_handler недоступен.
        print("\nInterrupted before startup completed.")
