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

from .config import BridgeConfig
from .links import parse_tg_link
from .server import run_bridge


def main() -> None:
    """CLI entry point: parse arguments and start a blocking bridge."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tg_link", help="tg://proxy?server=...&port=...&secret=...")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=1080)
    parser.add_argument("--dc-id-override", type=int, default=0)
    parser.add_argument(
        "--no-ccs",
        action="store_true",
        default=False,
        help="Do not send CCS (TDLib first_prefix) before the first AppData record "
        "(sent by default, like TDLib ObfuscatedTransport::do_write_tls)",
    )
    parser.add_argument(
        "--no-block-m",
        action="store_true",
        default=False,
        help="Disable block M (Kyber-like) in ClientHello",
    )
    parser.add_argument(
        "--no-block-e",
        action="store_true",
        default=False,
        help="Disable block E in ClientHello",
    )
    parser.add_argument(
        "--debug", action="store_true", default=False, help="Enable DEBUG logging"
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

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
        asyncio.run(run_bridge(cfg))
    except KeyboardInterrupt:
        # Защитная сетка: run_bridge() сама ловит SIGINT через
        # loop.add_signal_handler. Сюда попадаем только если Ctrl+C пришёл
        # до регистрации обработчика (узкое окно на старте) или на
        # платформе, где add_signal_handler недоступен.
        print("\nInterrupted before startup completed.")
