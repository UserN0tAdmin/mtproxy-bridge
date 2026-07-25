### **Readme:** [RU](./README.md) | EN

# mtproxy-bridge

[![License](https://img.shields.io/badge/license-LGPL--3.0--or--later-blue.svg)](./COPYING)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

> A local SOCKS5 bridge for Telegram MTProto proxies (FakeTLS / obfuscated2). The handshake logic is ported from the C++ **TDLib** — Telegram's official cross-platform library — so the traffic is indistinguishable from a genuine client.

## Why this is needed

Links of the form `tg://proxy?server=...&port=...&secret=...` (and `https://t.me/proxy?...`) define a Telegram MTProto proxy — a server the client talks to using a protocol disguised as TLS (FakeTLS) or obfuscated (obfuscated2).

Kurigram and similar clients don't understand this protocol, but they do know how to work through a plain SOCKS5.

`mtproxy-bridge` starts a local SOCKS5 server, performs the handshake with the proxy itself, and hands the client a familiar SOCKS5 socket; from then on, bytes are relayed as-is, with no re-encryption or MTProto parsing on top.

## Features

- **Automatic transport detection** — the secret type (`dd` / `ee` / bare 16-byte) is detected automatically; `needs_padded_transport()` reports which transport the client needs.
- **Accurate TDLib emulation** — the ClientHello (GREASE values, M/E blocks, X25519 key) is built following the same rules as `TlsHello::get_default`.
- **Automatic DC detection** — by IP or hostname, via a built-in data-center table (analogous to `ConnectionCreator::get_default_dc_options`); manual override available.
- **CLI and library** — one-off runs from the terminal, or embed it in an application before creating the Kurigram client.
- **Resilient connections** — `TCP_NODELAY` + keepalive on the upstream, 15s handshake timeout, 5s connect timeout, idle connections closed after 30 minutes, graceful shutdown on `SIGINT`/`SIGTERM`.

## Installation

Python 3.9+, the only external dependency is `cryptography`:

```bash
pip install git+https://github.com/UserN0tAdmin/mtproxy-bridge.git
```

## Secret types and transport

The bridge **does not translate framing**: the client itself must use the transport that matches the secret type.

| Secret                            | Client transport                    | Tag          |
|------------------------------------|---------------------------------------|--------------|
| bare, 16 bytes                     | `TCPAbridged`                         | `0xEFEFEFEF` |
| `0xDD` + 16 bytes                   | `TCPIntermediatePadded`               | `0xDDDDDDDD` |
| `0xEE` + 16 bytes + domain (SNI)    | FakeTLS → `TCPIntermediatePadded`     | `0xDDDDDDDD` |

An empty secret (TDLib plain TCP) is not supported.

## Using it as a library

The primary scenario is embedding it before creating the Telegram client. Public API:

- `is_mtproto_link(url)` — checks whether this is a `tg://proxy` / `t.me/proxy` link or a regular proxy;
- `needs_padded_transport(url)` — checks whether the client needs padded transport;
- `start_local_bridge(tg_link, ...)` — starts the bridge in the background, returns the local port;
- `stop_all_bridges()` — stops all bridges.

Example userbot with Kurigram:

```python
import asyncio
from typing import Any

from pyrogram import Client
from pyrogram.connection.transport import TCPAbridged, TCPIntermediatePadded
from mtproxy_bridge import is_mtproto_link, needs_padded_transport, start_local_bridge

# PASTE YOURS
API_ID = 1234567
API_HASH = "123456789abcdefgh"
MTPROXY = "https://t.me/proxy?server=...&port=...&secret=..."

async def create_client(proxy_url: str | None) -> Client | None:
    kwargs: dict[str, Any] = {
        "api_id": API_ID,
        "api_hash": API_HASH,
    }
    if proxy_url and is_mtproto_link(proxy_url):
        try:
            port = await start_local_bridge(proxy_url)
            transport = TCPIntermediatePadded if needs_padded_transport(proxy_url) else TCPAbridged
            kwargs["proxy"] = {"scheme": "socks5", "hostname": "127.0.0.1", "port": port}
            kwargs["protocol_factory"] = transport
        except Exception as e:
            print(f"Не удалось поднять мост: {e}")
            return None
    return Client("my_account", **kwargs)

async def main() -> None:
    app = await create_client(MTPROXY)
    if app is None:
        return
    async with app:
        chat = await app.get_chat("https://t.me/durov")
        print(chat)

if __name__ == "__main__":
    asyncio.run(main())
    
```

An invalid link or secret raises `ValueError`; wrap the call in `try/except`, as in the example above. To shut down the bridges (e.g., from your own `SIGINT`/`SIGTERM` handler), call `stop_all_bridges()`.

## Using it via the CLI

Not the primary way to use it. Example:

```bash
mtproxy-bridge "tg://proxy?server=1.2.3.4&port=443&secret=ee0102..." --listen-port 8088
```

Output on startup:

```
SOCKS5 bridge listening on

socks5://127.0.0.1:8088

tunnel to 1.2.3.4:443 (FakeTLS)
transport=padded intermediate (0xDD), send_ccs=True, use_block_m=True, use_block_e=True
```

| Parameter            | Default                    | Description |
|-----------------------|------------------------------|--------------|
| `tg_link`              | — (required)                 | `tg://proxy?server=...&port=...&secret=...` |
| `--listen-host`        | `127.0.0.1`                  | Host for the local SOCKS5 server |
| `--listen-port`        | `1080`                       | Port for the local SOCKS5 server |
| `--dc-id-override`     | auto-detected                | Explicitly set the DC ID if auto-detection fails |
| `--no-ccs`             | off (CCS is sent)            | Don't send CCS (TDLib `first_prefix`) before the first AppData record |
| `--no-block-m`         | off (block enabled)          | Disable block M (Kyber-like) in the ClientHello |
| `--no-block-e`         | off (block enabled)          | Disable block E in the ClientHello |
| `--debug`              | off                           | Enable DEBUG logging |

### It is strongly recommended not to disable CCS, block E, or block M unless clearly necessary!

## Limitations

- The bridge's SOCKS5 server only supports no-auth and the `CONNECT` command — sufficient for local use, but this does not make it a multi-user proxy.
- The DC ID is looked up in a built-in table of known IPs/domains; if the host doesn't resolve or isn't in the table, `--dc-id-override` is required.

## License

LGPL-3.0-or-later — see [`COPYING`](./COPYING), [`COPYING.LESSER`](./COPYING.LESSER), [`NOTICE`](./NOTICE).

## Acknowledgements

The handshake was ported from the [TDLib](https://github.com/tdlib/td) source — specifically `ObfuscatedTransport`, `ProxySecret`, `TlsInit`, and `ConnectionCreator::get_default_dc_options`. This project is not affiliated with Telegram.
