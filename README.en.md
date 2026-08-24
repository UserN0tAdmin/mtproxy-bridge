### **Readme:** [RU](./README.md) | EN

# mtproxy-bridge

[![License](https://img.shields.io/badge/license-LGPL--3.0--or--later-blue.svg)](./COPYING)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

> A local SOCKS5 bridge for Telegram MTProto proxies (FakeTLS / obfuscated2) and the new **WEB Proxy** type (`tg://webproxy`). The handshake logic is ported from the C++ **TDLib** — Telegram's official cross-platform library — so the traffic is indistinguishable from a genuine client.

## Why this is needed

Links of the form `tg://proxy?server=...&port=...&secret=...` (and `https://t.me/proxy?...`) define a Telegram MTProto proxy — a server the client talks to using a protocol disguised as TLS (FakeTLS) or obfuscated (obfuscated2).

The new `tg://webproxy?server=...&secret=...` type (WEB Proxy) has no dedicated TCP port: MTProto traffic is multiplexed through an HTTPS/WebSocket carrier session to a WEB relay.

Kurigram and similar clients understand neither protocol, but they do know how to work through a plain SOCKS5.

`mtproxy-bridge` starts a local SOCKS5 server, performs the handshake with the proxy itself (or keeps a WEB session with the relay), and hands the client a familiar SOCKS5 socket; from then on, bytes are relayed as-is, with no re-encryption or MTProto parsing on top.

## Features

- **Automatic transport detection** — the secret type (`dd` / `ee` / bare 16-byte) is detected automatically; `needs_padded_transport()` reports which transport the client needs.
- **WEB Proxy support** — `tg://webproxy` / `t.me/webproxy` links: bridge capability derived via HMAC(secret, host), bootstrap through the relay's page, all 4 carrier modes (`https`, `https-lanes`, `websocket`, `websocket-lanes`), 4 MiB flow-control windows.
- **Accurate TDLib emulation** — the ClientHello (GREASE values, M/E blocks, X25519 key) is built following the same rules as `TlsHello::get_default`.
- **Automatic DC detection** — by IP or hostname, via a built-in data-center table (analogous to `ConnectionCreator::get_default_dc_options`); manual override available.
- **CLI and library** — one-off runs from the terminal, or embed it in an application before creating the Kurigram client.
- **Resilient connections** — `TCP_NODELAY` + keepalive on the upstream, 15s handshake timeout, 5s connect timeout, idle connections closed after 30 minutes, graceful shutdown on `SIGINT`/`SIGTERM`.

## Installation

Kurigram v2.2.25+

It may also work with other clients that support [TCP Padded Intermediate](https://core.telegram.org/mtproto/mtproto-transports#padded-intermediate)

Python 3.9+; the base dependency is `cryptography`. The package is published
on GitHub only (not on PyPI), so installation goes through the repository URL:

```bash
# classic MTProxy only (tg://proxy)
pip install git+https://github.com/UserN0tAdmin/mtproxy-bridge.git

# + WEB Proxy (tg://webproxy): the [web] extra is required (aiohttp)
pip install "mtproxy-bridge[web] @ git+https://github.com/UserN0tAdmin/mtproxy-bridge.git"

# pinned version
pip install "mtproxy-bridge[web] @ git+https://github.com/UserN0tAdmin/mtproxy-bridge.git@v0.3.1"
```

Without the `[web]` extra, `tg://webproxy` links do not work: the CLI prints a
hint to reinstall with the extra. Direct mode (`tg://proxy`) always works.

For update `--force-reinstall`

## Secret types and transport

The bridge **does not translate framing**: the client itself must use the transport that matches the secret type.

| Secret                            | Client transport                    | Tag    |
|------------------------------------|---------------------------------------|--------|
| bare, 16 bytes                     | `TCPAbridged`                         | `0xEF` |
| `0xDD` + 16 bytes                   | `TCPIntermediatePadded`               | `0xDDDDDDDD` |
| `0xEE` + 16 bytes + domain (SNI)    | FakeTLS → `TCPIntermediatePadded`     | `0xDDDDDDDD` |

An empty secret (TDLib plain TCP) is not supported.

WEB Proxy (`tg://webproxy`) supports only `plain` (16 bytes) and `dd` secrets; `ee`/FakeTLS does not exist in WEB mode.

## Using it as a library

The primary scenario is embedding it before creating the Telegram client. Public API:

- `is_mtproto_link(url)` — checks whether this is a `tg://proxy` / `t.me/proxy` / `tg://webproxy` link or a regular proxy;
- `is_web_proxy_link(url)` — checks WEB links separately;
- `needs_padded_transport(url)` — checks whether the client needs padded transport;
- `start_local_bridge(tg_link, ...)` — starts the bridge in the background, returns the local port (the link type is detected automatically);
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
            print(f"The bridge could not be raised: {e}")
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

### WEB Proxy

The example works unchanged if you put a WEB link into `MTPROXY`:

```python
MTPROXY = "tg://webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef"
```

The bridge derives the bridge-capability (HMAC-SHA256 over hostname+secret), fetches the bootstrap from the relay's page, creates a session and uses whatever carrier mode the server announces (`https`, `https-lanes`, `websocket`, `websocket-lanes`). If a carrier dies, it is re-established lazily on the next client connection.

For non-standard deployments and tests, `start_local_bridge` accepts `web_origin=` to override the default `https://<host>` origin.

### Checking a proxy (check)

The library function performs a full MTProto ping: a real `req_pq_multi` is sent through the tunnel and the `resPQ` reply is verified together with the nonce echo — the only way to prove the secret is correct and the proxy actually relays to a Telegram DC. The function never raises for "proxy is dead" outcomes; every result is described in the returned object:

```python
from mtproxy_bridge import check_link, check_link_sync

result = await check_link(MTPROXY, timeout=15.0)   # from a coroutine
# result = check_link_sync(MTPROXY)                # from sync code

if result.ok:
    print(f"alive, ping {result.rtt_ms:.0f} ms")
else:
    print(f"dead at stage {result.stage}: {result.error}")
    if result.mtproto_error:                        # e.g. -404
        ...
print(result.to_json(indent=2))                     # machine-readable form
```

The same via the CLI (exit code 0 = alive, 1 = dead):

```bash
mtproxy-bridge check "tg://proxy?server=1.2.3.4&port=443&secret=ee0102..."
mtproxy-bridge check "tg://webproxy?server=proxy.example.com&secret=dd..." --json
```

```
[1/3] Link               OK   0 ms — tg://proxy, transport: abridged
[2/3] TCP connect        OK   84 ms — 1.2.3.4:443
[3/3] MTProto ping       OK   158 ms — resPQ, nonce matched

Proxy works (total 243 ms, ping 158 ms)
```

| Parameter     | Default       | Description |
|---------------|---------------|-------------|
| `tg_link`     | — (required)  | `tg://proxy` or `tg://webproxy` link |
| `--timeout`   | `15`          | total budget for all stages, seconds |
| `--dc-id`     | `2`           | data center ID for the obfuscated2 header |
| `--json`      | off           | JSON result to stdout (for scripts/monitoring) |
| `--debug`     | off           | DEBUG logging |

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

### The appropriate transport must be selected in the client!

___

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
