### **Readme:** RU | [EN](./README.en.md)

# mtproxy-bridge

[![License](https://img.shields.io/badge/license-LGPL--3.0--or--later-blue.svg)](./COPYING)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

> Локальный SOCKS5-мост для Telegram MTProto-прокси (FakeTLS / obfuscated2). Логика хендшейка портирована из C++ **TDLib** — официальной кросс-платформенной библиотеки Telegram, поэтому трафик неотличим от настоящего клиента.

## Зачем это нужно

Ссылки вида `tg://proxy?server=...&port=...&secret=...` (и `https://t.me/proxy?...`) задают Telegram MTProto-прокси — сервер, с которым клиент говорит на протоколе, замаскированном под TLS (FakeTLS) либо обфусцированном (obfuscated2). 

Kurigram и подобные клиенты такой протокол не понимают, зато умеют работать через обычный SOCKS5.

`mtproxy-bridge` поднимает локальный SOCKS5-сервер, сам проводит хендшейк с прокси и отдаёт клиенту привычный SOCKS5-сокет; дальше байты пробрасываются как есть, без повторного шифрования или разбора MTProto поверх.

## Возможности

- **Автоопределение транспорта** — тип секрета (`dd` / `ee` / голый 16-байтовый) определяется автоматически; нужный клиенту транспорт отдаёт `needs_padded_transport()`.
- **Точная эмуляция TDLib** — ClientHello (GREASE-значения, блоки M/E, X25519-ключ) собирается по тем же правилам, что и `TlsHello::get_default`.
- **Автоопределение DC** — по IP или hostname через встроенную таблицу дата-центров (аналог `ConnectionCreator::get_default_dc_options`); есть ручной override.
- **CLI и библиотека** — разовый запуск из терминала или встраивание в приложение перед созданием Kurigram-клиента.
- **Устойчивые соединения** — `TCP_NODELAY` + keepalive на upstream, таймаут хендшейка 15 с, таймаут коннекта 5 с, простой закрывает соединение через 30 минут, graceful shutdown по `SIGINT`/`SIGTERM`.

## Установка

**_На текущий момент работает лишь с dev версией Kurigram, ибо TCPIntermediatePadded пока только там. Также возможно с иными клиентами, кто поддерживает [TCPIntermediatePadded](https://core.telegram.org/mtproto/mtproto-transports#padded-intermediate)._**

Python 3.9+, единственная внешняя зависимость — `cryptography`:

```bash
pip install git+https://github.com/UserN0tAdmin/mtproxy-bridge.git
```

Для обновления `--force-reinstall`

## Типы секретов и транспорт

Мост **не переводит фрейминг**: клиент обязан сам использовать транспорт, соответствующий типу секрета.

| Секрет                         | Транспорт клиента                 | Тег    |
|--------------------------------|------------------------------------|--------|
| голый, 16 байт                 | `TCPAbridged`                      | `0xEF` |
| `0xDD` + 16 байт                | `TCPIntermediatePadded`            | `0xDDDDDDDD` |
| `0xEE` + 16 байт + домен (SNI)  | FakeTLS → `TCPIntermediatePadded`  | `0xDDDDDDDD` |

Пустой secret (TDLib plain TCP) не поддерживается.

## Использование как библиотека

Основной сценарий — встраивание перед созданием Telegram-клиента. Публичный API:

- `is_mtproto_link(url)` — проверяет это `tg://proxy` / `t.me/proxy` или обычный прокси;
- `needs_padded_transport(url)` — проверяет нужен ли клиенту padded-транспорт;
- `start_local_bridge(tg_link, ...)` — поднимает мост фоном, возвращает локальный порт;
- `stop_all_bridges()` — останавливает все мосты.

Пример юзербота с Kurigram:

```python
import asyncio
from typing import Any

from pyrogram import Client
from pyrogram.connection.transport import TCPAbridged, TCPIntermediatePadded
from mtproxy_bridge import is_mtproto_link, needs_padded_transport, start_local_bridge

# ВСТАВЬТЕ СВОИ
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

Невалидная ссылка или secret — `ValueError`; вызов стоит оборачивать в `try/except`, как в примере. Чтобы погасить мосты (например, в своём обработчике `SIGINT`/`SIGTERM`), вызовите `stop_all_bridges()`.

## Использование через CLI

Не основной способ использования. Пример:

```bash
mtproxy-bridge "tg://proxy?server=1.2.3.4&port=443&secret=ee0102..." --listen-port 8088
```

Вывод при старте:

```
SOCKS5 bridge listening on

socks5://127.0.0.1:8088

tunnel to 1.2.3.4:443 (FakeTLS)
transport=padded intermediate (0xDD), send_ccs=True, use_block_m=True, use_block_e=True
```

### В клиенте должен быть выбран соотв. транспорт!

___

| Параметр            | По умолчанию              | Описание |
|---------------------|----------------------------|----------|
| `tg_link`           | — (обязателен)             | `tg://proxy?server=...&port=...&secret=...` |
| `--listen-host`     | `127.0.0.1`                 | Хост локального SOCKS5-сервера |
| `--listen-port`     | `1080`                      | Порт локального SOCKS5-сервера |
| `--dc-id-override`  | автоопределение             | Явно задать DC ID, если автоопределение не сработало |
| `--no-ccs`          | выкл. (CCS отправляется)    | Не слать CCS (TDLib `first_prefix`) перед первым AppData-рекордом |
| `--no-block-m`      | выкл. (блок включён)        | Отключить блок M (Kyber-like) в ClientHello |
| `--no-block-e`      | выкл. (блок включён)        | Отключить блок E в ClientHello |
| `--debug`           | выкл.                       | DEBUG-логирование |

### Настоятельно рекомендуется не выключать CCS, блок E или M без явной необходимости!

## Ограничения

- SOCKS5-сервер моста поддерживает только no-auth и команду `CONNECT` — этого достаточно для локального использования, но не делает его многопользовательским прокси.
- DC ID ищется по встроенной таблице известных IP/доменов; если хост не резолвится или отсутствует в таблице, нужен `--dc-id-override`.

## Лицензия

LGPL-3.0-or-later — см. [`COPYING`](./COPYING), [`COPYING.LESSER`](./COPYING.LESSER), [`NOTICE`](./NOTICE).

## Благодарности

Хендшейк портирован с исходников [TDLib](https://github.com/tdlib/td) — в частности `ObfuscatedTransport`, `ProxySecret`, `TlsInit` и `ConnectionCreator::get_default_dc_options`. Проект не аффилирован с Telegram.
