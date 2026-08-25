### **Readme:** RU | [EN](./README.en.md)

# mtproxy-bridge

[![License](https://img.shields.io/badge/license-LGPL--3.0--or--later-blue.svg)](./COPYING)
![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![Status](https://img.shields.io/badge/status-beta-yellow.svg)

> Локальный SOCKS5-мост для Telegram MTProto-прокси (FakeTLS / obfuscated2) и нового типа **WEB Proxy** (`tg://webproxy`). Логика хендшейка портирована из C++ **TDLib** — официальной кросс-платформенной библиотеки Telegram, поэтому трафик неотличим от настоящего клиента.

## Зачем это нужно

Ссылки вида `tg://proxy?server=...&port=...&secret=...` (и `https://t.me/proxy?...`) задают Telegram MTProto-прокси — сервер, с которым клиент говорит на протоколе, замаскированном под TLS (FakeTLS) либо обфусцированном (obfuscated2). 

Новый тип `tg://webproxy?server=...&secret=...` (WEB Proxy) не имеет выделенного TCP-порта: MTProto-трафик мультиплексируется через HTTPS/WebSocket-carrier-сессию до WEB-релея.

Kurigram и подобные клиенты такие протоколы не понимают, зато умеют работать через обычный SOCKS5.

`mtproxy-bridge` поднимает локальный SOCKS5-сервер, сам проводит хендшейк с прокси (или держит WEB-сессию с релеем) и отдаёт клиенту привычный SOCKS5-сокет; дальше байты пробрасываются как есть, без повторного шифрования или разбора MTProto поверх.

## Возможности

- **Автоопределение транспорта** — тип секрета (`dd` / `ee` / голый 16-байтовый) определяется автоматически; нужный клиенту транспорт отдаёт `needs_padded_transport()`.
- **Поддержка WEB Proxy** — ссылки `tg://webproxy` / `t.me/webproxy`: bridge-capability из HMAC(секрет), bootstrap через страницу релея, все 4 carrier-режима (`https`, `https-lanes`, `websocket`, `websocket-lanes`), flow-control окна 4 МиБ.
- **Проверка прокси** — `check_link()` / `mtproxy-bridge check`: настоящий MTProto-ping (`req_pq_multi` → `resPQ`) через туннель со сверкой эхо-nonce; поэтапный отчёт, RTT, JSON-вывод для скриптов и мониторинга.
- **Точная эмуляция TDLib** — ClientHello (GREASE-значения, блоки M/E, X25519-ключ) собирается по тем же правилам, что и `TlsHello::get_default`.
- **Автоопределение DC** — по IP или hostname через встроенную таблицу дата-центров (аналог `ConnectionCreator::get_default_dc_options`); есть ручной override.
- **CLI и библиотека** — разовый запуск из терминала или встраивание в приложение перед созданием Kurigram-клиента.
- **Устойчивые соединения** — `TCP_NODELAY` + keepalive на upstream, таймаут хендшейка 15 с, таймаут коннекта 5 с, простой закрывает соединение через 30 минут, graceful shutdown по `SIGINT`/`SIGTERM`.

## Установка

Kurigram v2.2.25+

Также возможно с иными клиентами, кто поддерживает [TCP Padded Intermediate](https://core.telegram.org/mtproto/mtproto-transports#padded-intermediate)

Python 3.9+; базовая зависимость — `cryptography`. Пакет публикуется только на
GitHub (не на PyPI), поэтому установка — по URL репозитория:

```bash
# только classic MTProxy (tg://proxy)
pip install git+https://github.com/UserN0tAdmin/mtproxy-bridge.git

# + WEB Proxy (tg://webproxy): нужен extra [web] (aiohttp)
pip install "mtproxy-bridge[web] @ git+https://github.com/UserN0tAdmin/mtproxy-bridge.git"

# зафиксированная версия
pip install "mtproxy-bridge[web] @ git+https://github.com/UserN0tAdmin/mtproxy-bridge.git@v0.3.4"
```

Без extra `[web]` ссылки `tg://webproxy` не работают: CLI выведет подсказку
переустановки с extra. Прямой режим (`tg://proxy`) работает всегда.

Для обновления `--force-reinstall`

## Типы секретов и транспорт

Мост **не переводит фрейминг**: клиент обязан сам использовать транспорт, соответствующий типу секрета.

| Секрет                         | Транспорт клиента                 | Тег    |
|--------------------------------|------------------------------------|--------|
| голый, 16 байт                 | `TCPAbridged`                      | `0xEF` |
| `0xDD` + 16 байт                | `TCPIntermediatePadded`            | `0xDDDDDDDD` |
| `0xEE` + 16 байт + домен (SNI)  | FakeTLS → `TCPIntermediatePadded`  | `0xDDDDDDDD` |

Пустой secret (TDLib plain TCP) не поддерживается.

Для WEB Proxy (`tg://webproxy`) поддерживаются только `plain` (16 байт) и `dd`; `ee`/FakeTLS в WEB-режиме не существует.

## Использование как библиотека

Основной сценарий — встраивание перед созданием Telegram-клиента. Публичный API:

- `is_mtproto_link(url)` — проверяет это `tg://proxy` / `t.me/proxy` / `tg://webproxy` или обычный прокси;
- `is_web_proxy_link(url)` — проверяет WEB-ссылку отдельно;
- `needs_padded_transport(url)` — проверяет нужен ли клиенту padded-транспорт;
- `start_local_bridge(tg_link, ...)` — поднимает мост фоном, возвращает локальный порт (тип ссылки определяется автоматически);
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

### WEB Proxy

Пример работает без изменений, если в `MTPROXY` подставить WEB-ссылку:

```python
MTPROXY = "tg://webproxy?server=proxy.example.com&secret=dd0123456789abcdef0123456789abcdef"
```

Мост сам выведет bridge-capability (HMAC-SHA256 от hostname+секрета), получит bootstrap со страницы релея, создаст сессию и выберет carrier-режим, объявленный сервером (`https`, `https-lanes`, `websocket`, `websocket-lanes`). При смерти carrier-сессии она пересоздаётся лениво при следующем соединении клиента.

Для нестандартных деплоев и тестов у `start_local_bridge` есть параметр `web_origin=` — переопределить `https://<host>` на произвольный origin.

### Проверка прокси (check)

Библиечная функция выполняет полный MTProto-ping: через туннель отправляется настоящий `req_pq_multi`, в ответе сверяется `resPQ` и эхо nonce — единственный способ доказать, что секрет верен и прокси реально релеит до Telegram DC. Функция не бросает исключений по факту «прокси мёртв» — любой исход описан в результате:

```python
from mtproxy_bridge import check_link, check_link_sync

result = await check_link(MTPROXY, timeout=15.0)   # из корутины
# result = check_link_sync(MTPROXY)                # из синхронного кода

if result.ok:
    print(f"живой, ping {result.rtt_ms:.0f} мс")
    if result.carrier:                              # только WEB-режим
        print(f"carrier: {result.carrier}")
else:
    print(f"мертв на стадии {result.stage}: {result.error}")
    if result.mtproto_error:                        # например -404
        ...
print(result.to_json(indent=2))                     # машиночитаемый вид
```

То же через CLI (exit-код 0 = живой, 1 = нет):

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

| Параметр      | По умолчанию | Описание |
|---------------|--------------|----------|
| `tg_link`     | — (обязателен) | ссылка `tg://proxy` или `tg://webproxy` |
| `--timeout`   | `15`         | общий бюджет всех стадий, секунды |
| `--dc-id`     | `2`          | ID дата-центра для obfuscated2-заголовка |
| `--json`      | выкл.        | JSON результата в stdout (для скриптов/мониторинга) |
| `--debug`     | выкл.        | DEBUG-логирование |

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
| `tg_link`           | — (обязателен)             | `tg://proxy?server=...&port=...&secret=...` или `tg://webproxy?server=...&secret=...` |
| `--listen-host`     | `127.0.0.1`                 | Хост локального SOCKS5-сервера |
| `--listen-port`     | `1080`                      | Порт локального SOCKS5-сервера |
| `--dc-id-override`  | автоопределение             | Явно задать DC ID, если автоопределение не сработало |
| `--no-ccs`          | выкл. (CCS отправляется)    | Не слать CCS (TDLib `first_prefix`) перед первым AppData-рекордом (только прямой режим) |
| `--no-block-m`      | выкл. (блок включён)        | Отключить блок M (Kyber-like) в ClientHello (только прямой режим) |
| `--no-block-e`      | выкл. (блок включён)        | Отключить блок E в ClientHello (только прямой режим) |
| `--debug`           | выкл.                       | DEBUG-логирование |

### Настоятельно рекомендуется не выключать CCS, блок E или M без явной необходимости!

## Ограничения

- SOCKS5-сервер моста поддерживает только no-auth и команду `CONNECT` — этого достаточно для локального использования, но не делает его многопользовательским прокси.
- DC ID ищется по встроенной таблице известных IP/доменов; если хост не резолвится или отсутствует в таблице, нужен `--dc-id-override`.
- WEB-режим: carrier-режим выбирает сервер; при смерти сессии активные соединения клиентов рвутся и переподнимаются на новой сессии (как в референсном клиенте Telegram).

## Лицензия

LGPL-3.0-or-later — см. [`COPYING`](./COPYING), [`COPYING.LESSER`](./COPYING.LESSER), [`NOTICE`](./NOTICE).

## Благодарности

Хендшейк портирован с исходников [TDLib](https://github.com/tdlib/td) — в частности `ObfuscatedTransport`, `ProxySecret`, `TlsInit` и `ConnectionCreator::get_default_dc_options`. Проект не аффилирован с Telegram.
