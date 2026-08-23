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

"""Определение Telegram DC ID по IP/hostname (встроенная таблица)."""

from __future__ import annotations

import asyncio
import ipaddress
import socket

from .utils import log

# Built-in Telegram DC IPs. Источник: TDLib ``ConnectionCreator::get_default_dc_options``
# (td/telegram/net/ConnectionCreator.cpp:1257-1277) + актуальный getConfig dcOptions
# (snapshot 2026-08).
#
# Мост — SOCKS5-прокси, из которого DC ID не виден напрямую, поэтому делается
# reverse-mapping target_host → DC по IP-таблице.
#
# Production DCs: IDs 1-5. Test DCs: dc_id + 10000.
# IPv6 записаны в canonical compressed form (ipaddress.ip_address).
#
# ВНИМАНИЕ — расхождение с TDLib по protocolDcId для media_only:
#   TDLib (td/telegram/net/ConnectionCreator.cpp:634) кодирует media_only DC как
#   `is_media_only() ? -int_dc_id : int_dc_id`, т.е. ОТРИЦАТЕЛЬНЫЙ.
#   Мост кодирует media_only DC как ПОЛОЖИТЕЛЬНЫЙ (см. значения ниже с
#   media_only=True) — это намеренное решение, проверенное на практике.
#   Если прокси, реализованный строго по TDLib-спецификации, начнёт
#   отклонять соединения к media_only endpoints, поменяйте значения
#   149.154.167.222 / 2001:67c:4e8:f002::b / 149.154.165.120 /
#   2001:67c:4e8:f004::b на отрицательные (-2 и -4 соответственно).
KNOWN_DC_IPS: dict[str, int] = {
    # ===== DC 1 — Miami (auth + API) =====
    "149.154.175.50": 1,  # TDLib bootstrap (legacy)
    "149.154.175.57": 1,  # getConfig: текущий primary (старый)
    "149.154.175.53": 1,  # getConfig: static=True (старый)
    "149.154.175.55": 1,  # getConfig: primary + static=True (новый)
    "2001:b28:f23d:f001::a": 1,  # IPv6 primary

    # ===== DC 2 — Amsterdam (auth + API + media) =====
    "149.154.167.51": 2,  # TDLib bootstrap (legacy)
    "95.161.76.100": 2,  # TDLib bootstrap (legacy)
    "149.154.167.41": 2,  # getConfig: primary, static=True
    "149.154.167.50": 2,  # getConfig (новый)
    "149.154.167.222": 2,  # getConfig: media_only=True (старый)
    "149.154.167.151": 2,  # getConfig: media_only=True (новый)
    "2001:67c:4e8:f002::a": 2,  # IPv6 primary
    "2001:67c:4e8:f002::b": 2,  # IPv6 media_only=True

    # ===== DC 3 — Miami (auth + API) =====
    "149.154.175.100": 3,  # getConfig: primary, static=True
    "2001:b28:f23d:f003::a": 3,  # IPv6 primary

    # ===== DC 4 — Amsterdam (auth + API + media) =====
    "149.154.167.91": 4,  # getConfig: primary, static=True (старый)
    "149.154.167.92": 4,  # getConfig: primary + static=True (новый)
    "149.154.165.120": 4,  # getConfig: media_only=True (старый)
    "149.154.167.43": 4,  # getConfig: media_only=True (новый)
    "2001:67c:4e8:f004::a": 4,  # IPv6 primary
    "2001:67c:4e8:f004::b": 4,  # IPv6 media_only=True

    # ===== DC 5 — Singapore (auth + API) =====
    "149.154.171.5": 5,  # TDLib bootstrap (legacy)
    "91.108.56.101": 5,  # getConfig: primary, static=True (старый)
    "91.108.56.168": 5,  # getConfig: primary + static=True (новый)
    "2001:b28:f23f:f005::a": 5,  # IPv6 primary

    # ===== Test DCs (TDLib test-mode bootstrap) — dc ID = 10000 + id =====
    "149.154.175.10": 10001,
    "149.154.167.40": 10002,
    "149.154.175.117": 10003,
    # IPv6 test DCs (TDLib test-mode bootstrap, IPv6)
    "2001:b28:f23d:f001::e": 10001,
    "2001:67c:4e8:f002::e": 10002,
    "2001:b28:f23d:f003::e": 10003,
}


# CDN DCs (help.getConfig dcOptions с cdn=True). protocolDcId кодируется как
# отрицательный int16 (TDLib: DcId::external() → protocolDcId = -dc_id).
# Мост релеит байты end-to-end после obfuscated2 handshake; CDN-fileToken
# handshake делает клиент через туннель.
KNOWN_CDN_IPS: dict[str, int] = {
    # DC 203 — CDN (IPv4 + IPv6)
    "91.105.192.100": 203,
    "2a0a:f280:203:a:5000::100": 203,
}


def _normalize_ip(s: str) -> str:
    """Нормализует IP-строку к canonical form для dict lookup.

    Не-IP строки возвращаются как есть (для hostname-lookup через DNS).
    """
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return s


async def guess_dc_id_async(target_host: str) -> int:
    """Определяет Data Center ID по IP-адресу или hostname.

    Сначала пробует прямой lookup в :data:`KNOWN_CDN_IPS` /
    :data:`KNOWN_DC_IPS`. Если ``target_host`` — hostname, делает DNS-resolve
    и ищет полученные IP в тех же таблицах.

    Args:
        target_host: IP-адрес или hostname клиента (из SOCKS5 CONNECT).

    Returns:
        Положительный DC ID (1..5, 10001..10003) для обычных/test DC,
        отрицательный (-203) для CDN DC.

    Raises:
        ValueError: IP не найден в таблицах или DNS-resolve упал. Fallback
            на DC 2 НЕ делается — неправильный DC ID хуже отказа. Escape
            hatch: ``--dc-id-override``.
    """
    normalized = _normalize_ip(target_host)

    # 1. Прямой lookup: target_host может быть IP-адресом.
    # 1a. CDN-проверка — отдельной таблицей, чтобы вернуть -dc_id.
    if normalized in KNOWN_CDN_IPS:
        cdn_dc = KNOWN_CDN_IPS[normalized]
        log.info(f"  [dc-id] CDN endpoint {target_host} -> DC -{cdn_dc}")
        return -cdn_dc

    if normalized in KNOWN_DC_IPS:
        dc = KNOWN_DC_IPS[normalized]
        log.debug(f"  [dc-id] Found by IP: {target_host} -> DC {dc}")
        return dc

    # 2. DNS-resolve hostname → IP → lookup.
    dns_error: Exception | None = None
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(target_host, 443)
        for info in infos:
            ip = info[4][0]
            normalized_ip = _normalize_ip(ip)
            if normalized_ip in KNOWN_CDN_IPS:
                cdn_dc = KNOWN_CDN_IPS[normalized_ip]
                log.info(f"  [dc-id] CDN resolved {target_host} -> {ip} -> DC -{cdn_dc}")
                return -cdn_dc
            if normalized_ip in KNOWN_DC_IPS:
                dc = KNOWN_DC_IPS[normalized_ip]
                log.debug(f"  [dc-id] Resolved {target_host} -> {ip} -> DC {dc}")
                return dc
    except (socket.gaierror, OSError) as e:
        dns_error = e

    if dns_error:
        raise ValueError(
            f"Could not determine DC ID for {target_host}: "
            f"DNS-resolve failed ({dns_error}). "
            f"Use --dc-id-override or dc_id_override= in start_local_bridge()."
        ) from dns_error
    raise ValueError(
        f"Could not determine DC ID for {target_host}: "
        f"IP not found in the built-in DC table (TDLib ConnectionCreator + getConfig). "
        f"If the target is a non-standard DC, use --dc-id-override or dc_id_override= in start_local_bridge()."
    )
