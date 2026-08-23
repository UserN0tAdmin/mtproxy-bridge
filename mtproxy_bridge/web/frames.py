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

"""Кодек shared-фреймов WEB Proxy v1.

Формат (PROTOCOL.md, «Shared frames»):

    type:u8 | stream_id:u24 | payload_length:u32 | payload

Все целые — big-endian без знака. Батч — конкатенация полных фреймов;
лимиты повторяют референсную реализацию tproxy-server (internal/frame).
"""

from __future__ import annotations

import struct
from enum import IntEnum
from typing import NamedTuple

HEADER_SIZE = 8
MAX_PAYLOAD = 1024 * 1024  # максимум payload одного фрейма
INITIAL_STREAM_WINDOW = 4 * 1024 * 1024  # стартовый кредит окна в каждую сторону
DATA_CHUNK = 64 * 1024  # максимум DATA-куска релея
MAX_STREAM_ID = 0xFFFFFF  # stream_id — u24, не переиспользуется в сессии
MAX_BATCH_FRAMES = 4096  # максимум фреймов в одном теле carrier'а
MAX_PING_PAYLOAD = 64


class FrameType(IntEnum):
    """Типы shared-фреймов (значения заморожены протоколом v1)."""

    OPEN = 0x01  # client → relay, stream != 0, пустой payload
    DATA = 0x02  # оба направления, stream != 0, непустой payload
    CLOSE = 0x03  # оба направления, stream != 0, пустой payload
    WINDOW = 0x04  # оба направления, stream != 0, u32 delta > 0
    PING = 0x05  # relay → client, stream == 0, echo-токен
    PONG = 0x06  # client → relay, stream == 0, точный эхо-токен
    HELLO = 0x10  # client → relay, stream == 0, payload b"\x01"
    WELCOME = 0x11  # relay → client, stream == 0, пустой payload
    BYE = 0x1F  # relay → client, stream == 0, опциональная причина


class FrameError(ValueError):
    """Невалидный батч или форма фрейма (protocol failure)."""


class Frame(NamedTuple):
    """Разобранный shared-фрейм."""

    type: FrameType
    stream_id: int
    payload: bytes


def encode(ftype: FrameType | int, stream_id: int, payload: bytes = b"") -> bytes:
    """Кодирует один фрейм.

    Raises:
        FrameError: stream_id вне u24, payload длиннее MAX_PAYLOAD,
            отрицательный payload.
    """
    if not 0 <= stream_id <= MAX_STREAM_ID:
        raise FrameError(f"stream id {stream_id} exceeds 24 bits")
    if len(payload) > MAX_PAYLOAD:
        raise FrameError(f"frame payload {len(payload)} exceeds {MAX_PAYLOAD}")
    return (
        bytes((int(ftype),))
        + stream_id.to_bytes(3, "big")
        + struct.pack(">I", len(payload))
        + payload
    )


def parse_batch(
    data: bytes,
    *,
    max_payload: int = MAX_PAYLOAD,
    max_frames: int = MAX_BATCH_FRAMES,
) -> list[Frame]:
    """Разбирает полный батч фреймов (тело HTTP-запроса или WS-сообщение).

    Батч обязан быть полным и непустым: обрыв на границе фрейма — ошибка
    протокола, а не «ждём ещё» (в отличие от потокового TCP-фрейминга,
    carrier доставляет тела целиком).

    Raises:
        FrameError: пустой батч, обрезанный последний фрейм, превышение
            лимита payload или числа фреймов, неизвестный тип.
    """
    if max_payload <= 0 or max_payload > MAX_PAYLOAD:
        max_payload = MAX_PAYLOAD
    frames: list[Frame] = []
    offset = 0
    total = len(data)
    while offset < total:
        if len(frames) >= max_frames:
            raise FrameError("frame batch contains too many frames")
        if total - offset < HEADER_SIZE:
            raise FrameError("truncated frame header")
        ftype = data[offset]
        stream_id = int.from_bytes(data[offset + 1 : offset + 4], "big")
        (length,) = struct.unpack_from(">I", data, offset + 4)
        if length > max_payload:
            raise FrameError(
                f"frame payload {length} exceeds limit {max_payload}"
            )
        end = offset + HEADER_SIZE + length
        if end > total:
            raise FrameError("truncated frame payload")
        try:
            frame_type = FrameType(ftype)
        except ValueError as e:
            raise FrameError(f"unknown frame type 0x{ftype:02x}") from e
        frames.append(
            Frame(
                type=frame_type,
                stream_id=stream_id,
                payload=data[offset + HEADER_SIZE : end],
            )
        )
        offset = end
    if not frames:
        raise FrameError("empty frame batch")
    return frames


def hello_frame() -> bytes:
    """Тело POST /api/v1/session: ровно один HELLO (payload = b"\\x01")."""
    return encode(FrameType.HELLO, 0, b"\x01")


def is_welcome(frames: list[Frame]) -> bool:
    """Проверяет ответ создания сессии: единственный WELCOME, stream 0."""
    return (
        len(frames) == 1
        and frames[0].type is FrameType.WELCOME
        and frames[0].stream_id == 0
        and not frames[0].payload
    )


def window_payload(amount: int) -> bytes:
    """Payload WINDOW-фрейма: ненулевой u32 delta (big-endian)."""
    if not 0 < amount <= 0xFFFFFFFF:
        raise FrameError(f"window delta {amount} out of uint32 range")
    return amount.to_bytes(4, "big")


def parse_window_amount(payload: bytes) -> int:
    """Разбирает payload WINDOW-фрейма.

    Raises:
        FrameError: длина ≠ 4 байта или нулевой delta.
    """
    if len(payload) != 4:
        raise FrameError("WINDOW payload must be four bytes")
    amount = int.from_bytes(payload, "big")
    if amount == 0:
        raise FrameError("WINDOW delta must be nonzero")
    return amount


def validate_relay_frame(frame: Frame) -> None:
    """Валидирует форму relay→client фрейма (клиентская сторона).

    Формы из PROTOCOL.md: на stream 0 допустимы только WELCOME (пустой),
    PING (echo-токен ≤64 байт) и BYE; на стримовых id — только DATA
    (непустой), CLOSE (пустой) и WINDOW (корректный u32 delta).

    Raises:
        FrameError: нарушение формы — трактуется как protocol failure.
    """
    if frame.stream_id == 0:
        if frame.type is FrameType.WELCOME and not frame.payload:
            return
        if frame.type is FrameType.PING and len(frame.payload) <= MAX_PING_PAYLOAD:
            return
        if frame.type is FrameType.BYE:
            return
        raise FrameError(
            f"frame type 0x{int(frame.type):02x} is invalid on stream zero"
        )
    if frame.type is FrameType.DATA:
        if not frame.payload:
            raise FrameError("DATA payload must be nonempty")
        return
    if frame.type is FrameType.CLOSE:
        if frame.payload:
            raise FrameError("CLOSE requires an empty payload")
        return
    if frame.type is FrameType.WINDOW:
        parse_window_amount(frame.payload)  # бросит при неверной форме
        return
    raise FrameError(
        f"frame type 0x{int(frame.type):02x} is invalid relay-to-client"
    )
