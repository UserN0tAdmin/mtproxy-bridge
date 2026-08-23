#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.

"""Тесты кодека shared-фреймов WEB Proxy v1."""

import pytest

from mtproxy_bridge.web import frames as f
from mtproxy_bridge.web.frames import Frame, FrameError, FrameType


class TestEncode:
    def test_header_layout_big_endian(self):
        # type u8 | stream u24 | length u32 — побайтово сверяем с форматом.
        data = f.encode(FrameType.DATA, 0x010203, b"abcd")
        assert data == bytes([0x02, 0x01, 0x02, 0x03, 0, 0, 0, 4]) + b"abcd"

    def test_empty_payload(self):
        assert f.encode(FrameType.OPEN, 1) == b"\x01\x00\x00\x01\x00\x00\x00\x00"

    def test_stream_id_bounds(self):
        f.encode(FrameType.OPEN, f.MAX_STREAM_ID)
        with pytest.raises(FrameError):
            f.encode(FrameType.OPEN, f.MAX_STREAM_ID + 1)

    def test_payload_limit(self):
        f.encode(FrameType.DATA, 1, b"x" * f.MAX_PAYLOAD)
        with pytest.raises(FrameError):
            f.encode(FrameType.DATA, 1, b"x" * (f.MAX_PAYLOAD + 1))


class TestParseBatch:
    def test_roundtrip_all_types(self):
        batch = b"".join(
            [
                f.encode(t, sid, payload)
                for t, sid, payload in [
                    (FrameType.OPEN, 1, b""),
                    (FrameType.DATA, 1, b"hello"),
                    (FrameType.WINDOW, 2, f.window_payload(4096)),
                    (FrameType.CLOSE, 3, b""),
                    (FrameType.PING, 0, b"tok"),
                    (FrameType.PONG, 0, b"tok"),
                    (FrameType.HELLO, 0, b"\x01"),
                    (FrameType.WELCOME, 0, b""),
                    (FrameType.BYE, 0, b"reason"),
                ]
            ]
        )
        parsed = f.parse_batch(batch)
        assert [fr.type for fr in parsed] == [
            FrameType.OPEN,
            FrameType.DATA,
            FrameType.WINDOW,
            FrameType.CLOSE,
            FrameType.PING,
            FrameType.PONG,
            FrameType.HELLO,
            FrameType.WELCOME,
            FrameType.BYE,
        ]
        assert [fr.stream_id for fr in parsed] == [1, 1, 2, 3, 0, 0, 0, 0, 0]
        assert [fr.payload for fr in parsed] == [
            b"", b"hello", f.window_payload(4096), b"",
            b"tok", b"tok", b"\x01", b"", b"reason",
        ]

    def test_single_frame_is_valid_batch(self):
        assert f.parse_batch(f.hello_frame()) == [
            Frame(FrameType.HELLO, 0, b"\x01")
        ]

    def test_empty_batch_rejected(self):
        with pytest.raises(FrameError, match="empty"):
            f.parse_batch(b"")

    def test_truncated_header_rejected(self):
        with pytest.raises(FrameError, match="header"):
            f.parse_batch(b"\x02\x00\x00\x01")

    def test_truncated_payload_rejected(self):
        body = f.encode(FrameType.DATA, 5, b"12345")
        with pytest.raises(FrameError, match="truncated"):
            f.parse_batch(body[:-1])

    def test_trailing_garbage_rejected(self):
        body = f.encode(FrameType.OPEN, 1) + b"\x00"
        with pytest.raises(FrameError, match="header"):
            f.parse_batch(body)

    def test_unknown_type_rejected(self):
        with pytest.raises(FrameError, match="unknown frame type"):
            f.parse_batch(bytes([0x77, 0, 0, 1, 0, 0, 0, 0]))

    def test_too_many_frames_rejected(self):
        one = f.encode(FrameType.OPEN, 1)
        batch = one * (f.MAX_BATCH_FRAMES + 1)
        with pytest.raises(FrameError, match="too many frames"):
            f.parse_batch(batch)

    def test_per_call_payload_limit(self):
        body = f.encode(FrameType.DATA, 1, b"x" * 2048)
        assert len(f.parse_batch(body, max_payload=2048)) == 1
        with pytest.raises(FrameError, match="exceeds limit"):
            f.parse_batch(body, max_payload=1024)


class TestWindowHelpers:
    def test_window_payload_roundtrip(self):
        assert f.parse_window_amount(f.window_payload(0xFFFFFFFF)) == 0xFFFFFFFF
        assert f.parse_window_amount(f.window_payload(1)) == 1

    def test_zero_delta_rejected(self):
        with pytest.raises(FrameError):
            f.window_payload(0)
        with pytest.raises(FrameError):
            f.parse_window_amount(b"\x00\x00\x00\x00")

    def test_bad_length_rejected(self):
        with pytest.raises(FrameError, match="four bytes"):
            f.parse_window_amount(b"\x00\x00\x01")


class TestValidateRelayFrame:
    def test_stream_zero_allowlist(self):
        ok = [
            Frame(FrameType.WELCOME, 0, b""),
            Frame(FrameType.PING, 0, b"x" * f.MAX_PING_PAYLOAD),
            Frame(FrameType.BYE, 0, b"any reason"),
        ]
        for fr in ok:
            f.validate_relay_frame(fr)

    def test_stream_zero_rejects(self):
        bad = [
            Frame(FrameType.DATA, 0, b"data"),
            Frame(FrameType.PONG, 0, b"x"),  # PONG ходит только client→relay
            Frame(FrameType.WELCOME, 0, b"unexpected"),
            Frame(FrameType.OPEN, 0, b""),
            Frame(FrameType.BYE, 7, b""),  # BYE только на stream 0
        ]
        for fr in bad:
            with pytest.raises(FrameError):
                f.validate_relay_frame(fr)

    def test_stream_frames(self):
        ok = [
            Frame(FrameType.DATA, 1, b"a"),
            Frame(FrameType.CLOSE, 1, b""),
            Frame(FrameType.WINDOW, 1, f.window_payload(16)),
        ]
        for fr in ok:
            f.validate_relay_frame(fr)

    def test_stream_frames_rejects(self):
        bad = [
            Frame(FrameType.DATA, 1, b""),  # пустой DATA запрещён
            Frame(FrameType.CLOSE, 1, b"junk"),  # CLOSE обязан быть пустым
            Frame(FrameType.WINDOW, 1, b"\x00\x00\x00\x00"),  # нулевой delta
            Frame(FrameType.OPEN, 2, b"zzz"),  # OPEN релеем не отправляется
            Frame(FrameType.HELLO, 9, b"\x01"),
        ]
        for fr in bad:
            with pytest.raises(FrameError):
                f.validate_relay_frame(fr)


def test_hello_and_welcome_helpers():
    hello = f.hello_frame()
    assert hello == b"\x10\x00\x00\x00\x00\x00\x00\x01\x01"
    welcome = f.encode(FrameType.WELCOME, 0)
    assert f.is_welcome(f.parse_batch(welcome))
    assert not f.is_welcome(f.parse_batch(hello))
