#  mtproxy-bridge
#  Copyright (C) 2026-present UserN0tAdmin <https://github.com/UserN0tAdmin/mtproxy-bridge>
#
#  This file is part of mtproxy-bridge.
#
#  mtproxy-bridge is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  mtproxy-bridge is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with mtproxy-bridge.  If not, see <http://www.gnu.org/licenses/>.

"""Сторожа отмены ``WebStream.read`` в окне ``_return_window``.

Гонка: ``_ActivityDeadline.read`` (relay.py) оборачивает ``stream.read`` в
``asyncio.wait_for``; ``WebStream.read`` извлекает батч из ``_rx`` ДО
единственного await этой ветки — возврата WINDOW-кредита. Если таймаут
накрывает именно его (enqueue ждёт бюджет аплинка под backpressure), байты
пропадали молча, при этом дедлайн мог быть отодвинут другим направлением —
соединение жило дальше с дырой в потоке. Direct-режим (asyncio.StreamReader)
иммунен: между пробуждением и return у него нет await.

Отмена моделируется Event'ами (без гонок с таймингом): ``_entered``
гарантирует, что задача уже извлекла батч и висит в ``_return_window``;
``task.cancel()`` попадает точно в то окно, куда в проде бьёт wait_for.
"""

from __future__ import annotations

import asyncio

import pytest

from mtproxy_bridge.relay import _ActivityDeadline
from mtproxy_bridge.web.tunnel import WebStream


class _HangingTunnel:
    """Минимальный туннель: первый ``_return_window`` висит до release.

    Моделирует зависший ``carrier.enqueue`` (backpressure: релей не читает
    аплинк, бюджет 32 МиБ исчерпан). Второй и последующие вызовы завершаются
    сразу — как enqueue со освободившимся бюджетом.
    """

    def __init__(self) -> None:
        self._data_chunk = 64 * 1024
        self._entered = asyncio.Event()
        self._release = asyncio.Event()
        self.window_calls = 0
        self.window_amounts: list[int] = []

    async def _return_window(self, stream_id: int, amount: int) -> None:
        self.window_calls += 1
        self.window_amounts.append(amount)
        if self.window_calls == 1:
            self._entered.set()
            await self._release.wait()

    def close_stream_nowait(self, stream_id: int) -> None:
        pass


# ============================================================================
# Отмена внутри _return_window: батч должен вернуться в _rx
# ============================================================================


async def test_cancel_during_window_return_restores_batch():
    tun = _HangingTunnel()
    stream = WebStream(tun, 7)
    stream._feed(b"PAYLOAD")

    task = asyncio.create_task(stream.read())
    await tun._entered.wait()  # батч извлечён, read висит в _return_window
    task.cancel()  # сюда в проде бьёт истёкший wait_for из _ActivityDeadline
    with pytest.raises(asyncio.CancelledError):
        await task

    # Инвариант: извлечённые данные либо доставлены, либо возвращены в _rx.
    assert b"".join(stream._rx) == b"PAYLOAD"
    assert stream._unacked_rx == len(b"PAYLOAD")

    # Повторный read доставляет батч; окно возвращается со второго захода
    # (первый вызов отменён до буферизации кадра — двойного кредита нет).
    tun._release.set()
    assert await stream.read() == b"PAYLOAD"
    assert tun.window_amounts == [7, 7]
    assert stream._unacked_rx == 0
    assert not stream._rx


async def test_cancel_restore_keeps_order_with_late_feed():
    tun = _HangingTunnel()
    stream = WebStream(tun, 7)
    stream._feed(b"FIRST")

    task = asyncio.create_task(stream.read())
    await tun._entered.wait()
    stream._feed(b"SECOND")  # пришло, пока read висел в _return_window
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Восстановленный батч — в голову очереди, новые чанки — в хвост.
    tun._release.set()
    assert await stream.read() == b"FIRSTSECOND"


async def test_cancel_restore_delivers_data_before_eof():
    tun = _HangingTunnel()
    stream = WebStream(tun, 7)
    stream._feed(b"LASTBYTES")

    task = asyncio.create_task(stream.read())
    await tun._entered.wait()
    stream._mark_eof()  # CLOSE пришёл, пока read висел в _return_window
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Семантика «данные до EOF» (как у _mark_eof без отмены): батч
    # возвращается в _rx и уходит потребителю до пустого read.
    tun._release.set()
    assert await stream.read() == b"LASTBYTES"
    assert await stream.read() == b""


# ============================================================================
# Продовый путь: _ActivityDeadline.read + wait_for (исход «живого» соединения)
# ============================================================================


async def test_activity_deadline_timeout_keeps_batch_for_next_read():
    """Дедлайн отодвинут другим направлением, локальный wait_for истёк
    ровно на _return_window — батч должен дожить до следующего оборота
    цикла, а соединение — получить свои байты, а не тихую дыру."""
    timeout = 0.5
    idle = _ActivityDeadline(timeout)
    tun = _HangingTunnel()
    stream = WebStream(tun, 7)

    async def feed() -> None:
        await asyncio.sleep(0.1)  # за 0.4 c до дедлайна
        stream._feed(b"PRECIOUS")

    async def toucher() -> None:
        await asyncio.sleep(0.25)  # «байты клиента»: дедлайн уезжает на 0.75
        idle.touch()

    feeder = asyncio.create_task(feed())
    toucher_ = asyncio.create_task(toucher())

    # t=0.1: батч извлечён, read висит в _return_window.
    # t=0.25: дедлайн отодвинут другим направлением.
    # t=0.5: wait_for истекает и отменяет read внутри _return_window.
    data = await idle.read(stream.read)
    await asyncio.gather(feeder, toucher_)
    tun._release.set()

    assert data == b"PRECIOUS"
    assert tun.window_calls == 2
