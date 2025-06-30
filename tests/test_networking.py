import asyncio
import time

import pytest
from cydrogen._networking import MsgQueue


@pytest.mark.asyncio(loop_scope="module")
async def test_msg_queue() -> None:
    q: MsgQueue = MsgQueue()
    assert q.bytesize == 0
    q.put_nowait(b"12345678")
    assert q.bytesize == 8
    assert q.qsize == 1
    assert not q.empty
    q.put_nowait(b"ABCDEFGH", msg_id=1)
    assert q.bytesize == 16
    assert q.qsize == 2
    msg, msg_id = await q.get()
    assert msg == b"12345678"
    assert msg_id == 0
    assert q.bytesize == 8
    assert q.qsize == 1
    msg2, msg_id2 = await q.get()
    assert msg2 == b"ABCDEFGH"
    assert msg_id2 == 1
    assert q.empty


async def wait_and_put(q: MsgQueue, msg: bytes, msg_id: int = 0) -> None:
    await asyncio.sleep(1)
    q.put_nowait(msg, msg_id)


@pytest.mark.asyncio(loop_scope="module")
async def test_msg_queue_waiting() -> None:
    loop = asyncio.get_running_loop()
    q: MsgQueue = MsgQueue()

    start = time.monotonic()
    tput = loop.create_task(wait_and_put(q, b"12345678", msg_id=3))
    tget = loop.create_task(q.get())
    msg, msg_id = await tget
    assert tput.done()
    elapsed = time.monotonic() - start
    assert elapsed >= 1.0
    assert msg == b"12345678"
    assert msg_id == 3
