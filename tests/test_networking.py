import asyncio
import threading
import time

import pytest
from cydrogen import get_logger
from cydrogen._networking import MsgQueue, RWLock

logger = get_logger("cydrogen.tests")


@pytest.mark.asyncio
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


@pytest.mark.asyncio
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


def test_rwlock_acquire_readonly() -> None:
    lock = RWLock()
    assert lock.nb_readers == 0
    assert not lock.is_writing
    lock.acquire_readonly()
    assert lock.nb_readers == 1
    assert not lock.is_writing
    lock.acquire_readonly()
    assert lock.nb_readers == 2
    assert not lock.is_writing
    assert not lock.try_acquire_readwrite()
    lock.release_readonly()
    assert lock.nb_readers == 1
    assert not lock.is_writing
    lock.release_readonly()
    assert lock.nb_readers == 0
    assert not lock.is_writing


def test_rwlock_acquire_readwrite() -> None:
    lock = RWLock()
    assert lock.nb_readers == 0
    assert not lock.is_writing
    lock.acquire_readwrite()
    assert lock.nb_readers == 0
    assert lock.is_writing
    assert not lock.try_acquire_readonly()
    assert not lock.try_acquire_readwrite()  # only one writer at a time
    lock.release_readwrite()
    assert lock.nb_readers == 0
    assert not lock.is_writing


def test_rwlock_ro_context_manager() -> None:
    lock = RWLock()
    assert lock.nb_readers == 0
    assert not lock.is_writing
    with lock.readonly:
        assert lock.nb_readers == 1
        assert not lock.is_writing
        with lock.readonly:
            assert lock.nb_readers == 2
            assert not lock.is_writing
        assert lock.nb_readers == 1
        assert not lock.is_writing
    assert lock.nb_readers == 0
    assert not lock.is_writing


def test_rwlock_rw_context_manager() -> None:
    lock = RWLock()
    assert lock.nb_readers == 0
    assert not lock.is_writing
    with lock.readwrite:
        assert lock.nb_readers == 0
        assert lock.is_writing
    assert lock.nb_readers == 0
    assert not lock.is_writing


def test_concurrent_lock() -> None:
    lock = RWLock()

    def reader(idx: int) -> None:
        with lock.readonly:
            logger.info("Reader %d acquired the lock", idx)
            time.sleep(0.5)
        logger.info("Reader %d released the lock", idx)

    def writer(idx: int) -> None:
        time.sleep(0.25)
        with lock.readwrite:
            logger.info("Writer %d acquired the lock", idx)
            time.sleep(0.5)
        logger.info("Writer %d released the lock", idx)

    readers = [threading.Thread(target=reader, args=(idx,)) for idx in range(5)]
    writers = [threading.Thread(target=writer, args=(idx,)) for idx in range(2)]
    for r in readers:
        r.start()
    for w in writers:
        w.start()
    for r in readers:
        r.join()
    for w in writers:
        w.join()


def test_lock_priority_writer() -> None:
    lock = RWLock()
    results: list[int] = []

    def first_reader() -> None:
        # the first reader starts and holds the lock for 0.5s
        with lock.readonly:
            results.append(1)
            time.sleep(0.5)

    def writer() -> None:
        # the writer starts after 0.25s
        # because the first reader is still holding the lock, it has to wait
        time.sleep(0.25)
        with lock.readwrite:
            results.append(2)
            time.sleep(0.5)

    def second_reader() -> None:
        # the second reader starts after 0.4s
        # the writer is already waiting, and it has priority over the second reader
        # so the second reader has to wait until the writer is done
        time.sleep(0.4)
        with lock.readonly:
            results.append(3)
            time.sleep(0.2)

    # repeat the test multiple times to ensure the order is always the same
    for idx in range(20):
        logger.info("Iteration %d", idx)
        results.clear()
        threads = [
            threading.Thread(target=first_reader),
            threading.Thread(target=writer),
            threading.Thread(target=second_reader),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results == [1, 2, 3]
