import asyncio
import time

import pytest
from cydrogen import KxPair, Psk
from cydrogen._networking import MsgQueue
from cydrogen.networking import (
    KX_KK_AsyncRequestResponseClient,
    KX_N_AsyncRequestResponseClient,
    KX_XX_AsyncRequestResponseClient,
    RequestResponseHandler,
    start_kx_kk_server,
    start_kx_n_server,
    start_kx_xx_server,
)

CLIENT_PAIR = KxPair("PRd15/pwWvuRunBq5pv8jP1Y10gekV7ld8oH0vcYVC/GWd8Wi87qwB9CV76awCqiicaZAGVhEQvQSgZbPK9g6w==0")
SERVER_PAIR = KxPair("I4k9+3iOp9BLi5n8HIrYDvoMiJ3MZzkQbE3UU0XWmQIN7g2CCry+J5HqoNe8AzDWwB78nlsRkIwMm5X0VhSZRA==")
CLIENT_PUBKEY = CLIENT_PAIR.public_key()
SERVER_PUBKEY = SERVER_PAIR.public_key()
PSK = Psk("viHijbfh4pyqknE4mvQdD2AqmWB59xrB7yxEv+bN/64=")
HOST = "127.0.0.1"
PORT = 8888

MESSAGES = [
    b"one",
    b"two",
    b"three",
    b"four",
    b"five",
    b"six",
    b"seven",
    b"eight",
    b"nine",
    b"ten",
]


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


@pytest.mark.asyncio(loop_scope="module")
async def test_async_client_async_server_kx_xx() -> None:
    class H(RequestResponseHandler):
        async def response(self, msg: bytes, msg_id: int) -> bytes:  # noqa: ARG002
            return msg.upper()

    server: asyncio.Server = await start_kx_xx_server(H, HOST, PORT, SERVER_PAIR, psk=PSK)
    await server.start_serving()

    try:
        async with KX_XX_AsyncRequestResponseClient(HOST, PORT, CLIENT_PAIR, psk=PSK) as client:
            for msg in MESSAGES:
                response = await client.request(msg)
                assert response == msg.upper()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio(loop_scope="module")
async def test_async_client_async_server_kx_kk() -> None:
    class H(RequestResponseHandler):
        async def response(self, msg: bytes, msg_id: int) -> bytes:  # noqa: ARG002
            return msg.upper()

    server: asyncio.Server = await start_kx_kk_server(H, HOST, PORT, SERVER_PAIR, CLIENT_PUBKEY)
    await server.start_serving()

    try:
        async with KX_KK_AsyncRequestResponseClient(HOST, PORT, CLIENT_PAIR, SERVER_PUBKEY) as client:
            for msg in MESSAGES:
                response = await client.request(msg)
                assert response == msg.upper()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio(loop_scope="module")
async def test_two_async_clients_async_server_kx_n() -> None:
    class H(RequestResponseHandler):
        async def response(self, msg: bytes, msg_id: int) -> bytes:  # noqa: ARG002
            return msg.upper()

    server: asyncio.Server = await start_kx_n_server(H, HOST, PORT, SERVER_PAIR, psk=PSK)
    await server.start_serving()

    responses_client1 = {}
    responses_client2 = {}
    try:
        async with (
            KX_N_AsyncRequestResponseClient(HOST, PORT, SERVER_PUBKEY, psk=PSK) as client1,
            KX_N_AsyncRequestResponseClient(HOST, PORT, SERVER_PUBKEY, psk=PSK) as client2,
            asyncio.TaskGroup() as tg,
        ):
            for msg in MESSAGES:
                responses_client1[msg] = tg.create_task(client1.request(msg))
                responses_client2[msg] = tg.create_task(client2.request(msg))
        for msg, t in responses_client1.items():
            assert await t == msg.upper()
        for msg, t in responses_client2.items():
            assert await t == msg.upper()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio(loop_scope="module")
async def test_client_without_server() -> None:
    with pytest.raises(ConnectionRefusedError):
        async with KX_XX_AsyncRequestResponseClient(HOST, PORT, CLIENT_PAIR, psk=PSK, connect_retry=0):
            pass


@pytest.mark.asyncio(loop_scope="module")
async def test_client_delayed_server() -> None:
    class H(RequestResponseHandler):
        async def response(self, msg: bytes, msg_id: int) -> bytes:  # noqa: ARG002
            return msg.upper()

    async def delayed_server() -> asyncio.Server:
        await asyncio.sleep(2)
        server = await start_kx_xx_server(H, HOST, PORT, SERVER_PAIR, psk=PSK)
        await server.start_serving()
        return server

    server_task = asyncio.create_task(delayed_server())

    try:
        async with KX_XX_AsyncRequestResponseClient(HOST, PORT, CLIENT_PAIR, psk=PSK, connect_retry=3, connect_retry_wait=1) as client:
            for msg in MESSAGES:
                response = await client.request(msg)
                assert response == msg.upper()
    finally:
        server = await server_task
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio(loop_scope="module")
async def test_client_too_late_server() -> None:
    class H(RequestResponseHandler):
        async def response(self, msg: bytes, msg_id: int) -> bytes:  # noqa: ARG002
            return msg.upper()

    async def delayed_server() -> asyncio.Server:
        await asyncio.sleep(6)
        server = await start_kx_xx_server(H, HOST, PORT, SERVER_PAIR, psk=PSK)
        await server.start_serving()
        return server

    server_task = asyncio.create_task(delayed_server())

    try:
        with pytest.raises(ConnectionRefusedError):
            async with KX_XX_AsyncRequestResponseClient(HOST, PORT, CLIENT_PAIR, psk=PSK, connect_retry=3, connect_retry_wait=1):
                pass
    finally:
        server = await server_task
        server.close()
        await server.wait_closed()
