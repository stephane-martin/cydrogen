import asyncio
import queue
import time

import pytest
from cydrogen import KxPair, Psk
from cydrogen._networking import MsgQueue
from cydrogen.networking import (
    RequestResponseHandler,
    make_kx_kk_client,
    make_kx_n_client,
    make_kx_xx_client,
    start_kx_kk_server,
    start_kx_n_server,
    start_kx_xx_server,
)
from cydrogen.sync_networking import KX_N_TCPClient


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


class H(RequestResponseHandler):
    async def response(self, msg: bytes, msg_id: int):  # noqa: ARG002
        return msg.upper()


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
async def test_client_server_kx_xx() -> None:
    server: asyncio.Server = await start_kx_xx_server(H, HOST, PORT, SERVER_PAIR, psk=PSK)
    await server.start_serving()

    client = await make_kx_xx_client(HOST, PORT, CLIENT_PAIR, psk=PSK)

    expected_responses = [msg.upper() for msg in MESSAGES]
    async with client:
        for msg, expected in zip(MESSAGES, expected_responses, strict=True):
            response = await client.request(msg)
            assert response == expected

    # client is closed, server should still be running
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio(loop_scope="module")
async def test_client_server_kx_kk() -> None:
    server: asyncio.Server = await start_kx_kk_server(H, HOST, PORT, SERVER_PAIR, CLIENT_PUBKEY)
    await server.start_serving()

    client = await make_kx_kk_client(HOST, PORT, CLIENT_PAIR, SERVER_PUBKEY)

    expected_responses = [msg.upper() for msg in MESSAGES]
    async with client:
        for msg, expected in zip(MESSAGES, expected_responses, strict=True):
            response = await client.request(msg)
            assert response == expected

    # client is closed, server should still be running
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio(loop_scope="module")
async def test_client_server_kx_n() -> None:
    server: asyncio.Server = await start_kx_n_server(H, HOST, PORT, SERVER_PAIR, psk=PSK)
    await server.start_serving()

    client = await make_kx_n_client(HOST, PORT, SERVER_PUBKEY, psk=PSK)
    client2 = await make_kx_n_client(HOST, PORT, SERVER_PUBKEY, psk=PSK)

    expected_responses = {msg: msg.upper() for msg in MESSAGES}
    responses_client1 = {}
    responses_client2 = {}
    async with client, client2:  # noqa: SIM117
        async with asyncio.TaskGroup() as tg:
            for msg in MESSAGES:
                responses_client1[msg] = tg.create_task(client.request(msg))
                responses_client2[msg] = tg.create_task(client2.request(msg))
    for msg, t in responses_client1.items():
        assert await t == expected_responses[msg]
    for msg, t in responses_client2.items():
        assert await t == expected_responses[msg]

    # clients are closed, server should still be running
    server.close()
    await server.wait_closed()


@pytest.mark.asyncio(loop_scope="module")
async def test_sync_client_async_server_kx_n() -> None:
    """
    Test that a synchronous client KX_N client can communicate with an asynchronous KX_N server.
    """
    server: asyncio.Server = await start_kx_n_server(H, HOST, PORT, SERVER_PAIR, psk=PSK)
    await server.start_serving()

    q: queue.Queue = queue.Queue()

    def sync_client() -> None:
        try:
            with KX_N_TCPClient(HOST, PORT, SERVER_PUBKEY, psk=PSK) as client:
                for idx, msg in enumerate(MESSAGES):
                    client.write(msg, msg_id=idx + 1)
                    try:
                        resp, msg_id = client.read()
                        q.put((msg, idx + 1, resp, msg_id))
                    except Exception as ex:  # noqa: BLE001
                        q.put(ex)
                        return
        finally:
            q.shutdown()

    await asyncio.to_thread(sync_client)

    shutdown = False
    nb_received = 0
    try:
        while not shutdown:
            try:
                msg, msg_id, resp, resp_msg_id = q.get()
                nb_received += 1
                assert resp == msg.upper(), "Response does not match expected"
                assert resp_msg_id == msg_id, "Response message ID does not match request message ID"
            except queue.ShutDown:
                shutdown = True
    finally:
        server.close()
        await server.wait_closed()

    assert nb_received == len(MESSAGES), "Not all messages were received by the sync client."
