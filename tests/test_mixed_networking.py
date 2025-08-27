import asyncio
import queue

import pytest
from cydrogen import KxPair, Psk
from cydrogen.async_networking import (
    BaseAsyncRequestResponseClient,
    KX_KK_AsyncRequestResponseClient,
    KX_N_AsyncRequestResponseClient,
    KX_XX_AsyncRequestResponseClient,
    RequestResponseHandler,
    start_kx_kk_server,
    start_kx_n_server,
    start_kx_xx_server,
)
from cydrogen.sync_networking import (
    BaseTCPClient,
    BaseTCPHandler,
    BaseTCPServer,
    KX_KK_TCPClient,
    KX_KK_TCPHandler,
    KX_KK_TCPServer,
    KX_N_TCPClient,
    KX_N_TCPHandler,
    KX_N_TCPServer,
    KX_XX_TCPClient,
    KX_XX_TCPHandler,
    KX_XX_TCPServer,
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


class AsyncHandler(RequestResponseHandler):
    async def response(self, msg: bytes, msg_id: int) -> bytes:  # noqa: ARG002
        return msg.upper()


class SyncHandler(BaseTCPHandler):
    def handle_message(self, msg: bytes, msg_id: int) -> bool:  # noqa: ARG002
        self.write(msg.upper())
        return True


async def async_client_sync_server(client: BaseAsyncRequestResponseClient, server: BaseTCPServer) -> None:
    server.run(background=True)  # run the server in a background thread to avoid to block the event loop

    try:
        async with client:
            for msg in MESSAGES:
                resp: bytes = await client.request(msg)
                assert resp == msg.upper()
    finally:
        server.shutdown()


async def sync_client_async_server(client: BaseTCPClient, server: asyncio.Server) -> None:
    q: queue.Queue = queue.Queue()

    def sync_client() -> None:
        with client:
            for idx, msg in enumerate(MESSAGES):
                client.write(msg, msg_id=idx + 1)
                try:
                    resp, msg_id = client.read()
                    q.put((msg, idx + 1, resp, msg_id))
                except Exception as ex:  # noqa: BLE001
                    q.put(ex)
                    return
        q.put(StopIteration("Client finished sending messages."))

    shutdown = False
    nb_received = 0

    await server.start_serving()

    try:
        await asyncio.to_thread(sync_client)

        while not shutdown:
            r = q.get()
            if isinstance(r, StopIteration):
                shutdown = True
            elif isinstance(r, Exception):
                raise r
            else:
                msg, msg_id, resp, resp_msg_id = r
                nb_received += 1
                assert resp == msg.upper(), "Response does not match expected"
                assert resp_msg_id == msg_id, "Response message ID does not match request message ID"
    finally:
        server.close()
        await server.wait_closed()

    assert nb_received == len(MESSAGES), "Not all messages were received by the sync client."


@pytest.mark.asyncio
async def test_sync_client_async_server_kx_n() -> None:
    """
    Test that a synchronous client KX_N client can communicate with an asynchronous KX_N server.
    """
    client = KX_N_TCPClient(HOST, PORT, SERVER_PUBKEY, psk=PSK)
    server = await start_kx_n_server(AsyncHandler, HOST, PORT, SERVER_PAIR, psk=PSK)
    await sync_client_async_server(client, server)


@pytest.mark.asyncio
async def test_sync_client_async_server_kx_kk() -> None:
    """
    Test that a synchronous client KX_KK client can communicate with an asynchronous KX_KK server.
    """
    client = KX_KK_TCPClient(HOST, PORT, CLIENT_PAIR, SERVER_PUBKEY)
    server = await start_kx_kk_server(AsyncHandler, HOST, PORT, SERVER_PAIR, CLIENT_PUBKEY)
    await sync_client_async_server(client, server)


@pytest.mark.asyncio
async def test_sync_client_async_server_kx_xx() -> None:
    """
    Test that a synchronous client KX_XX client can communicate with an asynchronous KX_XX server.
    """
    client = KX_XX_TCPClient(HOST, PORT, CLIENT_PAIR, psk=PSK)
    server = await start_kx_xx_server(AsyncHandler, HOST, PORT, SERVER_PAIR, psk=PSK)
    await sync_client_async_server(client, server)


@pytest.mark.asyncio
async def test_async_client_sync_server_kx_n() -> None:
    """
    Test that an asynchronous client KX_N client can communicate with an synchronous KX_N server.
    """

    class Sync_H(SyncHandler, KX_N_TCPHandler):
        pass

    server = KX_N_TCPServer(HOST, PORT, SERVER_PAIR, Sync_H, psk=PSK)
    client = KX_N_AsyncRequestResponseClient(HOST, PORT, SERVER_PUBKEY, psk=PSK, connect_retry=10, connect_retry_wait=1)
    await async_client_sync_server(client, server)


@pytest.mark.asyncio
async def test_async_client_sync_server_kx_kk() -> None:
    """
    Test that an asynchronous client KX_KK client can communicate with an synchronous KX_KK server.
    """

    class Sync_H(SyncHandler, KX_KK_TCPHandler):
        pass

    server = KX_KK_TCPServer(HOST, PORT, SERVER_PAIR, Sync_H, CLIENT_PUBKEY)
    client = KX_KK_AsyncRequestResponseClient(HOST, PORT, CLIENT_PAIR, SERVER_PUBKEY, connect_retry=10, connect_retry_wait=1)
    await async_client_sync_server(client, server)


@pytest.mark.asyncio
async def test_async_client_sync_server_kx_xx() -> None:
    """
    Test that an asynchronous client KX_XX client can communicate with an synchronous KX_XX server.
    """

    class Sync_H(SyncHandler, KX_XX_TCPHandler):
        pass

    server = KX_XX_TCPServer(HOST, PORT, SERVER_PAIR, Sync_H, psk=PSK)
    client = KX_XX_AsyncRequestResponseClient(HOST, PORT, CLIENT_PAIR, psk=PSK, connect_retry=10, connect_retry_wait=1)
    await async_client_sync_server(client, server)
