import pytest
from cydrogen import KeyExchangeException, KxPair, Psk
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
CLIENT_PUBKEY = CLIENT_PAIR.public_key()
CLIENT_PAIR_WRONG = KxPair.gen()

SERVER_PAIR = KxPair("I4k9+3iOp9BLi5n8HIrYDvoMiJ3MZzkQbE3UU0XWmQIN7g2CCry+J5HqoNe8AzDWwB78nlsRkIwMm5X0VhSZRA==")
SERVER_PUBKEY = SERVER_PAIR.public_key()
SERVER_PAIR_WRONG = KxPair.gen()

PSK = Psk("viHijbfh4pyqknE4mvQdD2AqmWB59xrB7yxEv+bN/64=")
PSK_WRONG = Psk("wiHijbfh4pyqknE4mvQdD2AqmWB59xrB7yxEv+bN/64=")

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


class H_Mixin(BaseTCPHandler):
    def handle_message(self, msg: bytes, msg_id: int) -> bool:  # noqa: ARG002
        self.write(msg.upper())  # type: ignore
        return True


def sync_client_sync_server(client: BaseTCPClient, server: BaseTCPServer) -> None:
    server.run(background=True)

    nb_received = 0

    try:
        # start the client in the main thread
        # set up retries because the server is started in a background thread
        with client:
            for idx, msg in enumerate(MESSAGES):
                client.write(msg, msg_id=idx + 1)
                resp, msg_id = client.read()
                nb_received += 1
                assert resp == msg.upper(), "Response does not match expected"
                assert msg_id == idx + 1, "Response message ID does not match request message ID"
    finally:
        server.shutdown()

    assert nb_received == len(MESSAGES), "Not all messages were received by the sync client."


def test_sync_client_sync_server_kx_n() -> None:
    class H(H_Mixin, KX_N_TCPHandler):
        pass

    client = KX_N_TCPClient(HOST, PORT, SERVER_PUBKEY, psk=PSK, connect_retry=10, connect_retry_wait=1)
    server = KX_N_TCPServer(HOST, PORT, SERVER_PAIR, H, psk=PSK)
    sync_client_sync_server(client, server)


def test_sync_client_sync_server_kx_kk() -> None:
    class H(H_Mixin, KX_KK_TCPHandler):
        pass

    client = KX_KK_TCPClient(HOST, PORT, CLIENT_PAIR, SERVER_PUBKEY, connect_retry=10, connect_retry_wait=1)
    server = KX_KK_TCPServer(HOST, PORT, SERVER_PAIR, H, CLIENT_PUBKEY)
    sync_client_sync_server(client, server)


def test_sync_client_sync_server_kx_xx() -> None:
    class H(H_Mixin, KX_XX_TCPHandler):
        pass

    client = KX_XX_TCPClient(HOST, PORT, CLIENT_PAIR, psk=PSK, connect_retry=10, connect_retry_wait=1)
    server = KX_XX_TCPServer(HOST, PORT, SERVER_PAIR, H, psk=PSK)
    sync_client_sync_server(client, server)


def test_sync_client_sync_server_kx_n_wrong_psk() -> None:
    class H(H_Mixin, KX_N_TCPHandler):
        pass

    client = KX_N_TCPClient(HOST, PORT, SERVER_PUBKEY, psk=PSK, connect_retry=10, connect_retry_wait=1)
    server = KX_N_TCPServer(HOST, PORT, SERVER_PAIR, H, psk=PSK_WRONG)
    with pytest.raises(KeyExchangeException):
        sync_client_sync_server(client, server)


def test_sync_client_sync_server_kx_xx_wrong_psk() -> None:
    class H(H_Mixin, KX_XX_TCPHandler):
        pass

    client = KX_XX_TCPClient(HOST, PORT, CLIENT_PAIR, psk=PSK, connect_retry=10, connect_retry_wait=1)
    server = KX_XX_TCPServer(HOST, PORT, SERVER_PAIR, H, psk=PSK_WRONG)
    with pytest.raises(KeyExchangeException):
        sync_client_sync_server(client, server)


def test_sync_client_sync_server_kx_n_wrong_server_pubkey() -> None:
    class H(H_Mixin, KX_N_TCPHandler):
        pass

    client = KX_N_TCPClient(HOST, PORT, SERVER_PUBKEY, psk=PSK, connect_retry=10, connect_retry_wait=1)
    server = KX_N_TCPServer(HOST, PORT, SERVER_PAIR_WRONG, H, psk=PSK)
    with pytest.raises(KeyExchangeException):
        sync_client_sync_server(client, server)


def test_sync_client_sync_server_kx_kk_wrong_server_pubkey() -> None:
    class H(H_Mixin, KX_KK_TCPHandler):
        pass

    client = KX_KK_TCPClient(HOST, PORT, CLIENT_PAIR, SERVER_PUBKEY, connect_retry=10, connect_retry_wait=1)
    server = KX_KK_TCPServer(HOST, PORT, SERVER_PAIR_WRONG, H, CLIENT_PUBKEY)
    with pytest.raises(KeyExchangeException):
        sync_client_sync_server(client, server)
