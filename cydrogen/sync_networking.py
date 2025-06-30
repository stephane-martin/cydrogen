import logging
import platform
import socket
import socketserver
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Buffer, Iterator
from contextlib import suppress
from typing import Any, BinaryIO, Self

from ._exceptions import DecryptException, KeyExchangeException
from ._kx_n import KX_N_PACKET1BYTES, KxPair, KxPublicKey, Psk, SessionPair, client_init_kx_n
from ._secretbox import EncryptedMessage, SecretBox, SecretBoxKey

logger = logging.getLogger("cydrogen")

PLATFORM = platform.system().lower()
OK_MESSAGE = b"OK"


class KX_N_TCPHandler(socketserver.StreamRequestHandler, ABC):
    """
    KX_N_TCPHandler provides a handler to build a TCP server.

    Subclasses must implement the handle_message() method to define how to process incoming messages.
    """

    def __init__(self, request: socket.socket, client_address: Any, server: "KX_N_TCPServer") -> None:  # noqa: ANN401
        self.kx_pair: KxPair = server.kx_pair
        self.psk: Psk | None = server.psk
        self.session_pair: SessionPair
        self._write_lock = threading.Lock()
        self.server: KX_N_TCPServer = server  # to make type checker happy
        self.peer = request.getpeername()
        self.finishing_ev = threading.Event()  # to signal when the thread is finishing
        self.tbox: SecretBox
        super().__init__(request, client_address, server)  # calls setup(), handle(), and finish() in a finally block

    def setup(self) -> None:
        logger.warning("Connection from %s", self.peer)
        self.server.add_accepted_socket(self.request)
        super().setup()  # creates self.rfile and self.wfile

    def finish(self) -> None:
        self.finishing_ev.set()  # signal that this thread is finishing, can be used in handle_message() and post_connected()
        super().finish()  # closes self.rfile and self.wfile
        self.server.remove_accepted_socket(self.request)
        logger.warning("Connection closed: %s", self.peer)
        # That's all we need to do, the server itself will shutdown/close the accepted socket
        # for this thread by calling its shutdown_request(socket) method.

    def post_connected(self) -> None:
        logger.info("Connection established with %s, session keys generated", self.peer)

    def handle(self) -> None:
        # called by __init__
        set_keepalive(self.request)
        # receive packet1 from the client
        packet1 = self.rfile.read(KX_N_PACKET1BYTES)
        if len(packet1) != KX_N_PACKET1BYTES:
            logger.error("Received packet1 from %s is not the expected length: %s", self.peer, len(packet1))
            return
        # calculate the session keys
        try:
            self.session_pair = self.kx_pair.server_finish_kx_n(packet1, self.psk)
        except KeyExchangeException:
            logger.exception("Key exchange failed with %s", self.peer)
            return
        self.tbox = SecretBox(self.session_pair.tx)
        self.write(OK_MESSAGE)

        self.post_connected()  # allow subclasses to do something after the connection is established

        while True:
            # note that we successively read a message from the client, and then process it, and then loop.
            # contrary to the async handler, processing a message happens after reading it, not concurrently.
            # this means that the non-async server can only handle one message at a time per client connection.
            if not self._handle_message():
                logger.info("Stopping message handling for {self.peer}")
                return

    def _handle_message(self) -> bool:
        # basically, this method reads a message from the client, decrypts it, and calls handle_message()
        try:
            emsg: EncryptedMessage = EncryptedMessage.read_from(self.rfile)
        except OSError as ex:
            logger.warning("Connection closed with %s or read error: %s", self.peer, ex)
            return False
        try:
            msg: bytes = emsg.decrypt(self.session_pair.rx)
        except DecryptException as ex:
            logger.warning("Decryption failed for client %s, closing connection: %s", self.peer, ex)
            return False
        try:
            if not self.handle_message(msg, emsg.msg_id):
                logger.info("Stopping message handling for %s", self.peer)
                return False  # if handle_message returns False, we stop handling messages
        except Exception:
            logger.exception("Handling message from %s", self.peer)
            return False
        return True  # continue handling messages

    @abstractmethod
    def handle_message(self, msg: bytes, msg_id: int) -> bool:
        raise NotImplementedError

    def write(self, msg: Buffer, *, msg_id: int = 1) -> None:
        with self._write_lock:
            self.tbox.encrypt(msg, msg_id=msg_id, out=self.wfile)
            self.wfile.flush()


class KX_N_TCPServer(socketserver.ThreadingTCPServer):
    """
    KX_N_TCPServer provides a threading TCP server with key exchange variant N.
    """

    def __init__(self, addr: tuple[str, int], server_keys: KxPair, handler: type[KX_N_TCPHandler], *, psk: Psk | None = None) -> None:
        super().__init__(addr, handler, bind_and_activate=False)
        self.allow_reuse_address = True
        self.kx_pair = server_keys
        self.psk = psk
        self.running = False
        self.thread: threading.Thread | None = None
        self.sockets: dict[int, socket.socket] = {}  # to keep track of accepted sockets
        self.sockets_lock = threading.Lock()

    def _reset_main_socket(self) -> None:
        if self.socket is not None:
            with suppress(OSError):
                self.socket.close()
        self.socket = socket.socket(self.address_family, self.socket_type)

    def add_accepted_socket(self, sock: socket.socket) -> None:
        with self.sockets_lock:
            self.sockets[sock.fileno()] = sock

    def remove_accepted_socket(self, sock: socket.socket) -> None:
        with self.sockets_lock:
            if sock.fileno() in self.sockets:
                del self.sockets[sock.fileno()]

    def close_all_sockets(self) -> None:
        with self.sockets_lock:
            for sock in self.sockets.values():
                with suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
            self.sockets.clear()

    def run(self, *, background: bool = False) -> None:
        if self.running:
            raise RuntimeError("Server is already running")
        self.running = True
        with self.sockets_lock:
            self.sockets.clear()
        if background:
            logger.info("Starting server in background thread")
            self.thread = threading.Thread(target=self._run)
            self.thread.start()
        else:
            self.thread = None
            logger.info("Starting server in the main thread")
            self._run()

    def _run(self) -> None:
        # reset the socket to ensure a clean start
        self._reset_main_socket()
        try:
            with self as server:  # on exit, the context manager will call server_close
                server.server_bind()
                server.server_activate()
                logger.info("Server running on %s", server.server_address)
                server.serve_forever()  # this will block until shutdown is called
        finally:
            self.running = False
            logger.info("Server has stopped running")

    def server_close(self) -> None:
        logger.info("server_close")
        # close all the accepted sockets to interrupt the child threads
        self.close_all_sockets()
        super().server_close()  # close the main server socket and wait for threads to finish

    def shutdown(self) -> None:
        if not self.running:
            logger.warning("Server is not running, nothing to shutdown")
            return
        logger.info("shutdown")
        super().shutdown()  # trigger event to exit the serve_forever loop
        if self.thread is not None:  # when serve_forever runs in background, wait for the thread to finish
            self.thread.join()
            self.thread = None


class KX_N_TCPClient:
    """
    EncryptedTCPClient provides a client to connect to a TCP server using key exchange variant N.

    The client uses the server's public key to authenticate the server and generate session keys.
    """

    def __init__(self, server_address: tuple[str, int], server_public_key: KxPublicKey, *, psk: Psk | None = None) -> None:
        self.server_address: tuple[str, int] = server_address
        self.server_public_key: KxPublicKey = server_public_key
        self.psk: Psk | None = psk

        self.connected: bool = False
        self.closed: bool = True

        self.session_pair: SessionPair | None = None

        self.socket: socket.socket | None = None
        self.rfile: BinaryIO | None = None
        self.wfile: BinaryIO | None = None

        self.read_lock = threading.Lock()
        self.write_lock = threading.Lock()

    def connect(self, *, retry: int = -1) -> None:
        if self.connected:
            raise RuntimeError("Client is already connected")
        if not self.closed:
            raise RuntimeError("Client is already connecting")
        self.closed = False
        try:
            self._connect(retry=retry)
        except:
            self.close()
            raise
        else:
            self.connected = True
            logger.info("Server acknowledged, session keys established")

    def _connect(self, retry: int) -> None:
        while True:
            try:
                self.socket = socket.create_connection(self.server_address, timeout=30)
            except ConnectionRefusedError:
                if retry == 0:
                    raise
                if retry > 0:
                    retry -= 1
            else:
                break
            logger.warning("Connection to %s failed, retrying in 1 second...", self.server_address)
            time.sleep(1)

        self.socket.settimeout(None)  # timeout does not play nice with makefile
        set_keepalive(self.socket)
        logger.info("Connected to server at %s", self.server_address)
        self.rfile = self.socket.makefile("rb")
        self.wfile = self.socket.makefile("wb")

        self.session_pair, packet1 = client_init_kx_n(self.server_public_key, self.psk)
        self.wfile.write(packet1)
        self.wfile.flush()
        ack: bytes = EncryptedMessage.read_from(self.rfile).decrypt(self.session_pair.rx)
        if ack != OK_MESSAGE:
            raise KeyExchangeException("Server did not respond with OK")

    def write(self, msg: Buffer, *, msg_id: int = 1) -> None:
        if not self.connected or self.wfile is None or self.closed or self.session_pair is None:
            raise RuntimeError("Client is not connected")
        if not msg:
            logger.warning("Attempted to write an empty message, skipping")
            return
        tx, wfile = self.session_pair.tx, self.wfile
        try:
            with self.write_lock:
                SecretBox(tx).encrypt(msg, msg_id=msg_id, out=wfile)
                wfile.flush()
        except OSError:
            logger.exception("Failed to write to server")
            self.close()
            raise

    def read(self) -> tuple[bytes, int]:
        if not self.connected or self.rfile is None or self.closed or self.session_pair is None:
            raise RuntimeError("Client is not connected")
        return self.doread(self.rfile, self.session_pair.rx)

    def doread(self, rfile: BinaryIO, rx: SecretBoxKey) -> tuple[bytes, int]:
        if not self.connected or self.closed:
            raise RuntimeError("Client is not connected")
        try:
            with self.read_lock:
                emsg: EncryptedMessage = EncryptedMessage.read_from(rfile)
            return emsg.decrypt(rx), emsg.msg_id
        except OSError:
            logger.exception("Failed to read from server")
            self.close()
            raise
        except DecryptException:
            logger.exception("Decryption failed")
            self.close()
            raise

    def __iter__(self) -> Iterator[tuple[bytes, int]]:
        if not self.connected or self.rfile is None or self.closed or self.session_pair is None:
            raise RuntimeError("Client is not connected")
        return _ClientIterator(self)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.connected = False
        if self.socket is not None:
            with suppress(OSError):
                self.socket.shutdown(socket.SHUT_RDWR)
        if self.rfile is not None:
            with suppress(OSError):
                self.rfile.close()
        if self.wfile is not None:
            with suppress(OSError):
                self.wfile.close()
        if self.socket is not None:
            with suppress(OSError):
                self.socket.close()

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # noqa: ANN001
        self.close()


class _ClientIterator:
    def __init__(self, client: KX_N_TCPClient) -> None:
        if client.session_pair is None or client.rfile is None:
            raise RuntimeError("Client is not connected")
        self.client = client
        self.stopped = False
        self.rfile = client.rfile
        self.rx = client.session_pair.rx

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> tuple[bytes, int]:
        if self.stopped:
            raise StopIteration
        try:
            return self.client.doread(self.rfile, self.rx)
        except OSError as ex:
            self.stopped = True
            logger.warning("Connection closed or read error, stopping iteration: %s", ex)
            raise StopIteration from ex
        except DecryptException:
            self.stopped = True
            logger.warning("Decryption failed, stopping read loop")
            raise
        except:
            self.stopped = True
            raise


def set_keepalive_linux(sock: socket.socket, after_idle_sec: int, interval_sec: int, max_fails: int) -> None:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if after_idle_sec is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    if interval_sec is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    if max_fails is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)


def set_keepalive_osx(sock: socket.socket, after_idle_sec: int, interval_sec: int, max_fails: int) -> None:  # noqa: ARG001
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, interval_sec)  # type: ignore[attr-defined]


def set_keepalive_win(sock: socket.socket, after_idle_sec: int, interval_sec: int, max_fails: int) -> None:  # noqa: ARG001
    sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, after_idle_sec * 1000, interval_sec * 1000))  # type: ignore[attr-defined]


def set_keepalive(sock: socket.socket, *, after_idle_sec: int = 10, interval_sec: int = 5, max_fails: int = 4) -> None:
    if PLATFORM == "linux":
        set_keepalive_linux(sock, after_idle_sec, interval_sec, max_fails)
    elif PLATFORM == "darwin":
        set_keepalive_osx(sock, after_idle_sec, interval_sec, max_fails)
    elif PLATFORM == "Windows":
        set_keepalive_win(sock, after_idle_sec, interval_sec, max_fails)
    else:
        logger.warning("Keepalive not supported on %s", PLATFORM)
