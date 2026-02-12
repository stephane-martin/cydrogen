import platform
import socket
import socketserver
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Buffer, Callable
from contextlib import suppress
from typing import Any, Self

from ._kx_n import (
    KxPair,
    KxPublicKey,
    Psk,
)
from ._networking import SyncMsgQueue
from .exceptions import ClientClosedError, DecryptException, KeyExchangeException, SyncMsgQueueShutdown
from .logs import get_logger
from .networking import (
    BaseMachine,
    KX_KK_ClientStateMachine,
    KX_KK_ServerStateMachine,
    KX_N_ClientStateMachine,
    KX_N_ServerStateMachine,
    KX_XX_ClientStateMachine,
    KX_XX_ServerStateMachine,
    KxInitialCompleted,
    MachineProducedEvent,
    ReceivedEncryptedMessage,
)

logger = get_logger()


class Protocol:
    def __init__(
        self, sock: socket.socket, machine: BaseMachine, role: str, rekey_secs: int | None = 3600, rekey_grace_secs: int | None = 1800
    ) -> None:
        self.socket = sock
        self.peer = sock.getpeername()
        self.blogger = logger.bind(peer=self.peer, role=role)
        self._machine = machine
        self._machine_lock = threading.Lock()
        self.received_encrypted_msgs: SyncMsgQueue[memoryview] = SyncMsgQueue()
        self.received_decrypted_msgs: SyncMsgQueue[tuple[bytes, int]] = SyncMsgQueue()
        self._write_lock = threading.Lock()
        self.read_thread: threading.Thread = threading.Thread(target=self._read)
        self.decrypt_thread: threading.Thread = threading.Thread(target=self._decrypt_received_messages)
        self.rekey_thread: threading.Thread = threading.Thread(target=self._rekey)
        self.remove_old_keys_thread: threading.Thread = threading.Thread(target=self._remove_old_keys)
        self.kx_finished = threading.Event()
        self.rekey_secs = rekey_secs
        self.rekey_grace_secs = rekey_grace_secs
        self.connection_lost_ev = threading.Event()

    @property
    def exception(self) -> Exception | None:
        with self._machine_lock:
            return self._machine.exception

    def start(self) -> None:
        self.read_thread.start()
        self.decrypt_thread.start()
        self.rekey_thread.start()
        self.remove_old_keys_thread.start()

    def join(self) -> None:
        self.read_thread.join()
        self.decrypt_thread.join()
        self.rekey_thread.join()
        self.remove_old_keys_thread.join()

    def _send_to_machine(self, func: Callable[..., list[MachineProducedEvent] | MachineProducedEvent | None], *args: Any) -> None:  # noqa: ANN401
        try:
            with self._machine_lock:
                evs = func(*args)
        except Exception as ex:  # noqa: BLE001
            self.connection_lost(ex)
            self.kx_finished.set()
            return
        self._handle_machine_events(evs)
        with self._machine_lock:
            data = self._machine.data_to_send()
        if data:
            try:
                with self._write_lock:
                    self.socket.sendall(data)
            except Exception as ex:  # noqa: BLE001
                self.blogger.info("Connection lost while sending data", error=ex)
                self.connection_lost(ex)

    def connection_made(self) -> None:
        self._send_to_machine(self._machine.trigger_connection_made)

    def connection_lost(self, exc: Exception | None = None) -> None:
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            self.blogger.debug("socket shutdown", error=e)
        try:
            self._send_to_machine(self._machine.trigger_connection_lost, exc)
        except Exception as ex:  # noqa: BLE001
            self.blogger.info("error handling connection lost", error=ex)
        self.connection_lost_ev.set()

    def _rekey(self) -> None:
        if self.rekey_secs is None:
            return
        try:
            while True:
                if self.connection_lost_ev.wait(timeout=self.rekey_secs):
                    # connection lost, exit the rekey loop
                    return
                self._rekey1()
        except Exception as ex:  # noqa: BLE001
            self.connection_lost(ex)

    def _rekey1(self) -> None:
        self._send_to_machine(self._machine.trigger_rekey)

    def _remove_old_keys(self) -> None:
        if self.rekey_grace_secs is None:
            return
        while True:
            if self.connection_lost_ev.wait(timeout=self.rekey_grace_secs):
                # connection lost, exit the remove old keys loop
                return
            self._remove_old_keys1()

    def _remove_old_keys1(self) -> None:
        with self._machine_lock:
            self._machine.remove_oldest_material()

    def _read(self) -> None:
        # this is executed in a separate thread
        # when read() returns, the _received_encrypted_msgs queue is closed to signal _decrypt_received_messages() to exit
        try:
            self._read1()
        finally:
            self.received_encrypted_msgs.shutdown()
            self.blogger.info("read thread has finished")

    def _read1(self) -> None:
        while True:
            with self._machine_lock:
                buf = self._machine.get_buffer()
            try:
                n = self.socket.recv_into(buf)
                if n == 0:
                    self.blogger.info("Connection closed by peer")
                    self.connection_lost(None)
                    return
            except Exception as ex:  # noqa: BLE001
                self.blogger.info("Connection lost", error=ex)
                self.connection_lost(ex)
                return
            self._send_to_machine(self._machine.receive_data, n)

    def _decrypt_received_messages(self) -> None:
        # this is executed in a separate thread
        # when _decrypt_received_messages() returns, the _received_encrypted_msgs queue is closed to signal handle() to exit
        self.blogger.info("starting to decrypt received messages")
        try:
            self._decrypt_received_messages1()
        except Exception as ex:  # noqa: BLE001
            self.blogger.warning("decrypt thread exception", error=ex)
        finally:
            self.received_decrypted_msgs.shutdown()
            self.blogger.info("decrypt thread has finished")

    def _decrypt_received_messages1(self) -> None:
        while True:
            try:
                incoming = self.received_encrypted_msgs.get()
            except SyncMsgQueueShutdown:
                # this means that the queue of encrypted messages has been closed
                self.blogger.info("decrypt received messages has finished")
                # consequently, we close the queue of decrypted messages (previously queued messages may still be consumed)
                return
            # decrypt the message and push the result downstream to _received_decrypted_msgs queue
            try:
                # we don't need to hold the machine lock while decrypting, as decrypt_message() does not modify the machine state
                plaintext, msg_id = self._machine.decrypt_message(incoming)
                self.received_decrypted_msgs.put_nowait((plaintext, msg_id))
            except Exception as ex:
                self.connection_lost(ex)
                raise DecryptException("Failed to decrypt message from peer") from ex
            finally:
                with self._machine_lock:
                    self._machine.release_encrypted_message(incoming)  # return the mview to the freelist

    def _handle_machine_events(self, events: list[MachineProducedEvent] | MachineProducedEvent | None) -> None:
        if events is None:
            return
        if isinstance(events, MachineProducedEvent):
            self._handle_machine_event(events)
            return
        for event in events:
            self._handle_machine_event(event)

    def _handle_machine_event(self, ev: MachineProducedEvent) -> None:
        match ev:
            case KxInitialCompleted():
                self.blogger.info("Key exchange completed")
                self.kx_finished.set()
            case ReceivedEncryptedMessage(emsg=emsg):
                self.received_encrypted_msgs.put_nowait(emsg)

    def write(self, msg: Buffer, *, msg_id: int) -> None:
        # we don't need to hold the machine lock while encrypting, as encrypt_message() does not modify the machine state
        emsg = self._machine.encrypt_message(msg, msg_id)
        self._send_to_machine(self._machine.trigger_write_emessage, emsg)


class BaseTCPHandler(socketserver.BaseRequestHandler, ABC):
    """
    KX_N_TCPHandler provides a handler to build a TCP server with key exchange variant N.

    Subclasses must implement the handle_message() method to define how to process incoming messages.
    """

    def __init__(self, request: socket.socket, client_address: Any, server: "BaseTCPServer", machine: BaseMachine) -> None:  # noqa: ANN401
        self.request: socket.socket = request
        self.server: BaseTCPServer = server  # to make type checker happy
        self.current_msg_id: int = 0
        self.protocol = Protocol(request, machine, role="server_protocol")
        self.peer = request.getpeername()
        self.blogger = logger.bind(peer=self.peer, role="server_handler")
        super().__init__(request, client_address, server)  # calls setup(), handle(), and finish() in a finally block

    def setup(self) -> None:
        self.blogger.info("Connection from client")
        self.server.add_accepted_socket(self.request)
        super().setup()  # creates self.rfile and self.wfile

    def finish(self) -> None:
        super().finish()
        self.server.remove_accepted_socket(self.request)
        self.blogger.info("Connection closed")
        # That's all we need to do, the server itself will shutdown/close the accepted socket
        # for this thread by calling its shutdown_request(socket) method.

    def handle(self) -> None:
        # called by __init__ for each accepted connection
        set_keepalive(self.request)
        self.protocol.connection_made()
        self.protocol.start()

        try:
            while True:
                try:
                    msg, msg_id = self.protocol.received_decrypted_msgs.get()
                except SyncMsgQueueShutdown:
                    # this means that the queue of decrypted messages has been closed
                    self.blogger.info("No more decrypted messages to handle")
                    break
                if not self._handle_message(msg, msg_id):
                    break
        except Exception as ex:  # noqa: BLE001
            # just be sure that the other threads will finish, close the connection
            self.protocol.connection_lost(ex)
        else:
            self.protocol.connection_lost(None)
        finally:
            self.blogger.info("Waiting for protocol threads to finish")
            self.protocol.join()
            self.blogger.info("Protocol threads have finished")

    def _handle_message(self, msg: bytes, msg_id: int) -> bool:
        self.current_msg_id = msg_id
        try:
            if not self.handle_message(msg, msg_id):
                self.blogger.info("Stopping message handling")
                return False  # if handle_message returns False, we stop handling messages
        except Exception as ex:  # noqa: BLE001
            self.blogger.warning("Error handling message", error=ex)
            return False
        finally:
            self.current_msg_id = 0
        return True  # continue handling messages

    @abstractmethod
    def handle_message(self, msg: bytes, msg_id: int) -> bool:
        """
        Handle a message received from the client.

        This method must be implemented by subclasses to define how to process incoming messages.

        For a given client, this method will be called in order of the messages received, one at a time. The next message
        will not be read until this method returns.

        Implementers should call `self.write` to send a response back to the client.

        Args:
            msg: The decrypted message received from the client.
            msg_id: The message ID of the received message.

        Returns:
            True if the server should continue handling messages from this client, False if it should stop.
        """
        raise NotImplementedError

    def write(self, msg: Buffer, *, msg_id: int | None = None) -> None:
        """
        Write a message to the client. The message will be encrypted using the session keys.

        This method would be used when implementing handle_message() in a subclass.

        Args:
            msg: The message to write to the client.
            msg_id: Optional message ID. If not provided, it defaults to the current incoming message ID.
        """
        self.protocol.write(msg, msg_id=msg_id if msg_id is not None else self.current_msg_id)


class KX_N_TCPHandler(BaseTCPHandler):
    def __init__(self, request: socket.socket, client_address: Any, server: "KX_N_TCPServer") -> None:  # noqa: ANN401
        machine = KX_N_ServerStateMachine(server.server_keypair, psk=server.psk)
        super().__init__(request, client_address, server, machine)
        self.blogger = self.blogger.bind(server_type="KX_N")


class KX_KK_TCPHandler(BaseTCPHandler):
    def __init__(self, request: socket.socket, client_address: Any, server: "KX_KK_TCPServer") -> None:  # noqa: ANN401
        machine = KX_KK_ServerStateMachine(server.server_keypair, server.client_public_key)
        super().__init__(request, client_address, server, machine)
        self.blogger = self.blogger.bind(server_type="KX_KK")


class KX_XX_TCPHandler(BaseTCPHandler):
    def __init__(self, request: socket.socket, client_address: Any, server: "KX_XX_TCPServer") -> None:  # noqa: ANN401
        machine = KX_XX_ServerStateMachine(server.server_keypair, psk=server.psk, validate_peer_key=server.validate)
        super().__init__(request, client_address, server, machine)
        self.blogger = self.blogger.bind(server_type="KX_XX")


class BaseTCPServer(socketserver.ThreadingTCPServer):
    def __init__(self, host: str, port: int, server_keypair: KxPair, handler: type[BaseTCPHandler]) -> None:
        super().__init__((host, port), handler, bind_and_activate=False)
        self.allow_reuse_address = True
        self.server_keypair = server_keypair
        self.running = False
        self.thread: threading.Thread | None = None
        self.sockets: dict[int, socket.socket] = {}  # to keep track of accepted sockets
        self.sockets_lock = threading.Lock()
        self.blogger = logger.bind(role="server", server_host=host, server_port=port)

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
        """
        Start the server. If background is True, the server will run in a separate thread and the method will return immediately.

        Args:
            background: If True, the server will run in a background thread. If False, it will run in the current thread.

        Raises:
            RuntimeError: If the server is already running.
        """
        if self.running:
            raise RuntimeError("Server is already running")
        self.running = True
        with self.sockets_lock:
            self.sockets.clear()
        if background:
            self.blogger.info("Starting server in background thread")
            self.thread = threading.Thread(target=self._run)
            self.thread.start()
        else:
            self.thread = None
            self.blogger.info("Starting server in the main thread")
            self._run()

    def _run(self) -> None:
        # reset the socket to ensure a clean start
        self._reset_main_socket()
        try:
            with self as server:  # on exit, the context manager will call server_close
                server.server_bind()
                server.server_activate()
                self.blogger.info("Server running")
                server.serve_forever()  # this will block until shutdown is called
        finally:
            self.running = False
            self.blogger.info("Server has stopped running")

    def server_close(self) -> None:
        # close all the accepted sockets to interrupt the child threads
        self.close_all_sockets()
        super().server_close()  # close the main server socket and wait for threads to finish

    def shutdown(self) -> None:
        """
        Shutdown the server.

        `shutdown` makes `run` exit and closes all accepted sockets.

        `shutdown` does not wait for clients to go away and closes the channels with them immediately.
        """
        if not self.running:
            self.blogger.warning("Server is not running, nothing to shutdown")
            return
        super().shutdown()  # trigger event to exit the serve_forever loop
        if self.thread is not None:  # when serve_forever runs in background, wait for the thread to finish
            self.thread.join()
            self.thread = None


class KX_N_TCPServer(BaseTCPServer):
    def __init__(self, host: str, port: int, server_keypair: KxPair, handler: type[KX_N_TCPHandler], *, psk: Psk | None = None) -> None:
        super().__init__(host, port, server_keypair, handler)
        self.psk = psk


class KX_KK_TCPServer(BaseTCPServer):
    def __init__(self, host: str, port: int, server_keypair: KxPair, handler: type[KX_KK_TCPHandler], client_pubkey: KxPublicKey) -> None:
        super().__init__(host, port, server_keypair, handler)
        self.client_public_key: KxPublicKey = client_pubkey


class KX_XX_TCPServer(BaseTCPServer):
    def __init__(
        self,
        host: str,
        port: int,
        server_keypair: KxPair,
        handler: type[KX_XX_TCPHandler],
        *,
        psk: Psk | None = None,
        validate_client_public_key: Callable[[KxPublicKey], None] | None = None,
    ) -> None:
        super().__init__(host, port, server_keypair, handler)
        self.psk = psk
        self.validate = validate_client_public_key


class BaseTCPClient:
    def __init__(
        self,
        host: str,
        port: int,
        machine: BaseMachine,
        *,
        connect_retry: int = 3,
        connect_retry_wait: int = 30,
        rekey_secs: int | None = 3600,
    ) -> None:
        self.server_address: tuple[str, int] = (host, port)
        self.retry = connect_retry
        self.retry_wait = connect_retry_wait
        self.machine = machine

        self.connected = False
        self.connecting = False
        self.state_lock = threading.Lock()

        self.socket: socket.socket | None = None
        self.protocol: Protocol | None = None
        self.rekey_secs = rekey_secs
        self.blogger = logger.bind(role="client", server_host=host, server_port=port)

    def connect(self) -> None:
        with self.state_lock:
            if self.connected:
                self.blogger.info("Already connected")
                return
            if self.connecting:
                self.blogger.info("Already connecting")
                return
            self.connecting = True
        try:
            self.socket = self._create_connection()
            set_keepalive(self.socket)
            self.protocol = Protocol(self.socket, self.machine, rekey_secs=self.rekey_secs, role="client_protocol")
            self.protocol.connection_made()
            self.protocol.start()
            with self.state_lock:
                self.connected = True
                self.connecting = False
            self.protocol.kx_finished.wait()  # wait for key exchange to complete
            if self.protocol.exception is not None:
                self.close()
                if isinstance(self.protocol.exception, KeyExchangeException):
                    raise self.protocol.exception
                raise KeyExchangeException from self.protocol.exception
        except:
            with self.state_lock:
                self.connecting = False
            raise

    def _create_connection(self) -> socket.socket:
        retry = self.retry
        while True:
            try:
                return socket.create_connection(self.server_address, timeout=30)
            except ConnectionRefusedError:
                if retry == 0:
                    raise
            retry -= 1
            self.blogger.warning("Connection failed")
            if self.retry_wait > 0:
                self.blogger.info("Retry soon", wait=self.retry_wait)
                time.sleep(self.retry_wait)

    def close(self) -> None:
        with self.state_lock:
            if self.connecting:
                raise RuntimeError("Cannot close while connecting")
            if not self.connected:
                return
            if self.socket is not None:
                with suppress(OSError):
                    self.socket.shutdown(socket.SHUT_RDWR)
                self.socket = None  # will close the socket eventually when the socket is garbage collected
            if self.protocol is not None:
                self.protocol.join()
            self.connected = False

    def __enter__(self) -> Self:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:  # noqa: ANN001
        self.close()

    def read(self) -> tuple[bytes, int]:
        with self.state_lock:
            if self.connecting:
                raise RuntimeError("Cannot read while connecting")
            if not self.connected:
                raise ClientClosedError("Not connected")
        if self.protocol is None:
            raise RuntimeError("Protocol not initialized")  # should not happen
        if not self.protocol.kx_finished.is_set():
            raise RuntimeError("Key exchange not completed")
        try:
            return self.protocol.received_decrypted_msgs.get()
        except SyncMsgQueueShutdown:
            raise ClientClosedError from None

    def write(self, msg: Buffer, *, msg_id: int) -> None:
        with self.state_lock:
            if self.connecting:
                raise RuntimeError("Cannot write while connecting")
            if not self.connected:
                raise ClientClosedError("Not connected")
        if self.protocol is None:
            raise RuntimeError("Protocol not initialized")  # should not happen
        if not self.protocol.kx_finished.is_set():
            raise RuntimeError("Key exchange not completed")
        self.protocol.write(msg, msg_id=msg_id)


class KX_N_TCPClient(BaseTCPClient):
    def __init__(
        self,
        host: str,
        port: int,
        server_public_key: KxPublicKey,
        *,
        psk: Psk | None = None,
        connect_retry: int = 3,
        connect_retry_wait: int = 30,
        rekey_secs: int | None = 3600,
    ) -> None:
        machine = KX_N_ClientStateMachine(server_public_key, psk=psk)
        super().__init__(host, port, machine, connect_retry=connect_retry, connect_retry_wait=connect_retry_wait, rekey_secs=rekey_secs)


class KX_KK_TCPClient(BaseTCPClient):
    def __init__(
        self,
        host: str,
        port: int,
        client_keypair: KxPair,
        server_public_key: KxPublicKey,
        connect_retry: int = 3,
        connect_retry_wait: int = 30,
        rekey_secs: int | None = 3600,
    ) -> None:
        machine = KX_KK_ClientStateMachine(
            client_keypair,
            server_public_key,
        )
        super().__init__(host, port, machine, connect_retry=connect_retry, connect_retry_wait=connect_retry_wait, rekey_secs=rekey_secs)


class KX_XX_TCPClient(BaseTCPClient):
    def __init__(
        self,
        host: str,
        port: int,
        client_keypair: KxPair,
        *,
        psk: Psk | None = None,
        connect_retry: int = 3,
        connect_retry_wait: int = 30,
        validate_server_public_key: Callable[[KxPublicKey], None] | None = None,
        rekey_secs: int | None = 3600,
    ) -> None:
        machine = KX_XX_ClientStateMachine(client_keypair, psk=psk, validate_peer_key=validate_server_public_key)
        super().__init__(host, port, machine, connect_retry=connect_retry, connect_retry_wait=connect_retry_wait, rekey_secs=rekey_secs)


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


PLATFORM = platform.system().lower()


def set_keepalive(sock: socket.socket, *, after_idle_sec: int = 10, interval_sec: int = 5, max_fails: int = 4) -> None:
    if PLATFORM == "linux":
        set_keepalive_linux(sock, after_idle_sec, interval_sec, max_fails)
    elif PLATFORM == "darwin":
        set_keepalive_osx(sock, after_idle_sec, interval_sec, max_fails)
    elif PLATFORM == "Windows":
        set_keepalive_win(sock, after_idle_sec, interval_sec, max_fails)
    else:
        logger.warning("Keepalive not supported on %s", PLATFORM)
