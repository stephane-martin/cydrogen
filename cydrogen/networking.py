import asyncio
import logging
import platform
import socket
import socketserver
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Buffer, Coroutine, Iterator
from typing import BinaryIO, Self, TypeVar

from cydrogen import (
    KX_KK_PACKET1BYTES,
    KX_KK_PACKET2BYTES,
    KX_N_PACKET1BYTES,
    Counter,
    DecryptException,
    EncryptedMessage,
    KeyExchangeException,
    KxPair,
    KxPublicKey,
    Psk,
    SecretBox,
    SecretBoxKey,
    SessionPair,
    client_init_kx_n,
    load64,
    store64,
)

logger = logging.getLogger("cydrogen")

T = TypeVar("T")
PLATFORM = platform.system().lower()
OK_MESSAGE = b"OK"
CANCEL_MESSAGE_ID = 0


class KX_N_TCPHandler(socketserver.StreamRequestHandler, ABC):
    """
    KX_N_TCPHandler provides a handler to build a TCP server.

    The TCP server owns a key pair for key exchange variant N. The client
    authenticates the server using the server's public key, and generates
    session keys to secure the communication channel.
    """

    def __init__(self, request, client_address, server: "KX_N_TCPServer") -> None:
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
        logger.warning(f"Connection from {self.peer}")
        self.server.add_accepted_socket(self.request)
        super().setup()  # creates self.rfile and self.wfile

    def finish(self) -> None:
        self.finishing_ev.set()  # signal that this thread is finishing, can be used in handle_message() and post_connected()
        super().finish()  # closes self.rfile and self.wfile
        self.server.remove_accepted_socket(self.request)
        logger.warning(f"Connection from {self.peer} closed")
        # That's all we need to do, the server itself will shutdown/close the accepted socket
        # for this thread by calling its shutdown_request(socket) method.

    def post_connected(self) -> None:
        logger.info(f"Connection established with {self.peer}, session keys generated")

    def handle(self) -> None:
        # called by __init__
        set_keepalive(self.request)
        # receive packet1 from the client
        packet1 = self.rfile.read(KX_N_PACKET1BYTES)
        if len(packet1) != KX_N_PACKET1BYTES:
            logger.error(f"Received packet1 from {self.peer} is not the expected length: {len(packet1)}")
            return
        # calculate the session keys
        try:
            self.session_pair = self.kx_pair.server_finish_kx_n(packet1, self.psk)
        except KeyExchangeException as e:
            logger.error(f"Key exchange failed with {self.peer}: {e}")
            return
        self.tbox = SecretBox(self.session_pair.tx)
        self.write(OK_MESSAGE)

        self.post_connected()  # allow subclasses to do something after the connection is established

        while True:
            # note that we successively read a message from the client, and then process it, and then loop.
            # contrary to the async handler, processing a message happens after reading it, not concurrently.
            # this means that the non-async server can only handle one message at a time per client connection.
            if not self._handle_message():
                logger.info(f"Stopping message handling for {self.peer}")
                return

    def _handle_message(self) -> bool:
        # basically, this method reads a message from the client, decrypts it, and calls handle_message()
        try:
            emsg: EncryptedMessage = EncryptedMessage.read_from(self.rfile)
        except OSError as e:
            logger.warning(f"Connection closed by {self.peer} or read error: {e}")
            return False
        try:
            msg: bytes = emsg.decrypt(self.session_pair.rx)
        except DecryptException as e:
            logger.warning(f"Decryption failed for client {self.peer}, closing connection: {e}")
            return False
        if emsg.msg_id == CANCEL_MESSAGE_ID:
            # do nothing cause the threaded server does not support multiplexed requests, so
            # there are never pending requests to cancel
            return True
        try:
            if not self.handle_message(msg, emsg.msg_id):
                logger.info(f"Stopping message handling for {self.peer}")
                return False  # if handle_message returns False, we stop handling messages
        except Exception as e:
            logger.error(f"Error handling message from {self.peer}: {e}")
            return False
        return True  # continue handling messages

    @abstractmethod
    def handle_message(self, msg: bytes, msg_id: int) -> bool:
        raise NotImplementedError()

    def write(self, msg: Buffer, msg_id: int = 1):
        with self._write_lock:
            self.tbox.encrypt(msg, msg_id=msg_id, out=self.wfile)
            self.wfile.flush()


class KX_N_TCPServer(socketserver.ThreadingTCPServer):
    """
    EncryptedTCPServer provides a TCP server that uses the EncryptedTCPHandler.

    The server is initialized with a key pair for key exchange variant N and an optional
    pre-shared key (PSK) for additional security.
    """

    def __init__(self, addr: tuple[str, int], server_keys: KxPair, handler: type[KX_N_TCPHandler], *, psk: Psk | None = None):
        super().__init__(addr, handler, bind_and_activate=False)
        self.allow_reuse_address = True
        self.kx_pair = server_keys
        self.psk = psk
        self.running = False
        self.thread: threading.Thread | None = None
        self.sockets: dict[int, socket.socket] = {}  # to keep track of accepted sockets
        self.sockets_lock = threading.Lock()

    def _reset_main_socket(self):
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass
        self.socket = socket.socket(self.address_family, self.socket_type)

    def add_accepted_socket(self, sock: socket.socket):
        with self.sockets_lock:
            self.sockets[sock.fileno()] = sock

    def remove_accepted_socket(self, sock: socket.socket):
        with self.sockets_lock:
            if sock.fileno() in self.sockets:
                del self.sockets[sock.fileno()]

    def close_all_sockets(self):
        with self.sockets_lock:
            for sock in self.sockets.values():
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            self.sockets.clear()

    def run(self, background: bool = False):
        if self.running:
            raise RuntimeError("Server is already running, cannot start again")
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

    def _run(self):
        # reset the socket to ensure a clean start
        self._reset_main_socket()
        try:
            with self as server:  # on exit, the context manager will call server_close
                server.server_bind()
                server.server_activate()
                logger.info(f"Server is running on {server.server_address}")
                server.serve_forever()  # this will block until shutdown is called
        finally:
            self.running = False
            logger.info("Server has stopped running")

    def server_close(self):
        logger.info("server_close")
        # close all the accepted sockets to interrupt the child threads
        self.close_all_sockets()
        super().server_close()  # close the main server socket and wait for threads to finish

    def shutdown(self):
        if not self.running:
            logger.warning("Server is not running, nothing to shutdown")
            return
        logger.info("shutdown")
        super().shutdown()  # trigger event to exit the serve_forever loop
        if self.thread is not None:  # when serve_forever runs in background, wait for the thread to finish
            self.thread.join()
            self.thread = None


async def do_before_event(coro: Coroutine[None, None, T], before: asyncio.Event, name: str | None = None) -> T:
    t: asyncio.Task[T] = asyncio.create_task(coro, name=name)
    stop: asyncio.Task[bool] = asyncio.create_task(before.wait(), name="event_wait")
    try:
        done, pending = await asyncio.wait([t, stop], return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            # if t is done, it means we cancel 'waiting for before event'
            # if stop is done, it means we cancel 'coro'
            task.cancel()
    except asyncio.CancelledError:
        # If 'do_before_event' is canceled, while 't' has thrown an exception, we want to await t to retrieve the exception.
        # Else asyncio will complain that the exception was never retrieved
        pass
    return await t


class PendingProcessingTasks:
    def __init__(self) -> None:
        self.pending: dict[int, set[asyncio.Task]] = {}  # to keep track of pending tasks

    def register(self, msg_id: int, task: asyncio.Task):
        if msg_id not in self.pending:
            self.pending[msg_id] = set()
        self.pending[msg_id].add(task)

    def done(self, msg_id: int, task: asyncio.Task) -> None:
        if msg_id in self.pending:
            self.pending[msg_id].discard(task)

    def cancel(self, msg_id: int) -> None:
        if msg_id in self.pending:
            for task in self.pending[msg_id]:
                task.cancel()

    def cancel_all(self) -> int:
        nb = 0
        for msg_id, tasks in self.pending.items():
            nb += len(tasks)
            for task in tasks:
                task.cancel()
        self.pending.clear()
        return nb
        if nb > 0:
            logger.info(f"Cancelled {nb} pending responses for {self.peername}")


class AsyncHandler(ABC):
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, rbox: SecretBox, tbox: SecretBox, peername: str):
        self.reader: asyncio.StreamReader = reader
        self.writer: asyncio.StreamWriter = writer
        self.rbox: SecretBox = rbox
        self.tbox: SecretBox = tbox
        self.peername: str = peername
        self._pending_msg_tasks: PendingProcessingTasks = PendingProcessingTasks()  # to keep track of pending tasks
        self._stop_event = asyncio.Event()  # to signal when the handler should stop processing messages

    async def write(self, msg: Buffer, msg_id: int = 1) -> None:
        # write should be called by handle_message() to reply to the client
        # we interrupt the write operation if stop_event is set
        await do_before_event(
            self.tbox.aencrypt(msg, msg_id=msg_id, out=self.writer),
            self._stop_event,
            name="async_handler_aencrypt",
        )

    async def _msg_loop(self) -> None:
        try:
            while True:
                # read and decrypt next msg
                msg, msg_id, ok = await self._read_decrypt_next_msg()
                if not ok:
                    # stop the loop, whatever the reason
                    return
                # if the message is a cancel message, we handle it separately
                if self.if_cancel_message(msg, msg_id):
                    continue  # it was a cancel message, do not handle it further and let the loop continue
                # process the message in the background
                self._process_msg_background(msg, msg_id)  # no await!
                # and loop immediately!
        finally:
            self._stop_event.set()  # just in case, lets be sure to send the stop signal when we exit the loop
            nb = self._pending_msg_tasks.cancel_all()  # cancel all pending message processing tasks
            if nb > 0:
                logger.info(f"Cancelled {nb} pending responses for {self.peername}")

    async def _read_decrypt_next_msg(self) -> tuple[bytes, int, bool]:
        # read next message from the client but interrupt if stop_event is set
        wrong = (b"", 0, False)  # return value in case of error
        try:
            emsg: EncryptedMessage = await do_before_event(
                EncryptedMessage.aread_from(self.reader),
                self._stop_event,
                name="async_handler_aread_from",
            )
        except asyncio.CancelledError:
            logger.info("Read canceled because server is stopping")
            return wrong
        except OSError as e:
            if not self._stop_event.is_set():
                self._stop_event.set()
                logger.info(f"Failed to read next client message: {e}")
            return wrong
        except ConnectionError as e:
            if not self._stop_event.is_set():
                self._stop_event.set()
                logger.info(f"Connection error while reading next client message: {e}")
            return wrong
        except Exception as e:
            logger.error(f"Unexpected error reading message: {e}")
            self._stop_event.set()
            return wrong
        try:
            msg = self.rbox.decrypt(emsg)  # warning, maybe TODO: this is a CPU bound operation, should we use a thread pool executor?
        except DecryptException as e:
            self._stop_event.set()
            logger.error(f"Decryption failed, closing connection: {e}")
            return wrong
        await asyncio.sleep(0)  # yield control to the event loop to give a chance to set stop_event
        if self._stop_event.is_set():
            logger.info("Stopping client handling read loop")
            return wrong

        return msg, emsg.msg_id, True

    def if_cancel_message(self, msg: bytes, msg_id: int) -> bool:
        if msg_id != CANCEL_MESSAGE_ID:
            return False
        msg_id_to_cancel = load64(msg)
        logger.info(f"Received cancel request for msg_id {msg_id_to_cancel} from {self.peername}, cancelling pending response")
        self._pending_msg_tasks.cancel(msg_id_to_cancel)
        return True  # do not continue handling this message, it was a cancel request

    def _process_msg_background(self, msg: bytes, msg_id: int) -> None:
        # create a task to handle the message
        # the point is to avoid blocking the read loop while handling the message
        # this allows the server to handle multiple messages concurrently
        process_msg_task = asyncio.create_task(self._handle_message(msg, msg_id))
        # keep track of the task to protect it against GC and to cancel it if needed
        self._pending_msg_tasks.register(msg_id, process_msg_task)
        # untrack the task when it is done
        process_msg_task.add_done_callback(lambda t: self._pending_msg_tasks.done(msg_id, t))

    async def _handle_message(self, msg: bytes, msg_id: int) -> None:
        # this is executed as a separate task, so we can handle multiple messages concurrently
        # basically, it just calls handle_message() and handles exceptions/cancellation
        if self._stop_event.is_set():
            logger.info("Interrupting message handling")
            return
        should_continue: bool = False
        try:
            should_continue = await self.handle_message(msg, msg_id)
            if not should_continue:
                self._stop_event.set()
                logger.info("Stopping message handling as requested by handler")
        except asyncio.CancelledError:
            self._stop_event.set()
        except ConnectionError as e:
            if not self._stop_event.is_set():
                logger.info(f"Connection error while handling message: {e}")
                self._stop_event.set()
        except Exception as e:
            logger.warning(f"Error handling message: {e}")
            self._stop_event.set()

    @abstractmethod
    async def handle_message(self, msg: bytes, msg_id: int) -> bool:
        # handle_message defines the behavior of the server when it receives a message.
        # typically, you could
        # - do something with the incoming message (bytes)
        # - prepare a response message (bytes)
        # - write the response message using self.write
        # using the same incoming msg_id for the response would enable the client to match the response with the request
        raise NotImplementedError()


class BaseAsyncTCPServer(ABC):
    def __init__(self, addr: tuple[str, int], handler_class: type[AsyncHandler]):
        self.host: str = addr[0]
        self.port: int = addr[1]
        self._handler_class: type[AsyncHandler] = handler_class
        self._server: asyncio.Server | None = None

    async def client_connected(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await self._client_connected(reader, writer)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def _client_connected(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peername = writer.get_extra_info("peername")
        logger.info(f"Connection from {peername}")

        try:
            session_pair: SessionPair = await self.key_exchange(reader, writer)
        except Exception as ex:
            logger.error(f"Key exchange failed with {peername}: {ex}")
            return

        rbox = SecretBox(session_pair.rx)
        tbox = SecretBox(session_pair.tx)
        logger.info(f"Session keys established with {peername}")

        # instantiate a handler instance to deal with this client
        handler_instance = self._handler_class(reader, writer, rbox, tbox, peername)
        try:
            await handler_instance._msg_loop()
        finally:
            logger.info(f"Handler for {peername} finished")

    @abstractmethod
    async def key_exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> SessionPair:
        raise NotImplementedError()

    async def run(self) -> None:
        if self._server is not None:
            logger.info("Async server is already running, skipping start")
            return
        self._server = await asyncio.start_server(
            self.client_connected,
            host=self.host,
            port=self.port,
            keep_alive=True,
            reuse_address=True,
            start_serving=False,
        )
        logger.info(f"Async server is running on {self.host}:{self.port}")
        try:
            await self._server.serve_forever()
        except asyncio.CancelledError:
            logger.info("Async server has been cancelled")
        finally:
            self._server.close()
            self._server.close_clients()
            await self._server.wait_closed()
            self._server = None
            logger.info("Async server has stopped running")

    def close(self) -> None:
        if self._server is not None:
            logger.info("Asking to close server")
            self._server.close()  # interrupts the serve_forever loop
            self._server.close_clients()


class KX_N_AsyncTCPServer(BaseAsyncTCPServer):
    def __init__(self, addr: tuple[str, int], handler_class: type[AsyncHandler], server_pair: KxPair, *, psk: Psk | None = None):
        super().__init__(addr, handler_class)
        self.server_pair: KxPair = server_pair
        self.psk: Psk | None = psk

    async def key_exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> SessionPair:
        packet1 = await reader.readexactly(KX_N_PACKET1BYTES)  # will trigger exception if not enough data
        session_pair = self.server_pair.server_finish_kx_n(
            packet1, self.psk
        )  # this will raise KeyExchangeException if the key exchange fails
        await SecretBox(session_pair.tx).aencrypt(OK_MESSAGE, 0, out=writer)
        return session_pair


class KX_KK_AsyncTCPServer(BaseAsyncTCPServer):
    def __init__(self, addr: tuple[str, int], handler_class: type[AsyncHandler], server_pair: KxPair, client_public_key: KxPublicKey):
        super().__init__(addr, handler_class)
        self.server_pair: KxPair = server_pair
        self.client_public_key: KxPublicKey = client_public_key

    async def key_exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> SessionPair:
        # read packet1 from the client, expected length is KX_KK_PACKET1BYTES
        packet1 = await reader.readexactly(KX_KK_PACKET1BYTES)
        # calculate the session keys
        session_pair, packet2 = self.server_pair.server_process_kx_kk(self.client_public_key, packet1)
        # send packet2 to the client
        writer.write(packet2)
        await writer.drain()
        return session_pair


class KX_N_TCPClient:
    """
    EncryptedTCPClient provides a client to connect to a TCP server using key exchange variant N.

    The client uses the server's public key to authenticate the server and generate session keys.
    """

    def __init__(self, server_address: tuple[str, int], server_public_key: KxPublicKey, psk: Psk | None = None):
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

    def connect(self, retry: int = -1) -> None:
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
            logger.warning(f"Connection to {self.server_address} failed, retrying in 1 second...")
            time.sleep(1)

        self.socket.settimeout(None)  # timeout does not play nice with makefile
        set_keepalive(self.socket)
        logger.info(f"Connected to server at {self.server_address}")
        self.rfile = self.socket.makefile("rb")
        self.wfile = self.socket.makefile("wb")

        self.session_pair, packet1 = client_init_kx_n(self.server_public_key, self.psk)
        self.wfile.write(packet1)
        self.wfile.flush()
        ack: bytes = EncryptedMessage.read_from(self.rfile).decrypt(self.session_pair.rx)
        if ack != OK_MESSAGE:
            raise KeyExchangeException("Server did not respond with 'OK' after sending packet1")

    def write(self, msg: Buffer, msg_id: int = 1):
        if not self.connected or self.wfile is None or self.closed or self.session_pair is None:
            raise RuntimeError("Client is not connected. Call connect() before writing.")
        if not msg:
            logger.warning("Attempted to write an empty message, skipping")
            return
        tx, wfile = self.session_pair.tx, self.wfile
        try:
            with self.write_lock:
                SecretBox(tx).encrypt(msg, msg_id=msg_id, out=wfile)
                wfile.flush()
        except OSError:
            logger.error("Failed to write to server, closing connection")
            self.close()
            raise

    def read(self) -> tuple[bytes, int]:
        if not self.connected or self.rfile is None or self.closed or self.session_pair is None:
            raise RuntimeError("Client is not connected. Call connect() before reading.")
        return self._read(self.rfile, self.session_pair.rx)

    def _read(self, rfile, rx) -> tuple[bytes, int]:
        if not self.connected or self.closed:
            raise RuntimeError("Client is not connected. Call connect() before reading.")
        try:
            with self.read_lock:
                emsg: EncryptedMessage = EncryptedMessage.read_from(rfile)
            return emsg.decrypt(rx), emsg.msg_id
        except OSError:
            logger.error("Failed to read from server, closing connection")
            self.close()
            raise
        except DecryptException:
            logger.error("Decryption failed, closing connection")
            self.close()
            raise

    def __iter__(self) -> Iterator[tuple[bytes, int]]:
        if not self.connected or self.rfile is None or self.closed or self.session_pair is None:
            raise RuntimeError("Client is not connected. Call connect() before iterating.")
        return _ClientIterator(self)

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.connected = False
        if self.socket is not None:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if self.rfile is not None:
            try:
                self.rfile.close()
            except OSError:
                pass
        if self.wfile is not None:
            try:
                self.wfile.close()
            except OSError:
                pass
        if self.socket is not None:
            try:
                self.socket.close()
            except OSError:
                pass

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class _ClientIterator:
    def __init__(self, client: KX_N_TCPClient):
        self.client = client
        self.stopped = False
        self.rfile = client.rfile
        if client.session_pair is None:
            raise RuntimeError("Client is not connected. Call connect() before iterating.")
        self.rx = client.session_pair.rx

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> tuple[bytes, int]:
        if self.stopped:
            raise StopIteration
        try:
            return self.client._read(self.rfile, self.rx)
        except OSError as e:
            self.stopped = True
            logger.warning(f"Connection closed or read error, stopping iteration: {e}")
            raise StopIteration
        except DecryptException:
            self.stopped = True
            logger.warning("Decryption failed, stopping read loop")
            raise
        except:
            self.stopped = True
            raise


class BaseAsyncTCPClient(ABC):
    def __init__(self, server_address: tuple[str, int]):
        self.server_address: tuple[str, int] = server_address

        self.connected: bool = False
        self.closed: bool = True

        self.session_pair: SessionPair | None = None
        self.reader: asyncio.StreamReader | None = None
        self.writer: asyncio.StreamWriter | None = None

    async def connect(self, retry: int = -1) -> None:
        if self.connected:
            logger.info("Client is already connected, skipping connect")
            return
        if not self.closed:
            logger.info("Client is already connecting, skipping connect")
            return
        self.closed = False  # to indicate that we are in the process of connecting
        try:
            await self._connect(retry=retry)
            self.connected = True  # success, we are connected
            logger.info("Server acknowledged, session keys established")
        except:
            # if _connect failed, the reader/writer/session_pair are not set
            # we just need to reset the state to closed
            self.closed = True
            self.connected = False
            raise

    async def _connect(self, retry: int) -> None:
        reader: asyncio.StreamReader
        writer: asyncio.StreamWriter
        session_pair: SessionPair

        while True:
            try:
                reader, writer = await asyncio.open_connection(self.server_address[0], self.server_address[1])
            except ConnectionRefusedError:
                if retry == 0:
                    raise
                if retry > 0:
                    retry -= 1
            else:
                break
            logger.warning(f"Connection to {self.server_address} failed, retrying in 1 second...")
            await asyncio.sleep(1)

        logger.info(f"Connected to server at {self.server_address}")

        session_pair = await self._key_exchange(reader, writer)
        # if no exception, everything is fine, we can set the session pair and reader/writer
        self.reader = reader
        self.writer = writer
        self.session_pair = session_pair

    async def _key_exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> SessionPair:
        try:
            return await self.key_exchange(reader, writer)
        except Exception as ex:
            raise KeyExchangeException("Key exchange failed") from ex

    @abstractmethod
    async def key_exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> SessionPair:
        raise NotImplementedError()

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        writer = self.writer
        self.connected = False
        self.writer = None
        self.reader = None
        self.session_pair = None  # let the garbage collector clean up the session pair
        if writer is not None:
            if not writer.is_closing():
                writer.close()
            await writer.wait_closed()

    async def write(self, msg: Buffer, msg_id: int = 1) -> None:
        if self.session_pair is None or self.writer is None:
            raise RuntimeError("Client is not connected")
        tx: SecretBoxKey = self.session_pair.tx
        writer: asyncio.StreamWriter = self.writer
        if msg is None:
            raise ValueError("Msg cannot be None")
        try:
            await SecretBox(tx).aencrypt(msg, msg_id, writer)
        except:
            logger.warning("Failed to write to server")
            await self.close()
            raise

    async def read(self) -> tuple[bytes, int]:
        if self.session_pair is None or self.reader is None:
            raise RuntimeError("Client is not connected")
        reader: asyncio.StreamReader = self.reader
        rx: SecretBoxKey = self.session_pair.rx
        try:
            emsg: EncryptedMessage = await EncryptedMessage.aread_from(reader)
            return emsg.decrypt(rx), emsg.msg_id
        except OSError:
            logger.info("Connection closed or read error")
            await self.close()
            raise
        except DecryptException:
            logger.error("Decryption failed")
            await self.close()
            raise
        except:
            logger.warning("Unknown error while reading from server")
            await self.close()
            raise

    def __aiter__(self) -> AsyncIterator[tuple[bytes, int]]:
        if self.session_pair is None or self.reader is None:
            raise RuntimeError("Client is not connected. Call connect() before iterating.")
        return _AsyncClientIterator(self, self.reader, self.session_pair.rx)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()


class KX_N_AsyncTCPClient(BaseAsyncTCPClient):
    def __init__(self, server_address: tuple[str, int], server_public_key: KxPublicKey, psk: Psk | None = None):
        super().__init__(server_address)
        self.server_public_key: KxPublicKey = server_public_key
        self.psk: Psk | None = psk

    async def key_exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> SessionPair:
        pair, packet1 = client_init_kx_n(self.server_public_key, self.psk)
        writer.write(packet1)
        await writer.drain()
        emsg: EncryptedMessage = await EncryptedMessage.aread_from(reader)
        ack: bytes = emsg.decrypt(pair.rx)
        if ack != OK_MESSAGE:
            raise KeyExchangeException("Server did not respond with 'OK' after sending packet1")
        return pair


class KX_KK_AsyncTCPClient(BaseAsyncTCPClient):
    def __init__(self, server_address: tuple[str, int], client_pair: KxPair, server_public_key: KxPublicKey):
        super().__init__(server_address)
        self.client_pair: KxPair = client_pair
        self.server_public_key: KxPublicKey = server_public_key

    async def key_exchange(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> SessionPair:
        # generate first packet
        st = self.client_pair.client_init_kx_kk(self.server_public_key)
        # send st.packet1 to the server
        writer.write(st.packet1)
        await writer.drain()
        # read the server's response: expected KX_KK_PACKET2BYTES
        packet2 = await reader.readexactly(KX_KK_PACKET2BYTES)
        # finish the key exchange
        return st.client_finish_kx_kk(packet2)


class _AsyncClientIterator:
    def __init__(self, client: BaseAsyncTCPClient, reader: asyncio.StreamReader, rx: SecretBoxKey):
        self.stopped = False
        self.reader: asyncio.StreamReader = reader
        self.rx: SecretBoxKey = rx
        self.client: BaseAsyncTCPClient = client

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> tuple[bytes, int]:
        if self.stopped:
            raise StopAsyncIteration
        try:
            emsg: EncryptedMessage = await EncryptedMessage.aread_from(self.reader)
            return emsg.decrypt(self.rx), emsg.msg_id
        except OSError:
            self.stopped = True
            await self.client.close()
            raise StopAsyncIteration
        except DecryptException:
            self.stopped = True
            logger.error("Stopping iteration: decryption failed")
            await self.client.close()
            raise
        except:
            self.stopped = True
            logger.warning("Stopping iteration: unexpected error")
            await self.client.close()
            raise


REQUEST_CANCELLED_ERROR = asyncio.CancelledError("Client connection closed, request cancelled")


class BaseAsyncRequestResponseClient:
    def __init__(self, client: BaseAsyncTCPClient, request_timeout_secs: int | None = 30):
        self._client: BaseAsyncTCPClient = client
        self._counter = Counter()
        self._pending_requests: dict[int, asyncio.Future] = {}
        self._read_task: asyncio.Task | None = None
        self._request_timeout_secs = request_timeout_secs

    async def connect(self, retry: int = -1) -> None:
        await self._client.connect(retry=retry)
        if self._read_task is None:
            self._read_task = asyncio.create_task(self._read_responses())

    async def close(self) -> None:
        read_task = self._read_task
        # make request() fail if called after close()
        self._read_task = None
        # safe to call in any case because the _client.close() method is guarded
        await self._client.close()
        # now we can cancel the read task
        if read_task is not None:
            read_task.cancel()
            try:
                await read_task
            except asyncio.CancelledError:
                logger.info("Read task cancelled")
        # from here no more responses will be received, so cancel all pending requests
        for fut in self._pending_requests.values():
            if not fut.done():
                fut.set_exception(REQUEST_CANCELLED_ERROR)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()

    async def request(self, msg: Buffer, timeout_secs: int | None = None) -> bytes:
        timeout_secs = timeout_secs if timeout_secs is not None else self._request_timeout_secs
        if self._read_task is None:
            raise RuntimeError("Client is not connected. Call connect() before making requests.")
        # ensure we get a unique message ID for this request
        msg_id: int = self._counter()
        # create and register the future that will hold the response to this request
        fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        # when the response is received in read_task, we will set the result of this future
        self._pending_requests[msg_id] = fut
        try:
            await self._client.write(msg, msg_id=msg_id)
        except:
            # a response will never come, so clean up the future
            del self._pending_requests[msg_id]
            await self.close()
            raise
        if timeout_secs is None:
            # no timeout
            # we still have to take care of request cancellation by the user
            try:
                return await fut
            except asyncio.CancelledError:
                del self._pending_requests[msg_id]
                logger.info(f"Request {msg_id} cancelled")
                await self._cancel_request(msg_id)  # attempt to cancel the request on the server side
                raise
        # with timeout
        try:
            async with asyncio.timeout(timeout_secs):
                return await fut
        except TimeoutError:
            try:
                del self._pending_requests[msg_id]
            except KeyError:
                pass
            logger.info(f"Request {msg_id} timed out")
            await self._cancel_request(msg_id)  # attempt to cancel the request on the server side
            raise
        except asyncio.CancelledError:
            try:
                del self._pending_requests[msg_id]
            except KeyError:
                pass
            logger.info(f"Request {msg_id} cancelled")
            await self._cancel_request(msg_id)  # attempt to cancel the request on the server side
            raise

    async def _cancel_request(self, msg_id: int) -> None:
        # send a short cancel message to the server
        # msg_id = CANCEL_MESSAGE_ID is reserved for cancel requests
        cancel_msg = bytearray(8)
        store64(cancel_msg, msg_id)
        try:
            await self._client.write(cancel_msg, msg_id=CANCEL_MESSAGE_ID)
        except Exception as e:
            logger.info(f"Failed to send cancel request for msg_id {msg_id}: {e}")

    async def _read_responses(self) -> None:
        # read responses from the server in a loop
        fut: asyncio.Future[bytes]
        try:
            async for msg, msg_id in self._client:
                try:
                    # get the future associated with this msg_id
                    # we assume that the server sends the response with the request 'msg_id', using the same msg_id
                    fut = self._pending_requests.pop(msg_id)
                except KeyError:
                    logger.warning(f"Received response with unknown msg_id {msg_id}, ignoring")
                fut.set_result(msg)
        finally:
            # if the read loop unexpectedly exits, be sure to close the client
            await self.close()


class KX_N_AsyncRequestResponseClient(BaseAsyncRequestResponseClient):
    def __init__(
        self,
        server_address: tuple[str, int],
        server_public_key: KxPublicKey,
        *,
        psk: Psk | None = None,
        request_timeout_secs: int | None = 30,
    ):
        client = KX_N_AsyncTCPClient(server_address, server_public_key, psk)
        super().__init__(client, request_timeout_secs=request_timeout_secs)


class KX_KK_AsyncRequestResponseClient(BaseAsyncRequestResponseClient):
    def __init__(
        self,
        server_address: tuple[str, int],
        client_pair: KxPair,
        server_public_key: KxPublicKey,
        request_timeout_secs: int | None = 30,
    ):
        client = KX_KK_AsyncTCPClient(server_address, client_pair, server_public_key)
        super().__init__(client, request_timeout_secs=request_timeout_secs)


def set_keepalive_linux(sock: socket.socket, after_idle_sec: int, interval_sec: int, max_fails: int):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if after_idle_sec is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    if interval_sec is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    if max_fails is not None:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)


def set_keepalive_osx(sock, after_idle_sec, interval_sec, max_fails):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, interval_sec)


def set_keepalive_win(sock, after_idle_sec, interval_sec, max_fails):
    sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, after_idle_sec * 1000, interval_sec * 1000))


def set_keepalive(sock: socket.socket, *, after_idle_sec: int = 10, interval_sec: int = 5, max_fails: int = 4):
    if PLATFORM == "linux":
        return set_keepalive_linux(sock, after_idle_sec, interval_sec, max_fails)
    if PLATFORM == "darwin":
        return set_keepalive_osx(sock, after_idle_sec, interval_sec, max_fails)
    if PLATFORM == "Windows":
        return set_keepalive_win(sock, after_idle_sec, interval_sec, max_fails)
    logger.warning(f"Keepalive not supported on {PLATFORM} platform, skipping")
