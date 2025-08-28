import asyncio
import contextvars
import logging
import types
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Awaitable, Buffer, Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Self

from ._kx_n import (
    KxPair,
    KxPublicKey,
    Psk,
)
from ._networking import MsgQueue
from ._utils import Counter, load64, store64
from .exceptions import ClientClosedError, DecryptException, KeyExchangeException, MessageTooBigException
from .networking import (
    CANCEL_MESSAGE_ID,
    EOF_EXCEPTION,
    N_CPUS,
    PY312,
    BaseMachine,
    InvalidTransitionError,
    KX_KK_ClientStateMachine,
    KX_KK_ServerStateMachine,
    KX_N_ClientStateMachine,
    KX_N_ServerStateMachine,
    KX_XX_ClientStateMachine,
    KX_XX_ServerStateMachine,
    KxCompleted,
    KxFailed,
    KxProgress,
    MachineOutEvent,
    MState,
    ReceivedEncryptedMessage,
)

logger = logging.getLogger("cydrogen")


_DEFAULT_LIMIT: int = 2**16  # 64 KiB
"""
The threshold in bytes for the total size of received messages that have not been processed yet.

When the total size of received messages exceeds twice this limiit, the Protocol will ask the Transport to pause reading.
"""


type StreamHandlerFunction = Callable[["StreamReaderWriter"], Awaitable[None]]
"""
A function that handles a stream, taking a StreamReaderWriter instance as an argument and returning an Awaitable.

Typically: `async def handler(rw: StreamReaderWriter) -> None`.
"""

type ValidatePeerKeyFunc = Callable[[KxPublicKey], Awaitable[None]]
"""
A function that validates a peer's public key, taking a KxPublicKey instance as an argument and returning an Awaitable.

Typically: `async def validate_peer_key(peer_key: KxPublicKey) -> None`.

The function should raise an exception if the key is not valid.
"""


class StreamReaderWriter:
    """
    StreamReaderWriter provides a simple interface for reading and writing messages.

    Attributes:
        peername: The name of the peer this reader/writer is connected to.
    """

    def __init__(self, protocol: "KXProtocol") -> None:
        self._protocol: KXProtocol = protocol
        self.peername = protocol.peername

    def close(self) -> None:
        """
        Closes the stream reader/writer.
        """
        self._protocol.close()

    def is_closing(self) -> bool:
        """
        Returns whether the stream is closing.
        """
        return self._protocol.is_closing()

    async def wait_closed(self) -> None:
        """
        Waits until the stream is closed.
        """
        await self._protocol.wait_closed()

    async def get_next_msg(self) -> tuple[bytes, int]:
        """
        Reads the next message from the stream.

        Returns:
            The decrypted message.
            The message ID associated with the decrypted message.
        """
        return await self._protocol.get_next_msg()

    async def write_cancel_msg(self, target_msg_id: int) -> None:
        """
        Writes a cancel message to the server.

        This method only makes sense for a request/response client. It asks the server to cancel the processing of a
        previously sent message.

        Args:
            target_msg_id: The message ID of the message to cancel.
        """
        await self._protocol.write_cancel_msg(target_msg_id)

    async def write_msg(self, msg: Buffer, msg_id: int) -> None:
        """
        Writes a message to the stream after encrypting it.

        Args:
            msg: The message to write, as a bytes-like object.
            msg_id: The message ID to use for the message.
        """
        await self._protocol.write_msg(msg, msg_id)

    def write_eof(self) -> None:
        """
        Writes an EOF to the stream.
        """
        self._protocol.write_eof()

    def can_write_eof(self) -> bool:
        """
        Returns whether the stream can write an EOF.
        """
        return self._protocol.can_write_eof()

    async def drain(self) -> None:
        """
        Waits until all data has been written to the stream.
        """
        await self._protocol.drain()

    def get_extra_info(self, name: str, default: Any = None) -> Any:  # noqa: ANN401
        """
        Returns extra information about the stream.
        """
        return self._protocol.get_extra_info(name, default)


async def dummy_validate_peer_key(key: KxPublicKey) -> None:
    logger.debug("Dummy validate peer key called for %s", key)


class KXProtocol(asyncio.BufferedProtocol):
    def __init__(
        self,
        machine: BaseMachine,
        loop: asyncio.AbstractEventLoop,
        *,
        client_handler: StreamHandlerFunction | None = None,
        limit: int = _DEFAULT_LIMIT,
        validate_peer_key: ValidatePeerKeyFunc | None = None,
        executor: ThreadPoolExecutor,
    ) -> None:
        self._loop = loop
        self._reading_paused = False
        self._writing_paused = False
        self._drain_futures: deque[asyncio.Future] = deque()
        self._connection_lost = False
        self._machine = machine
        self._closed_fut = loop.create_future()
        self._limit = limit
        self._client_handler: StreamHandlerFunction | None = client_handler
        self._kx_completed = loop.create_future()
        self._validate_peer_key: ValidatePeerKeyFunc = validate_peer_key or dummy_validate_peer_key
        self._task: asyncio.Task | None = None
        self._decrypt_task: asyncio.Task | None = None
        self._validation_fut: asyncio.Future = self._loop.create_future()
        self._executor = executor

        self._received_encrypted_msgs: MsgQueue[memoryview] = MsgQueue()
        self._received_decrypted_msgs: MsgQueue[bytes] = MsgQueue()

        self.peername: str = ""

        self._transport: asyncio.Transport

    @property
    def received_size(self) -> int:
        """
        Returns the total size of received messages that have not been processed yet.
        """
        return self._received_decrypted_msgs.bytesize

    @property
    def machine(self) -> BaseMachine:
        return self._machine

    @property
    def kx_completed(self) -> asyncio.Future:
        return self._kx_completed

    def close(self) -> None:
        self._transport.close()

    def is_closing(self) -> bool:
        return self._transport.is_closing()

    async def wait_closed(self) -> None:
        await self._closed_fut

    async def get_next_msg(self) -> tuple[bytes, int]:
        return await self._received_decrypted_msgs.get()

    def _handle_machine_events(self, events: list[MachineOutEvent]) -> None:
        for event in events:
            self._handle_machine_event(event)

    def _handle_machine_event(self, ev: MachineOutEvent) -> None:
        match ev:
            case KxCompleted():
                self._kx_completed.set_result(None)
            case KxFailed(exc=exc):
                self._kx_completed.set_exception(exc)
            case KxProgress():
                pass
            case ReceivedEncryptedMessage(emsg=emsg):
                self._received_encrypted_msgs.put_nowait(emsg)

    async def write_cancel_msg(self, target_msg_id: int) -> None:
        cancel_msg = bytearray(8)
        store64(cancel_msg, target_msg_id)
        ciphertext = self._machine.encrypt_message(cancel_msg, CANCEL_MESSAGE_ID)
        evs = self._machine.trigger_write_emessage(ciphertext, CANCEL_MESSAGE_ID)
        self._handle_machine_events(evs)
        data = self._machine.data_to_send()
        if data:
            self._transport.write(data)
            await self.drain()

    async def write_msg(self, msg: Buffer, msg_id: int) -> None:
        """
        Write a message after encrypting it.

        Args:
            msg: The message to write, as a bytes-like object.
            msg_id: The message ID to use for the message.

        Raises:
            MessageTooBigException: If the message is too big to be sent.
            ValueError: If msg_id is CANCEL_MESSAGE_ID.
        """
        if msg_id == CANCEL_MESSAGE_ID:
            raise ValueError("Cannot write a message with msg_id CANCEL_MESSAGE_ID")
        length = len(memoryview(msg))
        if length == 0:
            return
        if length > self._machine.sent_msg_max_size:
            raise MessageTooBigException
        # execute encryption in a separate thread to avoid blocking the event loop
        # may raise MessageTooBigException if the message is too big
        ciphertext = await self._loop.run_in_executor(self._executor, self._machine.encrypt_message, msg, msg_id)
        evs = self._machine.trigger_write_emessage(ciphertext, msg_id)
        self._handle_machine_events(evs)
        data = self._machine.data_to_send()
        if data:
            self._transport.write(data)
            await self.drain()

    def write_eof(self) -> None:
        evs = self._machine.trigger_writer_eof()
        self._handle_machine_events(evs)
        self._transport.write_eof()

    def can_write_eof(self) -> bool:
        return self._transport.can_write_eof()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self.peername = str(transport.get_extra_info("peername", ""))
        if self._client_handler is None:
            logger.info("connected to server %s", self.peername)
        else:
            logger.info("new connection from client %s", self.peername)
        self._kx_completed.add_done_callback(self.key_exchange_completed)
        evs = self._machine.trigger_connection_made()
        self._handle_machine_events(evs)
        data = self._machine.data_to_send()
        if data:
            self._transport.write(data)

    def key_exchange_completed(self, kx_completed: asyncio.Future) -> None:
        if kx_completed.cancelled():
            logger.warning("Key exchange with %s was cancelled", self.peername)
            self._transport.abort()
            return
        if kx_completed.exception() is not None:
            logger.error("Key exchange with %s failed: %s", self.peername, kx_completed.exception())
            self._transport.abort()
            return

        logger.info("key exchange with %s completed with success", self.peername)

        self._task = self._loop.create_task(self.validate_and_handle())

    async def _decrypt_received_messages(self) -> None:
        """
        Decrypts received encrypted messages and pushes the decrypted messages to the queue of received decrypted messages.

        This is a long running coroutine that continuously reads encrypted messages from the queue of received encrypted messages,
        decrypts them, and pushes the decrypted messages to the queue of received decrypted messages.

        The function normally runs until the queue of received encrypted messages is closed (e.g. when the connection is lost or closed).
        But if an an exception occurs during decryption, the coroutine will raise a `DecryptException` and stop processing further messages.

        This coroutine is scheduled as a task by the Protocol when the key exchange is completed successfully.
        """
        logger.info("starting to decrypt received messages")
        while True:
            try:
                incoming, _ = await self._received_encrypted_msgs.get()
            except Exception as ex:  # noqa: BLE001
                # this means that the queue of encrypted messages has been closed
                logger.info("decrypt received messages has finished: %s", ex)
                # consequently, we close the queue of decrypted messages (previously queued messages may still be consumed)
                self._received_decrypted_msgs.close(ex)
                return
            # decrypt the message and push the result downstream to _received_decrypted_msgs queue
            try:
                plaintext, msg_id = await self._loop.run_in_executor(self._executor, self._machine.decrypt_message, incoming)
                self._received_decrypted_msgs.put_nowait(plaintext, msg_id)
            except Exception as ex:
                # we won't decrypt any more message after the decryption failure, so we close the queue of decrypted messages
                self._received_decrypted_msgs.close(ex)
                # DecryptException will be captured by the protocol, which will abort the transport
                raise DecryptException("Failed to decrypt message from peer") from ex
            finally:
                self._machine.release_encrypted_message(incoming)  # return the mview to the freelist

    async def continuous_decrypt(self) -> None:
        try:
            await self._decrypt_received_messages()
        except Exception:
            logger.exception("Continuous decryption task failed")
            self._transport.abort()

    async def validate_and_handle(self) -> None:
        try:
            await self.validate_peer_key()
            self._validation_fut.set_result(None)
        except asyncio.CancelledError:
            self._transport.abort()
            logger.warning("Peer public key validation for %s cancelled", self.peername)
            self._validation_fut.cancel()
            return
        except Exception as ex:
            self._transport.abort()
            logger.exception("Peer public key validation for %s failed", self.peername)
            if self._client_handler is None:
                # we are client side, we need to set the exception so that the client will fail
                self._validation_fut.set_exception(ex)
            else:
                # we are server side, there is nothing to await the validation future
                self._validation_fut.set_result(None)
            return
        logger.info("Peer public key validation for %s passed", self.peername)

        self._decrypt_task = self._loop.create_task(self.continuous_decrypt())

        if self._client_handler is None:
            logger.debug("skipping client handler")
            return
        try:
            await self._client_handler(StreamReaderWriter(self))
        except asyncio.CancelledError:
            logger.info("Client handler for %s cancelled", self.peername)
        except Exception:
            logger.exception("Client handler for %s", self.peername)
        finally:
            self._transport.close()
            logger.info("Client %s disconnected", self.peername)

    async def validate_peer_key(self) -> None:
        peer_key = self._machine.get_peer_key()
        if peer_key is None:
            logger.debug("No peer public key to validate")
            return
        logger.debug("Validating peer public key")
        try:
            await self._validate_peer_key(peer_key)
        except Exception as ex:
            raise KeyExchangeException("Failed to validate peer public key") from ex

    async def wait_for_validation(self) -> None:
        await self._validation_fut

    async def wait_for_key_exchange(self) -> None:
        await self._kx_completed

    def get_buffer(self, sizehint: int) -> memoryview:  # noqa: ARG002
        return self._machine.get_buffer()

    def buffer_updated(self, nbytes: int) -> None:
        evs = self._machine.trigger_receive_data(nbytes)
        self._handle_machine_events(evs)
        self.maybe_pause_reading()  # TODO: move ?
        data = self._machine.data_to_send()
        if data:
            self._transport.write(data)

    def maybe_pause_reading(self) -> None:
        if self._reading_paused:
            return
        if self.received_size > 2 * self._limit:
            try:
                logger.info("Transport was asked to pause reading, received_size: %d, limit: %d", self.received_size, self._limit)
                self._transport.pause_reading()
                self._reading_paused = True
            except NotImplementedError:
                pass

    def maybe_resume_reading(self) -> None:
        if not self._reading_paused:
            return
        if self.received_size <= self._limit:
            logger.info("Transport asked to resume reading, received_size: %d, limit: %d", self.received_size, self._limit)
            self._reading_paused = False
            self._transport.resume_reading()

    def connection_lost(self, exc: Exception | None) -> None:
        logger.info("connection lost for %s, exc: %s", self.peername, exc)
        if isinstance(exc, ConnectionError):
            exc = EOF_EXCEPTION
        evs = self._machine.trigger_connection_lost(exc)
        self._handle_machine_events(evs)
        self._received_encrypted_msgs.close(self._machine.exception)  # unblock readers
        # make wait_closed() return
        if not self._closed_fut.done():
            if exc is None:
                self._closed_fut.set_result(None)
            else:
                self._closed_fut.set_exception(exc)

        self._connection_lost = True  # makes next calls to drain() raise EOFError

        if self._writing_paused:
            # some writers may be on pause, we need to unblock them
            for dfut in self._drain_futures:
                if not dfut.done():
                    if exc is None:
                        dfut.set_result(None)
                    else:
                        dfut.set_exception(exc)

        if self._decrypt_task is not None and self._client_handler is None:
            # because we received connection_lost, it is not possible anymore to send encrypted messages
            # because self._client_handler is None, we know we are client side
            # because the queue of encrypted messages has been closed, we know that the decrypt task will finish soon
            # when _decrypt_task finishes, we also know we wont be decrypting any more message
            # so in that case we can shutdown the executor as no encryption/decryption will happen anymore
            def callback(_: asyncio.Future) -> None:
                self._executor.shutdown(wait=False)

            self._decrypt_task.add_done_callback(callback)

    def eof_received(self) -> bool:
        logger.info("eof received from %s", self.peername)
        evs = self._machine.trigger_reader_eof()
        self._handle_machine_events(evs)
        self._received_encrypted_msgs.close(self._machine.exception)  # unblock readers
        return False

    async def drain(self) -> None:
        if self._connection_lost:
            raise EOF_EXCEPTION
        if self._transport.is_closing():
            await asyncio.sleep(0)
        if self._connection_lost:
            raise EOF_EXCEPTION
        if not self._writing_paused:
            return
        waiter = self._loop.create_future()
        self._drain_futures.append(waiter)
        try:
            await waiter
        finally:
            self._drain_futures.remove(waiter)

    def pause_writing(self) -> None:
        logger.info("pause_writing called: Transport asked protocol to pause writing")
        self._writing_paused = True

    def resume_writing(self) -> None:
        logger.info("resume_writing called: Transport asked protocol to resume writing")
        self._writing_paused = False

        for waiter in self._drain_futures:
            if not waiter.done():
                waiter.set_result(None)

    def get_extra_info(self, name: str, default: Any = None) -> Any:  # noqa: ANN401
        return self._transport.get_extra_info(name, default)


async def _connect(
    host: str,
    port: int,
    protocol_factory: Callable[[], KXProtocol],
    retry: int,
    retry_wait: int,
) -> tuple[asyncio.Transport, KXProtocol]:
    loop = asyncio.get_running_loop()
    while True:
        try:
            logger.debug("Connecting to %s:%d...", host, port)
            transport, protocol = await loop.create_connection(protocol_factory, host, port)
            logger.debug("Connected to %s:%d", host, port)
            return transport, protocol
        except ConnectionRefusedError:
            if retry == 0:
                raise
        retry -= 1
        logger.warning("Connection to %s:%d failed", host, port)
        if retry_wait > 0:
            logger.info("Retrying connection in %d seconds...", retry_wait)
            await asyncio.sleep(retry_wait)


async def _open_connection(
    host: str,
    port: int,
    machine_factory: Callable[[], BaseMachine],
    limit: int,
    validate_server_key: ValidatePeerKeyFunc | None,
    retry: int,
    retry_wait: int,
    loop: asyncio.AbstractEventLoop,
) -> StreamReaderWriter:
    # one executor per client
    executor = ThreadPoolExecutor(max_workers=min(8, N_CPUS + 4))

    def protocol_factory() -> KXProtocol:
        machine = machine_factory()
        return KXProtocol(machine, loop, limit=limit, validate_peer_key=validate_server_key, executor=executor)

    try:
        transport, protocol = await _connect(host, port, protocol_factory, retry, retry_wait)
    except:
        executor.shutdown(wait=False)
        raise
    try:
        await protocol.wait_for_key_exchange()
    except Exception as ex:
        transport.abort()
        raise KeyExchangeException(f"Failed to complete key exchange with {host}:{port}") from ex
    try:
        await protocol.wait_for_validation()
    except Exception:
        transport.abort()
        raise
    return StreamReaderWriter(protocol)


async def open_kx_n_connection(
    host: str,
    port: int,
    server_public_key: KxPublicKey,
    *,
    psk: Psk | None = None,
    limit: int = _DEFAULT_LIMIT,
    connect_retry: int = 3,
    connect_retry_wait: int = 30,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
) -> StreamReaderWriter:
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

    def machine_factory() -> BaseMachine:
        return KX_N_ClientStateMachine(
            server_public_key, psk=psk, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size
        )

    return await _open_connection(host, port, machine_factory, limit, None, connect_retry, connect_retry_wait, loop)


async def open_kx_kk_connection(
    host: str,
    port: int,
    client_pair: KxPair,
    server_public_key: KxPublicKey,
    *,
    limit: int = _DEFAULT_LIMIT,
    connect_retry: int = 3,
    connect_retry_wait: int = 30,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
) -> StreamReaderWriter:
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

    def machine_factory() -> BaseMachine:
        return KX_KK_ClientStateMachine(
            client_pair, server_public_key, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size
        )

    return await _open_connection(host, port, machine_factory, limit, None, connect_retry, connect_retry_wait, loop)


async def open_kx_xx_connection(
    host: str,
    port: int,
    client_pair: KxPair,
    *,
    psk: Psk | None = None,
    limit: int = _DEFAULT_LIMIT,
    validate_server_key: ValidatePeerKeyFunc | None = None,
    connect_retry: int = 3,
    connect_retry_wait: int = 30,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
) -> StreamReaderWriter:
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

    def machine_factory() -> BaseMachine:
        return KX_XX_ClientStateMachine(
            client_pair, psk=psk, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size
        )

    return await _open_connection(host, port, machine_factory, limit, validate_server_key, connect_retry, connect_retry_wait, loop)


class BaseAsyncRequestResponseClient:
    def __init__(self, request_timeout_secs: int | None = 30) -> None:
        self._counter = Counter()
        self._pending_requests: dict[int, asyncio.Future[bytes]] = {}
        self._request_timeout_secs: int | None = request_timeout_secs

        self._rw: StreamReaderWriter
        self._read_task: asyncio.Task

    async def connect(self) -> None:
        self._read_task = asyncio.create_task(self._read_responses())

    def close(self, ex: BaseException | None = None) -> None:
        self._rw.close()
        if ex is None:
            for fut in self._pending_requests.values():
                fut.cancel()
        else:
            for fut in self._pending_requests.values():
                if not fut.done():
                    fut.set_exception(ex)

    async def wait_closed(self) -> None:
        await self._rw.wait_closed()
        try:
            await self._read_task
        except asyncio.CancelledError:
            pass
        except Exception as ex:  # noqa: BLE001
            logger.info("Read task stopped with error: %s", ex)

    async def __aenter__(self) -> Self:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:  # noqa: ANN001
        self.close()
        await self.wait_closed()

    async def request(self, msg: Buffer, *, timeout_secs: int | None = None) -> bytes:
        if self._read_task.done() or self._rw.is_closing():
            raise ClientClosedError
        timeout_secs = timeout_secs if timeout_secs is not None else self._request_timeout_secs
        # ensure we get a unique message ID for this request
        msg_id: int = self._counter()
        # create and register the future that will hold the response to this request
        fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        # when the response is received in read_task, we will set the result of this future
        self._pending_requests[msg_id] = fut
        try:
            await self._rw.write_msg(msg, msg_id=msg_id)
        except InvalidTransitionError as ex:
            # a response will never come, so clean up the future
            del self._pending_requests[msg_id]
            self.close(ex)
            if ex.orig_state in (MState.WRITER_CLOSED, MState.READER_WRITER_CLOSED):
                raise ClientClosedError from ex
            raise
        except:
            # a response will never come, so clean up the future
            del self._pending_requests[msg_id]
            self.close()
            raise
        try:
            async with asyncio.timeout(timeout_secs):
                return await fut
        except TimeoutError:
            await self._cancel_request(msg_id)  # attempt to cancel the request on the server side
            logger.info("Request timed out: %s", msg_id)
            raise
        except asyncio.CancelledError:
            await self._cancel_request(msg_id)  # attempt to cancel the request on the server side
            raise
        finally:
            if msg_id in self._pending_requests:
                del self._pending_requests[msg_id]

    async def _cancel_request(self, msg_id: int) -> None:
        # send a short cancel message to the server
        # msg_id = CANCEL_MESSAGE_ID is reserved for cancel requests

        try:
            await self._rw.write_cancel_msg(msg_id)
            logger.info("Request cancelled: %s", msg_id)
        except Exception as ex:  # noqa: BLE001
            logger.info("Failed to cancel request: %s: %s", msg_id, ex)

    async def _read_responses(self) -> None:
        # read responses from the server in a loop
        try:
            while True:
                msg, msg_id = await self._rw.get_next_msg()
                fut = self._pending_requests.get(msg_id)
                if fut is None:
                    await self.handle_unexpected_response(msg, msg_id)
                elif not fut.done():
                    fut.set_result(msg)
        except Exception as ex:  # noqa: BLE001
            self.close(ex)
        else:
            self.close()

    async def handle_unexpected_response(self, msg: bytes, msg_id: int) -> None:
        # this method is called when the client receives a response with an unknown msg_id
        # you can override this method to handle unexpected responses
        # by default, we just ignore it
        logger.warning("Unexpected response received. nbytes = %s, msg_id = %s", len(msg), msg_id)


class KX_N_AsyncRequestResponseClient(BaseAsyncRequestResponseClient):
    def __init__(
        self,
        host: str,
        port: int,
        server_public_key: KxPublicKey,
        *,
        psk: Psk | None = None,
        limit: int = _DEFAULT_LIMIT,
        request_timeout_secs: int | None = 30,
        connect_retry: int = 3,
        connect_retry_wait: int = 30,
        sent_msg_max_size: int = 2**20,
        received_msg_max_size: int = 2**20,
    ) -> None:
        super().__init__(request_timeout_secs=request_timeout_secs)
        self._host = host
        self._port = port
        self._server_public_key = server_public_key
        self._psk = psk
        self._limit = limit
        self._connect_retry = connect_retry
        self._connect_retry_wait = connect_retry_wait
        self.sent_msg_max_size = sent_msg_max_size
        self.received_msg_max_size = received_msg_max_size

    async def connect(self) -> None:
        self._rw = await open_kx_n_connection(
            self._host,
            self._port,
            self._server_public_key,
            psk=self._psk,
            limit=self._limit,
            connect_retry=self._connect_retry,
            connect_retry_wait=self._connect_retry_wait,
            sent_msg_max_size=self.sent_msg_max_size,
            received_msg_max_size=self.received_msg_max_size,
        )
        await super().connect()


class KX_KK_AsyncRequestResponseClient(BaseAsyncRequestResponseClient):
    def __init__(
        self,
        host: str,
        port: int,
        client_pair: KxPair,
        server_public_key: KxPublicKey,
        *,
        limit: int = _DEFAULT_LIMIT,
        request_timeout_secs: int | None = 30,
        connect_retry: int = 3,
        connect_retry_wait: int = 30,
        sent_msg_max_size: int = 2**20,
        received_msg_max_size: int = 2**20,
    ) -> None:
        super().__init__(request_timeout_secs=request_timeout_secs)
        self._host = host
        self._port = port
        self._client_pair = client_pair
        self._server_public_key = server_public_key
        self._limit = limit
        self._connect_retry = connect_retry
        self._connect_retry_wait = connect_retry_wait
        self.sent_msg_max_size = sent_msg_max_size
        self.received_msg_max_size = received_msg_max_size

    async def connect(self) -> None:
        self._rw = await open_kx_kk_connection(
            self._host,
            self._port,
            self._client_pair,
            self._server_public_key,
            limit=self._limit,
            connect_retry=self._connect_retry,
            connect_retry_wait=self._connect_retry_wait,
            sent_msg_max_size=self.sent_msg_max_size,
            received_msg_max_size=self.received_msg_max_size,
        )
        await super().connect()


class KX_XX_AsyncRequestResponseClient(BaseAsyncRequestResponseClient):
    def __init__(
        self,
        host: str,
        port: int,
        client_pair: KxPair,
        *,
        psk: Psk | None = None,
        limit: int = _DEFAULT_LIMIT,
        validate_server_key: ValidatePeerKeyFunc | None = None,
        request_timeout_secs: int | None = 30,
        connect_retry: int = 3,
        connect_retry_wait: int = 30,
        sent_msg_max_size: int = 2**20,
        received_msg_max_size: int = 2**20,
    ) -> None:
        super().__init__(request_timeout_secs=request_timeout_secs)
        self._host = host
        self._port = port
        self._client_pair = client_pair
        self._psk = psk
        self._limit = limit
        self._validate_server_key = validate_server_key
        self._connect_retry = connect_retry
        self._connect_retry_wait = connect_retry_wait
        self.sent_msg_max_size = sent_msg_max_size
        self.received_msg_max_size = received_msg_max_size

    async def connect(self) -> None:
        self._rw = await open_kx_xx_connection(
            self._host,
            self._port,
            self._client_pair,
            psk=self._psk,
            limit=self._limit,
            validate_server_key=self._validate_server_key,
            connect_retry=self._connect_retry,
            connect_retry_wait=self._connect_retry_wait,
            sent_msg_max_size=self.sent_msg_max_size,
            received_msg_max_size=self.received_msg_max_size,
        )
        await super().connect()


class ServerPendingProcessingTasks:
    def __init__(self) -> None:
        # keep track of pending server tasks by incoming message ID
        self.pending: dict[int, set[asyncio.Task]] = {}

    def register(self, msg_id: int, task: asyncio.Task) -> None:
        if msg_id not in self.pending:
            self.pending[msg_id] = set()
        self.pending[msg_id].add(task)

    def done(self, msg_id: int, task: asyncio.Task) -> None:
        s = self.pending.get(msg_id)
        if s is None:
            return
        s.discard(task)
        if not s:
            del self.pending[msg_id]

    def cancel(self, msg_id: int) -> None:
        for task in self.pending.get(msg_id, []):
            task.cancel()

    def cancel_all(self) -> int:
        nb = 0
        for tasks in self.pending.values():
            nb += len(tasks)
            for task in tasks:
                task.cancel()
        return nb


class BaseServerHandler(ABC):
    def __init__(self) -> None:
        self._tasks = ServerPendingProcessingTasks()
        self._stopping: bool = False
        self.rw: StreamReaderWriter
        self._msgid_var: contextvars.ContextVar = contextvars.ContextVar("msgid")

    async def handle(self, rw: StreamReaderWriter) -> None:
        # note: self.handle is a StreamHandlerFunction
        self.rw = rw
        try:
            while not self._stopping:
                msg, msg_id = await rw.get_next_msg()
                self._process_msg(msg, msg_id)
        except EOFError:
            logger.info("EOF received")
        except Exception as ex:  # noqa: BLE001
            logger.warning("While reading next message: %s", ex)
        finally:
            self._stopping = True
            nb = self._tasks.cancel_all()
            logger.info("Cancelled pending tasks: %s", nb)
            rw.close()
            await rw.wait_closed()

    def _process_msg(self, msg: bytes, msg_id: int) -> None:
        if msg_id == CANCEL_MESSAGE_ID:
            msg_id_to_cancel = load64(msg)
            logger.info("Received cancel for request: %s (%s)", msg_id_to_cancel, self.rw.peername)
            self._tasks.cancel(msg_id_to_cancel)
            return
        if self._stopping:
            # not scheduling new tasks if we are stopping
            return
        # schedule a new task to handle the message
        task: asyncio.Task = asyncio.create_task(self._handle_message(msg, msg_id))
        self._tasks.register(msg_id, task)

        def cb(t: asyncio.Task) -> None:
            self._tasks.done(msg_id, t)

        task.add_done_callback(cb)

    async def _handle_message(self, msg: bytes, msg_id: int) -> None:
        self._msgid_var.set(msg_id)
        try:
            if not await self.handle_message(msg, msg_id):
                self._stopping = True
                self.rw.close()
        except MessageTooBigException:
            logger.error("Server response is too big (incoming msg_id: %d)", msg_id)  # noqa: TRY400
            self._stopping = True
            self.rw.close()
        except Exception:
            logger.exception("Error while handling message %s", msg_id)

    @abstractmethod
    async def handle_message(self, msg: bytes, msg_id: int) -> bool:
        raise NotImplementedError

    async def write(self, msg: bytes, msg_id: int | None = None) -> None:
        # the write method can be used by subclasses to implement handle_message
        # it automatically uses the message ID from the incoming message to write the response, if not provided
        if msg_id is None:
            msg_id = self._msgid_var.get()
        await self.rw.write_msg(msg, msg_id)


class RequestResponseHandler(BaseServerHandler, ABC):
    @abstractmethod
    async def response(self, msg: bytes, msg_id: int) -> Buffer:
        raise NotImplementedError

    async def handle_message(self, msg: bytes, msg_id: int) -> bool:
        resp = await self.response(msg, msg_id)
        await self.rw.write_msg(resp, msg_id)
        return True


def wrap(handler: StreamHandlerFunction | type[BaseServerHandler]) -> StreamHandlerFunction:
    if isinstance(handler, type) and issubclass(handler, BaseServerHandler):
        return handler().handle
    if not isinstance(handler, type):
        return handler
    raise TypeError("Handler must be a callable or a subclass of BaseServerHandler")


async def _loop_create_server(factory: Callable[[], KXProtocol], host: str, port: int, executor: ThreadPoolExecutor) -> asyncio.Server:
    loop = asyncio.get_running_loop()
    server: asyncio.Server
    if PY312:
        # python 3.12 does not support keep_alive here
        server = await loop.create_server(factory, host, port, reuse_address=True, start_serving=False)
    else:
        server = await loop.create_server(factory, host, port, reuse_address=True, start_serving=False, keep_alive=True)

    # modify the server's _wakeup method to also shutdown the executor
    original_wakeup = server._wakeup  # type: ignore[attr-defined]  # noqa: SLF001

    def _wakeup(self: asyncio.Server) -> None:  # noqa: ARG001
        try:
            original_wakeup()
        finally:
            executor.shutdown(wait=False)

    server._wakeup = types.MethodType(_wakeup, server)  # type: ignore[attr-defined]  # noqa: SLF001
    return server


async def start_kx_n_server(
    handler: StreamHandlerFunction | type[BaseServerHandler],
    host: str,
    port: int,
    server_pair: KxPair,
    *,
    psk: Psk | None = None,
    limit: int = _DEFAULT_LIMIT,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
) -> asyncio.Server:
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    # a single executor per server, shared by all clients
    executor = ThreadPoolExecutor(max_workers=min(8, N_CPUS + 4))

    def factory() -> KXProtocol:
        machine = KX_N_ServerStateMachine(
            server_pair, psk=psk, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size
        )
        return KXProtocol(machine, loop, client_handler=wrap(handler), limit=limit, executor=executor)

    try:
        return await _loop_create_server(factory, host, port, executor)
    except:
        executor.shutdown(wait=False)
        raise


async def start_kx_kk_server(
    handler: StreamHandlerFunction | type[BaseServerHandler],
    host: str,
    port: int,
    server_pair: KxPair,
    client_public_key: KxPublicKey,
    *,
    limit: int = _DEFAULT_LIMIT,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
) -> asyncio.Server:
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=min(8, N_CPUS + 4))

    def factory() -> KXProtocol:
        machine = KX_KK_ServerStateMachine(
            server_pair, client_public_key, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size
        )
        return KXProtocol(machine, loop, client_handler=wrap(handler), limit=limit, executor=executor)

    try:
        return await _loop_create_server(factory, host, port, executor)
    except:
        executor.shutdown(wait=False)
        raise


async def start_kx_xx_server(
    handler: StreamHandlerFunction | type[BaseServerHandler],
    host: str,
    port: int,
    server_pair: KxPair,
    *,
    psk: Psk | None = None,
    limit: int = _DEFAULT_LIMIT,
    validate_client_key: ValidatePeerKeyFunc | None = None,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
) -> asyncio.Server:
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=min(8, N_CPUS + 4))

    def factory() -> KXProtocol:
        machine = KX_XX_ServerStateMachine(
            server_pair, psk=psk, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size
        )
        return KXProtocol(
            machine, loop, client_handler=wrap(handler), limit=limit, validate_peer_key=validate_client_key, executor=executor
        )

    try:
        return await _loop_create_server(factory, host, port, executor)
    except:
        executor.shutdown(wait=False)
        raise
