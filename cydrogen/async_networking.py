import asyncio
import contextlib
import contextvars
import inspect
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
from .logs import get_logger
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
    KxInitialCompleted,
    MachineProducedEvent,
    ReceivedEncryptedMessage,
)

logger = get_logger()
# Context Variables should be created at the top module level
msg_id_var: contextvars.ContextVar = contextvars.ContextVar("msgid")


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


class StreamReaderWriter:
    """
    StreamReaderWriter provides a simple interface for reading and writing messages.

    Attributes:
        peername: The name of the peer this reader/writer is connected to.
    """

    def __init__(self, protocol: "KXProtocol") -> None:
        self._protocol: KXProtocol = protocol
        self.peername: str = protocol.peername

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

    def get_extra_info(self, name: str, default: Any = None) -> Any:  # noqa: ANN401
        """
        Returns extra information about the stream.
        """
        return self._protocol.get_extra_info(name, default)

    @property
    def key_material_idx(self) -> int | None:
        """
        Returns the index of the current key material in use, or None if the key exchange has not completed yet.
        """
        return self._protocol.key_material_idx


class KXProtocol(asyncio.BufferedProtocol):
    def __init__(
        self,
        machine: BaseMachine,
        loop: asyncio.AbstractEventLoop,
        *,
        client_handler: StreamHandlerFunction | None = None,
        limit: int = _DEFAULT_LIMIT,
        executor: ThreadPoolExecutor,
        rekey_secs: int | None = 3600,
        rekey_grace_secs: int | None = 1800,
    ) -> None:
        self._loop = loop
        self._reading_paused = False
        self._writing_paused = False
        self._drain_futures: deque[asyncio.Future] = deque()
        self._connection_lost = False
        self._machine = machine
        self._closed_fut = loop.create_future()
        self._limit = int(limit)
        if self._limit <= 0:
            raise ValueError("limit must be a positive integer")
        self._client_handler: StreamHandlerFunction | None = client_handler
        self._kx_completed = loop.create_future()
        self._peer_task: asyncio.Task | None = None
        self._decrypt_task: asyncio.Task | None = None
        self._rekey_task: asyncio.Task | None = None
        self._remove_old_keys_task: asyncio.Task | None = None
        self._executor = executor
        self._rekey_secs = None if rekey_secs is None else int(rekey_secs)
        if self._rekey_secs is not None and self._rekey_secs <= 0:
            raise ValueError("rekey_secs must be a positive integer or None")
        self._rekey_grace_secs = None if rekey_grace_secs is None else int(rekey_grace_secs)
        if self._rekey_grace_secs is not None and self._rekey_grace_secs <= 0:
            raise ValueError("rekey_grace_secs must be a positive integer or None")
        self._received_encrypted_msgs: MsgQueue[memoryview] = MsgQueue()
        self._received_decrypted_msgs: MsgQueue[bytes] = MsgQueue()

        self.peername: str = ""

        self._transport: asyncio.Transport
        self.blogger = logger.bind(role="server" if client_handler else "client", color="async", cls="protocol")

    @property
    def key_material_idx(self) -> int | None:
        return self._machine.key_material_idx

    @property
    def received_size(self) -> int:
        """
        Returns the total size of received messages that have not been processed yet.
        """
        return self._received_decrypted_msgs.bytesize + self._received_encrypted_msgs.bytesize

    @property
    def machine(self) -> BaseMachine:
        return self._machine

    @property
    def kx_completed(self) -> asyncio.Future:
        return self._kx_completed

    def close(self) -> None:
        """
        Closes the underlying transport.
        """
        if not self.is_closing():
            self._transport.close()

    def is_closing(self) -> bool:
        """
        Returns whether the underlying transport is closing or closed
        """
        return self._transport.is_closing()

    async def wait_closed(self) -> None:
        """
        Waits until the underlying transport is fully closed (ie, connection lost with the peer)
        """
        with contextlib.suppress(EOFError):  # no need to raise if connection was closed without error
            await self._closed_fut

    async def get_next_msg(self) -> tuple[bytes, int]:
        payload, msg_id = await self._received_decrypted_msgs.get()
        self.maybe_resume_reading()
        return payload, msg_id

    def _handle_machine_events(self, events: list[MachineProducedEvent] | MachineProducedEvent | None) -> None:
        if events is None:
            return
        if isinstance(events, MachineProducedEvent):
            if self._handle_machine_event(events):
                self.maybe_pause_reading()
            return
        has_received_msg = False
        for event in events:
            if self._handle_machine_event(event):
                has_received_msg = True
        if has_received_msg:
            self.maybe_pause_reading()

    def _handle_machine_event(self, ev: MachineProducedEvent) -> bool:
        match ev:
            case KxInitialCompleted():
                if not self._kx_completed.done():
                    self._kx_completed.set_result(None)
                return False
            case ReceivedEncryptedMessage(emsg=emsg):
                self._received_encrypted_msgs.put_nowait(emsg)
                return True
            case _:
                return False

    def _send_to_machine(self, func: Callable[..., list[MachineProducedEvent] | MachineProducedEvent | None], *args: Any) -> None:  # noqa: ANN401
        """
        Triggers an action in the state machine and handles the resulting events.

        If the processing of events generate data to send, it is written to the transport.
        """
        try:
            evs = func(*args)
        except KeyExchangeException as ex:
            if self._kx_completed.done():
                # key exchange had already been completed, so this is a rekey error
                raise
            # initial key exchange failed, notify the caller waiting for key exchange
            self._kx_completed.set_exception(ex)
            return
        self._handle_machine_events(evs)
        data = self._machine.data_to_send()
        if data:
            self._transport.write(data)

    async def write_cancel_msg(self, target_msg_id: int) -> None:
        cancel_msg = bytearray(8)
        store64(cancel_msg, target_msg_id)
        emsg = self._machine.encrypt_message(cancel_msg, CANCEL_MESSAGE_ID)
        await self.drain()
        self._send_to_machine(self._machine.trigger_write_emessage, emsg)
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
        emsg = await self._loop.run_in_executor(self._executor, self._machine.encrypt_message, msg, msg_id)
        await self.drain()
        self._send_to_machine(self._machine.trigger_write_emessage, emsg)
        await self.drain()

    def write_eof(self) -> None:
        self._send_to_machine(self._machine.trigger_writer_eof)

    def can_write_eof(self) -> bool:
        return self._transport.can_write_eof()

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """
        Called by the asyncio framework when the network connection with the peer is established.
        """
        # called by asyncio when the network connection with the peer is established
        self.blogger.debug("connection_made")
        assert isinstance(transport, asyncio.Transport)
        self._transport = transport
        self.peername = str(transport.get_extra_info("peername", ""))
        self.blogger = self.blogger.bind(peer=self.peername)
        if self._client_handler is None:
            self.blogger.info("connected to server")
        else:
            self.blogger.info("new connection from client")
        # call _cb_key_exchange_completed when key exchange has been completed (failed or succeeded)
        self._kx_completed.add_done_callback(self._cb_key_exchange_completed)
        # start the key exchange process
        self._send_to_machine(self._machine.trigger_connection_made, self.peername)

    def _cb_key_exchange_completed(self, kx_completed: asyncio.Future) -> None:
        if kx_completed.cancelled():
            self.blogger.warning("Key exchange cancelled")
            self._transport.abort()
            return
        if kx_completed.exception() is not None:
            self.blogger.error("Key exchange failed", error=kx_completed.exception())
            self._transport.abort()
            return

        self.blogger.info("Key exchange success")
        # schedule the task that will handle the peer
        self._peer_task = self._loop.create_task(self.handle_peer())

    async def _decrypt_received_messages(self) -> None:
        """
        Decrypts received encrypted messages and pushes the decrypted messages to the queue of received decrypted messages.

        This is a long running coroutine that continuously reads encrypted messages from the queue of received encrypted messages,
        decrypts them, and pushes the decrypted messages to the queue of received decrypted messages.

        The function normally runs until the queue of received encrypted messages is closed (e.g. when the connection is lost or closed).
        But if an an exception occurs during decryption, the coroutine will raise a `DecryptException` and stop processing further messages.

        This coroutine is scheduled as a task by the Protocol when the key exchange is completed successfully.
        """
        self.blogger.info("starting to decrypt received messages")
        while True:
            try:
                incoming, _ = await self._received_encrypted_msgs.get()
            except Exception as ex:  # noqa: BLE001
                # this means that the queue of encrypted messages has been closed
                if isinstance(ex, EOFError):
                    self.blogger.info("decrypt received messages finished")
                else:
                    self.blogger.info("decrypt received messages finished", reason=ex)
                # consequently, we close the queue of decrypted messages (previously queued messages may still be consumed)
                self._received_decrypted_msgs.close(ex)
                return
            # decrypt the message and push the result downstream to _received_decrypted_msgs queue
            try:
                # execute decryption in a separate thread to avoid blocking the event loop
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
        except EOFError:
            self.blogger.info("Continuous decryption task finished")
            self._transport.close()
        except Exception:
            self.blogger.exception("Continuous decryption task failed")
            self._transport.abort()

    async def continuous_rekey(self) -> None:
        if self._rekey_secs is None:
            return
        self.blogger.info("starting continuous rekey task", period=self._rekey_secs)
        try:
            while True:
                await asyncio.sleep(self._rekey_secs)
                self._send_to_machine(self._machine.trigger_rekey)
        except asyncio.CancelledError:
            pass
        except Exception as ex:  # noqa: BLE001
            self.blogger.warning("Continuous rekey task failed", error=ex)
            self._transport.abort()

    async def continuous_remove_old_keys(self) -> None:
        if self._rekey_grace_secs is None:
            return
        self.blogger.info("starting continuous remove old keys task", period=self._rekey_grace_secs)
        try:
            while True:
                await asyncio.sleep(self._rekey_grace_secs)
                self._machine.remove_oldest_material()
        except asyncio.CancelledError:
            pass
        except Exception:
            self.blogger.exception("Continuous remove old keys task failed")
            self._transport.abort()

    async def handle_peer(self) -> None:
        self._decrypt_task = self._loop.create_task(self.continuous_decrypt())
        if self._rekey_secs is not None and self._client_handler is None:  # only trigger rekey if we are client side
            self._rekey_task = self._loop.create_task(self.continuous_rekey())
        if self._rekey_grace_secs is not None:  # both client and server side
            self._remove_old_keys_task = self._loop.create_task(self.continuous_remove_old_keys())
        if self._client_handler is not None:
            # server side
            try:
                await self._client_handler(StreamReaderWriter(self))
            except asyncio.CancelledError:
                self.blogger.info("Client handler cancelled")
            except Exception:
                self.blogger.exception("Client handler failed")
            finally:
                self._transport.close()
                self.blogger.info("Client disconnected")

    async def wait_for_key_exchange(self) -> None:
        await self._kx_completed

    def get_buffer(self, sizehint: int) -> memoryview:  # noqa: ARG002
        return self._machine.get_buffer()

    def buffer_updated(self, nbytes: int) -> None:
        self._send_to_machine(self._machine.receive_data, nbytes)

    def maybe_pause_reading(self) -> None:
        if self._reading_paused:
            return
        if self.received_size > 2 * self._limit:
            try:
                self.blogger.info("Pause reading", received_size=self.received_size, limit=self._limit)
                self._transport.pause_reading()
                self._reading_paused = True
            except NotImplementedError:
                pass

    def maybe_resume_reading(self) -> None:
        if not self._reading_paused:
            return
        if self.received_size <= self._limit:
            self.blogger.info("Resume reading", received_size=self.received_size, limit=self._limit)
            self._reading_paused = False
            self._transport.resume_reading()

    def connection_lost(self, exc: Exception | None) -> None:
        if isinstance(exc, ConnectionError):
            exc = EOF_EXCEPTION
        self.blogger.info("connection lost", reason=exc)
        try:
            self._send_to_machine(self._machine.trigger_connection_lost, exc)
        except Exception as ex:  # noqa: BLE001
            # we need to execute the rest of the function even if some rekey exception happens
            self.blogger.warning("error handling lost connection", error=ex)
        self._received_encrypted_msgs.close(self._machine.exception)  # unblock readers
        # make wait_closed() return
        if not self._closed_fut.done():
            self._closed_fut.set_result(None) if exc is None else self._closed_fut.set_exception(exc)

        self._connection_lost = True  # makes next calls to drain() raise EOFError

        if self._writing_paused:
            # some writers may be on pause, we need to unblock them
            for dfut in self._drain_futures:
                if not dfut.done():
                    dfut.set_result(None) if exc is None else dfut.set_exception(exc)

        if self._rekey_task is not None:
            self._rekey_task.cancel()
            self._rekey_task = None

        if self._remove_old_keys_task is not None:
            self._remove_old_keys_task.cancel()
            self._remove_old_keys_task = None

        if self._decrypt_task is not None and self._client_handler is None:
            # cancel the executor client-side

            # because we received connection_lost, it is not possible anymore to send encrypted messages
            # because self._client_handler is None, we know we are client side
            # because the queue of encrypted messages has been closed, we know that the decrypt task will finish soon
            # when _decrypt_task finishes, we also know we wont be decrypting any more message
            # so in that case we can shutdown the executor as no encryption/decryption will happen anymore
            self._decrypt_task.add_done_callback(self.shutdown_client_executor)

    def shutdown_client_executor(self, f: asyncio.Future) -> None:
        if not f.cancelled() and f.exception() is not None:
            self.blogger.info("decrypt task finished with error", error=f.exception())
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception as ex:  # noqa: BLE001
            self.blogger.warning("error shutting down client executor", error=ex)

    def eof_received(self) -> bool:
        self.blogger.info("eof received")
        try:
            self._send_to_machine(self._machine.trigger_reader_eof)
        except Exception as ex:  # noqa: BLE001
            self.blogger.warning("error handling eof received", error=ex)
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
        self.blogger.info("Pause writing")
        self._writing_paused = True

    def resume_writing(self) -> None:
        self.blogger.info("Resume writing")
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
    blogger = logger.bind(server_host=host, server_port=port, role="client", color="async")
    port = int(port)
    retry = int(retry)
    retry_wait = int(retry_wait)

    while True:
        try:
            blogger.info("Connecting...")
            transport, protocol = await loop.create_connection(protocol_factory, host, port)
            blogger.info("Connected")
            return transport, protocol
        except ConnectionRefusedError:
            if retry <= 0:
                raise
        retry -= 1
        blogger.warning("Connection failed")
        if retry_wait > 0:
            blogger.info("Retrying soon", wait=retry_wait)
            await asyncio.sleep(retry_wait)


async def _open_connection(
    host: str,
    port: int,
    machine_factory: Callable[[], BaseMachine],
    limit: int,
    retry: int,
    retry_wait: int,
    loop: asyncio.AbstractEventLoop,
    rekey_secs: int | None = 3600,
    rekey_grace_secs: int | None = 1800,
) -> StreamReaderWriter:
    # one executor per client
    executor = ThreadPoolExecutor(max_workers=min(8, N_CPUS + 4))

    def protocol_factory() -> KXProtocol:
        machine = machine_factory()
        return KXProtocol(machine, loop, limit=limit, executor=executor, rekey_secs=rekey_secs, rekey_grace_secs=rekey_grace_secs)

    transport: asyncio.Transport
    protocol: KXProtocol
    try:
        transport, protocol = await _connect(host, port, protocol_factory, retry, retry_wait)
    except:
        with contextlib.suppress(Exception):
            executor.shutdown(wait=False, cancel_futures=True)
        raise
    try:
        await protocol.wait_for_key_exchange()
    except KeyExchangeException:
        transport.abort()
        raise
    except Exception as ex:
        transport.abort()
        with contextlib.suppress(Exception):
            executor.shutdown(wait=False, cancel_futures=True)
        raise KeyExchangeException(f"Failed to complete key exchange with {host}:{port}") from ex
    return StreamReaderWriter(protocol)


async def open_kx_n_connection(
    host: str,
    port: int,
    server_public_key: bytes | str | Buffer | KxPublicKey,
    *,
    psk: Psk | bytes | str | None = None,
    limit: int = _DEFAULT_LIMIT,
    connect_retry: int = 3,
    connect_retry_wait: int = 30,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
    rekey_secs: int | None = 3600,
    rekey_grace_secs: int | None = 1800,
) -> StreamReaderWriter:
    """
    Open a connection to a server using the KX_N key exchange pattern.

    The server must support the KX_N pattern (sync or async).

    When the function returns, the network connection has been established and the key exchange has been completed.

    Args:
        host: The server hostname or IP address.
        port: The server port.
        server_public_key: The server's public key.
        psk: An optional pre-shared key.
        limit: The threshold in bytes for the total size of received messages that have not been processed yet.
        connect_retry: The number of times to retry connecting to the server if the connection fails.
        connect_retry_wait: The number of seconds to wait between connection retries.
        sent_msg_max_size: The maximum size in bytes of messages that can be sent.
        received_msg_max_size: The maximum size in bytes of messages that can be received.
        rekey_secs: The number of seconds between automatic rekeying. If None, automatic rekeying is disabled.
        rekey_grace_secs: The number of seconds to keep old keys after a rekey. If None, old keys are kept indefinitely.

    Returns:
        A StreamReaderWriter instance for reading and writing messages to the server.

    Raises:
        KeyExchangeException: If the key exchange fails.
        ConnectionError: If the connection to the server fails.
    """
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

    def machine_factory() -> BaseMachine:
        return KX_N_ClientStateMachine(
            server_public_key, psk=psk, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size
        )

    return await _open_connection(
        host,
        port,
        machine_factory,
        limit,
        connect_retry,
        connect_retry_wait,
        loop,
        rekey_secs=rekey_secs,
        rekey_grace_secs=rekey_grace_secs,
    )


async def open_kx_kk_connection(
    host: str,
    port: int,
    client_pair: bytes | str | Buffer | KxPair,
    server_public_key: bytes | str | Buffer | KxPublicKey,
    *,
    limit: int = _DEFAULT_LIMIT,
    connect_retry: int = 3,
    connect_retry_wait: int = 30,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
    rekey_secs: int | None = 3600,
    rekey_grace_secs: int | None = 1800,
) -> StreamReaderWriter:
    """
    Open a connection to a server using the KX_KK key exchange pattern.

    The server must support the KX_KK pattern (sync or async).

    When the function returns, the network connection has been established and the key exchange has been completed.

    Args:
        host: The server hostname or IP address.
        port: The server port.
        client_pair: The client's key pair.
        server_public_key: The server's public key.
        limit: The threshold in bytes for the total size of received messages that have not been processed yet.
        connect_retry: The number of times to retry connecting to the server if the connection fails.
        connect_retry_wait: The number of seconds to wait between connection retries.
        sent_msg_max_size: The maximum size in bytes of messages that can be sent.
        received_msg_max_size: The maximum size in bytes of messages that can be received.
        rekey_secs: The number of seconds between automatic rekeying. If None, automatic rekeying is disabled.
        rekey_grace_secs: The number of seconds to keep old keys after a rekey. If None, old keys are kept indefinitely.

    Returns:
        A StreamReaderWriter instance for reading and writing messages to the server.

    Raises:
        KeyExchangeException: If the key exchange fails.
        ConnectionError: If the connection to the server fails.
    """
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

    def machine_factory() -> BaseMachine:
        return KX_KK_ClientStateMachine(
            client_pair, server_public_key, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size
        )

    return await _open_connection(
        host,
        port,
        machine_factory,
        limit,
        connect_retry,
        connect_retry_wait,
        loop,
        rekey_secs=rekey_secs,
        rekey_grace_secs=rekey_grace_secs,
    )


async def open_kx_xx_connection(
    host: str,
    port: int,
    client_pair: bytes | str | Buffer | KxPair,
    *,
    psk: Psk | str | bytes | None = None,
    limit: int = _DEFAULT_LIMIT,
    validate_server_key: Callable[[KxPublicKey], None] | None = None,
    connect_retry: int = 3,
    connect_retry_wait: int = 30,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
    rekey_secs: int | None = 3600,
    rekey_grace_secs: int | None = 1800,
) -> StreamReaderWriter:
    """
    Open a connection to a server using the KX_XX key exchange pattern.

    The server must support the KX_XX pattern (sync or async).

    When the function returns, the network connection has been established and the key exchange has been completed.

    Args:
        host: The server hostname or IP address.
        port: The server port.
        client_pair: The client's key pair.
        server_public_key: The server's public key.
        psk: An optional pre-shared key.
        limit: The threshold in bytes for the total size of received messages that have not been processed yet.
        connect_retry: The number of times to retry connecting to the server if the connection fails.
        connect_retry_wait: The number of seconds to wait between connection retries.
        sent_msg_max_size: The maximum size in bytes of messages that can be sent.
        received_msg_max_size: The maximum size in bytes of messages that can be received.
        rekey_secs: The number of seconds between automatic rekeying. If None, automatic rekeying is disabled.
        rekey_grace_secs: The number of seconds to keep old keys after a rekey. If None, old keys are kept indefinitely.

    Returns:
        A StreamReaderWriter instance for reading and writing messages to the server.

    Raises:
        KeyExchangeException: If the key exchange fails.
        ConnectionError: If the connection to the server fails.
    """
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

    def machine_factory() -> BaseMachine:
        return KX_XX_ClientStateMachine(
            client_pair,
            psk=psk,
            sent_msg_max_size=sent_msg_max_size,
            received_msg_max_size=received_msg_max_size,
            validate_peer_key=validate_server_key,
        )

    return await _open_connection(
        host,
        port,
        machine_factory,
        limit,
        connect_retry,
        connect_retry_wait,
        loop,
        rekey_secs=rekey_secs,
        rekey_grace_secs=rekey_grace_secs,
    )


class BaseAsyncRequestResponseClient(ABC):
    """
    BaseAsyncRequestResponseClient is an abstract base class for asynchronous request/response clients.

    Subclasses must implement the `connect` method to establish the connection and set up the StreamReaderWriter.

    Such clients support the async context manager protocol and should be used with `async with` statements.
    """

    def __init__(self, request_timeout_secs: int | None = 30) -> None:
        """
        Initialize the BaseAsyncRequestResponseClient.

        Args:
            request_timeout_secs: The default timeout in seconds for requests. If None, requests will not timeout.
        """
        self._counter = Counter()
        self._pending_requests: dict[int, asyncio.Future[bytes]] = {}
        self._request_timeout_secs: int | None = request_timeout_secs

        self._rw: StreamReaderWriter | None = None
        self._read_task: asyncio.Task | None = None
        self.blogger = logger.bind(role="client", color="async", cls="request_response")

    def _start_read_responses(self) -> None:
        # must be called by connect() after setting up self._rw
        if self._rw is None:
            raise ClientClosedError
        self._counter = Counter()
        self._pending_requests.clear()
        read_task = asyncio.create_task(self._read_responses())

        def on_read_task_done(_: asyncio.Task) -> None:
            self._rw = None

        # when the read task is done, we set self._rw to None to indicate the client is closed now
        read_task.add_done_callback(on_read_task_done)
        self._read_task = read_task

    @abstractmethod
    async def connect(self) -> None:
        """
        Establish the connection and set up the StreamReaderWriter.

        Subclasses must implement this method.
        """
        raise NotImplementedError

    @property
    def key_material_idx(self) -> int | None:
        """
        Returns the index of the current key material in use, or None if the key exchange has not completed yet.
        """
        if self._rw is None:
            return None
        return self._rw.key_material_idx

    def is_closing(self) -> bool:
        """
        Returns whether the client is closing or closed.
        """
        return self._rw is None or self._rw.is_closing()

    def close(self) -> None:
        self._close_with_exception()

    def _close_with_exception(self, exc: Exception | None = None) -> None:
        """
        Close the client and the underlying connection.

        This method is idempotent.
        """
        if self.is_closing():
            self.blogger.debug("Client already closed")
        else:
            # close the StreamReaderWriter, which in turn closes the transport
            assert self._rw is not None
            self._rw.close()
        # abort the pending requests
        for fut in self._pending_requests.values():
            if not fut.done():
                if exc:
                    fut.set_exception(exc)
                else:
                    fut.cancel()
        self._pending_requests.clear()

    async def wait_closed(self) -> None:
        """
        Wait until the client is fully closed.

        If close() has not been called yet, this method will call it.
        """
        self.close()
        read_task = self._read_task
        # when the transport is closed, the read task will terminate at some point
        if read_task is None or read_task.done():
            return
        try:
            await read_task
            self.blogger.info("read responses task finished")
        except Exception as e:  # noqa: BLE001
            self.blogger.info("read responses task finished", error=e)
        finally:
            self._read_task = None

    async def __aenter__(self) -> Self:
        """
        Enter the async context manager, establishing the connection.
        """
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:  # noqa: ANN001
        """
        Exit the async context manager, closing the client.
        """
        self._close_with_exception(exc_value)
        await self.wait_closed()
        # return None (to propagate exception, if any)

    async def request(self, msg: Buffer, *, timeout_secs: int | None = None) -> bytes:
        """
        Send a request message and wait for the response.

        In addition to the exceptions listed below, this method may also raise various exceptions
        related to the underlying connection, such as ConnectionError, KeyExchangeException, DecryptException, etc.

        Args:
            msg: The request message to send, as a bytes-like object.
            timeout_secs: The timeout in seconds for this request. If None, no timeout is applied.

        Returns:
            The response message as bytes.

        Raises:
            ClientClosedError: If the client is closed.
            TimeoutError: If the request times out.
        """
        if self._rw is None or self._read_task is None or self._read_task.done() or self._rw.is_closing():
            raise ClientClosedError
        timeout_secs = timeout_secs if timeout_secs is not None else self._request_timeout_secs
        # ensure we get a unique message ID for this request
        msg_id: int = self._counter()
        # create and register the future that will hold the response to this request
        fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        # when the response is received in read_task, we will set the result of this future
        self._pending_requests[msg_id] = fut
        # ensure we clean up the pending request when done
        fut.add_done_callback(lambda _: self._pending_requests.pop(msg_id, None))
        try:
            await self._rw.write_msg(msg, msg_id=msg_id)
        except asyncio.CancelledError:
            # The user cancelled the request before it was sent.
            fut.cancel()
            raise
        except InvalidTransitionError as ex:
            # Invalid transition means the client is already closed or closing.
            fut.cancel()
            raise ClientClosedError from ex
        except Exception as ex:
            # Some other exception occurred while sending the request.
            fut.cancel()
            # Closing the client formally to unblock any other pending requests.
            self.blogger.info("Error sending request, closing client", error=ex)
            self._close_with_exception(ex)  # closing the client to make other pending requests fail.
            raise
        # if we are here, the request was sent successfully
        # now we wait for the response or timeout/cancellation
        try:
            if timeout_secs is None or timeout_secs <= 0:
                return await fut
            async with asyncio.timeout(timeout_secs):
                return await fut
        except asyncio.CancelledError:
            # The user cancelled the request before the server responded.
            # Attempt to cancel the request on the server side.
            # we don't close the client here, as other requests may still be valid
            await self._cancel_request(msg_id)
            raise
        except TimeoutError:
            # The server did not respond in time.
            # Attempt to cancel the request on the server side.
            # we don't close the client here, as other requests may still be valid
            await self._cancel_request(msg_id)
            raise
        except Exception as ex:
            # if we can an exception while awaiting the future, that means _close_with_exception was called
            # and cancelled all pending requests. So we know the client is closed or closing.
            # No need to call _close_with_exception again.
            self.blogger.debug("Error waiting for response", msg_id=msg_id, error=ex)
            raise

    async def _cancel_request(self, msg_id: int) -> None:
        # send a short cancel message to the server
        # msg_id = CANCEL_MESSAGE_ID is reserved for cancel requests
        if self._rw is None or self._rw.is_closing():
            return
        try:
            await self._rw.write_cancel_msg(msg_id)
            self.blogger.debug("Request cancelled", msg_id=msg_id)
        except Exception as ex:  # noqa: BLE001
            self.blogger.debug("Failed to cancel request", msg_id=msg_id, error=ex)

    async def _read_responses(self) -> None:
        """
        Continuously read responses from the server and dispatch them to the appropriate pending request futures.
        """
        # this is a Task, let's avoid to raise exceptions that would be logged as unhandled

        # bind the StreamReaderWriter to a local variable to ensure it is not changed during the read loop
        rw = self._rw
        if rw is None:
            self.blogger.warning("StreamReaderWriter is None in _read_responses, should not happen")
            return
        try:
            # this while loop will be interrupted when the connection is closed, causing get_next_msg to raise
            # EOFError or another exception
            while True:
                await self._read_response(rw)
        except Exception as ex:  # noqa: BLE001
            self._close_with_exception(ex)

    async def _read_response(self, rw: StreamReaderWriter) -> None:
        """
        Read a single response from the server and dispatch it to the appropriate pending request future.
        """
        msg, msg_id = await rw.get_next_msg()  # may raise
        fut = self._pending_requests.get(msg_id)
        if fut is None:
            # if we are here, it means we received a response with an unknown message ID
            # possibly because the request timed out and was removed from pending requests
            # or because the client has been closed and all pending requests were removed
            # or because the server sent an unsolicited response
            if self._rw is not None and not self._rw.is_closing():
                # client is not closed, we can handle the unexpected response
                await self.handle_unexpected_response(msg, msg_id)
            return
        if fut.done():
            return
        fut.set_result(msg)

    async def handle_unexpected_response(self, msg: bytes, msg_id: int) -> None:
        """
        Handle an unexpected response with an unknown message ID.

        Subclasses can override this method to provide custom handling for unexpected responses.

        By default, this method logs a warning and ignores the unexpected response.

        Args:
            msg: The unexpected response message as bytes.
            msg_id: The message ID of the unexpected response.
        """
        self.blogger.warning("Unexpected response received", nb_bytes=len(msg), msg_id=msg_id)


class KX_N_AsyncRequestResponseClient(BaseAsyncRequestResponseClient):
    """
    KX_N_AsyncRequestResponseClient is an asynchronous request/response client that uses the KX_N key exchange pattern.

    So that requests and responses are properly matched, the server must reuse the same message ID for the response as
    the one used in the request.

    The server must support the KX_N pattern (sync or async).
    """

    def __init__(
        self,
        host: str,
        port: int,
        server_public_key: bytes | str | Buffer | KxPublicKey,
        *,
        psk: Psk | bytes | str | None = None,
        limit: int = _DEFAULT_LIMIT,
        request_timeout_secs: int | None = 30,
        connect_retry: int = 3,
        connect_retry_wait: int = 30,
        sent_msg_max_size: int = 2**20,
        received_msg_max_size: int = 2**20,
        rekey_secs: int | None = 3600,
        rekey_grace_secs: int | None = 1800,
    ) -> None:
        """
        Initialize the KX_N_AsyncRequestResponseClient.

        Args:
            host: The server hostname or IP address.
            port: The server port.
            server_public_key: The server's public key.
            psk: An optional pre-shared key.
            limit: The threshold in bytes for the total size of received messages that have not been processed yet.
            request_timeout_secs: The default timeout in seconds for requests. If None, requests will not timeout.
            connect_retry: The number of times to retry connecting to the server if the connection fails.
            connect_retry_wait: The number of seconds to wait between connection retries.
            sent_msg_max_size: The maximum size in bytes of messages that can be sent.
            received_msg_max_size: The maximum size in bytes of messages that can be received.
            rekey_secs: The number of seconds between automatic rekeying. If None, automatic rekeying is disabled.
            rekey_grace_secs: The number of seconds to keep old keys after a rekey. If None, old keys are kept indefinitely.
        """
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
        self._rekey_secs = rekey_secs
        self._rekey_grace_secs = rekey_grace_secs
        self.blogger = self.blogger.bind(kx="KX_N", server_host=host, server_port=port)

    async def connect(self) -> None:
        """
        Establish the connection using the KX_N key exchange pattern.

        Raises:
            RuntimeError: If the client is already connected.
        """
        if self._rw is not None:
            raise RuntimeError("Client is already connected")
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
            rekey_secs=self._rekey_secs,
            rekey_grace_secs=self._rekey_grace_secs,
        )
        self._start_read_responses()


class KX_KK_AsyncRequestResponseClient(BaseAsyncRequestResponseClient):
    def __init__(
        self,
        host: str,
        port: int,
        client_pair: bytes | str | Buffer | KxPair,
        server_public_key: bytes | str | Buffer | KxPublicKey,
        *,
        limit: int = _DEFAULT_LIMIT,
        request_timeout_secs: int | None = 30,
        connect_retry: int = 3,
        connect_retry_wait: int = 30,
        sent_msg_max_size: int = 2**20,
        received_msg_max_size: int = 2**20,
        rekey_secs: int | None = 3600,
        rekey_grace_secs: int | None = 1800,
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
        self._rekey_secs = rekey_secs
        self._rekey_grace_secs = rekey_grace_secs
        self.blogger = self.blogger.bind(kx="KX_KK", server_host=host, server_port=port)

    async def connect(self) -> None:
        """
        Establish the connection using the KX_KK key exchange pattern.

        Raises:
            RuntimeError: If the client is already connected.
        """
        if self._rw is not None:
            raise RuntimeError("Client is already connected")
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
            rekey_secs=self._rekey_secs,
            rekey_grace_secs=self._rekey_grace_secs,
        )
        self._start_read_responses()


class KX_XX_AsyncRequestResponseClient(BaseAsyncRequestResponseClient):
    def __init__(
        self,
        host: str,
        port: int,
        client_pair: bytes | str | Buffer | KxPair,
        *,
        psk: Psk | bytes | str | None = None,
        limit: int = _DEFAULT_LIMIT,
        validate_server_key: Callable[[KxPublicKey], None] | None = None,
        request_timeout_secs: int | None = 30,
        connect_retry: int = 3,
        connect_retry_wait: int = 30,
        sent_msg_max_size: int = 2**20,
        received_msg_max_size: int = 2**20,
        rekey_secs: int | None = 3600,
        rekey_grace_secs: int | None = 1800,
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
        self._rekey_secs = rekey_secs
        self._rekey_grace_secs = rekey_grace_secs
        self.blogger = self.blogger.bind(kx="KX_XX", server_host=host, server_port=port)

    async def connect(self) -> None:
        """
        Establish the connection using the KX_XX key exchange pattern.

        Raises:
            RuntimeError: If the client is already connected.
        """
        if self._rw is not None:
            raise RuntimeError("Client is already connected")
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
            rekey_secs=self._rekey_secs,
            rekey_grace_secs=self._rekey_grace_secs,
        )
        self._start_read_responses()


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


class Stopping(Exception):
    pass


class BaseServerHandler(ABC):
    def __init__(self) -> None:
        self._tasks = ServerPendingProcessingTasks()
        self.stopping = asyncio.Event()
        self.rw: StreamReaderWriter
        self.blogger = logger.bind(role="server", color="async", cls="handler")

    async def get_msg(self) -> tuple[bytes, int]:
        """
        Get the next message from the stream reader-writer, but raise Stopping if self.stopping is set.
        """
        # wait for either a new message or for stopping
        get_msg_task = asyncio.create_task(self.rw.get_next_msg())
        stop_task = asyncio.create_task(self.stopping.wait())
        done, pending = await asyncio.wait({get_msg_task, stop_task}, return_when=asyncio.FIRST_COMPLETED)
        # we need to cancel the pending task
        for t in pending:
            t.cancel()
            # avoid "Task was destroyed but it is pending!" warnings
            with contextlib.suppress(asyncio.CancelledError):
                await t
        if stop_task in done:
            raise Stopping
        return get_msg_task.result()

    async def handle(self, rw: StreamReaderWriter) -> None:
        """
        Handle incoming messages from the given StreamReaderWriter representing a client connection.

        Note that this method is a StreamHandlerFunction and is intended to be called by the server framework.

        handle() will continuously read messages from the StreamReaderWriter and process them. It returns when
        the connection is closed, when an exception occurs, or when stopping is requested (when handle_message
        returns False or raises an exception).

        Args:
            rw: The StreamReaderWriter to handle.
        """
        # note: self.handle is a StreamHandlerFunction
        self.rw = rw
        self.blogger = self.blogger.bind(peer=rw.peername)
        try:
            while True:
                # wait for either a new message or for stopping
                msg, msg_id = await self.get_msg()  # may raise Stopping or EOFError or other exceptions
                # once we got a new message, process it in an independent task
                self._process_msg(msg, msg_id)  # does not raise
        except Stopping:
            self.blogger.debug("Stopping handler as requested")
        except EOFError:
            pass
        except Exception as ex:  # noqa: BLE001
            self.blogger.info("Reading next message", error=ex)
        finally:
            # cancel the pending message processing tasks
            if (nb := self._tasks.cancel_all()) > 0:  # cancel any pending tasks
                self.blogger.info("Cancelled pending tasks", nb_tasks=nb)
            # close the stream reader-writer
            rw.close()
            await rw.wait_closed()

    def _process_msg(self, msg: bytes, msg_id: int) -> None:
        """
        Process an incoming message by scheduling a new task to handle it.
        """
        if msg_id == CANCEL_MESSAGE_ID:
            self._cancel(msg)
            return
        if self.stopping.is_set():
            # not scheduling new tasks when we are stopping
            return
        # schedule a new task to handle the message
        incoming_msg_task: asyncio.Task = asyncio.create_task(self._handle_message(msg, msg_id))
        # register the task so that it does not get lost
        self._tasks.register(msg_id, incoming_msg_task)

        def cb(t: asyncio.Task) -> None:
            self._tasks.done(msg_id, t)

        # when the task is done, unregister it
        incoming_msg_task.add_done_callback(cb)

    def _cancel(self, msg: bytes) -> None:
        """
        Handle a cancel message by cancelling the corresponding processing task(s).
        """
        try:
            msg_id = load64(msg)
            self.blogger.debug("Cancelling request", msg_id=msg_id)
            self._tasks.cancel(msg_id)
        except ValueError:
            # malformed cancel message
            logger.warning("Received malformed cancel message")

    async def _handle_message(self, msg: bytes, msg_id: int) -> None:
        """
        Internal method to handle an incoming message.

        This method is executed in its own Task for each incoming message.
        """
        # _handle_message is executed in its own Task for each incoming message,
        # so we can use a context variable to store the message ID
        msg_id_var.set(msg_id)
        try:
            if not await self.handle_message(msg, msg_id):
                self.stopping.set()
        except asyncio.CancelledError:
            pass
        except MessageTooBigException:
            # if the handler tries to write a response that is too big, we stop the handler
            # TODO: instead, send the client an error message
            self.stopping.set()
            self.blogger.error("Server response is too big", msg_id=msg_id)  # noqa: TRY400
        except InvalidTransitionError as ex:
            # this typically happens when the message handler tries to write a response, but the rw is already closed
            self.stopping.set()
            if ex.writer_closed():
                # don't want to spam the logs with the full stack traces if the client closed the connection
                self.blogger.warning("Cannot write response: connection closed", msg_id=msg_id)
            else:
                self.blogger.exception("Error handling message", msg_id=msg_id)
        except Exception as ex:  # noqa: BLE001
            # stop the handler on any other exception
            # TODO: instead, send the client an error message
            self.stopping.set()
            self.blogger.warning("Error handling message", msg_id=msg_id, error=ex)

    @abstractmethod
    async def handle_message(self, msg: bytes, msg_id: int) -> bool:
        """
        Handle an incoming message from the client.

        Subclasses must implement this method to process incoming messages. The method should return True to continue handling messages,
        or False to stop the handler. If any exception is raised, the handler will also be stopped.

        When the client is an request/response client, the response must use the same message ID as the incoming message.

        Args:
            msg: the incoming message bytes.
            msg_id: the message ID of the incoming message.

        Returns:
            bool: True to continue handling messages, False to stop the handler.
        """
        raise NotImplementedError

    async def write(self, msg: Buffer, msg_id: int | None = None) -> None:
        """
        Write a message to the stream writer, using the provided message ID or the one from the context variable.

        Subclasses can use this method to send responses to clients, when implementing the `handle_message` method.
        """
        if self.stopping.is_set():
            # do not write if we are stopping
            self.blogger.debug("Not writing message as handler is stopping", msg_id=msg_id)
            return
        await self.rw.write_msg(msg, msg_id if msg_id is not None else msg_id_var.get())


class RequestResponseHandler(BaseServerHandler, ABC):
    """
    A base class for request-response server handlers.

    Subclasses must implement the `response` method to process incoming messages and generate responses.
    """

    @abstractmethod
    async def response(self, msg: bytes, msg_id: int) -> Buffer:
        raise NotImplementedError

    async def handle_message(self, msg: bytes, msg_id: int) -> bool:
        resp = await self.response(msg, msg_id)
        await self.rw.write_msg(resp, msg_id)
        return True


def wrap_handler(handler: StreamHandlerFunction | type[BaseServerHandler]) -> StreamHandlerFunction:
    if isinstance(handler, type):
        if issubclass(handler, BaseServerHandler):
            return handler().handle
        raise TypeError("Handler class must be a subclass of BaseServerHandler")
    if callable(handler):
        if not inspect.iscoroutinefunction(handler):
            raise TypeError("Handler function must be an async function")
        # check the handler has the proper signature
        sig = inspect.signature(handler)
        params = sig.parameters
        if len(params) != 1:
            raise TypeError("Handler function must accept exactly one argument")
        param = next(iter(params.values()))
        if param.annotation is not inspect.Parameter.empty and not issubclass(param.annotation, StreamReaderWriter):
            raise TypeError("Handler function argument must be of type StreamReaderWriter")
        if sig.return_annotation is not None and sig.return_annotation is not inspect.Signature.empty:
            raise TypeError("Handler function must return nothing")
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
            with contextlib.suppress(Exception):
                executor.shutdown(wait=False, cancel_futures=True)

    server._wakeup = types.MethodType(_wakeup, server)  # type: ignore[attr-defined]  # noqa: SLF001
    return server


async def start_kx_n_server(
    handler: StreamHandlerFunction | type[BaseServerHandler],
    host: str,
    port: int,
    server_pair: bytes | str | Buffer | KxPair,
    *,
    psk: Psk | str | bytes | None = None,
    limit: int = _DEFAULT_LIMIT,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
    rekey_grace_secs: int | None = 1800,
) -> asyncio.Server:
    """
    Start an async TCP server that uses the KX_N key exchange pattern.

    The server supports KX_N clients only (either sync or async).

    When the handler is a StreamHandlerFunction, the function defines how to handle each client connection. The function will
    be called for each client connection with a StreamReaderWriter object as argument. Through this object, the handler can
    read and write messages to the client.

    When the handler is a subclass of BaseServerHandler, an instance of the class will be created for each client connection.
    The class must implement the handle_message method to process incoming messages from the client. Each incoming message will
    be handled in its own asyncio Task, allowing concurrent processing of multiple messages from the same client.

    When this function returns, the server is created but not yet accepting connections. You need to call `server.start_serving()`
    or `server.serve_forever()` to start accepting connections.

    Args:
        handler: a StreamHandlerFunction or a subclass of BaseServerHandler to handle client connections.
        host: the host to bind the server to.
        port: the port to bind the server to.
        server_pair: the server's key exchange pair.
        psk: an optional pre-shared key for the key exchange. The same PSK must be used by the clients.
        limit: the maximum number of bytes to store in the receive buffer before pausing reading.
        sent_msg_max_size: the maximum bytes size of messages that can be sent to clients.
        received_msg_max_size: the maximum bytes size of messages that can be received from clients.
        rekey_grace_secs: the grace period in seconds before old keys are removed after a rekey.

    Returns:
        An asyncio.Server object representing the created server.

    Raises:
        OSError: if the server could not be started (e.g., address already in use).
        TypeError: if the handler is not a valid.
    """
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    # a single executor per server, shared by all clients
    executor = ThreadPoolExecutor(max_workers=min(8, N_CPUS + 4))

    def factory() -> KXProtocol:
        machine = KX_N_ServerStateMachine(
            server_pair, psk=psk, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size
        )
        return KXProtocol(
            machine, loop, client_handler=wrap_handler(handler), limit=limit, executor=executor, rekey_grace_secs=rekey_grace_secs
        )

    try:
        return await _loop_create_server(factory, host, port, executor)
    except:
        with contextlib.suppress(Exception):
            executor.shutdown(wait=False, cancel_futures=True)
        raise


async def start_kx_kk_server(
    handler: StreamHandlerFunction | type[BaseServerHandler],
    host: str,
    port: int,
    server_pair: bytes | str | Buffer | KxPair,
    client_public_key: KxPublicKey,
    *,
    limit: int = _DEFAULT_LIMIT,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
    rekey_grace_secs: int | None = 1800,
) -> asyncio.Server:
    """
    Start an async TCP server that uses the KX_KK key exchange pattern.

    The server supports KX_KK clients only (either sync or async).

    When the handler is a StreamHandlerFunction, the function defines how to handle each client connection. The function will
    be called for each client connection with a StreamReaderWriter object as argument. Through this object, the handler can
    read and write messages to the client.

    When the handler is a subclass of BaseServerHandler, an instance of the class will be created for each client connection.
    The class must implement the handle_message method to process incoming messages from the client. Each incoming message will
    be handled in its own asyncio Task, allowing concurrent processing of multiple messages from the same client.

    When this function returns, the server is created but not yet accepting connections. You need to call `server.start_serving()`
    or `server.serve_forever()` to start accepting connections.

    Args:
        handler: a StreamHandlerFunction or a subclass of BaseServerHandler to handle client connections.
        host: the host to bind the server to.
        port: the port to bind the server to.
        server_pair: the server's key exchange pair.
        client_public_key: the client's public key.
        limit: the maximum number of bytes to store in the receive buffer before pausing reading.
        sent_msg_max_size: the maximum bytes size of messages that can be sent to clients.
        received_msg_max_size: the maximum bytes size of messages that can be received from clients.
        rekey_grace_secs: the grace period in seconds before old keys are removed after a rekey.

    Returns:
        An asyncio.Server object representing the created server.

    Raises:
        OSError: if the server could not be started (e.g., address already in use).
        TypeError: if the handler is not a valid.
    """
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=min(8, N_CPUS + 4))

    def factory() -> KXProtocol:
        machine = KX_KK_ServerStateMachine(
            server_pair, client_public_key, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size
        )
        return KXProtocol(
            machine, loop, client_handler=wrap_handler(handler), limit=limit, executor=executor, rekey_grace_secs=rekey_grace_secs
        )

    try:
        return await _loop_create_server(factory, host, port, executor)
    except:
        with contextlib.suppress(Exception):
            executor.shutdown(wait=False, cancel_futures=True)
        raise


async def start_kx_xx_server(
    handler: StreamHandlerFunction | type[BaseServerHandler],
    host: str,
    port: int,
    server_pair: bytes | str | Buffer | KxPair,
    *,
    psk: Psk | str | bytes | None = None,
    limit: int = _DEFAULT_LIMIT,
    validate_client_key: Callable[[KxPublicKey], None] | None = None,
    sent_msg_max_size: int = 2**20,
    received_msg_max_size: int = 2**20,
    rekey_grace_secs: int | None = 1800,
) -> asyncio.Server:
    """
    Start an async TCP server that uses the KX_XX key exchange pattern.

    The server supports KX_XX clients only (either sync or async).

    When the handler is a StreamHandlerFunction, the function defines how to handle each client connection. The function will
    be called for each client connection with a StreamReaderWriter object as argument. Through this object, the handler can
    read and write messages to the client.

    When the handler is a subclass of BaseServerHandler, an instance of the class will be created for each client connection.
    The class must implement the handle_message method to process incoming messages from the client. Each incoming message will
    be handled in its own asyncio Task, allowing concurrent processing of multiple messages from the same client.

    If a validate_client_key function is provided, it will be called during the key exchange to validate the client's public key.
    Raise an exception in this function to reject the client connection.

    When this function returns, the server is created but not yet accepting connections. You need to call `server.start_serving()`
    or `server.serve_forever()` to start accepting connections.

    Args:
        handler: a StreamHandlerFunction or a subclass of BaseServerHandler to handle client connections.
        host: the host to bind the server to.
        port: the port to bind the server to.
        server_pair: the server's key exchange pair.
        psk: an optional pre-shared key for the key exchange. The same PSK must be used by the clients.
        limit: the maximum number of bytes to store in the receive buffer before pausing reading.
        validate_client_key: an optional function to validate the client's public key during the key exchange.
        sent_msg_max_size: the maximum bytes size of messages that can be sent to clients.
        received_msg_max_size: the maximum bytes size of messages that can be received from clients.
        rekey_grace_secs: the grace period in seconds before old keys are removed after a rekey.

    Returns:
        An asyncio.Server object representing the created server.

    Raises:
        OSError: if the server could not be started (e.g., address already in use).
        TypeError: if the handler is not a valid.
    """
    loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=min(8, N_CPUS + 4))

    def factory() -> KXProtocol:
        machine = KX_XX_ServerStateMachine(
            server_pair,
            psk=psk,
            sent_msg_max_size=sent_msg_max_size,
            received_msg_max_size=received_msg_max_size,
            validate_peer_key=validate_client_key,
        )
        return KXProtocol(
            machine, loop, client_handler=wrap_handler(handler), limit=limit, executor=executor, rekey_grace_secs=rekey_grace_secs
        )

    try:
        return await _loop_create_server(factory, host, port, executor)
    except:
        with contextlib.suppress(Exception):
            executor.shutdown(wait=False, cancel_futures=True)
        raise
