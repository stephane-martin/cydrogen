import asyncio
import contextvars
import logging
import sys
from abc import ABC, abstractmethod
from collections import deque
from collections.abc import Awaitable, Buffer, Callable
from enum import StrEnum
from typing import Any, Self

from ._decls import NOGIL_THRESHOLD_BYTES
from ._exceptions import DecryptException, KeyExchangeException
from ._kx_n import (
    KX_KK_PACKET1BYTES,
    KX_KK_PACKET2BYTES,
    KX_N_PACKET1BYTES,
    KX_XX_PACKET1BYTES,
    KX_XX_PACKET2BYTES,
    KX_XX_PACKET3BYTES,
    KxPair,
    KxPublicKey,
    KxXxClientState,
    KxXxServerState,
    Psk,
    SessionPair,
    client_init_kx_n,
)
from ._networking import BytearrayBuilder, MsgQueue, ReadBuffers
from ._secretbox import EncryptedMessage, SecretBox, encrypted_message_header
from ._utils import Counter, load64, store64

logger = logging.getLogger("cydrogen")

OK_MESSAGE: bytes = b"OK"
CANCEL_MESSAGE_ID: int = 0
_DEFAULT_LIMIT: int = 2**16  # 64 KiB


class MState(StrEnum):
    INITIAL = "initial"
    CONNECTED = "connected"
    READER_CLOSED = "reader_closed"
    WRITER_CLOSED = "writer_closed"
    READER_WRITER_CLOSED = "reader_writer_closed"
    WAITING_FOR_PACKET1 = "waiting_for_packet1"
    WAITING_FOR_PACKET2 = "waiting_for_packet2"
    WAITING_FOR_PACKET3 = "waiting_for_packet3"
    WAITING_FOR_SERVER_ACK = "waiting_for_server_ack"

    def kx_is_pending(self) -> bool:
        return self in (
            MState.WAITING_FOR_PACKET1,
            MState.WAITING_FOR_PACKET2,
            MState.WAITING_FOR_PACKET3,
            MState.WAITING_FOR_SERVER_ACK,
        )


class TransitionEvent(StrEnum):
    CONNECTION_LOST = "connection_lost"
    READER_EOF = "reader_eof"
    WRITER_EOF = "writer_eof"
    WRITE_EMESSAGE = "write_emessage"
    RECEIVE_DATA = "receive_data"
    DATA_TO_SEND = "data_to_send"


type TransitionDestination = tuple[MState, Callable]
type TransitionsByOrigState = dict[MState, TransitionDestination]
type TransitionsByEvent = dict[TransitionEvent, TransitionsByOrigState]

type StreamHandlerFunction = Callable[["StreamReaderWriter"], Awaitable[None]]
type ValidatePeerKeyFunc = Callable[[KxPublicKey], Awaitable[None]]

ALL_STATES: set[MState] = set(MState)


class Transitions:
    def __init__(self) -> None:
        self._t: TransitionsByEvent = {}

    def add(self, event: TransitionEvent, orig_state: MState, dest_state: MState, callback: Callable) -> None:
        if event not in self._t:
            self._t[event] = {}
        if orig_state not in self._t[event]:
            self._t[event][orig_state] = (dest_state, callback)
        else:
            raise RuntimeError(f"Transition {orig_state} => {event} already exists")

    def add_many(self, transitions: TransitionsByEvent) -> None:
        for event, orig_states in transitions.items():
            if event not in self._t:
                self._t[event] = {}
            for orig_state, (dest_state, callback) in orig_states.items():
                if orig_state not in self._t[event]:
                    self._t[event][orig_state] = (dest_state, callback)
                else:
                    raise RuntimeError(f"Transition {orig_state} => {event} already exists")

    def get(self, event: TransitionEvent, orig_state: MState) -> TransitionDestination:
        try:
            return self._t[event][orig_state]
        except KeyError as ex:
            raise RuntimeError(f"Invalid transition for {event} from {orig_state}") from ex

    def keep_only_valid_states(self, valid_states: frozenset[MState]) -> None:
        # remove all transitions that are referencing states not in valid_states
        to_remove: TransitionsByEvent = {}

        event: TransitionEvent
        dest: TransitionDestination
        state_transitions: TransitionsByOrigState

        for event, state_transitions in self._t.items():
            to_remove[event] = {}
            for orig_state, dest in state_transitions.items():
                if orig_state not in valid_states or dest[0] not in valid_states:
                    to_remove[event][orig_state] = dest

        for event, state_transitions in to_remove.items():
            for orig_state, dest in state_transitions.items():
                logger.debug("Removing: %s => %s => %s", orig_state, event, dest[0])
                del self._t[event][orig_state]
            if not self._t[event]:
                logger.debug("Removing event: %s", event)
                del self._t[event]


class BaseMachine:
    # INITIAL                   => connection_lost  => READER_WRITER_CLOSED
    # CONNECTED                 => connection_lost  => READER_WRITER_CLOSED
    # READER_CLOSED             => connection_lost  => READER_WRITER_CLOSED
    # WRITER_CLOSED             => connection_lost  => READER_WRITER_CLOSED
    # READER_WRITER_CLOSED      => connection_lost  => READER_WRITER_CLOSED
    # WAITING_FOR_PACKET1       => connection_lost  => READER_WRITER_CLOSED
    # WAITING_FOR_PACKET2       => connection_lost  => READER_WRITER_CLOSED
    # WAITING_FOR_PACKET3       => connection_lost  => READER_WRITER_CLOSED
    # WAITING_FOR_SERVER_ACK    => connection_lost  => READER_WRITER_CLOSED

    # INITIAL                   => reader_eof       => READER_WRITER_CLOSED
    # CONNECTED                 => reader_eof       => READER_CLOSED
    # READER_CLOSED             => reader_eof       => READER_CLOSED
    # WRITER_CLOSED             => reader_eof       => READER_WRITER_CLOSED
    # READER_WRITER_CLOSED      => reader_eof       => READER_WRITER_CLOSED
    # WAITING_FOR_PACKET1       => reader_eof       => READER_WRITER_CLOSED
    # WAITING_FOR_PACKET2       => reader_eof       => READER_WRITER_CLOSED
    # WAITING_FOR_PACKET3       => reader_eof       => READER_WRITER_CLOSED
    # WAITING_FOR_SERVER_ACK    => reader_eof       => READER_WRITER_CLOSED

    # INITIAL                   => writer_eof       => READER_WRITER_CLOSED
    # CONNECTED                 => writer_eof       => WRITER_CLOSED
    # READER_CLOSED             => writer_eof       => READER_WRITER_CLOSED
    # WRITER_CLOSED             => writer_eof       => WRITER_CLOSED
    # READER_WRITER_CLOSED      => writer_eof       => READER_WRITER_CLOSED
    # WAITING_FOR_PACKET1       => writer_eof       => READER_WRITER_CLOSED
    # WAITING_FOR_PACKET2       => writer_eof       => READER_WRITER_CLOSED
    # WAITING_FOR_PACKET3       => writer_eof       => READER_WRITER_CLOSED
    # WAITING_FOR_SERVER_ACK    => writer_eof       => READER_WRITER_CLOSED

    # CONNECTED                 => write_emessage   => CONNECTED
    # READER_CLOSED             => write_emessage   => READER_CLOSED

    # CONNECTED                 => receive_data     => CONNECTED
    # WRITER_CLOSED             => receive_data     => WRITER_CLOSED

    _valid_states: frozenset[MState] = frozenset()
    eof_exception = EOFError("Connection closed by peer")

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        self._transitions = Transitions()

        self._transitions.add_many(
            {
                TransitionEvent.CONNECTION_LOST: {
                    MState.INITIAL: (MState.READER_WRITER_CLOSED, self._connection_lost),
                    MState.CONNECTED: (MState.READER_WRITER_CLOSED, self._connection_lost),
                    MState.READER_CLOSED: (MState.READER_WRITER_CLOSED, self._connection_lost),
                    MState.WRITER_CLOSED: (MState.READER_WRITER_CLOSED, self._connection_lost),
                    MState.READER_WRITER_CLOSED: (MState.READER_WRITER_CLOSED, self._connection_lost),
                    MState.WAITING_FOR_PACKET1: (MState.READER_WRITER_CLOSED, self._connection_lost),
                    MState.WAITING_FOR_PACKET2: (MState.READER_WRITER_CLOSED, self._connection_lost),
                    MState.WAITING_FOR_PACKET3: (MState.READER_WRITER_CLOSED, self._connection_lost),
                    MState.WAITING_FOR_SERVER_ACK: (MState.READER_WRITER_CLOSED, self._connection_lost),
                },
                TransitionEvent.READER_EOF: {
                    MState.INITIAL: (MState.READER_WRITER_CLOSED, self._reader_eof),
                    MState.CONNECTED: (MState.READER_CLOSED, self._reader_eof),
                    MState.READER_CLOSED: (MState.READER_CLOSED, self._reader_eof),
                    MState.WRITER_CLOSED: (MState.READER_WRITER_CLOSED, self._reader_eof),
                    MState.READER_WRITER_CLOSED: (MState.READER_WRITER_CLOSED, self._reader_eof),
                    MState.WAITING_FOR_PACKET1: (MState.READER_WRITER_CLOSED, self._reader_eof),
                    MState.WAITING_FOR_PACKET2: (MState.READER_WRITER_CLOSED, self._reader_eof),
                    MState.WAITING_FOR_PACKET3: (MState.READER_WRITER_CLOSED, self._reader_eof),
                    MState.WAITING_FOR_SERVER_ACK: (MState.READER_WRITER_CLOSED, self._reader_eof),
                },
                TransitionEvent.WRITER_EOF: {
                    MState.INITIAL: (MState.READER_WRITER_CLOSED, self._writer_eof),
                    MState.CONNECTED: (MState.WRITER_CLOSED, self._writer_eof),
                    MState.READER_CLOSED: (MState.READER_WRITER_CLOSED, self._writer_eof),
                    MState.WRITER_CLOSED: (MState.WRITER_CLOSED, self._writer_eof),
                    MState.READER_WRITER_CLOSED: (MState.READER_WRITER_CLOSED, self._writer_eof),
                    MState.WAITING_FOR_PACKET1: (MState.READER_WRITER_CLOSED, self._writer_eof),
                    MState.WAITING_FOR_PACKET2: (MState.READER_WRITER_CLOSED, self._writer_eof),
                    MState.WAITING_FOR_PACKET3: (MState.READER_WRITER_CLOSED, self._writer_eof),
                    MState.WAITING_FOR_SERVER_ACK: (MState.READER_WRITER_CLOSED, self._writer_eof),
                },
                TransitionEvent.WRITE_EMESSAGE: {
                    MState.CONNECTED: (MState.CONNECTED, self._write_emessage),
                    MState.READER_CLOSED: (MState.READER_CLOSED, self._write_emessage),
                    MState.WAITING_FOR_PACKET1: (MState.WAITING_FOR_PACKET1, self._write_emessage),
                    MState.WAITING_FOR_PACKET2: (MState.WAITING_FOR_PACKET2, self._write_emessage),
                    MState.WAITING_FOR_PACKET3: (MState.WAITING_FOR_PACKET3, self._write_emessage),
                    MState.WAITING_FOR_SERVER_ACK: (MState.WAITING_FOR_SERVER_ACK, self._write_emessage),
                },
                TransitionEvent.RECEIVE_DATA: {
                    MState.CONNECTED: (MState.CONNECTED, self._receive_data_connected),
                    MState.WRITER_CLOSED: (MState.WRITER_CLOSED, self._receive_data_connected),
                },
                TransitionEvent.DATA_TO_SEND: {
                    # no MState.INITIAL case, because that will be handled by the subclass
                    MState.CONNECTED: (MState.CONNECTED, self._data_to_send),
                    MState.READER_CLOSED: (MState.READER_CLOSED, self._data_to_send),
                    MState.WRITER_CLOSED: (MState.WRITER_CLOSED, self._data_to_send),
                    MState.READER_WRITER_CLOSED: (MState.READER_WRITER_CLOSED, self._data_to_send),
                    MState.WAITING_FOR_PACKET1: (MState.WAITING_FOR_PACKET1, self._data_to_send),
                    MState.WAITING_FOR_PACKET2: (MState.WAITING_FOR_PACKET2, self._data_to_send),
                    MState.WAITING_FOR_PACKET3: (MState.WAITING_FOR_PACKET3, self._data_to_send),
                    MState.WAITING_FOR_SERVER_ACK: (MState.WAITING_FOR_SERVER_ACK, self._data_to_send),
                },
            },
        )

        self._kx_completed: asyncio.Future = loop.create_future()
        self._invalid_states: set[MState] = ALL_STATES - self._valid_states
        self._state: MState = MState.INITIAL
        self._data_ready_to_send: BytearrayBuilder = BytearrayBuilder()
        self._read_buffers: ReadBuffers = ReadBuffers()

        self._session_pair: SessionPair
        self._rbox: SecretBox
        self._tbox: SecretBox

        self._received_encrypted_msgs: MsgQueue[memoryview] = MsgQueue()
        self._received_decrypted_msgs: MsgQueue[bytes] = MsgQueue()
        self._exception: Exception | None = None

    @property
    def kx_completed(self) -> asyncio.Future:
        return self._kx_completed

    def get_buffer(self) -> memoryview:
        return self._read_buffers.get_buffer()

    @property
    def received_size(self) -> int:
        return self._received_decrypted_msgs.bytesize

    async def read_message(self) -> tuple[bytes, int]:
        return await self._received_decrypted_msgs.get()

    async def decrypt_received_messages(self) -> None:
        logger.info("starting to decrypt received messages")
        while True:
            try:
                incoming, _ = await self._received_encrypted_msgs.get()
            except Exception as ex:  # noqa: BLE001
                logger.info("decrypt received messages has finished: %s", ex)
                self._received_decrypted_msgs.close(ex)
                return
            # decrypt the message and push the result downstream to _received_decrypted_msgs queue
            emsg = EncryptedMessage.from_bytes(incoming)
            msg_id = emsg.msg_id
            try:
                plaintext: bytes = await asyncio.to_thread(self._rbox.decrypt, emsg)
                del emsg
                self._read_buffers.release_bytearray(incoming)  # return the mview to the freelist
                self._received_decrypted_msgs.put_nowait(plaintext, msg_id)
            except Exception as ex:
                # DecryptException will be captured by the protocol, which will abort the transport
                raise DecryptException("Failed to decrypt message from peer") from ex

    def connection_lost(self, exc: Exception | None) -> None:
        event = TransitionEvent.CONNECTION_LOST
        dest, callback = self._transitions.get(event, self._state)
        callback(exc)
        self._state = dest

    def _connection_lost(self, exc: Exception | None) -> None:
        if self._exception is None:
            # make sure a new reader would get rejected
            self._exception = self.eof_exception if exc is None else exc
            self._received_encrypted_msgs.close(self._exception)
        if self._state.kx_is_pending():
            self._fail_kx(self._exception)

    def reader_eof(self) -> None:
        event = TransitionEvent.READER_EOF
        dest, callback = self._transitions.get(event, self._state)
        callback()
        self._state = dest

    def _reader_eof(self) -> None:
        if self._exception is None:
            # make sure a new reader would get rejected
            self._exception = self.eof_exception
            self._received_encrypted_msgs.close(self._exception)
        if self._state.kx_is_pending():
            self._fail_kx(self._exception)

    def writer_eof(self) -> None:
        event = TransitionEvent.WRITER_EOF
        dest, callback = self._transitions.get(event, self._state)
        callback()
        self._state = dest

    def _writer_eof(self) -> None:
        if self._state.kx_is_pending():
            self._fail_kx(self.eof_exception)

    def _fail_kx(self, exc: Exception) -> None:
        if not self._kx_completed.done():
            logger.error("Key exchange failed")
            self._kx_completed.set_exception(exc)

    def _complete_kx(self) -> None:
        if not self._kx_completed.done():
            logger.info("Key exchange completed successfully")
            self._kx_completed.set_result(None)

    def encrypt_message(self, msg: Buffer, msg_id: int) -> bytearray:
        # This method only depends on self._tbox, which is set after the key exchange is completed
        # and is a constant for the lifetime of the machine.
        # So for practical purposes, it is thread-safe.
        # It makes it possible to offload the encryption to a thread if needed.
        return self._tbox.encrypt(msg, msg_id=msg_id)

    def write_emessage(self, ciphertext: bytes | bytearray, msg_id: int) -> None:
        event = TransitionEvent.WRITE_EMESSAGE
        dest, callback = self._transitions.get(event, self._state)
        callback(ciphertext, msg_id)
        self._state = dest

    def _write_emessage(self, ciphertext: bytes | bytearray, msg_id: int) -> None:
        # called by Protocol to prepare sending a message to the server
        self._data_ready_to_send.add(encrypted_message_header(ciphertext, msg_id))
        self._data_ready_to_send.add(ciphertext)

    def _get_small_message(self) -> tuple[bytes, int] | None:
        # for small messages that occur during key exchange, we consider the decryption is immediate,
        # so we don't need to go through the two queues.
        try:
            b = self._read_buffers.consume_message()
            if b is None:
                # not enough data to read the message
                return None
            if len(b) >= NOGIL_THRESHOLD_BYTES:
                logger.warning("_get_small_message: consuming abnormal big message: %s bytes", len(b))
            emsg = EncryptedMessage.from_bytes(b)
            msg_id = emsg.msg_id
            plaintext: bytes = self._rbox.decrypt(emsg)  # considered immediate
            del emsg
            self._read_buffers.release_bytearray(b)  # return the mview to the freelist
            return plaintext, msg_id
        except Exception as ex:
            self._fail_kx(ex)
            raise

    def receive_data(self, nbytes: int) -> None:
        event = TransitionEvent.RECEIVE_DATA
        self._read_buffers.buffer_updated(nbytes)
        try:
            while True:
                dest, callback = self._transitions.get(event, self._state)
                if not callback():
                    # not enough data
                    return
                # when callback returns False, it means there was not enough available data to advance the state
                # when callback returns True, there was some advance, hence set the destination state
                old_state = self._state
                self._state = dest
                if old_state.kx_is_pending() and self._state == MState.CONNECTED:
                    self._complete_kx()
        except Exception as ex:
            self._fail_kx(ex)
            raise

    def _receive_data_connected(self) -> bool:
        # we don't call _get_small_message here, because the message may be big and decrypting it may block the loop
        encrypted_data = self._read_buffers.consume_message()
        if encrypted_data is None:
            # not enough data to read more messages, we're finished for now
            return False
        self._received_encrypted_msgs.put_nowait(encrypted_data)
        return True

    def data_to_send(self) -> bytes:
        event = TransitionEvent.DATA_TO_SEND
        dest, callback = self._transitions.get(event, self._state)
        data: bytes = callback()
        self._state = dest
        return data

    def _data_to_send(self) -> bytearray:
        return self._data_ready_to_send.get()

    # TODO: use it
    def _check_invalid_state(self) -> None:
        if self._state in self._invalid_states:
            ex = RuntimeError(f"Invalid state: {self._state}")
            self._fail_kx(ex)
            raise ex

    def get_peer_key(self) -> KxPublicKey | None:
        return None


class KX_N_ClientStateMachine(BaseMachine):
    # INITIAL                   => data_to_send => WAITING_FOR_SERVER_ACK
    # WAITING_FOR_SERVER_ACK    => receive_data => CONNECTED (or stay in WAITING_FOR_SERVER_ACK if not enough data)

    _valid_states = frozenset(
        {
            MState.INITIAL,  # initial state, we can send packet1
            MState.WAITING_FOR_SERVER_ACK,  # waiting for server ACK after it has processed packet1
            MState.CONNECTED,  # key exchange completed successfully
            MState.READER_CLOSED,  # reader closed, we can still send data
            MState.WRITER_CLOSED,  # writer closed, we can still read data
            MState.READER_WRITER_CLOSED,  # both reader and writer closed, final state
        },
    )

    def __init__(self, server_public_key: KxPublicKey, loop: asyncio.AbstractEventLoop, *, psk: Psk | None = None) -> None:
        super().__init__(loop)

        self._transitions.add_many(
            {
                TransitionEvent.DATA_TO_SEND: {
                    MState.INITIAL: (MState.WAITING_FOR_SERVER_ACK, self._data_to_send_initial),
                },
                TransitionEvent.RECEIVE_DATA: {
                    MState.WAITING_FOR_SERVER_ACK: (MState.CONNECTED, self._receive_server_ack),
                },
            },
        )
        self._transitions.keep_only_valid_states(self._valid_states)

        self._server_public_key: KxPublicKey = server_public_key
        self._session_pair, self._packet1 = client_init_kx_n(server_public_key, psk)
        self._rbox: SecretBox = SecretBox(self._session_pair.rx)
        self._tbox: SecretBox = SecretBox(self._session_pair.tx)

    def _receive_server_ack(self) -> bool:
        two_uple = self._get_small_message()
        if two_uple is None:
            # not enough data to read the message
            return False
        if two_uple[0] != OK_MESSAGE:
            raise RuntimeError("Server did not respond with OK")
        return True

    def _data_to_send_initial(self) -> bytearray:
        self._data_ready_to_send.add(self._packet1)
        return self._data_to_send()

    def get_peer_key(self) -> KxPublicKey | None:
        return self._server_public_key


class KX_N_ServerStateMachine(BaseMachine):
    # INITIAL               => data_to_send => WAITING_FOR_PACKET1
    # WAITING_FOR_PACKET1   => receive_data => CONNECTED (or stay in WAITING_FOR_PACKET1 if not enough data)

    _valid_states = frozenset(
        {
            MState.INITIAL,
            MState.CONNECTED,
            MState.READER_CLOSED,
            MState.WRITER_CLOSED,
            MState.READER_WRITER_CLOSED,
            MState.WAITING_FOR_PACKET1,
        },
    )

    def __init__(self, server_pair: KxPair, loop: asyncio.AbstractEventLoop, *, psk: Psk | None = None) -> None:
        super().__init__(loop)

        self._transitions.add_many(
            {
                TransitionEvent.DATA_TO_SEND: {
                    MState.INITIAL: (MState.WAITING_FOR_PACKET1, self._data_to_send),
                },
                TransitionEvent.RECEIVE_DATA: {
                    MState.WAITING_FOR_PACKET1: (MState.CONNECTED, self._receive_packet1),
                },
            },
        )
        self._transitions.keep_only_valid_states(self._valid_states)

        self._server_pair: KxPair = server_pair
        self._psk: Psk | None = psk

    def _receive_packet1(self) -> bool:
        # we expect to receive packet1 from the client, length KX_N_PACKET1BYTES
        packet1: bytes | None = self._read_buffers.consume_bytes(KX_N_PACKET1BYTES)
        if packet1 is None:
            # not enough data to read the packet1
            return False
        self._session_pair = self._server_pair.server_finish_kx_n(packet1, self._psk)
        self._rbox = SecretBox(self._session_pair.rx)
        self._tbox = SecretBox(self._session_pair.tx)
        # send OK message to the client
        ciphertext = self.encrypt_message(OK_MESSAGE, msg_id=0)
        self.write_emessage(ciphertext, 0)
        return True


class KX_KK_ClientStateMachine(BaseMachine):
    # INITIAL               => data_to_send => WAITING_FOR_PACKET2
    # WAITING_FOR_PACKET2   => receive_data => CONNECTED (or stay in WAITING_FOR_PACKET2 if not enough data)

    _valid_states = frozenset(
        {
            MState.INITIAL,
            MState.CONNECTED,
            MState.READER_CLOSED,
            MState.WRITER_CLOSED,
            MState.READER_WRITER_CLOSED,
            MState.WAITING_FOR_PACKET2,
        },
    )

    def __init__(self, client_pair: KxPair, server_public_key: KxPublicKey, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__(loop)

        self._transitions.add_many(
            {
                TransitionEvent.DATA_TO_SEND: {
                    MState.INITIAL: (MState.WAITING_FOR_PACKET2, self._data_to_send_initial),
                },
                TransitionEvent.RECEIVE_DATA: {
                    MState.WAITING_FOR_PACKET2: (MState.CONNECTED, self._receive_packet2),
                },
            },
        )
        self._transitions.keep_only_valid_states(self._valid_states)

        self._client_pair: KxPair = client_pair
        self._server_public_key: KxPublicKey = server_public_key
        self._kx_state = self._client_pair.client_init_kx_kk(self._server_public_key)

    def _receive_packet2(self) -> bool:
        # we expect to receive packet2 from the server, length KX_KK_PACKET2BYTES
        packet2: bytes | None = self._read_buffers.consume_bytes(KX_KK_PACKET2BYTES)
        if packet2 is None:
            # not enough data to read the packet2
            return False
        self._kx_state.client_finish_kx_kk(packet2)
        assert self._kx_state.session_pair is not None
        self._session_pair = self._kx_state.session_pair
        self._rbox = SecretBox(self._session_pair.rx)
        self._tbox = SecretBox(self._session_pair.tx)
        return True

    def _data_to_send_initial(self) -> bytes:
        self._data_ready_to_send.add(self._kx_state.packet1)
        return self._data_to_send()

    def get_peer_key(self) -> KxPublicKey | None:
        return self._server_public_key


class KX_KK_ServerStateMachine(BaseMachine):
    # INITIAL               => data_to_send => WAITING_FOR_PACKET1
    # WAITING_FOR_PACKET1   => receive_data => CONNECTED (or stay in WAITING_FOR_PACKET1 if not enough data)

    _valid_states = frozenset(
        {
            MState.INITIAL,
            MState.CONNECTED,
            MState.READER_CLOSED,
            MState.WRITER_CLOSED,
            MState.READER_WRITER_CLOSED,
            MState.WAITING_FOR_PACKET1,
        },
    )

    def __init__(self, server_pair: KxPair, client_public_key: KxPublicKey, loop: asyncio.AbstractEventLoop) -> None:
        super().__init__(loop)

        self._transitions.add_many(
            {
                TransitionEvent.DATA_TO_SEND: {
                    MState.INITIAL: (MState.WAITING_FOR_PACKET1, self._data_to_send),
                },
                TransitionEvent.RECEIVE_DATA: {
                    MState.WAITING_FOR_PACKET1: (MState.CONNECTED, self._receive_packet1),
                },
            },
        )
        self._transitions.keep_only_valid_states(self._valid_states)

        self._server_pair: KxPair = server_pair
        self._client_public_key: KxPublicKey = client_public_key

    def _receive_packet1(self) -> bool:
        # we expect to receive packet1 from the client, length KX_KK_PACKET1BYTES
        packet1: bytes | None = self._read_buffers.consume_bytes(KX_KK_PACKET1BYTES)
        if packet1 is None:
            # not enough data to read the packet1
            return False
        pair, packet2 = self._server_pair.server_process_kx_kk(self._client_public_key, packet1)
        self._session_pair = pair
        self._rbox = SecretBox(self._session_pair.rx)
        self._tbox = SecretBox(self._session_pair.tx)
        self._data_ready_to_send.add(packet2)
        return True

    def get_peer_key(self) -> KxPublicKey | None:
        return self._client_public_key


class KX_XX_ClientStateMachine(BaseMachine):
    # INITIAL                => data_to_send => WAITING_FOR_PACKET2
    # WAITING_FOR_PACKET2    => receive_data => WAITING_FOR_SERVER_ACK (or stay in WAITING_FOR_PACKET2 if not enough data)
    # WAITING_FOR_SERVER_ACK => receive_data => CONNECTED (or stay in WAITING_FOR_SERVER_ACK if not enough data)

    _valid_states = frozenset(
        {
            MState.INITIAL,
            MState.CONNECTED,
            MState.READER_CLOSED,
            MState.WRITER_CLOSED,
            MState.READER_WRITER_CLOSED,
            MState.WAITING_FOR_PACKET2,
            MState.WAITING_FOR_SERVER_ACK,
        },
    )

    def __init__(self, client_pair: KxPair, loop: asyncio.AbstractEventLoop, *, psk: Psk | None = None) -> None:
        super().__init__(loop)

        self._transitions.add_many(
            {
                TransitionEvent.DATA_TO_SEND: {
                    MState.INITIAL: (MState.WAITING_FOR_PACKET2, self._data_to_send_initial),
                },
                TransitionEvent.RECEIVE_DATA: {
                    MState.WAITING_FOR_PACKET2: (MState.WAITING_FOR_SERVER_ACK, self._receive_packet2),
                    MState.WAITING_FOR_SERVER_ACK: (MState.CONNECTED, self._receive_server_ack),
                },
            },
        )
        self._transitions.keep_only_valid_states(self._valid_states)

        self._client_pair: KxPair = client_pair
        self._psk: Psk | None = psk
        self._kx_state: KxXxClientState = self._client_pair.client_init_kx_xx(self._psk)
        self._server_public_key: KxPublicKey | None = None  # will be set after receiving packet2 from the server

    def _receive_packet2(self) -> bool:
        # we expect to receive packet2 from the server, length KX_XX_PACKET2BYTES
        packet2: bytes | None = self._read_buffers.consume_bytes(KX_XX_PACKET2BYTES)
        if packet2 is None:
            # not enough data to read the packet2
            return False
        self._kx_state.client_process_kx_xx(packet2)
        assert self._kx_state.packet3
        assert self._kx_state.session_pair is not None
        assert self._kx_state.server_public_key is not None
        self._session_pair = self._kx_state.session_pair
        self._rbox = SecretBox(self._session_pair.rx)
        self._tbox = SecretBox(self._session_pair.tx)
        self._server_public_key = self._kx_state.server_public_key
        # send packet3 to the server
        self._data_ready_to_send.add(self._kx_state.packet3)
        return True

    def _receive_server_ack(self) -> bool:
        # self._state == MState.WAITING_FOR_SERVER_ACK:
        two_uple = self._get_small_message()
        if two_uple is None:
            # not enough data to read the message
            return False
        if two_uple[0] != OK_MESSAGE:
            raise RuntimeError("Server did not respond with OK")
        return True

    def _data_to_send_initial(self) -> bytes:
        self._data_ready_to_send.add(self._kx_state.packet1)
        return self._data_to_send()

    def get_peer_key(self) -> KxPublicKey | None:
        return self._server_public_key


class KX_XX_ServerStateMachine(BaseMachine):
    # INITIAL               => data_to_send => WAITING_FOR_PACKET1
    # WAITING_FOR_PACKET1   => receive_data => WAITING_FOR_PACKET3 (or stay in WAITING_FOR_PACKET1 if not enough data)
    # WAITING_FOR_PACKET3   => receive_data => CONNECTED (or stay in WAITING_FOR_PACKET3 if not enough data)

    _valid_states = frozenset(
        {
            MState.INITIAL,
            MState.CONNECTED,
            MState.READER_CLOSED,
            MState.WRITER_CLOSED,
            MState.READER_WRITER_CLOSED,
            MState.WAITING_FOR_PACKET1,
            MState.WAITING_FOR_PACKET3,
        },
    )

    def __init__(self, server_pair: KxPair, loop: asyncio.AbstractEventLoop, *, psk: Psk | None = None) -> None:
        super().__init__(loop)

        self._transitions.add_many(
            {
                TransitionEvent.DATA_TO_SEND: {
                    MState.INITIAL: (MState.WAITING_FOR_PACKET1, self._data_to_send),
                },
                TransitionEvent.RECEIVE_DATA: {
                    MState.WAITING_FOR_PACKET1: (MState.WAITING_FOR_PACKET3, self._receive_packet1),
                    MState.WAITING_FOR_PACKET3: (MState.CONNECTED, self._receive_packet3),
                },
            },
        )
        self._transitions.keep_only_valid_states(self._valid_states)

        self._server_pair: KxPair = server_pair
        self._psk: Psk | None = psk
        self._client_public_key: KxPublicKey | None = None  # will be set after receiving packet1 from the client
        self._kx_state: KxXxServerState

    def _receive_packet1(self) -> bool:
        # we expect to receive packet1 from the client, length KX_XX_PACKET1BYTES
        packet1: bytes | None = self._read_buffers.consume_bytes(KX_XX_PACKET1BYTES)
        if packet1 is None:
            # not enough data to read the packet1
            return False
        self._kx_state = self._server_pair.server_process_kx_xx(packet1, self._psk)
        assert self._kx_state.packet2
        # send packet2 to the client
        self._data_ready_to_send.add(self._kx_state.packet2)
        return True

    def _receive_packet3(self) -> bool:
        # self._state == MState.WAITING_FOR_PACKET3
        packet3: bytes | None = self._read_buffers.consume_bytes(KX_XX_PACKET3BYTES)
        if packet3 is None:
            # not enough data to read the packet3
            return False
        self._kx_state.server_finish_kx_xx(packet3)
        assert self._kx_state.session_pair is not None
        assert self._kx_state.client_public_key is not None
        self._session_pair = self._kx_state.session_pair
        self._rbox = SecretBox(self._session_pair.rx)
        self._tbox = SecretBox(self._session_pair.tx)
        self._client_public_key = self._kx_state.client_public_key
        # send OK message to the client
        ciphertext = self.encrypt_message(OK_MESSAGE, msg_id=0)
        self.write_emessage(ciphertext, 0)
        return True

    def get_peer_key(self) -> KxPublicKey | None:
        return self._client_public_key


class StreamReaderWriter:
    def __init__(self, protocol: "KXProtocol") -> None:
        self._protocol: KXProtocol = protocol
        self.peername = protocol.peername

    def close(self) -> None:
        self._protocol.close()

    def is_closing(self) -> bool:
        return self._protocol.is_closing()

    async def wait_closed(self) -> None:
        await self._protocol.wait_closed()

    async def get_next_msg(self) -> tuple[bytes, int]:
        return await self._protocol.get_next_msg()

    async def write_cancel_msg(self, target_msg_id: int) -> None:
        await self._protocol.write_cancel_msg(target_msg_id)

    async def write_msg(self, msg: Buffer, msg_id: int) -> None:
        await self._protocol.write_msg(msg, msg_id)

    def write_eof(self) -> None:
        self._protocol.write_eof()

    def can_write_eof(self) -> bool:
        return self._protocol.can_write_eof()

    async def drain(self) -> None:
        await self._protocol.drain()

    def get_extra_info(self, name: str, default: Any = None) -> Any:  # noqa: ANN401
        return self._protocol.get_extra_info(name, default)


async def dummy_validate_peer_key(key: KxPublicKey) -> None:
    logger.debug("Dummy validate peer key called for %s", key)


class KXProtocol(asyncio.BufferedProtocol):
    eof_exception = EOFError("Connection closed by peer")

    def __init__(
        self,
        machine: BaseMachine,
        loop: asyncio.AbstractEventLoop,
        *,
        client_handler: StreamHandlerFunction | None = None,
        limit: int = _DEFAULT_LIMIT,
        validate_peer_key: ValidatePeerKeyFunc | None = None,
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
        self._kx_completed = machine.kx_completed
        self._validate_peer_key: ValidatePeerKeyFunc = validate_peer_key or dummy_validate_peer_key
        self._task: asyncio.Task | None = None
        self._validation_fut: asyncio.Future = self._loop.create_future()

        self.peername: str = ""

        self._transport: asyncio.Transport

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
        return await self._machine.read_message()

    async def write_cancel_msg(self, target_msg_id: int) -> None:
        cancel_msg = bytearray(8)
        store64(cancel_msg, target_msg_id)
        ciphertext = self._machine.encrypt_message(cancel_msg, CANCEL_MESSAGE_ID)
        self._machine.write_emessage(ciphertext, CANCEL_MESSAGE_ID)
        data = self._machine.data_to_send()
        if data:
            self._transport.write(data)
            await self.drain()

    async def write_msg(self, msg: Buffer, msg_id: int) -> None:
        if msg_id == CANCEL_MESSAGE_ID:
            raise ValueError("Cannot write a message with msg_id CANCEL_MESSAGE_ID")
        length = len(memoryview(msg))
        if length == 0:
            return
        # execute encryption in a separate thread to avoid blocking the event loop
        ciphertext = await asyncio.to_thread(self._machine.encrypt_message, msg, msg_id)
        self._machine.write_emessage(ciphertext, msg_id)
        data = self._machine.data_to_send()
        if data:
            self._transport.write(data)
            await self.drain()

    def write_eof(self) -> None:
        self._machine.writer_eof()
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
        # state is INITIAL, we need to move the state and if necessary send the first packet
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

    async def continuous_decrypt(self) -> None:
        try:
            await self._machine.decrypt_received_messages()
        except Exception:
            logger.exception("Continuous decryption task failed")
            self._transport.abort()
            # restart the task to unblock readers
            await self._machine.decrypt_received_messages()

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
            self._validation_fut.set_exception(ex)
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
        await self._validate_peer_key(peer_key)

    async def wait_for_validation(self) -> None:
        await self._validation_fut

    async def wait_for_key_exchange(self) -> None:
        await self._kx_completed

    def get_buffer(self, sizehint: int) -> memoryview:  # noqa: ARG002
        return self._machine.get_buffer()

    def buffer_updated(self, nbytes: int) -> None:
        try:
            self._machine.receive_data(nbytes)
        except (DecryptException, KeyExchangeException):
            logger.exception("decryption or key exchange failed: abort connection with %s", self.peername)
            self._transport.abort()
            return
        except Exception:
            logger.exception("While processing received data from %s", self.peername)
            self._transport.close()
            return

        self.maybe_pause_reading()  # TODO: move ?

        data = self._machine.data_to_send()
        if data:
            self._transport.write(data)

    def maybe_pause_reading(self) -> None:
        if self._reading_paused:
            return
        if self._machine.received_size > 2 * self._limit:
            try:
                logger.info("Transport asked to pause reading, received_size: %d, limit: %d", self._machine.received_size, self._limit)
                self._transport.pause_reading()
                self._reading_paused = True
            except NotImplementedError:
                pass

    def maybe_resume_reading(self) -> None:
        if not self._reading_paused:
            return
        if self._machine.received_size <= self._limit:
            logger.info("Transport asked to resume reading, received_size: %d, limit: %d", self._machine.received_size, self._limit)
            self._reading_paused = False
            self._transport.resume_reading()

    def connection_lost(self, exc: Exception | None) -> None:
        logger.info("connection lost for %s, exc: %s", self.peername, exc)
        self._machine.connection_lost(exc)

        # make wait_closed() return
        if not self._closed_fut.done():
            if exc is None:
                self._closed_fut.set_result(None)
            else:
                self._closed_fut.set_exception(exc)

        self._connection_lost = True  # makes next calls to drain() raise EOFError

        if not self._writing_paused:
            return
        # some writers may be on pause, we need to unblock them
        for dfut in self._drain_futures:
            if not dfut.done():
                if exc is None:
                    dfut.set_result(None)
                else:
                    dfut.set_exception(exc)

    def eof_received(self) -> bool:
        logger.info("eof received from %s", self.peername)
        self._machine.reader_eof()
        return False

    async def drain(self) -> None:
        if self._connection_lost:
            raise self.eof_exception
        if self._transport.is_closing():
            await asyncio.sleep(0)
        if self._connection_lost:
            raise self.eof_exception
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


async def _connect(host: str, port: int, protocol: KXProtocol, retry: int, retry_wait: int) -> None:
    loop = asyncio.get_running_loop()
    while True:
        try:
            await loop.create_connection(lambda: protocol, host, port)
            return
        except ConnectionRefusedError:
            if retry == 0:
                raise
        retry -= 1
        logger.warning("Connection to %s:%d failed, retrying...", host, port)
        if retry_wait > 0:
            await asyncio.sleep(retry_wait)


async def _open_connection(
    host: str,
    port: int,
    machine: BaseMachine,
    limit: int,
    validate_server_key: ValidatePeerKeyFunc | None,
    retry: int,
    retry_wait: int,
    loop: asyncio.AbstractEventLoop,
) -> StreamReaderWriter:
    protocol = KXProtocol(machine, loop, limit=limit, validate_peer_key=validate_server_key)
    await _connect(host, port, protocol, retry, retry_wait)
    await protocol.wait_for_key_exchange()
    await protocol.wait_for_validation()
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
) -> StreamReaderWriter:
    loop = asyncio.get_running_loop()
    machine = KX_N_ClientStateMachine(server_public_key, loop, psk=psk)
    return await _open_connection(host, port, machine, limit, None, connect_retry, connect_retry_wait, loop)


async def open_kx_kk_connection(
    host: str,
    port: int,
    client_pair: KxPair,
    server_public_key: KxPublicKey,
    *,
    limit: int = _DEFAULT_LIMIT,
    connect_retry: int = 3,
    connect_retry_wait: int = 30,
) -> StreamReaderWriter:
    loop = asyncio.get_running_loop()
    machine = KX_KK_ClientStateMachine(client_pair, server_public_key, loop)
    return await _open_connection(host, port, machine, limit, None, connect_retry, connect_retry_wait, loop)


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
) -> StreamReaderWriter:
    loop = asyncio.get_running_loop()
    machine = KX_XX_ClientStateMachine(client_pair, loop, psk=psk)
    return await _open_connection(host, port, machine, limit, validate_server_key, connect_retry, connect_retry_wait, loop)


class AsyncRequestResponseClient:
    def __init__(self, rw: StreamReaderWriter, *, request_timeout_secs: int | None = 30) -> None:
        self._rw: StreamReaderWriter = rw
        self._counter = Counter()
        self._pending_requests: dict[int, asyncio.Future[bytes]] = {}
        self._request_timeout_secs = request_timeout_secs
        self._read_task: asyncio.Task = asyncio.create_task(self._read_responses())

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
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:  # noqa: ANN001
        self.close()
        await self.wait_closed()

    async def request(self, msg: Buffer, *, timeout_secs: int | None = None) -> bytes:
        if self._read_task.done():
            raise RuntimeError("RequestResponseClient is closed")
        timeout_secs = timeout_secs if timeout_secs is not None else self._request_timeout_secs
        # ensure we get a unique message ID for this request
        msg_id: int = self._counter()
        # create and register the future that will hold the response to this request
        fut: asyncio.Future[bytes] = asyncio.get_running_loop().create_future()
        # when the response is received in read_task, we will set the result of this future
        self._pending_requests[msg_id] = fut
        try:
            await self._rw.write_msg(msg, msg_id=msg_id)
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
                else:
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


async def make_kx_n_client(
    host: str,
    port: int,
    server_public_key: KxPublicKey,
    *,
    psk: Psk | None = None,
    limit: int = _DEFAULT_LIMIT,
    request_timeout_secs: int | None = 30,
    connect_retry: int = 3,
    connect_retry_wait: int = 30,
) -> AsyncRequestResponseClient:
    rw = await open_kx_n_connection(
        host, port, server_public_key, psk=psk, limit=limit, connect_retry=connect_retry, connect_retry_wait=connect_retry_wait
    )
    return AsyncRequestResponseClient(rw, request_timeout_secs=request_timeout_secs)


async def make_kx_kk_client(
    host: str,
    port: int,
    client_pair: KxPair,
    server_public_key: KxPublicKey,
    *,
    limit: int = _DEFAULT_LIMIT,
    request_timeout_secs: int | None = 30,
    connect_retry: int = 3,
    connect_retry_wait: int = 30,
) -> AsyncRequestResponseClient:
    rw = await open_kx_kk_connection(
        host, port, client_pair, server_public_key, limit=limit, connect_retry=connect_retry, connect_retry_wait=connect_retry_wait
    )
    return AsyncRequestResponseClient(rw, request_timeout_secs=request_timeout_secs)


async def make_kx_xx_client(
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
) -> AsyncRequestResponseClient:
    rw = await open_kx_xx_connection(
        host,
        port,
        client_pair,
        psk=psk,
        limit=limit,
        validate_server_key=validate_server_key,
        connect_retry=connect_retry,
        connect_retry_wait=connect_retry_wait,
    )
    return AsyncRequestResponseClient(rw, request_timeout_secs=request_timeout_secs)


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

    @classmethod
    def func(cls) -> StreamHandlerFunction:
        """Return a StreamHandlerFunction that can be used to handle the connection."""
        return cls().handle

    async def _handle_message(self, msg: bytes, msg_id: int) -> None:
        self._msgid_var.set(msg_id)
        try:
            if not await self.handle_message(msg, msg_id):
                self._stopping = True
                self.rw.close()
        except Exception:
            logger.exception("Error while handling message %s", msg_id)

    @abstractmethod
    async def handle_message(self, msg: bytes, msg_id: int) -> bool:
        raise NotImplementedError

    async def handle(self, rw: StreamReaderWriter) -> None:
        # self.handle is a StreamHandlerFunction
        self.rw = rw
        try:
            while not self._stopping:
                try:
                    msg, msg_id = await rw.get_next_msg()
                except EOFError:
                    logger.info("EOF received")
                    return
                except Exception as ex:  # noqa: BLE001
                    logger.warning("While reading next message: %s", ex)
                    return
                self._process(msg, msg_id)

        finally:
            self._stopping = True
            nb = self._tasks.cancel_all()
            logger.info("Cancelled pending tasks: %s", nb)
            rw.close()
            await rw.wait_closed()

    def _process(self, msg: bytes, msg_id: int) -> None:
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


class StreamHandler(BaseServerHandler, ABC):
    async def write(self, msg: bytes, msg_id: int | None = None) -> None:
        # the write method can be used by subclasses to implement handle_message
        # it automatically uses the message ID from the incoming message to write the response, if not provided
        if msg_id is None:
            msg_id = self._msgid_var.get()
        await self.rw.write_msg(msg, msg_id)

    @abstractmethod
    async def handle_message(self, msg: bytes, msg_id: int) -> bool:
        raise NotImplementedError


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
        return handler.func()
    if not isinstance(handler, type):
        return handler
    raise TypeError("Handler must be a callable or a subclass of BaseServerHandler")


async def _loop_create_server(factory: Callable[[], KXProtocol], host: str, port: int) -> asyncio.Server:
    loop = asyncio.get_running_loop()
    if sys.version_info < (3, 13):
        # python 3.12 does not support keep_alive here
        return await loop.create_server(factory, host, port, reuse_address=True, start_serving=False)
    return await loop.create_server(factory, host, port, reuse_address=True, start_serving=False, keep_alive=True)


async def start_kx_n_server(
    handler: StreamHandlerFunction | type[BaseServerHandler],
    host: str,
    port: int,
    server_pair: KxPair,
    *,
    psk: Psk | None = None,
    limit: int = _DEFAULT_LIMIT,
) -> asyncio.Server:
    loop = asyncio.get_running_loop()

    def factory() -> KXProtocol:
        # the machine will close the kx_completed future when the key exchange is done
        machine = KX_N_ServerStateMachine(server_pair, loop, psk=psk)
        # kxprotocol will wait for the kx_completed future before triggering the handler
        return KXProtocol(machine, loop, client_handler=wrap(handler), limit=limit)

    return await _loop_create_server(factory, host, port)


async def start_kx_kk_server(
    handler: StreamHandlerFunction | type[BaseServerHandler],
    host: str,
    port: int,
    server_pair: KxPair,
    client_public_key: KxPublicKey,
    *,
    limit: int = _DEFAULT_LIMIT,
) -> asyncio.Server:
    loop = asyncio.get_running_loop()

    def factory() -> KXProtocol:
        machine = KX_KK_ServerStateMachine(server_pair, client_public_key, loop)
        return KXProtocol(machine, loop, client_handler=wrap(handler), limit=limit)

    return await _loop_create_server(factory, host, port)


async def start_kx_xx_server(
    handler: StreamHandlerFunction | type[BaseServerHandler],
    host: str,
    port: int,
    server_pair: KxPair,
    *,
    psk: Psk | None,
    limit: int = _DEFAULT_LIMIT,
    validate_client_key: ValidatePeerKeyFunc | None = None,
) -> asyncio.Server:
    loop = asyncio.get_running_loop()

    def factory() -> KXProtocol:
        machine = KX_XX_ServerStateMachine(server_pair, loop, psk=psk)
        return KXProtocol(machine, loop, client_handler=wrap(handler), limit=limit, validate_peer_key=validate_client_key)

    return await _loop_create_server(factory, host, port)
