import asyncio
import concurrent.futures
import logging
import os
from collections.abc import Buffer, Callable
from dataclasses import dataclass
from enum import StrEnum

from ._decls import NOGIL_THRESHOLD_BYTES
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
from ._networking import BytearrayBuilder, ReadBuffers
from ._secretbox import EncryptedMessage, SecretBox, encrypted_message_header

logger = logging.getLogger("cydrogen")

OK_MESSAGE: bytes = b"OK"
"""
A message sent by the (some of) our servers to the client to acknowledge the successful completion of the key exchange.
"""

CANCEL_MESSAGE_ID: int = 0
"""
With request/response clients, this is the message ID sent by the client to the server to cancel a request.
"""

EOF_EXCEPTION = EOFError("Connection closed by peer")
"""
An exception that may be raised when the peer closes the connection.
"""

N_CPUS = os.process_cpu_count() or 1


class MState(StrEnum):
    """
    MState represents the different states of the state machine used in the key exchange protocol.
    """

    INITIAL = "initial"
    """
    Initial state of the state machine, before any key exchange has started.
    """

    CONNECTED = "connected"
    """
    Connected state, after the key exchange has completed successfully.
    """

    READER_CLOSED = "reader_closed"
    """
    Reader closed state, when the reader has been closed but the writer is still open.
    """

    WRITER_CLOSED = "writer_closed"
    """
    Writer closed state, when the writer has been closed but the reader is still open.
    """

    READER_WRITER_CLOSED = "reader_writer_closed"
    """
    Reader and writer closed state, when both the reader and writer have been closed.
    """

    WAITING_FOR_PACKET1 = "waiting_for_packet1"
    """
    Waiting for packet1 to be sent by peer.
    """

    WAITING_FOR_PACKET2 = "waiting_for_packet2"
    """
    Waiting for packet2 to be sent by peer.
    """

    WAITING_FOR_PACKET3 = "waiting_for_packet3"
    """
    Waiting for packet3 to be sent by peer.
    """

    WAITING_FOR_SERVER_ACK = "waiting_for_server_ack"
    """
    Waiting for the server to acknowledge the key exchange.
    """

    def kx_is_pending(self) -> bool:
        """
        Returns True if the state is one of the states where the key exchange is pending.
        """
        return self in (
            MState.WAITING_FOR_PACKET1,
            MState.WAITING_FOR_PACKET2,
            MState.WAITING_FOR_PACKET3,
            MState.WAITING_FOR_SERVER_ACK,
        )


class TransitionEvent(StrEnum):
    """
    TransitionEvent represents the different events that can trigger a state transition in the state machine.
    """

    CONNECTION_LOST = "connection_lost"
    """
    Connection lost event, triggered when the connection is lost or closed.
    """

    READER_EOF = "reader_eof"
    """
    Reader EOF event, triggered when the reader is closing.
    """

    WRITER_EOF = "writer_eof"
    """
    Writer EOF event, triggered when the writer is closing.
    """

    WRITE_EMESSAGE = "write_emessage"
    """
    Write encrypted message event, triggered when the Protocol wants to send an encrypted message.
    """

    RECEIVE_DATA = "receive_data"
    """
    Receive data event, triggered when the Protocol has received data from the peer.
    """

    DATA_TO_SEND = "data_to_send"
    """
    Initial event to send data to the peer, when we need to start the key exchange process.
    """


class InvalidTransitionError(RuntimeError):
    """
    Exception raised when an invalid transition is attempted in the state machine.
    """

    def __init__(self, event: TransitionEvent, orig_state: MState) -> None:
        """
        Initializes the InvalidTransitionError with the event and original state that caused the error.

        Args:
            event: The TransitionEvent that was attempted.
            orig_state: The original state from which the transition was attempted.
        """
        super().__init__(f"Invalid transition {orig_state} => {event}")
        self.event = event
        self.orig_state = orig_state


ALL_STATES: set[MState] = set(MState)
"""
A set containing all possible states of all the state machines.
"""


@dataclass(frozen=True, slots=True)
class Destination:
    """
    Destination represents a destination state and a callback function to be called when the transition occurs.
    """

    state: MState
    callback: Callable


type TransitionsByOrigState = dict[MState, Destination]
"""
A dictionary mapping original states to their corresponding Destination objects (for a given TransitionEvent).
"""


class Transitions:
    """
    Transitions represents the valid transitions for one of the state machines used in the key exchange protocol.
    """

    def __init__(self) -> None:
        self._t: dict[TransitionEvent, TransitionsByOrigState] = {}

    def add_many(self, ev: TransitionEvent, transitions: TransitionsByOrigState) -> None:
        if ev in self._t:
            raise KeyError(f"Event {ev} already exists in transitions")
        self._t[ev] = transitions

    def add_one(self, ev: TransitionEvent, orig_state: MState, dest_state: MState, callback: Callable) -> None:
        if ev not in self._t:
            raise KeyError(f"Event {ev} not found in transitions")
        if orig_state in self._t[ev]:
            raise KeyError(f"Transition for event {ev} and state {orig_state} already exists")
        self._t[ev][orig_state] = Destination(state=dest_state, callback=callback)

    def get(self, event: TransitionEvent, orig_state: MState) -> Destination:
        """
        Get the destination state and callback for a given event and original state.

        Args:
            event: The TransitionEvent for which to get the transition.
            orig_state: The original state from which the transition occurs.

        Returns:
            A tuple containing the destination state and the callback function to be called when the transition occurs.

        Raises:
            InvalidTransitionError: If the event is not valid for the original state.
        """
        try:
            return self._t[event][orig_state]
        except KeyError as ex:
            raise InvalidTransitionError(event, orig_state) from ex

    def keep_only_valid_states(self, valid_states: frozenset[MState]) -> None:
        """
        Remove the superfluous transitions that reference invalid states.

        Args:
            valid_states: the set of valid states that transitions should reference.
        """
        to_remove: dict[TransitionEvent, set[MState]] = {}

        for event, state_transitions in self._t.items():
            to_remove[event] = set()
            for orig_state, dest in state_transitions.items():
                if orig_state not in valid_states or dest.state not in valid_states:
                    to_remove[event].add(orig_state)

        for event, orig_states in to_remove.items():
            for orig_state in orig_states:
                logger.debug("Removing: %s => %s => ...", orig_state, event)
                del self._t[event][orig_state]
            if not self._t[event]:
                logger.debug("Removing event: %s", event)
                del self._t[event]


class BaseMachine:
    """
    BaseMachine is the base class for all state machines used in the key exchange protocols.


    When initializing the base machine, we register the transitions that are common to all state machines.

    Some of those transitions are not valid for all state machines, but they are kept here for convenience.
    Subclasses should override the `_valid_states` class variable to specify which states are valid for that machine,
    and call `self._transitions.keep_only_valid_states(...)` in their `__init__` method to remove the
    superfluous transitions.
    """

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
    """
    The set of valid states for this state machine.

    Subclasses should override this variable to specify which states are valid for that machine.
    """

    def __init__(
        self, kx_completed: concurrent.futures.Future | asyncio.Future, sent_msg_max_size: int = 2**20, received_msg_max_size: int = 2**20
    ) -> None:
        """
        Initializes the BaseMachine.

        Args:
            kx_completed: A Future that will be set when the key exchange is completed.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
        """
        self.sent_msg_max_size: int = sent_msg_max_size
        self.received_msg_max_size: int = received_msg_max_size

        self._transitions = Transitions()

        self._transitions.add_many(
            TransitionEvent.CONNECTION_LOST,
            {
                MState.INITIAL: Destination(MState.READER_WRITER_CLOSED, self._connection_lost),
                MState.CONNECTED: Destination(MState.READER_WRITER_CLOSED, self._connection_lost),
                MState.READER_CLOSED: Destination(MState.READER_WRITER_CLOSED, self._connection_lost),
                MState.WRITER_CLOSED: Destination(MState.READER_WRITER_CLOSED, self._connection_lost),
                MState.READER_WRITER_CLOSED: Destination(MState.READER_WRITER_CLOSED, self._connection_lost),
                MState.WAITING_FOR_PACKET1: Destination(MState.READER_WRITER_CLOSED, self._connection_lost),
                MState.WAITING_FOR_PACKET2: Destination(MState.READER_WRITER_CLOSED, self._connection_lost),
                MState.WAITING_FOR_PACKET3: Destination(MState.READER_WRITER_CLOSED, self._connection_lost),
                MState.WAITING_FOR_SERVER_ACK: Destination(MState.READER_WRITER_CLOSED, self._connection_lost),
            },
        )

        self._transitions.add_many(
            TransitionEvent.READER_EOF,
            {
                MState.INITIAL: Destination(MState.READER_WRITER_CLOSED, self._reader_eof),
                MState.CONNECTED: Destination(MState.READER_CLOSED, self._reader_eof),
                MState.READER_CLOSED: Destination(MState.READER_CLOSED, self._reader_eof),
                MState.WRITER_CLOSED: Destination(MState.READER_WRITER_CLOSED, self._reader_eof),
                MState.READER_WRITER_CLOSED: Destination(MState.READER_WRITER_CLOSED, self._reader_eof),
                MState.WAITING_FOR_PACKET1: Destination(MState.READER_WRITER_CLOSED, self._reader_eof),
                MState.WAITING_FOR_PACKET2: Destination(MState.READER_WRITER_CLOSED, self._reader_eof),
                MState.WAITING_FOR_PACKET3: Destination(MState.READER_WRITER_CLOSED, self._reader_eof),
                MState.WAITING_FOR_SERVER_ACK: Destination(MState.READER_WRITER_CLOSED, self._reader_eof),
            },
        )

        self._transitions.add_many(
            TransitionEvent.WRITER_EOF,
            {
                MState.INITIAL: Destination(MState.READER_WRITER_CLOSED, self._writer_eof),
                MState.CONNECTED: Destination(MState.WRITER_CLOSED, self._writer_eof),
                MState.READER_CLOSED: Destination(MState.READER_WRITER_CLOSED, self._writer_eof),
                MState.WRITER_CLOSED: Destination(MState.WRITER_CLOSED, self._writer_eof),
                MState.READER_WRITER_CLOSED: Destination(MState.READER_WRITER_CLOSED, self._writer_eof),
                MState.WAITING_FOR_PACKET1: Destination(MState.READER_WRITER_CLOSED, self._writer_eof),
                MState.WAITING_FOR_PACKET2: Destination(MState.READER_WRITER_CLOSED, self._writer_eof),
                MState.WAITING_FOR_PACKET3: Destination(MState.READER_WRITER_CLOSED, self._writer_eof),
                MState.WAITING_FOR_SERVER_ACK: Destination(MState.READER_WRITER_CLOSED, self._writer_eof),
            },
        )

        self._transitions.add_many(
            TransitionEvent.WRITE_EMESSAGE,
            {
                MState.CONNECTED: Destination(MState.CONNECTED, self._write_emessage),
                MState.READER_CLOSED: Destination(MState.READER_CLOSED, self._write_emessage),
                MState.WAITING_FOR_PACKET1: Destination(MState.WAITING_FOR_PACKET1, self._write_emessage),
                MState.WAITING_FOR_PACKET2: Destination(MState.WAITING_FOR_PACKET2, self._write_emessage),
                MState.WAITING_FOR_PACKET3: Destination(MState.WAITING_FOR_PACKET3, self._write_emessage),
                MState.WAITING_FOR_SERVER_ACK: Destination(MState.WAITING_FOR_SERVER_ACK, self._write_emessage),
            },
        )

        self._transitions.add_many(
            TransitionEvent.RECEIVE_DATA,
            {
                MState.CONNECTED: Destination(MState.CONNECTED, self._receive_data_connected),
                MState.WRITER_CLOSED: Destination(MState.WRITER_CLOSED, self._receive_data_connected),
            },
        )

        self._transitions.add_many(
            TransitionEvent.DATA_TO_SEND,
            {
                # no MState.INITIAL case, because that will be handled by the subclass
                MState.CONNECTED: Destination(MState.CONNECTED, self._data_to_send),
                MState.READER_CLOSED: Destination(MState.READER_CLOSED, self._data_to_send),
                MState.WRITER_CLOSED: Destination(MState.WRITER_CLOSED, self._data_to_send),
                MState.READER_WRITER_CLOSED: Destination(MState.READER_WRITER_CLOSED, self._data_to_send),
                MState.WAITING_FOR_PACKET1: Destination(MState.WAITING_FOR_PACKET1, self._data_to_send),
                MState.WAITING_FOR_PACKET2: Destination(MState.WAITING_FOR_PACKET2, self._data_to_send),
                MState.WAITING_FOR_PACKET3: Destination(MState.WAITING_FOR_PACKET3, self._data_to_send),
                MState.WAITING_FOR_SERVER_ACK: Destination(MState.WAITING_FOR_SERVER_ACK, self._data_to_send),
            },
        )

        self._kx_completed = kx_completed
        self._invalid_states: set[MState] = ALL_STATES - self._valid_states
        self._state: MState = MState.INITIAL
        self._data_ready_to_send: BytearrayBuilder = BytearrayBuilder()
        self._read_buffers: ReadBuffers = ReadBuffers(received_msg_max_size=received_msg_max_size)

        self._session_pair: SessionPair
        self._rbox: SecretBox
        self._tbox: SecretBox

        self._exception: Exception | None = None

    @property
    def kx_completed(self) -> asyncio.Future | concurrent.futures.Future:
        """
        Returns the Future that will be set when the key exchange is completed.

        This Future will be set with None if the key exchange is successful, or with an exception if it fails.
        """
        return self._kx_completed

    def get_buffer(self) -> memoryview:
        """
        Returns a memoryview of the buffer used to read data from the peer.

        The buffer is normally requested by the Transport to the Protocol when it needs to read data from the peer. The Protocol
        itself forwards the request to the Machine, which provides a memoryview of the buffer that can be used to read data.

        The underlying ReadBuffers class enables clever reusing of the memoryviews.
        """
        return self._read_buffers.get_buffer()

    def decrypt_message(self, msg: Buffer) -> tuple[bytes, int]:
        """
        Decrypts a message using the session keys established during the key exchange.

        Decryption may take some time, so it is recommended to call this method in a separate thread
        to avoid to block the event loop. As the decryption only depends on the session keys,
        and the session keys are constant after the key exchange is completed, this method is thread-safe.

        Args:
            msg: The encrypted message to decrypt, as a bytes-like object.

        Returns:
            The decrypted message as bytes.
            The message ID associated with the decrypted message.
        """
        emsg = EncryptedMessage.from_bytes(msg)
        msg_id = emsg.msg_id
        plaintext: bytes = self._rbox.decrypt(emsg)
        return plaintext, msg_id

    def release_encrypted_message(self, mv: Buffer) -> None:
        self._read_buffers.release_bytearray(mv)

    def trigger(self, ev: TransitionEvent, *args):  # noqa: ANN002, ANN201
        """
        Triggers a state transition in the state machine based on the given event and arguments.

        Args:
            ev: The TransitionEvent that triggers the state transition.
            *args: Additional arguments to pass to the callback function associated with the transition.

        Returns:
            The result of the callback function associated with the transition.
        """
        if ev == TransitionEvent.RECEIVE_DATA:
            return self._receive_data(*args)
        dest = self._transitions.get(ev, self._state)
        res = dest.callback(*args)
        self._state = dest.state
        return res

    def _receive_data(self, nbytes: int) -> list[memoryview]:
        self._read_buffers.buffer_updated(nbytes)
        emsgs: list[memoryview] = []
        try:
            while True:
                dest = self._transitions.get(TransitionEvent.RECEIVE_DATA, self._state)
                result = dest.callback()
                if not result:
                    # when callback returns False, it means there was not enough available data to advance the state
                    return emsgs
                # result may be True or a memoryview
                if result is not True:
                    emsgs.append(result)
                # update the state as the true result means there was some advancement
                old_state = self._state
                self._state = dest.state
                if old_state.kx_is_pending() and self._state == MState.CONNECTED:
                    self._complete_kx()
        except Exception as ex:
            self._fail_kx(ex)
            raise

    def _receive_data_connected(self) -> memoryview | None:
        # may raise MessageTooBigException if the received message is too big
        return self._read_buffers.consume_message()

    def _connection_lost(self, exc: Exception | None) -> Exception:
        # _reader_eof may have been called before this method, so we check if the exception is already set
        if self._exception is None:
            self._exception = EOF_EXCEPTION if exc is None else exc
        self._fail_kx(self._exception)
        return self._exception

    def _reader_eof(self) -> Exception:
        if self._exception is None:
            self._exception = EOF_EXCEPTION
        self._fail_kx(self._exception)
        return self._exception

    def _writer_eof(self) -> None:
        if self._state.kx_is_pending():
            self._fail_kx(EOF_EXCEPTION)

    def _fail_kx(self, exc: Exception) -> None:
        if not self._kx_completed.done():
            logger.error("Key exchange failed")
            self._kx_completed.set_exception(exc)

    def _complete_kx(self) -> None:
        if not self._kx_completed.done():
            logger.info("Key exchange completed successfully")
            self._kx_completed.set_result(None)

    def encrypt_message(self, msg: Buffer, msg_id: int) -> bytearray:
        """
        Encrypts a message using the session keys established during the key exchange.

        Encryption may take some time, so it is recommended to call this method in a separate thread
        to avoid to block the event loop. As the encryption only depends on the session keys,
        and the session keys are constant after the key exchange is completed, this method is thread-safe.

        Args:
            msg: The message to encrypt, as a bytes-like object.
            msg_id: The message ID to associate with the encrypted message.

        Returns:
            A bytearray containing the encrypted message, ready to be sent over the network.
        """
        return self._tbox.encrypt(msg, msg_id=msg_id, max_msg_size=self.sent_msg_max_size)

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

    def _data_to_send(self) -> bytearray:
        return self._data_ready_to_send.get()

    def get_peer_key(self) -> KxPublicKey | None:
        """
        Returns the public key of the peer when it is known.

        Returns:
            The public key of the peer, or None if the peer's key is not known yet or not applicable (e.g. in KX_N, server side).
        """
        return None


class KX_N_ClientStateMachine(BaseMachine):
    """
    KX_N_ClientStateMachine implements the client side of the KX_N key exchange protocol.
    """

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

    def __init__(
        self,
        server_public_key: KxPublicKey,
        kx_completed: concurrent.futures.Future | asyncio.Future,
        *,
        psk: Psk | None = None,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
    ) -> None:
        """
        Initializes the KX_N_ClientStateMachine.

        Args:
            server_public_key: The public key of the server to which we are connecting.
            kx_completed: A Future that will be set when the key exchange is completed.
            psk: An optional pre-shared key to use for the key exchange.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(kx_completed, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)

        self._transitions.add_one(TransitionEvent.DATA_TO_SEND, MState.INITIAL, MState.WAITING_FOR_SERVER_ACK, self._data_to_send_initial)
        self._transitions.add_one(TransitionEvent.RECEIVE_DATA, MState.WAITING_FOR_SERVER_ACK, MState.CONNECTED, self._receive_server_ack)

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
    """
    KX_N_ServerStateMachine implements the server side of the KX_N key exchange protocol.
    """

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

    def __init__(
        self,
        server_pair: KxPair,
        kx_completed: concurrent.futures.Future | asyncio.Future,
        *,
        psk: Psk | None = None,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
    ) -> None:
        """
        Initializes the KX_N_ServerStateMachine.

        Args:
            server_pair: The KxPair instance representing the server's key exchange pair.
            kx_completed: A Future that will be set when the key exchange is completed.
            psk: An optional pre-shared key to use for the key exchange.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(kx_completed, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)

        self._transitions.add_one(TransitionEvent.DATA_TO_SEND, MState.INITIAL, MState.WAITING_FOR_PACKET1, self._data_to_send)
        self._transitions.add_one(TransitionEvent.RECEIVE_DATA, MState.WAITING_FOR_PACKET1, MState.CONNECTED, self._receive_packet1)

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
        self.trigger(TransitionEvent.WRITE_EMESSAGE, ciphertext, 0)
        return True


class KX_KK_ClientStateMachine(BaseMachine):
    """
    KX_KK_ClientStateMachine implements the client side of the KX_KK key exchange protocol.
    """

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

    def __init__(
        self,
        client_pair: KxPair,
        server_public_key: KxPublicKey,
        kx_completed: concurrent.futures.Future | asyncio.Future,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
    ) -> None:
        """
        Initializes the KX_KK_ClientStateMachine.

        Args:
            client_pair: The KxPair instance representing the client's key exchange pair.
            server_public_key: The public key of the server to which we are connecting.
            kx_completed: A Future that will be set when the key exchange is completed.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(kx_completed, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)

        self._transitions.add_one(TransitionEvent.DATA_TO_SEND, MState.INITIAL, MState.WAITING_FOR_PACKET2, self._data_to_send_initial)
        self._transitions.add_one(TransitionEvent.RECEIVE_DATA, MState.WAITING_FOR_PACKET2, MState.CONNECTED, self._receive_packet2)

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
    """
    KX_KK_ServerStateMachine implements the server side of the KX_KK key exchange protocol.
    """

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

    def __init__(
        self,
        server_pair: KxPair,
        client_public_key: KxPublicKey,
        kx_completed: concurrent.futures.Future | asyncio.Future,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
    ) -> None:
        """
        Initializes the KX_KK_ServerStateMachine.

        Args:
            server_pair: The KxPair instance representing the server's key exchange pair.
            client_public_key: The public key of the client that is connecting to the server.
            kx_completed: A Future that will be set when the key exchange is completed.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(kx_completed, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)

        self._transitions.add_one(TransitionEvent.DATA_TO_SEND, MState.INITIAL, MState.WAITING_FOR_PACKET1, self._data_to_send)
        self._transitions.add_one(TransitionEvent.RECEIVE_DATA, MState.WAITING_FOR_PACKET1, MState.CONNECTED, self._receive_packet1)

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
    """
    KX_XX_ClientStateMachine implements the client side of the KX_XX key exchange protocol.
    """

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

    def __init__(
        self,
        client_pair: KxPair,
        kx_completed: concurrent.futures.Future | asyncio.Future,
        *,
        psk: Psk | None = None,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
    ) -> None:
        """
        Initializes the KX_XX_ClientStateMachine.

        Args:
            client_pair: The KxPair instance representing the client's key exchange pair.
            kx_completed: A Future that will be set when the key exchange is completed.
            psk: An optional pre-shared key to use for the key exchange.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(kx_completed, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)

        self._transitions.add_one(TransitionEvent.DATA_TO_SEND, MState.INITIAL, MState.WAITING_FOR_PACKET2, self._data_to_send_initial)
        self._transitions.add_one(
            TransitionEvent.RECEIVE_DATA, MState.WAITING_FOR_PACKET2, MState.WAITING_FOR_SERVER_ACK, self._receive_packet2
        )
        self._transitions.add_one(TransitionEvent.RECEIVE_DATA, MState.WAITING_FOR_SERVER_ACK, MState.CONNECTED, self._receive_server_ack)

        self._transitions.keep_only_valid_states(self._valid_states)

        self._client_pair: KxPair = client_pair
        self._psk: Psk | None = psk
        self._kx_state: KxXxClientState = self._client_pair.client_init_kx_xx(self._psk)
        self._server_public_key: KxPublicKey  # will be set after receiving packet2 from the server

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
    """
    KX_XX_ServerStateMachine implements the server side of the KX_XX key exchange protocol.
    """

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

    def __init__(
        self,
        server_pair: KxPair,
        kx_completed: concurrent.futures.Future | asyncio.Future,
        *,
        psk: Psk | None = None,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
    ) -> None:
        """
        Initializes the KX_XX_ServerStateMachine.

        Args:
            server_pair: The KxPair instance representing the server's key exchange pair.
            kx_completed: A Future that will be set when the key exchange is completed.
            psk: An optional pre-shared key to use for the key exchange.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(kx_completed, sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)

        self._transitions.add_one(TransitionEvent.DATA_TO_SEND, MState.INITIAL, MState.WAITING_FOR_PACKET1, self._data_to_send)
        self._transitions.add_one(
            TransitionEvent.RECEIVE_DATA, MState.WAITING_FOR_PACKET1, MState.WAITING_FOR_PACKET3, self._receive_packet1
        )
        self._transitions.add_one(TransitionEvent.RECEIVE_DATA, MState.WAITING_FOR_PACKET3, MState.CONNECTED, self._receive_packet3)

        self._transitions.keep_only_valid_states(self._valid_states)

        self._server_pair: KxPair = server_pair
        self._psk: Psk | None = psk
        self._client_public_key: KxPublicKey  # will be set after receiving packet1 from the client
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
        self.trigger(TransitionEvent.WRITE_EMESSAGE, ciphertext, 0)
        return True

    def get_peer_key(self) -> KxPublicKey | None:
        return self._client_public_key
