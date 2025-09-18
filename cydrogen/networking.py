# note that this module does not contain any networking code, it is just the state machines used by the networking code.
# in particular, it does not use asyncio or any other networking library.

import logging
import os
import sys
from collections.abc import Buffer, Callable
from dataclasses import dataclass
from enum import StrEnum

from ._datastructs import (
    EncryptedMessage,
    KX_KK_Packet1,
    KX_KK_Packet2,
    KX_N_Packet1,
    KX_Server_Ack,
    KX_XX_Packet1,
    KX_XX_Packet2,
    KX_XX_Packet3,
    MessageType,
)
from ._kx_n import (
    KxKkClientState,
    KxPair,
    KxPublicKey,
    KxXxClientState,
    KxXxServerState,
    Psk,
    SessionPair,
    client_init_kx_n,
)
from ._networking import BytearrayBuilder, ReadBuffers, RWLock
from ._secretbox import SecretBox
from .exceptions import CyException, InvalidPeerKeyException, KeyExchangeException

logger = logging.getLogger("cydrogen")

CANCEL_MESSAGE_ID: int = 0
"""
With request/response clients, this is the message ID sent by the client to the server to cancel a request.
"""

EOF_EXCEPTION = EOFError("Connection closed by peer")
"""
An exception that may be raised when the peer closes the connection.
"""

PY312 = sys.version_info < (3, 13)

N_CPUS: int = (os.cpu_count() or 1) if PY312 else (os.process_cpu_count() or 1)


class MachineProducedEvent:
    pass


class KxCompleted(MachineProducedEvent):
    pass


class KxFailed(MachineProducedEvent):
    def __init__(self, exc: Exception) -> None:
        self.exc = exc


class KxProgress(MachineProducedEvent):
    pass


class ReceivedEncryptedMessage(MachineProducedEvent):
    def __init__(self, emsg: memoryview) -> None:
        self.emsg = emsg


class MachineState(StrEnum):
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

    CONNECTED_WAITING_FOR_SERVER_ACK = "connected_waiting_for_server_ack"
    """
    Client is connected, and waiting for the server to acknowledge the rekeying operation.
    """

    CONNECTED_WAITING_FOR_PACKET2 = "connected_waiting_for_packet2"
    """
    Client or server is connected, and waiting for packet2 to be sent by peer.
    """

    CONNECTED_WAITING_FOR_PACKET3 = "connected_waiting_for_packet3"
    """
    Server is connected, and waiting for packet3 to be sent by peer.
    """

    def kx_is_pending(self) -> bool:
        """
        Returns True if the state is one of the states where the key exchange is pending.
        """
        return self in (
            MachineState.WAITING_FOR_PACKET1,
            MachineState.WAITING_FOR_PACKET2,
            MachineState.WAITING_FOR_PACKET3,
            MachineState.WAITING_FOR_SERVER_ACK,
        )


class ExternalEvent(StrEnum):
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

    RECEIVE_PACKET1 = "receive_packet1"
    """
    Receive first packet during a key exchange (KX_N, KX_KK, KX_XX).
    """

    RECEIVE_PACKET2 = "receive_packet2"
    """
    Receive second packet during a key exchange (KX_KK, KX_XX).
    """

    RECEIVE_PACKET3 = "receive_packet3"
    """
    Receive third packet during a key exchange (KX_XX).
    """

    RECEIVE_EMESSAGE = "receive_emessage"
    """
    Receive an encrypted message from the peer, after the key exchange has completed.
    """

    RECEIVE_SERVER_ACK = "receive_server_ack"
    """
    Receive server ACK.
    """

    CONNECTION_MADE = "connection_made"
    """
    When the network connection with the peer was made.
    """

    REKEY = "rekey"
    """
    Trigger a rekeying operation at the client.
    """


class InvalidTransitionError(CyException):
    """
    Exception raised when an invalid transition is attempted in the state machine.
    """

    def __init__(self, event: ExternalEvent, orig_state: MachineState) -> None:
        """
        Initializes the InvalidTransitionError with the event and original state that caused the error.

        Args:
            event: The TransitionEvent that was attempted.
            orig_state: The original state from which the transition was attempted.
        """
        super().__init__(f"Invalid transition {orig_state} => {event}")
        self.event = event
        self.orig_state = orig_state


ALL_STATES: set[MachineState] = set(MachineState)
"""
A set containing all possible states of all the state machines.
"""


@dataclass(frozen=True, slots=True)
class TransitionDestination:
    """
    Destination represents a destination state and a callback function to be called when the transition occurs.
    """

    state: MachineState
    callback: Callable[..., MachineProducedEvent | None] | Callable[..., None]


type TransitionsByOrigState = dict[MachineState, TransitionDestination]
"""
A dictionary mapping original states to their corresponding Destination objects (for a given TransitionEvent).
"""


class Transitions:
    """
    Transitions represents the valid transitions for one of the state machines used in the key exchange protocol.
    """

    def __init__(self) -> None:
        self._t: dict[ExternalEvent, TransitionsByOrigState] = {
            ExternalEvent.CONNECTION_MADE: {},
            ExternalEvent.RECEIVE_PACKET1: {},
            ExternalEvent.RECEIVE_PACKET2: {},
            ExternalEvent.RECEIVE_PACKET3: {},
            ExternalEvent.RECEIVE_SERVER_ACK: {},
            ExternalEvent.REKEY: {},
        }

    def add_many(self, ev: ExternalEvent, transitions: TransitionsByOrigState) -> None:
        if ev in self._t:
            raise KeyError(f"Event {ev} already exists in transitions")
        self._t[ev] = transitions

    def add_one(self, ev: ExternalEvent, orig_state: MachineState, dest_state: MachineState, callback: Callable) -> None:
        if ev not in self._t:
            raise KeyError(f"Event {ev} not found in transitions")
        if orig_state in self._t[ev]:
            raise KeyError(f"Transition for event {ev} and state {orig_state} already exists")
        self._t[ev][orig_state] = TransitionDestination(state=dest_state, callback=callback)

    def get(self, event: ExternalEvent, orig_state: MachineState) -> TransitionDestination:
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

    def keep_only_valid_states(self, valid_states: frozenset[MachineState]) -> None:
        """
        Remove the superfluous transitions that reference invalid states.

        Args:
            valid_states: the set of valid states that transitions should reference.
        """
        to_remove: dict[ExternalEvent, set[MachineState]] = {}

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


@dataclass(frozen=True, slots=True)
class CryptoMaterial:
    pair: SessionPair
    tbox: SecretBox
    rbox: SecretBox


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

    # CONNECTED                        => write_emessage => CONNECTED
    # CONNECTED_WAITING_FOR_SERVER_ACK => write_emessage => CONNECTED_WAITING_FOR_SERVER_ACK
    # CONNECTED_WAITING_FOR_PACKET2    => write_emessage => CONNECTED_WAITING_FOR_PACKET2
    # CONNECTED_WAITING_FOR_PACKET3    => write_emessage => CONNECTED_WAITING_FOR_PACKET3
    # READER_CLOSED                    => write_emessage => READER_CLOSED

    # CONNECTED                        => receive_emessage => CONNECTED
    # CONNECTED_WAITING_FOR_SERVER_ACK => receive_emessage => CONNECTED_WAITING_FOR_SERVER_ACK
    # CONNECTED_WAITING_FOR_PACKET2    => receive_emessage => CONNECTED_WAITING_FOR_PACKET2
    # CONNECTED_WAITING_FOR_PACKET3    => receive_emessage => CONNECTED_WAITING_FOR_PACKET3
    # WRITER_CLOSED                    => receive_emessage => WRITER_CLOSED

    _valid_states: frozenset[MachineState] = frozenset()
    """
    The set of valid states for this state machine.

    Subclasses should override this variable to specify which states are valid for that machine.
    """

    def __init__(self, sent_msg_max_size: int = 2**20, received_msg_max_size: int = 2**20) -> None:
        """
        Initializes the BaseMachine.

        Args:
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
        """
        self.sent_msg_max_size: int = sent_msg_max_size
        self.received_msg_max_size: int = received_msg_max_size
        self._kx_finished = False

        self._transitions = Transitions()

        self._transitions.add_many(
            ExternalEvent.CONNECTION_LOST,
            {
                MachineState.INITIAL: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._connection_lost),
                MachineState.CONNECTED: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._connection_lost),
                MachineState.READER_CLOSED: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._connection_lost),
                MachineState.WRITER_CLOSED: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._connection_lost),
                MachineState.READER_WRITER_CLOSED: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._connection_lost),
                MachineState.WAITING_FOR_PACKET1: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._connection_lost),
                MachineState.WAITING_FOR_PACKET2: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._connection_lost),
                MachineState.WAITING_FOR_PACKET3: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._connection_lost),
                MachineState.WAITING_FOR_SERVER_ACK: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._connection_lost),
            },
        )

        self._transitions.add_many(
            ExternalEvent.READER_EOF,
            {
                MachineState.INITIAL: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._reader_eof),
                MachineState.CONNECTED: TransitionDestination(MachineState.READER_CLOSED, self._reader_eof),
                MachineState.READER_CLOSED: TransitionDestination(MachineState.READER_CLOSED, self._reader_eof),
                MachineState.WRITER_CLOSED: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._reader_eof),
                MachineState.READER_WRITER_CLOSED: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._reader_eof),
                MachineState.WAITING_FOR_PACKET1: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._reader_eof),
                MachineState.WAITING_FOR_PACKET2: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._reader_eof),
                MachineState.WAITING_FOR_PACKET3: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._reader_eof),
                MachineState.WAITING_FOR_SERVER_ACK: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._reader_eof),
            },
        )

        self._transitions.add_many(
            ExternalEvent.WRITER_EOF,
            {
                MachineState.INITIAL: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._writer_eof),
                MachineState.CONNECTED: TransitionDestination(MachineState.WRITER_CLOSED, self._writer_eof),
                MachineState.READER_CLOSED: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._writer_eof),
                MachineState.WRITER_CLOSED: TransitionDestination(MachineState.WRITER_CLOSED, self._writer_eof),
                MachineState.READER_WRITER_CLOSED: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._writer_eof),
                MachineState.WAITING_FOR_PACKET1: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._writer_eof),
                MachineState.WAITING_FOR_PACKET2: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._writer_eof),
                MachineState.WAITING_FOR_PACKET3: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._writer_eof),
                MachineState.WAITING_FOR_SERVER_ACK: TransitionDestination(MachineState.READER_WRITER_CLOSED, self._writer_eof),
            },
        )

        self._transitions.add_many(
            ExternalEvent.WRITE_EMESSAGE,
            {
                MachineState.CONNECTED: TransitionDestination(MachineState.CONNECTED, self._write_emessage),
                MachineState.CONNECTED_WAITING_FOR_SERVER_ACK: TransitionDestination(
                    MachineState.CONNECTED_WAITING_FOR_SERVER_ACK, self._write_emessage
                ),
                MachineState.CONNECTED_WAITING_FOR_PACKET2: TransitionDestination(
                    MachineState.CONNECTED_WAITING_FOR_PACKET2, self._write_emessage
                ),
                MachineState.CONNECTED_WAITING_FOR_PACKET3: TransitionDestination(
                    MachineState.CONNECTED_WAITING_FOR_PACKET3, self._write_emessage
                ),
                MachineState.READER_CLOSED: TransitionDestination(MachineState.READER_CLOSED, self._write_emessage),
                MachineState.WAITING_FOR_PACKET1: TransitionDestination(MachineState.WAITING_FOR_PACKET1, self._write_emessage),
                MachineState.WAITING_FOR_PACKET2: TransitionDestination(MachineState.WAITING_FOR_PACKET2, self._write_emessage),
                MachineState.WAITING_FOR_PACKET3: TransitionDestination(MachineState.WAITING_FOR_PACKET3, self._write_emessage),
                MachineState.WAITING_FOR_SERVER_ACK: TransitionDestination(MachineState.WAITING_FOR_SERVER_ACK, self._write_emessage),
            },
        )

        self._transitions.add_many(
            ExternalEvent.RECEIVE_EMESSAGE,
            {
                MachineState.CONNECTED: TransitionDestination(MachineState.CONNECTED, self._receive_emessage),
                MachineState.CONNECTED_WAITING_FOR_SERVER_ACK: TransitionDestination(
                    MachineState.CONNECTED_WAITING_FOR_SERVER_ACK, self._receive_emessage
                ),
                MachineState.CONNECTED_WAITING_FOR_PACKET2: TransitionDestination(
                    MachineState.CONNECTED_WAITING_FOR_PACKET2, self._receive_emessage
                ),
                MachineState.CONNECTED_WAITING_FOR_PACKET3: TransitionDestination(
                    MachineState.CONNECTED_WAITING_FOR_PACKET3, self._receive_emessage
                ),
                MachineState.WRITER_CLOSED: TransitionDestination(MachineState.WRITER_CLOSED, self._receive_emessage),
            },
        )

        self._invalid_states: set[MachineState] = ALL_STATES - self._valid_states
        self._state: MachineState = MachineState.INITIAL
        self._data_ready_to_send: BytearrayBuilder = BytearrayBuilder()
        self._read_buffers: ReadBuffers = ReadBuffers(received_msg_max_size=received_msg_max_size)

        self._material_lock = RWLock()
        self._materials: list[CryptoMaterial] = []
        self._candidate_pair: SessionPair | None = None

        self.exception: Exception | None = None

    @property
    def key_material_idx(self) -> int | None:
        """
        Returns the index of the current key material, or None if no key material is set.

        This property is thread-safe.
        """
        with self._material_lock.readonly:
            return None if not self._materials else len(self._materials) - 1

    def _replace_current_material(self) -> None:
        # we lock _material_lock, so this method is thread-safe
        with self._material_lock.readwrite:
            if self._candidate_pair is None:
                raise RuntimeError("candidate pair not set")
            new_idx: int = len(self._materials)
            self._materials.append(
                CryptoMaterial(pair=self._candidate_pair, tbox=SecretBox(self._candidate_pair.tx), rbox=SecretBox(self._candidate_pair.rx))
            )
            self._candidate_pair = None
            logger.info("Switched to new session keys (index %d)", new_idx)

    def _get_material(self, idx: int | None = None) -> tuple[CryptoMaterial, int]:
        # we don't lock _material_lock, so this method is not thread-safe
        # be sure to lock _material_lock (read-only) before calling this method
        if not self._materials:
            raise RuntimeError("session keys not yet calculated")
        if idx is None:
            # return the current material
            return self._materials[-1], len(self._materials) - 1
        # return the material with the given index
        try:
            return self._materials[idx], idx
        except IndexError as ex:
            raise RuntimeError("unknown crypto material") from ex

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
        to avoid to block the event loop.

        This method is thread-safe.

        Args:
            msg: The encrypted message to decrypt, as a bytes-like object.

        Returns:
            The decrypted message as bytes.
            The message ID associated with the decrypted message.
        """
        emsg: EncryptedMessage = EncryptedMessage.from_bytes(msg)
        with self._material_lock.readonly:
            material, _ = self._get_material(emsg.session_keys_idx)
            plaintext = material.rbox.decrypt(emsg)
        return plaintext, emsg.msg_id

    def release_encrypted_message(self, mv: Buffer) -> None:
        self._read_buffers.release_bytearray(mv)

    def receive_data(self, nbytes: int) -> list[MachineProducedEvent]:
        self._read_buffers.buffer_updated(nbytes)
        events: list[MachineProducedEvent] = []
        try:
            while True:
                mtype = self._read_buffers.peek_message_type()
                if mtype is None:
                    # not enough data to determine the message type
                    return events
                old_state = self._state
                ev: MachineProducedEvent | None = None
                match mtype:
                    case MessageType.KX_N_PACKET1 | MessageType.KX_KK_PACKET1 | MessageType.KX_XX_PACKET1:
                        ev = self.trigger_receive_packet1()
                    case MessageType.KX_KK_PACKET2 | MessageType.KX_XX_PACKET2:
                        ev = self.trigger_receive_packet2()
                    case MessageType.KX_XX_PACKET3:
                        ev = self.trigger_receive_packet3()
                    case MessageType.KX_SERVER_ACK:
                        ev = self.trigger_receive_server_ack()
                    case MessageType.ENCRYPTED_MESSAGE:
                        ev = self.trigger_receive_emessage()
                    case _:
                        raise RuntimeError(f"Unknown message type: {mtype}")  # noqa: TRY301
                if not ev:
                    # there was not enough available data to advance the state
                    return events
                events.append(ev)
                if old_state.kx_is_pending() and self._state == MachineState.CONNECTED and (kx_ev := self._complete_kx()):
                    events.append(kx_ev)

        except Exception as ex:
            self._state = MachineState.READER_WRITER_CLOSED
            if kx_ev := self._fail_kx(ex):
                events.append(kx_ev)
                return events
            raise

    def trigger_connection_lost(self, exc: Exception | None) -> MachineProducedEvent | None:
        return self._trigger(ExternalEvent.CONNECTION_LOST, exc)

    def trigger_reader_eof(self) -> MachineProducedEvent | None:
        return self._trigger(ExternalEvent.READER_EOF)

    def trigger_writer_eof(self) -> MachineProducedEvent | None:
        return self._trigger(ExternalEvent.WRITER_EOF)

    def trigger_write_emessage(self, emsg: EncryptedMessage) -> MachineProducedEvent | None:
        return self._trigger(ExternalEvent.WRITE_EMESSAGE, emsg)

    def trigger_connection_made(self) -> MachineProducedEvent | None:
        return self._trigger(ExternalEvent.CONNECTION_MADE)

    def trigger_receive_packet1(self) -> MachineProducedEvent | None:
        return self._trigger(ExternalEvent.RECEIVE_PACKET1)

    def trigger_receive_packet2(self) -> MachineProducedEvent | None:
        return self._trigger(ExternalEvent.RECEIVE_PACKET2)

    def trigger_receive_packet3(self) -> MachineProducedEvent | None:
        return self._trigger(ExternalEvent.RECEIVE_PACKET3)

    def trigger_receive_emessage(self) -> MachineProducedEvent | None:
        return self._trigger(ExternalEvent.RECEIVE_EMESSAGE)

    def trigger_receive_server_ack(self) -> MachineProducedEvent | None:
        return self._trigger(ExternalEvent.RECEIVE_SERVER_ACK)

    def trigger_rekey(self) -> None:
        pass

    def _trigger(self, ev: ExternalEvent, *args) -> MachineProducedEvent | None:  # noqa: ANN002
        """
        Triggers a state transition in the state machine based on the given event and arguments.

        Args:
            ev: The TransitionEvent that triggers the state transition.
            *args: Additional arguments to pass to the callback function associated with the transition.

        Returns:
            The result of the callback function associated with the transition.
        """
        try:
            dest = self._transitions.get(ev, self._state)
            e = dest.callback(*args)
            self._state = dest.state
            return e
        except Exception as ex:
            self._state = MachineState.READER_WRITER_CLOSED
            if kx_ev := self._fail_kx(ex):
                return kx_ev
            raise

    def _receive_emessage(self) -> MachineProducedEvent | None:
        # may raise MessageTooBigException if the received message is too big
        msg = self._read_buffers.consume_message()
        return None if msg is None else ReceivedEncryptedMessage(msg)

    def _connection_lost(self, exc: Exception | None) -> MachineProducedEvent | None:
        # _reader_eof may have been called before this method, so we check if the exception is already set
        if self.exception is None:
            self.exception = EOF_EXCEPTION if exc is None else exc
        return self._fail_kx(self.exception)

    def _reader_eof(self) -> MachineProducedEvent | None:
        if self.exception is None:
            self.exception = EOF_EXCEPTION
        return self._fail_kx(self.exception)

    def _writer_eof(self) -> MachineProducedEvent | None:
        return self._fail_kx(EOF_EXCEPTION)

    def _write_emessage(self, emsg: EncryptedMessage) -> None:
        # called by Protocol to prepare sending a message to the server
        self._data_ready_to_send.add(emsg)

    def _connection_made(self) -> None:
        pass

    def _fail_kx(self, exc: Exception) -> MachineProducedEvent | None:
        if self._kx_finished:
            return None
        self._kx_finished = True
        if isinstance(exc, KeyExchangeException):
            return KxFailed(exc)
        new_ex = KeyExchangeException()
        new_ex.__cause__ = exc
        return KxFailed(new_ex)

    def _complete_kx(self) -> MachineProducedEvent | None:
        if self._kx_finished:
            return None
        self._kx_finished = True
        return KxCompleted()

    def encrypt_message(self, msg: Buffer, msg_id: int) -> EncryptedMessage:
        """
        Encrypts a message using the session keys established during the key exchange.

        Encryption may take some time, so it is recommended to call this method in a separate thread
        to avoid to block the event loop.

        This method is thread-safe.

        Args:
            msg: The message to encrypt, as a bytes-like object.
            msg_id: The message ID to associate with the encrypted message.

        Returns:
            A bytearray containing the encrypted message, ready to be sent over the network.
        """
        with self._material_lock.readonly:
            mat, idx = self._get_material()
            ciphertext = mat.tbox.encrypt(msg, msg_id=msg_id, max_msg_size=self.sent_msg_max_size)
        return EncryptedMessage(ciphertext, msg_id, idx)

    def data_to_send(self) -> bytearray:
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

    # INITIAL                          => connection_made    => WAITING_FOR_SERVER_ACK
    # WAITING_FOR_SERVER_ACK           => receive_server_ack => CONNECTED
    # CONNECTED                        => rekey              => CONNECTED_WAITING_FOR_SERVER_ACK
    # CONNECTED_WAITING_FOR_SERVER_ACK => receive_server_ack => CONNECTED

    _valid_states = frozenset(
        {
            MachineState.INITIAL,  # initial state, we can send packet1
            MachineState.WAITING_FOR_SERVER_ACK,  # waiting for server ACK after it has processed packet1
            MachineState.CONNECTED,  # key exchange completed successfully
            MachineState.CONNECTED_WAITING_FOR_SERVER_ACK,  # rekeying, waiting for server ACK
            MachineState.READER_CLOSED,  # reader closed, we can still send data
            MachineState.WRITER_CLOSED,  # writer closed, we can still read data
            MachineState.READER_WRITER_CLOSED,  # both reader and writer closed, final state
        },
    )

    def __init__(
        self,
        server_public_key: KxPublicKey,
        *,
        psk: Psk | None = None,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
    ) -> None:
        """
        Initializes the KX_N_ClientStateMachine.

        Args:
            server_public_key: The public key of the server to which we are connecting.
            psk: An optional pre-shared key to use for the key exchange.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        self._packet1: KX_N_Packet1 | None = None

        super().__init__(sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)

        self._transitions.add_one(
            ExternalEvent.CONNECTION_MADE,
            MachineState.INITIAL,
            MachineState.WAITING_FOR_SERVER_ACK,
            self._kx_start,
        )
        self._transitions.add_one(
            ExternalEvent.REKEY,
            MachineState.CONNECTED,
            MachineState.CONNECTED_WAITING_FOR_SERVER_ACK,
            self._kx_start,
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_SERVER_ACK,
            MachineState.WAITING_FOR_SERVER_ACK,
            MachineState.CONNECTED,
            self._receive_server_ack,
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_SERVER_ACK,
            MachineState.CONNECTED_WAITING_FOR_SERVER_ACK,
            MachineState.CONNECTED,
            self._receive_server_ack,
        )

        self._transitions.keep_only_valid_states(self._valid_states)

        self._server_public_key: KxPublicKey = server_public_key
        self._psk = psk

    def _receive_server_ack(self) -> MachineProducedEvent | None:
        if self._candidate_pair is None:
            raise RuntimeError("candidate pair not set")
        b = self._read_buffers.consume_server_ack()
        if b is None:
            return None  # not enough data to read the server ACK
        KX_Server_Ack.from_bytes(b)  # just to verify the message is well formed
        # switch to the new session keys (the server has already switched to them at this point)
        self._replace_current_material()
        self._packet1 = None
        return KxProgress()

    def _kx_start(self) -> None:
        if self._candidate_pair is not None or self._packet1 is not None:
            raise RuntimeError("Rekeying already in progress")
        self._candidate_pair, self._packet1 = client_init_kx_n(self._server_public_key, self._psk)
        self._data_ready_to_send.add(self._packet1)

    def get_peer_key(self) -> KxPublicKey | None:
        return self._server_public_key

    def trigger_rekey(self) -> None:
        logger.info("Rekeying requested")
        self._trigger(ExternalEvent.REKEY)


class KX_N_ServerStateMachine(BaseMachine):
    """
    KX_N_ServerStateMachine implements the server side of the KX_N key exchange protocol.
    """

    # INITIAL               => connection_made => WAITING_FOR_PACKET1
    # WAITING_FOR_PACKET1   => receive_packet1 => CONNECTED (initial key exchange)
    # CONNECTED             => receive_packet1 => CONNECTED (rekeying)

    _valid_states = frozenset(
        {
            MachineState.INITIAL,
            MachineState.CONNECTED,
            MachineState.READER_CLOSED,
            MachineState.WRITER_CLOSED,
            MachineState.READER_WRITER_CLOSED,
            MachineState.WAITING_FOR_PACKET1,
        },
    )

    def __init__(
        self,
        server_pair: KxPair,
        *,
        psk: Psk | None = None,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
    ) -> None:
        """
        Initializes the KX_N_ServerStateMachine.

        Args:
            server_pair: The KxPair instance representing the server's key exchange pair.
            psk: An optional pre-shared key to use for the key exchange.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)

        self._transitions.add_one(
            ExternalEvent.CONNECTION_MADE, MachineState.INITIAL, MachineState.WAITING_FOR_PACKET1, self._connection_made
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_PACKET1, MachineState.WAITING_FOR_PACKET1, MachineState.CONNECTED, self._receive_packet1
        )
        self._transitions.add_one(ExternalEvent.RECEIVE_PACKET1, MachineState.CONNECTED, MachineState.CONNECTED, self._receive_packet1)
        self._transitions.keep_only_valid_states(self._valid_states)

        self._server_pair: KxPair = server_pair
        self._psk: Psk | None = psk

    def _receive_packet1(self) -> MachineProducedEvent | None:
        # we expect to receive packet1 from the client, length KX_N_PACKET1BYTES
        packet1 = self._read_buffers.consume_kx_packet()
        if packet1 is None:
            # not enough data to read the packet1
            return None
        self._candidate_pair = self._server_pair.server_finish_kx_n(KX_N_Packet1.from_bytes(packet1), self._psk)
        # switch to the new session keys:
        # - next messages the server sends will be encrypted with the new session keys
        # - we will be able to decrypt messages from the client encrypted with the new session keys
        # - we are still able to decrypt messages from the client encrypted with the old session keys
        self._replace_current_material()
        # Send ACK to the client. When the client receives the ACK, it will switch to the new session keys.
        self._data_ready_to_send.add(KX_Server_Ack())
        return KxProgress()


class KX_KK_ClientStateMachine(BaseMachine):
    """
    KX_KK_ClientStateMachine implements the client side of the KX_KK key exchange protocol.
    """

    # INITIAL                       => connection_made => WAITING_FOR_PACKET2
    # WAITING_FOR_PACKET2           => receive_packet2 => CONNECTED
    # CONNECTED                     => rekey           => CONNECTED_WAITING_FOR_PACKET2
    # CONNECTED_WAITING_FOR_PACKET2 => receive_packet2 => CONNECTED

    _valid_states = frozenset(
        {
            MachineState.INITIAL,
            MachineState.CONNECTED,
            MachineState.CONNECTED_WAITING_FOR_PACKET2,
            MachineState.READER_CLOSED,
            MachineState.WRITER_CLOSED,
            MachineState.READER_WRITER_CLOSED,
            MachineState.WAITING_FOR_PACKET2,
        },
    )

    def __init__(
        self,
        client_pair: KxPair,
        server_public_key: KxPublicKey,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
    ) -> None:
        """
        Initializes the KX_KK_ClientStateMachine.

        Args:
            client_pair: The KxPair instance representing the client's key exchange pair.
            server_public_key: The public key of the server to which we are connecting.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)

        self._transitions.add_one(ExternalEvent.CONNECTION_MADE, MachineState.INITIAL, MachineState.WAITING_FOR_PACKET2, self._kx_start)
        self._transitions.add_one(ExternalEvent.REKEY, MachineState.CONNECTED, MachineState.CONNECTED_WAITING_FOR_PACKET2, self._kx_start)
        self._transitions.add_one(
            ExternalEvent.RECEIVE_PACKET2, MachineState.WAITING_FOR_PACKET2, MachineState.CONNECTED, self._receive_packet2
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_PACKET2, MachineState.CONNECTED_WAITING_FOR_PACKET2, MachineState.CONNECTED, self._receive_packet2
        )

        self._transitions.keep_only_valid_states(self._valid_states)

        self._client_pair: KxPair = client_pair
        self._server_public_key: KxPublicKey = server_public_key
        self._kx_state: KxKkClientState | None = None

    def _receive_packet2(self) -> MachineProducedEvent | None:
        if self._kx_state is None:
            raise RuntimeError("kx state not set")
        # we expect to receive packet2 from the server, length KX_KK_PACKET2BYTES
        packet2 = self._read_buffers.consume_kx_packet()
        if packet2 is None:
            # not enough data to read the packet2
            return None
        self._kx_state.client_finish_kx_kk(KX_KK_Packet2.from_bytes(packet2))
        assert self._kx_state.session_pair is not None
        self._candidate_pair = self._kx_state.session_pair
        # switch to the new session keys. the server has already switched to them at this point.
        self._replace_current_material()
        self._kx_state = None
        return KxProgress()

    def _kx_start(self) -> None:
        if self._kx_state is not None:
            raise RuntimeError("Rekeying already in progress")
        self._kx_state = self._client_pair.client_init_kx_kk(self._server_public_key)
        assert self._kx_state is not None
        assert self._kx_state.packet1 is not None
        self._data_ready_to_send.add(self._kx_state.packet1)

    def get_peer_key(self) -> KxPublicKey | None:
        return self._server_public_key

    def trigger_rekey(self) -> None:
        self._trigger(ExternalEvent.REKEY)


class KX_KK_ServerStateMachine(BaseMachine):
    """
    KX_KK_ServerStateMachine implements the server side of the KX_KK key exchange protocol.
    """

    # INITIAL               => connection_made => WAITING_FOR_PACKET1
    # WAITING_FOR_PACKET1   => receive_packet1 => CONNECTED (initial key exchange)
    # CONNECTED             => receive_packet1 => CONNECTED (rekeying)

    _valid_states = frozenset(
        {
            MachineState.INITIAL,
            MachineState.CONNECTED,
            MachineState.READER_CLOSED,
            MachineState.WRITER_CLOSED,
            MachineState.READER_WRITER_CLOSED,
            MachineState.WAITING_FOR_PACKET1,
        },
    )

    def __init__(
        self,
        server_pair: KxPair,
        client_public_key: KxPublicKey,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
    ) -> None:
        """
        Initializes the KX_KK_ServerStateMachine.

        Args:
            server_pair: The KxPair instance representing the server's key exchange pair.
            client_public_key: The public key of the client that is connecting to the server.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)

        self._transitions.add_one(
            ExternalEvent.CONNECTION_MADE, MachineState.INITIAL, MachineState.WAITING_FOR_PACKET1, self._connection_made
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_PACKET1, MachineState.WAITING_FOR_PACKET1, MachineState.CONNECTED, self._receive_packet1
        )
        self._transitions.add_one(ExternalEvent.RECEIVE_PACKET1, MachineState.CONNECTED, MachineState.CONNECTED, self._receive_packet1)

        self._transitions.keep_only_valid_states(self._valid_states)

        self._server_pair: KxPair = server_pair
        self._client_public_key: KxPublicKey = client_public_key

    def _receive_packet1(self) -> MachineProducedEvent | None:
        # we expect to receive packet1 from the client, length KX_KK_PACKET1BYTES
        packet1 = self._read_buffers.consume_kx_packet()
        if packet1 is None:
            # not enough data to read the packet1
            return None
        self._candidate_pair, packet2 = self._server_pair.server_process_kx_kk(self._client_public_key, KX_KK_Packet1.from_bytes(packet1))
        # when the client receives packet2, it will switch to the new session keys
        self._data_ready_to_send.add(packet2)
        # switch to the new session keys server side
        self._replace_current_material()
        return KxProgress()

    def get_peer_key(self) -> KxPublicKey | None:
        return self._client_public_key


class KX_XX_ClientStateMachine(BaseMachine):
    """
    KX_XX_ClientStateMachine implements the client side of the KX_XX key exchange protocol.
    """

    # INITIAL                          => connection_made    => WAITING_FOR_PACKET2
    # WAITING_FOR_PACKET2              => receive_packet2    => WAITING_FOR_SERVER_ACK
    # WAITING_FOR_SERVER_ACK           => receive_server_ack => CONNECTED
    # CONNECTED                        => rekey              => CONNECTED_WAITING_FOR_PACKET2
    # CONNECTED_WAITING_FOR_PACKET2    => receive_packet2    => CONNECTED_WAITING_FOR_SERVER_ACK
    # CONNECTED_WAITING_FOR_SERVER_ACK => receive_server_ack => CONNECTED

    _valid_states = frozenset(
        {
            MachineState.INITIAL,
            MachineState.CONNECTED,
            MachineState.CONNECTED_WAITING_FOR_PACKET2,
            MachineState.CONNECTED_WAITING_FOR_SERVER_ACK,
            MachineState.READER_CLOSED,
            MachineState.WRITER_CLOSED,
            MachineState.READER_WRITER_CLOSED,
            MachineState.WAITING_FOR_PACKET2,
            MachineState.WAITING_FOR_SERVER_ACK,
        },
    )

    def __init__(
        self,
        client_pair: KxPair,
        *,
        psk: Psk | None = None,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
        validate_peer_key: Callable[[KxPublicKey], None] | None = None,
    ) -> None:
        """
        Initializes the KX_XX_ClientStateMachine.

        Args:
            client_pair: The KxPair instance representing the client's key exchange pair.
            psk: An optional pre-shared key to use for the key exchange.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)
        self.validate_peer_key = validate_peer_key

        self._transitions.add_one(ExternalEvent.CONNECTION_MADE, MachineState.INITIAL, MachineState.WAITING_FOR_PACKET2, self._kx_start)
        self._transitions.add_one(ExternalEvent.REKEY, MachineState.CONNECTED, MachineState.CONNECTED_WAITING_FOR_PACKET2, self._kx_start)
        self._transitions.add_one(
            ExternalEvent.RECEIVE_PACKET2, MachineState.WAITING_FOR_PACKET2, MachineState.WAITING_FOR_SERVER_ACK, self._receive_packet2
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_PACKET2,
            MachineState.CONNECTED_WAITING_FOR_PACKET2,
            MachineState.CONNECTED_WAITING_FOR_SERVER_ACK,
            self._receive_packet2,
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_SERVER_ACK, MachineState.WAITING_FOR_SERVER_ACK, MachineState.CONNECTED, self._receive_server_ack
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_SERVER_ACK,
            MachineState.CONNECTED_WAITING_FOR_SERVER_ACK,
            MachineState.CONNECTED,
            self._receive_server_ack,
        )

        self._transitions.keep_only_valid_states(self._valid_states)

        self._client_pair: KxPair = client_pair
        self._psk: Psk | None = psk
        self._server_public_key: KxPublicKey | None = None  # will be set after receiving packet2 from the server
        self._kx_state: KxXxClientState | None = None

    def _receive_packet2(self) -> MachineProducedEvent | None:
        if self._kx_state is None:
            raise RuntimeError("kx state not set")
        # we expect to receive packet2 from the server, length KX_XX_PACKET2BYTES
        packet2 = self._read_buffers.consume_kx_packet()
        if packet2 is None:
            # not enough data to read the packet2
            return None
        self._kx_state.client_process_kx_xx(KX_XX_Packet2.from_bytes(packet2))
        assert self._kx_state.packet3
        assert self._kx_state.session_pair is not None
        assert self._kx_state.server_public_key is not None
        self._candidate_pair = self._kx_state.session_pair
        if self._server_public_key is None:  # only validate the server public key once
            self._server_public_key = self._kx_state.server_public_key
            if self.validate_peer_key is not None:
                try:
                    self.validate_peer_key(self._server_public_key)
                except InvalidPeerKeyException as ex:
                    return self._fail_kx(ex)
                except Exception as ex:  # noqa: BLE001
                    # ensure the exception is of type InvalidPeerKeyException
                    new_ex = InvalidPeerKeyException()
                    new_ex.__cause__ = ex
                    return self._fail_kx(new_ex)
        # send packet3 to the server
        self._data_ready_to_send.add(self._kx_state.packet3)
        return KxProgress()

    def _receive_server_ack(self) -> MachineProducedEvent | None:
        if self._kx_state is None:
            raise RuntimeError("kx state not set")
        b = self._read_buffers.consume_server_ack()
        if b is None:
            return None
        KX_Server_Ack.from_bytes(b)  # just to verify the message is well formed
        # switch to the new session keys (the server has already switched to them at this point)
        self._replace_current_material()
        self._kx_state = None
        return KxProgress()

    def _kx_start(self) -> None:
        if self._kx_state is not None:
            raise RuntimeError("Rekeying already in progress")
        self._kx_state = self._client_pair.client_init_kx_xx(self._psk)
        assert self._kx_state is not None
        assert self._kx_state.packet1 is not None
        self._data_ready_to_send.add(self._kx_state.packet1)

    def get_peer_key(self) -> KxPublicKey | None:
        return self._server_public_key

    def trigger_rekey(self) -> None:
        self._trigger(ExternalEvent.REKEY)


class KX_XX_ServerStateMachine(BaseMachine):
    """
    KX_XX_ServerStateMachine implements the server side of the KX_XX key exchange protocol.
    """

    # INITIAL                       => connection_made => WAITING_FOR_PACKET1
    # WAITING_FOR_PACKET1           => receive_packet1 => WAITING_FOR_PACKET3 (initial key exchange)
    # CONNECTED                     => receive_packet1 => CONNECTED_WAITING_FOR_PACKET3 (rekeying)
    # WAITING_FOR_PACKET3           => receive_packet3 => CONNECTED
    # CONNECTED_WAITING_FOR_PACKET3 => receive_packet3 => CONNECTED

    _valid_states = frozenset(
        {
            MachineState.INITIAL,
            MachineState.CONNECTED,
            MachineState.CONNECTED_WAITING_FOR_PACKET3,
            MachineState.READER_CLOSED,
            MachineState.WRITER_CLOSED,
            MachineState.READER_WRITER_CLOSED,
            MachineState.WAITING_FOR_PACKET1,
            MachineState.WAITING_FOR_PACKET3,
        },
    )

    def __init__(
        self,
        server_pair: KxPair,
        *,
        psk: Psk | None = None,
        received_msg_max_size: int = 2**20,
        sent_msg_max_size: int = 2**20,
        validate_peer_key: Callable[[KxPublicKey], None] | None = None,
    ) -> None:
        """
        Initializes the KX_XX_ServerStateMachine.

        Args:
            server_pair: The KxPair instance representing the server's key exchange pair.
            psk: An optional pre-shared key to use for the key exchange.
            received_msg_max_size: The maximum size of messages that can be received, in bytes.
            sent_msg_max_size: The maximum size of messages that can be sent, in bytes.
        """
        super().__init__(sent_msg_max_size=sent_msg_max_size, received_msg_max_size=received_msg_max_size)
        self.validate_peer_key = validate_peer_key

        self._transitions.add_one(
            ExternalEvent.CONNECTION_MADE, MachineState.INITIAL, MachineState.WAITING_FOR_PACKET1, self._connection_made
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_PACKET1, MachineState.WAITING_FOR_PACKET1, MachineState.WAITING_FOR_PACKET3, self._receive_packet1
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_PACKET1,
            MachineState.CONNECTED,
            MachineState.CONNECTED_WAITING_FOR_PACKET3,
            self._receive_packet1,
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_PACKET3, MachineState.WAITING_FOR_PACKET3, MachineState.CONNECTED, self._receive_packet3
        )
        self._transitions.add_one(
            ExternalEvent.RECEIVE_PACKET3,
            MachineState.CONNECTED_WAITING_FOR_PACKET3,
            MachineState.CONNECTED,
            self._receive_packet3,
        )

        self._transitions.keep_only_valid_states(self._valid_states)

        self._server_pair: KxPair = server_pair
        self._psk: Psk | None = psk
        self._client_public_key: KxPublicKey | None = None  # will be set after receiving packet1 from the client
        self._kx_state: KxXxServerState | None = None

    def _receive_packet1(self) -> MachineProducedEvent | None:
        if self._kx_state is not None:
            raise RuntimeError("kx state already set")
        # we expect to receive packet1 from the client, length KX_XX_PACKET1BYTES
        packet1 = self._read_buffers.consume_kx_packet()
        if packet1 is None:
            # not enough data to read the packet1
            return None
        self._kx_state = self._server_pair.server_process_kx_xx(KX_XX_Packet1.from_bytes(packet1), self._psk)
        assert self._kx_state.packet2
        # send packet2 to the client
        self._data_ready_to_send.add(self._kx_state.packet2)
        return KxProgress()

    def _receive_packet3(self) -> MachineProducedEvent | None:
        if self._kx_state is None:
            raise RuntimeError("kx state not set")
        # self._state == MState.WAITING_FOR_PACKET3
        packet3 = self._read_buffers.consume_kx_packet()
        if packet3 is None:
            # not enough data to read the packet3
            return None
        self._kx_state.server_finish_kx_xx(KX_XX_Packet3.from_bytes(packet3))
        assert self._kx_state.session_pair is not None
        assert self._kx_state.client_public_key is not None
        self._candidate_pair = self._kx_state.session_pair
        if self._client_public_key is None:  # only validate the client public key once
            self._client_public_key = self._kx_state.client_public_key
            if self.validate_peer_key is not None:
                try:
                    self.validate_peer_key(self._client_public_key)
                except InvalidPeerKeyException as ex:
                    return self._fail_kx(ex)
                except Exception as ex:  # noqa: BLE001
                    # ensure the exception is of type InvalidPeerKeyException
                    new_ex = InvalidPeerKeyException()
                    new_ex.__cause__ = ex
                    return self._fail_kx(new_ex)

        # switch to the new session keys.
        self._replace_current_material()
        self._kx_state = None

        # send ACK to the client
        # when the client receives the ACK, it will switch to the new session keys
        self._data_ready_to_send.add(KX_Server_Ack())
        return KxProgress()

    def get_peer_key(self) -> KxPublicKey | None:
        return self._client_public_key
