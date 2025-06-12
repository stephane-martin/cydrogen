from collections.abc import Buffer
from dataclasses import dataclass
from typing import Self

from ._basekey import BaseKey
from ._secretbox import SecretBoxKey

class Psk(BaseKey):
    """
    The Psk class represents a pre-shared key (PSK).

    Pre-shared keys are used optionally by the key exchange algorithms.
    """

@dataclass
class SessionPair:
    """
    The SessionPair class represents a pair of symmetric keys to be used to secure a session with a peer.

    Attributes:
        rx: The symmetric key used to decrypt messages received from the peer.
        tx: The symmetric key used to encrypt messages sent to the peer.
    """

    rx: SecretBoxKey
    tx: SecretBoxKey

class KxPublicKey:
    """
    The KxPublicKey class represents a public key used in key exchange.

    KxPublicKey implements the buffer protocol, allowing it to be used as a byte-like object.
    """
    def __init__(self, kp: bytes | str | Buffer | Self):
        """
        Initializes a KxPublicKey instance.

        Args:
            kp: The public key data to initialize the KxPublicKey instance with.

        Raises:
            ValueError: If the provided key data is invalid.
        """
        ...

    def __str__(self) -> str:
        """
        Returns a string representation of the KxPublicKey (base64 encoded).

        Returns:
            A base64 encoded string representation of the public key.
        """
        ...

    def __repr__(self) -> str: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

class KxSecretKey:
    """
    The KxSecretKey class represents a secret key used in key exchange.

    KxSecretKey implements the buffer protocol, allowing it to be used as a byte-like object.
    """
    def __init__(self, kp: bytes | str | Buffer | Self):
        """
        Initializes a KxSecretKey instance.

        Args:
            kp: The secret key data to initialize the KxSecretKey instance with.

        Raises:
            ValueError: If the provided key data is invalid.
        """
        ...

    def __str__(self) -> str:
        """
        Returns a string representation of the KxSecretKey (base64 encoded).

        Returns:
            A base64 encoded string representation of the secret key.
        """
        ...

    def __repr__(self) -> str: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

class KxPair:
    """
    KxPair represents a pair of public/secret keys used in key exchange.

    KxPair implements the buffer protocol, allowing it to be used as a byte-like object.
    """
    def __init__(self, kp: str | bytes | Buffer | Self):
        """
        Initializes a KxPair instance.

        Args:
            kp: The key pair data to initialize the KxPair instance with.

        Raises:
            ValueError: If the provided key pair data is invalid.
        """
        ...

    def __str__(self) -> str:
        """
        Returns a string representation of the KxPair (base64 encoded).

        Returns:
            A base64 encoded string representation of the key pair.
        """
        ...

    def public_key(self) -> KxPublicKey:
        """
        Returns the public key part of the KxPair.

        Returns:
            A KxPublicKey instance representing the public key part of the KxPair.
        """
        ...

    def secret_key(self) -> KxSecretKey:
        """
        Returns the secret key part of the KxPair.

        Returns:
            A KxSecretKey instance representing the secret key part of the KxPair.
        """
        ...

    @classmethod
    def gen(cls) -> Self:
        """
        Generates a new KxPair instance with a random key pair.

        Returns:
            A new KxPair instance with a randomly generated public and secret key.
        """
        ...

    def __repr__(self) -> str: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

def kx_n_gen_session_and_packet(peer: KxPublicKey, psk: Psk | None = None) -> tuple[SessionPair, bytes]:
    """
    Generate session keys and a packet with an ephemeral public key to send to the server

    Args:
        peer: The public key of the peer to exchange keys with.
        psk: An optional pre-shared key to use in the key exchange.

    Returns:
        A tuple containing a SessionPair with the symmetric keys for the session and a bytes object
        representing the packet to send to the server.

    Raises:
        KeyExchangeException: If the operation fails.
    """
    ...

def kx_n_gen_session_from_packet(static_kp: KxPair, packet1: bytes, psk: Psk | None = None) -> SessionPair:
    """
    Generate session keys from a received packet and the static key pair.

    Args:
        static_kp: The static key pair used for the key exchange.
        packet1: The received packet containing the ephemeral public key and other data.
        psk: An optional pre-shared key to use in the key exchange.

    Returns:
        A SessionPair with the symmetric keys for the session.

    Raises:
        KeyExchangeException: If the operation fails. In particular, this exception is raised if the packet is invalid or if the key exchange fails.
    """
    ...
