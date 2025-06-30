from collections.abc import Buffer
from typing import Self

from ._basekey import BaseKey
from ._secretbox import SecretBoxKey

KX_N_PACKET1BYTES: int
"""
The number of bytes of the packet sent to the server in key exchange variant N.
"""

KX_KK_PACKET1BYTES: int
"""
The number of bytes of the first packet sent to the server in key exchange variant KK.
"""

KX_KK_PACKET2BYTES: int
"""
The number of bytes of the second packet sent to the client in key exchange variant KK.
"""

KX_XX_PACKET1BYTES: int
KX_XX_PACKET2BYTES: int
KX_XX_PACKET3BYTES: int

KX_PAIR_SIZE: int
"""
The size of a key exchange pair (KxPair) in bytes.
"""

class Psk(BaseKey):
    """
    The Psk class represents a pre-shared key (PSK).

    Pre-shared keys are used optionally by the key exchange algorithms.
    """
    def __init__(self, data: str | bytes | None) -> None: ...
    def __eq__(self, other: object) -> bool: ...

class SessionPair:
    """
    The SessionPair class represents a pair of symmetric keys to be used to secure a session with a peer.

    Attributes:
        rx: The symmetric key used to decrypt messages received from the peer.
        tx: The symmetric key used to encrypt messages sent to the peer.
    """

    rx: SecretBoxKey
    tx: SecretBoxKey

    def __init__(self, rx: SecretBoxKey, tx: SecretBoxKey) -> None:
        """
        Initializes a SessionPair instance.

        Args:
            rx: The symmetric key used to decrypt messages received from the peer.
            tx: The symmetric key used to encrypt messages sent to the peer.
        """

    def __eq__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...

class KxPublicKey:
    """
    The KxPublicKey class represents a public key used in key exchange.

    KxPublicKey implements the buffer protocol, allowing it to be used as a byte-like object.
    """
    def __init__(self, kp: bytes | str | Buffer | Self) -> None:
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

    def __eq__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

class KxSecretKey:
    """
    The KxSecretKey class represents a secret key used in key exchange.

    KxSecretKey implements the buffer protocol, allowing it to be used as a byte-like object.
    """
    def __init__(self, kp: bytes | str | Buffer | Self) -> None:
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

    def __eq__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

class KxKkClientState:
    """
    KxKkClientState represents the state of a key exchange variant KK from the client side.

    `session_pair` is initially `None` and will be set after `client_finish_kx_kk` is called.

    Attributes:
        packet1: The packet to send to the server as part of the key exchange.
        session_pair: The session pair containing the symmetric keys for the session.
    """

    packet1: bytes
    session_pair: SessionPair | None

    def client_finish_kx_kk(self, packet2: Buffer) -> Self:
        """
        Finalizes the key exchange variant KK from the client side.

        Args:
            packet2: The packet received from the server.

        Returns:
            The updated state including the session keys.

        Raises:
            KeyExchangeException: If the operation fails. In particular, this exception is raised if the packet is invalid or if the key exchange fails.
        """
        ...

class KxXxClientState:
    packet1: bytes
    packet3: bytes
    session_pair: SessionPair | None
    server_public_key: KxPublicKey | None

    def __init__(self, client_kp: KxPair, psk: Psk | None = None) -> None: ...
    def __str__(self) -> str: ...
    def client_process_kx_xx(self, packet2: Buffer) -> Self: ...

class KxXxServerState:
    packet2: bytes
    session_pair: SessionPair | None
    client_public_key: KxPublicKey | None

    def __init__(self, psk: Psk | None = None) -> None: ...
    def __str__(self) -> str: ...
    def server_finish_kx_xx(self, packet3: Buffer) -> Self: ...

class KxPair:
    """
    KxPair represents a pair of public/secret keys used in key exchange.

    KxPair implements the buffer protocol, allowing it to be used as a byte-like object.
    """
    def __init__(self, kp: str | bytes | Buffer | Self) -> None:
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

    def server_finish_kx_n(self, packet1: Buffer, psk: Psk | None = None) -> SessionPair:
        """
        See [cydrogen.server_finish_kx_n][]
        """

    def client_init_kx_kk(self, server_public_key: KxPublicKey) -> KxKkClientState:
        """
        Initiate a key exchange variant KK from the client side.

        Args:
            server_public_key: The public key of the server to exchange keys with.

        Returns:
            A state object containing the first packet to send to the server.

        Raises:
            KeyExchangeException: If the operation fails.
        """
        pass

    def server_process_kx_kk(self, client_public_key: KxPublicKey, packet1: Buffer) -> tuple[SessionPair, bytes]:
        """
        Process a key exchange variant KK from the server side.

        Args:
            client_public_key: The public key of the client to exchange keys with.
            packet1: The packet received from the client.

        Returns:
            A SessionPair with the symmetric keys for the session.
            A bytes object representing the packet to send back to the client.

        Raises:
            KeyExchangeException: If the operation fails. In particular, this exception is raised if the packet is invalid or if the key exchange fails.
        """
        ...

    def client_init_kx_xx(self, psk: Psk | None = None) -> KxXxClientState: ...
    def server_process_kx_xx(self, packet1: Buffer, psk: Psk | None = None) -> KxXxServerState: ...
    @classmethod
    def gen(cls) -> Self:
        """
        Generates a new KxPair instance with a random key pair.

        Returns:
            A new KxPair instance with a randomly generated public and secret key.
        """
        ...

    @classmethod
    def from_keys(cls, public_key: KxPublicKey | str | bytes | Buffer, secret_key: KxSecretKey | str | bytes | Buffer) -> Self:
        """
        Creates a KxPair instance from a public key and a secret key.

        Args:
            public_key: The public key to use.
            secret_key: The secret key to use.

        Returns:
            A KxPair instance initialized with the provided keys.

        Raises:
            ValueError: If the provided keys are invalid.
        """
        ...

    def __repr__(self) -> str: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

def client_init_kx_n(server_public_key: KxPublicKey, psk: Psk | None = None) -> tuple[SessionPair, bytes]:
    """
    Initiate a key exchange variant N (anonymous client) from the client side.

    Args:
        server_public_key: The public key of the server to exchange keys with.
        psk: An optional pre-shared key to use in the key exchange.

    Returns:
        A tuple containing a SessionPair with the symmetric keys for the session.
        A bytes object representing the packet to send to the server.

    Raises:
        KeyExchangeException: If the operation fails.
    """
    ...

def server_finish_kx_n(server_kp: KxPair, packet1: Buffer, psk: Psk | None = None) -> SessionPair:
    """
    Finalize a key exchange variant N (anonymous client) from the server side.

    Args:
        server_kp: The server key pair.
        packet1: The packet received from the client.
        psk: An optional pre-shared key to use in the key exchange.

    Returns:
        A SessionPair with the symmetric keys for the session.

    Raises:
        KeyExchangeException: If the operation fails. In particular, this exception is raised if the packet is invalid or if the key exchange fails.
    """
    ...
