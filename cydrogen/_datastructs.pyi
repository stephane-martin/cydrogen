from collections.abc import Buffer
from enum import StrEnum
from typing import Self

from ._protocols import AsyncWriter, Writer

ENC_MSG_MARKER: bytes
"""
ENC_MSG_MARKER is the magic marker for encrypted messages.
"""

ENC_MSG_HEADER_SIZE: int
"""
ENC_MSG_HEADER_SIZE is the size of the header for encrypted messages.

It includes the magic marker (4 bytes), length of the message (8 bytes), and message ID (8 bytes).
"""

KX_N_PACKET1_MARKER: bytes
KX_KK_PACKET1_MARKER: bytes
KX_KK_PACKET2_MARKER: bytes
KX_XX_PACKET1_MARKER: bytes
KX_XX_PACKET2_MARKER: bytes
KX_XX_PACKET3_MARKER: bytes

class MessageType(StrEnum):
    ENCRYPTED_MESSAGE = ...
    KX_N_PACKET1 = ...
    KX_KK_PACKET1 = ...
    KX_KK_PACKET2 = ...
    KX_XX_PACKET1 = ...
    KX_XX_PACKET2 = ...
    KX_XX_PACKET3 = ...

    @classmethod
    def from_marker(cls, marker: bytes | str) -> Self: ...
    def is_encrypted_message(self) -> bool: ...
    def is_kx_packet(self) -> bool: ...

class EncryptedMessage:
    """
    EncryptedMessage represents an encrypted message.

    EncryptedMessage encapsulates the ciphertext and the message ID. It is used to
    serialize an encrypted message to a bytes object that can be sent over the wire.

    The serialized format is as follows:
    - The first 4 bytes are a magic header (ENC_MSG_HEADER).
    - The next 8 bytes are the length (N) of the encrypted message.
    - The next 8 bytes are the message ID.
    - The rest is the encrypted message (N bytes).

    All attributes are readonly after initialization.

    Attributes:
        ciphertext: The encrypted message itself.
        msg_id: The message ID associated with the encrypted message.
    """

    ciphertext: Buffer
    msg_id: int

    def __init__(self, ctext: Buffer, msg_id: int) -> None:
        """
        Initialize the encrypted message.

        Args:
            ctext: The ciphertext of the encrypted message.
            msg_id: The message ID associated with the encrypted message.

        Raises:
            ValueError: If ctext is None.
        """
        ...

    def __bytes__(self) -> bytes:
        """
        Return the serialized form of the encrypted message as bytes.

        Returns:
            bytes: The serialized encrypted message.
        """
        ...

    def __len__(self) -> int:
        """
        Return the length of the framed, encrypted message in bytes, including the header and message ID.

        Returns:
            int: The length of the encrypted message.
        """
        ...

    def writeto(self, out: Writer) -> int:
        """
        Write the framed encrypted message to a file-like/path-like object.

        Args:
            out: A file-like object to write the message to.

        Returns:
            The number of bytes written to the file object.

        Raises:
            ValueError: If the file object is None.
            TypeError: If the file object is not a file-like/path-like object.
            OSError: If the write operation fails.
        """
        ...

    async def awriteto(self, out: AsyncWriter) -> None:
        """
        Asynchronously write the framed encrypted message to an async writer.

        Args:
            out: An async writer to write the message to.

        Raises:
            ValueError: If the async writer is None.
            TypeError: If the async writer is not an async writer.
        """
        ...

    @classmethod
    def from_bytes(cls, framed: bytes | Buffer, *, max_msg_size: int | None = None) -> Self:
        """
        Create an EncryptedMessage from a framed bytes object.

        Args:
            framed: A bytes-like object containing the framed ciphertext.
            max_msg_size: Optional maximum size of the message. If provided, raises ValueError
                          if the message size exceeds this limit.

        Returns:
            An instance of EncryptedMessage.

        Raises:
            ValueError: If the framed message is None or if parsing fails.
            OSError: If reading the message header or message fails.
        """
        ...

    def __eq__(self, other: object) -> bool: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...
    def __hash__(self) -> int: ...

class KX_N_Packet1:
    packet: bytes

    def __init__(self, packet: Buffer) -> None: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...
    def __bytes__(self) -> bytes: ...
    def __len__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    @classmethod
    def from_bytes(cls, framed: Buffer) -> Self: ...

class KX_KK_Packet1:
    packet: bytes

    def __init__(self, packet: Buffer) -> None: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...
    def __bytes__(self) -> bytes: ...
    def __len__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    @classmethod
    def from_bytes(cls, framed: Buffer) -> Self: ...

class KX_KK_Packet2:
    packet: bytes

    def __init__(self, packet: Buffer) -> None: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...
    def __bytes__(self) -> bytes: ...
    def __len__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    @classmethod
    def from_bytes(cls, framed: Buffer) -> Self: ...

class KX_XX_Packet1:
    packet: bytes

    def __init__(self, packet: Buffer) -> None: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...
    def __bytes__(self) -> bytes: ...
    def __len__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    @classmethod
    def from_bytes(cls, framed: Buffer) -> Self: ...

class KX_XX_Packet2:
    packet: bytes

    def __init__(self, packet: Buffer) -> None: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...
    def __bytes__(self) -> bytes: ...
    def __len__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    @classmethod
    def from_bytes(cls, framed: Buffer) -> Self: ...

class KX_XX_Packet3:
    packet: bytes

    def __init__(self, packet: Buffer) -> None: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...
    def __bytes__(self) -> bytes: ...
    def __len__(self) -> int: ...
    def __eq__(self, other: object) -> bool: ...
    def __hash__(self) -> int: ...
    @classmethod
    def from_bytes(cls, framed: Buffer) -> Self: ...
