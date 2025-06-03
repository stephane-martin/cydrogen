from collections.abc import Buffer
from os import PathLike
from typing import BinaryIO, Protocol, Self, type_check_only

from ._basekey import BaseKey
from ._context import Context
from ._masterkey import MasterKey

ENC_MSG_HEADER: bytes
"""
ENC_MSG_HEADER is the magic header for encrypted messages.
"""

@type_check_only
class Reader(Protocol):
    def read(self, length: int = ...) -> bytes: ...

@type_check_only
class Writer(Protocol):
    def write(self, buf: Buffer) -> int: ...

class SecretBoxKey(BaseKey):
    """
    SecretBoxKey represents a key for the secretbox API.

    The secretbox API is used for authenticated encryption of messages.
    """

    def __init__(self, key: bytes | str | Self | BaseKey | Buffer):
        """
        Initialize the SecretBoxKey with a key.

        Args:
            key: 32-bytes-like object, a base64 encoded string, or another SecretBoxKey.

        Raises:
            ValueError: If the key is None.
            TypeError: If the key is of an unsupported type.
        """
        ...

    def secretbox(self, ctx: bytes | str | Context | Buffer | None = None) -> "SecretBox":
        """
        Create a SecretBox instance with the current key and context.

        Args:
            ctx: Optional context for the secret box. If None, a default context is used.

        Returns:
            A new SecretBox instance initialized with the current key and context.
        """
        ...

    @classmethod
    def from_password(
        cls,
        password: bytes | Buffer,
        *,
        master_key: bytes | str | Buffer | MasterKey | None = None,
        ctx: bytes | str | Context | Buffer | None = None,
        opslimit: int = ...,
    ) -> Self:
        """
        Derive a key from a password using the provided master key.

        This class method is used to create a high entropy key from a password.
        This is useful for example to encrypt a file using a password.

        Args:
            password: The password to derive the key from.
            master_key: Optional master key to use for derivation. If None, a default master key is used.
            ctx: Optional context for the key derivation.
            opslimit: Optional operation limit for the key derivation. The higher the opslimit
                      the more secure the key derivation is, but it will take longer to compute.
                      Default is 10000 operations.

        Returns:
            A new SecretBoxKey instance derived from the password.
        """
        ...

    def __eq__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...

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
        ciphertext: The encrypted message as bytes.
        msg_id: The message ID associated with the encrypted message.
    """

    ciphertext: bytes
    msg_id: int

    def __init__(self, ctext: bytes | Buffer, msg_id: int):
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
            IOError: If the write operation fails.
        """
        ...

    def decrypt(
        self,
        key: bytes | str | SecretBoxKey | BaseKey | Buffer,
        ctx: bytes | str | Context | Buffer | None = None,
        out: Writer | None = None,
    ) -> bytes:
        """
        Decrypt the message using the secret box key and context.

        Args:
            key: The secret box key to use for decryption.
            ctx: Optional context for the decryption. If None, a default context is used.
            out: Optional file-like object to write the decrypted plaintext to.

        Returns:
            The decrypted plaintext as bytes.

        Raises:
            ValueError: If the key is None, if the ciphertext is too short or the context is invalid.
            TypeError: if the key has an unsupported type, or if the out object does not support writing.
            DecryptException: If decryption fails.
        """
        ...

    @classmethod
    def from_bytes(cls, framed: bytes | Buffer) -> Self:
        """
        Create an EncryptedMessage from a framed bytes object.

        Args:
            framed: A bytes-like object containing the framed message.

        Returns:
            An instance of EncryptedMessage.

        Raises:
            ValueError: If the framed message is None or if parsing fails.
            IOError: If reading the message header or message fails.
        """
        ...

    @classmethod
    def read_from(cls, reader: Reader, *, max_msg_size: int | None = None) -> Self:
        """
        Read an EncryptedMessage from a file-like/path-like object.

        Args:
            reader: A file-like object to read the message from.
            max_msg_size: Optional maximum size of the message. If provided, raises ValueError
                          if the message size exceeds this limit.

        Returns:
            An instance of EncryptedMessage.

        Raises:
            ValueError: If the file object is None or if parsing fails.
            IOError: If reading the message header or message fails.
            TypeError: If the file object is not a file-like/path-like object.
        """
        ...

    def __eq__(self, other: object) -> bool: ...

class SecretBox:
    """
    SecretBox is a class for encrypting and decrypting messages using a secret key.

    All attributes are readonly after initialization.

    Attributes:
        key: The SecretBoxKey used for encryption and decryption.
        ctx: The context for the secret box operations.
    """

    key: SecretBoxKey
    ctx: Context

    def __init__(self, key: bytes | str | SecretBoxKey | BaseKey | Buffer, *, ctx: bytes | str | Context | Buffer | None = None):
        """
        Initialize the secret box with a key and context.

        Args:
            key: The key to use for encryption and decryption.
            ctx: Optional context for the secret box. If None, a default context is used.

        Raises:
            ValueError: If the key is None or the context is invalid.
            TypeError: If the key has an unsupported type.
        """
        ...

    def encrypt(self, plaintext: bytes | Buffer, msg_id: int = ..., out: Writer | None = None) -> bytes:
        """
        Encrypt the plaintext using the secret box key, context and message ID.

        If out is provided, the framed ciphertext will be written to it.

        Args:
            plaintext: The plaintext to encrypt.
            msg_id: Optional message ID to associate with the encrypted message. Default is 0.
            out: Optional file-like object to write the encrypted ciphertext to.

        Returns:
            The encrypted message as bytes.

        Raises:
            ValueError: If the plaintext is None, if the ciphertext is too short.
            TypeError: if the out object does not support writing.
            EncryptException: If encryption fails.
        """
        ...

    def decrypt(self, ciphertext: bytes | Buffer | EncryptedMessage, msg_id: int = ..., out: Writer | None = None) -> bytes:
        """
        Decrypt the ciphertext using the secret box key, an optional context and message ID.

        The optional msg_id must match the one used during encryption.

        If out is provided, the plaintext will be written to it.

        Args:
            ciphertext: The ciphertext to decrypt. Can be an EncryptedMessage or a bytes-like object.
            msg_id: Optional message ID to verify against the ciphertext. Default is 0.
            out: Optional file-like object to write the decrypted plaintext to.

        Returns:
            The decrypted plaintext as bytes.

        Raises:
            ValueError: If the ciphertext is None or if the ciphertext is too short.
            TypeError: If the out object does not support writing.
            DecryptException: If decryption fails.
        """
        ...

    def encrypt_file(self, src: str | PathLike | BinaryIO, dst: str | PathLike | BinaryIO, chunk_size: int = ...) -> int:
        """
        Encrypt a file-like/path-like object and write the ciphertext to another file-like object.

        Args:
            src: The source file-like/path-like object to read the plaintext from.
            dst: The destination file-like/path-like object to write the ciphertext to.
            chunk_size: Optional size of the chunks to read from the source file. Default is io.DEFAULT_BUFFER_SIZE.

        Returns:
            The total number of bytes written to the destination file.

        Raises:
            ValueError: If the source or destination file objects are None.
            TypeError: If the source or destination file objects are not file-like/path-like objects.
            IOError: If reading from the source file or writing to the destination file fails.
            EncryptException: If encryption fails.
        """
        ...

    def decrypt_file(self, src: str | PathLike | BinaryIO, dst: str | PathLike | BinaryIO) -> int:
        """
        Decrypt a file-like object and write the plaintext to another file-like object.

        Args:
            src: The source file-like object to read the ciphertext from.
            dst: The destination file-like object to write the plaintext to.

        Returns:
            The total number of bytes written to the destination file.

        Raises:
            ValueError: If the source or destination file objects are None.
            TypeError: If the source or destination file objects are not file-like/path-like objects.
            IOError: If reading from the source file or writing to the destination file fails.
            DecryptException: If decryption fails.
        """
        ...
