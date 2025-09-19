from collections.abc import Buffer
from os import PathLike
from typing import BinaryIO, Self

from ._basekey import BaseKey
from ._context import Context
from ._datastructs import EncryptedMessage
from ._masterkey import MasterKey

class SecretBoxKey(BaseKey):
    """
    SecretBoxKey represents a key for the secretbox API.

    The secretbox API is used for authenticated encryption of messages.
    """

    def __init__(self, key: bytes | str | Self | Buffer) -> None:
        """
        Initialize the SecretBoxKey with a key.

        Args:
            key: 32-bytes-like object, a base64 encoded string, or another SecretBoxKey.

        Raises:
            ValueError: If the key is None.
            TypeError: If the key is of an unsupported type.
        """
        ...

    def secretbox(self, ctx: bytes | str | Context | Buffer | None = None) -> SecretBox:
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

    def __init__(self, key: bytes | str | SecretBoxKey | Buffer, *, ctx: bytes | str | Context | Buffer | None = None) -> None:
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

    def encrypt(self, plaintext: bytes | Buffer, msg_id: int = 0, max_msg_size: int | None = None) -> bytes:
        """
        Encrypt the plaintext using the secret box key, context and message ID.

        Args:
            plaintext: The plaintext to encrypt.
            msg_id: Optional message ID to associate with the encrypted message. Default is 0.
            max_msg_size: Optional maximum size of the plaintext. If provided, raises `cydrogen.MessageTooBigException` if the plaintext size exceeds this limit.

        Returns:
            The encrypted message as bytes (not framed).

        Raises:
            ValueError: If the plaintext is None.
            MessageTooBigException: If the plaintext is too long.
            TypeError: if the out object does not support writing.
            EncryptException: If encryption fails.
        """
        ...

    def decrypt(self, ciphertext: bytes | Buffer | EncryptedMessage, msg_id: int = 0, max_msg_size: int | None = None) -> bytes:
        """
        Decrypt the ciphertext using the secret box key, an optional context and message ID.

        The optional msg_id must match the one used during encryption.

        Args:
            ciphertext: The ciphertext to decrypt. Can be an EncryptedMessage or a bytes-like object.
            msg_id: Optional message ID to verify against the ciphertext. Default is 0.
            max_msg_size: Optional maximum size of the plaintext. If provided, raises `cydrogen.MessageTooBigException` if the plaintext size exceeds this limit.

        Returns:
            The decrypted plaintext as bytes.

        Raises:
            ValueError: If the ciphertext is None or if the ciphertext is too short.
            MessageTooBigException: If the decrypted plaintext is too long.
            TypeError: If the out object does not support writing.
            DecryptException: If decryption fails.
        """
        ...

    def encrypt_file(self, src: str | PathLike | BinaryIO, dst: str | PathLike | BinaryIO, chunk_size: int = 8192) -> int:
        """
        Encrypt a file-like/path-like object and write the ciphertext to another file-like object.

        Args:
            src: The source file-like/path-like object to read the plaintext from.
            dst: The destination file-like/path-like object to write the ciphertext to.
            chunk_size: Optional size of the chunks to read from the source file.

        Returns:
            The total number of bytes written to the destination file.

        Raises:
            ValueError: If the source or destination file objects are None.
            TypeError: If the source or destination file objects are not file-like/path-like objects.
            OSError: If reading from the source file or writing to the destination file fails.
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
            OSError: If reading from the source file or writing to the destination file fails.
            DecryptException: If decryption fails.
        """
        ...
