from collections.abc import Buffer
from os import PathLike
from typing import BinaryIO, Self

from ._basekey import BaseKey
from ._context import Context

class HashKey(BaseKey):
    """
    HashKey represents a crypto key for hashing.

    Hashing operations may be performed using a key to prevent dictionary attacks.
    If you don't need to prevent dictionary attacks, you can use the empty key for hashing.
    """

    def __init__(self, key: str | bytes | BaseKey | Self | Buffer | None = None):
        """
        Initialize the HashKey with an optional key. If the key is None, an empty key is created.

        It is not possible to initialize a HashKey from another concrete key type like MasterKey,
        SignKeyPair, SignPublicKey, or SignSecretKey.

        Args:
            key: A bytes-like object, a base64 encoded string, or None for an empty key.

        Raises:
            TypeError: If the key is of an unsupported type.
            ValueError: If the key is not a valid bytes-like object or base64 encoded string.
        """
        ...

    def hasher(
        self, data: bytes | Buffer | None = None, ctx: Context | str | bytes | Buffer | None = None, digest_size: int = 16
    ) -> "Hash":
        """
        Returns a hasher object initialized with the key.

        Args:
            data: Optional initial data to hash.
            ctx: Optional context for the hash operation.
            digest_size: Size of the desired digest in bytes.

        Returns:
            A Hash object initialized with the key, the context and optional data.

        Raises:
            ValueError: If the digest size is not within the valid range (16 to 65535 bytes) or if the context is invalid.
        """
        ...

    def __eq__(self, other: object) -> bool: ...
    def __repr__(self) -> str: ...

class Hash:
    """
    Hash is a class for computing cryptographic hashes.

    All attributes are initialized in the constructor and are immutable after that.

    Attributes:
        ctx: The context for the hash operation.
        key: The key used for hashing.
        digest_size: The size of the hash digest in bytes.
        block_size: The block size used in the hash algorithm.
    """

    ctx: Context
    key: HashKey
    digest_size: int
    block_size: int

    def __init__(
        self,
        data: bytes | Buffer | None = None,
        *,
        ctx: str | bytes | Context | Buffer | None = None,
        digest_size: int = 16,
        key: str | bytes | BaseKey | HashKey | Buffer | None = None,
    ):
        """
        Initialize the hasher.

        Args:
            data: Optional initial data to hash.
            ctx: Optional context for the hash operation.
            digest_size: Size of the desired digest in bytes (default is 16).
            key: Optional HashKey to use for hashing.

        Raises:
            ValueError: If the digest size is not within the valid range (16 to 65535 bytes) or if the context is invalid.
            RuntimeError: If the hash has already been finalized.
            TypedError: If the key is of an unsupported type.
        """
        ...
    def update(self, data: bytes | Buffer) -> None:
        """
        Update the hash with new data.

        Args:
            data: Data to hash, as a bytes-like object.

        Raises:
            RuntimeError: If the hash has already been finalized.
        """
        ...
    def write(self, data: bytes | Buffer) -> int:
        """
        Write data to the hash.

        Args:
            data: Data to hash, as a bytes-like object.

        Returns:
            The number of bytes written to the hash.

        Raises:
            RuntimeError: If the hash has already been finalized.
        """
        ...
    def update_from(self, fileobj: str | PathLike | BinaryIO, chunk_size: int = ...):
        """
        Read data from a file-like/path-like object and update the hash.

        Args:
            fileobj: A file-like object or path-like object to read data from.
            chunk_size: Size of the chunks to read from the file (default is io.DEFAULT_BUFFER_SIZE).

        Raises:
            ValueError: If fileobj_or_path is None.
            TypeError: If fileobj_or_path is not a path-like object or a file-like object.
        """
        ...
    def digest(self) -> bytes:
        """
        Finalize the hash and return the digest.

        Returns:
            The computed hash digest.
        """
        ...
    def hexdigest(self) -> str:
        """
        Finalize the hash and return the digest as a hex string.

        Returns:
            The hexadecimal representation of the hash digest.
        """
        ...

def hash_file(
    fileobj: str | PathLike | BinaryIO,
    ctx: str | bytes | Context | Buffer | None = None,
    digest_size: int = 16,
    key: str | bytes | BaseKey | HashKey | Buffer | None = None,
    chunk_size: int = ...,
) -> bytes:
    """
    Compute the hash of a binary file-like object.

    Args:
        fileobj: A file-like object or path-like object to read data from.
        ctx: Optional context for the hash operation.
        digest_size: Size of the desired digest in bytes (default is 16).
        key: Optional HashKey to use for hashing.
        chunk_size: Size of the chunks to read from the file (default is io.DEFAULT_BUFFER_SIZE).

    Returns:
        The computed hash digest as bytes.

    Raises:
        ValueError: If fileobj is None or if the digest size is not within the valid range (16 to 65535 bytes) or if the context is invalid.
        TypeError: If fileobj is not a path-like object or a file-like object, or if key is of an unsupported type.
    """
    ...
