from collections.abc import Buffer
from os import PathLike
from typing import BinaryIO, Protocol, Self, type_check_only

from ._context import Context

@type_check_only
class Reader(Protocol):
    def read(self, length: int = ...) -> bytes: ...

@type_check_only
class Writer(Protocol):
    def write(self, buf: Buffer) -> int: ...

class SignPublicKey:
    """
    SignPublicKey represents a public key used for signature verification.
    """
    def __init__(self, key: str | bytes | Self | Buffer):
        """
        Initialize a SignPublicKey instance.

        Args:
            key: The public key to initialize with.

        Raises:
            MemoryError: If memory allocation for the key fails.
            ValueError: If the key is None or not of the correct length.
            TypeError: If the key is of an unsupported type.
        """
        ...

    def writeto(self, out: Writer) -> int:
        """
        Write the key to a writer.

        Args:
            out: A writer object that supports the write method.

        Returns:
            The number of bytes written, which should be 32.

        Raises:
            TypeError: If the provided writer does not have a 'write' method.
        """
        ...

    def verifier(self, ctx: str | bytes | Context | Buffer | None = None) -> "Verifier":
        """
        Create a Verifier instance using this public key.

        The Verifier can be used to verify signatures created with the corresponding secret key.

        Args:
            ctx: Optional context for the verifier.

        Returns:
            An instance of Verifier initialized with this public key.
        """
        ...

    @classmethod
    def read_from(cls, reader: Reader) -> Self:
        """
        Create a key from a reader.

        Args:
            reader: A reader object that supports the read method.

        Returns:
            A new instance of SignPublicKey read from the provided reader.

        Raises:
            TypeError: If the provided reader does not have a 'read' method.
            ValueError: If the read data is not 32 bytes long.
        """
        ...

    def __buffer__(self, flags: int, /) -> memoryview: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...

class SignSecretKey:
    """
    SignSecretKey represents a secret key used for signing messages.
    """
    def __init__(self, key: str | bytes | Self | Buffer):
        """
        Initialize a SignSecretKey instance.

        Args:
            key: The secret key to initialize with.

        Raises:
            MemoryError: If memory allocation for the key fails.
            ValueError: If the key is None or not of the correct length.
            TypeError: If the key is of an unsupported type.
        """
        ...

    def writeto(self, out: Writer) -> int:
        """
        Write the key to a writer.

        Args:
            out: A writer object that supports the write method.

        Returns:
            The number of bytes written, which should be 64.

        Raises:
            TypeError: If the provided writer does not have a 'write' method.
        """
        ...

    def check_public_key(self, other: SignPublicKey) -> bool:
        """
        Check if the provided public key matches the one derived from this secret key.

        Args:
            other: The public key to check against.

        Returns:
            True if the public key matches, False otherwise.
        """
        ...

    def signer(self, ctx: str | bytes | Context | Buffer | None = None) -> "Signer":
        """
        Create a Signer instance using this secret key.

        The Signer can be used to sign messages.

        Args:
            ctx: Optional context for the signer.

        Returns:
            An instance of Signer initialized with this secret key.
        """
        ...

    @classmethod
    def read_from(cls, reader: Reader) -> Self:
        """
        Create a key from a reader.

        Args:
            reader: A reader object that supports the read method.

        Returns:
            A new instance of SignSecretKey read from the provided reader.

        Raises:
            TypeError: If the provided reader does not have a 'read' method.
            ValueError: If the read data is not 64 bytes long.
        """
        ...

    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __eq__(self, other) -> bool: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

class SignKeyPair:
    """
    SignKeyPair represents a pair of secret and public keys used for signing and verifying messages.

    All attributes are read-only after initialization.

    Attributes:
        public_key: The public key for verification.
        secret_key: The secret key for signing.
    """

    public_key: SignPublicKey
    secret_key: SignSecretKey

    def __init__(self, kp: str | bytes | Self | SignSecretKey | Buffer):
        """
        Initialize a SignKeyPair instance.

        Args:
            kp: The key pair to initialize with. This can be a SignSecretKey or a bytes-like object.

        Raises:
            MemoryError: If memory allocation for the key fails.
            ValueError: If the key is None or not of the correct length.
            TypeError: If the key is of an unsupported type.
        """
        ...

    @classmethod
    def gen(cls) -> Self:
        """
        Generate a random SignKeyPair.

        Returns:
            An instance of SignKeyPair initialized with a newly generated secret key.
        """
        ...

    def signer(self, ctx: str | bytes | Context | Buffer | None = None) -> "Signer":
        """
        Create a Signer instance using the secret key of this key pair.

        The Signer can be used to sign messages.

        Returns:
            An instance of Signer initialized with the secret key of this key pair.
        """
        ...

    def verifier(self, ctx: str | bytes | Context | Buffer | None = None) -> "Verifier":
        """
        Create a Verifier instance using the public key of this key pair.

        The Verifier can be used to verify signatures created with the corresponding secret key.

        Returns:
            An instance of Verifier initialized with the public key of this key pair.
        """
        ...

    def __eq__(self, other: object) -> bool: ...
    def __str__(self) -> str: ...
    def __repr__(self) -> str: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...

class BaseSigner:
    """
    Base class for Signer and Verifier.

    Users should not instantiate this class directly.

    Attributes:
        ctx: The context used for signing or verifying.
    """

    ctx: Context

    def __init__(self, *, ctx: str | bytes | Context | Buffer | None = None, data: bytes | Buffer | None = None):
        """
        Initialize a BaseSigner instance.

        Args:
            ctx: Optional context for the signer or verifier.
            data: Optional initial data to update the signer or verifier with.

        Raises:
            ValueError: If the context is None.
            TypeError: If the context is of an unsupported type.
            SignException: If the signer or verifier fails to initialize.
        """
        ...

    def update_from(self, fileobj: str | PathLike | BinaryIO, chunk_size=...):
        """
        Update the signer or verifier with data read from a file-like/path-like object.

        Args:
            fileobj: A file-like or path-like object to read data from.
            chunk_size: The size of chunks to read from the file object.

        Raises:
            ValueError: If the file object is None.
            TypeError: If fileobj is not a file-like or path-like object.
            SignException: If the update fails.
        """
        ...

    def update(self, data: bytes | Buffer):
        """
        Update the signer or verifier with new data.

        Args:
            data: The data to update the signer or verifier with.

        Raises:
            SignException: If the update fails.
        """
        ...

    def write(self, data: bytes | Buffer) -> int:
        """
        Write data to the signer or verifier.

        This method is similar to update but returns the length of the data written.

        Args:
            data: The data to write to the signer or verifier.

        Returns:
            The length of the data written.

        Raises:
            SignException: If the write fails.
        """
        ...

class Signer(BaseSigner):
    """
    Signer is used to create signatures for messages using a secret key.

    Attributes:
        key: The secret key used for signing.
    """

    key: SignSecretKey

    def __init__(
        self,
        private_key: SignSecretKey | str | bytes | Buffer,
        *,
        ctx: str | bytes | Context | Buffer | None = None,
        data: bytes | Buffer | None = None,
    ):
        """
        Initialize a Signer instance.

        Args:
            private_key: The secret key used for signing.
            ctx: Optional context for the signer.
            data: Optional initial data to update the signer with.

        Raises:
            ValueError: If the private key is None.
            TypeError: If the private key is of an unsupported type.
            SignException: If the signer fails to initialize.
        """
        ...

    def sign(self) -> bytes:
        """
        Create a signature for the data that has been updated in the signer.

        Returns:
            A bytes object containing the signature.

        Raises:
            RuntimeError: If the signer has already been finalized.
            SignException: If the signature creation fails.
        """
        ...

class Verifier(BaseSigner):
    """
    Verifier is used to verify signatures created with a corresponding secret key.

    Attributes:
        key: The public key used for verification.
    """

    key: SignPublicKey

    def __init__(
        self,
        public_key: SignPublicKey | str | bytes | Buffer,
        *,
        ctx: str | bytes | Context | Buffer | None = None,
        data: bytes | Buffer | None = None,
    ):
        """
        Initialize a Verifier instance.

        Args:
            public_key: The public key used for signature verification.
            ctx: Optional context for the verifier.
            data: Optional initial data to update the verifier with.

        Raises:
            ValueError: If the public key is None.
            TypeError: If the public key is of an unsupported type.
            SignException: If the verifier fails to initialize.
        """
        ...

    def verify(self, signature: bytes | Buffer) -> None:
        """
        Verify a signature against the data that has been updated in the verifier.

        Args:
            signature: The signature to verify, must be 64 bytes long.

        Raises:
            ValueError: If the signature is None or not of the correct length.
            RuntimeError: If the verifier has already been finalized.
            VerifyException: If the verification fails.
        """
        ...

def sign_file(
    key: SignSecretKey | str | bytes | Buffer,
    fileobj: str | PathLike | BinaryIO,
    ctx: str | bytes | Context | Buffer | None = None,
    chunk_size: int = ...,
) -> bytes:
    """
    Sign a file using the provided secret key.

    Args:
        key: The secret key used for signing.
        fileobj: A file-like or path-like object to read data from.
        ctx: Optional context for the signer.
        chunk_size: The size of chunks to read from the file object.

    Returns:
        A bytes object containing the signature.

    Raises:
        ValueError: If the key or file object is None.
        TypeError: If the key is not a SignSecretKey, fileobj is not a file-like object, or the context is invalid.
        SignException: If the signing process fails.
    """
    ...

def verify_file(
    key: SignPublicKey | str | bytes | Buffer,
    fileobj: str | PathLike | BinaryIO,
    signature: bytes | Buffer,
    ctx: str | bytes | Context | Buffer | None = None,
    chunk_size: int = ...,
) -> None:
    """
    Verify a signature against the data read from a file using the provided public key.

    Args:
        key: The public key used for signature verification.
        fileobj: A file-like or path-like object to read data from.
        signature: The signature to verify, must be 64 bytes long.
        ctx: Optional context for the verifier.
        chunk_size: The size of chunks to read from the file object.

    Raises:
        ValueError: If the key, file object, or signature is None, or if the signature is not of the correct length.
        TypeError: If the key is not a SignPublicKey, fileobj is not a file-like object, or the context is invalid.
        VerifyException: If the verification process fails.
    """
    ...
