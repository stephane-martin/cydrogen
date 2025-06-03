from collections.abc import Buffer
from typing import Protocol, Self, type_check_only

@type_check_only
class Reader(Protocol):
    def read(self, length: int = ...) -> bytes: ...

@type_check_only
class Writer(Protocol):
    def write(self, buf: Buffer) -> int: ...

class BaseKey:
    """
    Base class for keys used in symmetric cryptography (e.g., hashing, encryption).

    Users should not instantiate this class directly. Instead, use one of the subclasses.

    The memory to store the key is allocated using guarded heap allocations, similar to
    [what is done in libsodium](https://doc.libsodium.org/memory_management#guarded-heap-allocations).

    BaseKey implements the buffer protocol, allowing it to be used as a bytes-like object.
    """

    def __init__(self, b: bytes | None = None):
        """
        Initialize the BaseKey with an optional bytes object.

        Raises:
            MemoryError: If memory allocation for the key fails.
            TypeError: If the provided key is not a bytes object.
            ValueError: If the provided key is not 32 bytes long.
        """
        ...

    @classmethod
    def gen(cls) -> Self:
        """
        Generate a new BaseKey with random bytes.

        Returns:
            A new instance of BaseKey.
        """
        ...

    @classmethod
    def zero(cls) -> Self:
        """
        Generate a new BaseKey initialized to zero.

        Returns:
            A new instance of BaseKey initialized to zero.
        """
        ...

    @classmethod
    def read_from(cls, reader: Reader) -> Self:
        """
        Create a key from a reader.

        Args:
            reader: A reader object that supports the read method.

        Returns:
            A new instance of BaseKey read from the provided reader.

        Raises:
            TypeError: If the provided reader does not have a 'read' method.
            ValueError: If the read data is not 32 bytes long.
        """
        ...

    def is_zero(self) -> bool:
        """
        Checks if the key is the zero key.

        Returns:
            True if the key is zero, False otherwise.
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

    def __str__(self) -> str: ...
    def __bool__(self) -> bool: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...
