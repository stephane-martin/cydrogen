from typing import Self

class BaseKey:
    """
    Base class for keys used in symmetric cryptography (e.g., hashing, encryption).

    Users should not instantiate this class directly. Instead, use on the subclasses.

    The memory to store the key is allocated using guarded heap allocations, similar
    to [what is done in libsodium](https://doc.libsodium.org/memory_management#guarded-heap-allocations).

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
            BaseKey: A new instance of BaseKey.
        """
        ...

    @classmethod
    def zero(cls) -> Self:
        """
        Generate a new BaseKey initialized to zero.

        Returns:
            BaseKey: A new instance of BaseKey initialized to zero.
        """
        ...

    def is_zero(self) -> bool:
        """
        Checks if the key is the zero key.

        Returns:
            bool: True if the key is zero, False otherwise.
        """
        ...

    def __str__(self) -> str: ...
    def __bool__(self) -> bool: ...
    def __buffer__(self, flags: int, /) -> memoryview: ...
