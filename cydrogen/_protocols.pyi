from collections.abc import Buffer
from typing import Protocol, type_check_only

@type_check_only
class Reader(Protocol):
    """
    Protocol for reading bytes from a source.
    """
    def read(self, length: int = -1) -> bytes:
        """
        Read at most `length` bytes from the source.

        Args:
            length (int): The maximum number of bytes to read. If -1, read until EOF.

        Returns:
            bytes: The bytes read from the source.
        """
        ...

@type_check_only
class Writer(Protocol):
    """
    Protocol for writing bytes to a destination.
    """
    def write(self, buf: Buffer) -> int:
        """
        Write bytes to the destination.

        Args:
            buf (Buffer): The bytes to write.

        Returns:
            int: The number of bytes written.
        """
        ...
