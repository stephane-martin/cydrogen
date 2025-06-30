from collections.abc import Buffer
from typing import Protocol


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


class AsyncReader(Protocol):
    """
    Protocol for reading bytes from a source asynchronously.
    """

    async def read(self, length: int = -1) -> bytes:
        """
        Asynchronously read at most `length` bytes from the source.

        Args:
            length (int): The maximum number of bytes to read. If -1, read until EOF.

        Returns:
            bytes: The bytes read from the source.
        """
        ...


class Writer(Protocol):
    """
    Protocol for writing bytes to a destination.
    """

    def write(self, buf: Buffer) -> int:
        """

        Args:
            buf (Buffer): The bytes to write.

        Returns:
            int: The number of bytes written.
        """
        ...


class AsyncWriter(Protocol):
    """
    Protocol for writing bytes to a destination asynchronously.
    """

    def write(self, data: Buffer) -> None:
        """
        Asynchronously write bytes to the destination.

        Args:
            data: The bytes to write.
        """
        ...

    async def drain(self) -> None:
        """
        Asynchronously drain the writer, ensuring all data is written.
        """
        ...
