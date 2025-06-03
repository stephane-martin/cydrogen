from collections.abc import Buffer
from os import PathLike
from typing import BinaryIO, Literal, Protocol, type_check_only

@type_check_only
class Reader(Protocol):
    def read(self, length: int = ...) -> bytes: ...

@type_check_only
class Writer(Protocol):
    def write(self, buf: Buffer) -> int: ...

def store64(dst: Buffer, src: int):
    """
    Store a 64-bit unsigned integer into a byte array.

    Big-endian encoding.

    Args:
        dst: A byte array of at least 8 bytes.
        src: The 64-bit unsigned integer to store.

    Raises:
        ValueError: If the destination byte array is less than 8 bytes long.
    """
    ...

def store32(dst: Buffer, src: int):
    """
    Store a 32-bit unsigned integer into a byte array.

    Big-endian encoding.

    Args:
        dst: A byte array of at least 4 bytes.
        src: The 32-bit unsigned integer to store.

    Raises:
        ValueError: If the destination byte array is less than 4 bytes long.
    """
    ...

def store16(dst: Buffer, src: int):
    """
    Store a 16-bit unsigned integer into a byte array.

    Big-endian encoding.

    Args:
        dst: A byte array of at least 2 bytes.
        src: The 16-bit unsigned integer to store.

    Raises:
        ValueError: If the destination byte array is less than 2 bytes long.
    """
    ...

def load64(src: Buffer) -> int:
    """
    Load a 64-bit unsigned integer from a byte array.

    Big-endian encoding.

    Args:
        src: A byte array of at least 8 bytes.

    Returns:
        The 64-bit unsigned integer represented by the first 8 bytes of the array.

    Raises:
        ValueError: If the input byte array is less than 8 bytes long.
    """
    ...

def load32(src: Buffer) -> int:
    """
    Load a 32-bit unsigned integer from a byte array.

    Big-endian encoding.

    Args:
        src: A byte array of at least 4 bytes.

    Returns:
        The 32-bit unsigned integer represented by the first 4 bytes of the array.

    Raises:
        ValueError: If the input byte array is less than 4 bytes long.
    """
    ...

def load16(src: Buffer) -> int:
    """
    Load a 16-bit unsigned integer from a byte array.

    Big-endian encoding.

    Args:
        src: A byte array of at least 2 bytes.

    Returns:
        The 16-bit unsigned integer represented by the first 2 bytes of the array.

    Raises:
        ValueError: If the input byte array is less than 2 bytes long.
    """
    ...

def have_mman() -> bool: ...
def little_endian() -> bool: ...
def big_endian() -> bool: ...

class SafeReader:
    """
    A safe reader for file-like objects.

    When working with unbuffered streams, it is possible that the read operation
    may not read the requested number of bytes. This class handles such cases
    by repeatedly reading until the requested number of bytes is read or EOF is reached.
    """
    def __init__(self, fileobj: Reader):
        """
        Initialize the SafeReader.

        Args:
            fileobj: A file-like object that supports reading.
        Raises:
            ValueError: If fileobj is None.
            TypeError: If fileobj does not have a 'read' method.
        """
        ...

    def readinto(self, buf: Buffer) -> int:
        """
        Read bytes into a buffer.

        Args:
            buf: A buffer to read bytes into. Must be a writable bytearray or memoryview.

        Returns:
            The number of bytes read into the buffer. It may be less than the length of the buffer if EOF is reached.
        """
        ...

    def read(self, length: int = ...) -> bytes:
        """
        Read bytes from the file-like object.

        Args:
            length: The number of bytes to read. Defaults to io.DEFAULT_BUFFER_SIZE.

        Returns:
            A bytes object containing the read bytes. If EOF is reached before reading the requested number of bytes, it returns the bytes read so far.
        """
        ...

class SafeWriter:
    """
    A safe writer for file-like objects.

    When working with unbuffered streams, it is possible that the write operation
    may not write the requested number of bytes. This class handles such cases
    by repeatedly writing until the requested number of bytes is written or an error occurs.
    """

    def __init__(self, fileobj: Writer):
        """
        Initialize the SafeWriter.

        Args:
            fileobj: A file-like object that supports writing.

        Raises:
            ValueError: If fileobj is None.
            TypeError: If fileobj does not have a 'write' method.
        """
        ...

    def write(self, buf: Buffer) -> int:
        """
        Write bytes to the file-like object.

        Args:
            buf: A buffer containing bytes to write. Must be a bytes-like object.

        Returns:
            The number of bytes written. It may be less than the length of the buffer if an error occurs during writing.
        """
        ...

class TeeWriter:
    def __init__(self, w1: Writer, w2: Writer):
        """
        Initialize the TeeWriter.

        Args:
            w1: The first writer (must have a write method).
            w2: The second writer (must have a write method).

        Raises:
            ValueError: If either w1 or w2 is None.
            TypeError: If either w1 or w2 does not have a 'write' method.
        """
        ...

    def write(self, buf: Buffer) -> int:
        """
        Write bytes to both writers.

        Args:
            buf: A buffer containing bytes to write. Must be a bytes-like object.

        Returns:
            The number of bytes written to both writers.

        Raises:
            IOError: If the two writers do not write the same number of bytes.
        """
        ...

class FileOpener:
    """
    A context manager for opening files or file-like objects.

    When used on a path-like object, it opens the file in the specified mode.
    When used on a file-like object, it uses that object directly.

    Examples:
        >>> with FileOpener("example.txt", mode="rb") as f:
        ...     data = f.read()
        >>> with FileOpener(io.BytesIO(b"data"), mode="wb") as f:
        ...     f.write(b"data")
    """

    def __init__(self, fileobj_or_path: str | PathLike | BinaryIO, *, mode: Literal["rb", "wb", "ab"] = ...):
        """
        Initialize the FileOpener.

        Args:
            fileobj_or_path: A path-like object (str or Path) or a file-like object.
            mode: The mode in which to open the file. Defaults to 'rb'.
                Valid modes are 'rb', 'wb', and 'ab'.

        Raises:
            ValueError: If fileobj_or_path is None or mode is invalid.
            TypeError: If fileobj_or_path is not a path-like object or a file-like object.
        """
        ...

    def __enter__(self) -> BinaryIO: ...
    def __exit__(self, exc_type, exc_value, traceback) -> None: ...
