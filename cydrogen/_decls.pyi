from collections.abc import Buffer

def random_u32() -> int:
    """
    Generate a random 32-bit unsigned integer.

    Returns:
        A random 32-bit unsigned integer.
    """
    ...

def random_uniform(upper_bound: int) -> int:
    """
    Generate a random number uniformly distributed in the range [0, upper_bound).

    upper_bound must be a positive integer with size uint32_t.

    Args:
        upper_bound: The upper bound (exclusive) for the random number.

    Returns:
        A random integer in the range [0, upper_bound).
    """
    ...

def randomize_buffer(buf: Buffer) -> None:
    """
    Fill a buffer with random bytes.

    Args:
        buf: A buffer to fill with random bytes. The buffer must be writable.
    """
    ...

def gen_random_buffer(size: int) -> bytes:
    """
    Generate a random buffer of the specified size.

    Args:
        size: The size of the buffer to generate.

    Returns:
        A bytes object containing random data of the specified size.
    """
    ...

def shuffle_buffer(buf: Buffer) -> None:
    """
    Shuffle a buffer in place.

    Args:
        buf: A buffer to shuffle. The buffer must be writable.
    """
    ...

def pad(buf: Buffer, blocksize: int = 8192) -> bytes:
    """
    Pad a buffer to a multiple of the specified block size.

    Args:
        buf: A buffer to pad.
        blocksize: The block size to pad to (default is 8192).

    Returns:
        A bytes object containing the padded buffer.

    Raises:
        ValueError: If blocksize is invalid
    """
    ...

def unpad(buf: Buffer, blocksize: int = 8192) -> bytes:
    """
    Unpad a buffer that was padded to a multiple of the specified block size.

    Args:
        buf: A padded buffer to unpad.
        blocksize: The block size that was used for padding (default is 8192).

    Returns:
        A bytes object containing the unpadded buffer.

    Raises:
        ValueError: If the buffer is not padded correctly or if blocksize is invalid.
    """
    ...
