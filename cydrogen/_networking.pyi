from collections.abc import Buffer, Sized

class BytearrayBuilder:
    def __init__(self) -> None: ...
    def add(self, data: Buffer) -> None: ...
    def get(self) -> bytearray: ...

class MsgQueue[T: Sized]:
    """
    MsgQueue is a queue that holds messages to be sent or received.
    """

    def __init__(self) -> None:
        """
        Initialize MsgQueue.
        """
        ...

    @property
    def bytesize(self) -> int:
        """
        The total size of the messages in the queue, in bytes.
        """
        ...

    @property
    def qsize(self) -> int:
        """
        Get the number of messages in the queue.

        Returns:
            The number of messages in the queue.
        """
        ...

    @property
    def empty(self) -> bool:
        """
        Check if the queue is empty.

        Returns:
            True if the queue is empty, False otherwise.
        """
        ...

    def put_nowait(self, msg: T, msg_id: int = 0) -> None:
        """
        Put a message into the queue without waiting.

        If the queue has been closed, this method will raise an exception (the one that was passed to `close` method).

        Args:
            msg: The message to put into the queue. It must be a Sized object (e.g., bytes, bytearray).
            msg_id: An optional identifier for the message.

        Raises:
            ValueError: If the message is invalid.
            Exception: If the queue has been closed.
        """
        ...

    def close(self, exc: BaseException | None = None) -> None:
        """
        Close the queue, preventing any further messages from being added.

        Args:
            exc: An exception to raise when trying to get/put messages from/to the queue after it has been closed. If not provided, EOFError will be raised.
        """
        ...

    async def get(self) -> tuple[T, int]:
        """
        Get a message from the queue, waiting if necessary until a message is available.

        If the queue has not been closed, this method will block until a message is available.
        If the queue has been closed and there are pending messages, get will return a message without exception.
        If the queue has been closed and there are no pending messages, it will raise an exception (the one that was passed to `close` method).

        Returns:
            The message from the queue.
            The message ID, if it was provided when the message was put into the queue.

        Raises:
            Exception: if the queue has been closed and there are no pending messages in the queue.
        """
        ...

class ReadBuffers:
    """
    ReadBuffers manages a pool of read buffers in which the Transport can read data.

    The point is to avoid allocating a new bytearray for each read operation, which can be expensive.

    Instead (pooling buffers used by the Transport):

    - ReadBuffers provides a suitable memoryview than can be used by the Transport to read data into.
    - The Transport can notify ReadBuffers when the buffer has been updated with new data.
    - When data in consumed from the ReadBuffers, the memoryviews that have been consumed are put back into the pool.

    Also (pooling buffers returned by consume methods):

    - ReadBuffers maintains a pool of bytearrays, each of size `8192` bytes, to avoid to allocate new bytearrays when data is consumed.
    - After consuming data (typically by decrypting it), the user may release the memoryview back to the ReadBuffers instance.
    """
    def __init__(self, nb_max_read_buffers: int = 16, read_buffer_size: int = 65536) -> None:
        """
        Initialize ReadBuffers.

        Args:
            nb_max_read_buffers: Maximum number of read buffers that are kept in the pool.
            read_buffer_size: Size of each read buffer.
        """
        ...

    def get_buffer(self) -> memoryview:
        """
        Return a buffer than can be used by the Transport to read data into.

        The returned buffer is a memoryview slice a bytearray that is managed by the ReadBuffers instance. The slice
        has a maximum size of `read_buffer_size` bytes.

        Returns:
            A memoryview of a bytearray that can be used for reading data.
        """
        ...

    def buffer_updated(self, nbytes: int) -> None:
        """
        Notify ReadBuffers that the buffer previously returned by `get_buffer` has been updated with `nbytes` bytes of data.
        """
        ...

    def consume_bytes(self, nbytes: int) -> memoryview | None:
        """
        Consume `nbytes` bytes from the ReadBuffers instance.

        Return a memoryview of the consumed bytes, or None if not enough bytes are available. The corresponding bytes are
        removed from the ReadBuffers instance.

        Args:
            nbytes: The number of bytes to consume.

        Returns:
            A memoryview of the consumed bytes, or None if not enough bytes are available.
        """
        ...

    def consume_message(self) -> memoryview | None:
        """
        Consume and return a complete `EncryptedMessage` from the read buffers.

        Return a memoryview of the consumed message, or None if no complete message is available. The corresponding bytes are
        removed from the ReadBuffers instance.

        Returns:
            A memoryview of the consumed message, or None if no complete message is available.
        """
        ...

    def release_bytearray(self, mv: Buffer) -> None:
        """
        Give back a memoryview previously returned by `consume_bytes` or `consume_message` to the ReadBuffers instance, so
        that the underlying bytearray can be reused.

        Args:
            mv: The memoryview to release.
        """
        ...
