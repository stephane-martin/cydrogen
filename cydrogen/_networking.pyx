# cython: language_level=3, overflowcheck=True

from cpython.bytearray cimport PyByteArray_Resize
from libc.stdint cimport uint16_t
from libc.stdint cimport uint32_t
from libc.stdint cimport uint64_t

from ._datastructs cimport CY_ENC_MSG_HEADER_SIZE, EncryptedMessage
from ._decls cimport hydro_secretbox_HEADERBYTES
from ._utils cimport load64, encode_length, store64

import asyncio
import threading
from collections import deque

from .exceptions import MessageTooBigException, SyncMsgQueueShutdown
from .logs import get_logger
from ._datastructs import MessageType


logger = get_logger("cydrogen")


cdef class BytearrayBuilder:
    def __init__(self):
        self.b = bytearray(65536)
        self.offset = 0

    cpdef add_encrypted_message(self, EncryptedMessage msg):
        header = msg.header()
        lendata = len(header) + len(msg.ciphertext)
        needed = lendata + 8
        if self.offset + needed > len(self.b):
            if PyByteArray_Resize(self.b, self.offset + needed) < 0:
                raise MemoryError("Failed to resize bytearray")
        cdef unsigned char[:] mv = self.b
        cdef const unsigned char[:] hv = header
        cdef const unsigned char[:] cv = msg.ciphertext
        store64(mv[self.offset : self.offset + 8], lendata)
        mv[self.offset + 8 : self.offset + 8 + len(header)] = hv[0 : len(header)]
        mv[self.offset + 8 + len(header) : self.offset + needed] = cv[0 : len(msg.ciphertext)]
        self.offset += needed

    cpdef add(self, const unsigned char[:] data):
        # we need 8 bytes (to encode the length of data) + len(data) bytes
        needed = len(data) + 8
        if self.offset + needed > len(self.b):
            # we don't have enough space in the bytearray, resize it
            if PyByteArray_Resize(self.b, self.offset + needed) < 0:
                raise MemoryError("Failed to resize bytearray")
        self.b[self.offset : self.offset + 8] = encode_length(data)
        cdef unsigned char[:] mv = self.b
        mv[self.offset + 8 : self.offset + needed] = data[0 : len(data)]
        self.offset += needed

    cpdef get(self):
        cdef bytearray result = self.b[: self.offset]   # this is an actual copy
        if len(self.b) > 65536:
            PyByteArray_Resize(self.b, 65536)  # shrink to initial size, can't fail
        self.offset = 0
        return result


cdef first_future_not_done(futures):
    """
    Returns the first future in the deque that is not done.
    If all futures are done, returns None.
    """
    if futures is None:
        return None
    for f in futures:
        if not f.done():
            return f
    return None


cdef class MsgQueue:
    def __init__(self):
        self.readers_futures = deque()
        self.msg_deque = deque()
        self._bytesize = 0
        self.exc = None

    @property
    def bytesize(self) -> int:
        return self._bytesize

    @property
    def qsize(self):
        return len(self.msg_deque)

    @property
    def empty(self):
        return len(self.msg_deque) == 0

    cpdef put_nowait(self, msg, uint64_t msg_id=0):
        if msg is None:
            raise ValueError("Cannot put None in the message queue")
        cdef size_t msg_size = len(msg)     # raise ValueError is msg is not sized
        if self.exc is not None:
            raise self.exc
        fut = first_future_not_done(self.readers_futures)
        if fut is not None:
            # there is a reader waiting, set the result directly, bypassing the deque
            fut.set_result((msg, msg_id))
            return
        self.msg_deque.append((msg, msg_id))
        self._bytesize += msg_size

    async def get(self):
        if len(self.msg_deque) > 0:
            # there are messages in the queue, return the first one
            msg, msg_id = self.msg_deque.popleft()
            self._bytesize -= len(msg)
            return msg, msg_id
        # we need to wait for a message to be put in the queue
        # but first check if the queue is closed
        if self.exc is not None:
            # if the queue is closed, raise the exception
            raise self.exc
        # create a future and add it to the deque of futures
        fut = asyncio.get_running_loop().create_future()
        self.readers_futures.append(fut)
        try:
            # wait for the future to be set
            return await fut
        finally:
            # if we are here, the future was set, so we can remove it from the deque
            self.readers_futures.remove(fut)

    cpdef close(self, object exc=None):
        if self.exc is not None:
            return  # already closed
        if exc is None:
            exc = EOFError("Queue closed")
        self.exc = exc
        # set the exception for all futures waiting for messages
        for fut in self.readers_futures:
            if not fut.done():
                fut.set_exception(exc)


cdef class ReadBuffers:
    def __init__(self, uint16_t nb_max_read_buffers = 16, uint32_t read_buffer_size = 65536, size_t received_msg_max_size = 1048576):
        self.read_buffers = deque()
        self.nb_max_read_buffers = nb_max_read_buffers
        self.read_buffer_size = read_buffer_size
        self.received_msg_max_size = received_msg_max_size
        self.current_read_buffer = None
        self.write_pos = 0
        self.read_pos = 0
        self.available_bytes = 0
        self.read_buffers_freelist = []
        self.consume_bytearray_freelist = []
        self.consume_bytearray_size = 8192

    cpdef get_buffer(self):
        cdef unsigned char[:] mv
        if self.current_read_buffer is not None:
            # we have a current buffer, return a memoryview of the unused part of it
            mv = self.current_read_buffer
            return mv[self.write_pos : self.read_buffer_size]
        if self.read_buffers_freelist:
            # we have a free buffer in the freelist, use it
            self.current_read_buffer = self.read_buffers_freelist.pop()
        else:
            # if not, we need to create a new one
            self.current_read_buffer = bytearray(self.read_buffer_size)
        # store the current buffer in the deque of buffers
        self.read_buffers.append(self.current_read_buffer)
        mv = self.current_read_buffer
        return mv

    cpdef buffer_updated(self, uint32_t nbytes):
        # the transport is supposed to call get_buffer() before calling this method, so self._current_buffer should not be None
        if self.current_read_buffer is None:
            raise ValueError("buffer_updated(...) called without calling get_buffer() first")
        if nbytes == 0:
            return
        self.available_bytes += nbytes
        self.write_pos += nbytes
        if self.write_pos >= self.read_buffer_size:
            # the current buffer is full, next time in get_buffer() we will create a new buffer
            self.current_read_buffer = None
            self.write_pos = 0

    cpdef peek_message_type(self):
        h = self.peek_bytes(10)
        if h is None:
            # not enough data to read the start of the message
            return None
        return MessageType.from_marker(h[8:10])

    cpdef consume_kx_packet(self):
        h = self.peek_bytes(10)
        if h is None:
            # not enough data to read the start of the message
            return None
        if not MessageType.from_marker(h[8:10]).is_kx_packet():
            raise ValueError("Not a KX packet")
        length = load64(h[0:8])
        packet_size = length - 2
        if packet_size < 48 or packet_size > 96:
            raise ValueError("Invalid KX packet size")
        # try to consume for real
        b = self.consume_bytes(length + 8)
        if b is None:
            # not enough data to read the whole message
            return None
        return b[8:len(b)]  # skip the length field

    cpdef consume_server_ack(self):
        h = self.peek_bytes(10)
        if h is None:
            # not enough data to read the start of the message
            return None
        if not MessageType.from_marker(h[8:10]).is_server_ack():
            raise ValueError("Not a server ACK")
        length = load64(h[0:8])
        # try to consume for real
        b = self.consume_bytes(length + 8)
        if b is None:
            # not enough data to read the whole message
            return None
        return b[8:len(b)]  # skip the length field

    cpdef consume_message(self):
        h = self.peek_bytes(10)
        if h is None:
            # not enough data to read the start of the message
            return None
        length = load64(h[0:8])
        if not MessageType.from_marker(h[8:10]).is_encrypted_message():
            raise ValueError("Not an encrypted message")
        if length < CY_ENC_MSG_HEADER_SIZE:
            raise ValueError("Message is too short")
        ciphertext_size = length - CY_ENC_MSG_HEADER_SIZE
        if ciphertext_size < hydro_secretbox_HEADERBYTES:
            raise ValueError("Ciphertext is too short")
        plaintext_size = ciphertext_size - hydro_secretbox_HEADERBYTES
        if plaintext_size > self.received_msg_max_size:
            # the message is too large, we cannot handle it
            # it's more efficient to check the message size here rather than after consuming the bytes or decrypting the message
            # we avoid unnecessary memory allocations and decryption attempts
            raise MessageTooBigException
        # try to consume for real
        b = self.consume_bytes(length + 8)
        if b is None:
            # not enough data to read the whole message
            return None
        return b[8:len(b)]  # skip the length field

    cdef peek_bytes(self, uint16_t nbytes):
        if nbytes > self.read_buffer_size:
            raise ValueError(f"Cannot peek {nbytes} bytes, maximum is {self.read_buffer_size}")
        # so we need to peek the bytes from at most two buffers
        if nbytes > self.available_bytes:
            return None
        if nbytes == 0:
            return bytearray()
        cdef uint32_t nb_bytes_to_read_from_first_buffer = min(nbytes, self.read_buffer_size - self.read_pos)
        cdef bytearray result = self.read_buffers[0][self.read_pos : self.read_pos + nb_bytes_to_read_from_first_buffer]
        if nb_bytes_to_read_from_first_buffer == nbytes:
            # we can read all the bytes from the first buffer
            return result
        # we need to read some bytes from the second buffer
        cdef uint32_t nb_bytes_to_read_from_second_buffer = nbytes - nb_bytes_to_read_from_first_buffer
        result += self.read_buffers[1][0:nb_bytes_to_read_from_second_buffer]
        return result

    cdef get_bytearray(self, uint64_t nbytes):
        cdef bytearray b
        cdef unsigned char[:] mv
        if nbytes > self.consume_bytearray_size:
            # we don't want to use the freelist for large bytearrays, just create a new one
            b = bytearray(nbytes)
            mv = b
            return mv
        if len(self.consume_bytearray_freelist) == 0:
            # if the freelist is empty, create a new bytearray
            b = bytearray(self.consume_bytearray_size)
        else:
            b = self.consume_bytearray_freelist.pop()
        mv = b
        return mv[:nbytes]

    cpdef release_bytearray(self, const unsigned char[:] mv):
        if not isinstance(mv.base, bytearray):
            # this should not happen
            logger.warning("release_bytes: Object is not a bytearray, type: %s", type(mv.base))
            return
        cdef bytearray obj = mv.base
        if len(obj) > self.consume_bytearray_size:
            obj = obj[:self.consume_bytearray_size]
        self.consume_bytearray_freelist.append(obj)

    cpdef consume_bytes(self, uint64_t nbytes):
        if nbytes > self.available_bytes:
            return None
        if nbytes == 0:
            logger.warning("consume_bytes: requested unexpected 0 byte")
            return None
        # we know that in total we have at least nbytes available bytes in the buffers, so
        # - we know that we have at least one buffer in the deque
        # - we know that we won't exhaust the buffers
        # - we know that we won't read invalid data from the last buffer
        # start to read from the first buffer in the deque
        # the data we need may be split across multiple buffers, so we may need to loop through the buffers
        cdef unsigned char[:] result = self.get_bytearray(nbytes)
        cdef uint64_t total_read = 0
        cdef bytearray current_read_buffer = self.read_buffers[0]
        cdef unsigned char[:] current_read_view = current_read_buffer
        cdef uint32_t nb_bytes_to_read = 0

        while True:
            nb_bytes_to_read = min(nbytes - total_read, self.read_buffer_size - self.read_pos)
            result[total_read : (total_read + nb_bytes_to_read)] = current_read_view[self.read_pos : (self.read_pos + nb_bytes_to_read)]
            self.read_pos += nb_bytes_to_read
            self.available_bytes -= nb_bytes_to_read
            total_read += nb_bytes_to_read
            if self.read_pos >= self.read_buffer_size:
                # we have read the whole current buffer, discard and move to the next one
                self.read_buffers.popleft()  # discard
                if len(self.read_buffers_freelist) < self.nb_max_read_buffers:
                    # if we have not reached the maximum number of free buffers, add the current buffer to the freelist
                    self.read_buffers_freelist.append(current_read_buffer)
                if self.read_buffers:  # move to next buffer if any
                    current_read_buffer = self.read_buffers[0]
                    current_read_view = current_read_buffer
                    self.read_pos = 0
                else:
                    # this means that we have read exactly all the data from all the buffers
                    assert total_read == nbytes
                    self.read_pos = 0
                    return result
            if total_read == nbytes:
                return result

cdef class SyncMsgQueue:
    def __init__(self):
        self.queue = deque()
        self.mutex = threading.Lock()
        self.not_empty = threading.Condition(self.mutex)
        self.is_shutdown = 0

    cpdef put_nowait(self, item):
        with self.mutex:
            if self.is_shutdown:
                raise SyncMsgQueueShutdown
            self.queue.append(item)
            self.not_empty.notify()

    cpdef get(self):
        with self.not_empty:
            if self.is_shutdown and not len(self.queue):
                raise SyncMsgQueueShutdown

            while not len(self.queue):
                self.not_empty.wait()
                if self.is_shutdown and not len(self.queue):
                    raise SyncMsgQueueShutdown
            return self.queue.popleft()

    cpdef shutdown(self):
        with self.mutex:
            self.is_shutdown = 1
            # All getters need to re-check queue-empty to raise ShutDown
            self.not_empty.notify_all()


cdef class RWLockROProperty:
    def __init__(self, RWLock rwlock):
        self.rwlock = rwlock

    def __enter__(self):
        self.rwlock.acquire_readonly()

    def __exit__(self, exc_type, exc_value, traceback):
        self.rwlock.release_readonly()


cdef class RWLockRWProperty:
    def __init__(self, RWLock rwlock):
        self.rwlock = rwlock

    def __enter__(self):
        self.rwlock.acquire_readwrite()

    def __exit__(self, exc_type, exc_value, traceback):
        self.rwlock.release_readwrite()


cdef class RWLock:
    def __init__(self):
        # flag to indicate if a writer is active
        self._writing = False
        # flag to indicate if a writer is waiting
        self._pending_writers = 0
        # number of active readers
        self._nb_readers = 0
        # lock to protect access to the internal state
        self._lock = threading.Lock()
        # condition variable to wait for readers to finish
        self._no_reader = threading.Condition(self._lock)
        # condition variable to wait for writer to finish
        self._no_writer = threading.Condition(self._lock)

    cpdef acquire_readonly(self):
        with self._lock:
            # wait that there is no active writer and no pending writer
            while self._writing or self._pending_writers > 0:
                self._no_writer.wait()
            self._nb_readers += 1

    cpdef try_acquire_readonly(self):
        # try to acquire the readonly lock without blocking
        # returns True if the lock was acquired, False otherwise
        with self._lock:
            if self._writing or self._pending_writers > 0:
                return False
            self._nb_readers += 1
            return True

    cpdef release_readonly(self):
        with self._lock:
            if self._nb_readers == 0:
                raise RuntimeError("Cannot release readonly lock that is not held")
            self._nb_readers -= 1
            if self._nb_readers == 0:
                # notify writers waiting for readers to finish
                self._no_reader.notify_all()

    cpdef acquire_readwrite(self):
        with self._lock:
            # the pending writer flag prevents new readers from starting, giving priority to writer
            self._pending_writers += 1
            # wait for all readers to finish
            while self._nb_readers > 0:
                self._no_reader.wait()
            # wait for any active writer to finish
            while self._writing:
                self._no_writer.wait()
            # mark the _writing flag so that no new reader/new writer can start
            self._writing = True
            self._pending_writers -= 1

    cpdef try_acquire_readwrite(self):
        # try to acquire the readwrite lock without blocking
        # returns True if the lock was acquired, False otherwise
        with self._lock:
            if self._writing or self._pending_writers > 0 or self._nb_readers > 0:
                return False
            self._writing = True
            return True

    cpdef release_readwrite(self):
        with self._lock:
            if not self._writing:
                raise RuntimeError("Cannot release readwrite lock that is not held")
            self._writing = False
            # notify all readers/writers waiting for writer to finish
            self._no_writer.notify_all()

    @property
    def nb_readers(self):
        with self._lock:
            return self._nb_readers

    @property
    def is_writing(self):
        with self._lock:
            return self._writing

    @property
    def readonly(self):
        return RWLockROProperty(self)

    @property
    def readwrite(self):
        return RWLockRWProperty(self)
