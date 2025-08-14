# cython: language_level=3, overflowcheck=True

from cpython.bytearray cimport PyByteArray_Resize
from libc.stdint cimport uint16_t
from libc.stdint cimport uint32_t
from libc.stdint cimport uint64_t

from ._decls cimport hydro_secretbox_HEADERBYTES
from ._secretbox cimport parse_encrypted_message_header, _ENC_MSG_HEADER_SIZE

import asyncio
import logging
from collections import deque

from .exceptions import MessageTooBigException


logger = logging.getLogger("cydrogen")


cdef class BytearrayBuilder:
    def __init__(self):
        self.b = bytearray(65536)
        self.offset = 0

    cpdef add(self, const unsigned char[:] data):
        if self.offset + len(data) > len(self.b):
            # we don't have enough space in the bytearray, resize it
            if PyByteArray_Resize(self.b, self.offset + len(data)) < 0:
                raise MemoryError("Failed to resize bytearray")
        cdef unsigned char[:] mv = self.b
        mv[self.offset : self.offset + len(data)] = data[0 : len(data)]
        self.offset += len(data)

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

    cpdef consume_message(self):
        header = self.peek_bytes(_ENC_MSG_HEADER_SIZE)
        if header is None:
            # not enough data to read the header
            return None
        ciphertext_size, _ = parse_encrypted_message_header(header)
        plaintext_size = ciphertext_size - hydro_secretbox_HEADERBYTES
        if plaintext_size > self.received_msg_max_size:
            # the message is too large, we cannot handle it
            # it's more efficient to check the message size here rather than after consuming the bytes or decrypting the message
            # we avoid unnecessary memory allocations and decryption attempts
            raise MessageTooBigException
        # try to consume for real
        b = self.consume_bytes(_ENC_MSG_HEADER_SIZE + ciphertext_size)
        if b is None:
            # not enough data to read the whole message
            return None
        return b

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
