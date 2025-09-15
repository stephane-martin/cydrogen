# cython: language_level=3

cimport cython
from libc.stdint cimport uint16_t
from libc.stdint cimport uint32_t
from libc.stdint cimport uint64_t


@cython.final
cdef class BytearrayBuilder:
    cdef bytearray b
    cdef size_t offset

    cpdef add(self, const unsigned char[:] data)
    cpdef get(self)


@cython.final
cdef class MsgQueue:
    cdef object readers_futures     # A list of futures for readers waiting for messages
    cdef object msg_deque           # A deque of messages
    cdef size_t _bytesize   # The total size of the messages in the queue in bytes
    cdef object exc                 # Exception to raise when closing the queue

    cpdef put_nowait(self, msg, uint64_t msg_id=*)
    cpdef close(self, exc=*)


@cython.final
cdef class SyncMsgQueue:
    cdef object queue
    cdef object mutex
    cdef object not_empty
    cdef bint is_shutdown

    cpdef put_nowait(self, item)
    cpdef get(self)
    cpdef shutdown(self)


@cython.final
cdef class ReadBuffers:
    cdef object read_buffers
    cdef uint16_t nb_max_read_buffers
    cdef uint32_t read_buffer_size
    cdef bytearray current_read_buffer
    cdef uint32_t write_pos
    cdef uint32_t read_pos
    cdef uint64_t available_bytes
    cdef object read_buffers_freelist
    cdef object consume_bytearray_freelist
    cdef uint16_t consume_bytearray_size
    cdef size_t received_msg_max_size

    cpdef get_buffer(self)
    cpdef buffer_updated(self, uint32_t nbytes)
    cpdef consume_message(self)
    cpdef consume_kx_packet(self)
    cpdef consume_server_ack(self)
    cpdef peek_message_type(self)
    cdef peek_bytes(self, uint16_t nbytes)
    cdef get_bytearray(self, uint64_t nbytes)
    cpdef release_bytearray(self, const unsigned char[:] mv)
    cpdef consume_bytes(self, uint64_t nbytes)


@cython.final
cdef class RWLock:
    cdef bint _writing
    cdef uint32_t _pending_writers
    cdef uint32_t _nb_readers
    cdef object _lock
    cdef object _no_reader
    cdef object _no_writer

    cpdef acquire_readonly(self)
    cpdef release_readonly(self)
    cpdef acquire_readwrite(self)
    cpdef release_readwrite(self)
    cpdef try_acquire_readonly(self)
    cpdef try_acquire_readwrite(self)


@cython.final
cdef class RWLockROProperty:
    cdef RWLock rwlock


@cython.final
cdef class RWLockRWProperty:
    cdef RWLock rwlock
