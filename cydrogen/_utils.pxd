# cython: language_level=3

cimport cython

from libc.stdint cimport int64_t
from libc.stdint cimport uint64_t
from libc.stdint cimport uint32_t
from libc.stdint cimport uint16_t
from libc.stdint cimport uint8_t


cdef extern from "<stdatomic.h>" nogil:
    ctypedef uint64_t atomic_ullong

    ctypedef enum memory_order:
        memory_order_relaxed
        memory_order_consume
        memory_order_acquire
        memory_order_release
        memory_order_acq_rel
        memory_order_seq_cst

    void atomic_store_explicit(atomic_ullong* object, uint64_t desired, memory_order order)
    uint64_t atomic_fetch_add_explicit(atomic_ullong* object, uint64_t operand, memory_order order)
    uint64_t atomic_load_explicit(atomic_ullong* object, memory_order order)


cdef extern from "cyutils.h" nogil:
    int cyd_is_zero(const unsigned char *n, const size_t nlen)
    int cyd_mlock(void * const addr, const size_t len)
    int cyd_munlock(void * const addr, const size_t len)
    int cyd_mprotect_noaccess(void *ptr)
    int cyd_mprotect_readonly(void *ptr)
    int cyd_mprotect_readwrite(void *ptr)

    void *cyd_malloc(const size_t size)
    void *cyd_allocarray(size_t count, size_t size)
    void cyd_free(void *ptr)
    void cyd_memzero(void * const pnt, const size_t length)
    int cyd_memcmp(const void * const b1_, const void * const b2_, size_t length)
    int cyd_is_zero(const unsigned char *n, const size_t nlen)

    uint64_t cyd_load64_le(const uint8_t src[8])
    void cyd_store64_le(uint8_t dst[8], uint64_t w)
    uint32_t cyd_load32_le(const uint8_t src[4])
    void cyd_store32_le(uint8_t dst[4], uint32_t w)
    uint16_t cyd_load16_le(const uint8_t src[2])
    void cyd_store16_le(uint8_t dst[2], uint16_t w)
    uint64_t cyd_load64_be(const uint8_t src[8])
    void cyd_store64_be(uint8_t dst[8], uint64_t w)
    uint32_t cyd_load32_be(const uint8_t src[4])
    void cyd_store32_be(uint8_t dst[4], uint32_t w)
    uint16_t cyd_load16_be(const uint8_t src[2])
    void cyd_store16_be(uint8_t dst[2], uint16_t w)

    int cyd_have_mman()
    int cyd_is_little_endian()
    int cyd_is_big_endian()


cdef extern from "fnv.h" nogil:
    int64_t fnv_impl(const void *src, uint64_t len, uint32_t prefix, uint32_t suffix)


@cython.auto_pickle(False)
cdef class Counter:
    cdef atomic_ullong count

    cpdef uint64_t value(self) noexcept


@cython.final
cdef class SafeMemory:
    cdef bint readonly_protected
    cdef void *ptr
    cdef size_t size

    cdef set(self, const unsigned char[:] data)
    cdef mark_readonly(self)
    cpdef writeto(self, out)


cdef uint64_t _load64(const unsigned char[:] src) noexcept nogil
cdef void _store64(unsigned char[:] dst, uint64_t src) noexcept nogil
cdef uint32_t _load32(const unsigned char[:] src) noexcept nogil
cdef void _store32(unsigned char[:] dst, uint32_t src) noexcept nogil
cdef uint16_t _load16(const unsigned char[:] src) noexcept nogil
cdef void _store16(unsigned char[:] dst, uint16_t src) noexcept nogil

cpdef load64(const unsigned char[:] src)
cpdef store64(unsigned char[:] dst, uint64_t src)
cpdef load32(const unsigned char[:] src)
cpdef store32(unsigned char[:] dst, uint32_t src)
cpdef load16(const unsigned char[:] src)
cpdef store16(unsigned char[:] dst, uint16_t src)


cpdef encode_length(obj)


@cython.final
cdef class FileOpener:
    cdef object fileobj
    cdef object path
    cdef str mode


@cython.final
cdef class SafeReader:
    cdef object fileobj
    cdef bint direct
    cdef bint has_readinto
    cpdef readinto(self, unsigned char[:] buf)
    cpdef read(self, size_t length=*)


@cython.final
cdef class AsyncSafeReader:
    cdef object reader
    cdef bint has_readexactly


@cython.final
cdef class SafeWriter:
    cdef object fileobj
    cdef bint direct
    cpdef write(self, const unsigned char[:] buf)


cdef make_safe_reader(fileobj)
cdef make_async_safe_reader(reader)
cdef make_safe_writer(fileobj)
cpdef int64_t fnv(const unsigned char[:] src) noexcept
