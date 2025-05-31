# cython: language_level=3

cimport cython
from libc.stdint cimport uint64_t
from libc.stdint cimport uint32_t
from libc.stdint cimport uint16_t
from libc.stdint cimport uint8_t


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


cdef class SafeMemory:
    cdef void *ptr
    cdef size_t size

    cpdef set(self, const unsigned char[:] data)
    cpdef set_zero(self)


cdef inline uint64_t _load64(const unsigned char[:] src) nogil:
    with cython.boundscheck(False):
        return cyd_load64_be(&src[0])


cdef inline void _store64(unsigned char[:] dst, uint64_t src) nogil:
    with cython.boundscheck(False):
        cyd_store64_be(&dst[0], src)


cdef inline uint32_t _load32(const unsigned char[:] src) nogil:
    with cython.boundscheck(False):
        return cyd_load32_be(&src[0])


cdef inline void _store32(unsigned char[:] dst, uint32_t src) nogil:
    with cython.boundscheck(False):
        cyd_store32_be(&dst[0], src)


cdef inline uint16_t _load16(const unsigned char[:] src) nogil:
    with cython.boundscheck(False):
        return cyd_load16_be(&src[0])


cdef inline void _store16(unsigned char[:] dst, uint16_t src) nogil:
    with cython.boundscheck(False):
        cyd_store16_be(&dst[0], src)


cpdef load64(const unsigned char[:] src)
cpdef store64(unsigned char[:] dst, uint64_t src)
cpdef load32(const unsigned char[:] src)
cpdef store32(unsigned char[:] dst, uint32_t src)
cpdef load16(const unsigned char[:] src)
cpdef store16(unsigned char[:] dst, uint16_t src)

cdef mprotect_readonly(void *ptr)
cdef uint8_t* malloc_key(size_t size) noexcept nogil
cdef void free_key(uint8_t* ptr) noexcept nogil
cdef key_is_zero(const unsigned char[:] key)

cdef class FileOpener:
    cdef object fileobj
    cdef object path
    cdef str mode
    cdef __enter__(self)


cdef class SafeReader:
    cdef object fileobj
    cdef bint direct
    cdef bint has_readinto
    cpdef readinto(self, unsigned char[:] buf)
    cpdef read(self, size_t length=*)


cdef class SafeWriter:
    cdef object fileobj
    cdef bint direct
    cpdef write(self, const unsigned char[:] buf)


cdef class TeeWriter:
    cdef SafeWriter w1
    cdef SafeWriter w2
    cpdef write(self, const unsigned char[:] buf)
