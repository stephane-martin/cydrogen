# cython: language_level=3


cdef class FileOpener:
    cdef object fileobj
    cdef object path
    cdef str mode
    cdef __enter__(self)


cdef class SafeReader:
    cdef object fileobj
    cdef bint direct
    cpdef readinto(self, unsigned char[:] buf)
    cpdef read(self, size_t length)


cdef class SafeWriter:
    cdef object fileobj
    cdef bint direct
    cpdef write(self, const unsigned char[:] buf)


cdef class TeeWriter:
    cdef SafeWriter w1
    cdef SafeWriter w2
    cpdef write(self, const unsigned char[:] buf)
