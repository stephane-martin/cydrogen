# cython: language_level=3

from libc.stdint cimport uint8_t


cdef class BaseKey:
    cdef uint8_t* key
    cdef eq(self, BaseKey other)
    cpdef is_zero(self)
