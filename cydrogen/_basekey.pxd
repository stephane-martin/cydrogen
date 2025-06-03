# cython: language_level=3

from libc.stdint cimport uint8_t

from ._utils cimport SafeMemory

cdef class BaseKey:
    cdef SafeMemory key
    cdef eq(self, BaseKey other)
    cpdef is_zero(self)
    cpdef writeto(self, out)
