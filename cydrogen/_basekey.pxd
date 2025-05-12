# cython: language_level=3

from libc.stdint cimport uint8_t
from ._decls cimport hydro_hash_KEYBYTES


cdef class BaseKey:
    cdef uint8_t key[hydro_hash_KEYBYTES]
    cdef eq(self, BaseKey other)
    cpdef is_zero(self)
