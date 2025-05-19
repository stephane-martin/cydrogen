# cython: language_level=3

import base64

from libc.string cimport memcpy
from libc.stdint cimport uint8_t
from cpython.buffer cimport PyBuffer_FillInfo

from ._decls cimport *
from ._random cimport gen_random_buffer


cdef class BaseKey:
    def __cinit__(self, b=None):
        hydro_memzero(&self.key[0], hydro_hash_KEYBYTES)

    def __dealloc__(self):
        hydro_memzero(&self.key[0], hydro_hash_KEYBYTES)

    def __init__(self, b=None):
        if b is None:
            return
        if not isinstance(b, bytes):
            raise TypeError("Key must be a bytes object")
        if len(b) != hydro_hash_KEYBYTES:
            raise ValueError("Key must be 32 bytes long")
        cdef const unsigned char* b_ptr = b
        memcpy(&self.key[0], b_ptr, hydro_hash_KEYBYTES)

    def __str__(self):
        return base64.standard_b64encode(self).decode("ascii")

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.key, hydro_hash_KEYBYTES, 1, flags)

    cdef eq(self, BaseKey other):
        if other is None:
            return False
        cdef const uint8_t* self_ptr = &self.key[0]
        cdef const uint8_t* other_ptr = &other.key[0]
        if self_ptr == other_ptr:
            return True
        return hydro_equal(self_ptr, other_ptr, hydro_secretbox_KEYBYTES) == 1

    @classmethod
    def gen(cls):
        return cls(gen_random_buffer(hydro_hash_KEYBYTES))

    @classmethod
    def zero(cls):
        return cls(b'\x00' * hydro_hash_KEYBYTES)

    cpdef is_zero(self):
        cdef uint8_t z[hydro_hash_KEYBYTES]
        hydro_memzero(&z[0], hydro_hash_KEYBYTES)
        return hydro_equal(&self.key[0], &z[0], hydro_hash_KEYBYTES) == 1

    def __bool__(self):
        return not self.is_zero()
