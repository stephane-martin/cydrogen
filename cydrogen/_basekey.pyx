# cython: language_level=3

import base64

from libc.string cimport memcpy
from cpython.buffer cimport PyBuffer_FillInfo

from ._decls cimport keys_equal, basekey_memzero, hydro_hash_KEYBYTES
from ._decls cimport gen_random_buffer
from ._utils cimport free_key, malloc_key, key_is_zero, mprotect_readonly


cdef class BaseKey:
    def __cinit__(self, b=None):
        self.key = malloc_key(hydro_hash_KEYBYTES)

    def __dealloc__(self):
        if self.key != NULL:
            free_key(self.key)

    def __init__(self, b=None):
        if self.key == NULL:
            raise MemoryError("Failed to allocate memory for key")
        basekey_memzero(self.key)
        if b is None:
            mprotect_readonly(self.key)
            return
        if not isinstance(b, bytes):
            raise TypeError("Key must be a bytes object")
        if len(b) != hydro_hash_KEYBYTES:
            raise ValueError("Key must be 32 bytes long")
        cdef const unsigned char* b_ptr = b
        memcpy(self.key, b_ptr, hydro_hash_KEYBYTES)
        mprotect_readonly(self.key)

    def __str__(self):
        return base64.standard_b64encode(self).decode("ascii")

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.key, hydro_hash_KEYBYTES, 1, flags)

    cdef eq(self, BaseKey other):
        if other is None:
            return False
        if self.key == other.key:
            return True
        return keys_equal(self, other)

    @classmethod
    def gen(cls):
        return cls(gen_random_buffer(hydro_hash_KEYBYTES))

    @classmethod
    def zero(cls):
        return cls(b"\x00" * hydro_hash_KEYBYTES)

    cpdef is_zero(self):
        return key_is_zero(self)

    def __bool__(self):
        return not self.is_zero()
