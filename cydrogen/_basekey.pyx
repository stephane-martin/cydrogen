# cython: language_level=3

from cpython.buffer cimport PyBuffer_FillInfo

from ._decls cimport randomize_buffer, hydro_hash_KEYBYTES
from ._utils cimport SafeMemory

import base64


cdef class BaseKey:
    def __init__(self, b=None):
        if b is None:
            # empty key
            self.key = SafeMemory(hydro_hash_KEYBYTES)
            self.key.set_zero()
            return
        if isinstance(b, SafeMemory):
            # no need to allocate a new SafeMemory object
            if len(b) != hydro_hash_KEYBYTES:
                raise ValueError("Key must be 32 bytes long")
            self.key = b
            return
        if not isinstance(b, bytes):
            raise TypeError("Key must be a bytes object")
        if len(b) != hydro_hash_KEYBYTES:
            raise ValueError("Key must be 32 bytes long")
        self.key = SafeMemory.from_buffer(b)

    def __str__(self):
        return base64.standard_b64encode(self).decode("ascii")

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.key.ptr, self.key.size, 1, flags)

    # because BaseKey does not implement __eq__, equality checks between
    # base keys and subclasses will go through the __eq__ method of the subclass.
    # so that basekey == specialized_key returns False
    cdef eq(self, BaseKey other):
        if other is None:
            return False
        return self.key == other.key

    @classmethod
    def gen(cls):
        cdef SafeMemory mem = SafeMemory(hydro_hash_KEYBYTES)
        randomize_buffer(mem)
        mem.mark_readonly()
        return cls(mem)

    @classmethod
    def zero(cls):
        return cls(b"\x00" * hydro_hash_KEYBYTES)

    cpdef is_zero(self):
        return not bool(self.key)

    def __bool__(self):
        return bool(self.key)

    cpdef writeto(self, out):
        if out is None:
            raise ValueError("Output cannot be None")
        return self.key.writeto(out)

    @classmethod
    def read_from(cls, reader):
        if reader is None:
            raise ValueError("Reader cannot be None")
        cdef SafeMemory mem = SafeMemory.read_from(reader, hydro_hash_KEYBYTES)
        return cls(mem)
