# cython: language_level=3

from ._basekey cimport BaseKey

from ._decls cimport *


cdef class HashKey(BaseKey):
    pass


cdef class Hash:
    cdef hydro_hash_state state
    cdef readonly size_t digest_size
    cdef readonly size_t block_size
    cdef bytes result
    cdef bint finalized

    cpdef update(self, const unsigned char[:] data)
    cpdef write(self, const unsigned char[:] data)
    cpdef digest(self)
    cpdef hexdigest(self)
