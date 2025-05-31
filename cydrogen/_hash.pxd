# cython: language_level=3

from ._basekey cimport BaseKey
from ._context cimport Context

from ._decls cimport *


cdef class HashKey(BaseKey):
    cpdef hasher(self, data=*, ctx=*, size_t digest_size=*)

cdef make_hashkey(key)

cdef class Hash:
    cdef readonly Context ctx
    cdef readonly HashKey key
    cdef readonly size_t digest_size
    cdef readonly size_t block_size

    cdef hydro_hash_state state
    cdef bytes result
    cdef bint finalized

    cpdef update(self, const unsigned char[:] data)
    cpdef write(self, const unsigned char[:] data)
    cpdef update_from(self, fileobj, chunk_size=*)
    cpdef digest(self)
    cpdef hexdigest(self)


cpdef hash_file(fileobj, ctx=*, size_t digest_size=*, key=*, chunk_size=*)
