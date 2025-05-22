# cython: language_level=3

from ._decls cimport hydro_hash_CONTEXTBYTES

cdef class Context:
    cdef char ctx[hydro_hash_CONTEXTBYTES]
    cpdef is_empty(self)
