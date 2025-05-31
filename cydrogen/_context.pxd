# cython: language_level=3

from ._decls cimport hydro_hash_CONTEXTBYTES

cdef class Context:
    cdef bytes ctx
    cpdef is_empty(self)


cdef make_context(ctx)
