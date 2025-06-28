# cython: language_level=3

cimport cython
from ._decls cimport hydro_hash_CONTEXTBYTES


@cython.final
cdef class Context:
    cdef bytes ctx
    cpdef is_empty(self)


cdef make_context(ctx)
