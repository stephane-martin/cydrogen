# cython: language_level=3

from cpython.buffer cimport PyBuffer_FillInfo
from libc.string cimport memcpy

from ._decls cimport *


cdef class Context:
    """
    A context is composed of exactly 8 bytes. Many features of this library require a context.
    The context is not secret, but it helps to avoid mistakes by separating different domains.
    The same crypto feature working in different contexts will produce different results.
    """

    def __cinit__(self, ctx=None):
        hydro_memzero(&self.ctx[0], hydro_hash_CONTEXTBYTES)

    def __init__(self, ctx=None):
        cdef Context other
        cdef const char* src_ptr

        # if ctx is None, return the empty context
        # the empty context is all spaces
        if ctx is None:
            spaces = b' ' * hydro_hash_CONTEXTBYTES
            src_ptr = spaces
            memcpy(&self.ctx[0], src_ptr, hydro_hash_CONTEXTBYTES)
            return

        # if ctx is a Context, copy the context
        if isinstance(ctx, Context):
            other = <Context>ctx
            memcpy(&self.ctx[0], &other.ctx[0], hydro_hash_CONTEXTBYTES)
            return

        # if ctx is a string, encode it to bytes
        if isinstance(ctx, str):
            ctx = ctx.encode('ascii')

        # else, assume ctx is a bytes like object
        cdef const unsigned char[:] ctx_view = ctx
        if len(ctx_view) != hydro_hash_CONTEXTBYTES:
            raise ValueError("Context must be 8 bytes long")
        memcpy(&self.ctx[0], &ctx_view[0], hydro_hash_CONTEXTBYTES)

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.ctx, hydro_hash_CONTEXTBYTES, 1, flags)

    def __eq__(self, other):
        if not isinstance(other, Context):
            return False
        cdef Context o = <Context>other
        cdef const char* self_ptr = &self.ctx[0]
        cdef const char* other_ptr = &o.ctx[0]
        if self_ptr == other_ptr:
            return True
        return hydro_equal(self_ptr, other_ptr, hydro_hash_CONTEXTBYTES) == 1
