# cython: language_level=3

from cpython.buffer cimport PyBuffer_FillInfo

from ._decls cimport hydro_hash_CONTEXTBYTES


cdef bytes empty_ctx = bytes(b" " * hydro_hash_CONTEXTBYTES)


cdef pad_validate_ctx(ctx):
    # pads the context to 8 bytes with spaces.
    # raises ValueError if ctx is not a valid ASCII string or if it exceeds 8 bytes.
    if not ctx:
        return empty_ctx
    if isinstance(ctx, str):
        try:
            ctx = ctx.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("Context must be a valid ASCII string")
    ctx = bytes(ctx)
    try:
        ctx.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("Context must be a valid ASCII string")
    if len(ctx) > hydro_hash_CONTEXTBYTES:
        raise ValueError("Context must be 8 bytes long maximum")
    if len(ctx) < hydro_hash_CONTEXTBYTES:
        ctx += b" " * (hydro_hash_CONTEXTBYTES - len(ctx))
    return ctx


cdef class Context:
    def __init__(self, ctx=None):
        cdef Context o
        if isinstance(ctx, Context):
            o = <Context>ctx
            self.ctx = o.ctx
            return
        self.ctx = pad_validate_ctx(ctx)

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        cdef unsigned char* ptr = self.ctx
        PyBuffer_FillInfo(buffer, self, ptr, hydro_hash_CONTEXTBYTES, 1, flags)

    def __str__(self):
        return self.ctx.decode("ascii")

    def __repr__(self):
        return f"Context({repr(str(self))})"

    def __eq__(self, other):
        if other is None:
            return False
        try:
            return self.ctx == pad_validate_ctx(other)
        except (ValueError, TypeError):
            return False

    def __bool__(self):
        return not self.is_empty()

    @classmethod
    def empty(cls):
        return cls()

    cpdef is_empty(self):
        return self.ctx == empty_ctx


cdef make_context(ctx):
    # helper function to return a Context object
    # avoids unnecessary overhead if ctx is already a Context instance
    if isinstance(ctx, Context):
        return ctx
    return Context(ctx)
