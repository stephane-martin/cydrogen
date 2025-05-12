# cython: language_level=3

from libc.stdint cimport uint8_t
from ._decls cimport *
from ._context cimport Context


cdef class SignPublicKey:
    cdef uint8_t key[hydro_sign_PUBLICKEYBYTES]
    cdef eq(self, SignPublicKey other)
    cpdef verify(self, const unsigned char[:] message, const unsigned char[:] signature, ctx=*)
    cpdef verifier(self, ctx=*)


cdef class SignSecretKey:
    cdef uint8_t key[hydro_sign_SECRETKEYBYTES]
    cdef eq(self, SignSecretKey other)
    cpdef sign(self, const unsigned char[:] message, ctx=*)
    cpdef signer(self, ctx=*)
    cdef public_key(self)
    cpdef check_publick_key(self, SignPublicKey other)


cdef class SignKeyPair:
    cdef readonly SignSecretKey secret_key
    cdef readonly SignPublicKey public_key
    cpdef sign(self, const unsigned char[:] message, ctx=*)
    cpdef verify(self, const unsigned char[:] message, const unsigned char[:] signature, ctx=*)
    cpdef signer(self, ctx=*)
    cpdef verifier(self, ctx=*)


cdef class BaseSigner:
    cdef Context ctx
    cdef hydro_sign_state state
    cdef bint finalized
    cpdef update(self, const unsigned char[:] data)


cdef class Signer(BaseSigner):
    cdef SignSecretKey key
    cpdef sign(self)


cdef class Verifier(BaseSigner):
    cdef SignPublicKey key
    cpdef verify(self, const unsigned char[:] signature)
