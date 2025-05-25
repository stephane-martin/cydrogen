# cython: language_level=3

from libc.stdint cimport uint8_t
from ._decls cimport *
from ._context cimport Context


cdef class SignPublicKey:
    cdef uint8_t* key
    cdef eq(self, SignPublicKey other)
    cpdef verifier(self, ctx=*)


cdef class SignSecretKey:
    cdef uint8_t* key
    cdef eq(self, SignSecretKey other)
    cpdef signer(self, ctx=*)
    cdef public_key(self)
    cpdef check_public_key(self, SignPublicKey other)


cdef class SignKeyPair:
    cdef readonly SignSecretKey secret_key
    cdef readonly SignPublicKey public_key
    cpdef signer(self, ctx=*)
    cpdef verifier(self, ctx=*)


cdef class BaseSigner:
    cdef Context ctx
    cdef hydro_sign_state state
    cdef bint finalized
    cpdef update(self, const unsigned char[:] data)
    cpdef write(self, const unsigned char[:] data)
    cpdef update_from(self, fileobj, chunk_size=*)


cdef class Signer(BaseSigner):
    cdef SignSecretKey key
    cpdef sign(self)


cdef class Verifier(BaseSigner):
    cdef SignPublicKey key
    cpdef verify(self, const unsigned char[:] signature)


cpdef sign_file(SignSecretKey key, fileobj, ctx=*, chunk_size=*)
cpdef verify_file(SignPublicKey key, fileobj, const unsigned char[:] signature, ctx=*, chunk_size=*)
