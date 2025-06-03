# cython: language_level=3

from libc.stdint cimport uint8_t

from ._context cimport Context
from ._decls cimport *
from ._utils cimport SafeMemory


cdef class SignPublicKey:
    cdef SafeMemory key
    cpdef writeto(self, out)
    cpdef verifier(self, ctx=*)


cdef make_sign_public_key(key)


cdef class SignSecretKey:
    cdef SafeMemory key
    cdef public_key(self)
    cpdef writeto(self, out)
    cpdef check_public_key(self, SignPublicKey other)
    cpdef signer(self, ctx=*)


cdef make_sign_secret_key(key)


cdef class SignKeyPair:
    cdef readonly SignSecretKey secret_key
    cdef readonly SignPublicKey public_key
    cpdef writeto(self, out)
    cpdef signer(self, ctx=*)
    cpdef verifier(self, ctx=*)


cdef class BaseSigner:
    cdef readonly Context ctx
    cdef hydro_sign_state state
    cdef bint finalized
    cpdef update(self, const unsigned char[:] data)
    cpdef write(self, const unsigned char[:] data)
    cpdef update_from(self, fileobj, chunk_size=*)


cdef class Signer(BaseSigner):
    cdef readonly SignSecretKey key
    cpdef sign(self)


cdef class Verifier(BaseSigner):
    cdef readonly SignPublicKey key
    cpdef verify(self, const unsigned char[:] signature)


cpdef sign_file(key, fileobj, ctx=*, chunk_size=*)
cpdef verify_file(key, fileobj, const unsigned char[:] signature, ctx=*, chunk_size=*)
