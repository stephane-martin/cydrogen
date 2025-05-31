# cython: language_level=3

from libc.stdint cimport uint64_t

from ._decls cimport *
from ._basekey cimport BaseKey


cdef class MasterKey(BaseKey):
    cpdef derive_key_from_password(self, const unsigned char[:] password, ctx=*, uint64_t opslimit=*)
    cpdef derive_key_from_password_with_length(self, const unsigned char[:] password, size_t length=*, ctx=*, uint64_t opslimit=*)
    cpdef derive_subkey(self, uint64_t subkey_id, ctx=*)
    cpdef derive_subkey_with_length(self, uint64_t subkey_id, size_t length=*, ctx=*)
    cpdef derive_sign_keypair(self)
    cpdef hash_password(self, const unsigned char[:] password, uint64_t opslimit=*)
    cpdef verify_password(self, const unsigned char[:] password, const unsigned char[:] stored, uint64_t opslimit=*)


cdef make_masterkey(key)
