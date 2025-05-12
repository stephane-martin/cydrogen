# cython: language_level=3

from libc.stdint cimport uint8_t

from ._decls cimport *
from ._basekey cimport BaseKey


cdef class MasterKey(BaseKey):
    cpdef derive_key_from_password(self, password, ctx=*, opslimit=*)
    cpdef derive_key_from_password_with_length(self, password, length=*, ctx=*, opslimit=*)
    cpdef derive_subkey(self, uint64_t subkey_id, ctx=*)
    cpdef derive_subkey_with_length(self, uint64_t subkey_id, length=*, ctx=*)
    cpdef derive_sign_keypair(self)
    cpdef hash_password(self, password, opslimit=*)
    cpdef verify_password(self, password, stored, opslimit=*)
