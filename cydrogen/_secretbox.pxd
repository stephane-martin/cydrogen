# cython: language_level=3

from libc.stdint cimport uint64_t

from ._basekey cimport BaseKey
from ._context cimport Context


cdef class SecretBoxKey(BaseKey):
    pass


cdef class EncryptedMessage:
    cdef readonly const unsigned char[:] message
    cdef readonly uint64_t msg_id
    cpdef writeto(self, fileobj)
    cpdef decrypt(self, key, ctx=*, out=*)


cdef class SecretBox:
    cdef SecretBoxKey key
    cdef Context ctx

    cpdef encrypt(self, const unsigned char[:] plaintext, msg_id=*, out=*)
    cpdef decrypt(self, const unsigned char[:] ciphertext, msg_id=*, out=*)
    cpdef encrypt_file(self, src, dst, chunk_size=*)
    cdef _encrypt_file(self, fileobj, out, chunk_size=*)
    cpdef decrypt_file(self, src, out)
    cdef _decrypt_file(self, fileobj, out)
