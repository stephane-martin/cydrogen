# cython: language_level=3

from libc.stdint cimport uint64_t

from ._basekey cimport BaseKey
from ._context cimport Context


cdef bytes _ENC_MSG_HEADER
cdef const size_t _ENC_MSG_HEADER_SIZE


cdef class SecretBoxKey(BaseKey):
    cpdef secretbox(self, ctx=*)


cdef make_secretbox_key(key)
cpdef parse_encrypted_message_header(const unsigned char[:] header)
cpdef encrypted_message_header(const unsigned char[:] ciphertext, uint64_t msg_id)

cdef class EncryptedMessage:
    cdef readonly object ciphertext
    cdef readonly uint64_t msg_id
    cdef header(self)
    cpdef writeto(self, fileobj)
    cpdef decrypt(self, key, ctx=*, out=*)


cdef class SecretBox:
    cdef readonly SecretBoxKey key
    cdef readonly Context ctx
    cpdef encrypt(self, const unsigned char[:] plaintext, uint64_t msg_id=*, out=*, max_msg_size=*)
    cpdef decrypt(self, ciphertext, uint64_t msg_id=*, out=*, max_msg_size=*)
    cpdef encrypt_file(self, src, dst, size_t chunk_size=*)
    cdef _encrypt_file(self, fileobj, out, size_t chunk_size=*)
    cpdef decrypt_file(self, src, out)
    cdef _decrypt_file(self, fileobj, out)
