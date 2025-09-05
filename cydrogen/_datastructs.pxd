# cython: language_level=3

from libc.stdint cimport uint64_t

cdef bytes CY_ENC_MSG_MARKER
cdef const size_t CY_ENC_MSG_HEADER_SIZE

cdef class EncryptedMessage:
    cdef readonly object ciphertext
    cdef readonly uint64_t msg_id
    cdef bytearray encoded
    cpdef writeto(self, fileobj)
