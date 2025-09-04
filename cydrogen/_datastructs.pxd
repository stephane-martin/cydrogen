# cython: language_level=3

from libc.stdint cimport uint64_t

cdef bytes CY_ENC_MSG_MARKER
cdef const size_t CY_ENC_MSG_HEADER_SIZE

cpdef parse_encrypted_message_header(const unsigned char[:] header)
cpdef encrypted_message_header(uint64_t msg_id)

cdef class EncryptedMessage:
    cdef readonly object ciphertext
    cdef readonly uint64_t msg_id
    cdef header(self)
    cpdef writeto(self, fileobj)
