# cython: language_level=3

from libc.stdint cimport uint64_t
from libc.stdint cimport uint32_t

cdef bytes CY_ENC_MSG_MARKER
cdef const size_t CY_ENC_MSG_HEADER_SIZE
cdef bytes CY_KX_N_PACKET1_MARKER
cdef bytes CY_KX_KK_PACKET1_MARKER
cdef bytes CY_KX_KK_PACKET2_MARKER
cdef bytes CY_KX_XX_PACKET1_MARKER
cdef bytes CY_KX_XX_PACKET2_MARKER
cdef bytes CY_KX_XX_PACKET3_MARKER
cdef bytes CY_KX_SERVER_ACK_MARKER


cdef class EncryptedMessage:
    cdef readonly object ciphertext
    cdef readonly uint64_t msg_id
    cdef readonly uint32_t session_keys_idx
    cpdef writeto(self, fileobj)


cdef class KX_N_Packet1:
    cdef readonly bytes packet
    cdef bytes encoded


cdef class KX_KK_Packet1:
    cdef readonly bytes packet
    cdef bytes encoded


cdef class KX_KK_Packet2:
    cdef readonly bytes packet
    cdef bytes encoded


cdef class KX_XX_Packet1:
    cdef readonly bytes packet
    cdef bytes encoded


cdef class KX_XX_Packet2:
    cdef readonly bytes packet
    cdef bytes encoded


cdef class KX_XX_Packet3:
    cdef readonly bytes packet
    cdef bytes encoded


cdef class KX_Server_Ack:
    cdef readonly bytes packet
    cdef bytes encoded
