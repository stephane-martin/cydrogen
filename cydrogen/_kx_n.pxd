# cython: language_level=3

from libc.stdint cimport uint8_t

from ._basekey cimport BaseKey
from ._datastructs cimport KX_KK_Packet1, KX_KK_Packet2, KX_N_Packet1, KX_XX_Packet1, KX_XX_Packet2, KX_XX_Packet3
from ._decls cimport hydro_kx_keypair, hydro_kx_state
from ._secretbox cimport SecretBoxKey
from ._utils cimport SafeMemory


cdef class Psk(BaseKey):
    pass


cdef class SessionPair:
    cdef readonly SecretBoxKey rx
    cdef readonly SecretBoxKey tx


cdef class KxPublicKey:
    cdef SafeMemory kp

    cdef uint8_t* ptr(self)


cdef class KxSecretKey:
    cdef SafeMemory kp

    cdef uint8_t* ptr(self)


cdef class KxPair:
    cdef SafeMemory kp

    cdef hydro_kx_keypair* ptr(self)
    cpdef public_key(self)
    cpdef secret_key(self)

    cpdef client_init_kx_kk(self, KxPublicKey server_public_key)
    cpdef client_init_kx_xx(self, Psk psk=*)
    cpdef server_process_kx_kk(self, KxPublicKey client_public_key, KX_KK_Packet1 packet1)
    cpdef server_process_kx_xx(self, KX_XX_Packet1 packet1, Psk psk=*)
    cpdef server_finish_kx_n(self, KX_N_Packet1 packet1, Psk psk=*)


cdef class KxKkClientState:
    cdef readonly KX_KK_Packet1 packet1
    cdef readonly SessionPair _session_pair
    cdef KxPair client_kp
    cdef hydro_kx_state state
    cdef object mu

    cpdef client_finish_kx_kk(self, KX_KK_Packet2 packet2)


cdef class KxXxClientState:
    cdef readonly KX_XX_Packet1 packet1
    cdef readonly KX_XX_Packet3 _packet3
    cdef readonly SessionPair _session_pair
    cdef readonly KxPublicKey _server_public_key
    cdef object mu

    cdef KxPair client_kp
    cdef Psk psk
    cdef hydro_kx_state state

    cpdef client_process_kx_xx(self, KX_XX_Packet2 packet2)

cdef class KxXxServerState:
    cdef readonly KX_XX_Packet2 packet2
    cdef readonly SessionPair _session_pair
    cdef readonly KxPublicKey _client_public_key
    cdef object mu

    cdef Psk psk
    cdef hydro_kx_state state

    cpdef server_finish_kx_xx(self, KX_XX_Packet3 packet3)

cpdef client_init_kx_n(KxPublicKey peer, Psk psk=*)
cpdef server_finish_kx_n(KxPair static, KX_N_Packet1 packet1, Psk psk=*)
