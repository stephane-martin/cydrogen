# cython: language_level=3

from libc.stdint cimport uint8_t

from ._basekey cimport BaseKey
from ._decls cimport hydro_kx_keypair, hydro_kx_state
from ._secretbox cimport SecretBoxKey
from ._utils cimport SafeMemory

from dataclasses import dataclass


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
    cpdef server_process_kx_kk(self, KxPublicKey client_public_key, bytes packet1)
    cpdef server_process_kx_xx(self, bytes packet1, Psk psk=*)
    cpdef server_finish_kx_n(self, bytes packet1, Psk psk=*)


cdef class KxKkClientState:
    cdef readonly bytes packet1
    cdef readonly SessionPair session_pair
    cdef KxPair client_kp
    cdef hydro_kx_state state

    cpdef client_finish_kx_kk(self, bytes packet2)


cdef class KxXxClientState:
    cdef readonly bytes packet1
    cdef readonly bytes packet3
    cdef readonly SessionPair session_pair
    cdef readonly KxPublicKey server_public_key

    cdef KxPair client_kp
    cdef Psk psk
    cdef hydro_kx_state state

    cpdef client_process_kx_xx(self, bytes packet2)

cdef class KxXxServerState:
    cdef readonly bytes packet2
    cdef readonly SessionPair session_pair
    cdef readonly KxPublicKey client_public_key

    cdef Psk psk
    cdef hydro_kx_state state

    cpdef server_finish_kx_xx(self, bytes packet3)

cpdef client_init_kx_n(KxPublicKey peer, Psk psk=*)
cpdef server_finish_kx_n(KxPair static, bytes packet1, Psk psk=*)
