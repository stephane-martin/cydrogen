# cython: language_level=3

from libc.stdint cimport uint8_t

from ._basekey cimport BaseKey
from ._decls cimport hydro_kx_keypair
from ._secretbox cimport SecretBoxKey
from ._utils cimport SafeMemory

from dataclasses import dataclass


cdef class Psk(BaseKey):
    cdef uint8_t* ptr(self)


@dataclass
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

cpdef kx_n_gen_session_and_packet(KxPublicKey peer, Psk psk=*)
cpdef kx_n_gen_session_from_packet(KxPair static, bytes packet1, Psk psk=*)
