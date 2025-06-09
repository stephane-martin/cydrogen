# cython: language_level=3

from cpython.buffer cimport PyBuffer_FillInfo
from libc.stdint cimport uint8_t
from libc.string cimport memcpy

from ._basekey cimport BaseKey
from ._decls cimport kx_keygen, hydro_kx_keypair, hydro_kx_PUBLICKEYBYTES, hydro_kx_SECRETKEYBYTES, hydro_kx_N_PACKET1BYTES
from ._decls cimport kx_n_1, kx_n_2
from ._exceptions cimport KeyExchangeException
from ._secretbox cimport SecretBoxKey

import base64


KP_SIZE = sizeof(hydro_kx_keypair)


cdef class Psk(BaseKey):
    def __repr__(self):
        return f'Psk({repr(str(self))})'

    cdef uint8_t* ptr(self):
        return <uint8_t*>(self.key.ptr)


cdef class SessionPair:
    def __repr__(self):
        return f'SessionPair(rx={repr(self.rx)}, tx={repr(self.tx)})'


cdef class KxPublicKey:
    def __init__(self, kp):
        if kp is None:
            raise ValueError("pk cannot be None")
        if isinstance(kp, SafeMemory):
            if len(kp) != KP_SIZE:
                raise ValueError(f"safemem must be {KP_SIZE} bytes long")
            self.kp = kp
            return
        if isinstance(kp, str):
            kp = base64.standard_b64decode(kp)
        kp = bytes(kp)
        if len(kp) != hydro_kx_PUBLICKEYBYTES:
            raise ValueError(f"{hydro_kx_PUBLICKEYBYTES} bytes required for public key")
        cdef SafeMemory mem = SafeMemory(KP_SIZE)
        cdef hydro_kx_keypair* kp_ptr = <hydro_kx_keypair*>(<void*>(mem.ptr))
        cdef uint8_t* src = kp
        cdef uint8_t* dst = <uint8_t*>(kp_ptr.pk)
        memcpy(dst, src, hydro_kx_PUBLICKEYBYTES)
        mem.mark_readonly()
        self.kp = mem

    cdef uint8_t* ptr(self):
        cdef hydro_kx_keypair* kp_ptr = <hydro_kx_keypair*>(<void*>(self.kp.ptr))
        return <uint8_t*>(kp_ptr.pk)

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.ptr(), hydro_kx_PUBLICKEYBYTES, 1, flags)

    def __str__(self):
        return base64.standard_b64encode(bytes(self)).decode("utf-8")

    def __repr__(self):
        return f'KxPublicKey({repr(str(self))})'


cdef class KxSecretKey:
    # length hydro_kx_SECRETKEYBYTES
    def __init__(self, kp):
        if kp is None:
            raise ValueError("kp cannot be None")
        if isinstance(kp, SafeMemory):
            if len(kp) != KP_SIZE:
                raise ValueError(f"safemem must be {KP_SIZE} bytes long")
            self.kp = kp
            return
        if isinstance(kp, str):
            kp = base64.standard_b64decode(kp)
        kp = bytes(kp)
        if len(kp) != hydro_kx_SECRETKEYBYTES:
            raise ValueError(f"{hydro_kx_SECRETKEYBYTES} bytes required for secret key")
        cdef SafeMemory mem = SafeMemory(KP_SIZE)
        cdef hydro_kx_keypair* kp_ptr = <hydro_kx_keypair*>(<void*>(mem.ptr))
        cdef uint8_t* src = kp
        cdef uint8_t* dst = <uint8_t*>(kp_ptr.sk)
        memcpy(dst, src, hydro_kx_SECRETKEYBYTES)
        mem.mark_readonly()
        self.kp = mem

    cdef uint8_t* ptr(self):
        cdef hydro_kx_keypair* kp_ptr = <hydro_kx_keypair*>(<void*>(self.kp.ptr))
        return <uint8_t*>(kp_ptr.sk)

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.ptr(), hydro_kx_SECRETKEYBYTES, 1, flags)

    def __str__(self):
        return base64.standard_b64encode(bytes(self)).decode("utf-8")

    def __repr__(self):
        return f'KxSecretKey({repr(str(self))})'


cdef class KxPair:
    def __init__(self, kp):
        if kp is None:
            raise ValueError("kp cannot be None")
        if isinstance(kp, SafeMemory):
            # no need to allocate a new SafeMemory object
            if len(kp) != KP_SIZE:
                raise ValueError(f"safemem must be {KP_SIZE} bytes long")
            self.kp = kp
            return
        if isinstance(kp, str):
            kp = base64.standard_b64decode(kp)
        kp = bytes(kp)
        if len(kp) != KP_SIZE:
            raise ValueError(f"{KP_SIZE} bytes required for keypair")
        self.kp = SafeMemory.from_buffer(kp)

    cdef hydro_kx_keypair* ptr(self):
        return <hydro_kx_keypair*>(<void*>(self.kp.ptr))

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.ptr(), sizeof(hydro_kx_keypair), 1, flags)

    def __str__(self):
        return base64.standard_b64encode(bytes(self)).decode("utf-8")

    def __repr__(self):
        return f'KxPair({repr(str(self))})'

    def __bool__(self):
        return bool(self.kp)

    def __len__(self):
        return len(self.kp)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, KxPair):
            return False
        cdef KxPair o = <KxPair>other
        return self.kp == o.kp

    cpdef public_key(self):
        return KxPublicKey(self.kp)

    cpdef secret_key(self):
        return KxSecretKey(self.kp)

    @classmethod
    def gen(cls):
        return cls(kx_keygen())


cpdef kx_n_gen_session_and_packet(KxPublicKey peer, Psk psk=None):
    # generate the first packet for the key exchange
    if peer is None:
        raise ValueError("peer cannot be None")
    try:
        rx, tx, packet1 = kx_n_1(peer, psk)
    except RuntimeError as ex:
        raise KeyExchangeException("failed to generate first packet") from ex
    cdef SessionPair pair = SessionPair(rx=SecretBoxKey(rx), tx=SecretBoxKey(tx))
    return pair, packet1


cpdef kx_n_gen_session_from_packet(KxPair static_kp, bytes packet1, Psk psk=None):
    if static_kp is None:
        raise ValueError("static key pair cannot be None")
    if packet1 is None:
        raise ValueError("packet1 cannot be None")
    if len(packet1) != hydro_kx_N_PACKET1BYTES:
        raise ValueError(f"Packet1 must be {hydro_kx_N_PACKET1BYTES} bytes long")
    try:
        rx, tx = kx_n_2(packet1, psk, static_kp)
    except RuntimeError as ex:
        raise KeyExchangeException("failed to generate session from packet") from ex
    return SessionPair(rx=SecretBoxKey(rx), tx=SecretBoxKey(tx))
