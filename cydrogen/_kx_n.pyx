# cython: language_level=3

from cpython.buffer cimport PyBuffer_FillInfo
from libc.stdint cimport uint8_t
from libc.string cimport memcmp, memcpy

from ._basekey cimport BaseKey
from ._decls cimport kx_keygen, hydro_kx_keypair
from ._decls cimport hydro_kx_PUBLICKEYBYTES, hydro_kx_SECRETKEYBYTES, hydro_kx_N_PACKET1BYTES
from ._decls cimport hydro_kx_KK_PACKET1BYTES, hydro_kx_KK_PACKET2BYTES
from ._decls cimport kx_n_1, kx_n_2, kx_kk_1, kx_kk_2, kx_kk_3
from ._exceptions cimport KeyExchangeException
from ._secretbox cimport SecretBoxKey

import base64


KP_SIZE = sizeof(hydro_kx_keypair)


cdef class Psk(BaseKey):
    def __repr__(self):
        return f'Psk({repr(str(self))})'

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, Psk):
            return False
        cdef Psk o = <Psk>other
        return self.key == o.key


cdef class SessionPair:
    def __init__(self, SecretBoxKey rx, SecretBoxKey tx):
        if rx is None or tx is None:
            raise ValueError("rx and tx cannot be None")
        self.rx = rx
        self.tx = tx

    def __repr__(self):
        return f'SessionPair(rx={repr(self.rx)}, tx={repr(self.tx)})'

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, SessionPair):
            return False
        cdef SessionPair o = <SessionPair>other
        return self.rx == o.rx and self.tx == o.tx


cdef class KxKkClientState:
    def __init__(self, KxPair client_kp):
        self.packet1 = b""
        self.session_pair = None
        self.client_kp = client_kp

    cpdef client_finish_kx_kk(self, bytes packet2):
        if not self.packet1:
            raise RuntimeError("client_finish_kx_kk called before client_init_kx_kk")
        if self.session_pair is not None:
            raise RuntimeError("client_finish_kx_kk already called")
        if packet2 is None:
            raise ValueError("packet2 cannot be None")
        if len(packet2) != hydro_kx_KK_PACKET2BYTES:
            raise ValueError(f"Packet2 must be {hydro_kx_KK_PACKET2BYTES} bytes long")
        try:
            rx, tx = kx_kk_3(&self.state, packet2, self.client_kp)
        except RuntimeError as ex:
            raise KeyExchangeException("failed to finish key exchange") from ex
        self.session_pair = SessionPair(rx=SecretBoxKey(rx), tx=SecretBoxKey(tx))
        return self.session_pair


cdef class KxPublicKey:
    def __init__(self, kp):
        if kp is None:
            raise ValueError("pk cannot be None")
        if isinstance(kp, SafeMemory):
            if len(kp) != KP_SIZE:
                raise ValueError(f"safemem must be {KP_SIZE} bytes long")
            self.kp = kp
            return
        cdef KxPublicKey other
        if isinstance(kp, KxPublicKey):
            other = <KxPublicKey>kp
            self.kp = other.kp
            return
        if isinstance(kp, str):
            kp = base64.standard_b64decode(kp)
        cdef bytes pubkey = bytes(kp)
        if len(pubkey) != hydro_kx_PUBLICKEYBYTES:
            raise ValueError(f"{hydro_kx_PUBLICKEYBYTES} bytes required for public key")
        # KxPublicKey holds memory for a full keypair to allow for easy initialization from a keypair
        # but in fact we will only store the public key part.
        cdef SafeMemory mem = SafeMemory(KP_SIZE)
        # treat the memory as a hydro_kx_keypair
        cdef hydro_kx_keypair* kp_ptr = <hydro_kx_keypair*>(<void*>(mem.ptr))
        # find the public key pointer in the keypair
        cdef uint8_t* dst = <uint8_t*>(kp_ptr.pk)
        # copy the public key bytes into the keypair's public key field
        cdef uint8_t* src = pubkey
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

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, KxPublicKey):
            return False
        cdef KxPublicKey o = <KxPublicKey>other
        # we must only compare the public parts of the keypairs
        return memcmp(self.ptr(), o.ptr(), hydro_kx_PUBLICKEYBYTES) == 0


cdef class KxSecretKey:
    def __init__(self, kp):
        if kp is None:
            raise ValueError("kp cannot be None")
        if isinstance(kp, SafeMemory):
            if len(kp) != KP_SIZE:
                raise ValueError(f"safemem must be {KP_SIZE} bytes long")
            self.kp = kp
            return
        cdef KxSecretKey other
        if isinstance(kp, KxSecretKey):
            other = <KxSecretKey>kp
            self.kp = other.kp
            return
        if isinstance(kp, str):
            kp = base64.standard_b64decode(kp)
        kp = bytes(kp)
        if len(kp) != hydro_kx_SECRETKEYBYTES:
            raise ValueError(f"{hydro_kx_SECRETKEYBYTES} bytes required for secret key")
        cdef SafeMemory mem = SafeMemory(KP_SIZE)
        cdef hydro_kx_keypair* kp_ptr = <hydro_kx_keypair*>(<void*>(mem.ptr))
        cdef uint8_t* dst = <uint8_t*>(kp_ptr.sk)
        cdef uint8_t* src = kp
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

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, KxSecretKey):
            return False
        cdef KxSecretKey o = <KxSecretKey>other
        # we must only compare the secret parts of the keypairs
        return memcmp(self.ptr(), o.ptr(), hydro_kx_SECRETKEYBYTES) == 0


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
        cdef KxPair other
        if isinstance(kp, KxPair):
            other = <KxPair>kp
            self.kp = other.kp
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

    cpdef server_finish_kx_n(self, bytes packet1, Psk psk=None):
        return server_finish_kx_n(self, packet1, psk)

    cpdef client_init_kx_kk(self, KxPublicKey server_public_key):
        if server_public_key is None:
            raise ValueError("Server public key cannot be None")
        cdef KxKkClientState state = KxKkClientState(self)
        try:
            state.packet1 = kx_kk_1(&state.state, server_public_key, self)
        except RuntimeError as ex:
            raise KeyExchangeException("failed to generate first packet for key exchange") from ex
        return state

    cpdef server_process_kx_kk(self, KxPublicKey client_public_key, bytes packet1):
        if client_public_key is None:
            raise ValueError("Client public key cannot be None")
        if packet1 is None:
            raise ValueError("packet1 cannot be None")
        if len(packet1) != hydro_kx_KK_PACKET1BYTES:
            raise ValueError(f"Packet1 must be {hydro_kx_KK_PACKET1BYTES} bytes long")
        try:
            rx, tx, packet2 = kx_kk_2(packet1, client_public_key, self)
        except RuntimeError as ex:
            raise KeyExchangeException("failed to generate session from packet") from ex
        return SessionPair(rx=SecretBoxKey(rx), tx=SecretBoxKey(tx)), packet2

    @classmethod
    def gen(cls):
        return cls(kx_keygen())

    @classmethod
    def from_keys(cls, public_key, secret_key):
        if public_key is None:
            raise ValueError("Public key cannot be None")
        if secret_key is None:
            raise ValueError("Secret key cannot be None")

        cdef KxPublicKey pk = KxPublicKey(public_key)
        cdef KxSecretKey sk = KxSecretKey(secret_key)

        cdef SafeMemory mem = SafeMemory(KP_SIZE)
        cdef hydro_kx_keypair* kp_ptr = <hydro_kx_keypair*>(<void*>(mem.ptr))
        memcpy(<uint8_t*>(kp_ptr.sk), sk.ptr(), hydro_kx_SECRETKEYBYTES)
        memcpy(<uint8_t*>(kp_ptr.pk), pk.ptr(), hydro_kx_PUBLICKEYBYTES)
        mem.mark_readonly()
        return cls(mem)


cpdef client_init_kx_n(KxPublicKey server_public_key, Psk psk=None):
    # generate the first packet for the key exchange
    if server_public_key is None:
        raise ValueError("Server public key cannot be None")
    try:
        rx, tx, packet1 = kx_n_1(server_public_key, psk)
    except RuntimeError as ex:
        raise KeyExchangeException("failed to generate first packet") from ex
    return SessionPair(rx=SecretBoxKey(rx), tx=SecretBoxKey(tx)), packet1


cpdef server_finish_kx_n(KxPair server_kp, bytes packet1, Psk psk=None):
    if server_kp is None:
        raise ValueError("static key pair cannot be None")
    if packet1 is None:
        raise ValueError("packet1 cannot be None")
    if len(packet1) != hydro_kx_N_PACKET1BYTES:
        raise ValueError(f"Packet1 must be {hydro_kx_N_PACKET1BYTES} bytes long")
    try:
        rx, tx = kx_n_2(packet1, psk, server_kp)
    except RuntimeError as ex:
        raise KeyExchangeException("failed to generate session from packet") from ex
    return SessionPair(rx=SecretBoxKey(rx), tx=SecretBoxKey(tx))
