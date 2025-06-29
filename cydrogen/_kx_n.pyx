# cython: language_level=3

from cpython.buffer cimport PyBuffer_FillInfo
from libc.stdint cimport uint8_t
from libc.string cimport memcmp, memcpy

from ._basekey cimport BaseKey
from ._decls cimport kx_keygen, hydro_kx_keypair
from ._decls cimport hydro_kx_PUBLICKEYBYTES, hydro_kx_SECRETKEYBYTES
from ._decls cimport hydro_kx_N_PACKET1BYTES
from ._decls cimport hydro_kx_KK_PACKET1BYTES, hydro_kx_KK_PACKET2BYTES
from ._decls cimport hydro_kx_XX_PACKET1BYTES, hydro_kx_XX_PACKET2BYTES, hydro_kx_XX_PACKET3BYTES
from ._decls cimport kx_n_1, kx_n_2
from ._decls cimport kx_kk_1, kx_kk_2, kx_kk_3
from ._decls cimport kx_xx_1, kx_xx_2, kx_xx_3, kx_xx_4
from ._exceptions cimport KeyExchangeException
from ._secretbox cimport SecretBoxKey

import base64
import threading


KX_PAIR_SIZE = sizeof(hydro_kx_keypair)
KX_N_PACKET1BYTES = hydro_kx_N_PACKET1BYTES
KX_KK_PACKET1BYTES = hydro_kx_KK_PACKET1BYTES
KX_KK_PACKET2BYTES = hydro_kx_KK_PACKET2BYTES
KX_XX_PACKET1BYTES = hydro_kx_XX_PACKET1BYTES
KX_XX_PACKET2BYTES = hydro_kx_XX_PACKET2BYTES
KX_XX_PACKET3BYTES = hydro_kx_XX_PACKET3BYTES


cdef class Psk(BaseKey):
    def __init__(self, b=None):
        if isinstance(b, str):
            super().__init__(base64.standard_b64decode(b))
            return
        super().__init__(b)

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
        self.mu = threading.Lock()

    cpdef client_finish_kx_kk(self, bytes packet2):
        with self.mu:
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
            return self

cdef class KxXxClientState:
    def __init__(self, KxPair client_kp, Psk psk=None):
        self.packet1 = b""
        self.packet3 = b""
        self.server_public_key = None
        self.session_pair = None
        self.client_kp = client_kp
        self.psk = psk
        self.mu = threading.Lock()

    def __str__(self) -> str:
        return f"""packet1: {self.packet1}
packet3: {self.packet3}
server_public_key: {self.server_public_key}
session_pair: {self.session_pair}"""

    cpdef client_process_kx_xx(self, bytes packet2):
        with self.mu:
            if not self.packet1:
                raise RuntimeError("client_process_kx_xx called before client_init_kx_xx")
            if self.packet3:
                raise RuntimeError("client_process_kx_xx already called")
            if packet2 is None:
                raise ValueError("packet2 cannot be None")
            if len(packet2) != hydro_kx_XX_PACKET2BYTES:
                raise ValueError(f"Packet2 must be {hydro_kx_XX_PACKET2BYTES} bytes long")
            try:
                rx, tx, peer_pk, packet3 = kx_xx_3(&self.state, packet2, self.psk, self.client_kp)
            except RuntimeError as ex:
                raise KeyExchangeException("failed to process second packet for key exchange") from ex
            self.packet3 = packet3
            self.server_public_key = KxPublicKey(peer_pk)
            self.session_pair = SessionPair(rx=SecretBoxKey(rx), tx=SecretBoxKey(tx))
            return self


cdef class KxXxServerState:
    def __init__(self, Psk psk=None):
        self.packet2 = b""
        self.client_public_key = None
        self.session_pair = None
        self.psk = psk
        self.mu = threading.Lock()

    def __str__(self) -> str:
        return f"""packet2: {self.packet2}
client_public_key: {self.client_public_key}
session_pair: {self.session_pair}
"""
    cpdef server_finish_kx_xx(self, bytes packet3):
        with self.mu:
            if self.session_pair is not None:
                raise RuntimeError("server_finish_kx_xx already called")
            if not self.packet2:
                raise RuntimeError("server_finish_kx_xx called before server_process_kx_xx")
            if packet3 is None:
                raise ValueError("packet3 cannot be None")
            if len(packet3) != hydro_kx_XX_PACKET3BYTES:
                raise ValueError(f"Packet3 must be {hydro_kx_XX_PACKET3BYTES} bytes long")
            try:
                rx, tx, client_public_key = kx_xx_4(&self.state, packet3, self.psk)
            except RuntimeError as ex:
                raise KeyExchangeException("failed to finish key exchange") from ex
            self.client_public_key = KxPublicKey(client_public_key)
            self.session_pair = SessionPair(rx=SecretBoxKey(rx), tx=SecretBoxKey(tx))
            return self

cdef class KxPublicKey:
    def __init__(self, kp):
        if kp is None:
            raise ValueError("pk cannot be None")

        cdef KxPublicKey other
        cdef SafeMemory mem
        cdef hydro_kx_keypair* kp_ptr
        cdef uint8_t* dst
        cdef uint8_t* src

        if isinstance(kp, SafeMemory):
            if len(kp) == KX_PAIR_SIZE:
                self.kp = kp
                return
            if len(kp) == hydro_kx_PUBLICKEYBYTES:
                mem = SafeMemory(KX_PAIR_SIZE)
                kp_ptr = <hydro_kx_keypair*>(<void*>(mem.ptr))
                dst = <uint8_t*>(kp_ptr.pk)
                src = <uint8_t*>((<SafeMemory>kp).ptr)
                memcpy(dst, src, hydro_kx_PUBLICKEYBYTES)
                mem.mark_readonly()
                self.kp = mem
                return
            raise ValueError(f"invalid SafeMemory length: {len(kp)} bytes, expected {hydro_kx_PUBLICKEYBYTES} or {KX_PAIR_SIZE} bytes")
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
        mem = SafeMemory(KX_PAIR_SIZE)
        # treat the memory as a hydro_kx_keypair
        kp_ptr = <hydro_kx_keypair*>(<void*>(mem.ptr))
        # find the public key pointer in the keypair
        dst = <uint8_t*>(kp_ptr.pk)
        # copy the public key bytes into the keypair's public key field
        src = pubkey
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
            if len(kp) != KX_PAIR_SIZE:
                raise ValueError(f"safemem must be {KX_PAIR_SIZE} bytes long")
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
        cdef SafeMemory mem = SafeMemory(KX_PAIR_SIZE)
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
            if len(kp) != KX_PAIR_SIZE:
                raise ValueError(f"safemem must be {KX_PAIR_SIZE} bytes long")
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
        if len(kp) != KX_PAIR_SIZE:
            raise ValueError(f"{KX_PAIR_SIZE} bytes required for keypair")
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

    cpdef client_init_kx_xx(self, Psk psk=None):
        cdef KxXxClientState state = KxXxClientState(self, psk)
        try:
            state.packet1 = kx_xx_1(&state.state, psk)
        except RuntimeError as ex:
            raise KeyExchangeException("failed to generate first packet for key exchange") from ex
        return state

    cpdef server_process_kx_xx(self, bytes packet1, Psk psk=None):
        if packet1 is None:
            raise ValueError("packet1 cannot be None")
        cdef KxXxServerState state = KxXxServerState(psk)
        if len(packet1) != hydro_kx_XX_PACKET1BYTES:
            raise ValueError(f"Packet1 must be {hydro_kx_XX_PACKET1BYTES} bytes long")
        try:
            state.packet2 = kx_xx_2(&state.state, packet1, psk, self)
        except RuntimeError as ex:
            raise KeyExchangeException("failed to generate second packet for key exchange") from ex
        return state

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

        cdef SafeMemory mem = SafeMemory(KX_PAIR_SIZE)
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
