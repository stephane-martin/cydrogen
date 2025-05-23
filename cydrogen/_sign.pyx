# cython: language_level=3

import base64
import io

from cpython.buffer cimport PyBuffer_FillInfo
from libc.stdint cimport uint8_t
from libc.string cimport memcpy

from ._decls cimport *
from ._context cimport Context
from ._exceptions cimport SignException, VerifyException
from ._utils cimport FileOpener


cdef const int hydro_x25519_PUBLICKEYBYTES = 32
cdef const int hydro_x25519_SECRETKEYBYTES = 32


cdef class SignPublicKey:
    def __cinit__(self, key):
        hydro_memzero(&self.key[0], hydro_sign_PUBLICKEYBYTES)

    def __dealloc__(self):
        hydro_memzero(&self.key[0], hydro_sign_PUBLICKEYBYTES)

    def __init__(self, key):
        if key is None:
            raise ValueError("Public key cannot be None")
        if isinstance(key, str):
            key = base64.standard_b64decode(key)
        if isinstance(key, SignPublicKey):
            key = bytes(key)
        if not isinstance(key, bytes):
            raise TypeError("Public key must be a bytes object")
        if len(key) != hydro_sign_PUBLICKEYBYTES:
            raise ValueError("Public key must be 32 bytes long")
        cdef const unsigned char* key_ptr = key
        memcpy(&self.key[0], key_ptr, hydro_sign_PUBLICKEYBYTES)

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.key, hydro_sign_PUBLICKEYBYTES, 1, flags)

    def __str__(self):
        return base64.standard_b64encode(self).decode("ascii")

    def __repr__(self):
        return f'SignPublicKey({repr(str(self))})'

    cdef eq(self, SignPublicKey other):
        if other is None:
            return False
        cdef const uint8_t* self_ptr = &self.key[0]
        cdef const uint8_t* other_ptr = &other.key[0]
        if self_ptr == other_ptr:
            return True
        return hydro_equal(self_ptr, other_ptr, hydro_sign_PUBLICKEYBYTES) == 1

    def __eq__(self, other):
        if not isinstance(other, SignPublicKey):
            return False
        cdef SignPublicKey o = <SignPublicKey>other
        return self.eq(o)

    cpdef verifier(self, ctx=None):
        return Verifier(self, ctx=ctx)


cdef class SignSecretKey:
    def __cinit__(self, key):
        hydro_memzero(&self.key[0], hydro_sign_SECRETKEYBYTES)

    def __dealloc__(self):
        hydro_memzero(&self.key[0], hydro_sign_SECRETKEYBYTES)

    def __init__(self, key):
        if key is None:
            raise ValueError("Secret key cannot be None")
        if isinstance(key, str):
            key = base64.standard_b64decode(key)
        if isinstance(key, SignSecretKey):
            key = bytes(key)
        if not isinstance(key, bytes):
            raise TypeError("Secret key must be a bytes object")
        if len(key) != hydro_sign_SECRETKEYBYTES:
            raise ValueError(f"Secret key must be 64 bytes long (length: {len(key)})")
        cdef const unsigned char* key_ptr = key
        memcpy(&self.key[0], key_ptr, hydro_sign_SECRETKEYBYTES)

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.key, hydro_sign_SECRETKEYBYTES, 1, flags)

    def __str__(self):
        return base64.standard_b64encode(self).decode("ascii")

    def __repr__(self):
        return f'SignSecretKey({repr(str(self))})'

    cdef eq(self, SignSecretKey other):
        if other is None:
            return False
        cdef const uint8_t* self_ptr = &self.key[0]
        cdef const uint8_t* other_ptr = &other.key[0]
        if self_ptr == other_ptr:
            return True
        return hydro_equal(self_ptr, other_ptr, hydro_sign_SECRETKEYBYTES) == 1

    def __eq__(self, other):
        if not isinstance(other, SignSecretKey):
            return False
        cdef SignSecretKey o = <SignSecretKey>other
        return self.eq(o)

    cdef public_key(self):
        cdef bytearray pk = bytearray(hydro_x25519_PUBLICKEYBYTES)
        memcpy(<uint8_t*>pk, &self.key[hydro_x25519_SECRETKEYBYTES], hydro_x25519_PUBLICKEYBYTES)
        return SignPublicKey(bytes(pk))

    cpdef check_public_key(self, SignPublicKey other):
        if other is None:
            return False
        return other.eq(self.public_key())

    cpdef signer(self, ctx=None):
        return Signer(self, ctx=ctx)


cdef class SignKeyPair:
    def __init__(self, secret_key):
        self.secret_key = SignSecretKey(secret_key)
        self.public_key = self.secret_key.public_key()

    def __eq__(self, other):
        if not isinstance(other, SignKeyPair):
            return False
        cdef SignKeyPair o = <SignKeyPair>other
        return self.secret_key.eq(o.secret_key)

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.secret_key.key, hydro_sign_SECRETKEYBYTES, 1, flags)

    def __str__(self):
        return base64.standard_b64encode(self).decode("ascii")

    def __repr__(self):
        return f'SignKeyPair({repr(str(self))})'

    @classmethod
    def gen(cls):
        """
        Generate a new key pair.
        """
        cdef hydro_sign_keypair kp
        hydro_sign_keygen(&kp)
        cdef bytes secret_key = kp.sk[:hydro_sign_SECRETKEYBYTES]
        return cls(secret_key)

    cpdef signer(self, ctx=None):
        return self.secret_key.signer(ctx=ctx)

    cpdef verifier(self, ctx=None):
        return self.public_key.verifier(ctx=ctx)


cdef class BaseSigner:
    def __init__(self, *, ctx=None, data=None):
        self.ctx = Context(ctx)
        self.finalized = 0
        if hydro_sign_init(&self.state, self.ctx.ctx) != 0:
            raise SignException("Failed to initialize signer")
        if data is not None:
            self.update(data)

    cpdef update(self, const unsigned char[:] data):
        if data is None:
            return
        if hydro_sign_update(&self.state, &data[0], len(data)) != 0:
            raise SignException("Failed to update signer")

    cpdef write(self, const unsigned char[:] data):
        if data is None:
            return 0
        self.update(data)
        return len(data)

    cpdef update_from(self, fileobj, chunk_size=io.DEFAULT_BUFFER_SIZE):
        if fileobj is None:
            raise ValueError("File object cannot be None")
        cdef bytearray buf = bytearray(chunk_size)
        cdef size_t n = 0

        with FileOpener(fileobj, mode="rb") as f:
            while True:
                n = f.readinto(buf)
                if n == 0:
                    return
                self.update(buf[:n])


cdef class Signer(BaseSigner):
    def __init__(self, SignSecretKey private_key, *, ctx=None, data=None):
        if private_key is None:
            raise ValueError("Private key cannot be None")
        super().__init__(ctx=ctx, data=data)
        self.key = private_key

    cpdef sign(self):
        if self.finalized == 1:
            raise RuntimeError("already finalized")
        self.finalized = 1
        cdef uint8_t csig[hydro_sign_BYTES]
        if hydro_sign_final_create(&self.state, csig, self.key.key) != 0:
            raise SignException("Failed to create signature")
        cdef bytearray sig = bytearray(hydro_sign_BYTES)
        cdef unsigned char* sig_ptr = sig
        memcpy(sig_ptr, &csig[0], hydro_sign_BYTES)
        return bytes(sig)


cdef class Verifier(BaseSigner):
    def __init__(self, SignPublicKey public_key, *, ctx=None, data=None):
        if public_key is None:
            raise ValueError("Public key cannot be None")
        super().__init__(ctx=ctx, data=data)
        self.key = public_key

    cpdef verify(self, const unsigned char[:] signature):
        if signature is None:
            raise ValueError("Signature cannot be None")
        if len(signature) != hydro_sign_BYTES:
            raise ValueError("Signature must be 64 bytes long")
        if self.finalized == 1:
            raise RuntimeError("already finalized")
        self.finalized = 1
        cdef uint8_t csig[hydro_sign_BYTES]
        memcpy(&csig[0], &signature[0], hydro_sign_BYTES)
        if hydro_sign_final_verify(&self.state, csig, self.key.key) != 0:
            raise VerifyException("Failed to verify signature")


cpdef sign_file(SignSecretKey key, fileobj, ctx=None, chunk_size=io.DEFAULT_BUFFER_SIZE):
    if key is None:
        raise ValueError("Key cannot be None")
    if fileobj is None:
        raise ValueError("File object cannot be None")
    cdef Signer signer = Signer(key, ctx=ctx)
    signer.update_from(fileobj, chunk_size=chunk_size)
    return signer.sign()


cpdef verify_file(SignPublicKey key, fileobj, const unsigned char[:] signature, ctx=None, chunk_size=io.DEFAULT_BUFFER_SIZE):
    if key is None:
        raise ValueError("Key cannot be None")
    if fileobj is None:
        raise ValueError("File object cannot be None")
    if signature is None:
        raise ValueError("Signature cannot be None")
    if len(signature) != hydro_sign_BYTES:
        raise ValueError("Signature must be 64 bytes long")
    cdef Verifier verifier = Verifier(key, ctx=ctx)
    verifier.update_from(fileobj, chunk_size=chunk_size)
    verifier.verify(signature)
