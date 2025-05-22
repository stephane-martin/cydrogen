# cython: language_level=3

import base64

from cpython.buffer cimport PyBuffer_FillInfo
from libc.stdint cimport uint8_t
from libc.string cimport memcpy

from ._decls cimport *
from ._context cimport Context
from ._exceptions cimport SignException


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

    cpdef verify(self, const unsigned char[:] message, const unsigned char[:] signature, ctx=None):
        """
        Verify a signature for a message using the public key and an optional context.
        Returns True if the signature is valid, False otherwise.
        """
        if message is None:
            raise ValueError("Message cannot be None")
        if signature is None:
            raise ValueError("Signature cannot be None")
        if len(signature) != hydro_sign_BYTES:
            raise ValueError("Signature must be 64 bytes long")
        cdef Context myctx = Context(ctx)
        cdef const unsigned char* msg_ptr = &message[0]
        cdef uint8_t csig[hydro_sign_BYTES]
        cdef const unsigned char* sig_ptr = &signature[0]
        memcpy(&csig[0], sig_ptr, hydro_sign_BYTES)
        if hydro_sign_verify(csig, msg_ptr, len(message), myctx.ctx, self.key) != 0:
            return False
        return True

    cpdef verifier(self, ctx=None):
        """
        Create a Verifier object for this public key.
        """
        return Verifier(self, ctx=ctx)


cdef class SignSecretKey:
    def __cinit__(self, key):
        hydro_memzero(&self.key[0], hydro_sign_SECRETKEYBYTES)

    def __dealloc__(self):
        hydro_memzero(&self.key[0], hydro_sign_SECRETKEYBYTES)

    def __init__(self, key):
        if key is None:
            raise ValueError("Secret key cannot be None")
        if isinstance(key, SignSecretKey):
            key = bytes(key)
        if not isinstance(key, bytes):
            raise TypeError("Secret key must be a bytes object")
        if len(key) != hydro_sign_SECRETKEYBYTES:
            raise ValueError("Secret key must be 64 bytes long")
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

    cpdef sign(self, const unsigned char[:] message, ctx=None):
        """
        Sign a message using the secret key and an optional context.
        Returns the signature as a bytes object.
        """
        if message is None:
            raise ValueError("Message cannot be None")
        cdef Context myctx = Context(ctx)
        cdef const unsigned char* msg_ptr = &message[0]
        cdef uint8_t csig[hydro_sign_BYTES]
        if hydro_sign_create(csig, msg_ptr, len(message), myctx.ctx, self.key) != 0:
            raise SignException("Failed to sign message")
        cdef bytearray sig = bytearray(hydro_sign_BYTES)
        cdef uint8_t* sig_ptr = sig
        memcpy(sig_ptr, &csig[0], hydro_sign_BYTES)
        return bytes(sig)

    cpdef signer(self, ctx=None):
        """
        Create a Signer object for this secret key.
        """
        return Signer(self, ctx=ctx)

    cdef public_key(self):
        cdef bytearray pk = bytearray(hydro_x25519_PUBLICKEYBYTES)
        memcpy(<uint8_t*>pk, &self.key[hydro_x25519_SECRETKEYBYTES], hydro_x25519_PUBLICKEYBYTES)
        return SignPublicKey(bytes(pk))

    cpdef check_publick_key(self, SignPublicKey other):
        if other is None:
            return False
        return other.eq(self.public_key())


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

    cpdef sign(self, const unsigned char[:] message, ctx=None):
        return self.secret_key.sign(message, ctx=ctx)

    cpdef verify(self, const unsigned char[:] message, const unsigned char[:] signature, ctx=None):
        return self.public_key.verify(message, signature, ctx=ctx)

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
            return False
        return True
