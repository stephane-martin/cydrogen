# cython: language_level=3

import base64
import io

from cpython.buffer cimport PyBuffer_FillInfo
from libc.stdint cimport uint8_t
from libc.string cimport memcpy

from ._basekey cimport BaseKey
from ._decls cimport hydro_sign_PUBLICKEYBYTES, hydro_sign_SECRETKEYBYTES
from ._decls cimport sign_keygen, sign_init, sign_update, sign_final_create, sign_final_verify
from ._context cimport make_context
from ._exceptions cimport SignException, VerifyException
from ._hash cimport HashKey
from ._masterkey cimport MasterKey
from ._secretbox cimport SecretBoxKey
from ._utils cimport FileOpener, SafeMemory

cdef const int hydro_x25519_PUBLICKEYBYTES = 32
cdef const int hydro_x25519_SECRETKEYBYTES = 32


cdef class SignPublicKey:
    def __init__(self, key):
        self.key = SafeMemory(hydro_sign_PUBLICKEYBYTES)
        if key is None:
            raise ValueError("Public key cannot be None")
        if isinstance(key, SignSecretKey):
            raise TypeError("Can't use SignSecretKey as public sign key")
        if isinstance(key, (MasterKey, HashKey, SecretBoxKey, BaseKey)):
            raise TypeError("Can't use BaseKey, MasterKey, HashKey, or SecretBoxKey as public/secret sign key")
        if isinstance(key, str):
            key = base64.standard_b64decode(key)
        key = bytes(key)
        if len(key) != hydro_sign_PUBLICKEYBYTES:
            raise ValueError("Public key must be 32 bytes long")
        self.key.set(key)

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.key.ptr, self.key.size, 1, flags)

    def __str__(self):
        return base64.standard_b64encode(self).decode("ascii")

    def __repr__(self):
        return f'SignPublicKey({repr(str(self))})'

    def __eq__(self, other):
        if not isinstance(other, SignPublicKey):
            return False
        cdef SignPublicKey o = <SignPublicKey>other
        return self.key == o.key

    cpdef verifier(self, ctx=None):
        return Verifier(self, ctx=ctx)


cdef make_sign_public_key(key):
    if isinstance(key, SignPublicKey):
        return key
    return SignPublicKey(key)


cdef class SignSecretKey:
    def __init__(self, key):
        self.key = SafeMemory(hydro_sign_SECRETKEYBYTES)
        if key is None:
            raise ValueError("Secret key cannot be None")
        if isinstance(key, SignPublicKey):
            raise TypeError("Can't use SignPublicKey as secret sign key")
        if isinstance(key, (MasterKey, HashKey, SecretBoxKey, BaseKey)):
            raise TypeError("Can't use BaseKey, MasterKey, HashKey, or SecretBoxKey as public/secret sign key")
        if isinstance(key, str):
            key = base64.standard_b64decode(key)
        key = bytes(key)
        if len(key) != hydro_sign_SECRETKEYBYTES:
            raise ValueError(f"Secret key must be 64 bytes long (length: {len(key)})")
        self.key.set(key)

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.key.ptr, self.key.size, 1, flags)

    def __str__(self):
        return base64.standard_b64encode(self).decode("ascii")

    def __repr__(self):
        return f'SignSecretKey({repr(str(self))})'

    def __eq__(self, other):
        if not isinstance(other, SignSecretKey):
            return False
        cdef SignSecretKey o = <SignSecretKey>other
        return self.key == o.key

    cdef public_key(self):
        cdef bytearray pk = bytearray(hydro_x25519_PUBLICKEYBYTES)
        cdef uint8_t* pk_ptr = <uint8_t*>pk
        cdef uint8_t* key_ptr = <uint8_t*>self.key.ptr
        key_ptr += hydro_x25519_SECRETKEYBYTES
        memcpy(pk_ptr, key_ptr, hydro_x25519_PUBLICKEYBYTES)
        return SignPublicKey(bytes(pk))

    cpdef check_public_key(self, SignPublicKey other):
        if other is None:
            return False
        return other == self.public_key()

    cpdef signer(self, ctx=None):
        return Signer(self, ctx=ctx)


cdef make_sign_secret_key(key):
    if isinstance(key, SignSecretKey):
        return key
    return SignSecretKey(key)


cdef class SignKeyPair:
    def __init__(self, kp):
        if kp is None:
            raise ValueError("Key cannot be None")
        self.secret_key = make_sign_secret_key(kp)
        self.public_key = self.secret_key.public_key()

    def __eq__(self, other):
        if not isinstance(other, SignKeyPair):
            return False
        cdef SignKeyPair o = <SignKeyPair>other
        return self.secret_key.eq(o.secret_key)

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        PyBuffer_FillInfo(buffer, self, self.secret_key.key.ptr, self.secret_key.key.size, 1, flags)

    def __str__(self):
        return base64.standard_b64encode(self).decode("ascii")

    def __repr__(self):
        return f'SignKeyPair({repr(str(self))})'

    @classmethod
    def gen(cls):
        return cls(sign_keygen())

    cpdef signer(self, ctx=None):
        return self.secret_key.signer(ctx=ctx)

    cpdef verifier(self, ctx=None):
        return self.public_key.verifier(ctx=ctx)


cdef class BaseSigner:
    def __init__(self, *, ctx=None, data=None):
        self.ctx = make_context(ctx)
        self.finalized = 0
        try:
            sign_init(&self.state, self.ctx)
        except ValueError:
            raise
        except Exception as ex:
            raise SignException("Failed to initialize signer/verifier") from ex
        if data is not None:
            self.update(data)

    cpdef update(self, const unsigned char[:] data):
        if data is None:
            return
        if len(data) == 0:
            return
        try:
            sign_update(&self.state, data)
        except ValueError:
            raise
        except Exception as ex:
            raise SignException("Failed to update signer") from ex

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
    def __init__(self, private_key, *, ctx=None, data=None):
        if private_key is None:
            raise ValueError("Private key cannot be None")
        super().__init__(ctx=ctx, data=data)
        self.key = make_sign_secret_key(private_key)

    cpdef sign(self):
        if self.finalized == 1:
            raise RuntimeError("already finalized")
        self.finalized = 1
        cdef bytearray sig = bytearray(hydro_sign_BYTES)
        try:
            sign_final_create(&self.state, self.key, sig)
        except ValueError:
            raise
        except Exception as ex:
            raise SignException("Failed to create signature") from ex
        return bytes(sig)


cdef class Verifier(BaseSigner):
    def __init__(self, public_key, *, ctx=None, data=None):
        if public_key is None:
            raise ValueError("Public key cannot be None")
        super().__init__(ctx=ctx, data=data)
        self.key = make_sign_public_key(public_key)

    cpdef verify(self, const unsigned char[:] signature):
        if signature is None:
            raise ValueError("Signature cannot be None")
        if len(signature) != hydro_sign_BYTES:
            raise ValueError("Signature must be 64 bytes long")
        if self.finalized == 1:
            raise RuntimeError("already finalized")
        self.finalized = 1
        try:
            sign_final_verify(&self.state, self.key, signature)
        except ValueError:
            raise
        except Exception as ex:
            raise VerifyException("Failed to verify signature") from ex


cpdef sign_file(key, fileobj, ctx=None, chunk_size=io.DEFAULT_BUFFER_SIZE):
    if key is None:
        raise ValueError("Key cannot be None")
    if fileobj is None:
        raise ValueError("File object cannot be None")
    cdef Signer signer = Signer(key, ctx=ctx)
    signer.update_from(fileobj, chunk_size=chunk_size)
    return signer.sign()


cpdef verify_file(key, fileobj, const unsigned char[:] signature, ctx=None, chunk_size=io.DEFAULT_BUFFER_SIZE):
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
