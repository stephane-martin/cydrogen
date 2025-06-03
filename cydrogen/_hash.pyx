# cython: language_level=3

import base64
import io

from ._basekey cimport BaseKey
from ._masterkey cimport MasterKey
from ._secretbox cimport SecretBoxKey
from ._sign import SignPublicKey, SignSecretKey, SignKeyPair
from ._context cimport make_context
from ._utils cimport FileOpener, SafeMemory

from ._decls cimport hydro_hash_BYTES_MIN, hydro_hash_BYTES_MAX, hash_init, hash_update, hash_final


cdef class HashKey(BaseKey):
    def __init__(self, key=None):
        # when key is None, return the empty key
        if key is None:
            super().__init__()
            return

        if isinstance(key, SafeMemory):
            super().__init__(key)
            return

        # when key argument is already a HashKey, copy the key
        cdef HashKey o
        if isinstance(key, HashKey):
            o = <HashKey>key
            super().__init__(o.key)
            return

        if isinstance(key, (MasterKey, SignKeyPair, SignPublicKey, SignSecretKey, SecretBoxKey)):
            raise TypeError("can't create a HashKey from another concrete key type")

        # when key argument is a string, assume it's a base64 encoded key
        if isinstance(key, str):
            super().__init__(base64.standard_b64decode(key))
            return

        # else, assume it's a bytes like object
        super().__init__(bytes(key))

    def __eq__(self, other):
        if not isinstance(other, HashKey):
            return False
        cdef HashKey o = <HashKey>other
        # call the BaseKey equality method
        return self.eq(o)

    def __repr__(self):
        return f'HashKey({repr(str(self))})'

    cpdef hasher(self, data=None, ctx=None, size_t digest_size=16):
        return Hash(data, ctx=ctx, digest_size=digest_size, key=self)


cdef make_hashkey(key):
    if isinstance(key, HashKey):
        return key
    return HashKey(key)


cdef class Hash:
    def __init__(self, data=None, *, ctx=None, size_t digest_size=16, key=None):
        if digest_size < hydro_hash_BYTES_MIN or digest_size > hydro_hash_BYTES_MAX:
            raise ValueError("Hash length must be between 16 and 65535 bytes")

        self.ctx = make_context(ctx)
        self.key = make_hashkey(key)
        self.digest_size = digest_size
        self.block_size = 64
        self.finalized = 0
        self.result = bytes()

        hash_init(&self.state, self.ctx, self.key)

        if data is not None:
            self.update(data)

    cpdef update(self, const unsigned char[:] data):
        if self.finalized == 1:
            raise RuntimeError("Hash has already been finalized")
        if data is None:
            return
        cdef size_t n = len(data)
        if n == 0:
            return
        hash_update(&self.state, data)

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

    cpdef write(self, const unsigned char[:] data):
        if data is None:
            return 0
        self.update(data)
        return len(data)

    cpdef digest(self):
        if self.finalized == 1:
            return self.result
        cdef bytearray res = bytearray(self.digest_size)
        hash_final(&self.state, res)
        self.result = bytes(res)
        self.finalized = 1
        return self.result

    cpdef hexdigest(self):
        return self.digest().hex()


cpdef hash_file(fileobj, ctx=None, size_t digest_size=16, key=None, chunk_size=io.DEFAULT_BUFFER_SIZE):
    if fileobj is None:
        raise ValueError("File object cannot be None")
    cdef Hash hasher = Hash(ctx=ctx, digest_size=digest_size, key=key)
    hasher.update_from(fileobj, chunk_size=chunk_size)
    return hasher.digest()
