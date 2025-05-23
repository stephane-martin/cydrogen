# cython: language_level=3

import base64
import io

from libc.stdint cimport uint8_t

from ._basekey cimport BaseKey
from ._masterkey cimport MasterKey
from ._secretbox cimport SecretBoxKey
from ._sign import SignPublicKey, SignSecretKey, SignKeyPair
from ._context cimport Context
from ._utils cimport FileOpener

from ._decls cimport *


cdef class HashKey(BaseKey):
    """
    HashKey represents a key for hashing.
    """

    def __init__(self, key=None):
        # when key is None, return the empty key
        if key is None:
            super().__init__()
            return

        # when key argument is already a HashKey, copy the key
        if isinstance(key, HashKey):
            super().__init__(bytes(key))
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
        return self.eq(o)

    def __repr__(self):
        return f'HashKey({repr(str(self))})'

    cpdef hasher(self, data=None, ctx=None, size_t digest_size=16):
        """
        Hash the data with the key.
        """
        return Hash(data, ctx=ctx, digest_size=digest_size, key=self)

    cpdef hash_file(self, fileobj, ctx=None, size_t digest_size=16, chunk_size=io.DEFAULT_BUFFER_SIZE):
        return hash_file(fileobj, ctx=ctx, digest_size=digest_size, key=self, chunk_size=chunk_size)


cdef class Hash:
    def __init__(self, data=None, *, ctx=None, size_t digest_size=16, key=None):
        """
        Initialize the hash with a context and an optional key.
        """
        if digest_size < hydro_hash_BYTES_MIN or digest_size > hydro_hash_BYTES_MAX:
            raise ValueError("Hash length must be between 16 and 65535 bytes")

        self.ctx = Context(ctx)
        self.key = HashKey(key)
        self.digest_size = digest_size
        self.block_size = 64
        self.finalized = 0
        self.result = bytes()

        if hydro_hash_init(&self.state, self.ctx.ctx, self.key.key) != 0:
            raise RuntimeError("Failed to initialize hash state")
        if data is not None:
            self.update(data)

    cpdef update(self, const unsigned char[:] data):
        """
        Update the hash with new data.
        """
        if self.finalized == 1:
            raise RuntimeError("Hash has already been finalized")
        if data is None or len(data) == 0:
            return
        if hydro_hash_update(&self.state, &data[0], len(data)) != 0:
            raise RuntimeError("Failed to update hash")

    cpdef update_from(self, fileobj, chunk_size=io.DEFAULT_BUFFER_SIZE):
        """
        Read data from a file-like object and update the hash.
        """
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
        """
        Write data to the hash.
        """
        if data is None:
            return 0
        self.update(data)
        return len(data)

    cpdef digest(self):
        """
        Finalize the hash and return the digest.
        """
        if self.finalized == 1:
            return self.result
        cdef bytearray res = bytearray(self.digest_size)
        cdef uint8_t* res_ptr = res
        if hydro_hash_final(&self.state, res_ptr, self.digest_size) != 0:
            raise RuntimeError("Failed to finalize hash")
        self.result = bytes(res)
        self.finalized = 1
        return self.result

    cpdef hexdigest(self):
        """
        Finalize the hash and return the digest as a hex string.
        """
        return self.digest().hex()


cpdef hash_file(fileobj, ctx=None, size_t digest_size=16, key=None, chunk_size=io.DEFAULT_BUFFER_SIZE):
    """
    Compute the hash of a binary file-like object.
    """
    if fileobj is None:
        raise ValueError("File object cannot be None")
    cdef Hash hasher = Hash(ctx=ctx, digest_size=digest_size, key=key)
    hasher.update_from(fileobj, chunk_size=chunk_size)
    return hasher.digest()
