# cython: language_level=3

import base64
import io

from libc.stdint cimport uint8_t

from ._basekey cimport BaseKey
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


cdef class Hash:
    def __init__(self, *, ctx=None, data=None, digest_size=16, key=None):
        """
        Initialize the hash with a context and an optional key.
        """
        cdef Context myctx = Context(ctx)
        cdef HashKey ckey = HashKey(key)
        digest_size = int(digest_size)
        if digest_size < hydro_hash_BYTES_MIN or digest_size > hydro_hash_BYTES_MAX:
            raise ValueError("Hash length must be between 16 and 65535 bytes")
        self.digest_size = digest_size
        self.block_size = 64
        self.finalized = 0
        self.result = bytes()
        if hydro_hash_init(&self.state, myctx.ctx, ckey.key) != 0:
            raise RuntimeError("Failed to initialize hash state")
        if data is not None:
            self.update(data)

    cpdef update(self, const unsigned char[:] data):
        """
        Update the hash with new data.
        """
        if self.finalized == 1:
            raise RuntimeError("Hash has already been finalized")
        if len(data) == 0:
            return
        if hydro_hash_update(&self.state, &data[0], len(data)) != 0:
            raise RuntimeError("Failed to update hash")

    cpdef write(self, const unsigned char[:] data):
        """
        Write data to the hash.
        """
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

    @classmethod
    def file_digest(cls, fileobj, *, ctx=None, digest_size=16, key=None, chunk_size=io.DEFAULT_BUFFER_SIZE):
        """
        Compute the hash of a binary file-like object.
        """
        cdef bytearray buf = bytearray(chunk_size)
        cdef Hash h = cls(ctx=ctx, digest_size=digest_size, key=key)
        cdef size_t n = 0

        with FileOpener(fileobj, "rb") as f:
            while True:
                n = f.readinto(buf)
                if n == 0:
                    return h.digest()
                h.update(buf[:n])
