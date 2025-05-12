# cython: language_level=3

import base64

from libc.string cimport memcpy
from libc.stdint cimport uint8_t

from ._decls cimport *

from ._context cimport Context
from ._basekey cimport BaseKey
from ._exceptions cimport DeriveException
from ._sign import SignKeyPair


cdef class MasterKey(BaseKey):
    """
    A MasterKey can be used to derive subkeys, derive a key from a password, or hash passwords for storage.
    """
    def __init__(self, key=None):
        if key is None:
            super().__init__()
            return

        # when key argument is already a MasterKey, copy the key
        if isinstance(key, MasterKey):
            super().__init__(bytes(key))
            return

        # when key argument is a string, assume it's a base64 encoded key
        if isinstance(key, str):
            super().__init__(base64.standard_b64decode(key))
            return

        # else, assume it's a bytes like object
        super().__init__(bytes(key))

    def __eq__(self, other):
        if not isinstance(other, MasterKey):
            return False
        cdef MasterKey o = <MasterKey>other
        return self.eq(o)

    cpdef derive_key_from_password(self, password, ctx=None, opslimit=10000):
        """
        Derive a key from a password using the master key.
        The derived key is returned as a BaseKey.
        """
        return BaseKey(self.derive_key_from_password_with_length(password, length=32, ctx=ctx, opslimit=opslimit))

    cpdef derive_key_from_password_with_length(self, password, length=32, ctx=None, opslimit=10000):
        """
        Derive a key from a password using the master key.
        The length of the derived key in bytes is specified by the length argument.
        The derived key is returned as bytes.
        """
        password = bytes(password)
        if len(password) == 0:
            raise ValueError("Password cannot be empty")
        cdef size_t clen = int(length)
        if clen == 0:
            raise ValueError("Length cannot be 0")
        cdef const char* password_ptr = password
        cdef Context myctx = Context(ctx)
        derived_key = bytearray(clen)
        cdef uint8_t* derived_key_ptr = derived_key
        if hydro_pwhash_deterministic(derived_key_ptr, clen, password_ptr, len(password), myctx.ctx, self.key, opslimit, 0, 1) != 0:
            raise DeriveException("Failed to derive key from password")
        return bytes(derived_key)

    cpdef derive_subkey(self, uint64_t subkey_id, ctx=None):
        """
        Derive a subkey from the master key using the subkey_id.
        The derived key is returned as a BaseKey.
        """
        return BaseKey(self.derive_subkey_with_length(subkey_id, length=32, ctx=ctx))

    cpdef derive_subkey_with_length(self, uint64_t subkey_id, length=32, ctx=None):
        """
        Derive a subkey from the master key using the subkey_id.
        The length of the derived key in bytes is specified by the length argument.
        The derived key is returned as bytes.
        """
        if self.is_zero():
            raise ValueError("A zero key cannot be used to derive a subkey")
        cdef size_t clen = int(length)
        if clen < hydro_kdf_BYTES_MIN or clen > hydro_kdf_BYTES_MAX:
            raise ValueError("Subkey length must be between 16 and 65535 bytes")
        cdef Context myctx = Context(ctx)
        cdef bytearray subkey = bytearray(clen)
        cdef uint8_t* subkey_ptr = subkey
        if hydro_kdf_derive_from_key(subkey_ptr, clen, subkey_id, myctx.ctx, self.key) != 0:
            raise DeriveException("Failed to derive subkey")
        return bytes(subkey)

    cpdef derive_sign_keypair(self):
        """
        Derive a sign keypair from the master key.
        The derived keypair is returned as a SignKeyPair.
        """
        if self.is_zero():
            raise ValueError("A zero key cannot be used to derive a sign keypair")
        cdef hydro_sign_keypair kp
        hydro_sign_keygen_deterministic(&kp, self.key)
        cdef bytes secret_key = kp.sk[:hydro_sign_SECRETKEYBYTES]
        return SignKeyPair(secret_key)

    cpdef hash_password(self, password, opslimit=10000):
        """
        Returns a representation of the password suitable for storage.
        The returned value is a bytes object.
        """
        password = bytes(password)
        if len(password) == 0:
            raise ValueError("Password cannot be empty")
        cdef const char* password_ptr = password
        cdef uint8_t stored[hydro_pwhash_STOREDBYTES]
        if hydro_pwhash_create(stored, password_ptr, len(password), self.key, opslimit, 0, 1) != 0:
            raise DeriveException("Failed to hash password")
        cdef bytearray res = bytearray(hydro_pwhash_STOREDBYTES)
        cdef uint8_t* res_ptr = res
        memcpy(res_ptr, stored, hydro_pwhash_STOREDBYTES)
        return bytes(res)

    cpdef verify_password(self, password, stored, opslimit=10000):
        """
        Verify a password against a stored hash.
        Returns True if the password is correct, False otherwise.
        """
        password = bytes(password)
        if len(password) == 0:
            raise ValueError("Password cannot be empty")
        stored = bytes(stored)
        if len(stored) != hydro_pwhash_STOREDBYTES:
            raise ValueError("Stored hash must be 128 bytes long")
        cdef uint8_t* stored_ptr = stored
        cdef uint8_t stored_array[hydro_pwhash_STOREDBYTES]
        memcpy(&stored_array[0], stored_ptr, hydro_pwhash_STOREDBYTES)
        cdef const char* password_ptr = password
        if hydro_pwhash_verify(stored_array, password_ptr, len(password), self.key, opslimit, 0, 1) != 0:
            return False
        return True
