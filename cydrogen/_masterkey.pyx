# cython: language_level=3

import base64

from libc.stdint cimport uint64_t

from ._basekey cimport BaseKey
from ._context cimport make_context
from ._decls cimport pwhash_deterministic, kdf_derive_from_key
from ._decls cimport sign_keygen_deterministic, pwhash_create, pwhash_verify
from ._decls cimport hydro_pwhash_STOREDBYTES, hydro_kdf_BYTES_MIN, hydro_kdf_BYTES_MAX
from ._exceptions cimport DeriveException
from ._hash import HashKey
from ._secretbox import SecretBoxKey
from ._sign import SignPublicKey, SignSecretKey, SignKeyPair
from ._utils cimport SafeMemory


cdef class MasterKey(BaseKey):
    def __init__(self, key=None):
        if key is None:
            super().__init__()
            return

        if isinstance(key, SafeMemory):
            super().__init__(key)
            return

        cdef MasterKey o
        if isinstance(key, MasterKey):
            o = <MasterKey>key
            super().__init__(o.key)
            return

        if isinstance(key, (SignKeyPair, SignPublicKey, SignSecretKey, HashKey, SecretBoxKey)):
            raise TypeError("can't create a MasterKey from another key type")

        if isinstance(key, str):
            key = base64.standard_b64decode(key)

        # else, assume it's a bytes-like object
        super().__init__(bytes(key))

    def __eq__(self, other):
        if not isinstance(other, MasterKey):
            return False
        cdef MasterKey o = <MasterKey>other
        return self.eq(o)

    def __repr__(self):
        return f'MasterKey({repr(str(self))})'

    cpdef derive_key_from_password(self, const unsigned char[:] password, ctx=None, uint64_t opslimit=10000):
        if password is None:
            raise ValueError("Password cannot be None")
        cdef bytes derived = self.derive_key_from_password_with_length(password, length=32, ctx=ctx, opslimit=opslimit)
        return BaseKey(derived)

    cpdef derive_key_from_password_with_length(self, const unsigned char[:] password, size_t length=32, ctx=None, uint64_t opslimit=10000):
        if password is None:
            raise ValueError("Password cannot be None")
        cdef size_t pwdlen = len(password)
        if pwdlen == 0:
            raise ValueError("Password cannot be empty")
        if length == 0:
            raise ValueError("Length cannot be 0")
        derived_key = bytearray(length)
        try:
            pwhash_deterministic(password, make_context(ctx), self, opslimit, derived_key)
        except ValueError:
            raise
        except Exception as ex:
            raise DeriveException("Failed to derive key from password") from ex
        return bytes(derived_key)

    cpdef derive_subkey(self, uint64_t subkey_id, ctx=None):
        return BaseKey(self.derive_subkey_with_length(subkey_id, length=32, ctx=ctx))

    cpdef derive_subkey_with_length(self, uint64_t subkey_id, size_t length=32, ctx=None):
        if self.is_zero():
            raise ValueError("A zero key cannot be used to derive a subkey")
        if length < hydro_kdf_BYTES_MIN or length > hydro_kdf_BYTES_MAX:
            raise ValueError("Subkey length must be between 16 and 65535 bytes")
        cdef bytearray subkey = bytearray(length)
        try:
            kdf_derive_from_key(self, subkey_id, make_context(ctx), subkey)
        except ValueError:
            raise
        except Exception as ex:
            raise DeriveException("Failed to derive subkey") from ex
        return bytes(subkey)

    cpdef derive_sign_keypair(self):
        if self.is_zero():
            raise ValueError("A zero key cannot be used to derive a sign keypair")
        return SignKeyPair(sign_keygen_deterministic(self))

    cpdef hash_password(self, const unsigned char[:] password, uint64_t opslimit=10000):
        if password is None:
            raise ValueError("Password cannot be None")
        if len(password) == 0:
            raise ValueError("Password cannot be empty")
        cdef bytearray stored = bytearray(hydro_pwhash_STOREDBYTES)
        try:
            pwhash_create(password, self, opslimit, stored)
        except ValueError:
            raise
        except Exception as ex:
            raise DeriveException("Failed to hash password") from ex
        return bytes(stored)

    cpdef verify_password(self, const unsigned char[:] password, const unsigned char[:] stored, uint64_t opslimit=10000):
        if password is None:
            raise ValueError("Password cannot be None")
        if stored is None:
            raise ValueError("Stored hash cannot be None")
        if len(password) == 0:
            raise ValueError("Password cannot be empty")
        if len(stored) != hydro_pwhash_STOREDBYTES:
            raise ValueError("Stored hash must be 128 bytes long")
        return pwhash_verify(stored, password, self, opslimit)


cdef make_masterkey(key):
    if isinstance(key, MasterKey):
        return key
    return MasterKey(key)
