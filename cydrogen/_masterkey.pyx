# cython: language_level=3

import base64

from libc.stdint cimport uint64_t

from ._decls cimport pwhash_deterministic, kdf_derive_from_key
from ._decls cimport sign_keygen_deterministic, pwhash_create, pwhash_verify
from ._decls cimport hydro_pwhash_STOREDBYTES, hydro_kdf_BYTES_MIN, hydro_kdf_BYTES_MAX

from ._context cimport Context
from ._basekey cimport BaseKey
from ._hash import HashKey
from ._secretbox import SecretBoxKey
from ._sign import SignPublicKey, SignSecretKey, SignKeyPair
from ._exceptions cimport DeriveException


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

        if isinstance(key, (BaseKey, SignKeyPair, SignPublicKey, SignSecretKey, HashKey, SecretBoxKey)):
            # when key argument is a BaseKey or a derived key, copy the key
            raise TypeError("can't create a MasterKey from another key type")

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

    def __repr__(self):
        return f'MasterKey({repr(str(self))})'

    cpdef derive_key_from_password(self, const unsigned char[:] password, ctx=None, uint64_t opslimit=10000):
        """
        Derive a key from a password using the master key.
        The derived key is returned as a BaseKey.
        """
        if password is None:
            raise ValueError("Password cannot be None")
        return BaseKey(self.derive_key_from_password_with_length(password, length=32, ctx=ctx, opslimit=opslimit))

    cpdef derive_key_from_password_with_length(self, const unsigned char[:] password, size_t length=32, ctx=None, uint64_t opslimit=10000):
        """
        Derive a key from a password using the master key.
        The length of the derived key in bytes is specified by the length argument.
        The derived key is returned as bytes.
        """
        if password is None:
            raise ValueError("Password cannot be None")
        cdef size_t pwdlen = len(password)
        if pwdlen == 0:
            raise ValueError("Password cannot be empty")
        if length == 0:
            raise ValueError("Length cannot be 0")
        cdef Context myctx = Context(ctx)
        derived_key = bytearray(length)
        try:
            pwhash_deterministic(password, myctx, self, opslimit, derived_key)
        except ValueError:
            raise
        except Exception as ex:
            raise DeriveException("Failed to derive key from password") from ex
        return bytes(derived_key)

    cpdef derive_subkey(self, uint64_t subkey_id, ctx=None):
        """
        Derive a subkey from the master key using the subkey_id.
        The derived key is returned as a BaseKey.
        """
        return BaseKey(self.derive_subkey_with_length(subkey_id, length=32, ctx=ctx))

    cpdef derive_subkey_with_length(self, uint64_t subkey_id, size_t length=32, ctx=None):
        """
        Derive a subkey from the master key using the subkey_id.
        The length of the derived key in bytes is specified by the length argument.
        The derived key is returned as bytes.
        """
        if self.is_zero():
            raise ValueError("A zero key cannot be used to derive a subkey")
        if length < hydro_kdf_BYTES_MIN or length > hydro_kdf_BYTES_MAX:
            raise ValueError("Subkey length must be between 16 and 65535 bytes")
        cdef Context myctx = Context(ctx)
        cdef bytearray subkey = bytearray(length)
        try:
            kdf_derive_from_key(self, subkey_id, myctx, subkey)
        except ValueError:
            raise
        except Exception as ex:
            raise DeriveException("Failed to derive subkey") from ex
        return bytes(subkey)

    cpdef derive_sign_keypair(self):
        """
        Derive a sign keypair from the master key.
        The derived keypair is returned as a SignKeyPair.
        """
        if self.is_zero():
            raise ValueError("A zero key cannot be used to derive a sign keypair")
        return SignKeyPair(sign_keygen_deterministic(self))

    cpdef hash_password(self, const unsigned char[:] password, uint64_t opslimit=10000):
        """
        Returns a representation of the password suitable for storage.
        The returned value is a bytes object.
        """
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
        """
        Verify a password against a stored hash.
        Returns True if the password is correct, False otherwise.
        """
        if password is None:
            raise ValueError("Password cannot be None")
        if stored is None:
            raise ValueError("Stored hash cannot be None")
        if len(password) == 0:
            raise ValueError("Password cannot be empty")
        if len(stored) != hydro_pwhash_STOREDBYTES:
            raise ValueError("Stored hash must be 128 bytes long")
        return pwhash_verify(stored, password, self, opslimit)
