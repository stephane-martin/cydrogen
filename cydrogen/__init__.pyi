"""
The `cydrogen` package provides Python bindings for the `libhydrogen` library.

It includes functionalities for cryptographic operations such as hashing, symmetric
encryption, and signing.

Everything present directly in the parent `cydrogen` module is considered the public API.
Users should not import anything from the `cydrogen._someinternal` submodule, as it is not
part of the public API and may change without notice.
"""

from ._context import Context
from ._decls import (
    gen_random_buffer,
    random_u32,
    random_uniform,
    randomize_buffer,
    shuffle_buffer,
)
from ._exceptions import CyException, DecryptException, DeriveException, EncryptException, SignException, VerifyException
from ._hash import Hash, HashKey, hash_file
from ._masterkey import MasterKey
from ._secretbox import EncryptedMessage, SecretBox, SecretBoxKey
from ._sign import Signer, SignKeyPair, SignPublicKey, SignSecretKey, Verifier, sign_file, verify_file
from ._utils import load32, store32

__all__ = [
    "random_u32",
    "random_uniform",
    "randomize_buffer",
    "gen_random_buffer",
    "CyException",
    "BaseException",
    "EncryptException",
    "DecryptException",
    "DeriveException",
    "SignException",
    "VerifyException",
    "HashKey",
    "SecretBoxKey",
    "MasterKey",
    "Context",
    "Hash",
    "SecretBox",
    "SignPublicKey",
    "SignSecretKey",
    "SignKeyPair",
    "Signer",
    "Verifier",
    "EncryptedMessage",
    "hash_file",
    "sign_file",
    "verify_file",
    "load32",
    "store32",
    "shuffle_buffer",
]
