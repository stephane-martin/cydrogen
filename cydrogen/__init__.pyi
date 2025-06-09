"""
The `cydrogen` package provides Python bindings for the [libhydrogen](https://github.com/jedisct1/libhydrogen) library.

It includes functionalities for cryptographic operations such as hashing, symmetric
encryption, and signing.

Everything present directly in the parent `cydrogen` module is considered the public API.

Users should not import anything from `cydrogen._someinternal` submodules, as these are
internal implementations and may change without notice.
"""

from ._basekey import BaseKey
from ._context import Context
from ._decls import (
    gen_random_buffer,
    pad,
    random_u32,
    random_uniform,
    randomize_buffer,
    shuffle_buffer,
    unpad,
)
from ._exceptions import (
    CyException,
    DecryptException,
    DeriveException,
    EncryptException,
    KeyExchangeException,
    SignException,
    VerifyException,
)
from ._hash import Hash, HashKey, hash_file
from ._kx_n import KxPair, KxPublicKey, KxSecretKey, Psk, SessionPair, kx_n_gen_session_and_packet, kx_n_gen_session_from_packet
from ._masterkey import MasterKey
from ._secretbox import EncryptedMessage, SecretBox, SecretBoxKey
from ._sign import Signer, SignKeyPair, SignPublicKey, SignSecretKey, Verifier, sign_file, verify_file

__all__ = [
    # random
    "random_u32",
    "random_uniform",
    "randomize_buffer",
    "gen_random_buffer",
    "shuffle_buffer",
    # base key
    "BaseKey",
    # exceptions
    "CyException",
    "EncryptException",
    "DecryptException",
    "DeriveException",
    "SignException",
    "VerifyException",
    "KeyExchangeException",
    # context
    "Context",
    # hashing
    "Hash",
    "HashKey",
    "hash_file",
    # cryptobox
    "SecretBoxKey",
    "SecretBox",
    "EncryptedMessage",
    # master key / derivation
    "MasterKey",
    # signing
    "SignPublicKey",
    "SignSecretKey",
    "SignKeyPair",
    "Signer",
    "Verifier",
    "sign_file",
    "verify_file",
    # key exchange
    "KxPair",
    "KxPublicKey",
    "KxSecretKey",
    "Psk",
    "SessionPair",
    "kx_n_gen_session_and_packet",
    "kx_n_gen_session_from_packet",
    # padding
    "pad",
    "unpad",
]
