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
from ._kx_n import (
    KX_KK_PACKET1BYTES,
    KX_KK_PACKET2BYTES,
    KX_N_PACKET1BYTES,
    KX_PAIR_SIZE,
    KX_XX_PACKET1BYTES,
    KX_XX_PACKET2BYTES,
    KX_XX_PACKET3BYTES,
    KxKkClientState,
    KxPair,
    KxPublicKey,
    KxSecretKey,
    KxXxClientState,
    KxXxServerState,
    Psk,
    SessionPair,
    client_init_kx_n,
    server_finish_kx_n,
)
from ._masterkey import MasterKey
from ._secretbox import EncryptedMessage, SecretBox, SecretBoxKey
from ._sign import Signer, SignKeyPair, SignPublicKey, SignSecretKey, Verifier, sign_file, verify_file
from ._utils import Counter, load16, load32, load64, store16, store32, store64

__all__ = [
    # utils
    "Counter",
    "load16",
    "load32",
    "load64",
    "store16",
    "store32",
    "store64",
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
    "KxXxClientState",
    "KxXxServerState",
    "KxPublicKey",
    "KxSecretKey",
    "Psk",
    "SessionPair",
    "client_init_kx_n",
    "server_finish_kx_n",
    "KxKkClientState",
    # padding
    "pad",
    "unpad",
    "KX_PAIR_SIZE",
    "KX_N_PACKET1BYTES",
    "KX_KK_PACKET1BYTES",
    "KX_KK_PACKET2BYTES",
    "KX_XX_PACKET1BYTES",
    "KX_XX_PACKET2BYTES",
    "KX_XX_PACKET3BYTES",
]
