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
from ._exceptions import CyException, DecryptException, DeriveException, EncryptException, SignException, VerifyException
from ._hash import Hash, HashKey, hash_file
from ._masterkey import MasterKey
from ._secretbox import EncryptedMessage, SecretBox, SecretBoxKey
from ._sign import Signer, SignKeyPair, SignPublicKey, SignSecretKey, Verifier, sign_file, verify_file
from ._utils import load16, load32, load64, store16, store32, store64

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
    "load64",
    "store64",
    "load16",
    "store16",
    "shuffle_buffer",
    "pad",
    "unpad",
]


def do_init():
    # initialize the libhydrogen library
    # we hide the import of hynit here to avoid to declare it in the public API
    from ._decls import hynit

    hynit()


do_init()
