from ._context import Context
from ._decls import (
    NOGIL_THRESHOLD_BYTES,
    gen_random_buffer,
    pad,
    random_u32,
    random_uniform,
    randomize_buffer,
    shuffle_buffer,
    unpad,
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
from ._networking import MsgQueue, ReadBuffers
from ._secretbox import (
    ENC_MSG_HEADER_SIZE,
    ENC_MSG_MARKER,
    EncryptedMessage,
    SecretBox,
    SecretBoxKey,
    encrypted_message_header,
    parse_encrypted_message_header,
)
from ._sign import Signer, SignKeyPair, SignPublicKey, SignSecretKey, Verifier, sign_file, verify_file
from ._utils import Counter, load16, load32, load64, store16, store32, store64
from .exceptions import (
    ClientClosedError,
    CyException,
    DecryptException,
    DeriveException,
    EncryptException,
    KeyExchangeException,
    MessageTooBigException,
    SignException,
    VerifyException,
)

__all__ = [
    "ENC_MSG_HEADER_SIZE",
    "ENC_MSG_MARKER",
    "KX_KK_PACKET1BYTES",
    "KX_KK_PACKET2BYTES",
    "KX_N_PACKET1BYTES",
    "KX_PAIR_SIZE",
    "KX_XX_PACKET1BYTES",
    "KX_XX_PACKET2BYTES",
    "KX_XX_PACKET3BYTES",
    "NOGIL_THRESHOLD_BYTES",
    "BaseException",
    "ClientClosedError",
    "Context",
    "Counter",
    "CyException",
    "DecryptException",
    "DeriveException",
    "EncryptException",
    "EncryptedMessage",
    "Hash",
    "HashKey",
    "KeyExchangeException",
    "KxKkClientState",
    "KxPair",
    "KxPublicKey",
    "KxSecretKey",
    "KxXxClientState",
    "KxXxServerState",
    "MasterKey",
    "MessageTooBigException",
    "MsgQueue",
    "Psk",
    "ReadBuffers",
    "SecretBox",
    "SecretBoxKey",
    "SessionPair",
    "SignException",
    "SignKeyPair",
    "SignPublicKey",
    "SignSecretKey",
    "Signer",
    "Verifier",
    "VerifyException",
    "client_init_kx_n",
    "encrypted_message_header",
    "gen_random_buffer",
    "hash_file",
    "load16",
    "load32",
    "load64",
    "pad",
    "parse_encrypted_message_header",
    "random_u32",
    "random_uniform",
    "randomize_buffer",
    "server_finish_kx_n",
    "shuffle_buffer",
    "sign_file",
    "store16",
    "store32",
    "store64",
    "unpad",
    "verify_file",
]


def do_init() -> None:
    # initialize the libhydrogen library
    # we hide the import of hynit here to avoid to declare it in the public API
    from ._decls import hynit

    hynit()


do_init()
