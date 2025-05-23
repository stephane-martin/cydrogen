import base64
import io
from itertools import product

import pytest

import cydrogen

SK_BYTES = b"\xb5\xb3Y\x8bV\x13\xb1`?\xea\xa2\x96\x93\xf3\xfc&:\x0e+pIZ\x13\x84\x99\x94\xb7\x94a\xb0\x12*\xdf\xba=;\x9d\xe3\xfe\xee2\xef\xd3\x905\xba!pI@J\x88\xf3j\x8d\xc2\xae\x0eA\x98\xaa,\xfe\x02"
PK_BYTES = b"\xdf\xba=;\x9d\xe3\xfe\xee2\xef\xd3\x905\xba!pI@J\x88\xf3j\x8d\xc2\xae\x0eA\x98\xaa,\xfe\x02"
SK_STR = base64.b64encode(SK_BYTES).decode("ascii")
PK_STR = base64.b64encode(PK_BYTES).decode("ascii")

MESSAGES = [
    b"Nobody inspects the spammish repetition",
    b"Then shalt thou count to three, no more, no less. Three shall be the number thou shalt count, and the number of the counting shall be three.",
    b"I don't want to talk to you no more, you empty headed animal food trough wiper.",
]

CONTEXTS = [b"EXAMPLES", b"CONTEXTS"]


def test_gen_kp():
    kp = cydrogen.SignKeyPair.gen()
    kp_bytes = bytes(kp)
    assert len(kp_bytes) == 64
    assert kp_bytes != b"\x00" * 64


def test_kp_from_bytes():
    kp = cydrogen.SignKeyPair(SK_BYTES)
    assert bytes(kp) == SK_BYTES
    assert bytes(kp.public_key) == PK_BYTES
    assert bytes(kp.secret_key) == SK_BYTES
    kp2 = cydrogen.SignKeyPair(SK_STR)
    assert bytes(kp2) == SK_BYTES


def test_sk_from_bytes():
    sk = cydrogen.SignSecretKey(SK_BYTES)
    assert bytes(sk) == SK_BYTES
    sk2 = cydrogen.SignSecretKey(SK_STR)
    assert bytes(sk2) == SK_BYTES


def test_pk_from_bytes():
    pk = cydrogen.SignPublicKey(PK_BYTES)
    assert bytes(pk) == PK_BYTES
    pk2 = cydrogen.SignPublicKey(PK_STR)
    assert bytes(pk2) == PK_BYTES


def test_sk_pk_consistent():
    sk = cydrogen.SignSecretKey(SK_BYTES)
    pk = cydrogen.SignPublicKey(PK_BYTES)
    assert sk.check_public_key(pk)


def test_sign_message():
    kp = cydrogen.SignKeyPair(SK_BYTES)
    signatures = set()

    for msg, ctx in product(MESSAGES, CONTEXTS):
        signer = kp.signer(ctx=ctx)
        signer.update(msg)
        signature = signer.sign()
        assert len(signature) == 64
        assert signature not in signatures
        signatures.add(signature)


def test_verify_message():
    kp = cydrogen.SignKeyPair(SK_BYTES)

    for msg, ctx in product(MESSAGES, CONTEXTS):
        signer = kp.signer(ctx=ctx)
        signer.update(msg)
        signature = signer.sign()
        verifier = kp.verifier(ctx=ctx)
        verifier.update(msg)
        verifier.verify(signature)

        # now lets modify the message
        msg2 = bytearray(msg)
        msg2[0] = (msg2[0] + 1) % 256
        verifier = kp.verifier(ctx=ctx)
        verifier.update(msg2)
        with pytest.raises(cydrogen.VerifyException):
            verifier.verify(signature)

        # now lets modify the signature
        signature2 = bytearray(signature)
        signature2[0] = (signature2[0] + 1) % 256
        verifier = kp.verifier(ctx=ctx)
        verifier.update(msg)
        with pytest.raises(cydrogen.VerifyException):
            verifier.verify(signature2)


def test_sign_file():
    buf = cydrogen.gen_random_buffer(70000)
    fobj = io.BytesIO(buf)
    kp = cydrogen.SignKeyPair(SK_BYTES)

    fobj.seek(0)
    sig = cydrogen.sign_file(kp.secret_key, fobj)

    fobj.seek(0)
    cydrogen.verify_file(kp.public_key, fobj, sig)

    fobj.seek(0)
    with pytest.raises(cydrogen.VerifyException):
        cydrogen.verify_file(kp.public_key, fobj, sig, ctx=b"BOO")
