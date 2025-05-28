import base64
import io
from itertools import product

import pytest

import cydrogen
from cydrogen._basekey import BaseKey  # type: ignore[import]

KEY_BYTES = b"\xeaCU\x91\xdb?\xc2\xefZ\xb9HO\x84\xc5\xf3\xbf\x07\xecunR\xab\xa4\xa7`\r=\xe5\xf0e\xfb%"
KEY_BYTES_2 = b")\xf5G\x95\xa9e\xeb\xb3\xfcU1?[\x9f\xd1\x8b6\xe4\x8a\xac\xf1 \xf5\xd3\xf8\x98c\xae\xce\xdcoA"

MESSAGES = [
    b"Nobody inspects the spammish repetition",
    b"Then shalt thou count to three, no more, no less. Three shall be the number thou shalt count, and the number of the counting shall be three.",
    b"I don't want to talk to you no more, you empty headed animal food trough wiper.",
]


def test_create_zero_hash_key():
    key = cydrogen.HashKey()
    assert bytes(key) == 32 * b"\x00"
    assert key.is_zero()
    assert not bool(key)


def test_create_hash_key_from_bytes():
    key = cydrogen.HashKey(KEY_BYTES)
    assert bytes(key) == KEY_BYTES
    assert bool(key)


def test_create_hash_key_from_str():
    key_str = base64.standard_b64encode(KEY_BYTES).decode("utf-8")
    key = cydrogen.HashKey(key_str)
    assert str(key) == key_str
    assert bool(key)


def test_gen_hash_key():
    key = cydrogen.HashKey.gen()
    assert bool(key)
    assert len(bytes(key)) == 32


def test_copy_hash_key():
    key1 = cydrogen.HashKey.gen()
    key2 = cydrogen.HashKey(key1)
    assert bytes(key1) == bytes(key2)
    assert key1 == key2


def test_hash_key_equality():
    key1 = cydrogen.HashKey(KEY_BYTES)
    key2 = cydrogen.HashKey(KEY_BYTES)
    key3 = cydrogen.HashKey.gen()
    assert key1 == key1
    assert key1 == key2
    assert key1 != key3


def test_hash_key_repr():
    key_str = base64.standard_b64encode(KEY_BYTES).decode("utf-8")
    key = cydrogen.HashKey(KEY_BYTES)
    assert repr(key) == f"HashKey({repr(key_str)})"


def test_no_convert_hashkey_secretboxkey():
    key = cydrogen.HashKey(KEY_BYTES)
    with pytest.raises(TypeError):
        cydrogen.SecretBoxKey(key)


def test_no_convert_secretboxkey_hash_key():
    key = cydrogen.SecretBoxKey(KEY_BYTES)
    with pytest.raises(TypeError):
        cydrogen.HashKey(key)


def test_convert_basekey_hash_key():
    key = BaseKey.gen()
    hk = cydrogen.HashKey(key)
    assert bytes(hk) == bytes(key)


def test_no_convert_hash_key_basekey():
    key = cydrogen.HashKey(KEY_BYTES)
    with pytest.raises(TypeError):
        BaseKey(key)


def test_simple_digest():
    key = cydrogen.HashKey(KEY_BYTES)
    h = key.hasher(MESSAGES[0]).digest()
    expected_hash = b"\x95\x08\x00\x14T9\xdcnr\x94\xf5C$\xfb.?"
    assert len(h) == 16
    assert h == expected_hash


def test_digest():
    master_keys = [cydrogen.HashKey(), cydrogen.HashKey(KEY_BYTES), cydrogen.HashKey(KEY_BYTES_2)]
    ctxs = [cydrogen.Context(b"EXAMPLES"), cydrogen.Context(b"CONTEXTS")]
    sizes = [16, 32, 64, 128]
    digests = set()
    for msg, key, ctx, digest_size in product(MESSAGES, master_keys, ctxs, sizes):
        h = cydrogen.Hash(key=key, ctx=ctx, digest_size=digest_size)
        h.update(msg)
        digest = h.digest()
        assert len(digest) == digest_size
        h = key.hasher(msg, ctx=ctx, digest_size=digest_size)
        assert h.digest() == digest
        assert digest not in digests
        digests.add(digest)


def test_hash_file():
    key = cydrogen.HashKey(KEY_BYTES)
    buf = cydrogen.gen_random_buffer(70000)
    fobj = io.BytesIO(buf)

    # call function hash_file with default chunk size
    fobj.seek(0)
    digest1 = cydrogen.hash_file(fobj, ctx=b"CONTEXTS", digest_size=16, key=key, chunk_size=io.DEFAULT_BUFFER_SIZE)
    assert len(digest1) == 16
    # call function hash_file with custom chunk size
    fobj.seek(0)
    digest2 = cydrogen.hash_file(fobj, ctx=b"CONTEXTS", digest_size=16, key=key, chunk_size=65536)
    assert digest1 == digest2
    # call hasher method update_from
    fobj.seek(0)
    hasher = key.hasher(ctx=b"CONTEXTS")
    hasher.update_from(fobj)
    assert hasher.digest() == digest1
