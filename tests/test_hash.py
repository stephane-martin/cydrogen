import base64
import io

import cydrogen
import pytest
from cydrogen._basekey import BaseKey

KEY_BYTES = [
    b"\xeaCU\x91\xdb?\xc2\xefZ\xb9HO\x84\xc5\xf3\xbf\x07\xecunR\xab\xa4\xa7`\r=\xe5\xf0e\xfb%",
    b")\xf5G\x95\xa9e\xeb\xb3\xfcU1?[\x9f\xd1\x8b6\xe4\x8a\xac\xf1 \xf5\xd3\xf8\x98c\xae\xce\xdcoA",
]

MESSAGES = [
    b"Nobody inspects the spammish repetition",
    b"Then shalt thou count to three, no more, no less. Three shall be the number thou shalt count, and the number of the counting shall be three.",
    b"I don't want to talk to you no more, you empty headed animal food trough wiper.",
]

CONTEXTS = [
    b"EXAMPLES",
    b"CONTEXTS",
    b"HELLO",
]


def test_create_zero_hash_key():
    key = cydrogen.HashKey()
    assert bytes(key) == 32 * b"\x00"
    assert key.is_zero()
    assert not bool(key)


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_create_hash_key_from_bytes(key_bytes: bytes):
    key = cydrogen.HashKey(key_bytes)
    assert bytes(key) == key_bytes
    assert bool(key)


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_create_hash_key_from_str(key_bytes: bytes):
    key_str = base64.standard_b64encode(key_bytes).decode("utf-8")
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


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_hash_key_equality(key_bytes: bytes):
    key1 = cydrogen.HashKey(key_bytes)
    key2 = cydrogen.HashKey(key_bytes)
    key3 = cydrogen.HashKey.gen()
    assert key1 == key1  # noqa: PLR0124
    assert key1 == key2
    assert key1 != key3


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_hash_key_repr(key_bytes: bytes):
    key_str = base64.standard_b64encode(key_bytes).decode("utf-8")
    key = cydrogen.HashKey(key_bytes)
    assert repr(key) == f"HashKey({key_str!r})"


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_no_convert_hashkey_secretboxkey(key_bytes: bytes):
    key = cydrogen.HashKey(key_bytes)
    with pytest.raises(TypeError):
        cydrogen.SecretBoxKey(key)


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_no_convert_secretboxkey_hash_key(key_bytes: bytes):
    key = cydrogen.SecretBoxKey(key_bytes)
    with pytest.raises(TypeError):
        cydrogen.HashKey(key)


def test_convert_basekey_hash_key():
    key = BaseKey.gen()
    hk = cydrogen.HashKey(key)
    assert bytes(hk) == bytes(key)


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_no_convert_hash_key_basekey(key_bytes: bytes) -> None:
    key = cydrogen.HashKey(key_bytes)
    with pytest.raises(TypeError):
        BaseKey(key)  # type: ignore[arg-type]


def test_simple_digest() -> None:
    key = cydrogen.HashKey(KEY_BYTES[0])
    h = key.hasher(MESSAGES[0]).digest()
    expected_hash = b"\x95\x08\x00\x14T9\xdcnr\x94\xf5C$\xfb.?"
    assert len(h) == 16
    assert h == expected_hash


@pytest.fixture(params=[None, *KEY_BYTES])
def hashkey(request: pytest.FixtureRequest) -> cydrogen.HashKey:
    if request.param is None:
        return cydrogen.HashKey()
    return cydrogen.HashKey(request.param)


@pytest.fixture(params=[None, *CONTEXTS])
def context(request: pytest.FixtureRequest) -> cydrogen.Context:
    if request.param is None:
        return cydrogen.Context()
    return cydrogen.Context(request.param)


test_digest_digests: set[bytes] = set()


@pytest.mark.parametrize("message", MESSAGES)
@pytest.mark.parametrize("digest_size", [16, 32, 64, 128])
def test_digest(context: cydrogen.Context, hashkey: cydrogen.HashKey, digest_size: int, message: bytes) -> None:
    h = cydrogen.Hash(key=hashkey, ctx=context, digest_size=digest_size)
    h.update(message)
    digest = h.digest()
    assert len(digest) == digest_size
    h = hashkey.hasher(message, ctx=context, digest_size=digest_size)
    assert h.digest() == digest
    assert digest not in test_digest_digests
    test_digest_digests.add(digest)


def test_hash_file() -> None:
    key = cydrogen.HashKey(KEY_BYTES[0])
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
