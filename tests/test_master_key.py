import base64
from itertools import product

import pytest

import cydrogen
from cydrogen._basekey import BaseKey  # type: ignore[import]

KEY_BYTES = b"\xeaCU\x91\xdb?\xc2\xefZ\xb9HO\x84\xc5\xf3\xbf\x07\xecunR\xab\xa4\xa7`\r=\xe5\xf0e\xfb%"
KEY_BYTES_2 = b")\xf5G\x95\xa9e\xeb\xb3\xfcU1?[\x9f\xd1\x8b6\xe4\x8a\xac\xf1 \xf5\xd3\xf8\x98c\xae\xce\xdcoA"


def test_create_zero_master_key():
    key = cydrogen.MasterKey()
    assert bytes(key) == 32 * b"\x00"
    assert key.is_zero()
    assert not bool(key)


def test_create_master_key_from_bytes():
    key = cydrogen.MasterKey(KEY_BYTES)
    assert bytes(key) == KEY_BYTES
    assert bool(key)


def test_create_master_key_from_str():
    key_str = base64.standard_b64encode(KEY_BYTES).decode("utf-8")
    key = cydrogen.MasterKey(key_str)
    assert str(key) == key_str
    assert bool(key)


def test_gen_master_key():
    key = cydrogen.MasterKey.gen()
    assert bool(key)
    assert len(bytes(key)) == 32


def test_copy_master_key():
    key1 = cydrogen.MasterKey.gen()
    key2 = cydrogen.MasterKey(key1)
    assert bytes(key1) == bytes(key2)
    assert key1 == key2


def test_master_key_equality():
    key1 = cydrogen.MasterKey(KEY_BYTES)
    key2 = cydrogen.MasterKey(KEY_BYTES)
    key3 = cydrogen.MasterKey.gen()
    assert key1 == key1
    assert key1 == key2
    assert key1 != key3


def test_master_key_repr():
    key_str = base64.standard_b64encode(KEY_BYTES).decode("utf-8")
    key = cydrogen.MasterKey(KEY_BYTES)
    assert repr(key) == f"MasterKey({key_str})"


def test_no_convert_masterkey_hashkey():
    key = cydrogen.MasterKey(KEY_BYTES)
    with pytest.raises(TypeError):
        cydrogen.HashKey(key)


def test_no_convert_masterkey_secretboxkey():
    key = cydrogen.MasterKey(KEY_BYTES)
    with pytest.raises(TypeError):
        cydrogen.SecretBoxKey(key)


def test_no_convert_hashkey_master_key():
    key = cydrogen.HashKey(KEY_BYTES)
    with pytest.raises(TypeError):
        cydrogen.MasterKey(key)


def test_no_convert_secretboxkey_master_key():
    key = cydrogen.SecretBoxKey(KEY_BYTES)
    with pytest.raises(TypeError):
        cydrogen.MasterKey(key)


def test_no_convert_basekey_master_key():
    key = BaseKey.gen()
    with pytest.raises(TypeError):
        cydrogen.MasterKey(key)


def test_no_convert_master_key_basekey():
    key = cydrogen.MasterKey(KEY_BYTES)
    with pytest.raises(TypeError):
        BaseKey(key)


def test_derive_key_from_password_with_length():
    master_keys = [cydrogen.MasterKey(KEY_BYTES), cydrogen.MasterKey(KEY_BYTES_2)]
    passwords = [b"password", b"password2"]
    ctx = [cydrogen.Context(b"EXAMPLES"), cydrogen.Context(b"CONTEXTS")]
    lengths = [32, 64, 128]
    opslimits = [1000, 10000, 100000]

    generated_keys = set()

    for master_key, password, ctx, length, opslimit in product(master_keys, passwords, ctx, lengths, opslimits):
        derived_key = master_key.derive_key_from_password_with_length(password, length=length, ctx=ctx, opslimit=opslimit)
        assert isinstance(derived_key, bytes)
        assert len(derived_key) == length
        assert derived_key != bytes(master_key)
        # Check that the derived key is deterministic
        derived_key_2 = master_key.derive_key_from_password_with_length(password, length=length, ctx=ctx, opslimit=opslimit)
        assert bytes(derived_key) == bytes(derived_key_2)
        # Check that the derived key is unique
        assert derived_key not in generated_keys
        generated_keys.add(bytes(derived_key))


def test_derive_key_from_password():
    key = cydrogen.MasterKey(KEY_BYTES)
    key2 = key.derive_key_from_password(b"password")
    assert isinstance(key2, BaseKey)


def test_derive_subkey_with_length():
    master_keys = [cydrogen.MasterKey(KEY_BYTES), cydrogen.MasterKey(KEY_BYTES_2)]
    subkey_ids = [1, 2, 3]
    ctx = [cydrogen.Context(b"EXAMPLES"), cydrogen.Context(b"CONTEXTS")]
    lengths = [32, 64, 128]

    generated_keys = set()

    for master_key, subkey_id, ctx, length in product(master_keys, subkey_ids, ctx, lengths):
        derived_key = master_key.derive_subkey_with_length(subkey_id, length=length, ctx=ctx)
        assert isinstance(derived_key, bytes)
        assert len(derived_key) == length
        assert derived_key != bytes(master_key)
        # Check that the derived key is deterministic
        derived_key_2 = master_key.derive_subkey_with_length(subkey_id, length=length, ctx=ctx)
        assert bytes(derived_key) == bytes(derived_key_2)
        # Check that the derived key is unique
        assert derived_key not in generated_keys
        generated_keys.add(bytes(derived_key))


def test_derive_subkey():
    key = cydrogen.MasterKey(KEY_BYTES)
    key2 = key.derive_subkey(1, ctx=b"EXAMPLES")
    assert isinstance(key2, BaseKey)


def test_derive_sign_keypair():
    key = cydrogen.MasterKey(KEY_BYTES)
    key2 = key.derive_sign_keypair()
    assert isinstance(key2, cydrogen.SignKeyPair)
