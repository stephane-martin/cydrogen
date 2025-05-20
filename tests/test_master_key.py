import base64

import pytest

import cydrogen
from cydrogen._basekey import BaseKey  # type: ignore[import]

KEY_BYTES = b"\xeaCU\x91\xdb?\xc2\xefZ\xb9HO\x84\xc5\xf3\xbf\x07\xecunR\xab\xa4\xa7`\r=\xe5\xf0e\xfb%"


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
    key_bytes = b"\xeaCU\x91\xdb?\xc2\xefZ\xb9HO\x84\xc5\xf3\xbf\x07\xecunR\xab\xa4\xa7`\r=\xe5\xf0e\xfb%"
    key_str = base64.standard_b64encode(key_bytes).decode("utf-8")
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
