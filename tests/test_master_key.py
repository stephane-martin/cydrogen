import base64

import cydrogen
import pytest
from cydrogen._basekey import BaseKey  # type: ignore[import]

KEY_BYTES = [
    b"\xeaCU\x91\xdb?\xc2\xefZ\xb9HO\x84\xc5\xf3\xbf\x07\xecunR\xab\xa4\xa7`\r=\xe5\xf0e\xfb%",
    b")\xf5G\x95\xa9e\xeb\xb3\xfcU1?[\x9f\xd1\x8b6\xe4\x8a\xac\xf1 \xf5\xd3\xf8\x98c\xae\xce\xdcoA",
]

CONTEXTS = [
    b"EXAMPLES",
    b"CONTEXTS",
]


@pytest.fixture(params=[None, *KEY_BYTES])
def master_key(request: pytest.FixtureRequest) -> cydrogen.MasterKey:
    if request.param is None:
        return cydrogen.MasterKey()
    return cydrogen.MasterKey(request.param)


@pytest.fixture(params=CONTEXTS)
def context(request: pytest.FixtureRequest) -> cydrogen.Context:
    return cydrogen.Context(request.param)


def test_create_zero_master_key() -> None:
    key = cydrogen.MasterKey()
    assert bytes(key) == 32 * b"\x00"
    assert key.is_zero()
    assert not bool(key)


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_create_master_key_from_bytes(key_bytes: bytes) -> None:
    key = cydrogen.MasterKey(key_bytes)
    assert bytes(key) == key_bytes
    assert bool(key)


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_create_master_key_from_str(key_bytes: bytes) -> None:
    key_str = base64.standard_b64encode(key_bytes).decode("utf-8")
    key = cydrogen.MasterKey(key_str)
    assert str(key) == key_str
    assert bool(key)


def test_gen_master_key() -> None:
    key = cydrogen.MasterKey.gen()
    assert bool(key)
    assert len(bytes(key)) == 32


def test_copy_master_key() -> None:
    key1 = cydrogen.MasterKey.gen()
    key2 = cydrogen.MasterKey(key1)
    key3 = cydrogen.MasterKey(bytes(key1))
    assert bytes(key1) == bytes(key2)
    assert key1 == key2
    assert key1 == key3


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_master_key_equality(key_bytes: bytes) -> None:
    key1 = cydrogen.MasterKey(key_bytes)
    key2 = cydrogen.MasterKey(key_bytes)
    key3 = cydrogen.MasterKey.gen()
    assert key1 == key1  # noqa: PLR0124
    assert key1 == key2
    assert key1 != key3


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_master_key_repr(key_bytes: bytes) -> None:
    key_str = base64.standard_b64encode(key_bytes).decode("utf-8")
    key = cydrogen.MasterKey(key_bytes)
    assert repr(key) == f"MasterKey({key_str!r})"


def test_convert_basekey_master_key() -> None:
    key = BaseKey.gen()
    cydrogen.MasterKey(key)


def test_no_convert_masterkey_hashkey() -> None:
    key = cydrogen.MasterKey(KEY_BYTES[0])
    with pytest.raises(TypeError):
        cydrogen.HashKey(key)


def test_no_convert_masterkey_secretboxkey() -> None:
    key = cydrogen.MasterKey(KEY_BYTES[0])
    with pytest.raises(TypeError):
        cydrogen.SecretBoxKey(key)


def test_no_convert_hashkey_master_key() -> None:
    key = cydrogen.HashKey(KEY_BYTES[0])
    with pytest.raises(TypeError):
        cydrogen.MasterKey(key)


def test_no_convert_secretboxkey_master_key() -> None:
    key = cydrogen.SecretBoxKey(KEY_BYTES[0])
    with pytest.raises(TypeError):
        cydrogen.MasterKey(key)


def test_no_convert_master_key_basekey() -> None:
    key = cydrogen.MasterKey(KEY_BYTES[0])
    with pytest.raises(TypeError):
        BaseKey(key)  # type: ignore[arg-type]


def test_no_convert_masterkey_signkeypair() -> None:
    key = cydrogen.MasterKey(KEY_BYTES[0])
    with pytest.raises(TypeError):
        cydrogen.SignKeyPair(key)


def test_no_convert_signkeypair_master_key() -> None:
    key = cydrogen.SignKeyPair.gen()
    with pytest.raises(TypeError):
        cydrogen.MasterKey(key)


test_derive_key_from_password_with_length_set = set()


@pytest.mark.parametrize("password", [b"password", b"password2"])
@pytest.mark.parametrize("opslimit", [1000, 10000, 100000])
@pytest.mark.parametrize("length", [32, 64, 128])
def test_derive_key_from_password_with_length(
    master_key: cydrogen.MasterKey,
    context: cydrogen.Context,
    password: bytes,
    opslimit: int,
    length: int,
) -> None:
    derived_key = master_key.derive_key_from_password_with_length(password, length=length, ctx=context, opslimit=opslimit)
    assert isinstance(derived_key, bytes)
    assert len(derived_key) == length
    assert derived_key != bytes(master_key)
    # Check that the derived key is deterministic
    derived_key_2 = master_key.derive_key_from_password_with_length(password, length=length, ctx=context, opslimit=opslimit)
    assert bytes(derived_key) == bytes(derived_key_2)
    # Check that the derived key is unique
    assert derived_key not in test_derive_key_from_password_with_length_set
    test_derive_key_from_password_with_length_set.add(bytes(derived_key))


def test_derive_key_from_password(master_key: cydrogen.MasterKey) -> None:
    key2 = master_key.derive_key_from_password(b"password")
    assert isinstance(key2, BaseKey)


def test_derive_none_password(master_key: cydrogen.MasterKey) -> None:
    with pytest.raises(ValueError):
        master_key.derive_key_from_password(None)  # type: ignore[arg-type]


def test_derive_empty_password(master_key: cydrogen.MasterKey) -> None:
    with pytest.raises(ValueError):
        master_key.derive_key_from_password(b"")


def test_derive_key_from_password_with_zero_length(master_key: cydrogen.MasterKey) -> None:
    with pytest.raises(ValueError):
        master_key.derive_key_from_password_with_length(b"password", length=0)


test_derive_subkey_with_length_set = set()


@pytest.mark.parametrize("subkey_id", [1, 2, 3])
@pytest.mark.parametrize("length", [32, 64, 128])
def test_derive_subkey_with_length(master_key: cydrogen.MasterKey, context: cydrogen.Context, subkey_id: int, length: int) -> None:
    if not master_key:
        # the special case of a zero master key is taken care of in the next test case test_derive_from_zero_master_key
        pytest.skip("Master key is zero, skipping subkey derivation tests.")
        return

    derived_key = master_key.derive_subkey_with_length(subkey_id, length=length, ctx=context)
    assert isinstance(derived_key, bytes)
    assert len(derived_key) == length
    assert derived_key != bytes(master_key)
    # Check that the derived key is deterministic
    derived_key_2 = master_key.derive_subkey_with_length(subkey_id, length=length, ctx=context)
    assert bytes(derived_key) == bytes(derived_key_2)
    # Check that the derived key is unique
    assert derived_key not in test_derive_subkey_with_length_set
    test_derive_subkey_with_length_set.add(bytes(derived_key))


def test_derive_from_zero_master_key() -> None:
    with pytest.raises(ValueError):
        cydrogen.MasterKey().derive_subkey_with_length(1, length=32)


def test_derive_subkey_with_zero_length() -> None:
    key = cydrogen.MasterKey(KEY_BYTES[0])
    with pytest.raises(ValueError):
        key.derive_subkey_with_length(1, length=0)


def test_derive_subkey_with_15_length() -> None:
    key = cydrogen.MasterKey(KEY_BYTES[0])
    with pytest.raises(ValueError):
        key.derive_subkey_with_length(1, length=15)


def test_derive_subkey_with_65536_length() -> None:
    key = cydrogen.MasterKey(KEY_BYTES[0])
    with pytest.raises(ValueError):
        key.derive_subkey_with_length(1, length=65536)


def test_derive_subkey(master_key: cydrogen.MasterKey, context: cydrogen.Context) -> None:
    if not master_key:
        pytest.skip("Master key is zero, skipping subkey derivation tests.")
        return
    key2 = master_key.derive_subkey(1, ctx=context)
    assert isinstance(key2, BaseKey)


def test_derive_sign_keypair(master_key: cydrogen.MasterKey) -> None:
    if not master_key:
        # the special case of a zero master key is taken care of in the next test case test_derive_sign_keypair_from_zero_masterkey
        pytest.skip("Master key is zero, skipping sign keypair derivation tests.")
        return
    key2 = master_key.derive_sign_keypair()
    assert isinstance(key2, cydrogen.SignKeyPair)
    key3 = master_key.derive_sign_keypair()
    assert isinstance(key3, cydrogen.SignKeyPair)
    assert bytes(key2) == bytes(key3)


def test_derive_sign_keypair_from_zero_masterkey() -> None:
    with pytest.raises(ValueError):
        cydrogen.MasterKey().derive_sign_keypair()


def test_derive_kx_keypair(master_key: cydrogen.MasterKey) -> None:
    if not master_key:
        # the special case of a zero master key is taken care of in the next test case test_derive_kx_keypair_from_zero_masterkey
        pytest.skip("Master key is zero, skipping KxPair derivation tests.")
        return
    key2 = master_key.derive_kx_keypair()
    assert isinstance(key2, cydrogen.KxPair)
    key3 = master_key.derive_kx_keypair()
    assert isinstance(key3, cydrogen.KxPair)
    assert key2 == key3


def test_derive_kx_keypair_from_zero_masterkey() -> None:
    with pytest.raises(ValueError):
        cydrogen.MasterKey().derive_kx_keypair()


test_hash_password_set = set()


@pytest.mark.parametrize("password", [b"password", b"password2"])
@pytest.mark.parametrize("opslimit", [1000, 10000, 100000])
def test_hash_password(master_key: cydrogen.MasterKey, password: bytes, opslimit: int) -> None:
    h = master_key.hash_password(password, opslimit=opslimit)
    assert isinstance(h, bytes)
    assert len(h) == 128
    # Check that the hash is unique
    assert h not in test_hash_password_set
    test_hash_password_set.add(h)


@pytest.mark.parametrize("password", [b"password", b"password2"])
@pytest.mark.parametrize("opslimit", [1000, 10000, 100000])
def test_verify_password(master_key: cydrogen.MasterKey, password: bytes, opslimit: int) -> None:
    h = master_key.hash_password(password, opslimit=opslimit)
    assert master_key.verify_password(password, h, opslimit=opslimit)
    assert not master_key.verify_password(b"wrongpassword", h, opslimit=opslimit)
    assert not master_key.verify_password(password, 128 * b"w", opslimit=opslimit)
