import asyncio
import base64
import io
import tempfile
from collections.abc import Buffer

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


def test_create_zero_sb_key() -> None:
    with pytest.raises(TypeError):
        cydrogen.SecretBoxKey()  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        cydrogen.SecretBoxKey(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        cydrogen.SecretBoxKey(b"")


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_create_sb_key_from_bytes(key_bytes: bytes) -> None:
    key = cydrogen.SecretBoxKey(key_bytes)
    assert bytes(key) == key_bytes
    assert bool(key)


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_create_sb_key_from_str(key_bytes: bytes) -> None:
    key_str = base64.standard_b64encode(key_bytes).decode("utf-8")
    key = cydrogen.SecretBoxKey(key_str)
    assert str(key) == key_str
    assert bool(key)


def test_gen_sb_key():
    key = cydrogen.SecretBoxKey.gen()
    assert bool(key)
    assert len(bytes(key)) == 32


def test_copy_sb_key():
    key1 = cydrogen.SecretBoxKey.gen()
    key2 = cydrogen.SecretBoxKey(key1)
    assert bytes(key1) == bytes(key2)
    assert key1 == key2


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_sb_key_equality(key_bytes: bytes) -> None:
    key1 = cydrogen.SecretBoxKey(key_bytes)
    key2 = cydrogen.SecretBoxKey(key_bytes)
    key3 = cydrogen.SecretBoxKey.gen()
    assert key1 == key1  # noqa: PLR0124
    assert key1 == key2
    assert key1 != key3


@pytest.mark.parametrize("key_bytes", KEY_BYTES)
def test_sb_key_repr(key_bytes: bytes) -> None:
    key_str = base64.standard_b64encode(key_bytes).decode("utf-8")
    key = cydrogen.SecretBoxKey(key_bytes)
    assert repr(key) == f"SecretBoxKey({key_str!r})"


def test_convert_basekey_sb_key() -> None:
    key = BaseKey.gen()
    hk = cydrogen.SecretBoxKey(key)
    assert bytes(hk) == bytes(key)


def test_no_convert_sb_key_basekey() -> None:
    key = cydrogen.SecretBoxKey(KEY_BYTES[0])
    with pytest.raises(TypeError):
        BaseKey(key)  # type: ignore[arg-type]


def test_sb_key_from_password():
    password = b"correct horse battery staple"
    key = cydrogen.SecretBoxKey.from_password(password)
    assert bool(key)
    key2 = cydrogen.SecretBoxKey.from_password(password, ctx=b"EXAMPLES")
    assert bool(key2)
    assert key != key2
    mk = cydrogen.MasterKey.gen()
    key3 = cydrogen.SecretBoxKey.from_password(password, master_key=mk)
    assert bool(key3)
    assert key3 != key


@pytest.fixture(params=KEY_BYTES)
def secretbox_key(request: pytest.FixtureRequest) -> cydrogen.SecretBoxKey:
    return cydrogen.SecretBoxKey(request.param)


@pytest.mark.parametrize("message", MESSAGES)
def test_secretbox_encrypt_decrypt(secretbox_key: cydrogen.SecretBoxKey, message: bytes) -> None:
    box = cydrogen.SecretBox(secretbox_key)
    key2 = cydrogen.SecretBoxKey.gen()

    # encrypt the message
    ciphertext = box.encrypt(message, msg_id=3)
    enc_msg = cydrogen.EncryptedMessage(ciphertext, msg_id=3)

    # decrypt the message passing explicitly the right msg_id
    decrypted_msg = box.decrypt(ciphertext, msg_id=3)
    assert decrypted_msg == message
    decrypted_msg = box.decrypt(enc_msg.ciphertext, msg_id=3)
    assert decrypted_msg == message
    # decrypt the message as EncryptedMessage (without passing explicitly the msg_id)
    decrypted_msg = box.decrypt(enc_msg)
    assert decrypted_msg == message
    # decrypt the message as EncryptedMessage (passing explicitly the msg_id)
    decrypted_msg = box.decrypt(enc_msg, msg_id=3)
    assert decrypted_msg == message
    # try to decrypt the message with a different msg_id (should fail)
    with pytest.raises(cydrogen.DecryptException):
        box.decrypt(ciphertext, msg_id=4)
    with pytest.raises(cydrogen.DecryptException):
        box.decrypt(ciphertext)
    with pytest.raises(cydrogen.DecryptException):
        box.decrypt(enc_msg, msg_id=4)
    # try to decrypt the message with a different key (should fail)
    box2 = cydrogen.SecretBox(key2)
    with pytest.raises(cydrogen.DecryptException):
        box2.decrypt(enc_msg)
    # try to decrypt the message with a different context (should fail)
    box3 = cydrogen.SecretBox(secretbox_key, ctx=b"EXAMPLES")
    with pytest.raises(cydrogen.DecryptException):
        box3.decrypt(enc_msg)
    # try to decrypt the message serialized as a frame (should fail)
    with pytest.raises(cydrogen.DecryptException):
        box.decrypt(bytes(enc_msg), msg_id=3)


@pytest.mark.parametrize(("message", "msg_id"), [(MESSAGES[0], 1), (MESSAGES[1], 2), (MESSAGES[2], 3)])
def test_serialize_encrypted_message(secretbox_key: cydrogen.SecretBoxKey, message: bytes, msg_id: int) -> None:
    box = cydrogen.SecretBox(secretbox_key)
    # encrypt the message
    ciphertext = box.encrypt(message, msg_id=msg_id)
    enc_msg = cydrogen.EncryptedMessage(ciphertext, msg_id=msg_id)
    # serialize the ciphertext
    serialized = bytes(enc_msg)
    assert isinstance(serialized, bytes)
    # deserialize the ciphertext
    deserialized = cydrogen.EncryptedMessage.from_bytes(serialized)
    assert isinstance(deserialized, cydrogen.EncryptedMessage)
    assert deserialized == enc_msg


@pytest.mark.parametrize(("message", "msg_id"), [(MESSAGES[0], 1), (MESSAGES[1], 2), (MESSAGES[2], 3)])
def test_encrypted_message_writeto(secretbox_key: cydrogen.SecretBoxKey, message: bytes, msg_id: int) -> None:
    box = cydrogen.SecretBox(secretbox_key)
    ciphertext = box.encrypt(message, msg_id=msg_id)
    enc_msg = cydrogen.EncryptedMessage(ciphertext, msg_id=msg_id)
    buf = io.BytesIO()
    enc_msg.writeto(buf)
    assert bytes(enc_msg) == buf.getvalue()


class AsyncBytesIOWriter:
    def __init__(self) -> None:
        self.b = io.BytesIO()

    def write(self, data: Buffer):
        self.b.write(data)

    async def drain(self) -> None:
        # Simulate async behavior
        await asyncio.sleep(0)

    def getvalue(self) -> bytes:
        return self.b.getvalue()


@pytest.mark.asyncio(loop_scope="module")
@pytest.mark.parametrize(("message", "msg_id"), [(MESSAGES[0], 1), (MESSAGES[1], 2), (MESSAGES[2], 3)])
async def test_encrypted_message_awriteto(secretbox_key: cydrogen.SecretBoxKey, message: bytes, msg_id: int) -> None:
    box = cydrogen.SecretBox(secretbox_key)
    ciphertext = box.encrypt(message, msg_id=msg_id)
    enc_msg = cydrogen.EncryptedMessage(ciphertext, msg_id=msg_id)
    buf = AsyncBytesIOWriter()
    await enc_msg.awriteto(buf)
    assert bytes(enc_msg) == buf.getvalue()


def test_encrypted_message_equals() -> None:
    msg = cydrogen.EncryptedMessage(b"blabla", msg_id=1)
    msg2 = cydrogen.EncryptedMessage(b"blabla", msg_id=1)
    assert msg == msg2
    msg3 = cydrogen.EncryptedMessage(b"blabla", msg_id=2)
    assert msg != msg3
    msg4 = cydrogen.EncryptedMessage(b"blabla2", msg_id=1)
    assert msg != msg4
    msg5 = cydrogen.EncryptedMessage(b"blabla2", msg_id=2)
    assert msg != msg5
    msg6 = cydrogen.EncryptedMessage(b"blabla", msg_id=1, session_keys_idx=1)
    assert msg != msg6


class AsyncBytesIOReader:
    def __init__(self, data: Buffer) -> None:
        self.b = io.BytesIO(data)

    async def read(self, length: int = -1) -> bytes:  # noqa: ARG002
        # Simulate async behavior
        await asyncio.sleep(0)
        # we read byte by byte to check that we will handle a full read correctly
        return self.b.read(1)


def test_encrypt_decrypt_file() -> None:
    buf = cydrogen.gen_random_buffer(100000)
    key = cydrogen.SecretBoxKey(KEY_BYTES[0])
    box = cydrogen.SecretBox(key)

    with tempfile.TemporaryFile() as fobj_plain, tempfile.TemporaryFile() as fobj_enc, tempfile.TemporaryFile() as fobj_dec:
        # write our plain text file
        fobj_plain.write(buf)
        fobj_plain.flush()
        fobj_plain.seek(0)

        # encrypt the file
        box.encrypt_file(fobj_plain, fobj_enc)
        fobj_enc.flush()
        fobj_enc.seek(0)
        fobj_plain.seek(0)

        # decrypt the file
        box.decrypt_file(fobj_enc, fobj_dec)
        fobj_dec.flush()
        fobj_dec.seek(0)
        fobj_enc.seek(0)

        # check that the decrypted file is the same as the original
        assert fobj_dec.read() == fobj_plain.read()
