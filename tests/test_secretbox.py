import base64
import tempfile
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


def test_create_zero_sb_key():
    with pytest.raises(TypeError):
        cydrogen.SecretBoxKey()
    with pytest.raises(ValueError):
        cydrogen.SecretBoxKey(None)
    with pytest.raises(ValueError):
        cydrogen.SecretBoxKey(b"")


def test_create_sb_key_from_bytes():
    key = cydrogen.SecretBoxKey(KEY_BYTES)
    assert bytes(key) == KEY_BYTES
    assert bool(key)


def test_create_sb_key_from_str():
    key_str = base64.standard_b64encode(KEY_BYTES).decode("utf-8")
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


def test_sb_key_equality():
    key1 = cydrogen.SecretBoxKey(KEY_BYTES)
    key2 = cydrogen.SecretBoxKey(KEY_BYTES)
    key3 = cydrogen.SecretBoxKey.gen()
    assert key1 == key1
    assert key1 == key2
    assert key1 != key3


def test_sb_key_repr():
    key_str = base64.standard_b64encode(KEY_BYTES).decode("utf-8")
    key = cydrogen.SecretBoxKey(KEY_BYTES)
    assert repr(key) == f"SecretBoxKey({repr(key_str)})"


def test_convert_basekey_sb_key():
    key = BaseKey.gen()
    hk = cydrogen.SecretBoxKey(key)
    assert bytes(hk) == bytes(key)


def test_no_convert_sb_key_basekey():
    key = cydrogen.SecretBoxKey(KEY_BYTES)
    with pytest.raises(TypeError):
        BaseKey(key)


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


def test_secretbox_encrypt_decrypt():
    key = cydrogen.SecretBoxKey(KEY_BYTES)
    key2 = cydrogen.SecretBoxKey(KEY_BYTES_2)
    box = cydrogen.SecretBox(key)

    for msg in MESSAGES:
        # encrypt the message
        ciphertext = box.encrypt(msg, msg_id=3)
        enc_msg = cydrogen.EncryptedMessage(ciphertext, msg_id=3)

        # decrypt the message passing explicitly the right msg_id
        decrypted_msg = box.decrypt(ciphertext, msg_id=3)
        assert decrypted_msg == msg
        decrypted_msg = box.decrypt(enc_msg.ciphertext, msg_id=3)
        assert decrypted_msg == msg
        # decrypt the message as EncryptedMessage (without passing explicitly the msg_id)
        decrypted_msg = box.decrypt(enc_msg)
        assert decrypted_msg == msg
        # decrypt the message as EncryptedMessage (passing explicitly the msg_id)
        decrypted_msg = box.decrypt(enc_msg, msg_id=3)
        assert decrypted_msg == msg
        # decrypt the message directly from the encrypted message object
        decrypted_msg = enc_msg.decrypt(key)
        assert decrypted_msg == msg
        # try to decrypt the message with a different msg_id (should fail)
        with pytest.raises(cydrogen.DecryptException):
            box.decrypt(ciphertext, msg_id=4)
        with pytest.raises(cydrogen.DecryptException):
            box.decrypt(ciphertext)
        with pytest.raises(cydrogen.DecryptException):
            box.decrypt(enc_msg, msg_id=4)
        # try to decrypt the message with a different key (should fail)
        with pytest.raises(cydrogen.DecryptException):
            enc_msg.decrypt(key2)
        # try to decrypt the message with a different context (should fail)
        with pytest.raises(cydrogen.DecryptException):
            enc_msg.decrypt(key, ctx=b"EXAMPLES")
        # try to decrypt the message serialized as a frame (should fail)
        with pytest.raises(cydrogen.DecryptException):
            box.decrypt(bytes(enc_msg), msg_id=3)


def test_serialize_encrypted_message():
    key = cydrogen.SecretBoxKey(KEY_BYTES)
    sb = cydrogen.SecretBox(key)
    msg_ids = [1, 2, 3]

    for msg, msg_id in product(MESSAGES, msg_ids):
        # encrypt the message
        ciphertext = sb.encrypt(msg, msg_id=msg_id)
        enc_msg = cydrogen.EncryptedMessage(ciphertext, msg_id=msg_id)
        # serialize the ciphertext
        serialized = bytes(enc_msg)
        assert isinstance(serialized, bytes)
        # deserialize the ciphertext
        deserialized = cydrogen.EncryptedMessage.from_bytes(serialized)
        assert isinstance(deserialized, cydrogen.EncryptedMessage)
        assert deserialized == enc_msg


def test_encrypt_decrypt_file():
    buf = cydrogen.gen_random_buffer(100000)
    key = cydrogen.SecretBoxKey(KEY_BYTES)
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
