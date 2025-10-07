import pathlib

import pytest
from cydrogen import SecretBoxKey
from cydrogen.exceptions import DecryptException


def test_decrypt_file_with_appended_data(tmp_path: pathlib.Path):
    """
    Tests that decryption fails if extra data is appended to the ciphertext.
    This verifies ciphertext integrity.
    """
    key: SecretBoxKey = SecretBoxKey.gen()
    sbox = key.secretbox()

    plaintext_path = tmp_path / "plaintext.txt"
    plaintext_path.write_bytes(b"test data")

    encrypted_path = tmp_path / "encrypted.bin"
    decrypted_path = tmp_path / "decrypted.txt"

    # Encrypt the original file
    sbox.encrypt_file(str(plaintext_path), str(encrypted_path))

    # Tamper with the encrypted file by appending garbage data
    with encrypted_path.open("ab") as f:
        f.write(b"garbage data")

    # Expect the decryption to fail with a DecryptException
    with pytest.raises(DecryptException):
        sbox.decrypt_file(str(encrypted_path), str(decrypted_path))
