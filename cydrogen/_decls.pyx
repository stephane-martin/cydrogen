# cython: language_level=3

cdef ctx_memzero(char ctx[hydro_hash_CONTEXTBYTES]):
    hydro_memzero(&ctx[0], hydro_hash_CONTEXTBYTES)


cdef basekey_memzero(uint8_t* key):
    hydro_memzero(key, hydro_hash_KEYBYTES)


cdef pk_memzero(uint8_t* key):
    hydro_memzero(key, hydro_sign_PUBLICKEYBYTES)


cdef sk_memzero(uint8_t* key):
    hydro_memzero(key, hydro_sign_SECRETKEYBYTES)


cdef keys_equal(const unsigned char[:] key1, const unsigned char[:] key2):
    if key1 is None and key2 is None:
        return True
    if key1 is None and key2 is not None:
        return False
    if key1 is not None and key2 is None:
        return False
    if len(key1) != len(key2):
        return False
    cdef size_t lenk = len(key1)
    return hydro_equal(&key1[0], &key2[0], lenk) == 1


cdef hash_init(hydro_hash_state *state, const unsigned char[:] ctx, const unsigned char[:] key):
    if len(ctx) < hydro_hash_CONTEXTBYTES:
        raise ValueError("Context must be 8 bytes long")
    if len(key) < hydro_hash_KEYBYTES:
        raise ValueError("Key must be 32 bytes long")
    cdef int res = hydro_hash_init(state, <char*>(&ctx[0]), &key[0])
    if res != 0:
        raise RuntimeError("Failed to initialize hash state")


cdef hash_update(hydro_hash_state *state, const unsigned char[:] data):
    cdef size_t in_len = len(data)
    if in_len == 0:
        return 0
    cdef int res = hydro_hash_update(state, &data[0], in_len)
    if res != 0:
        raise RuntimeError("Failed to update hash state")


cdef hash_final(hydro_hash_state *state, unsigned char[:] out):
    cdef size_t out_len = len(out)
    if out_len < hydro_hash_BYTES_MIN or out_len > hydro_hash_BYTES_MAX:
        raise ValueError("Hash length must be between 16 and 65535 bytes")
    cdef int res = hydro_hash_final(state, &out[0], out_len)
    if res != 0:
        raise RuntimeError("Failed to finalize hash state")

cdef secretbox_encrypt(
        const unsigned char[:] plaintext,
        uint64_t msg_id,
        const unsigned char[:] ctx,
        const unsigned char[:] key,
        unsigned char[:] ciphertext):

    if len(ctx) < hydro_secretbox_CONTEXTBYTES:
        raise ValueError("Context must be 8 bytes long")
    if len(key) < hydro_secretbox_KEYBYTES:
        raise ValueError("Key must be 32 bytes long")
    if len(plaintext) == 0:
        raise ValueError("Plaintext cannot be empty")
    cdef size_t plaintext_len = len(plaintext)
    cdef size_t ciphertext_len = plaintext_len + hydro_secretbox_HEADERBYTES
    if len(ciphertext) < ciphertext_len:
        raise ValueError("Ciphertext buffer is too small")
    cdef int res = hydro_secretbox_encrypt(&ciphertext[0], &plaintext[0], plaintext_len, msg_id, <char*>(&ctx[0]), &key[0])
    if res != 0:
        raise RuntimeError("Failed to encrypt message")


cdef secretbox_decrypt(
        const unsigned char[:] ciphertext,
        uint64_t msg_id,
        const unsigned char[:] ctx,
        const unsigned char[:] key,
        unsigned char[:] plaintext):

    if len(ctx) < hydro_secretbox_CONTEXTBYTES:
        raise ValueError("Context must be 8 bytes long")
    if len(key) < hydro_secretbox_KEYBYTES:
        raise ValueError("Key must be 32 bytes long")
    cdef size_t ciphertext_len = len(ciphertext)
    if ciphertext_len < hydro_secretbox_HEADERBYTES:
        raise ValueError("Ciphertext is too short")
    cdef size_t plaintext_len = ciphertext_len - hydro_secretbox_HEADERBYTES
    if len(plaintext) < plaintext_len:
        raise ValueError("Plaintext buffer is too small")
    cdef int res = hydro_secretbox_decrypt(&plaintext[0], &ciphertext[0], ciphertext_len, msg_id, <char*>(&ctx[0]), &key[0])
    if res != 0:
        raise RuntimeError("Failed to decrypt message")


cdef pwhash_deterministic(
        const unsigned char[:] password,
        const unsigned char[:] ctx,
        const unsigned char[:] master_key,
        uint64_t opslimit,
        unsigned char[:] derived_key):

    if len(ctx) < hydro_pwhash_CONTEXTBYTES:
        raise ValueError("Context must be 8 bytes long")
    if len(master_key) < hydro_pwhash_MASTERKEYBYTES:
        raise ValueError("Master key must be 32 bytes long")
    cdef size_t pwdlen = len(password)
    if pwdlen == 0:
        raise ValueError("Password cannot be empty")
    cdef size_t dk_len = len(derived_key)
    if dk_len == 0:
        raise ValueError("Derived key length cannot be 0")
    cdef const char* password_ptr = <const char*>(&password[0])
    cdef const char* ctx_ptr = <const char*>(&ctx[0])
    cdef const uint8_t* master_key_ptr = <const uint8_t*>(&master_key[0])
    cdef uint8_t* derived_key_ptr = <uint8_t*>(&derived_key[0])
    cdef int res

    with nogil:
        res = hydro_pwhash_deterministic(
            derived_key_ptr, dk_len,
            password_ptr, pwdlen,
            ctx_ptr,
            master_key_ptr,
            opslimit, 0, 1)
    if res != 0:
        raise RuntimeError("Failed to derive key from password")


cdef kdf_derive_from_key(
        const unsigned char[:] master_key,
        uint64_t subkey_id,
        const unsigned char[:] ctx,
        unsigned char[:] subkey):

    cdef size_t subkey_len = len(subkey)
    if subkey_len < hydro_kdf_BYTES_MIN or subkey_len > hydro_kdf_BYTES_MAX:
        raise ValueError("Subkey length must be between 16 and 65535 bytes")
    if len(ctx) < hydro_kdf_CONTEXTBYTES:
        raise ValueError("Context must be 8 bytes long")
    if len(master_key) < hydro_kdf_KEYBYTES:
        raise ValueError("Master key must be 32 bytes long")
    cdef const char* ctx_ptr = <const char*>(&ctx[0])
    cdef const uint8_t* master_key_ptr = <const uint8_t*>(&master_key[0])
    cdef uint8_t* subkey_ptr = <uint8_t*>(&subkey[0])
    cdef int res = hydro_kdf_derive_from_key(subkey_ptr, subkey_len, subkey_id, ctx_ptr, master_key_ptr)
    if res != 0:
        raise RuntimeError("Failed to derive subkey from master key")


cdef pwhash_create(
        const unsigned char[:] password,
        const unsigned char[:] master_key,
        uint64_t opslimit,
        unsigned char[:] stored):

    cdef size_t pwdlen = len(password)
    if pwdlen == 0:
        raise ValueError("Password cannot be empty")
    if len(master_key) < hydro_pwhash_MASTERKEYBYTES:
        raise ValueError("Master key must be 32 bytes long")
    if len(stored) < hydro_pwhash_STOREDBYTES:
        raise ValueError(f"Stored buffer must be {hydro_pwhash_STOREDBYTES} bytes long")
    cdef const char* password_ptr = <const char*>(&password[0])
    cdef const uint8_t* master_key_ptr = <const uint8_t*>(&master_key[0])
    cdef uint8_t* stored_ptr = <uint8_t*>(&stored[0])
    cdef int res

    with nogil:
        res = hydro_pwhash_create(stored_ptr, password_ptr, pwdlen, master_key_ptr, opslimit, 0, 1)
    if res != 0:
        raise RuntimeError("Failed to create password hash")

cdef pwhash_verify(
        const unsigned char[:] stored,
        const unsigned char[:] password,
        const unsigned char[:] master_key,
        uint64_t opslimit_max):

    cdef size_t pwdlen = len(password)
    if pwdlen == 0:
        raise ValueError("Password cannot be empty")
    if len(stored) < hydro_pwhash_STOREDBYTES:
        raise ValueError(f"Stored buffer must be {hydro_pwhash_STOREDBYTES} bytes long")
    if len(master_key) < hydro_pwhash_MASTERKEYBYTES:
        raise ValueError(f"Master key must be {hydro_pwhash_MASTERKEYBYTES} bytes long")
    cdef const uint8_t* stored_ptr = <const uint8_t*>(&stored[0])
    cdef const char* password_ptr = <const char*>(&password[0])
    cdef const uint8_t* master_key_ptr = <const uint8_t*>(&master_key[0])
    cdef int res

    with nogil:
        res = hydro_pwhash_verify(stored_ptr, password_ptr, pwdlen, master_key_ptr, opslimit_max, 0, 1)
    return res == 0

cdef sign_keygen_deterministic(const unsigned char[:] master_key):
    if len(master_key) < hydro_random_SEEDBYTES:
        raise ValueError(f"Master key must be {hydro_random_SEEDBYTES} bytes long")
    cdef hydro_sign_keypair kp
    cdef const uint8_t* seed_ptr = <const uint8_t*>(&master_key[0])
    hydro_sign_keygen_deterministic(&kp, seed_ptr)
    cdef bytes secret_key = kp.sk[:hydro_sign_SECRETKEYBYTES]
    return secret_key


cdef sign_keygen():
    cdef hydro_sign_keypair kp
    hydro_sign_keygen(&kp)
    cdef bytes secret_key = kp.sk[:hydro_sign_SECRETKEYBYTES]
    return secret_key


cdef sign_init(hydro_sign_state *state, const unsigned char[:] ctx):
    if len(ctx) < hydro_sign_CONTEXTBYTES:
        raise ValueError("Context must be 8 bytes long")
    cdef int res = hydro_sign_init(state, <char*>(&ctx[0]))
    if res != 0:
        raise RuntimeError("Failed to initialize sign state")


cdef sign_update(hydro_sign_state *state, const unsigned char[:] data):
    if len(data) == 0:
        return
    cdef size_t in_len = len(data)
    cdef int res = hydro_sign_update(state, &data[0], in_len)
    if res != 0:
        raise RuntimeError("Failed to update sign state")


cdef sign_final_create(hydro_sign_state *state, const unsigned char[:] sk, unsigned char[:] signature):
    if len(sk) < hydro_sign_SECRETKEYBYTES:
        raise ValueError(f"Secret key must be {hydro_sign_SECRETKEYBYTES} bytes long")
    if len(signature) < hydro_sign_BYTES:
        raise ValueError(f"Signature buffer must be {hydro_sign_BYTES} bytes long")
    cdef int res = hydro_sign_final_create(state, &signature[0], &sk[0])
    if res != 0:
        raise RuntimeError("Failed to finalize sign state for creation")


cdef sign_final_verify(hydro_sign_state *state, const unsigned char[:] pk, const unsigned char[:] signature):
    if len(pk) < hydro_sign_PUBLICKEYBYTES:
        raise ValueError(f"Public key must be {hydro_sign_PUBLICKEYBYTES} bytes long")
    if len(signature) < hydro_sign_BYTES:
        raise ValueError(f"Signature must be {hydro_sign_BYTES} bytes long")
    cdef int res = hydro_sign_final_verify(state, &signature[0], &pk[0])
    if res != 0:
        raise RuntimeError("Failed to finalize sign state for verification")


cdef _pad(unsigned char[:] buf, size_t unpadded_buflen, size_t blocksize):
    cdef int padded_length = hydro_pad(&buf[0], unpadded_buflen, blocksize, len(buf))
    if padded_length == -1:
        raise ValueError("Buffer is too small for padding")
    return padded_length


cpdef pad(const unsigned char[:] buf, size_t blocksize=8192):
    if buf is None:
        raise ValueError("Buffer cannot be None")
    if blocksize < 1:
        raise ValueError("Block size must be at least 1 byte")
    cdef size_t unpadded_length = len(buf)
    cdef size_t padded_length = unpadded_length + (blocksize - (unpadded_length % blocksize))
    cdef bytearray new_buf = bytearray(padded_length)
    cdef unsigned char[:] new_buf_view = new_buf
    new_buf_view[0:unpadded_length] = buf[0:unpadded_length]
    del new_buf_view
    cdef int length = _pad(new_buf, unpadded_length, blocksize)
    return bytes(new_buf[0:length])


cpdef unpad(const unsigned char[:] buf, size_t blocksize=8192):
    if buf is None:
        raise ValueError("Buffer cannot be None")
    if blocksize < 1:
        raise ValueError("Block size must be at least 1 byte")
    cdef int unpadded_length = hydro_unpad(&buf[0], len(buf), blocksize)
    if unpadded_length == -1:
        raise ValueError("Buffer is not padded correctly")
    return bytes(buf[0:unpadded_length])


def hynit():
    if hydro_init() != 0:
        raise RuntimeError("Failed to initialize libhydrogen")


cpdef random_u32():
    return hydro_random_u32()


cpdef random_uniform(uint32_t upper_bound):
    return hydro_random_uniform(upper_bound)


cpdef randomize_buffer(unsigned char[:] buf):
    if buf is None:
        raise ValueError("Buffer cannot be None")
    hydro_random_buf(<void*>&buf[0], len(buf))


cpdef gen_random_buffer(size_t size):
    if size == 0:
        return bytes()
    cdef bytearray buf = bytearray(size)
    randomize_buffer(buf)
    return bytes(buf)


cpdef shuffle_buffer(unsigned char[:] buf):
    if buf is None:
        raise ValueError("Buffer cannot be None")
    cdef uint32_t n = len(buf)
    if n == 0 or n == 1:
        return
    if n == 2:
        buf[0], buf[1] = buf[1], buf[0]
        return
    cdef uint32_t i, j
    for i in range(n - 1, 0, -1):
        j = random_uniform(i + 1)
        buf[i], buf[j] = buf[j], buf[i]
