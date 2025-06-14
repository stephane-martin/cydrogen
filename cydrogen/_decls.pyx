# cython: language_level=3

from cpython.buffer cimport PyBUF_READ
from cpython.memoryview cimport PyMemoryView_FromMemory

from ._utils cimport SafeMemory

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
    cdef int res = hydro_hash_init(state, <const char*>(&ctx[0]), &key[0])
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
    cdef int res = hydro_secretbox_encrypt(&ciphertext[0], &plaintext[0], plaintext_len, msg_id, <const char*>(&ctx[0]), &key[0])
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
    cdef int res = hydro_secretbox_decrypt(&plaintext[0], &ciphertext[0], ciphertext_len, msg_id, <const char*>(&ctx[0]), &key[0])
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


cdef sign_keygen():
    cdef SafeMemory kp_mem = SafeMemory(sizeof(hydro_sign_keypair))
    cdef hydro_sign_keypair* kp_ptr = <hydro_sign_keypair*>(kp_mem.ptr)
    hydro_sign_keygen(kp_ptr)
    return SafeMemory.from_buffer(PyMemoryView_FromMemory(<char*>(kp_ptr.sk), hydro_sign_SECRETKEYBYTES, PyBUF_READ))


cdef sign_keygen_deterministic(const unsigned char[:] master_key):
    if len(master_key) < hydro_random_SEEDBYTES:
        raise ValueError(f"Master key must be {hydro_random_SEEDBYTES} bytes long")
    cdef SafeMemory kp_mem = SafeMemory(sizeof(hydro_sign_keypair))
    cdef hydro_sign_keypair* kp_ptr = <hydro_sign_keypair*>(kp_mem.ptr)
    hydro_sign_keygen_deterministic(kp_ptr, &master_key[0])
    return SafeMemory.from_buffer(PyMemoryView_FromMemory(<char*>(kp_ptr.sk), hydro_sign_SECRETKEYBYTES, PyBUF_READ))


cdef kx_keygen():
    cdef SafeMemory kp_mem = SafeMemory(sizeof(hydro_kx_keypair))
    cdef hydro_kx_keypair* kp_ptr = <hydro_kx_keypair*>(kp_mem.ptr)
    hydro_kx_keygen(kp_ptr)
    kp_mem.mark_readonly()
    return kp_mem


cdef kx_keygen_deterministic(const unsigned char[:] master_key):
    if len(master_key) < hydro_kx_SEEDBYTES:
        raise ValueError(f"Master key must be {hydro_kx_SEEDBYTES} bytes long")
    cdef SafeMemory kp_mem = SafeMemory(sizeof(hydro_kx_keypair))
    cdef hydro_kx_keypair* kp_ptr = <hydro_kx_keypair*>(kp_mem.ptr)
    hydro_kx_keygen_deterministic(kp_ptr, &master_key[0])
    kp_mem.mark_readonly()
    return kp_mem


cdef sign_init(hydro_sign_state *state, const unsigned char[:] ctx):
    if len(ctx) < hydro_sign_CONTEXTBYTES:
        raise ValueError("Context must be 8 bytes long")
    cdef int res = hydro_sign_init(state, <const char*>(&ctx[0]))
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


cpdef uint32_t random_u32() noexcept nogil:
    return hydro_random_u32()


cpdef uint32_t random_uniform(uint32_t upper_bound) noexcept nogil:
    return hydro_random_uniform(upper_bound)


cdef random_buf_deterministic(unsigned char[:] buf, const unsigned char[:] seed):
    if len(seed) < hydro_random_SEEDBYTES:
        raise ValueError(f"Seed must be {hydro_random_SEEDBYTES} bytes long")
    if len(buf) == 0:
        return
    hydro_random_buf_deterministic(<void*>&buf[0], len(buf), <const uint8_t*>(&seed[0]))


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
    cdef uint32_t i, j
    for i in range(n - 1, 0, -1):
        j = random_uniform(i + 1)
        buf[i], buf[j] = buf[j], buf[i]

cdef kx_n_1(const unsigned char[:] server_public_key, const unsigned char[:] psk):
    if server_public_key is None:
        raise ValueError("Peer public key cannot be None")
    if len(server_public_key) != hydro_kx_PUBLICKEYBYTES:
        raise ValueError(f"Peer public key must be {hydro_kx_PUBLICKEYBYTES} bytes long")
    if psk is not None and len(psk) != hydro_kx_PSKBYTES:
        raise ValueError(f"PSK must be {hydro_kx_PSKBYTES} bytes long")
    # we will store the generate session keypair in 'session'
    cdef SafeMemory session = SafeMemory(sizeof(hydro_kx_session_keypair))
    cdef hydro_kx_session_keypair* kp_ptr = <hydro_kx_session_keypair*>(session.ptr)
    # we will store the generated packet in 'packet1'
    cdef bytearray packet1 = bytearray(hydro_kx_N_PACKET1BYTES)
    cdef uint8_t* packet1_ptr = packet1
    # pointer to the optional psk
    cdef const uint8_t* psk_ptr = NULL
    if psk is not None:
        psk_ptr = &psk[0]
    # pointer to the peer public key
    cdef const uint8_t* peer_ptr = &server_public_key[0]

    # generate the session keypair and packet1
    cdef int ret = hydro_kx_n_1(kp_ptr, packet1_ptr, psk_ptr, peer_ptr)
    if ret != 0:
        raise RuntimeError("Failed to generate packet1 for key exchange")

    rx = SafeMemory.from_buffer(PyMemoryView_FromMemory(<char*>(kp_ptr.rx), hydro_kx_SESSIONKEYBYTES, PyBUF_READ))
    tx = SafeMemory.from_buffer(PyMemoryView_FromMemory(<char*>(kp_ptr.tx), hydro_kx_SESSIONKEYBYTES, PyBUF_READ))
    return rx, tx, bytes(packet1)


cdef kx_n_2(const unsigned char[:] packet1, const unsigned char[:] psk, const unsigned char[:] static_kp):
    if packet1 is None:
        raise ValueError("Packet1 cannot be None")
    if len(packet1) != hydro_kx_N_PACKET1BYTES:
        raise ValueError(f"Packet1 must be {hydro_kx_N_PACKET1BYTES} bytes long")
    if psk is not None and len(psk) != hydro_kx_PSKBYTES:
        raise ValueError(f"PSK must be {hydro_kx_PSKBYTES} bytes long")
    if static_kp is None:
        raise ValueError("Static keypair cannot be None")
    if len(static_kp) != sizeof(hydro_kx_keypair):
        raise ValueError("Static keypair must be {} bytes long".format(sizeof(hydro_kx_keypair)))
    # we will store the generate session keypair in 'session'
    cdef SafeMemory session = SafeMemory(sizeof(hydro_kx_session_keypair))
    cdef hydro_kx_session_keypair* session_ptr = <hydro_kx_session_keypair*>(session.ptr)
    # pointer to the optional psk
    cdef const uint8_t* psk_ptr = NULL
    if psk is not None:
        psk_ptr = &psk[0]
    # pointer to the static keypair
    cdef const hydro_kx_keypair* static_kp_ptr = <const hydro_kx_keypair*>(<const void*>(&static_kp[0]))
    # pointer to the packet1
    cdef const uint8_t* packet1_ptr = &packet1[0]
    # generate the session keypair
    cdef int ret = hydro_kx_n_2(session_ptr, packet1_ptr, psk_ptr, static_kp_ptr)
    if ret != 0:
        raise RuntimeError("Failed to generate session keypair from packet1")
    rx = SafeMemory.from_buffer(PyMemoryView_FromMemory(<char*>(session_ptr.rx), hydro_kx_SESSIONKEYBYTES, PyBUF_READ))
    tx = SafeMemory.from_buffer(PyMemoryView_FromMemory(<char*>(session_ptr.tx), hydro_kx_SESSIONKEYBYTES, PyBUF_READ))
    return rx, tx


cdef kx_kk_1(hydro_kx_state* state, const unsigned char[:] server_public_key, const unsigned char[:] client_kp):
    if server_public_key is None:
        raise ValueError("Peer public key cannot be None")
    if len(server_public_key) != hydro_kx_PUBLICKEYBYTES:
        raise ValueError(f"Peer public key must be {hydro_kx_PUBLICKEYBYTES} bytes long")
    if client_kp is None:
        raise ValueError("Client keypair cannot be None")
    if len(client_kp) != sizeof(hydro_kx_keypair):
        raise ValueError("Client keypair must be {} bytes long".format(sizeof(hydro_kx_keypair)))

    cdef bytearray packet1 = bytearray(hydro_kx_KK_PACKET1BYTES)
    cdef uint8_t* packet1_ptr = packet1
    cdef const uint8_t* peer_ptr = &server_public_key[0]
    cdef const hydro_kx_keypair* static_kp_ptr = <const hydro_kx_keypair*>(<const void*>(&client_kp[0]))

    cdef int ret = hydro_kx_kk_1(state, packet1_ptr, peer_ptr, static_kp_ptr)
    if ret != 0:
        raise RuntimeError("Failed to generate packet1 for key exchange kk")

    return bytes(packet1)


cdef kx_kk_2(const unsigned char[:] packet1, const unsigned char[:] client_public_key, const unsigned char[:] server_kp):
    if packet1 is None:
        raise ValueError("Packet1 cannot be None")
    if len(packet1) != hydro_kx_KK_PACKET1BYTES:
        raise ValueError(f"Packet1 must be {hydro_kx_KK_PACKET1BYTES} bytes long")
    if client_public_key is None:
        raise ValueError("Client public key cannot be None")
    if len(client_public_key) != hydro_kx_PUBLICKEYBYTES:
        raise ValueError(f"Client public key must be {hydro_kx_PUBLICKEYBYTES} bytes long")
    if server_kp is None:
        raise ValueError("Server keypair cannot be None")
    if len(server_kp) != sizeof(hydro_kx_keypair):
        raise ValueError("Server keypair must be {} bytes long".format(sizeof(hydro_kx_keypair)))

    cdef SafeMemory session = SafeMemory(sizeof(hydro_kx_session_keypair))
    cdef hydro_kx_session_keypair* session_ptr = <hydro_kx_session_keypair*>(session.ptr)
    cdef bytearray packet2 = bytearray(hydro_kx_KK_PACKET2BYTES)
    cdef uint8_t* packet2_ptr = packet2
    cdef const uint8_t* packet1_ptr = &packet1[0]
    cdef const uint8_t* peer_pk_ptr = &client_public_key[0]
    cdef const hydro_kx_keypair* static_kp_ptr = <const hydro_kx_keypair*>(<const void*>(&server_kp[0]))

    cdef int ret = hydro_kx_kk_2(session_ptr, packet2_ptr, packet1_ptr, peer_pk_ptr, static_kp_ptr)
    if ret != 0:
        raise RuntimeError("Failed to generate packet2 for key exchange kk")

    rx = SafeMemory.from_buffer(PyMemoryView_FromMemory(<char*>(session_ptr.rx), hydro_kx_SESSIONKEYBYTES, PyBUF_READ))
    tx = SafeMemory.from_buffer(PyMemoryView_FromMemory(<char*>(session_ptr.tx), hydro_kx_SESSIONKEYBYTES, PyBUF_READ))

    return rx, tx, bytes(packet2)


cdef kx_kk_3(hydro_kx_state* state, const unsigned char[:] packet2, const unsigned char[:] client_kp):
    if packet2 is None:
        raise ValueError("Packet2 cannot be None")
    if len(packet2) != hydro_kx_KK_PACKET2BYTES:
        raise ValueError(f"Packet2 must be {hydro_kx_KK_PACKET2BYTES} bytes long")
    if client_kp is None:
        raise ValueError("Client keypair cannot be None")
    if len(client_kp) != sizeof(hydro_kx_keypair):
        raise ValueError("Client keypair must be {} bytes long".format(sizeof(hydro_kx_keypair)))

    cdef SafeMemory session = SafeMemory(sizeof(hydro_kx_session_keypair))
    cdef hydro_kx_session_keypair* session_ptr = <hydro_kx_session_keypair*>(session.ptr)
    cdef const uint8_t* packet2_ptr = &packet2[0]
    cdef const hydro_kx_keypair* static_kp_ptr = <const hydro_kx_keypair*>(<const void*>(&client_kp[0]))

    cdef int ret = hydro_kx_kk_3(state, session_ptr, packet2_ptr, static_kp_ptr)
    if ret != 0:
        raise RuntimeError("Failed to finalize key exchange kk")

    rx = SafeMemory.from_buffer(PyMemoryView_FromMemory(<char*>(session_ptr.rx), hydro_kx_SESSIONKEYBYTES, PyBUF_READ))
    tx = SafeMemory.from_buffer(PyMemoryView_FromMemory(<char*>(session_ptr.tx), hydro_kx_SESSIONKEYBYTES, PyBUF_READ))

    return rx, tx
