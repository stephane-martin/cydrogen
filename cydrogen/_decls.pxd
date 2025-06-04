# cython: language_level=3

from libc.stdint cimport uint32_t
from libc.stdint cimport uint64_t
from libc.stdint cimport uint8_t


cdef extern from "hydrogen.h" nogil:
    const int hydro_random_SEEDBYTES
    const int hydro_hash_BYTES
    const int hydro_hash_BYTES_MAX
    const int hydro_hash_BYTES_MIN
    const int hydro_hash_CONTEXTBYTES
    const int hydro_hash_KEYBYTES
    const int hydro_secretbox_CONTEXTBYTES
    const int hydro_secretbox_HEADERBYTES
    const int hydro_secretbox_KEYBYTES
    const int hydro_secretbox_PROBEBYTES
    const int hydro_pwhash_CONTEXTBYTES
    const int hydro_pwhash_MASTERKEYBYTES
    const int hydro_pwhash_STOREDBYTES
    const int hydro_kdf_BYTES_MAX
    const int hydro_kdf_BYTES_MIN
    const int hydro_kdf_CONTEXTBYTES
    const int hydro_kdf_KEYBYTES
    const int hydro_sign_BYTES
    const int hydro_sign_CONTEXTBYTES
    const int hydro_sign_PUBLICKEYBYTES
    const int hydro_sign_SECRETKEYBYTES
    const int hydro_sign_SEEDBYTES


cdef extern from "hydrogen.h" nogil:
    int hydro_init()
    void hydro_memzero(void *pnt, size_t len)
    uint32_t hydro_random_u32()
    uint32_t hydro_random_uniform(uint32_t upper_bound)
    void hydro_random_buf(void *buf, size_t len)
    bint hydro_equal(const void *b1_, const void *b2_, size_t len)

    struct hydro_hash_state:
        pass

    void hydro_hash_keygen(uint8_t *key)

    int hydro_hash_init(
        hydro_hash_state *state,
        const char ctx[hydro_hash_CONTEXTBYTES],
        const uint8_t key[hydro_hash_KEYBYTES])

    int hydro_hash_update(hydro_hash_state *state, const void *in_, size_t in_len)
    int hydro_hash_final(hydro_hash_state *state, uint8_t *out, size_t out_len)

    void hydro_secretbox_keygen(uint8_t key[hydro_secretbox_KEYBYTES])

    int hydro_secretbox_encrypt(
        uint8_t *c,
        const void *m_, size_t mlen,
        uint64_t msg_id,
        const char ctx[hydro_secretbox_CONTEXTBYTES],
        const uint8_t key[hydro_secretbox_KEYBYTES])

    int hydro_secretbox_decrypt(
        void *m_,
        const uint8_t *c, size_t clen,
        uint64_t msg_id,
        const char ctx[hydro_secretbox_CONTEXTBYTES],
        const uint8_t key[hydro_secretbox_KEYBYTES])

    int hydro_pwhash_deterministic(
        uint8_t *h, size_t h_len,
        const char *passwd, size_t passwd_len,
        const char ctx[hydro_pwhash_CONTEXTBYTES],
        const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES],
        uint64_t opslimit, size_t memlimit, uint8_t threads)

    int hydro_pwhash_create(
        uint8_t stored[hydro_pwhash_STOREDBYTES],
        const char *passwd, size_t passwd_len,
        const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES],
        uint64_t opslimit, size_t memlimit, uint8_t threads)

    int hydro_pwhash_verify(
        const uint8_t stored[hydro_pwhash_STOREDBYTES],
        const char *passwd, size_t passwd_len,
        const uint8_t master_key[hydro_pwhash_MASTERKEYBYTES],
        uint64_t opslimit_max, size_t memlimit_max, uint8_t threads_max)

    int hydro_kdf_derive_from_key(
        uint8_t *subkey, size_t subkey_len, uint64_t subkey_id,
        const char ctx[hydro_kdf_CONTEXTBYTES],
        const uint8_t key[hydro_kdf_KEYBYTES])

    struct hydro_sign_state:
        pass

    struct hydro_sign_keypair:
        uint8_t pk[hydro_sign_PUBLICKEYBYTES]
        uint8_t sk[hydro_sign_SECRETKEYBYTES]

    void hydro_sign_keygen(hydro_sign_keypair *kp)
    void hydro_sign_keygen_deterministic(hydro_sign_keypair *kp, const uint8_t seed[hydro_sign_SEEDBYTES])

    int hydro_sign_create(
        uint8_t csig[hydro_sign_BYTES],
        const void *m_, size_t mlen,
        const char ctx[hydro_sign_CONTEXTBYTES],
        const uint8_t sk[hydro_sign_SECRETKEYBYTES])

    int hydro_sign_verify(
        const uint8_t csig[hydro_sign_BYTES],
        const void *m_, size_t mlen,
        const char ctx[hydro_sign_CONTEXTBYTES],
        const uint8_t pk[hydro_sign_PUBLICKEYBYTES])

    int hydro_sign_init(hydro_sign_state *state, const char ctx[hydro_sign_CONTEXTBYTES])
    int hydro_sign_update(hydro_sign_state *state, const void *m_, size_t mlen)
    int hydro_sign_final_create(hydro_sign_state *state, uint8_t csig[hydro_sign_BYTES], const uint8_t sk[hydro_sign_SECRETKEYBYTES])
    int hydro_sign_final_verify(hydro_sign_state *state, const uint8_t csig[hydro_sign_BYTES], const uint8_t pk[hydro_sign_PUBLICKEYBYTES])

    int hydro_pad(unsigned char *buf, size_t unpadded_buflen, size_t blocksize, size_t max_buflen)
    int hydro_unpad(const unsigned char *buf, size_t padded_buflen, size_t blocksize)


cdef ctx_memzero(char ctx[hydro_hash_CONTEXTBYTES])
cdef basekey_memzero(uint8_t* key)
cdef pk_memzero(uint8_t* key)
cdef sk_memzero(uint8_t* key)
cdef keys_equal(const unsigned char[:] key1, const unsigned char[:] key2)


cdef hash_init(hydro_hash_state *state, const unsigned char[:] ctx, const unsigned char[:] key)
cdef hash_update(hydro_hash_state *state, const unsigned char[:] data)
cdef hash_final(hydro_hash_state *state, unsigned char[:] out)

cdef secretbox_encrypt(
        const unsigned char[:] plaintext,
        uint64_t msg_id,
        const unsigned char[:] ctx,
        const unsigned char[:] key,
        unsigned char[:] ciphertext)

cdef secretbox_decrypt(
        const unsigned char[:] ciphertext,
        uint64_t msg_id,
        const unsigned char[:] ctx,
        const unsigned char[:] key,
        unsigned char[:] plaintext)


cdef pwhash_deterministic(
        const unsigned char[:] password,
        const unsigned char[:] ctx,
        const unsigned char[:] master_key,
        uint64_t opslimit,
        unsigned char[:] derived_key)

cdef kdf_derive_from_key(
        const unsigned char[:] master_key,
        uint64_t subkey_id,
        const unsigned char[:] ctx,
        unsigned char[:] subkey)

cdef pwhash_create(
        const unsigned char[:] password,
        const unsigned char[:] master_key,
        uint64_t opslimit,
        unsigned char[:] stored)

cdef pwhash_verify(
        const unsigned char[:] stored,
        const unsigned char[:] password,
        const unsigned char[:] master_key,
        uint64_t opslimit_max)

cdef sign_keygen_deterministic(const unsigned char[:] master_key)
cdef sign_keygen()
cdef sign_init(hydro_sign_state *state, const unsigned char[:] ctx)
cdef sign_update(hydro_sign_state *state, const unsigned char[:] data)
cdef sign_final_create(hydro_sign_state *state, const unsigned char[:] sk, unsigned char[:] signature)
cdef sign_final_verify(hydro_sign_state *state, const unsigned char[:] pk, const unsigned char[:] signature)

cdef _pad(unsigned char[:] buf, size_t unpadded_buflen, size_t blocksize)
cpdef pad(const unsigned char[:] buf, size_t blocksize=*)
cpdef unpad(const unsigned char[:] buf, size_t blocksize=*)

cpdef random_u32()
cpdef random_uniform(uint32_t upper_bound)
cpdef randomize_buffer(unsigned char[:] buf)
cpdef gen_random_buffer(size_t size)
cpdef shuffle_buffer(unsigned char[:] buf)
