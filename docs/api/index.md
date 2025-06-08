# Cydrogen API

`Cydrogen` provides Python wrappers for the `libhydrogen` library. The `Cydrogen` API is somewhat more high-level to be more Pythonic,
but it provides the same functionality.

The Key Exchange features are not implemented yet in `Cydrogen`, but they will be added in the future.

Contrary to `libhydrogen`, cryptographic keys are typed, to avoid confusion and mistakes.

See:

- [Contexts](context.md) to create contexts consumed at various places in the API.
- [SecretBoxes](secretbox.md) for authenticated encryption.
- [Hashes](hash.md) for hashing data.
- [Signatures](sign.md) for signing and verifying data.
- [Key Derivation](masterkey.md) for deriving keys from other keys, from passwords, etc.
- [Randomness](random.md) for generating random data.
