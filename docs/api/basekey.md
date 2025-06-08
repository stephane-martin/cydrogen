# Base keys

The cryptographic keys involved for the [secretbox API][cydrogen.SecretBoxKey], for the [hash API][cydrogen.HashKey]
and for [key derivation][cydrogen.MasterKey] are very similar. All of them are derived from a base key class.

Because they inherit from `BaseKey` class, `HashKeys`, `SecretBoxKeys` and `Masterkeys` have the following properties:

- They encapsulate a 32-byte key that's allocated using guarded heap memory.
- A random key can be generated using the [`gen`][cydrogen.BaseKey.gen] class method.
- They implement the Buffer protocol and can by used as `bytes-like` objects.
- They can be exported as a `str` using the [`__str__`][cydrogen.BaseKey.__str__] method (base64 encoding is used).
- They can be written to a file using the [`writeto`][cydrogen.BaseKey.writeto] method.
- They can be read from a file using the [`read_from`][cydrogen.BaseKey.read_from] method.

## ::: cydrogen.BaseKey
    options:
      heading: "class BaseKey"
      show_root_heading: true
