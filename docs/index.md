# Cydrogen

`Cydrogen` is a Python library that wraps the [`libhydrogen`](https://github.com/jedisct1/libhydrogen) library.

`libhydrogen` is "a small, easy-to-use, hard-to-misuse cryptographic library". It is based on the Curve25519
elliptic curve and the Gimli permutation. See their [documentation](https://github.com/jedisct1/libhydrogen/wiki)
for more information.

`Cydrogen` is made using [Cython](https://cython.org/).

## Objectives

- Python interface to `libhydrogen` that is easy to use and hard to misuse.
- Pythonic API.
- Support for Python 3.12+.
- Support for Windows, macOS, and Linux.
- Publish wheels for supported platforms on PyPI.

## Features

- Random number generation.
- Generic hashing.
- Key derivation.
- Secret-key authenticated encryption ("cryptobox").
- Public-key signatures.
- Password hashing.
- Storing cryptographic secrets in heap-guarded memory.

## Installation

We publish the source distribution and wheels for several platforms on [PyPI](https://pypi.org/project/cydrogen/). You can install the latest version with:

```bash
pip install cydrogen
```

`Cydrogen` does not have any runtime dependencies other than Python 3.12+.

All relevant classes and functions are present directly in the `cydrogen` module.

No specific initialization is required to use the library. `libhydrogen` is initialized automatically when you import `cydrogen`.
