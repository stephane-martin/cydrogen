class CyException(Exception):
    """
    Base class for all exceptions in the `cydrogen` package.
    """

    ...

class EncryptException(CyException):
    """
    Exception raised for errors during encryption operations.
    """

    ...

class DecryptException(CyException):
    """
    Exception raised for errors during decryption operations.

    In particular, this exception is raised when the decryption fails due to an invalid key
    or tampered ciphertext.
    """

    ...

class DeriveException(CyException):
    """
    Exception raised for errors during key derivation operations.
    """

    ...

class SignException(CyException):
    """
    Exception raised for errors during signing operations.
    """

    ...

class VerifyException(CyException):
    """
    Exception raised for errors during signature verification operations.

    In particular, this exception is raised when the signature verification fails due to an
    invalid signature or tampered data.
    """

    ...
