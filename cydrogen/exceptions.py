class CyException(Exception):
    """
    Base class for all exceptions in the cydrogen library.
    """


class EncryptException(CyException):
    """
    Raised when an error occurs during encryption.
    """

    def __init__(self, message: str = "An error occurred during encryption.") -> None:
        super().__init__(message)


class DecryptException(CyException):
    """
    Raised when an error occurs during decryption.
    """

    def __init__(self, message: str = "An error occurred during decryption.") -> None:
        super().__init__(message)


class DeriveException(CyException):
    """
    Raised when an error occurs during key derivation.
    """

    def __init__(self, message: str = "An error occurred during key derivation.") -> None:
        super().__init__(message)


class SignException(CyException):
    """
    Raised when an error occurs during signing.
    """

    def __init__(self, message: str = "An error occurred during signing.") -> None:
        super().__init__(message)


class VerifyException(CyException):
    """
    Raised when an error occurs during signature verification.
    """

    def __init__(self, message: str = "An error occurred during signature verification.") -> None:
        super().__init__(message)


class KeyExchangeException(CyException):
    """
    Raised when an error occurs during key exchange.
    """

    def __init__(self, message: str = "An error occurred during key exchange.") -> None:
        super().__init__(message)


class MessageTooBigException(CyException):
    """
    Raised when the message is too big to be processed.
    """

    def __init__(self, message: str = "Message is too big to be processed.") -> None:
        super().__init__(message)


class ClientClosedError(CyException):
    """
    Raised when an attempt is made to send a request when the client is closed.
    """

    def __init__(self, message: str = "Client is closed.") -> None:
        super().__init__(message)


class SyncMsgQueueShutdown(CyException):
    pass
