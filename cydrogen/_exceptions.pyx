# cython: language_level=3

cdef class CyException(Exception):
    pass


cdef class EncryptException(CyException):
    pass


cdef class DecryptException(CyException):
    pass


cdef class DeriveException(CyException):
    pass


cdef class SignException(CyException):
    pass


cdef class VerifyException(CyException):
    pass


cdef class KeyExchangeException(CyException):
    pass


cdef class MessageTooBigException(CyException):
    """
    Raised when the message is too big to be processed.
    """
    def __init__(self, message: str = "Message is too big to be processed."):
        super().__init__(message)


cdef class ClientClosedError(CyException):
    """
    Raised when an attempt is made to send a request when the client is closed.
    """
    def __init__(self, message: str = "Client is closed.") -> None:
        super().__init__(message)
