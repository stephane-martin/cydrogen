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
