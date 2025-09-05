# cython: language_level=3

from cpython.buffer cimport PyBuffer_FillInfo
from libc.string cimport memcmp, memcpy
from libc.stdint cimport uint64_t

from ._decls cimport hydro_secretbox_HEADERBYTES
from ._utils cimport make_safe_writer, store64, load64

from .exceptions import DecryptException


cdef bytes CY_ENC_MSG_MARKER = b"EM"
cdef const size_t CY_ENC_MSG_HEADER_SIZE = 10         # 2 bytes marker + 8 bytes for message ID
ENC_MSG_MARKER = bytes(CY_ENC_MSG_MARKER)             # to make it available in Python
ENC_MSG_HEADER_SIZE = CY_ENC_MSG_HEADER_SIZE          # to make it available in Python


cpdef parse_encrypted_message_header(const unsigned char[:] header):
    if header is None:
        raise ValueError("Header cannot be None")
    if len(header) < CY_ENC_MSG_HEADER_SIZE:
        raise OSError("Header is too short")
    cdef unsigned char* marker_ptr = CY_ENC_MSG_MARKER
    if memcmp(&header[0], marker_ptr, 2) != 0:
        raise DecryptException("Invalid message marker")
    cdef uint64_t msg_id = load64(header[2:10])
    return msg_id


cpdef encrypted_message_header(uint64_t msg_id):
    cdef bytearray header = bytearray(CY_ENC_MSG_HEADER_SIZE)
    header[0:2] = CY_ENC_MSG_MARKER
    cdef unsigned char[:] header_view = header
    store64(header_view[2:10], msg_id)
    return header


cdef class EncryptedMessage:
    def __init__(self, ctext, uint64_t msg_id):
        if ctext is None:
            raise ValueError("Message cannot be None")
        self.ciphertext = ctext
        self.msg_id = msg_id
        self.encoded = bytearray(CY_ENC_MSG_HEADER_SIZE + len(ctext))
        self.encoded[0:2] = CY_ENC_MSG_MARKER
        cdef const unsigned char[:] ctext_view = ctext
        cdef unsigned char[:] encoded_view = self.encoded
        cdef unsigned char* encoded_ptr = self.encoded
        store64(encoded_view[2:10], msg_id)
        memcpy(encoded_ptr + CY_ENC_MSG_HEADER_SIZE, &ctext_view[0], len(ctext))

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        cdef const unsigned char* encoded_ptr = self.encoded
        PyBuffer_FillInfo(buffer, self, encoded_ptr, len(self.encoded), 1, flags)

    def __bytes__(self):
        return bytes(self.encoded)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, EncryptedMessage):
            return False
        cdef EncryptedMessage o = <EncryptedMessage>other
        return self.encoded == o.encoded

    def __hash__(self):
        # TODO: replace with Py_HashBuffer when Python 3.14 is the minimum version
        return hash(bytes(self.encoded))

    cpdef writeto(self, out):
        if out is None:
            raise ValueError("File object cannot be None")
        n_written = make_safe_writer(out).write(self.encoded)
        if n_written < (CY_ENC_MSG_HEADER_SIZE + len(self.ciphertext)):
            raise OSError("Failed to write the entire message to the file object")
        return n_written

    async def awriteto(self, out):
        if out is None:
            raise ValueError("File object cannot be None")
        out.write(self.encoded)
        await out.drain()

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed, *, max_msg_size=None):
        msg_id = parse_encrypted_message_header(framed)
        ciphertext_size = len(framed) - CY_ENC_MSG_HEADER_SIZE  # positive because parsing succeeded
        if ciphertext_size < hydro_secretbox_HEADERBYTES:
            raise ValueError("Ciphertext size is too small")
        plaintext_size = ciphertext_size - hydro_secretbox_HEADERBYTES
        if max_msg_size is not None and plaintext_size > max_msg_size:
            raise ValueError("Plaintext size exceeds maximum allowed size, {} > {}".format(plaintext_size, max_msg_size))
        return cls(framed[CY_ENC_MSG_HEADER_SIZE:len(framed)], msg_id)
