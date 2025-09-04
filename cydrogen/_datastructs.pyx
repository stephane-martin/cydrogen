# cython: language_level=3

from libc.string cimport memcmp
from libc.stdint cimport uint64_t

from ._utils cimport make_safe_reader, make_safe_writer, make_async_safe_reader, store64, load64

from .exceptions import DecryptException


cdef bytes CY_ENC_MSG_MARKER = b"qN\x00\x00"          # used internally here
cdef const size_t CY_ENC_MSG_HEADER_SIZE = 20         # 4 bytes marker + 8 bytes for ciphertext length + 8 bytes for message ID
ENC_MSG_MARKER = bytes(CY_ENC_MSG_MARKER)             # to make it available in Python
ENC_MSG_HEADER_SIZE = CY_ENC_MSG_HEADER_SIZE          # to make it available in Python


cpdef parse_encrypted_message_header(const unsigned char[:] header):
    if header is None:
        raise ValueError("Header cannot be None")
    if len(header) < CY_ENC_MSG_HEADER_SIZE:
        raise OSError("Header is too short")
    cdef unsigned char* marker_ptr = CY_ENC_MSG_MARKER
    if memcmp(&header[0], marker_ptr, 4) != 0:
        raise DecryptException("Invalid message marker")
    cdef size_t msg_size = load64(header[4:12])
    cdef uint64_t msg_id = load64(header[12:20])
    return msg_size, msg_id


cpdef encrypted_message_header(const unsigned char[:] ciphertext, uint64_t msg_id):
    cdef bytearray header = bytearray(CY_ENC_MSG_HEADER_SIZE)
    header[0:4] = CY_ENC_MSG_MARKER
    cdef unsigned char[:] header_view = header
    store64(header_view[4:12], len(ciphertext))
    store64(header_view[12:20], msg_id)
    return header


cdef class EncryptedMessage:
    def __init__(self, ctext, uint64_t msg_id):
        if ctext is None:
            raise ValueError("Message cannot be None")
        # check that ctext is a bytes-like object or a memoryview
        _ = memoryview(ctext)
        self.ciphertext = ctext
        self.msg_id = msg_id

    cdef header(self):
        return encrypted_message_header(self.ciphertext, self.msg_id)

    def __len__(self):
        return len(self.ciphertext) + CY_ENC_MSG_HEADER_SIZE

    def __bytes__(self):
        return bytes(self.header()) + bytes(self.ciphertext)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, EncryptedMessage):
            return False
        cdef EncryptedMessage o = <EncryptedMessage>other
        if self.msg_id != o.msg_id:
            return False
        cdef const unsigned char[:] self_view = self.ciphertext
        cdef const unsigned char[:] o_view = o.ciphertext
        if len(self_view) != len(o_view):
            return False
        return memcmp(&self_view[0], &o_view[0], len(self_view)) == 0

    def __hash__(self):
        # TODO: replace with Py_HashBuffer when Python 3.14 is the minimum version
        return hash(bytes(self))

    cpdef writeto(self, out):
        if out is None:
            raise ValueError("File object cannot be None")
        w = make_safe_writer(out)
        n_written = w.write(self.header()) + w.write(self.ciphertext)
        if n_written < (CY_ENC_MSG_HEADER_SIZE + len(self.ciphertext)):
            raise OSError("Failed to write the entire message to the file object")
        return n_written

    async def awriteto(self, out):
        if out is None:
            raise ValueError("File object cannot be None")
        out.write(self.header())
        out.write(self.ciphertext)
        await out.drain()

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed, *, max_msg_size=None):
        msg_size, msg_id = parse_encrypted_message_header(framed)
        if max_msg_size is not None and msg_size > max_msg_size:
            raise ValueError("Message size exceeds maximum allowed size, {} > {}".format(msg_size, max_msg_size))
        if len(framed) < (msg_size + CY_ENC_MSG_HEADER_SIZE):
            raise OSError("Framed message is too short")
        return cls(framed[CY_ENC_MSG_HEADER_SIZE:CY_ENC_MSG_HEADER_SIZE + msg_size], msg_id)

    @classmethod
    def read_from(cls, reader, *, max_msg_size=None):
        if reader is None:
            raise ValueError("File object cannot be None")
        r = make_safe_reader(reader)

        cdef bytearray header_buf = bytearray(CY_ENC_MSG_HEADER_SIZE)
        if r.readinto(header_buf) < CY_ENC_MSG_HEADER_SIZE:
            raise OSError("Failed to read next message header")
        msg_size, msg_id = parse_encrypted_message_header(header_buf)
        if max_msg_size is not None and msg_size > max_msg_size:
            raise ValueError("Message size exceeds maximum allowed size, {} > {}".format(msg_size, max_msg_size))
        cdef bytearray msg = bytearray(msg_size)
        if r.readinto(msg) < msg_size:
            raise OSError("Failed to read the entire message")
        return cls(msg, msg_id)

    @classmethod
    async def aread_from(cls, reader, *, max_msg_size=None):
        if reader is None:
            raise ValueError("File object cannot be None")
        r = make_async_safe_reader(reader)
        try:
            header_buf = await r.readexactly(CY_ENC_MSG_HEADER_SIZE)
        except EOFError as ex:
            raise OSError("Failed to read next message header") from ex
        if header_buf[:4] != CY_ENC_MSG_MARKER:
            raise ValueError("Invalid message header")
        msg_size, msg_id = parse_encrypted_message_header(header_buf)
        if max_msg_size is not None and msg_size > <size_t>max_msg_size:
            raise ValueError("Message size exceeds maximum allowed size, {} > {}".format(msg_size, max_msg_size))
        try:
            msg = await r.readexactly(msg_size)
        except EOFError as ex:
            raise OSError("Failed to read the entire message") from ex
        return cls(msg, msg_id)
