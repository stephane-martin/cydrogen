# cython: language_level=3

from cpython.buffer cimport PyBuffer_FillInfo
from libc.string cimport memcmp
from libc.stdint cimport uint64_t
from libc.stdint cimport uint32_t

from ._decls cimport hydro_secretbox_HEADERBYTES
from ._decls cimport hydro_kx_N_PACKET1BYTES
from ._decls cimport hydro_kx_KK_PACKET1BYTES, hydro_kx_KK_PACKET2BYTES
from ._decls cimport hydro_kx_XX_PACKET1BYTES, hydro_kx_XX_PACKET2BYTES, hydro_kx_XX_PACKET3BYTES
from ._utils cimport make_safe_writer, store64, load64, store32, load32, hash_buffer

from enum import StrEnum

from .exceptions import DecryptException


cdef bytes CY_ENC_MSG_MARKER = b"EM"
cdef const size_t CY_ENC_MSG_HEADER_SIZE = 14         # 2 bytes marker + 8 bytes for message ID + 4 byte for session keys index
ENC_MSG_MARKER = bytes(CY_ENC_MSG_MARKER)
ENC_MSG_HEADER_SIZE = CY_ENC_MSG_HEADER_SIZE

cdef bytes CY_KX_N_PACKET1_MARKER = b"N1"
cdef bytes CY_KX_KK_PACKET1_MARKER = b"K1"
cdef bytes CY_KX_KK_PACKET2_MARKER = b"K2"
cdef bytes CY_KX_XX_PACKET1_MARKER = b"X1"
cdef bytes CY_KX_XX_PACKET2_MARKER = b"X2"
cdef bytes CY_KX_XX_PACKET3_MARKER = b"X3"
cdef bytes CY_KX_SERVER_ACK_MARKER = b"SA"

KX_N_PACKET1_MARKER = bytes(CY_KX_N_PACKET1_MARKER)     # explicit bytes() to make a copy and ensure the cython markers are not modified
KX_KK_PACKET1_MARKER = bytes(CY_KX_KK_PACKET1_MARKER)
KX_KK_PACKET2_MARKER = bytes(CY_KX_KK_PACKET2_MARKER)
KX_XX_PACKET1_MARKER = bytes(CY_KX_XX_PACKET1_MARKER)
KX_XX_PACKET2_MARKER = bytes(CY_KX_XX_PACKET2_MARKER)
KX_XX_PACKET3_MARKER = bytes(CY_KX_XX_PACKET3_MARKER)
KX_SERVER_ACK_MARKER = bytes(CY_KX_SERVER_ACK_MARKER)


class MessageType(StrEnum):
    ENCRYPTED_MESSAGE = ENC_MSG_MARKER.decode("ascii")
    KX_N_PACKET1 = KX_N_PACKET1_MARKER.decode("ascii")
    KX_KK_PACKET1 = KX_KK_PACKET1_MARKER.decode("ascii")
    KX_KK_PACKET2 = KX_KK_PACKET2_MARKER.decode("ascii")
    KX_XX_PACKET1 = KX_XX_PACKET1_MARKER.decode("ascii")
    KX_XX_PACKET2 = KX_XX_PACKET2_MARKER.decode("ascii")
    KX_XX_PACKET3 = KX_XX_PACKET3_MARKER.decode("ascii")
    KX_SERVER_ACK = KX_SERVER_ACK_MARKER.decode("ascii")

    @classmethod
    def from_marker(cls, marker):
        if isinstance(marker, str):
            return cls(marker)
        return cls(marker.decode("ascii"))

    def is_encrypted_message(self):
        return self == MessageType.ENCRYPTED_MESSAGE

    def is_server_ack(self):
        return self == MessageType.KX_SERVER_ACK

    def is_kx_packet(self):
        return self in {
            MessageType.KX_N_PACKET1,
            MessageType.KX_KK_PACKET1,
            MessageType.KX_KK_PACKET2,
            MessageType.KX_XX_PACKET1,
            MessageType.KX_XX_PACKET2,
            MessageType.KX_XX_PACKET3,
        }


cdef parse_encrypted_message_header(const unsigned char[:] header):
    if header is None:
        raise ValueError("Header cannot be None")
    if len(header) < CY_ENC_MSG_HEADER_SIZE:
        raise OSError("Header is too short")
    cdef unsigned char* marker_ptr = CY_ENC_MSG_MARKER
    if memcmp(&header[0], marker_ptr, 2) != 0:
        raise DecryptException("Invalid message marker")
    cdef uint64_t msg_id = load64(header[2:10])
    cdef uint32_t session_keys_idx = load32(header[10:14])
    return msg_id, session_keys_idx


cdef class EncryptedMessage:
    def __init__(self, const unsigned char[:] ctext_view, uint64_t msg_id, uint32_t session_keys_idx=0):
        self.msg_id = msg_id
        self.session_keys_idx = session_keys_idx
        # Keep a reference to the ciphertext
        self.ciphertext = ctext_view

    cpdef header(self):
        cdef bytearray h = bytearray(CY_ENC_MSG_HEADER_SIZE)
        cdef unsigned char[:] hv = h
        h[0:2] = CY_ENC_MSG_MARKER
        store64(hv[2:10], self.msg_id)
        store32(hv[10:14], self.session_keys_idx)
        return h

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        # Create the encoded message. This actually copies the ciphertext.
        encoded = bytearray(CY_ENC_MSG_HEADER_SIZE + len(self.ciphertext))
        encoded[0:2] = CY_ENC_MSG_MARKER
        cdef unsigned char[:] ciphertext_view = self.ciphertext
        cdef unsigned char[:] encoded_view = encoded
        store64(encoded_view[2:10], self.msg_id)
        store32(encoded_view[10:14], self.session_keys_idx)
        encoded_view[CY_ENC_MSG_HEADER_SIZE:len(encoded)] = ciphertext_view[0:len(self.ciphertext)]
        cdef unsigned char* encoded_ptr = encoded
        PyBuffer_FillInfo(buffer, encoded, <void*>encoded_ptr, len(encoded), 1, flags)

    def __len__(self):
        return CY_ENC_MSG_HEADER_SIZE + len(self.ciphertext)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, EncryptedMessage):
            return False
        cdef EncryptedMessage o = <EncryptedMessage>other
        if self.msg_id != o.msg_id:
            return False
        if self.session_keys_idx != o.session_keys_idx:
            return False
        if len(self.ciphertext) != len(o.ciphertext):
            return False
        cdef const unsigned char[:] self_ctext_view = self.ciphertext
        cdef const unsigned char[:] o_ctext_view = o.ciphertext
        cdef const unsigned char* self_ptr = &self_ctext_view[0]
        cdef const unsigned char* o_ptr = &o_ctext_view[0]
        return memcmp(self_ptr, o_ptr, len(self.ciphertext)) == 0

    def __hash__(self):
        return hash_buffer(self)

    cpdef writeto(self, out):
        n_written = make_safe_writer(out).write(self)
        if n_written < len(self):
            raise OSError("Failed to write the entire message to the file object")
        return n_written

    async def awriteto(self, out):
        if out is None:
            raise ValueError("File object cannot be None")
        out.write(self)
        await out.drain()

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed, *, max_msg_size=None):
        msg_id, session_keys_idx = parse_encrypted_message_header(framed)
        ciphertext_size = len(framed) - CY_ENC_MSG_HEADER_SIZE  # positive because parsing succeeded
        if ciphertext_size < hydro_secretbox_HEADERBYTES:
            raise ValueError("Ciphertext size is too small")
        plaintext_size = ciphertext_size - hydro_secretbox_HEADERBYTES
        if max_msg_size is not None and plaintext_size > max_msg_size:
            raise ValueError("Plaintext size exceeds maximum allowed size, {} > {}".format(plaintext_size, max_msg_size))
        return cls(framed[CY_ENC_MSG_HEADER_SIZE:len(framed)], msg_id, session_keys_idx)


cdef class KX_N_Packet1:
    def __init__(self, const unsigned char[:] packet):
        if packet is None:
            raise ValueError("Packet cannot be None")
        if len(packet) != hydro_kx_N_PACKET1BYTES:
            raise ValueError("Invalid packet size")
        self.packet = bytes(packet)
        self.encoded = CY_KX_N_PACKET1_MARKER + self.packet

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        cdef const unsigned char* encoded_ptr = self.encoded
        PyBuffer_FillInfo(buffer, self, <void*>encoded_ptr, len(self.encoded), 1, flags)

    def __bytes__(self):
        return bytes(self.encoded)

    def __len__(self):
        return len(self.encoded)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, KX_N_Packet1):
            return False
        cdef KX_N_Packet1 o = <KX_N_Packet1>other
        return self.packet == o.packet

    def __hash__(self):
        return hash(self.packet)

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed):
        if bytes(framed[0:2]) != KX_N_PACKET1_MARKER:
            raise ValueError("Invalid packet marker")
        return cls(framed[2:len(framed)])


cdef class KX_KK_Packet1:
    def __init__(self, const unsigned char[:] packet):
        if packet is None:
            raise ValueError("Packet cannot be None")
        if len(packet) != hydro_kx_KK_PACKET1BYTES:
            raise ValueError("Invalid packet size")
        self.packet = bytes(packet)
        self.encoded = CY_KX_KK_PACKET1_MARKER + self.packet

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        cdef const unsigned char* encoded_ptr = self.encoded
        PyBuffer_FillInfo(buffer, self, <void*>encoded_ptr, len(self.encoded), 1, flags)

    def __bytes__(self):
        return bytes(self.encoded)

    def __len__(self):
        return len(self.encoded)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, KX_KK_Packet1):
            return False
        cdef KX_KK_Packet1 o = <KX_KK_Packet1>other
        return self.packet == o.packet

    def __hash__(self):
        return hash(self.packet)

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed):
        if bytes(framed[0:2]) != KX_KK_PACKET1_MARKER:
            raise ValueError("Invalid packet marker")
        return cls(framed[2:len(framed)])

cdef class KX_KK_Packet2:
    def __init__(self, const unsigned char[:] packet):
        if packet is None:
            raise ValueError("Packet cannot be None")
        if len(packet) != hydro_kx_KK_PACKET2BYTES:
            raise ValueError("Invalid packet size")
        self.packet = bytes(packet)
        self.encoded = CY_KX_KK_PACKET2_MARKER + self.packet

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        cdef const unsigned char* encoded_ptr = self.encoded
        PyBuffer_FillInfo(buffer, self, <void*>encoded_ptr, len(self.encoded), 1, flags)

    def __bytes__(self):
        return bytes(self.encoded)

    def __len__(self):
        return len(self.encoded)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, KX_KK_Packet2):
            return False
        cdef KX_KK_Packet2 o = <KX_KK_Packet2>other
        return self.packet == o.packet

    def __hash__(self):
        return hash(self.packet)

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed):
        if bytes(framed[0:2]) != KX_KK_PACKET2_MARKER:
            raise ValueError("Invalid packet marker")
        return cls(framed[2:len(framed)])


cdef class KX_XX_Packet1:
    def __init__(self, const unsigned char[:] packet):
        if packet is None:
            raise ValueError("Packet cannot be None")
        if len(packet) != hydro_kx_XX_PACKET1BYTES:
            raise ValueError("Invalid packet size")
        self.packet = bytes(packet)
        self.encoded = CY_KX_XX_PACKET1_MARKER + self.packet

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        cdef const unsigned char* encoded_ptr = self.encoded
        PyBuffer_FillInfo(buffer, self, <void*>encoded_ptr, len(self.encoded), 1, flags)

    def __bytes__(self):
        return bytes(self.encoded)

    def __len__(self):
        return len(self.encoded)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, KX_XX_Packet1):
            return False
        cdef KX_XX_Packet1 o = <KX_XX_Packet1>other
        return self.packet == o.packet

    def __hash__(self):
        return hash(self.packet)

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed):
        if bytes(framed[0:2]) != KX_XX_PACKET1_MARKER:
            raise ValueError("Invalid packet marker")
        return cls(framed[2:len(framed)])


cdef class KX_XX_Packet2:
    def __init__(self, const unsigned char[:] packet):
        if packet is None:
            raise ValueError("Packet cannot be None")
        if len(packet) != hydro_kx_XX_PACKET2BYTES:
            raise ValueError("Invalid packet size")
        self.packet = bytes(packet)
        self.encoded = CY_KX_XX_PACKET2_MARKER + self.packet

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        cdef const unsigned char* encoded_ptr = self.encoded
        PyBuffer_FillInfo(buffer, self, <void*>encoded_ptr, len(self.encoded), 1, flags)

    def __bytes__(self):
        return bytes(self.encoded)

    def __len__(self):
        return len(self.encoded)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, KX_XX_Packet2):
            return False
        cdef KX_XX_Packet2 o = <KX_XX_Packet2>other
        return self.packet == o.packet

    def __hash__(self):
        return hash(self.packet)

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed):
        if bytes(framed[0:2]) != KX_XX_PACKET2_MARKER:
            raise ValueError("Invalid packet marker")
        return cls(framed[2:len(framed)])


cdef class KX_XX_Packet3:
    def __init__(self, const unsigned char[:] packet):
        if packet is None:
            raise ValueError("Packet cannot be None")
        if len(packet) != hydro_kx_XX_PACKET3BYTES:
            raise ValueError("Invalid packet size")
        self.packet = bytes(packet)
        self.encoded = CY_KX_XX_PACKET3_MARKER + self.packet

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        cdef const unsigned char* encoded_ptr = self.encoded
        PyBuffer_FillInfo(buffer, self, <void*>encoded_ptr, len(self.encoded), 1, flags)

    def __bytes__(self):
        return bytes(self.encoded)

    def __len__(self):
        return len(self.encoded)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, KX_XX_Packet3):
            return False
        cdef KX_XX_Packet3 o = <KX_XX_Packet3>other
        return self.packet == o.packet

    def __hash__(self):
        return hash(self.packet)

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed):
        if bytes(framed[0:2]) != KX_XX_PACKET3_MARKER:
            raise ValueError("Invalid packet marker")
        return cls(framed[2:len(framed)])


cdef class KX_Server_Ack:
    def __init__(self):
        self.packet = b"OK"
        self.encoded = CY_KX_SERVER_ACK_MARKER + self.packet

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        cdef const unsigned char* encoded_ptr = self.encoded
        PyBuffer_FillInfo(buffer, self, <void*>encoded_ptr, len(self.encoded), 1, flags)

    def __bytes__(self):
        return bytes(self.encoded)

    def __len__(self):
        return len(self.encoded)

    def __eq__(self, other):
        if other is None:
            return False
        return isinstance(other, KX_Server_Ack)

    def __hash__(self):
        return hash(self.packet)

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed):
        if bytes(framed[0:2]) != KX_SERVER_ACK_MARKER:
            raise ValueError("Invalid packet marker")
        if bytes(framed[2:len(framed)]) != b"OK":
            raise ValueError("Invalid server ack packet")
        return cls()
