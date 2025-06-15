# cython: language_level=3

import base64
import io

from libc.stdint cimport uint64_t
from libc.stdint cimport uint32_t

from ._basekey cimport BaseKey
from ._context cimport make_context
from ._exceptions cimport DecryptException, EncryptException
from ._hash cimport Hash, HashKey
from ._masterkey cimport MasterKey, make_masterkey
from ._sign import SignPublicKey, SignSecretKey, SignKeyPair
from ._utils cimport FileOpener, SafeMemory, TeeWriter, make_safe_reader, make_safe_writer, make_async_safe_reader
from ._utils cimport store64, load64, store32, load32

from ._decls cimport hydro_secretbox_HEADERBYTES, secretbox_encrypt, secretbox_decrypt


# declared as a cdef so that it cannot be modified at runtime
cdef bytes _ENC_MSG_HEADER = b"qN\x00\x00"

ENC_MSG_HEADER = _ENC_MSG_HEADER[:4]


cdef class SecretBoxKey(BaseKey):
    def __init__(self, key):
        if key is None:
            raise ValueError("Key argument cannot be None")

        if isinstance(key, SafeMemory):
            super().__init__(key)
            return

        # when key argument is already a SecretBoxKey, copy the key
        cdef SecretBoxKey o
        if isinstance(key, SecretBoxKey):
            o = <SecretBoxKey>key
            super().__init__(o.key)
            return

        if isinstance(key, (HashKey, MasterKey, SignKeyPair, SignPublicKey, SignSecretKey)):
            raise TypeError("can't create a SecretBoxKey from another concrete key type")

        # when key argument is a string, assume it's a base64 encoded key
        if isinstance(key, str):
            super().__init__(base64.standard_b64decode(key))
            return

        # else, assume it's a bytes like object
        super().__init__(bytes(key))

    def __eq__(self, other):
        if not isinstance(other, SecretBoxKey):
            return False
        cdef SecretBoxKey o = <SecretBoxKey>other
        return self.eq(o)

    def __repr__(self):
        return f'SecretBoxKey({repr(str(self))})'

    @classmethod
    def from_password(cls, const unsigned char[:] password, *, master_key=None, ctx=None, opslimit=10000):
        if password is None:
            raise ValueError("Password cannot be None")
        cdef mkey = make_masterkey(master_key)
        cdef BaseKey derived = mkey.derive_key_from_password(password, ctx=ctx, opslimit=opslimit)
        return cls(derived)

    cpdef secretbox(self, ctx=None):
        return SecretBox(self, ctx=ctx)


cdef make_secretbox_key(key):
    if isinstance(key, SecretBoxKey):
        return key
    return SecretBoxKey(key)


cdef class EncryptedMessage:
    def __init__(self, const unsigned char[:] ctext, uint64_t msg_id):
        if ctext is None:
            raise ValueError("Message cannot be None")
        self.ciphertext = bytes(ctext)
        self.msg_id = msg_id

    cdef header(self):
        cdef bytearray header = bytearray(4 + 8 + 8)
        header[0:4] = _ENC_MSG_HEADER
        cdef unsigned char[:] header_view = header
        store64(header_view[4:12], len(self.ciphertext))
        store64(header_view[12:20], self.msg_id)
        return header

    def __bytes__(self):
        return bytes(self.header()) + self.ciphertext

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, EncryptedMessage):
            return False
        cdef EncryptedMessage o = <EncryptedMessage>other
        if self.msg_id != o.msg_id:
            return False
        return self.ciphertext == o.ciphertext

    cpdef writeto(self, out):
        if out is None:
            raise ValueError("File object cannot be None")

        w = make_safe_writer(out)
        n_written = w.write(self.header()) + w.write(self.ciphertext)
        if n_written < (20 + len(self.ciphertext)):
            raise OSError("Failed to write the entire message to the file object")
        return n_written

    async def awriteto(self, out):
        if out is None:
            raise ValueError("File object cannot be None")
        out.write(self.header())
        out.write(self.ciphertext)
        await out.drain()

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed):
        if framed is None:
            raise ValueError("Framed message cannot be None")
        return cls.read_from(io.BytesIO(framed))

    @classmethod
    def read_from(cls, reader, *, max_msg_size=None):
        if reader is None:
            raise ValueError("File object cannot be None")
        r = make_safe_reader(reader)

        cdef bytearray header_buf = bytearray(20)
        if r.readinto(header_buf) < 20U:
            raise OSError("Failed to read next message header")
        if header_buf[:4] != _ENC_MSG_HEADER:
            raise ValueError("Invalid message header")
        cdef size_t msg_size = load64(header_buf[4:12])
        if max_msg_size is not None:
            if msg_size > <size_t>max_msg_size:
                raise ValueError("Message size exceeds maximum allowed size, {} > {}".format(msg_size, max_msg_size))
        cdef uint64_t msg_id = load64(header_buf[12:20])
        cdef bytearray msg = bytearray(msg_size)
        if r.readinto(msg) != msg_size:
            raise OSError("Failed to read the entire message")
        return cls(msg, msg_id)

    @classmethod
    async def aread_from(cls, reader, *, max_msg_size=None):
        if reader is None:
            raise ValueError("File object cannot be None")
        r = make_async_safe_reader(reader)
        try:
            header_buf = await r.readexactly(20)
        except EOFError as ex:
            raise OSError("Failed to read next message header") from ex
        if header_buf[:4] != _ENC_MSG_HEADER:
            raise ValueError("Invalid message header")
        cdef size_t msg_size = load64(header_buf[4:12])
        if max_msg_size is not None:
            if msg_size > <size_t>max_msg_size:
                raise ValueError("Message size exceeds maximum allowed size, {} > {}".format(msg_size, max_msg_size))
        cdef uint64_t msg_id = load64(header_buf[12:20])
        try:
            msg = await r.readexactly(msg_size)
        except EOFError as ex:
            raise OSError("Failed to read the entire message") from ex
        return cls(msg, msg_id)

    cpdef decrypt(self, key, ctx=None, out=None):
        if key is None:
            raise ValueError("Key cannot be None")
        return SecretBox(key, ctx=ctx).decrypt(self.ciphertext, msg_id=self.msg_id, out=out)


cdef class SecretBox:
    def __init__(self, key, *, ctx=None):
        if key is None:
            raise ValueError("Key cannot be None")
        self.key = make_secretbox_key(key)
        self.ctx = make_context(ctx)

    async def aencrypt(self, const unsigned char[:] plaintext, uint64_t msg_id, out):
        if out is None:
            raise ValueError("Output stream writer cannot be None")
        ciphertext = self.encrypt(plaintext, msg_id=msg_id)
        await EncryptedMessage(ciphertext, msg_id).awriteto(out)

    cpdef encrypt(self, const unsigned char[:] plaintext, uint64_t msg_id=0, out=None):
        if plaintext is None:
            raise ValueError("Plaintext cannot be None")
        if out is not None:
            make_safe_writer(out)  # ensure out is a file-like object
        cdef bytearray ciphertext = bytearray(len(plaintext) + hydro_secretbox_HEADERBYTES)
        try:
            secretbox_encrypt(plaintext, msg_id, self.ctx, self.key, ciphertext)
        except ValueError:
            raise
        except Exception as ex:
            raise EncryptException("Encryption failed") from ex
        cdef EncryptedMessage msg = EncryptedMessage(ciphertext, msg_id)
        if out is not None:
            # write the encrypted message to the output writer
            # note that EncryptedMessage.writeto writes the full frame including the header0
            msg.writeto(out)
        return msg.ciphertext

    async def adecrypt(self, ciphertext, uint64_t msg_id, out):
        if out is None:
            raise ValueError("Output stream writer cannot be None")
        plaintext = self.decrypt(ciphertext, msg_id=msg_id)
        out.write(plaintext)
        await out.drain()

    cpdef decrypt(self, ciphertext, uint64_t msg_id=0, out=None):
        if ciphertext is None:
            raise ValueError("Ciphertext cannot be None")

        if isinstance(ciphertext, EncryptedMessage):
            _id = ciphertext.msg_id
            ciphertext = ciphertext.ciphertext
            if msg_id != 0U and _id != msg_id:
                raise DecryptException("The passed message ID does not match the one in the EncryptedMessage")
            msg_id = _id

        if len(ciphertext) < hydro_secretbox_HEADERBYTES:
            raise ValueError("Ciphertext is too short")
        cdef size_t plaintext_len = len(ciphertext) - hydro_secretbox_HEADERBYTES
        cdef bytearray plaintext = bytearray(plaintext_len)
        try:
            secretbox_decrypt(ciphertext, msg_id, self.ctx, self.key, plaintext)
        except ValueError:
            raise
        except Exception as ex:
            raise DecryptException("Decryption failed") from ex
        if out is not None:
            make_safe_writer(out).write(plaintext)
        return bytes(plaintext)

    cpdef encrypt_file(self, src, dst, size_t chunk_size=8192):
        if src is None or dst is None:
            raise ValueError("Source and destination file objects cannot be None")
        with FileOpener(src, mode="rb") as src_obj, FileOpener(dst, mode="wb") as dst_obj:
            return self._encrypt_file(src_obj, dst_obj, chunk_size=chunk_size)

    cdef _encrypt_file(self, fileobj, out, size_t chunk_size=8192):
        if fileobj is None or out is None:
            raise ValueError("Source and destination file objects cannot be None")
        if chunk_size <= hydro_secretbox_HEADERBYTES:
            raise ValueError("Chunk size must be greater than the header size")
        w = make_safe_writer(out)
        cdef Hash hasher = Hash(ctx=self.ctx, key=bytes(self.key))
        cdef uint64_t total_bytes_written = 0
        cdef bytearray buf = bytearray(chunk_size - hydro_secretbox_HEADERBYTES)     # the buffer used to read a chunk of the file
        cdef unsigned char[:] buf_view = buf
        cdef size_t n = 0               # the size of the current plaintext chunk
        cdef uint64_t msg_id = 1        # we will increment this for each chunk

        # write the max buffer size to the output file so that we can read it at decrypt time
        cdef bytearray header = bytearray(8)
        header[0:4] = _ENC_MSG_HEADER
        cdef unsigned char[:] header_view = header
        store32(header_view[4:8], chunk_size)  # store the chunk size in the header
        w.write(header)  # write the header to the output file
        total_bytes_written += 8

        while True:
            n = fileobj.readinto(buf)               # read a chunk of the plaintext file into the plaintext buffer
            if n == 0:
                break
            hasher.update(buf_view[:n])
            self.encrypt(buf_view[:n], msg_id=msg_id, out=w)
            total_bytes_written += n + hydro_secretbox_HEADERBYTES + 20
            msg_id += 1

        # encrypt and write the hash of the original file
        self.encrypt(hasher.digest(), msg_id=0, out=w)
        return total_bytes_written

    cpdef decrypt_file(self, src, dst):
        if src is None or dst is None:
            raise ValueError("Source and destination file objects cannot be None")
        with FileOpener(src, mode="rb") as src_obj, FileOpener(dst, mode="wb") as out_obj:
            return self._decrypt_file(src_obj, out_obj)

    cdef _decrypt_file(self, fileobj, out):
        if fileobj is None or out is None:
            raise ValueError("Source and destination file objects cannot be None")
        cdef uint64_t msg_id = 1
        cdef uint64_t total_bytes_written = 0
        cdef bytearray sbuf = bytearray(8)
        cdef size_t max_buf_size = 0
        cdef EncryptedMessage enc_msg
        cdef Hash hasher = Hash(ctx=self.ctx, key=bytes(self.key))
        cdef TeeWriter tee
        cdef bytes transmitted_hash
        cdef bytes computed_hash

        r = make_safe_reader(fileobj)
        w = make_safe_writer(out)

        if (<uint32_t>r.readinto(sbuf)) != 8U:
            raise OSError("Failed to read max buffer size")
        if sbuf[:4] != _ENC_MSG_HEADER:
            raise ValueError("Invalid message header")
        max_buf_size = load32(sbuf[4:8])
        tee = TeeWriter(w, hasher)

        while True:
            try:
                enc_msg = EncryptedMessage.read_from(r, max_msg_size=max_buf_size)
            except OSError as ex:
                # we have reached the end of the file without having seen the hash
                raise DecryptException("final hash not found")
            if enc_msg.msg_id == 0:
                # if the message ID is 0, we assume it's the hash of the original file
                # we don't need to write it to the output file
                break
            if enc_msg.msg_id != msg_id:
                raise DecryptException("Invalid message ID")
            enc_msg.decrypt(self.key, ctx=self.ctx, out=tee)
            total_bytes_written += len(enc_msg.ciphertext) - hydro_secretbox_HEADERBYTES
            msg_id += 1

        # the last encrypted message contains hash of the original file
        # we need to compare it with the hash of the decrypted file
        transmitted_hash = enc_msg.decrypt(self.key, ctx=self.ctx)
        if len(transmitted_hash) != hasher.digest_size:
            raise DecryptException("Invalid hash length")
        computed_hash = hasher.digest()
        if transmitted_hash != computed_hash:
            raise DecryptException("Invalid hash")
        return total_bytes_written
