# cython: language_level=3

import base64
import io

from libc.stdint cimport uint64_t

from ._basekey cimport BaseKey
from ._context cimport Context
from ._exceptions cimport DecryptException, EncryptException
from ._hash cimport Hash, HashKey
from ._masterkey cimport MasterKey
from ._sign import SignPublicKey, SignSecretKey, SignKeyPair
from ._utils cimport FileOpener, SafeReader, SafeWriter, TeeWriter
from ._utils cimport store64, load64, store32, load32

from ._decls cimport hydro_secretbox_HEADERBYTES, secretbox_encrypt, secretbox_decrypt


cdef bytes ENC_MSG_HEADER = b"qN\x00\x00"


cdef class SecretBoxKey(BaseKey):
    """
    SecretBoxKey represents a key for the secretbox API.
    """

    def __init__(self, key):
        if key is None:
            raise ValueError("Key argument cannot be None")

        # when key argument is already a SecretBoxKey, copy the key
        if isinstance(key, SecretBoxKey):
            super().__init__(bytes(key))
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
        """
        Derive a key from a password using the master key.
        The derived key is returned as a SecretBoxKey.
        """
        if password is None:
            raise ValueError("Password cannot be None")
        cdef mkey = MasterKey(master_key)
        cdef BaseKey derived = mkey.derive_key_from_password(password, ctx=ctx, opslimit=opslimit)
        return cls(derived)

    cpdef secretbox(self, ctx=None):
        return SecretBox(self, ctx=ctx)


cdef class EncryptedMessage:
    def __init__(self, const unsigned char[:] message, uint64_t msg_id):
        """
        Initialize the encrypted message.
        """
        if message is None:
            raise ValueError("Message cannot be None")
        self.message = message
        self.msg_id = msg_id

    def __bytes__(self):
        """
        Returns the encrypted message as a framed bytes object that could be sent over the wire.
        - The first 8 bytes are the length (N) of the encrypted message.
        - The next 8 bytes are the message ID.
        - The rest is the encrypted message (N bytes).
        """
        w = io.BytesIO()
        self.writeto(w)
        return w.getvalue()

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, EncryptedMessage):
            return False
        cdef EncryptedMessage o = <EncryptedMessage>other
        if self.msg_id != o.msg_id:
            return False
        if len(self.message) != len(o.message):
            return False
        return bytes(self.message) == bytes(o.message)

    cpdef writeto(self, fileobj):
        """
        Write the framed encrypted message to a file-like object.
        """
        if fileobj is None:
            raise ValueError("File object cannot be None")

        cdef bytearray header = bytearray(4 + 8 + 8)
        header[0:4] = ENC_MSG_HEADER
        cdef unsigned char[:] header_view = header
        store64(header_view[4:12], len(self.message))
        store64(header_view[12:20], self.msg_id)

        cdef SafeWriter w
        with FileOpener(fileobj, mode="wb") as f:
            w = SafeWriter(f)
            w.write(header)
            w.write(self.message)

    @classmethod
    def from_bytes(cls, const unsigned char[:] framed):
        if framed is None:
            raise ValueError("Framed message cannot be None")
        return cls.read_from(io.BytesIO(framed))

    @classmethod
    def read_from(cls, fileobj, *, max_msg_size=None):
        if fileobj is None:
            raise ValueError("File object cannot be None")
        cdef size_t msg_size = 0
        cdef uint64_t msg_id = 0
        cdef bytearray msg
        cdef bytearray header_buf = bytearray(20)
        cdef SafeReader r

        with FileOpener(fileobj, mode="rb") as f:
            r = SafeReader(f)
            try:
                r.readinto(header_buf)
            except OSError as ex:
                raise OSError("Failed to read next message header") from ex
            if header_buf[:4] != ENC_MSG_HEADER:
                raise ValueError("Invalid message header")
            msg_size = load64(header_buf[4:12])
            if max_msg_size is not None and msg_size > max_msg_size:
                raise ValueError("Message size exceeds maximum allowed size, {} > {}".format(msg_size, max_msg_size))
            msg_id = load64(header_buf[12:20])
            msg = bytearray(msg_size)
            try:
                r.readinto(msg)
            except OSError as ex:
                raise OSError("Failed to read message") from ex
            return cls(msg, msg_id)

    cpdef decrypt(self, key, ctx=None, out=None):
        """
        Decrypt the message using the secret box key and context.
        Returns the decrypted message as bytes.
        """
        if key is None:
            raise ValueError("Key cannot be None")
        return SecretBox(key, ctx=ctx).decrypt(self.message, msg_id=self.msg_id, out=out)


cdef class SecretBox:
    def __init__(self, key, *, ctx=None):
        """
        Initialize the secret box with a key and context.
        """
        if key is None:
            raise ValueError("Key cannot be None")
        self.key = SecretBoxKey(key)
        self.ctx = Context(ctx)

    cpdef encrypt(self, const unsigned char[:] plaintext, uint64_t msg_id=0, out=None):
        """
        Encrypt the plaintext using the secret box key and context.
        The optional msg_id can be used to differentiate between different messages.
        If out is provided, the framed ciphertext will be written to it.
        Returns the encrypted message as a bytes-like object.
        """
        if plaintext is None:
            raise ValueError("Plaintext cannot be None")
        cdef bytearray ciphertext = bytearray(len(plaintext) + hydro_secretbox_HEADERBYTES)
        try:
            secretbox_encrypt(plaintext, msg_id, self.ctx, self.key, ciphertext)
        except ValueError:
            raise
        except Exception as ex:
            raise EncryptException("Encryption failed") from ex
        cdef EncryptedMessage msg = EncryptedMessage(ciphertext, msg_id)
        if out is not None:
            msg.writeto(out)
        return msg.message

    cpdef decrypt(self, ciphertext, uint64_t msg_id=0, out=None):
        """
        Decrypt the ciphertext using the secret box key and context.
        The optional msg_id must match the one used during encryption.
        If out is provided, the plaintext will be written to it.
        """
        if ciphertext is None:
            raise ValueError("Ciphertext cannot be None")

        cdef const unsigned char[:] ciphertext_view
        if isinstance(ciphertext, EncryptedMessage):
            ciphertext_view = (<EncryptedMessage>ciphertext).message
            _id = (<EncryptedMessage>ciphertext).msg_id
            if msg_id != 0 and _id != msg_id:
                raise DecryptException("Message ID does not match")
            msg_id = _id
        else:
            ciphertext_view = ciphertext

        if len(ciphertext_view) < hydro_secretbox_HEADERBYTES:
            raise ValueError("Ciphertext is too short")
        cdef size_t plaintext_len = len(ciphertext_view) - hydro_secretbox_HEADERBYTES
        cdef bytearray plaintext = bytearray(plaintext_len)
        try:
            secretbox_decrypt(ciphertext_view, msg_id, self.ctx, self.key, plaintext)
        except ValueError:
            raise
        except Exception as ex:
            raise DecryptException("Decryption failed") from ex
        cdef SafeWriter w
        if out is not None:
            w = SafeWriter(out)
            w.write(plaintext)
        return bytes(plaintext)

    cpdef encrypt_file(self, src, dst, size_t chunk_size=io.DEFAULT_BUFFER_SIZE):
        """
        Encrypt a file-like object and write the ciphertext to another file-like object.
        """
        if src is None or dst is None:
            raise ValueError("Source and destination file objects cannot be None")
        with FileOpener(src, mode="rb") as src_obj, FileOpener(dst, mode="wb") as dst_obj:
            return self._encrypt_file(src_obj, dst_obj, chunk_size=chunk_size)

    cdef _encrypt_file(self, fileobj, out, size_t chunk_size=io.DEFAULT_BUFFER_SIZE):
        if fileobj is None or out is None:
            raise ValueError("Source and destination file objects cannot be None")
        if chunk_size <= hydro_secretbox_HEADERBYTES:
            raise ValueError("Chunk size must be greater than the header size")
        cdef Hash hasher = Hash(ctx=self.ctx, key=bytes(self.key))
        cdef uint64_t total_bytes_written = 0
        cdef bytearray buf = bytearray(chunk_size - hydro_secretbox_HEADERBYTES)     # the buffer used to read a chunk of the file
        cdef unsigned char[:] buf_view = buf
        cdef size_t n = 0               # the size of the current plaintext chunk
        cdef uint64_t msg_id = 1        # we will increment this for each chunk

        cdef SafeWriter w = SafeWriter(out)

        # write the max buffer size to the output file so that we can read it at decrypt time
        cdef bytearray header = bytearray(8)
        header[0:4] = ENC_MSG_HEADER
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

    cpdef decrypt_file(self, src, out):
        """
        Decrypt a file-like object and write the plaintext to another file-like object.
        """
        if src is None or out is None:
            raise ValueError("Source and destination file objects cannot be None")
        with FileOpener(src, mode="rb") as src_obj, FileOpener(out, mode="wb") as out_obj:
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

        cdef SafeReader r = SafeReader(fileobj)
        cdef SafeWriter w = SafeWriter(out)

        try:
            r.readinto(sbuf)
        except OSError as ex:
            raise OSError("Failed to read max buffer size") from ex
        if sbuf[:4] != ENC_MSG_HEADER:
            raise ValueError("Invalid message header")
        max_buf_size = load32(sbuf[4:8])
        tee = TeeWriter(w, hasher)

        while True:
            try:
                enc_msg = EncryptedMessage.read_from(r, max_msg_size=max_buf_size)
            except OSError:
                # we have reached the end of the file without having seen the hash
                raise DecryptException("final hash not found")
            if enc_msg.msg_id == 0:
                # if the message ID is 0, we assume it's the hash of the original file
                # we don't need to write it to the output file
                break
            if enc_msg.msg_id != msg_id:
                raise DecryptException("Invalid message ID")
            enc_msg.decrypt(self.key, ctx=self.ctx, out=tee)
            total_bytes_written += len(enc_msg.message) - hydro_secretbox_HEADERBYTES
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
