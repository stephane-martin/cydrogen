# cython: language_level=3

from libc.stdint cimport uint64_t
from libc.stdint cimport uint32_t

from ._basekey cimport BaseKey
from ._context cimport make_context
from ._hash cimport Hash, HashKey
from ._masterkey cimport MasterKey, make_masterkey
from ._sign import SignPublicKey, SignSecretKey, SignKeyPair
from ._utils cimport FileOpener, SafeMemory, TeeWriter, make_safe_reader, make_safe_writer
from ._utils cimport store32, load32
from ._decls cimport hydro_secretbox_HEADERBYTES, secretbox_encrypt, secretbox_decrypt
from ._datastructs cimport EncryptedMessage, CY_ENC_MSG_MARKER, CY_ENC_MSG_HEADER_SIZE, encrypted_message_header

import base64

from .exceptions import DecryptException, EncryptException, MessageTooBigException


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

    def __hash__(self):
        return hash(self.key)

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


cdef class SecretBox:
    def __init__(self, key, *, ctx=None):
        if key is None:
            raise ValueError("Key cannot be None")
        self.key = make_secretbox_key(key)
        self.ctx = make_context(ctx)

    cpdef encrypt(self, const unsigned char[:] plaintext, uint64_t msg_id=0, out=None, max_msg_size=None):
        if plaintext is None:
            raise ValueError("Plaintext cannot be None")
        if max_msg_size is not None and len(plaintext) > max_msg_size:
            raise MessageTooBigException
        if out is not None:
            make_safe_writer(out)  # ensure out is a file-like object
        cdef bytearray ciphertext = bytearray(len(plaintext) + hydro_secretbox_HEADERBYTES)
        try:
            secretbox_encrypt(plaintext, msg_id, self.ctx, self.key, ciphertext)
        except ValueError:
            raise
        except Exception as ex:
            raise EncryptException("Encryption failed") from ex
        if out is not None:
            # write the framed encrypted message to the output writer
            w = make_safe_writer(out)
            w.write(encrypted_message_header(ciphertext, msg_id))
            w.write(ciphertext)
        return ciphertext

    cpdef decrypt(self, ciphertext, uint64_t msg_id=0, out=None, max_msg_size=None):
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
        plaintext_len = len(ciphertext) - hydro_secretbox_HEADERBYTES
        if max_msg_size is not None and plaintext_len > max_msg_size:
            raise MessageTooBigException
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
        header[0:4] = CY_ENC_MSG_MARKER
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
            total_bytes_written += n + hydro_secretbox_HEADERBYTES + CY_ENC_MSG_HEADER_SIZE
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
        if sbuf[:4] != CY_ENC_MSG_MARKER:
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
            self.decrypt(enc_msg, out=tee)
            total_bytes_written += len(enc_msg.ciphertext) - hydro_secretbox_HEADERBYTES
            msg_id += 1

        # the last encrypted message contains hash of the original file
        # we need to compare it with the hash of the decrypted file
        transmitted_hash = self.decrypt(enc_msg)
        if len(transmitted_hash) != hasher.digest_size:
            raise DecryptException("Invalid hash length")
        computed_hash = hasher.digest()
        if transmitted_hash != computed_hash:
            raise DecryptException("Invalid hash")
        return total_bytes_written
