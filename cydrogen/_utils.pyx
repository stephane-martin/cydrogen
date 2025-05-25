# cython: language_level=3

from libc.stdint cimport uint64_t
from libc.stdint cimport uint32_t
from libc.stdint cimport uint16_t

import io
import pathlib


cdef mprotect_readonly(void *ptr):
    if cyd_mprotect_readonly(ptr) != 0:
        raise OSError("Failed to change memory protection to read-only")


cdef uint8_t* malloc_key(size_t size) noexcept nogil:
    return <uint8_t*>cyd_malloc(size)


cdef void free_key(uint8_t* ptr) noexcept nogil:
    cyd_free(ptr)


cdef key_is_zero(const unsigned char[:] key):
    if key is None:
        raise ValueError("key cannot be None")
    cdef size_t lenk = len(key)
    if lenk == 0:
        return True
    return cyd_is_zero(&key[0], lenk) == 1


cpdef load64(const unsigned char[:] src):
    if len(src) < 8:
        raise ValueError(f"src must be 8 bytes long, got {len(src)} bytes")
    return _load64(src)


cpdef store64(unsigned char[:] dst, uint64_t src):
    if len(dst) < 4:
        raise ValueError(f"dst must be 8 bytes long, got {len(dst)} bytes")
    _store64(dst, src)


cpdef load32(const unsigned char[:] src):
    if len(src) < 4:
        raise ValueError(f"src must be 4 bytes long, got {len(src)} bytes")
    return _load32(src)


cpdef store32(unsigned char[:] dst, uint32_t src):
    if len(dst) < 4:
        raise ValueError(f"dst must be 4 bytes long, got {len(dst)} bytes")
    _store32(dst, src)


cpdef load16(const unsigned char[:] src):
    if len(src) < 2:
        raise ValueError(f"src must be 2 bytes long, got {len(src)} bytes")
    return _load16(src)


cpdef store16(unsigned char[:] dst, uint16_t src):
    if len(dst) < 2:
        raise ValueError(f"dst must be 2 bytes long, got {len(dst)} bytes")
    _store16(dst, src)


def have_mman():
    return cyd_have_mman() == 1


def little_endian():
    return cyd_is_little_endian() == 1


def big_endian():
    return cyd_is_big_endian() == 1


cdef class FileOpener:
    def __init__(self, fileobj_or_path, *, mode="rb"):
        if fileobj_or_path is None:
            raise ValueError("fileobj_or_path cannot be None")
        self.fileobj = None
        self.path = None
        self.mode = mode
        if self.mode not in ("rb", "wb"):
            raise ValueError("mode must be 'rb' or 'wb'")
        if isinstance(fileobj_or_path, str) or isinstance(fileobj_or_path, pathlib.Path):
            self.path = pathlib.Path(fileobj_or_path)
        elif isinstance(fileobj_or_path, io.IOBase) or isinstance(fileobj_or_path, SafeReader) or isinstance(fileobj_or_path, SafeWriter):
            self.fileobj = fileobj_or_path
        else:
            raise TypeError("fileobj must be a string, pathlib.Path, or a file-like object")

    cdef __enter__(self):
        if self.path is not None:
            self.fileobj = open(self.path, self.mode)
        return self.fileobj

    def __exit__(self, exc_type, exc_value, traceback):
        if self.path is not None:
            self.fileobj.close()


cdef class SafeReader:
    """
    SafeReader is a wrapper around a file-like object that ensures all requested bytes are read.
    """

    def __init__(self, fileobj):
        if fileobj is None:
            raise ValueError("fileobj cannot be None")
        self.direct = 0
        self.fileobj = fileobj
        if isinstance(fileobj, SafeReader) or isinstance(fileobj, io.BufferedReader):
            self.direct = 1

    cpdef readinto(self, unsigned char[:] buf):
        """
        Read bytes into the buffer. Raises OSError if not all bytes can't be read.
        """
        if buf is None:
            raise ValueError("buf cannot be None")
        if self.direct == 1:
            return self.fileobj.readinto(buf)
        cdef size_t offset = 0
        cdef size_t remaining = len(buf)
        cdef size_t n = 0

        while remaining > 0:
            n = self.fileobj.readinto(buf[offset:offset + remaining])
            if n == 0:
                raise OSError("Failed to read all bytes")
            offset += n
            remaining -= n
        return len(buf)

    cpdef read(self, size_t length):
        """
        Read a specific number of bytes from the file-like object.
        Raises OSError if not all bytes can't be read.
        """
        cdef bytearray buf = bytearray(length)
        self.readinto(buf)
        return bytes(buf)


cdef class SafeWriter:
    """
    SafeWriter is a wrapper around a file-like object that ensures all requested bytes are written.
    """

    def __init__(self, fileobj):
        if fileobj is None:
            raise ValueError("fileobj cannot be None")
        self.direct = 0
        self.fileobj = fileobj
        if isinstance(fileobj, SafeWriter) or isinstance(fileobj, io.BufferedWriter):
            self.direct = 1

    cpdef write(self, const unsigned char[:] buf):
        """
        Write bytes to the file-like object. Raises OSError if not all bytes can't be written.
        """
        if buf is None:
            raise ValueError("buf cannot be None")
        if self.direct == 1:
            return self.fileobj.write(buf)
        cdef size_t offset = 0
        cdef size_t remaining = len(buf)
        cdef size_t n = 0

        while remaining > 0:
            n = self.fileobj.write(buf[offset:offset + remaining])
            if n == 0:
                raise OSError("Failed to write all bytes")
            offset += n
            remaining -= n
        return len(buf)


cdef class TeeWriter:
    def __init__(self, w1, w2):
        self.w1 = SafeWriter(w1)
        self.w2 = SafeWriter(w2)

    cpdef write(self, const unsigned char[:] buf):
        """
        Write the buffer to both writers.
        """
        self.w1.write(buf)
        self.w2.write(buf)
        return len(buf)
