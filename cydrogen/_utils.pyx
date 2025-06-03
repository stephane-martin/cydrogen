# cython: language_level=3

cimport cython

from cpython.buffer cimport PyBuffer_FillInfo, PyBUF_WRITABLE
from libc.stdint cimport uint64_t
from libc.stdint cimport uint32_t
from libc.stdint cimport uint16_t

import io
import os
import pathlib
import tempfile


cdef class SafeMemory:
    def __cinit__(self, size_t size):
        if size == 0:
            return
        self.ptr = cyd_malloc(size)
        if self.ptr != NULL:
            self.size = size
            cyd_memzero(self.ptr, self.size)

    def __dealloc__(self):
        if self.ptr != NULL:
            cyd_free(self.ptr)

    def __init__(self, size_t size):
        if size == 0:
            raise ValueError("size must be greater than 0")
        if self.ptr == NULL:
            raise MemoryError("Failed to allocate memory")
        self.readonly_protected = 0

    def __len__(self):
        return self.size

    def __getbuffer__(self, Py_buffer *buffer, int flags):
        if flags & PyBUF_WRITABLE:
            # consumer is asking for writable buffer
            if self.readonly_protected:
                raise ValueError("Memory is read-only, cannot provide writable buffer")
            PyBuffer_FillInfo(buffer, self, self.ptr, self.size, 0, flags)
        else:
            PyBuffer_FillInfo(buffer, self, self.ptr, self.size, 1, flags)

    def __eq__(self, other):
        if other is None:
            return False
        if not isinstance(other, SafeMemory):
            return False
        cdef SafeMemory o = <SafeMemory>other
        if self.size != o.size:
            return False
        if self.ptr == o.ptr:
            return True
        return cyd_memcmp(self.ptr, o.ptr, self.size) == 0

    def __bool__(self):
        return cyd_is_zero(<const unsigned char*>(self.ptr), self.size) == 0

    cdef set(self, const unsigned char[:] data):
        if self.readonly_protected == 1:
            raise ValueError("Memory is read-only")
        if data is None:
            raise ValueError("Data cannot be None")
        if len(data) != len(self):
            raise ValueError(f"Data must be {self.size} bytes long, got {len(data)} bytes")
        if len(data) == 0:
            self.mark_readonly()
            return
        cdef unsigned char[:] view = self
        view[0:len(self)] = data[0:len(self)]
        del view
        self.mark_readonly()

    cdef set_zero(self):
        if self.readonly_protected == 1:
            raise ValueError("Memory is read-only")
        cyd_memzero(self.ptr, self.size)
        self.mark_readonly()

    cdef mark_readonly(self):
        if self.readonly_protected:
            return
        mprotect_readonly(self.ptr)
        self.readonly_protected = 1

    cdef writeto(self, out):
        if out is None:
            raise ValueError("Output cannot be None")
        cdef SafeWriter w = SafeWriter(out)
        return w.write(self)

    @classmethod
    def read_from(cls, reader, size_t size):
        if reader is None:
            raise ValueError("reader cannot be None")
        cdef SafeMemory mem = cls(size)
        if size == 0:
            mem.mark_readonly()
            return mem
        cdef SafeReader r = SafeReader(reader)
        cdef size_t n = r.readinto(mem)
        if n < size:
            raise ValueError(f"Expected to read {size} bytes, but got {n} bytes")
        mem.mark_readonly()
        return mem

    @classmethod
    def from_buffer(cls, const unsigned char[:] data):
        if data is None:
            raise ValueError("data cannot be None")
        cdef SafeMemory mem = cls(len(data))
        if len(data) == 0:
            mem.mark_readonly()
            return mem
        mem.set(data)
        return mem


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


cdef uint64_t _load64(const unsigned char[:] src) noexcept nogil:
    with cython.boundscheck(False):
        return cyd_load64_be(&src[0])


cdef void _store64(unsigned char[:] dst, uint64_t src) noexcept nogil:
    with cython.boundscheck(False):
        cyd_store64_be(&dst[0], src)


cdef uint32_t _load32(const unsigned char[:] src) noexcept nogil:
    with cython.boundscheck(False):
        return cyd_load32_be(&src[0])


cdef void _store32(unsigned char[:] dst, uint32_t src) noexcept nogil:
    with cython.boundscheck(False):
        cyd_store32_be(&dst[0], src)


cdef uint16_t _load16(const unsigned char[:] src) noexcept nogil:
    with cython.boundscheck(False):
        return cyd_load16_be(&src[0])


cdef void _store16(unsigned char[:] dst, uint16_t src) noexcept nogil:
    with cython.boundscheck(False):
        cyd_store16_be(&dst[0], src)


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
        if mode not in ("rb", "wb", "ab"):
            raise ValueError("mode must be 'rb', 'wb', or 'ab'")
        self.fileobj = None
        self.path = None
        self.mode = mode
        if isinstance(fileobj_or_path, (str, os.PathLike)):
            self.path = pathlib.Path(fileobj_or_path)
            return
        if isinstance(fileobj_or_path, (io.IOBase, SafeReader, SafeWriter, tempfile._TemporaryFileWrapper)):
            self.fileobj = fileobj_or_path
            return
        raise TypeError("fileobj must be path-like or a file-like")

    cdef __enter__(self):
        if self.path is not None:
            self.fileobj = open(self.path, self.mode)
        return self.fileobj

    def __exit__(self, exc_type, exc_value, traceback):
        if self.path is not None:
            self.fileobj.close()


cdef class SafeReader:
    def __init__(self, fileobj):
        if fileobj is None:
            raise ValueError("fileobj cannot be None")
        if not hasattr(fileobj, "read"):
            raise TypeError("fileobj must be a file-like object with a 'read' method")
        self.fileobj = fileobj
        self.direct = isinstance(fileobj, (SafeReader, io.BufferedReader, io.BytesIO, io.BufferedRandom))
        self.has_readinto = hasattr(fileobj, "readinto")

    cpdef readinto(self, unsigned char[:] buf):
        if len(buf) == 0:
            return 0
        if self.direct and self.has_readinto:
            return self.fileobj.readinto(buf)
        cdef bytes tmp = self.read(len(buf))
        if len(tmp) == 0:
            return 0
        cdef const unsigned char[:] view = tmp
        buf[0:len(tmp)] = view
        return len(tmp)

    cpdef read(self, size_t length=io.DEFAULT_BUFFER_SIZE):
        if length == 0:
            return b""
        if self.direct == 1:
            return self.fileobj.read(length)

        cdef bytearray result = bytearray(length)
        cdef size_t offset = 0
        cdef bytes tmp
        cdef const unsigned char[:] view

        while offset < length:
            tmp = self.fileobj.read(length - offset)
            if len(tmp) == 0:
                return bytes(result[:offset])
            view = tmp
            result[offset:offset + len(tmp)] = view
            offset += len(tmp)

        return bytes(result[0:offset])


cdef class SafeWriter:
    def __init__(self, fileobj):
        if fileobj is None:
            raise ValueError("fileobj cannot be None")
        if not hasattr(fileobj, "write"):
            raise TypeError("fileobj must be a file-like object with a 'write' method")
        self.fileobj = fileobj
        self.direct = isinstance(fileobj, (SafeWriter, io.BufferedWriter, io.BytesIO, io.BufferedRandom))

    cpdef write(self, const unsigned char[:] buf):
        if buf is None:
            raise ValueError("buf cannot be None")
        if self.direct == 1:
            return self.fileobj.write(buf)
        cdef size_t length = len(buf)
        cdef size_t offset = 0
        cdef size_t n = 0
        while offset < length:
            n = self.fileobj.write(buf[offset:length])
            if n == 0:
                return offset
            offset += n
        return length


cdef class TeeWriter:
    def __init__(self, w1, w2):
        self.w1 = SafeWriter(w1)
        self.w2 = SafeWriter(w2)

    cpdef write(self, const unsigned char[:] buf):
        cdef size_t n1 = self.w1.write(buf)
        cdef size_t n2 = self.w2.write(buf)
        if n1 != n2:
            raise IOError("Writers did not write the same number of bytes")
        return n1
