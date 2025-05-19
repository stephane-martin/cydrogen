# cython: language_level=3

import io
import pathlib


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
