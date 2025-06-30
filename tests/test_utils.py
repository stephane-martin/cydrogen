import asyncio
import io
import tempfile
import threading
from collections.abc import Buffer

import pytest
from cydrogen._protocols import Reader, Writer
from cydrogen._utils import AsyncSafeReader, Counter, FileOpener, SafeMemory, SafeReader, SafeWriter


def increment_counter(counter: Counter):
    for _ in range(10000):
        # each call to value() increments the counter by 2
        counter.value()


def test_counter():
    c = Counter()
    assert c.value() == 1
    # here the internal counter is 3

    t1 = threading.Thread(target=increment_counter, args=(c,))
    t2 = threading.Thread(target=increment_counter, args=(c,))
    t1.start()
    t2.start()
    t2.join()
    t1.join()

    # each thread increments the counter by 20000
    assert c.value() == 40003


def test_init_zero_safe_memory() -> None:
    zero = SafeMemory(0)
    assert zero.readonly
    assert len(zero) == 0
    assert bytes(zero) == b""
    assert not zero


def test_init_safe_memory() -> None:
    sm = SafeMemory(32)
    assert sm.readonly
    assert len(sm) == 32
    assert bytes(sm) == b"\x00" * 32
    assert not sm


def test_negative_size_safe_memory() -> None:
    with pytest.raises(OverflowError):
        SafeMemory(-1)


def test_safe_memory_from_buffer() -> None:
    sm = SafeMemory.from_buffer(b"")
    assert len(sm) == 0
    assert bytes(sm) == b""
    assert sm.readonly
    assert not sm

    sm2 = SafeMemory.from_buffer(b"foobar")
    assert len(sm2) == 6
    assert bytes(sm2) == b"foobar"
    assert sm2.readonly
    assert sm2

    sm3 = SafeMemory.from_buffer(sm2)
    assert len(sm3) == 6
    assert bytes(sm3) == b"foobar"
    assert sm3.readonly
    assert sm3


def test_safe_memory_from_buffer_invalid() -> None:
    with pytest.raises(TypeError):
        SafeMemory.from_buffer(123)  # type: ignore[arg-type]


def test_safe_memory_equal() -> None:
    sm1 = SafeMemory.from_buffer(b"test")
    sm2 = SafeMemory.from_buffer(b"test")
    sm3 = SafeMemory.from_buffer(b"TEST")

    assert sm1 == sm2
    assert sm1 != sm3
    assert sm2 != sm3

    # Check that SafeMemory is not equal to other types
    assert sm1 != b"test"
    assert sm1 != "test"
    assert sm1 != 123


def test_safe_memory_hashable() -> None:
    assert hash(SafeMemory.from_buffer(b"")) == 0

    sm = SafeMemory.from_buffer(b"test")
    sm2 = SafeMemory.from_buffer(b"test")
    assert hash(sm) == hash(sm2)

    sm3 = SafeMemory.from_buffer(b"TEST")
    assert hash(sm) != hash(sm3)


def test_too_big_safe_memory() -> None:
    with pytest.raises(ValueError):
        SafeMemory(100000)  # This is larger than the maximum size of a memoryview


def test_safe_memory_is_buffer() -> None:
    sm = SafeMemory.from_buffer(b"test")
    mv = memoryview(sm)
    assert mv.readonly
    assert mv.tobytes() == b"test"


def test_safe_memory_read_from() -> None:
    b = io.BytesIO(b"test data")
    sm = SafeMemory.read_from(b, 4)
    assert len(sm) == 4
    assert bytes(sm) == b"test"
    assert sm.readonly
    assert sm


def test_safe_memory_read_from_too_short() -> None:
    b = io.BytesIO(b"short")
    with pytest.raises(ValueError):
        SafeMemory.read_from(b, 10)


class SlowReader:
    def __init__(self, reader: Reader) -> None:
        self._reader = reader

    def read(self, length: int = -1) -> bytes:  # noqa: ARG002
        return self._reader.read(1)  # Simulate slow reading by reading one byte at a time


class SlowReaderWithReadinto(SlowReader):
    def readinto(self, buf) -> int:  # noqa: ANN001
        if not buf:
            return 0
        data = self._reader.read(1)
        if not data:
            return 0
        buf[0] = data[0]
        return 1


@pytest.fixture
def slow_reader() -> Reader:
    data = b"abracadabra"
    return SlowReader(io.BytesIO(data))


def test_safe_memory_read_from_slow_reader(slow_reader: Reader) -> None:
    sm = SafeMemory.read_from(slow_reader, 5)
    assert len(sm) == 5
    assert bytes(sm) == b"abrac"
    assert sm.readonly
    assert sm

    # Ensure that reading more than available data raises an error
    with pytest.raises(ValueError):
        SafeMemory.read_from(slow_reader, 20)  # Only 11 bytes available in the original data


def test_safe_memory_build() -> None:
    def cb(mv: memoryview) -> None:
        mv[0:6] = b"foobar"

    sm = SafeMemory.build(6, cb)
    assert len(sm) == 6
    assert bytes(sm) == b"foobar"
    assert sm.readonly
    assert sm

    with pytest.raises(ValueError):
        SafeMemory.build(5, cb)

    sm2 = SafeMemory.build(7, cb)
    assert len(sm2) == 7
    assert bytes(sm2) == b"foobar\x00"


def test_file_opener():
    b = io.BytesIO(b"foobar")
    b.seek(0)
    with FileOpener(b) as f:
        assert f.read() == b"foobar"

    with tempfile.TemporaryFile() as f:
        f.write(b"test data")
        f.flush()
        f.seek(0)
        with FileOpener(f) as opener:
            assert opener.read() == b"test data"

    with tempfile.NamedTemporaryFile() as f:
        f.write(b"temporary file data")
        f.flush()
        f.seek(0)
        with FileOpener(f) as opener:
            assert opener.read() == b"temporary file data"
        f.seek(0)
        with FileOpener(f.name) as opener:
            assert opener.read() == b"temporary file data"


def test_file_opener_safe_reader(slow_reader: Reader) -> None:
    r = SafeReader(slow_reader)
    with FileOpener(r) as opener:
        assert opener.read(8192) == b"abracadabra"


def test_file_opener_invalid():
    with pytest.raises(TypeError):
        FileOpener(123)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        FileOpener(None)  # type: ignore[arg-type]


_DATA = 32 * b"A" + 32 * b"B" + 32 * b"C"


_READERS: list[Reader | bytes] = [
    _DATA,
    io.BytesIO(_DATA),
    SlowReader(io.BytesIO(_DATA)),
    SafeReader(io.BytesIO(_DATA)),
    SlowReaderWithReadinto(io.BytesIO(_DATA)),
]


@pytest.fixture(params=_READERS)
def reader(request: pytest.FixtureRequest) -> Reader:
    if not isinstance(request.param, bytes):
        yield request.param
        return
    f = tempfile.TemporaryFile()  # noqa: SIM115
    f.write(request.param)
    f.seek(0)
    yield f
    f.close()


def test_safe_reader(reader: Reader):
    safe_reader = SafeReader(reader)
    b = bytearray(32)
    n = safe_reader.readinto(b)
    assert b == _DATA[0:32]
    assert n == 32
    all_b = safe_reader.read(32)
    assert all_b == _DATA[32:64]
    remaining = safe_reader.read(1024)
    assert remaining == _DATA[64:96]
    empty = safe_reader.read(1024)
    assert empty == b""


class AsyncBytesIOReader:
    def __init__(self, data: Buffer) -> None:
        self.b = io.BytesIO(data)

    async def read(self, length: int = -1) -> bytes:  # noqa: ARG002
        # Simulate async behavior
        await asyncio.sleep(0)
        # we read byte by byte to check that we will handle a full read correctly
        return self.b.read(1)


@pytest.mark.asyncio(loop_scope="module")
async def test_async_safe_reader() -> None:
    safe_reader = AsyncSafeReader(AsyncBytesIOReader(_DATA))
    all_a = await safe_reader.readexactly(32)
    assert all_a == _DATA[0:32]
    all_b = await safe_reader.readexactly(32)
    assert all_b == _DATA[32:64]
    with pytest.raises(EOFError):
        await safe_reader.readexactly(1024)


@pytest.mark.asyncio(loop_scope="module")
async def test_async_safe_reader_stream_reader() -> None:
    r = asyncio.StreamReader()
    r.feed_data(_DATA)
    r.feed_eof()
    safe_reader = AsyncSafeReader(r)
    all_a = await safe_reader.readexactly(32)
    assert all_a == _DATA[0:32]
    all_b = await safe_reader.readexactly(32)
    assert all_b == _DATA[32:64]
    with pytest.raises(EOFError):
        await safe_reader.readexactly(1024)


class SlowWriter:
    def __init__(self, writer: Writer) -> None:
        self._writer = writer

    def write(self, data: Buffer) -> int:
        b = bytes(data)
        if not b:
            return 0
        return self._writer.write(b[0:1])  # Simulate slow writing by writing one byte at a time


def test_safe_writer() -> None:
    b = io.BytesIO()
    w = SlowWriter(b)
    safew = SafeWriter(w)
    safew.write(_DATA)
    assert b.getvalue() == _DATA
