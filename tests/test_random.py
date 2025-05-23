import cydrogen


def test_random_u32():
    for _ in range(100):
        result = cydrogen.random_u32()
        assert isinstance(result, int)
        assert 0 <= result < 2**32


def test_random_uniform():
    upper_bound = 100
    for _ in range(100):
        result = cydrogen.random_uniform(upper_bound)
        assert isinstance(result, int)


def test_gen_random_buffer():
    size = 128
    for _ in range(100):
        result = cydrogen.gen_random_buffer(size)
        assert isinstance(result, bytes)
        assert len(result) == size
        assert result != size * b"\x00"


def test_randomize_buffer():
    # def randomize_buffer(buf: bytes) -> None
    size = 128
    for _ in range(100):
        buf = bytearray(size)
        cydrogen.randomize_buffer(buf)
        assert isinstance(buf, bytearray)
        assert len(buf) == size
        assert buf != size * b"\x00"
