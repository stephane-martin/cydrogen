# cython: language_level=3


from ._decls cimport *


cpdef random_u32():
    """
    Generate a random 32-bit unsigned integer.
    """
    return hydro_random_u32()


cpdef random_uniform(uint32_t upper_bound):
    """
    Generate a random number uniformly distributed in the range [0, upper_bound).
    """
    return hydro_random_uniform(upper_bound)


cpdef randomize_buffer(unsigned char[:] buf):
    """
    Fill a buffer with random bytes.
    """
    if buf is None:
        raise ValueError("Buffer cannot be None")
    hydro_random_buf(<void*>&buf[0], len(buf))


cpdef gen_random_buffer(size_t size):
    """
    Generate a random buffer of the specified size.
    """
    if size == 0:
        return bytes()
    cdef bytearray buf = bytearray(size)
    randomize_buffer(buf)
    return bytes(buf)


cpdef shuffle_buffer(unsigned char[:] buf):
    """
    Shuffle a buffer in place.
    """
    if buf is None:
        raise ValueError("Buffer cannot be None")
    cdef size_t n = len(buf)
    if n == 0 or n == 1:
        return
    if n == 2:
        buf[0], buf[1] = buf[1], buf[0]
        return
    for i in range(n - 1, 0, -1):
        j = random_uniform(i + 1)
        buf[i], buf[j] = buf[j], buf[i]
