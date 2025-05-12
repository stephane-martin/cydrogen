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
