# cython: language_level=3

from libc.stdint cimport uint32_t


cpdef random_u32()
cpdef random_uniform(uint32_t upper_bound)
cpdef randomize_buffer(unsigned char[:] buf)
cpdef gen_random_buffer(size_t size)
