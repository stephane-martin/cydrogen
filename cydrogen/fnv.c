#include "fnv.h"

#define PY_UHASH_CPY(dst, src) do {                                     \
	dst[0] = src[0]; dst[1] = src[1]; dst[2] = src[2]; dst[3] = src[3]; \
    dst[4] = src[4]; dst[5] = src[5]; dst[6] = src[6]; dst[7] = src[7]; \
} while(0)

#define PyHASH_MULTIPLIER 1000003UL

int64_t fnv_impl(const void *src, uint64_t len, uint32_t prefix, uint32_t suffix) {
    const unsigned char *p = src;
    uint64_t x;
    uint64_t remainder, blocks;
    union {
        uint64_t value;
        unsigned char bytes[8];
    } block;

    remainder = len % 8;
    if (remainder == 0) {
        remainder = 8;
    }
    blocks = (len - remainder) / 8;

    x = (uint64_t) prefix;
    x ^= (uint64_t) *p << 7;
    while (blocks--) {
        PY_UHASH_CPY(block.bytes, p);
        x = (PyHASH_MULTIPLIER * x) ^ block.value;
        p += 8;
    }
    /* add remainder */
    for (; remainder > 0; remainder--)
        x = (PyHASH_MULTIPLIER * x) ^ (uint64_t) *p++;
    x ^= (uint64_t) len;

    x ^= (uint64_t) suffix;
    if (x == (uint64_t) -1) {
        x = (uint64_t) -2;
    }
    return x;
}
