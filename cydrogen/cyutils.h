#ifndef CYUTILS_H
#define CYUTILS_H 1

#if !defined(__clang__) && !defined(__GNUC__)
#    ifdef __attribute__
#        undef __attribute__
#    endif
#    define __attribute__(a)
#endif

#if !defined(__unix__) && (defined(__APPLE__) || defined(__linux__))
#    define __unix__ 1
#endif
#ifndef __GNUC__
#    define __restrict__
#endif

#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#    define NATIVE_BIG_ENDIAN
#endif
#ifndef NATIVE_BIG_ENDIAN
#    ifndef NATIVE_LITTLE_ENDIAN
#        define NATIVE_LITTLE_ENDIAN
#    endif
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

inline int cyd_is_little_endian(void) {
#ifdef NATIVE_LITTLE_ENDIAN
	return 1;
#else
	return 0;
#endif
}

inline int cyd_is_big_endian(void) {
#ifdef NATIVE_BIG_ENDIAN
	return 1;
#else
	return 0;
#endif
}

inline int cyd_have_mman(void) {
#ifdef HAVE_SYS_MMAN_H
	return 1;
#else
	return 0;
#endif
}

inline uint64_t cyd_load64_le(const uint8_t src[8]) {
#ifdef NATIVE_LITTLE_ENDIAN
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[0];
    w |= (uint64_t) src[1] <<  8;
    w |= (uint64_t) src[2] << 16;
    w |= (uint64_t) src[3] << 24;
    w |= (uint64_t) src[4] << 32;
    w |= (uint64_t) src[5] << 40;
    w |= (uint64_t) src[6] << 48;
    w |= (uint64_t) src[7] << 56;
    return w;
#endif
}

inline void cyd_store64_le(uint8_t dst[8], uint64_t w) {
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w; w >>= 8;
    dst[4] = (uint8_t) w; w >>= 8;
    dst[5] = (uint8_t) w; w >>= 8;
    dst[6] = (uint8_t) w; w >>= 8;
    dst[7] = (uint8_t) w;
#endif
}

inline uint32_t cyd_load32_le(const uint8_t src[4]) {
#ifdef NATIVE_LITTLE_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[0];
    w |= (uint32_t) src[1] <<  8;
    w |= (uint32_t) src[2] << 16;
    w |= (uint32_t) src[3] << 24;
    return w;
#endif
}

inline void cyd_store32_le(uint8_t dst[4], uint32_t w) {
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w;
#endif
}

inline uint16_t cyd_load16_le(const uint8_t src[2]) {
#ifdef NATIVE_LITTLE_ENDIAN
    uint16_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint16_t w = (uint16_t) src[0];
    w |= (uint16_t) src[1] << 8;
    return w;
#endif
}

inline void cyd_store16_le(uint8_t dst[2], uint16_t w) {
#ifdef NATIVE_LITTLE_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w;
#endif
}


inline uint64_t cyd_load64_be(const uint8_t src[8]) {
#ifdef NATIVE_BIG_ENDIAN
    uint64_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint64_t w = (uint64_t) src[7];
    w |= (uint64_t) src[6] <<  8;
    w |= (uint64_t) src[5] << 16;
    w |= (uint64_t) src[4] << 24;
    w |= (uint64_t) src[3] << 32;
    w |= (uint64_t) src[2] << 40;
    w |= (uint64_t) src[1] << 48;
    w |= (uint64_t) src[0] << 56;
    return w;
#endif
}

inline void cyd_store64_be(uint8_t dst[8], uint64_t w) {
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[7] = (uint8_t) w; w >>= 8;
    dst[6] = (uint8_t) w; w >>= 8;
    dst[5] = (uint8_t) w; w >>= 8;
    dst[4] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

inline uint32_t cyd_load32_be(const uint8_t src[4]) {
#ifdef NATIVE_BIG_ENDIAN
    uint32_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint32_t w = (uint32_t) src[3];
    w |= (uint32_t) src[2] <<  8;
    w |= (uint32_t) src[1] << 16;
    w |= (uint32_t) src[0] << 24;
    return w;
#endif
}

inline void cyd_store32_be(uint8_t dst[4], uint32_t w) {
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[3] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

inline uint16_t cyd_load16_be(const uint8_t src[2]) {
#ifdef NATIVE_BIG_ENDIAN
    uint16_t w;
    memcpy(&w, src, sizeof w);
    return w;
#else
    uint16_t w = (uint16_t) src[1];
    w |= (uint16_t) src[0] << 8;
    return w;
#endif
}

inline void cyd_store16_be(uint8_t dst[2], uint16_t w) {
#ifdef NATIVE_BIG_ENDIAN
    memcpy(dst, &w, sizeof w);
#else
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

int cyd_is_zero(const unsigned char *n, const size_t nlen);
void cyd_memzero(void * const pnt, const size_t len);
int cyd_memcmp(const void * const b1_, const void * const b2_, size_t len) __attribute__ ((warn_unused_result));
int cyd_compare(const unsigned char *b1_, const unsigned char *b2_, size_t len) __attribute__ ((warn_unused_result));

int cyd_mlock(void * const addr, const size_t len) __attribute__ ((nonnull));
int cyd_munlock(void * const addr, const size_t len) __attribute__ ((nonnull));
int cyd_mprotect_noaccess(void *ptr) __attribute__ ((nonnull));
int cyd_mprotect_readonly(void *ptr) __attribute__ ((nonnull));
int cyd_mprotect_readwrite(void *ptr) __attribute__ ((nonnull));

void *cyd_malloc(const size_t size) __attribute__ ((malloc));
void *cyd_allocarray(size_t count, size_t size) __attribute__ ((malloc));
void cyd_free(void *ptr);

#endif
