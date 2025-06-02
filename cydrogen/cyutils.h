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

int cyd_is_little_endian(void);
int cyd_is_big_endian(void);
int cyd_have_mman(void);

uint64_t cyd_load64_le(const uint8_t src[8]);
void cyd_store64_le(uint8_t dst[8], uint64_t w);
uint32_t cyd_load32_le(const uint8_t src[4]);
void cyd_store32_le(uint8_t dst[4], uint32_t w);
uint16_t cyd_load16_le(const uint8_t src[2]);
void cyd_store16_le(uint8_t dst[2], uint16_t w);
uint64_t cyd_load64_be(const uint8_t src[8]);
void cyd_store64_be(uint8_t dst[8], uint64_t w);
uint32_t cyd_load32_be(const uint8_t src[4]);
void cyd_store32_be(uint8_t dst[4], uint32_t w);
uint16_t cyd_load16_be(const uint8_t src[2]);
void cyd_store16_be(uint8_t dst[2], uint16_t w);

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
