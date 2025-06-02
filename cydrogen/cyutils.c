#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(HAVE_RAISE) && !defined(__wasm__)
#    include <signal.h>
#endif

#ifdef HAVE_SYS_MMAN_H
#    include <sys/mman.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#    include <sys/param.h>
#endif

#ifdef _WIN32
#    include <windows.h>
#    include <wincrypt.h>
#else
#    include <unistd.h>
#endif

#include "cyutils.h"
#include "cyd_memcpy_s.h"

#ifndef ENOSYS
#    define ENOSYS ENXIO
#endif

#if defined(_WIN32) && (!defined(WINAPI_FAMILY) || WINAPI_FAMILY == WINAPI_FAMILY_DESKTOP_APP)
#    define WINAPI_DESKTOP
#endif

#define CANARY_SIZE 16U
#define GARBAGE_VALUE 0xdb

#ifndef MAP_NOCORE
#    ifdef MAP_CONCEAL
#        define MAP_NOCORE MAP_CONCEAL
#    else
#        define MAP_NOCORE 0
#    endif
#endif
#if !defined(MAP_ANON) && defined(MAP_ANONYMOUS)
#    define MAP_ANON MAP_ANONYMOUS
#endif

#if defined(WINAPI_DESKTOP) || (defined(MAP_ANON) && defined(HAVE_MMAP)) || defined(HAVE_POSIX_MEMALIGN)
#    define HAVE_ALIGNED_MALLOC
#endif

#if defined(HAVE_MPROTECT) && !(defined(PROT_NONE) && defined(PROT_READ) && defined(PROT_WRITE))
#    undef HAVE_MPROTECT
#endif

#if defined(HAVE_ALIGNED_MALLOC) && (defined(WINAPI_DESKTOP) || defined(HAVE_MPROTECT))
#    define HAVE_PAGE_PROTECTION
#endif

#if !defined(MADV_DODUMP) && defined(MADV_CORE)
#    define MADV_DODUMP   MADV_CORE
#    define MADV_DONTDUMP MADV_NOCORE
#endif


#ifndef DEFAULT_PAGE_SIZE
#    ifdef PAGE_SIZE
#        define DEFAULT_PAGE_SIZE PAGE_SIZE
#    else
#        define DEFAULT_PAGE_SIZE 0x10000
#    endif
#endif

size_t cyd_page_size = DEFAULT_PAGE_SIZE;
unsigned char cyd_canary[CANARY_SIZE];

#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void _cyd_dummy_symbol_to_prevent_memzero_lto(void *const pnt, const size_t len);

__attribute__((weak)) void _cyd_dummy_symbol_to_prevent_memzero_lto(void *const pnt, const size_t len) {
    (void) pnt;
    (void) len;
}
#endif

void cyd_memzero(void * const pnt, const size_t len) {
#if defined(_WIN32) && !defined(__CRT_INLINE)
    SecureZeroMemory(pnt, len);
#elif defined(HAVE_MEMSET_S)
    if (len > 0U && memset_s(pnt, (rsize_t) len, 0, (rsize_t) len) != 0) {
        abort();
    }
#elif defined(HAVE_EXPLICIT_BZERO)
    explicit_bzero(pnt, len);
#elif defined(HAVE_MEMSET_EXPLICIT)
    memset_explicit(pnt, 0, len);
#elif defined(HAVE_EXPLICIT_MEMSET)
    explicit_memset(pnt, 0, len);
#elif HAVE_WEAK_SYMBOLS
    if (len > 0U) {
        memset(pnt, 0, len);
        _cyd_dummy_symbol_to_prevent_memzero_lto(pnt, len);
    }
#else
    volatile unsigned char *volatile pnt_ = (volatile unsigned char *volatile) pnt;
    size_t i = (size_t) 0U;
    while (i < len) {
        pnt_[i++] = 0U;
    }
#endif
}

#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void _cyd_dummy_symbol_to_prevent_memcmp_lto(const unsigned char *b1, const unsigned char *b2, const size_t len);
__attribute__((weak)) void _cyd_dummy_symbol_to_prevent_memcmp_lto(const unsigned char *b1, const unsigned char *b2, const size_t len) {
    (void) b1;
    (void) b2;
    (void) len;
}
#endif

int cyd_memcmp(const void *const b1_, const void *const b2_, size_t len) {
#ifdef HAVE_WEAK_SYMBOLS
    const unsigned char *b1 = (const unsigned char *) b1_;
    const unsigned char *b2 = (const unsigned char *) b2_;
#else
    const volatile unsigned char *volatile b1 = (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 = (const volatile unsigned char *volatile) b2_;
#endif
    size_t i;
	volatile unsigned char d = 0U;
#if HAVE_WEAK_SYMBOLS
    _cyd_dummy_symbol_to_prevent_memcmp_lto(b1, b2, len);
#endif
    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (1 & ((d - 1) >> 8)) - 1;
}

#ifdef HAVE_WEAK_SYMBOLS
__attribute__((weak)) void _cyd_dummy_symbol_to_prevent_compare_lto(const unsigned char *b1, const unsigned char *b2, const size_t len);
__attribute__((weak)) void _cyd_dummy_symbol_to_prevent_compare_lto(const unsigned char *b1, const unsigned char *b2, const size_t len) {
    (void) b1;
    (void) b2;
    (void) len;
}
#endif

int cyd_compare(const unsigned char *b1_, const unsigned char *b2_, size_t len) {
#ifdef HAVE_WEAK_SYMBOLS
    const unsigned char *b1 = b1_;
    const unsigned char *b2 = b2_;
#else
    const volatile unsigned char *volatile b1 = (const volatile unsigned char *volatile) b1_;
    const volatile unsigned char *volatile b2 = (const volatile unsigned char *volatile) b2_;
#endif
    size_t i;
    volatile unsigned char gt = 0U;
    volatile unsigned char eq = 1U;
    uint16_t x1, x2;

#if HAVE_WEAK_SYMBOLS
    _cyd_dummy_symbol_to_prevent_compare_lto(b1, b2, len);
#endif
    i = len;
    while (i != 0U) {
        i--;
        x1 = b1[i];
        x2 = b2[i];
        gt |= (((unsigned int) x2 - (unsigned int) x1) >> 8) & eq;
        eq &= (((unsigned int) (x2 ^ x1)) - 1) >> 8;
    }
    return (int) (gt + gt + eq) - 1;
}


int cyd_mlock(void *const addr, const size_t len) {
#if defined(MADV_DONTDUMP) && defined(HAVE_MADVISE)
    (void) madvise(addr, len, MADV_DONTDUMP);
#endif
#ifdef HAVE_MLOCK
    return mlock(addr, len);
#elif defined(WINAPI_DESKTOP)
    return -(VirtualLock(addr, len) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

int cyd_munlock(void *const addr, const size_t len) {
    cyd_memzero(addr, len);
#if defined(MADV_DODUMP) && defined(HAVE_MADVISE)
    (void) madvise(addr, len, MADV_DODUMP);
#endif
#ifdef HAVE_MLOCK
    return munlock(addr, len);
#elif defined(WINAPI_DESKTOP)
    return -(VirtualUnlock(addr, len) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int _cyd_mprotect_noaccess(void *ptr, size_t size) {
#ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_NONE);
#elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_NOACCESS, &old) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int _cyd_mprotect_readonly(void *ptr, size_t size) {
#ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_READ);
#elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_READONLY, &old) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

static int _cyd_mprotect_readwrite(void *ptr, size_t size) {
#ifdef HAVE_MPROTECT
    return mprotect(ptr, size, PROT_READ | PROT_WRITE);
#elif defined(WINAPI_DESKTOP)
    DWORD old;
    return -(VirtualProtect(ptr, size, PAGE_READWRITE, &old) == 0);
#else
    errno = ENOSYS;
    return -1;
#endif
}

#ifdef HAVE_ALIGNED_MALLOC

__attribute__((noreturn)) static void _cyd_out_of_bounds(void) {
#   if defined(HAVE_RAISE) && !defined(__wasm__)
#       ifdef SIGPROT
            raise(SIGPROT);
#       elif defined(SIGSEGV)
            raise(SIGSEGV);
#       elif defined(SIGKILL)
            raise(SIGKILL);
#       endif
#   endif
    abort();
}

static inline size_t _cyd_page_round(const size_t size) {
    const size_t page_mask = cyd_page_size - 1U;
    return (size + page_mask) & ~page_mask;
}

static __attribute__((malloc)) unsigned char* _cyd_alloc_aligned(const size_t size) {
    void *ptr;
#   if defined(MAP_ANON) && defined(HAVE_MMAP)
        if ((ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_NOCORE, -1, 0)) == MAP_FAILED) {
        	ptr = NULL;
    	}
#   elif defined(HAVE_POSIX_MEMALIGN)
        if (posix_memalign(&ptr, cyd_page_size, size) != 0) {
            ptr = NULL;
        }
#   elif defined(WINAPI_DESKTOP)
        ptr = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#   else
#       error Bug
#   endif
    return (unsigned char *) ptr;
}

static void _cyd_free_aligned(unsigned char *const ptr, const size_t size) {
#   if defined(MAP_ANON) && defined(HAVE_MMAP)
        (void) munmap(ptr, size);
#   elif defined(HAVE_POSIX_MEMALIGN)
        free(ptr);
#   elif defined(WINAPI_DESKTOP)
        VirtualFree(ptr, 0U, MEM_RELEASE);
#   else
#       error Bug
#   endif
}

static unsigned char * _cyd_unprotected_ptr_from_user_ptr(void *const ptr) {
    uintptr_t      unprotected_ptr_u;
    unsigned char *canary_ptr;
    size_t         page_mask;

    canary_ptr = ((unsigned char *) ptr) - sizeof cyd_canary;
    page_mask = cyd_page_size - 1U;
    unprotected_ptr_u = ((uintptr_t) canary_ptr & (uintptr_t) ~page_mask);
    if (unprotected_ptr_u <= cyd_page_size * 2U) {
        abort();
    }
    return (unsigned char *) unprotected_ptr_u;
}

#endif /* HAVE_ALIGNED_MALLOC */

static int _cyd_mprotect(void *ptr, int (*cb)(void *ptr, size_t size)) {
#ifndef HAVE_PAGE_PROTECTION
    (void) ptr;
    (void) cb;
    errno = ENOSYS;
    return -1;
#else
    unsigned char *base_ptr;
    unsigned char *unprotected_ptr;
    size_t unprotected_size;
    unprotected_ptr = _cyd_unprotected_ptr_from_user_ptr(ptr);
    base_ptr = unprotected_ptr - cyd_page_size * 2U;
    memcpy(&unprotected_size, base_ptr, sizeof unprotected_size);
    return cb(unprotected_ptr, unprotected_size);
#endif
}

int cyd_mprotect_noaccess(void *ptr) {
    return _cyd_mprotect(ptr, _cyd_mprotect_noaccess);
}

int cyd_mprotect_readonly(void *ptr) {
    return _cyd_mprotect(ptr, _cyd_mprotect_readonly);
}

int cyd_mprotect_readwrite(void *ptr) {
    return _cyd_mprotect(ptr, _cyd_mprotect_readwrite);
}

static __attribute__((malloc)) void* _cyd_malloc(const size_t size) {
#ifndef HAVE_ALIGNED_MALLOC
    return malloc(size > (size_t) 0U ? size : (size_t) 1U);
#else
    void          *user_ptr;
    unsigned char *base_ptr;
    unsigned char *canary_ptr;
    unsigned char *unprotected_ptr;
    size_t         size_with_canary;
    size_t         total_size;
    size_t         unprotected_size;

    if (size >= (size_t) SIZE_MAX - cyd_page_size * 4U) {
        errno = ENOMEM;
        return NULL;
    }
    if (cyd_page_size <= sizeof cyd_canary || cyd_page_size < sizeof unprotected_size) {
        abort();
    }
    size_with_canary = (sizeof cyd_canary) + size;
    unprotected_size = _cyd_page_round(size_with_canary);
    total_size       = cyd_page_size + cyd_page_size + unprotected_size + cyd_page_size;

    if ((base_ptr = _cyd_alloc_aligned(total_size)) == NULL) {
        return NULL; /* LCOV_EXCL_LINE */

    }
    unprotected_ptr = base_ptr + cyd_page_size * 2U;
    _cyd_mprotect_noaccess(base_ptr + cyd_page_size, cyd_page_size);
#   ifndef HAVE_PAGE_PROTECTION
    memcpy(unprotected_ptr + unprotected_size, cyd_canary, sizeof cyd_canary);
#   endif
    _cyd_mprotect_noaccess(unprotected_ptr + unprotected_size, cyd_page_size);
    (void) cyd_mlock(unprotected_ptr, unprotected_size); /* not a hard error in the context of cyd_malloc() */
    canary_ptr = unprotected_ptr + _cyd_page_round(size_with_canary) - size_with_canary;
    user_ptr = canary_ptr + sizeof cyd_canary;
    memcpy(canary_ptr, cyd_canary, sizeof cyd_canary);
    memcpy(base_ptr, &unprotected_size, sizeof unprotected_size);
    _cyd_mprotect_readonly(base_ptr, cyd_page_size);
    assert(_cyd_unprotected_ptr_from_user_ptr(user_ptr) == unprotected_ptr);
    return user_ptr;
#endif /* !HAVE_ALIGNED_MALLOC */
}

__attribute__((malloc)) void* cyd_malloc(const size_t size) {
    void *ptr;
    if ((ptr = _cyd_malloc(size)) == NULL) {
        return NULL;
    }
    memset(ptr, (int) GARBAGE_VALUE, size);
    return ptr;
}

__attribute__((malloc)) void* cyd_allocarray(size_t count, size_t size) {
    if (count > (size_t) 0U && size >= (size_t) SIZE_MAX / count) {
        errno = ENOMEM;
        return NULL;
    }
    return cyd_malloc(count * size);
}

void cyd_free(void *ptr) {
#ifndef HAVE_ALIGNED_MALLOC
    free(ptr);
#else
    unsigned char *base_ptr;
    unsigned char *canary_ptr;
    unsigned char *unprotected_ptr;
    size_t         total_size;
    size_t         unprotected_size;

    if (ptr == NULL) {
        return;
    }
    canary_ptr      = ((unsigned char *) ptr) - sizeof cyd_canary;

    unprotected_ptr = _cyd_unprotected_ptr_from_user_ptr(ptr);
    base_ptr        = unprotected_ptr - cyd_page_size * 2U;
    memcpy(&unprotected_size, base_ptr, sizeof unprotected_size);
    total_size = cyd_page_size + cyd_page_size + unprotected_size + cyd_page_size;
    _cyd_mprotect_readwrite(base_ptr, total_size);
    if (cyd_memcmp(canary_ptr, cyd_canary, sizeof cyd_canary) != 0) {
        _cyd_out_of_bounds();
    }
#   ifndef HAVE_PAGE_PROTECTION
    if (cyd_memcmp(unprotected_ptr + unprotected_size, cyd_canary, sizeof cyd_canary) != 0) {
        _cyd_out_of_bounds();
    }
#   endif
    (void) cyd_munlock(unprotected_ptr, unprotected_size);
    _cyd_free_aligned(base_ptr, total_size);
#endif /* HAVE_ALIGNED_MALLOC */
}

int cyd_is_zero(const unsigned char *n, const size_t nlen) {
    size_t i;
    volatile unsigned char d = 0U;
    for (i = 0U; i < nlen; i++) {
        d |= n[i];
    }
    return 1 & ((d - 1) >> 8);
}

int cyd_is_little_endian(void) {
#ifdef NATIVE_LITTLE_ENDIAN
	return 1;
#else
	return 0;
#endif
}

int cyd_is_big_endian(void) {
#ifdef NATIVE_BIG_ENDIAN
	return 1;
#else
	return 0;
#endif
}

int cyd_have_mman(void) {
#ifdef HAVE_SYS_MMAN_H
	return 1;
#else
	return 0;
#endif
}

uint64_t cyd_load64_le(const uint8_t src[8]) {
#ifdef NATIVE_LITTLE_ENDIAN
    uint64_t w;
    cyd_memcpy_s(&w, sizeof w, src, 8);
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

void cyd_store64_le(uint8_t dst[8], uint64_t w) {
#ifdef NATIVE_LITTLE_ENDIAN
    cyd_memcpy_s(dst, 8, &w, sizeof w);
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

uint32_t cyd_load32_le(const uint8_t src[4]) {
#ifdef NATIVE_LITTLE_ENDIAN
    uint32_t w;
    cyd_memcpy_s(&w, sizeof w, src, 4);
    return w;
#else
    uint32_t w = (uint32_t) src[0];
    w |= (uint32_t) src[1] <<  8;
    w |= (uint32_t) src[2] << 16;
    w |= (uint32_t) src[3] << 24;
    return w;
#endif
}

void cyd_store32_le(uint8_t dst[4], uint32_t w) {
#ifdef NATIVE_LITTLE_ENDIAN
    cyd_memcpy_s(dst, 4, &w, sizeof w);
#else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[3] = (uint8_t) w;
#endif
}

uint16_t cyd_load16_le(const uint8_t src[2]) {
#ifdef NATIVE_LITTLE_ENDIAN
    uint16_t w;
    cyd_memcpy_s(&w, sizeof w, src, 2);
    return w;
#else
    uint16_t w = (uint16_t) src[0];
    w |= (uint16_t) src[1] << 8;
    return w;
#endif
}

void cyd_store16_le(uint8_t dst[2], uint16_t w) {
#ifdef NATIVE_LITTLE_ENDIAN
    cyd_memcpy_s(dst, 2, &w, sizeof w);
#else
    dst[0] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w;
#endif
}


uint64_t cyd_load64_be(const uint8_t src[8]) {
#ifdef NATIVE_BIG_ENDIAN
    uint64_t w;
    cyd_memcpy_s(&w, sizeof w, src, 8);
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

void cyd_store64_be(uint8_t dst[8], uint64_t w) {
#ifdef NATIVE_BIG_ENDIAN
    cyd_memcpy_s(dst, 8, &w, sizeof w);
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

uint32_t cyd_load32_be(const uint8_t src[4]) {
#ifdef NATIVE_BIG_ENDIAN
    uint32_t w;
    cyd_memcpy_s(&w, sizeof w, src, 4);
    return w;
#else
    uint32_t w = (uint32_t) src[3];
    w |= (uint32_t) src[2] <<  8;
    w |= (uint32_t) src[1] << 16;
    w |= (uint32_t) src[0] << 24;
    return w;
#endif
}

void cyd_store32_be(uint8_t dst[4], uint32_t w) {
#ifdef NATIVE_BIG_ENDIAN
    cyd_memcpy_s(dst, 4, &w, sizeof w);
#else
    dst[3] = (uint8_t) w; w >>= 8;
    dst[2] = (uint8_t) w; w >>= 8;
    dst[1] = (uint8_t) w; w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}

uint16_t cyd_load16_be(const uint8_t src[2]) {
#ifdef NATIVE_BIG_ENDIAN
    uint16_t w;
    cyd_memcpy_s(&w, sizeof w, src, 2);
    return w;
#else
    uint16_t w = (uint16_t) src[1];
    w |= (uint16_t) src[0] << 8;
    return w;
#endif
}

void cyd_store16_be(uint8_t dst[2], uint16_t w) {
#ifdef NATIVE_BIG_ENDIAN
    cyd_memcpy_s(dst, 2, &w, sizeof w);
#else
    dst[1] = (uint8_t) w;
    w >>= 8;
    dst[0] = (uint8_t) w;
#endif
}
