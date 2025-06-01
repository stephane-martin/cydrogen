#include "cyd_memcpy_s.h"

int cyd_memcpy_s(void *dest, size_t dmax, const void *src, size_t smax) {
    uint8_t *dp;
    const uint8_t  *sp;

    dp = dest;
    sp = src;

    if (dp == NULL) {
        return -(ESNULLP);
    }

    if (dmax == 0) {
        return -(ESZEROL);
    }

    if (dmax > RSIZE_MAX_MEM) {
        return -(ESLEMAX);
    }

    if (smax == 0) {
        return EOK;
    }

    if (smax > dmax) {
        memset(dp, 0, dmax);
        return -(ESLEMAX);
    }

    if (sp == NULL) {
        memset(dp, 0, dmax);
        return -(ESNULLP);
    }

    if( ((dp > sp) && (dp < (sp+smax))) || ((sp > dp) && (sp < (dp+dmax))) ) {
        memset(dp, 0, dmax);
        return -(ESOVRLP);
    }

	memcpy(dp, sp, smax);

    return EOK;
}
