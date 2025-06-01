#ifndef __CYD_MEMCPY_S_H__
#define __CYD_MEMCPY_S_H__ 

#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#ifndef ESNULLP
#define ESNULLP         ( 400 )       /* null ptr                    */
#endif

#ifndef ESZEROL
#define ESZEROL         ( 401 )       /* length is zero              */
#endif

#ifndef ESLEMIN
#define ESLEMIN         ( 402 )       /* length is below min         */
#endif


#ifndef ESLEMAX
#define ESLEMAX         ( 403 )       /* length exceeds max          */
#endif

#ifndef ESOVRLP

#define ESOVRLP         ( 404 )       /* overlap undefined           */
#endif

#ifndef ESEMPTY
#define ESEMPTY         ( 405 )       /* empty string                */
#endif

#ifndef ESNOSPC
#define ESNOSPC         ( 406 )       /* not enough space for s2     */
#endif

#ifndef ESUNTERM
#define ESUNTERM        ( 407 )       /* unterminated string         */
#endif

#ifndef ESNODIFF
#define ESNODIFF        ( 408 )       /* no difference               */
#endif


#ifndef ESNOTFND
#define ESNOTFND        ( 409 )       /* not found                   */
#endif

/* Additional for safe snprintf_s interfaces                         */
#ifndef ESBADFMT
#define ESBADFMT        ( 410 )       /* bad format string           */
#endif

#ifndef ESFMTTYP
#define ESFMTTYP        ( 411 )       /* bad format type             */
#endif


/* EOK may or may not be defined in errno.h */
#ifndef EOK
#define EOK             ( 0 )
#endif

#ifndef RSIZE_MAX_MEM
#define RSIZE_MAX_MEM   ( 256UL << 20 )     /* 256MB */
#endif

int cyd_memcpy_s(void *dest, size_t dmax, const void *src, size_t smax);

#endif
