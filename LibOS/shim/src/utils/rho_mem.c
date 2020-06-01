#if 0
#include <stdlib.h>
#include <stdint.h>
#endif

#include <string.h>

#include <shim_internal.h>
#include <shim_utils.h>

#include <rho_log.h>
#include <rho_mem.h>
#include <rho_misc.h>

void *
rhoL_malloc(size_t size)
{
    void *p = NULL;

    p = malloc(size);
    if (p == NULL)
        rho_die("out of memory");
    return (p);
}

void *
rhoL_calloc(size_t nmemb, size_t size)
{
    void *p = NULL;

    p = calloc(nmemb, size);
    if (p == NULL)
        rho_die("out of memory");

    return (p);
}

char *
rhoL_strdup(const char *s)
{
    size_t len = 0;
    void *p = NULL;

    RHO_ASSERT(s != NULL);

    len = strlen(s);
    p = rhoL_memdup(s, len + 1);

    return (p);
}

void *
rhoL_memdup(const void *p, size_t n)
{
    void *out = NULL;

    out = rhoL_malloc(n);
    memcpy(out, p, n);
    return (out);
}

char *
rhoL_strndup(const char *s, size_t n)
{
    size_t len = 0;
    void *p = NULL;

    RHO_ASSERT(s != NULL);

    len = strlen(s);
    p = rhoL_zalloc(RHO_MIN(len, n) + 1);
    memcpy(p, s, RHO_MIN(len, n));

    return (p);
}

/*
 * Graphene does not provide a realloc,
 * we provide a simple (but inefficient) one, however, unlike normal
 * realloc(3), we need the old size of the memory block.
 */
void *
rhoL_realloc(void *ptr, size_t oldsize, size_t newsize)
{
    void *newp = NULL;

    newp = rhoL_malloc(newsize);
    memcpy(newp, ptr, RHO_MIN(oldsize, newsize));
    free(ptr);

    return (newp);
}

void
rhoL_free(void *p)
{
    if (p != NULL)
        free(p);
}

#define MUL_NO_OVERFLOW (1UL << (sizeof(size_t) * 4))

/* based on OpenBSD */
void *
rhoL_mallocarray(size_t nmemb, size_t size, int flags)
{
    void *p = NULL;
    size_t n = 0;

    /* 
     * MUL_NO_OVERFLOW * MUL_NO_OVERLOFOW would overflow.
     *
     * So, if both nmemb and size are less then MUL_NO_OVERFLOW
     * we are safe.  However, if at least one is greater, then we
     * see if nmemb * size > SIZE_MAX (we have to also check
     * that nmemb is not zero to avoid a divide-by-zero error.
     */

    if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
        (nmemb > 0) && ((SIZE_MAX / nmemb) < size)) {
        rho_die("unsigned integer overflow (nmemb=%zu, size%zu)",
                nmemb, size);
    }

    n = nmemb * size;
    p = rhoL_malloc(n);
    if (flags & RHO_MEM_ZERO)
        memset(p, 0x00, n);

    return (p);
}
