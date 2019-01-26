#ifndef _RHO_MEM_H_
#define _RHO_MEM_H_

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

#define RHO_MEM_ZERO    (1U<<1)

void * rhoL_malloc(size_t size);
void * rhoL_calloc(size_t nmemb, size_t size);
char * rhoL_strdup(const char *s);
char * rhoL_strndup(const char *s, size_t n);
void * rhoL_realloc(void *ptr, size_t oldsize, size_t newsize);
void rhoL_free(void *p);
void * rhoL_mallocarray(size_t nmemb, size_t size, int flags);
void * rhoL_memdup(const void *ptr, size_t size);

#define rhoL_zalloc(size) rhoL_calloc(1, (size))

RHO_DECLS_END

#endif /* _RHO_MEM_H_ */
