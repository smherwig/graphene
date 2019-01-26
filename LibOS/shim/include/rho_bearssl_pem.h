#ifndef _RHO_BEARSSL_PEM_H_
#define _RHO_BEARSSL_PEM_H_

#include <stddef.h>

#include <bearssl.h>

#include <rho_decls.h>

#include <rho_pem.h>

RHO_DECLS_BEGIN

struct rho_pem * rho_bearssl_pem_decode(const void *src, size_t len, size_t *num);

RHO_DECLS_END

#endif /* _RHO_BEARSSL_PEM_H_ */
