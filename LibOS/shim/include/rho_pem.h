#ifndef _RHO_PEM_H_
#define _RHO_PEM_H_

#include <stddef.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

/*
 * Type for a named blob (the `name' is a normalized PEM header name)
 */
struct rho_pem {
	char *name;
	unsigned char *data;
	size_t data_len;
};

void rho_pem_destroy(struct rho_pem *pem);

RHO_DECLS_END

#endif /* _RHO_PEM_H_ */
