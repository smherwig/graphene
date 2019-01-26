#ifndef _RHO_DER_H_
#define _RHO_DER_H_

#include <stddef.h>
#include <stdbool.h>

#include "rho_decls.h"

RHO_DECLS_BEGIN

bool rho_der_looks_like_der(const unsigned char *buf, size_t len);

RHO_DECLS_END

#endif /* _RHO_DER_H_ */
