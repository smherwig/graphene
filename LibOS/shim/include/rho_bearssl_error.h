#ifndef _RHO_BEARSSL_ERROR_H_
#define _RHO_BEARSSL_ERROR_H_

#include <rho_decls.h>

RHO_DECLS_BEGIN

const char * rho_bearssl_error_get_name(int err, const char **comment);
void rho_bearssl_warn_last_error(const br_ssl_engine_context *engine,
        const char *msg);

RHO_DECLS_END

#endif /* _RHO_BEARSSL_ERROR_H_ */
