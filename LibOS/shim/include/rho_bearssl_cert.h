#ifndef _RHO_BEARSSL_CERT_H_
#define _RHO_BEARSSL_CERT_H_


#include <shim_internal.h>
#include <shim_types.h>

#include <bearssl.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

br_x509_certificate * rho_bearssl_certs_from_cbuf(unsigned char *buf,
        size_t len, size_t *num);

br_x509_certificate * rho_bearssl_certs_from_file(const char *fname,
        size_t *num);

void rho_bearssl_certs_destroy(br_x509_certificate *certs, size_t num);

RHO_DECLS_END

#endif /* _RHO_BEARSSL_CERT_H_ */
