#ifndef _RHO_BEARSSL_COMMON_H_
#define _RHO_BEARSSL_COMMON_H_

#include <shim_internal.h>
#include <shim_types.h>

#include <bearssl.h>

#include <rho_decls.h>
#include <rho_ssl.h>


RHO_DECLS_BEGIN


#define RHO_SSL_IGN_CHARS (RHO_STR_WHITESPACE "-_./+:")

struct rho_ssl_ccert_context {
	const br_ssl_client_certificate_class *vtable;
	int verbose;
	br_x509_certificate *chain;
	size_t chain_len;
	struct rho_bearssl_key *sk;
	int issuer_key_type;
};

struct rho_ssl_ctx {
    /* TODO: add a union that covers client and server context */
    br_ssl_client_context cc;
    struct rho_ssl_ccert_context zc;
    br_x509_minimal_context xc;
    br_sslio_context ioc;
    int protocol_version;   /* e.g., BR_TLS12 */
    uint8_t *wbuf;
    uint8_t *rbuf;
};

RHO_DECLS_END

#endif /* _RHO_BEARSSL_COMMON_H_ */
