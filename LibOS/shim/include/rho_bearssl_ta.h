#ifndef _RHO_BEARSSL_TA_H_
#define _RHO_BEARSSL_TA_H_

#include <stddef.h>

#include <bearssl.h>

#include <rho_decls.h>

#include <rho_vector.h>

RHO_DECLS_BEGIN

/* Type for a vector of trust anchors (aka CAs) */
RHO_VECTOR(rho_bearssl_ta_list, br_x509_trust_anchor);

size_t rho_bearssl_ta_list_from_file(struct rho_bearssl_ta_list *dst,
        const char *fname);

void rho_bearssl_ta_destroy(br_x509_trust_anchor *ta);

void rho_bearssl_ta_list_destroy(struct rho_bearssl_ta_list *tas);

RHO_DECLS_END

#endif /* _RHO_BEARSSL_TA_H_ */
