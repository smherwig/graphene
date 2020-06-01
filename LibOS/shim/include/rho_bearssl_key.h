#ifndef _RHO_BEARSSL_KEY_H_
#define _RHO_BEARSSL_KEY_H_

#include <bearssl.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

struct rho_bearssl_key {
    int key_type;   /* BR_KEYTYPE_RSA or BR_KEYTYPE_EC */
    union {
        br_rsa_private_key rsa;
        br_ec_private_key ec;
    } key;
};

struct rho_bearssl_key * rho_bearssl_key_from_file(const char *path);
void rho_bearssl_key_destroy(struct rho_bearssl_key *sk);

RHO_DECLS_END

#endif /* _RHO_BEARSSL_KEY_H_ */
