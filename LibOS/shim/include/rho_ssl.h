#ifndef _RHO_SSL_H_
#define _RHO_SSL_H_

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_decls.h>
#include <rho_sock.h>

/*
 * rho_ssl_params is similar to a profile in which all SSL configuration is
 * set.  A rho_ssl_params is passed to rho_ssl_ctx_create, which creates a
 * context according to the profile/params.  rho_ssl_wrap then attaches
 * a context to a socket descriptor, and rho_ssl_do_handshake is called
 * after a connect/accept.
 *
 * The use of rho_ssl_params eases support for multiple backends, and mimics
 * the (natural) approach taken by various scripting languages (Lua, Ruby,
 * Python to a degree), in which an SSL context is created based on a
 * dictionary-like specification of the options.  Here, rho_ssl_params takes
 * the place of such a dictionary.
 */
enum rho_ssl_mode {
    RHO_SSL_MODE_UNSPECIFED = 0, /* not valid; forces user to explicitly set mode */
    RHO_SSL_MODE_CLIENT,
    RHO_SSL_MODE_SERVER
};

enum rho_ssl_protocol {
    RHO_SSL_PROTOCOL_UNSPECIFED = 0, /* not valid; forces user to explicitly set protocol */
    RHO_SSL_PROTOCOL_SSLv23,
    RHO_SSL_PROTOCOL_TLSv1,
    RHO_SSL_PROTOCOL_TLSv1_1,
    RHO_SSL_PROTOCOL_TLSv1_2,
};

struct rho_ssl_params {
    enum rho_ssl_mode mode;
    enum rho_ssl_protocol protocol;
    char *key_file;
    char *cert_file;
    char *ca_file;
    bool verify;
    int refcnt;
};

/* opaque (to support multiple backends) */
struct rho_ssl_ctx;

/*
 * SSL PARAMS
 *
 * (implemented in rho_ssl_common.c)
 */

struct rho_ssl_params * rho_ssl_params_create(void);
void rho_ssl_params_destroy(struct rho_ssl_params *params);
void rho_ssl_params_incref(struct rho_ssl_params *params);

void rho_ssl_params_set_mode(struct rho_ssl_params *params, 
        enum rho_ssl_mode mode);

void rho_ssl_params_set_protocol(struct rho_ssl_params *params,
        enum rho_ssl_protocol protocol);

void rho_ssl_params_set_private_key_file(struct rho_ssl_params *params,
        const char *path);

void rho_ssl_params_set_certificate_file(struct rho_ssl_params *params,
        const char *path);

void rho_ssl_params_set_ca_file(struct rho_ssl_params *params,
        const char *path);

void rho_ssl_params_set_verify(struct rho_ssl_params *params, bool verify);

/*
 * SSL CONTEXT
 *
 * (implemented in backend (openssl/ or bearssl/)
 */

struct rho_ssl_ctx * rho_ssl_ctx_create(struct rho_ssl_params *params);
void rho_ssl_ctx_destroy(struct rho_ssl_ctx *ctx);

/*
 * SSL WRAPPED SOCKET
 *
 * (implemented in backend (openssl/ or bearssl/)
 */

void rho_ssl_wrap(struct rho_sock *sock, struct rho_ssl_ctx *ctx);
int rho_ssl_do_handshake(struct rho_sock *sock);

#endif /* ! _RHO_SSL_H_ */
