#include <rho_mem.h>
#include <rho_ssl.h>

struct rho_ssl_params *
rho_ssl_params_create(void)
{
    struct rho_ssl_params *params = NULL;
    
    params = rhoL_zalloc(sizeof(*params));
    params->refcnt++;

    return (params);
}

void
rho_ssl_params_destroy(struct rho_ssl_params *params)
{
    params->refcnt--;
    if (params->refcnt != 0)
        return;
   
    if (params->key_file != NULL)
        rhoL_free(params->key_file);
    if (params->cert_file != NULL)
        rhoL_free(params->cert_file);
    if (params->ca_file != NULL)
        rhoL_free(params->ca_file);
    if (params->ca_der != NULL)
        rhoL_free(params->ca_der);
        
    rhoL_free(params);
}

void
rho_ssl_params_incref(struct rho_ssl_params *params)
{
    params->refcnt++;
}

void
rho_ssl_params_set_mode(struct rho_ssl_params *params, enum rho_ssl_mode mode)
{
    params->mode = mode;
}

void
rho_ssl_params_set_protocol(struct rho_ssl_params *params,
        enum rho_ssl_protocol protocol)
{
    params->protocol = protocol;
}

void
rho_ssl_params_set_private_key_file(struct rho_ssl_params *params,
        const char *path)
{
    params->key_file = rhoL_strdup(path);
}

void
rho_ssl_params_set_certificate_file(struct rho_ssl_params *params,
        const char *path)
{
    params->cert_file = rhoL_strdup(path);
}

void
rho_ssl_params_set_ca_file(struct rho_ssl_params *params, const char *path)
{
    params->ca_file = rhoL_strdup(path);
}

void
rho_ssl_params_set_ca_der(struct rho_ssl_params *params, unsigned char *ca_der,
        size_t ca_der_len)
{
    params->ca_der = rhoL_memdup(ca_der, ca_der_len);
    params->ca_der_len = ca_der_len;
}

void
rho_ssl_params_set_verify(struct rho_ssl_params *params, bool verify)
{
    params->verify = verify;
}
