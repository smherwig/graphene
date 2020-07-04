#include <stdarg.h>
#include <stdint.h>

#include <bearssl.h>

#include "rho_crypto.h"
#include "rho_log.h"
#include "rho_mem.h"

struct rho_md {
    const br_hash_class **ctx;
    uint8_t *salt;
    size_t saltlen;
};

static const br_hash_class *
rho_md_type2class(enum rho_md_type type)
{
    switch (type) {
    case RHO_MD_MD5:    return &br_md5_vtable;
    case RHO_MD_SHA1:   return &br_sha1_vtable;
    case RHO_MD_SHA224: return &br_sha224_vtable;
    case RHO_MD_SHA256: return &br_sha256_vtable;
    case RHO_MD_SHA384: return &br_sha384_vtable;
    case RHO_MD_SHA512: return &br_sha512_vtable;
    default: rho_die("'%d' is not a valid rho_md_type", type);
    }

    /* NOT REACHED */
    return (NULL);
}

static void
rho_md_setsalt(struct rho_md *h, void *salt, size_t saltlen)
{
    RHO_ASSERT(h != NULL);
    RHO_ASSERT(salt != NULL);

    if (h->salt != NULL)
        rhoL_free(salt);

    h->salt = rhoL_memdup(salt, saltlen);
    h->saltlen = saltlen;
}

struct rho_md *
rho_md_create(enum rho_md_type md_type, void *salt, size_t saltlen)
{

    struct rho_md *h = NULL;
    const br_hash_class *klass = NULL;
    const br_hash_class **ctx = NULL;

    klass = rho_md_type2class(md_type);
    ctx = rhoL_zalloc(klass->context_size);
    klass->init(ctx);

    h = rhoL_zalloc(sizeof(*h));
    h->ctx = ctx;

    if ((salt != NULL) && (saltlen > 0)) {
        (*ctx)->update(ctx, salt, saltlen);
        rho_md_setsalt(h, salt, saltlen);
    }

    return (h);
}

void
rho_md_destroy(struct rho_md *h)
{
    rhoL_free(h->ctx);
    if (h->salt != NULL)
        rhoL_free(h->salt);
    rhoL_free(h);
}

void
rho_md_update(struct rho_md *h, const void *data, size_t count)
{
    const br_hash_class **ctx = h->ctx;
    (*ctx)->update(ctx, data, count);
}

void
rho_md_finish(struct rho_md *h, void *out)
{
    const br_hash_class **ctx = h->ctx;
    (*ctx)->out(ctx, out);
}

void
rho_md_reset(struct rho_md *h, void *salt, size_t saltlen)
{
    const br_hash_class **ctx = h->ctx;

    (*ctx)->init(ctx);

    if ((salt != NULL) && (saltlen > 0))
        rho_md_setsalt(h, salt, saltlen);

    if (h->saltlen > 0)
        (*ctx)->update(ctx, h->salt, h->saltlen);
}

void
rho_md_oneshot(enum rho_md_type md_type, void *salt, size_t saltlen,
        void *data, size_t count, void *out)
{
    struct rho_md *h = NULL;

    h = rho_md_create(md_type, salt, saltlen);
    rho_md_update(h, data, count);
    rho_md_finish(h, out);
    rho_md_destroy(h);
}
