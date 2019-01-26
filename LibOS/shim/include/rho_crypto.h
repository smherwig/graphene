#ifndef _RHO_CRYPTO_H_
#define _RHO_CRYPTO_H_

#include <stdarg.h>
#include <stdbool.h>

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

/*
 * INIT/FINI
 */
void rho_crypto_init(void);
void rho_crypto_fini(void);

/*
 * MESSAGE DIGESTS
 */

/* opaque */
struct rho_md;

enum rho_md_type {
    RHO_MD_MD5,
    RHO_MD_SHA1,
    RHO_MD_SHA224,
    RHO_MD_SHA256,
    RHO_MD_SHA384,
    RHO_MD_SHA512
};

#define RHO_MD_SIZE_MD5     16
#define RHO_MD_SIZE_SHA1    20
#define RHO_MD_SIZE_SHA224  28
#define RHO_MD_SIZE_SHA256  32
#define RHO_MD_SIZE_SHA284  48
#define RHO_MD_SIZE_SHA512  64

struct rho_md * rho_md_create(enum rho_md_type md_type, void *salt,
        size_t saltlen);
void rho_md_destroy(struct rho_md *h);
void rho_md_update(struct rho_md *h, const void *data, size_t count);
void rho_md_finish(struct rho_md *h, void *out);
void rho_md_reset(struct rho_md *h, void *salt, size_t saltlen);
void rho_md_oneshot(enum rho_md_type type, void *salt, size_t saltlen,
        void *data, size_t count, void *out);

/*
 * HMAC
 */

/* opaque */
struct rho_hmac;

struct rho_hmac * rho_hmac_create(enum rho_md_type md_type, void *key,
        size_t keylen);
void rho_hmac_destroy(struct rho_hmac *hm);
void rho_hmac_update(struct rho_hmac *hm, void *data, size_t len);
void rho_hmac_finish(struct rho_hmac *hm, void *md);
void rho_hmac_reset(struct rho_hmac *hm, void *key, size_t keylen);
void rho_hmac_oneshot(enum rho_md_type md_type, void *key, size_t keylen,
        void *data, size_t datalen, void *out);

/*
 * KEY-DERIVATION FUNCTIONS (KDFs)
 */

void rho_kdf_pbkdf2hmac(const char *pass, uint8_t *salt, size_t saltlen,
        int iterations, struct rho_md *h, uint8_t *key, size_t keylen);

void rho_kdf_pbkdf2hmac_oneshot(const char *pass, uint8_t *salt, size_t saltlen,
        int iterations, enum rho_md_type md_type, uint8_t *key, size_t keylen);

/*
 * CIPHERS
 */

struct rho_cipher;
enum rho_cipher_mode {
    RHO_CIPHER_MODE_ENCRYPT,
    RHO_CIPHER_MODE_DECRYPT
};

enum rho_cipher_type {
    RHO_CIPHER_AES_128_CBC,
    RHO_CIPHER_AES_128_ECB,

    RHO_CIPHER_AES_192_CBC,
    RHO_CIPHER_AES_192_ECB,

    RHO_CIPHER_AES_256_CBC,
    RHO_CIPHER_AES_256_ECB,
    RHO_RIPHER_AES_256_XTS
};

#define RHO_CIPHER_KEYLENGTH_AES_128     16
#define RHO_CIPHER_KEYLENGTH_AES_192     24
#define RHO_CIPHER_KEYLENGTH_AES_256    32 

/* iv length is the block size length, which is 16 for AES*/
#define RHO_CIPHER_IVLENGTH_AES         16
#define RHO_CIPHER_IVLENGTH_AES_128     16
#define RHO_CIPHER_IVLENGTH_AES_192     16
#define RHO_CIPHER_IVLENGTH_AES_256     16

#define RHO_CIPHER_BLOCKSIZE_AES        16
#define RHO_CIPHER_BLOCKSIZE_AES_128    16
#define RHO_CIPHER_BLOCKSIZE_AES_192    16
#define RHO_CIPHER_BLOCKSIZE_AES_256    16

struct rho_cipher * rho_cipher_create(enum rho_cipher_type type,
        enum rho_cipher_mode mode, bool padded, const void *key,
        const void *iv);

void rho_cipher_destroy(struct rho_cipher *c);

void rho_cipher_update(struct rho_cipher *c, const void *in, size_t inlen,
        void *out, size_t *outlen);

void rho_cipher_finish(struct rho_cipher *c, void *out, size_t *outlen);

void rho_cipher_reset(struct rho_cipher *c, enum rho_cipher_mode mode,
        bool padded, void *key, void *iv);

void rho_cipher_oneshot(enum rho_cipher_type type, enum rho_cipher_mode mode,
        bool padded, const void *key, const void *iv,
        const void *in, size_t inlen, void *out, size_t *outlen);

RHO_DECLS_END

#endif /* ! _RHO_CRYPTO_H_ */
