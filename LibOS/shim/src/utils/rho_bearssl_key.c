#include <stddef.h>

#include <shim_internal.h>
#include <shim_types.h>

#include <bearssl.h>

#include <rho_bearssl_common.h>
#include <rho_bearssl_error.h>
#include <rho_bearssl_key.h>
#include <rho_bearssl_pem.h>

#include <rho_der.h>
#include <rho_file.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_pem.h>
#include <rho_str.h>

static struct rho_bearssl_key *
rho_bearssl_key_decode(const unsigned char *buf, size_t len)
{
	br_skey_decoder_context dc;
	int err;
	struct rho_bearssl_key *sk;

	br_skey_decoder_init(&dc);
	br_skey_decoder_push(&dc, buf, len);
	err = br_skey_decoder_last_error(&dc);
	if (err != 0) {
		const char *errname, *errmsg;
        rho_warn("ERROR (decoding): err=%d\n", err);
		errname = rho_bearssl_error_get_name(err, &errmsg);
		if (errname != NULL) {
			rho_warn("  %s: %s\n", errname, errmsg);
		} else {
			rho_warn("  (unknown)\n");
		}
		return NULL;
	}
	switch (br_skey_decoder_key_type(&dc)) {
		const br_rsa_private_key *rk;
		const br_ec_private_key *ek;

	case BR_KEYTYPE_RSA:
		rk = br_skey_decoder_get_rsa(&dc);
		sk = rhoL_malloc(sizeof *sk);
		sk->key_type = BR_KEYTYPE_RSA;
		sk->key.rsa.n_bitlen = rk->n_bitlen;
		sk->key.rsa.p = rhoL_memdup(rk->p, rk->plen);
		sk->key.rsa.plen = rk->plen;
		sk->key.rsa.q = rhoL_memdup(rk->q, rk->qlen);
		sk->key.rsa.qlen = rk->qlen;
		sk->key.rsa.dp = rhoL_memdup(rk->dp, rk->dplen);
		sk->key.rsa.dplen = rk->dplen;
		sk->key.rsa.dq = rhoL_memdup(rk->dq, rk->dqlen);
		sk->key.rsa.dqlen = rk->dqlen;
		sk->key.rsa.iq = rhoL_memdup(rk->iq, rk->iqlen);
		sk->key.rsa.iqlen = rk->iqlen;
		break;

	case BR_KEYTYPE_EC:
		ek = br_skey_decoder_get_ec(&dc);
		sk = rhoL_malloc(sizeof *sk);
		sk->key_type = BR_KEYTYPE_EC;
		sk->key.ec.curve = ek->curve;
		sk->key.ec.x = rhoL_memdup(ek->x, ek->xlen);
		sk->key.ec.xlen = ek->xlen;
		break;

	default:
		rho_warn("Unknown key type: %d\n",
			br_skey_decoder_key_type(&dc));
		sk = NULL;
		break;
	}

	return sk;
}

struct rho_bearssl_key *
rho_bearssl_key_from_file(const char *path)
{
    int error = 0;
    unsigned char *buf = NULL;
    size_t len = 0;
    struct rho_bearssl_key *sk = NULL;
    struct rho_pem *pos = NULL;
    size_t num = 0;
    size_t u = 0;

    error = rho_file_readall(path, &buf, &len);
    if (error == -1)
        goto done;

    if (rho_der_looks_like_der(buf, len)) {
        sk = rho_bearssl_key_decode(buf, len);
        goto done;
    } else    {
        pos = rho_bearssl_pem_decode(buf, len, &num);
        if (pos == NULL) {
            goto done;
        }
        for (u = 0; pos[u].name; u++) {
			const char *name;

			name = pos[u].name;
			if (rho_str_equal_ci_ignore(name, "RSA PRIVATE KEY", RHO_SSL_IGN_CHARS)
				|| rho_str_equal_ci_ignore(name, "EC PRIVATE KEY", RHO_SSL_IGN_CHARS)
				|| rho_str_equal_ci_ignore(name, "PRIVATE KEY", RHO_SSL_IGN_CHARS))
			{
				sk = rho_bearssl_key_decode(pos[u].data, pos[u].data_len);
				goto done;
			}
		}
		rho_warn("ERROR: no private key in file '%s'\n", path);
		goto done;
	}

done:
	if (buf != NULL) {
		rhoL_free(buf);
	}
	if (pos != NULL) {
		for (u = 0; pos[u].name; u ++) {
			rho_pem_destroy(&pos[u]);
		}
		rhoL_free(pos);
	}
	return sk;
}

/*
 * Free a private key.
 */
void
rho_bearssl_key_destroy(struct rho_bearssl_key *sk)
{
	if (sk == NULL) {
		return;
	}
	switch (sk->key_type) {
	case BR_KEYTYPE_RSA:
		rhoL_free(sk->key.rsa.p);
		rhoL_free(sk->key.rsa.q);
		rhoL_free(sk->key.rsa.dp);
		rhoL_free(sk->key.rsa.dq);
		rhoL_free(sk->key.rsa.iq);
		break;
	case BR_KEYTYPE_EC:
		rhoL_free(sk->key.ec.x);
		break;
	}
	rhoL_free(sk);
}

