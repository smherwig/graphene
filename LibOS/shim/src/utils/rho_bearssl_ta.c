#include <stddef.h>

#include <shim_internal.h>
#include <shim_types.h>

#include <bearssl.h>

#include <rho_log.h>
#include <rho_mem.h>
#include <rho_vector.h>

#include <rho_bearssl_cert.h>
#include <rho_bearssl_ta.h>

/* dn = distinguished name */
static void
rho_bearssl_dn_append(void *ctx, const void *buf, size_t len)
{
    debug("> rho_bearssl_dn_append: len=%lu\n", len);
	RHO_VECTOR_ADDMANY(*(rho_bytevector *)ctx, buf, len);
}

static int
rho_bearssl_certificate_to_ta_inner(br_x509_trust_anchor *ta,
	br_x509_certificate *xc)
{
	br_x509_decoder_context *dc = rhoL_zalloc(sizeof(*dc));
	rho_bytevector vdn = RHO_VECTOR_INIT;
	br_x509_pkey *pk = NULL;

    debug("rho_bearssl_certificate_to_ta_inner: A: sizeof(dc):%lu\n", sizeof(*dc));
	br_x509_decoder_init(dc, rho_bearssl_dn_append, &vdn);
    debug("rho_bearssl_certificate_to_ta_inner: B\n");
	br_x509_decoder_push(dc, xc->data, xc->data_len);
    debug("rho_bearssl_certificate_to_ta_inner: C\n");
	pk = br_x509_decoder_get_pkey(dc);
    debug("rho_bearssl_certificate_to_ta_inner: D\n");
	if (pk == NULL) {
        debug("rho_bearssl_certificate_to_ta_inner: E\n");
        rho_warn("ERROR: CA decoding failed with error %d\n",
			br_x509_decoder_last_error(dc));
		RHO_VECTOR_CLEAR(vdn);
        rhoL_free(dc);
		return -1;
	}
    debug("rho_bearssl_certificate_to_ta_inner: F\n");
	ta->dn.data = RHO_VECTOR_TOARRAY(vdn);
    debug("rho_bearssl_certificate_to_ta_inner: G\n");
	ta->dn.len = RHO_VECTOR_LEN(vdn);
    debug("rho_bearssl_certificate_to_ta_inner: H\n");
	RHO_VECTOR_CLEAR(vdn);
    debug("rho_bearssl_certificate_to_ta_inner: I\n");
	ta->flags = 0;
	if (br_x509_decoder_isCA(dc)) {
		ta->flags |= BR_X509_TA_CA;
	}
	switch (pk->key_type) {
	case BR_KEYTYPE_RSA:
		ta->pkey.key_type = BR_KEYTYPE_RSA;
		ta->pkey.key.rsa.n = rhoL_memdup(pk->key.rsa.n, pk->key.rsa.nlen);
		ta->pkey.key.rsa.nlen = pk->key.rsa.nlen;
		ta->pkey.key.rsa.e = rhoL_memdup(pk->key.rsa.e, pk->key.rsa.elen);
		ta->pkey.key.rsa.elen = pk->key.rsa.elen;
		break;
	case BR_KEYTYPE_EC:
		ta->pkey.key_type = BR_KEYTYPE_EC;
		ta->pkey.key.ec.curve = pk->key.ec.curve;
		ta->pkey.key.ec.q = rhoL_memdup(pk->key.ec.q, pk->key.ec.qlen);
		ta->pkey.key.ec.qlen = pk->key.ec.qlen;
		break;
	default:
		rho_warn("ERROR: unsupported public key type in CA\n");
		rhoL_free(ta->dn.data);
        rhoL_free(dc);
		return -1;
	}
    rhoL_free(dc);
	return 0;
}

/*
 * Decode certificates from a file and interpret them as trust anchors.
 * The trust anchors are added to the provided list. The number of found
 * anchors is returned; on error, 0 is returned (finding no anchor at
 * all is considered an error). An appropriate error message is displayed.
 */
size_t
rho_bearssl_ta_list_from_cbuf(struct rho_bearssl_ta_list *dst, unsigned char *buf,
        size_t len)
{
	br_x509_certificate *xcs = NULL;
	struct rho_bearssl_ta_list tas = RHO_VECTOR_INIT;
	size_t u = 0;
    size_t num = 0;

	xcs = rho_bearssl_certs_from_cbuf(buf, len, &num);
	if (xcs == NULL) {
        debug("rho_bearssl_certs_from_cbuf failed\n");
		return 0;
	}
    debug("rho_bearssl_certs_from_cbuf succeeded: num=%lu\n", (unsigned long)num);
	for (u = 0; u < num; u++) {
		br_x509_trust_anchor ta;
        memset(&ta, 0x00, sizeof(ta));
        debug("rho_bearssl_ta_list_from_cbuf loop: #%lu\n", (unsigned long)num);
		if (rho_bearssl_certificate_to_ta_inner(&ta, &(xcs[u])) < 0) {
            debug("rho_bearssl_certificate_to_inner failed\n");
            rho_bearssl_ta_list_destroy(&tas);
			rho_bearssl_certs_destroy(xcs, num);
			return 0;
		}
		RHO_VECTOR_ADD(tas, ta);
	}
    debug("rho_bearssl_ta_list_from_cbuf out of loop\n");
	RHO_VECTOR_ADDMANY(*dst, &RHO_VECTOR_ELT(tas, 0), num);
	RHO_VECTOR_CLEAR(tas);
	rho_bearssl_certs_destroy(xcs, num);
    debug("rho_bearssl_ta_list_from_cbuf returning %lu\n", (unsigned long)num);
	return num;
}

size_t
rho_bearssl_ta_list_from_file(struct rho_bearssl_ta_list *dst, const char *fname)
{
	br_x509_certificate *xcs;
	struct rho_bearssl_ta_list tas = RHO_VECTOR_INIT;
	size_t u, num;

    debug("rho_bearssl_certs_from_file\n");
	xcs = rho_bearssl_certs_from_file(fname, &num);
	if (xcs == NULL) {
        debug("rho_bearssl_certs_from_file failed\n");
		return 0;
	}
    debug("rho_bearssl_certs_from_file succeeded: num=%lu\n", (unsigned long)num);
	for (u = 0; u < num; u ++) {
		br_x509_trust_anchor ta;

		if (rho_bearssl_certificate_to_ta_inner(&ta, &xcs[u]) < 0) {
            rho_bearssl_ta_list_destroy(&tas);
			rho_bearssl_certs_destroy(xcs, num);
			return 0;
		}
		RHO_VECTOR_ADD(tas, ta);
	}
	RHO_VECTOR_ADDMANY(*dst, &RHO_VECTOR_ELT(tas, 0), num);
	RHO_VECTOR_CLEAR(tas);
	rho_bearssl_certs_destroy(xcs, num);
	return num;
}

/*
 * Release contents for a trust anchor (assuming they were dynamically
 * allocated). The structure itself is NOT released.
 */
void
rho_bearssl_ta_destroy(br_x509_trust_anchor *ta)
{
	rhoL_free(ta->dn.data);
	switch (ta->pkey.key_type) {
	case BR_KEYTYPE_RSA:
		rhoL_free(ta->pkey.key.rsa.n);
		rhoL_free(ta->pkey.key.rsa.e);
		break;
	case BR_KEYTYPE_EC:
		rhoL_free(ta->pkey.key.ec.q);
		break;
	}
}

void
rho_bearssl_ta_list_destroy(struct rho_bearssl_ta_list *tas)
{
    RHO_VECTOR_CLEAREXT(*tas, &rho_bearssl_ta_destroy);
}
