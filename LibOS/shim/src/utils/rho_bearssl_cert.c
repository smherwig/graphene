#include <stddef.h>

#include <bearssl.h>

#include <rho_der.h>
#include <rho_file.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_str.h>
#include <rho_vector.h>

#include <rho_bearssl_cert.h>
#include <rho_bearssl_common.h>
#include <rho_bearssl_pem.h>


/*
 * Get the certificate(s) from a file. This accepts both a single
 * DER-encoded certificate, and a text file that contains
 * PEM-encoded certificates (and possibly other objects, which are
 * then ignored).
 *
 * On decoding error, or if the file turns out to contain no certificate
 * at all, then an error message is printed and NULL is returned.
 *
 * The returned array, and all referenced buffers, are allocated with
 * xmalloc() and must be released by the caller. The returned array
 * ends with a dummy entry whose 'data' field is NULL.
 * The number of decoded certificates (not counting the dummy entry)
 * is written into '*num'.
 */
br_x509_certificate *
rho_bearssl_certs_from_file(const char *fname, size_t *num)
{
	RHO_VECTOR(,br_x509_certificate) cert_list = RHO_VECTOR_INIT;
	unsigned char *buf;
	size_t len;
	struct rho_pem *pos;
	size_t u, num_pos;
	br_x509_certificate *xcs;
	br_x509_certificate dummy;

	*num = 0;

	/*
	 * TODO: reading the whole file is crude; we could parse them
	 * in a streamed fashion. But it does not matter much in practice.
	 */
    debug("rho_file_readall\n");
    if (rho_file_readall(fname, &buf, &len) == -1) {
        debug("rho_file_readall failed\n");
		return NULL;
    }
    debug("rho_file_readall succeeded, len=%lu\n", (unsigned long)len);
    rho_hexdump(buf, len, "root.crt");

	/*
	 * Check for a DER-encoded certificate.
	 */
    debug("rho_der_looks_like_der\n");
	if (rho_der_looks_like_der(buf, len)) {
		xcs = rhoL_mallocarray(2, sizeof(*xcs), 0);
		xcs[0].data = buf;
		xcs[0].data_len = len;
		xcs[1].data = NULL;
		xcs[1].data_len = 0;
		*num = 1;
        debug("is der, returning\n");
		return xcs;
	}

    debug("rho_bearssl_pem_decode\n");
	pos = rho_bearssl_pem_decode(buf, len, &num_pos);
	rhoL_free(buf);
	if (pos == NULL) {
        debug("pos == NULL\n");
		return NULL;
	}
    debug("rho_bearssl_pem_decode succeed: num_pos=%lu\n", (unsigned long)num_pos);
	for (u = 0; u < num_pos; u ++) {
		if (rho_str_equal_ci_ignore(pos[u].name, "CERTIFICATE", RHO_SSL_IGN_CHARS)
			|| rho_str_equal_ci_ignore(pos[u].name, "X509 CERTIFICATE", RHO_SSL_IGN_CHARS))
		{
			br_x509_certificate xc;

			xc.data = pos[u].data;
			xc.data_len = pos[u].data_len;
			pos[u].data = NULL;
			RHO_VECTOR_ADD(cert_list, xc);
		}
	}
	for (u = 0; u < num_pos; u ++) {
		rho_pem_destroy(&pos[u]);
	}
	rhoL_free(pos);

	if (RHO_VECTOR_LEN(cert_list) == 0) {
        rho_warn("ERROR: no certificate in file '%s'\n", fname);
		return NULL;
	}
	*num = RHO_VECTOR_LEN(cert_list);
	dummy.data = NULL;
	dummy.data_len = 0;
	RHO_VECTOR_ADD(cert_list, dummy);
	xcs = RHO_VECTOR_TOARRAY(cert_list);
	RHO_VECTOR_CLEAR(cert_list);
	return xcs;
}

/*
 * Release certificates. This releases all certificate data arrays,
 * and the whole array as well.
 */
void
rho_bearssl_certs_destroy(br_x509_certificate *certs, size_t num)
{
	size_t u;

	for (u = 0; u < num; u++) {
		rhoL_free(certs[u].data);
	}
	rhoL_free(certs);
}

