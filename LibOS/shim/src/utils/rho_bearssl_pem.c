#include <stddef.h>

#include <shim_internal.h>
#include <shim_types.h>

#include <bearssl.h>

#include <rho_bearssl_pem.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_pem.h>
#include <rho_vector.h>


static void
rho_bearssl_pem_vblob_append(void *cc, const void *data, size_t len)
{
	rho_bytevector *bv;

	bv = cc;
	RHO_VECTOR_ADDMANY(*bv, data, len);
}


/*
 * Decode a buffer as a PEM file, and return all objects. On error, NULL
 * is returned and an error message is printed. Absence of any object
 * is an error.
 *
 * The returned array is terminated by a dummy object whose 'name' is
 * NULL. The number of objects (not counting the dummy terminator) is
 * written in '*num'.
 */
struct rho_pem *
rho_bearssl_pem_decode(const void *src, size_t len, size_t *num)
{
	RHO_VECTOR(, struct rho_pem) pem_list = RHO_VECTOR_INIT;
	br_pem_decoder_context pc;
	struct rho_pem po, *pos;
	const unsigned char *buf;
	rho_bytevector bv = RHO_VECTOR_INIT;
	int inobj;
	int extra_nl;

	*num = 0;
	br_pem_decoder_init(&pc);
	buf = src;
	inobj = 0;
	po.name = NULL;
	po.data = NULL;
	po.data_len = 0;
	extra_nl = 1;
	while (len > 0) {
		size_t tlen;

		tlen = br_pem_decoder_push(&pc, buf, len);
		buf += tlen;
		len -= tlen;
		switch (br_pem_decoder_event(&pc)) {

		case BR_PEM_BEGIN_OBJ:
			po.name = rhoL_strdup(br_pem_decoder_name(&pc));
			br_pem_decoder_setdest(&pc, rho_bearssl_pem_vblob_append, &bv);
			inobj = 1;
			break;

		case BR_PEM_END_OBJ:
			if (inobj) {
				po.data = RHO_VECTOR_TOARRAY(bv);
				po.data_len = RHO_VECTOR_LEN(bv);
				RHO_VECTOR_ADD(pem_list, po);
				RHO_VECTOR_CLEAR(bv);
				po.name = NULL;
				po.data = NULL;
				po.data_len = 0;
				inobj = 0;
			}
			break;

		case BR_PEM_ERROR:
			rhoL_free(po.name);
			RHO_VECTOR_CLEAR(bv);
			rho_warn("ERROR: invalid PEM encoding\n");
			RHO_VECTOR_CLEAREXT(pem_list, &rho_pem_destroy);
			return NULL;
		}

		/*
		 * We add an extra newline at the end, in order to
		 * support PEM files that lack the newline on their last
		 * line (this is somwehat invalid, but PEM format is not
		 * standardised and such files do exist in the wild, so
		 * we'd better accept them).
		 */
		if (len == 0 && extra_nl) {
			extra_nl = 0;
			buf = (const unsigned char *)"\n";
			len = 1;
		}
	}
	if (inobj) {
		rho_warn("ERROR: unfinished PEM object\n");
		rhoL_free(po.name);
		RHO_VECTOR_CLEAR(bv);
		RHO_VECTOR_CLEAREXT(pem_list, &rho_pem_destroy);
		return NULL;
	}

	*num = RHO_VECTOR_LEN(pem_list);
	RHO_VECTOR_ADD(pem_list, po);
	pos = RHO_VECTOR_TOARRAY(pem_list);
	RHO_VECTOR_CLEAR(pem_list);
	return pos;
}
