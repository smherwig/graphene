#ifndef _RHO_BINASCII_H_
#define _RHO_BINASCII_H_

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

void rho_binascii_hexlify(uint8_t *bin, size_t binsize, char *outhex);
void rho_binascii_unhexlify(char *hex, size_t hexlen, uint8_t *outbin);
size_t rho_binascii_hex2bin(unsigned char *dst, const char *src);

size_t rho_binascii_b64encodesize(size_t binsize);
void rho_binascii_b64encode(const uint8_t *bin, size_t binsize, char *outasc);

RHO_DECLS_END

#endif /* !_RHO_BINASCII_H_ */
