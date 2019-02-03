#ifndef _RHO_RAND_H_
#define _RHO_RAND_H_

#include <stddef.h>
#include <stdint.h>

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_decls.h>


RHO_DECLS_BEGIN

void rho_rand_randombytes(uint8_t *buf, size_t size);

uint8_t rho_rand_uint8(void);
uint16_t rho_rand_uint16(void);
uint32_t rho_rand_uint32(void);
uint64_t rho_rand_uint64(void);

RHO_DECLS_END

#endif /* !_RHO_RAND_H_ */
