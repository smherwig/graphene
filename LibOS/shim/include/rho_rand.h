#ifndef _RHO_RAND_H_
#define _RHO_RAND_H_

#include <stddef.h>
#include <stdint.h>

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_decls.h>


RHO_DECLS_BEGIN

void rho_rand_bytes(uint8_t *buf, size_t size);

uint8_t rho_rand_u8(void);
uint16_t rho_rand_u16(void);
uint32_t rho_rand_u32(void);
uint64_t rho_rand_u64(void);

uint32_t rho_rand_uniform_u32(uint32_t a, uint32_t b);

RHO_DECLS_END

#endif /* !_RHO_RAND_H_ */
