#ifndef _RHO_ENDIAN_H_
#define _RHO_ENDIAN_H_

#include <stdint.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

static inline uint16_t
rho_swap_u16(uint16_t x)
{
    return ( (x >> 8) | (x << 8) );
}

static inline uint32_t
rho_swap_u32(uint32_t x)
{
    return (
        ((x >> 24) & 0x000000ff) | 
        ((x >>  8) & 0x0000ff00) | 
        ((x <<  8) & 0x00ff0000) | 
        ((x << 24) & 0xff000000)
    );
}

static inline uint64_t
rho_swap_u64(uint64_t x)
{
    return (
        ((x >> 56) & 0x00000000000000ff) |
        ((x >> 40) & 0x000000000000ff00) |
        ((x >> 24) & 0x0000000000ff0000) |
        ((x >>  8) & 0x00000000ff000000) |
        ((x <<  8) & 0x000000ff00000000) |
        ((x << 24) & 0x0000ff0000000000) |
        ((x << 40) & 0x00ff000000000000) |
        ((x << 56) & 0xff00000000000000)
    );
}

/* XXX: for now, assume host is little-endian */
#define rho_htobe16(x)  rho_swap_u16(x)
#define rho_be16toh(x)  rho_swap_u16(x)
#define rho_htole16(x)  ((uint16_t)(x))
#define rho_le16toh(x)  ((uint16_t)(x))

#define rho_htobe32(x)  rho_swap_u32(x)
#define rho_be32toh(x)  rho_swap_u32(x)
#define rho_htole32(x)  ((uint32_t)(x))
#define rho_le32toh(x)  ((uint32_t)(x))

#define rho_htobe64(x)  rho_swap_u64(x)
#define rho_be64toh(x)  rho_swap_u64(x)
#define rho_htole64(x)  ((uint64_t)(x))
#define rho_le64toh(x)  ((uint64_t)(x))


RHO_DECLS_END

#endif /* ! _RHO_ENDIAN_H_ */
