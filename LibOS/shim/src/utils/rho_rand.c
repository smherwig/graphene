#include <stddef.h>
#include <stdint.h>

#include <shim_internal.h>
#include <shim_types.h>
#include <shim_utils.h>

#include <rho_rand.h>

void
rho_rand_bytes(uint8_t *buf, size_t size)
{
    getrand(buf, size);
}

uint8_t
rho_rand_u8(void)
{
    uint8_t v = 0;
    rho_rand_bytes((uint8_t *)&v, sizeof(v));
    return (v);
}

uint16_t
rho_rand_u16(void)
{
    uint16_t v = 0;
    rho_rand_bytes((uint8_t *)&v, sizeof(v));
    return (v);
}

uint32_t
rho_rand_u32(void)
{
    uint32_t v = 0;
    rho_rand_bytes((uint8_t *)&v, sizeof(v));
    return (v);
}

uint64_t
rho_rand_u64(void)
{
    uint64_t v = 0;
    rho_rand_bytes((uint8_t *)&v, sizeof(v));
    return (v);
}

/*
 * Distributions
 */

uint32_t
rho_rand_uniform_u32(uint32_t a, uint32_t b)
{
    uint32_t u = 0;
    double d = 0;
    uint32_t ret = 0;

    u = rho_rand_u32();
    d = u / 4294967295.0;
    ret = (uint32_t)(a + ((b-a) * d));
    return (ret);
}
