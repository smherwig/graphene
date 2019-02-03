#include <stddef.h>
#include <stdint.h>

#include <shim_internal.h>
#include <shim_types.h>
#include <shim_utils.h>

#include <rho_rand.h>

void
rho_rand_randombytes(uint8_t *buf, size_t size)
{
    getrand(buf, size);
}

uint8_t
rho_rand_uint8(void)
{
    uint8_t v = 0;
    rho_rand_randombytes((uint8_t *)&v, sizeof(v));
    return (v);
}

uint16_t
rho_rand_uint16(void)
{
    uint16_t v = 0;
    rho_rand_randombytes((uint8_t *)&v, sizeof(v));
    return (v);
}

uint32_t
rho_rand_uint32(void)
{
    uint32_t v = 0;
    rho_rand_randombytes((uint8_t *)&v, sizeof(v));
    return (v);
}

uint64_t
rho_rand_uint64(void)
{
    uint64_t v = 0;
    rho_rand_randombytes((uint8_t *)&v, sizeof(v));
    return (v);
}
