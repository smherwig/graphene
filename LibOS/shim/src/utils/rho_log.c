#if 0
#include <stdarg.h>
#endif

#include <shim_internal.h>

#include <rho_log.h>

void
rho_hexdump(const void *p, size_t len, const char *fmt, ...)
{
    va_list ap;
    size_t i = 0;
    const uint8_t *pc = p;

    va_start(ap, fmt);
    SYS_PRINTF(fmt, ap);
    va_end(ap);

    SYS_PRINTF("(%lu bytes):", len);
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0)
            SYS_PRINTF("\n0x%04lx:  ", i);
        SYS_PRINTF("%02x ", pc[i]);
    }
    SYS_PRINTF("\n");
}

