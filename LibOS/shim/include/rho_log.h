#ifndef _RHO_LOG_H_
#define _RHO_LOG_H_

#include <assert.h>
#include <errno.h>

#include <shim_internal.h>

#include <pal.h>
#include <pal_debug.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

#define RHO_ASSERT(cond) assert(cond)

#define RHO_TRACE_ENTER(fmt, ...) \
    debug("> %s: " fmt "\n", __func__, ##__VA_ARGS__)

#define RHO_TRACE_EXIT(fmt, ...) \
    debug("< %s: "fmt "\n", __func__, ##__VA_ARGS__)

#define rho_errno_die(errnum, fmt, ...) \
    do { \
        sys_printf("die %s:%d " fmt ": %s\n", \
                __func__, __LINE__,##__VA_ARGS__, PAL_STRERROR(errnum)); \
        shim_terminate(-1); \
    } while (0)

#define rho_die(fmt, ...) \
    do { \
        sys_printf("die %s:%d " fmt "\n", \
                __func__, __LINE__,##__VA_ARGS__); \
        shim_terminate(-1); \
    } while (0)

#define rho_errno_warn(errnum, fmt, ...) \
    do { \
        sys_printf("warn %s:%d " fmt ": %s\n", \
                __func__, __LINE__,##__VA_ARGS__, PAL_STRERROR(errnum)); \
    } while (0)

#define rho_warn(fmt, ...) \
        sys_printf("warn %s:%d " fmt "\n", \
                __func__, __LINE__,##__VA_ARGS__)

void rho_hexdump(const void *p, size_t len, const char *fmt, ...);

RHO_DECLS_END

#endif /* ! _ RHO_LOG_H_ */

