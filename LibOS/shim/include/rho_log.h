#ifndef _RHO_LOG_H_
#define _RHO_LOG_H_

#include <assert.h>
#include <errno.h>

#include <shim_internal.h>

#include <pal.h>
#include <pal_debug.h>
#include <pal_error.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

#define RHO_ASSERT(cond) assert(cond)

#ifndef RHO_LOG_PREFIX
#define RHO_LOG_PREFIX "RHO"
#endif

#define RHO_TRACE_ENTER(fmt, ...) \
    debug(RHO_LOG_PREFIX " (Enter %s) " fmt "\n", __func__, ##__VA_ARGS__)

#define RHO_TRACE_EXIT(fmt, ...) \
    debug(RHO_LOG_PREFIX " (Exit %s) "fmt "\n", __func__, ##__VA_ARGS__)

#define rho_errno_die(errnum, fmt, ...) \
    do { \
        SYS_PRINTF(RHO_LOG_PREFIX " (Die %s:%d) " fmt ": %s\n", \
                __func__, __LINE__,##__VA_ARGS__, pal_strerror(errnum)); \
        shim_clean_and_exit(-ENOTRECOVERABLE); \
    } while (0)

#define rho_die(fmt, ...) \
    do { \
        SYS_PRINTF(RHO_LOG_PREFIX " (Die %s:%d) " fmt "\n", \
                __func__, __LINE__,##__VA_ARGS__); \
        shim_clean_and_exit(-ENOTRECOVERABLE); \
    } while (0)

#define rho_errno_warn(errnum, fmt, ...) \
    do { \
        SYS_PRINTF(RHO_LOG_PREFIX " (Warn %s:%d) " fmt ": %s\n", \
                __func__, __LINE__,##__VA_ARGS__, pal_strerror(errnum)); \
    } while (0)

#define rho_warn(fmt, ...) \
        SYS_PRINTF(RHO_LOG_PREFIX " (Warn %s:%d) " fmt "\n", \
                __func__, __LINE__,##__VA_ARGS__)

#define rho_info(fmt, ...) \
        SYS_PRINTF(RHO_LOG_PREFIX " (Info %s:%d) " fmt "\n", \
                __func__, __LINE__,##__VA_ARGS__)

#define rho_debug(fmt, ...) \
        debug(RHO_LOG_PREFIX " (Debug %s:%d) " fmt "\n", \
                __func__, __LINE__,##__VA_ARGS__)

void rho_hexdump(const void *p, size_t len, const char *fmt, ...);

RHO_DECLS_END

#endif /* ! _ RHO_LOG_H_ */

