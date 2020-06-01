#ifndef _RHO_MISC_H_
#define _RHO_MISC_H_

#include <rho_decls.h>

RHO_DECLS_BEGIN

#define RHO_C_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define RHO_MAX(a, b) ((a) > (b) ? (a) : (b))
#define RHO_MIN(a, b) ((a) < (b) ? (a) : (b))

RHO_DECLS_END

#endif /* _RHO_MISC_H_ */
