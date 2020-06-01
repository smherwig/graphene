#ifndef _RHO_PATH_H_
#define _RHO_PATH_H_

#include <stddef.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

int rho_path_join(const char *a, const char *b, char *buf, size_t buflen);
char * rho_path_join_alloc(const char *a, const char *b);

RHO_DECLS_END

#endif /* ! _RHO_PATH_H_ */
