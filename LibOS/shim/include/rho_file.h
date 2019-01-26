#ifndef _RHO_FILE_H_
#define _RHO_FILE_H_

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

/* return 0 on success; -1 on failure */
int rho_file_readall(const char *path, uint8_t **buf, size_t *len);

RHO_DECLS_END

#endif /* _RHO_FILE_H_ */
