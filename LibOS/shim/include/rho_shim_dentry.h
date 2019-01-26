#ifndef _RHO_SHIM_DENTRY_H_
#define _RHO_SHIM_DENTRY_H_

#include <shim_internal.h>
#include <shim_handle.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

void rho_shim_dentry_print(const struct shim_dentry *dent);

int rho_shim_dentry_abspath(const struct shim_dentry *dent, char *buf,
        size_t bufsize);

int rho_shim_dentry_relpath(const struct shim_dentry *dent, char *buf,
        size_t bufsize);



RHO_DECLS_END

#endif /* _RHO_SHIM_DENTRY_H_ */
