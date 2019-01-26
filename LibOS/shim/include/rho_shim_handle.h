#ifndef _RHO_SHIM_HANDLE_H_
#define _RHO_SHIM_HANDLE_H_

#include <shim_internal.h>
#include <shim_handle.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

struct shim_handle * rho_shim_handle_open(const char *path, int flags,
        mode_t mode);

int rho_shim_handle_close(struct shim_handle *hdl);
int rho_shim_handle_read(struct shim_handle *hdl, void *buf, int count);
int rho_shim_handle_write(struct shim_handle *hdl, const void *buf, int count);
size_t rho_shim_handle_getfilesize(struct shim_handle *hdl);

RHO_DECLS_END

#endif /* _RHO_SHIM_HANDLE_H_ */
