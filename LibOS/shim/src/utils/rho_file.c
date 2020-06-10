#include <shim_internal.h>
#include <shim_handle.h>
#include <shim_fs.h>

#include <errno.h>

#include <rho_file.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_shim_handle.h>

int
rho_file_readall(const char *path, uint8_t **buf, size_t *len)
{
    int error = 0;
    struct shim_handle *hdl = NULL;
    size_t size = 0;
    int n = 0;

    hdl = rho_shim_handle_open(path, O_RDONLY, 0);
    if (hdl == NULL)
        goto fail;

    size = rho_shim_handle_getfilesize(hdl);
    *buf = rhoL_malloc(size);
    
    n = rho_shim_handle_read(hdl, *buf, size);
    if ((n < 0) || (((unsigned)n) != size)) {
        debug("rho_shim_handle_read(%lu) returned %d\n",
                (unsigned long)size, n);
        goto fail;
    }
    
    *len = n;
    error = 0;
    goto succeed;

fail:
    if (*buf != NULL) {
        rhoL_free(*buf);
        *buf = NULL;
    }
succeed:
#if 0
    // this seems to drop the reference count below 0
    if (hdl != NULL)
        rho_shim_handle_close(hdl); 
#endif
    return (error);
}
