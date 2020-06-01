#include <shim_internal.h>
#include <shim_handle.h>
#include <shim_fs.h>

#include <atomic.h>

#include <rho_log.h>

struct shim_handle *
rho_shim_handle_open(const char *path, int flags, mode_t mode)
{
    int ret = 0;
    struct shim_handle *hdl = NULL;
    
    hdl = get_new_handle();
    if (!hdl)
        rho_die("get_new_handle() failed");
    ret = open_namei(hdl, NULL, path, flags, mode, NULL);
    if (ret < 0)
        /* error */

    put_handle(hdl);
    return (hdl);
}

int
rho_shim_handle_close(struct shim_handle *hdl)
{
    put_handle(hdl);
    return (0);
}

int
rho_shim_handle_read(struct shim_handle *hdl, void *buf, int count)
{
    return (do_handle_read(hdl, buf, count));
}

int
rho_shim_handle_write(struct shim_handle *hdl, const void *buf, int count)
{
    return (do_handle_write(hdl, buf, count));
}

size_t
rho_shim_handle_getfilesize(struct shim_handle *hdl)
{
    return (get_file_size(hdl));
}

void
rho_shim_handle_print(const struct shim_handle *hdl)
{
    debug("handle (addr=0x%p) = {\n", hdl);
    debug("  ref_count: %ld\n", atomic_read(&hdl->ref_count));
    debug("  type: %d\n", hdl->type);
    debug("  fs_type: %s\n", hdl->fs_type);
    debug("  path: %s\n", qstrgetstr(&hdl->path));
    debug("  flags: %08x\n", hdl->flags);
    debug("  acc_mode: %08x\n", hdl->acc_mode);

#if 0
    switch (hdl->type) {
    case TYPE_SMDISH:
        debug("  info (smdish) {\n");
        debug("    mf_idx: %d\n", hdl->info.smdish.mf_idx);
        debug("  }\n");
        break;
    case TYPE_SMUF:
        debug("  info (smuf) {\n");
        debug("    mf_idx: %d\n", hdl->info.smuf.mf_idx);
        debug("  }\n");
        break;
    default:
        break;
    } 
#endif
    debug("}\n");
}
