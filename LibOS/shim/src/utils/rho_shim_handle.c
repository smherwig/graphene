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
    rho_debug("handle (addr=%p) {type: %d, ref_count: %ld, fs_type: \"%s\", "
              "path: \"%s\", uri: \"%s\", flags: 0x%x, acc_mode: 0x%x, "
              "owner: %u}",
            hdl, hdl->type, atomic_read(&hdl->ref_count), hdl->fs_type,
            qstrgetstr(&hdl->path), qstrgetstr(&hdl->uri), hdl->flags,
            hdl->acc_mode, hdl->owner);

    switch (hdl->type) {
    case TYPE_NEXTFS:
        rho_debug("handle info (nextfs) {fd: %u}", hdl->info.nextfs.fd);
        break;
    case TYPE_SMDISH:
        rho_debug("handle info (smdish) {mf_idx: %d}", hdl->info.smdish.mf_idx);
        break;
    case TYPE_SMUF:
        rho_debug("handle info (smuf) {mf_idx: %d}", hdl->info.smuf.mf_idx);
        break;
    case TYPE_SMC:
        rho_debug("handle info (smc) {mf_idx: %d}", hdl->info.smc.mf_idx);
        break;
    default:
        break;
    } 
}
