#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_fs.h>

#include <rho_log.h>
#include <rho_path.h>

void
rho_shim_dentry_print(const struct shim_dentry *dent)
{
    rho_debug("dentry{state:%d, rel_path: \"%s\", name: \"%s\", nchildren: %d, ino: %lu, type: %u, mode: %u",
            dent->state, qstrgetstr(&dent->rel_path), qstrgetstr(&dent->name),
            dent->nchildren, dent->ino, dent->type, dent->mode);
}

/*
 * If the mount point for dentry's filesystem is
 * /foo/bar, and dentry's filename is baz/abc, this function
 * will return /foo/bar/baz/abc.
 */
int 
rho_shim_dentry_abspath(const struct shim_dentry *dent, char *buf,
        size_t bufsize)
{
    int error = 0;
    struct shim_mount *mnt = NULL;
    const char *mntpath = NULL;
    const char *relpath = NULL;

    mntpath = qstrgetstr(&mnt->path);
    relpath = qstrgetstr(&dent->rel_path);
    error = rho_path_join(mntpath, relpath, buf, bufsize);

    return (error);
}

/*
 * If the mount point for dentry's filesystem is
 * /foo/bar, and dentry's filename is baz/abc, this function
 * will return /baz/abc.
 */
int
rho_shim_dentry_relpath(const struct shim_dentry *dent, char *buf,
        size_t bufsize)
{
    int error = 0;
    const char *relpath = NULL;
    size_t len = 0;

    /* XXX: does relpath start with a '/' ?  -- no */
    relpath = qstrgetstr(&dent->rel_path);
    len = dent->rel_path.len; 

    if (len + 2 <= bufsize) {
        buf[0] = '/';
        memcpy(buf + 1, relpath, len);
        buf[len+1] = '\0';
    } else {
        /* not enough space to write nul-terminated path */
        error = -1;
    }

    return (error);
}
