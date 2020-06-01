#include <shim_internal.h>
#include <shim_utils.h>
#include <shim_fs.h>

#include <rho_path.h>

void
rho_shim_dentry_print(const struct shim_dentry *dent)
{
    debug("dentry {\n");
    debug("  state: %d,\n", dent->state);
    debug("  rel_path: %s\n", qstrgetstr(&dent->rel_path));
    debug("  len(rel_path): %lu\n", (unsigned long) dent->rel_path.len);
    debug("  name: %s\n", qstrgetstr(&dent->name));
    debug("  len(name): %lu\n", (unsigned long) dent->name.len);
    debug("  nchildren: %d\n", dent->nchildren);
    debug("  ino: %lu\n", dent->ino);
    debug("  type: %lu\n", (unsigned long)dent->type);
    debug("  mode: %lu\n", (unsigned long)dent->mode);
    debug("}\n");
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
