/*
 * fs.c
 *
 * The 'sm0' filesystem.
 */

#include <shim_internal.h>
#include <shim_thread.h>
#include <shim_handle.h>
#include <shim_vma.h>
#include <shim_fs.h>
#include <shim_utils.h>
#include <shim_profile.h>

#include <pal.h>
#include <pal_debug.h>
#include <pal_error.h>

#include <errno.h>

#include <linux/stat.h>
#include <linux/fcntl.h>

#include <asm/fcntl.h>
#include <asm/mman.h>
#include <asm/unistd.h>
#include <asm/prctl.h>

#include <inttypes.h>
#include <string.h>

#include <bearssl.h>

#include <rho_binascii.h>
#include <rho_bitops.h>
#include <rho_endian.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_misc.h>
#include <rho_queue.h>
#include <rho_rand.h>
#include <rho_shim_dentry.h>
#include <rho_sock.h>
#include <rho_ssl.h>
#include <rho_str.h>
#include <rho_ticketlock.h>

#include <rpc.h>
#include <tcad.h>

#define SM0_IV_SIZE 12
#define SM0_KEY_SIZE 32

/* ticketlock with associated data (the iv) */
struct sm0_lockad {
    struct rho_ticketlock tl; 
    uint8_t iv[SM0_IV_SIZE];
}; 

struct sm0_memfile {
    char name[TCAD_MAX_NAME_SIZE];
    /* ---- */
    size_t size;
    void *pub_mem;
    void *priv_mem;
    uint8_t key[SM0_KEY_SIZE];
    struct sm0_lockad *lockad;
};

/*
 * FIXME:
 * We have a hard limit of 32 memfiles opened.
 * The implementation is simplistic because the struct
 * is (I believe) shallow-copied during migration/fork,
 * and a more robust data structure (with internal pointers)
 * would require additional work to reconstitute during
 * migration/fork.
 */
struct sm0_mdata {
    uint32_t fd_bitmap;
    struct sm0_memfile fd_tab[32];
};

/******************************************
 * SM0_LOCKAD: lock with associated data 
 * (i.e, the IV)
 ******************************************/

static struct sm0_lockad *
sm0_lockad_create(void)
{
    struct sm0_lockad *lockad = NULL;

    RHO_TRACE_ENTER();

    lockad =  DkVirtualMemoryAlloc(NULL, 
            sizeof(struct sm0_lockad), PAL_ALLOC_UNTRUSTED, 
            PAL_PROT((PROT_READ|PROT_WRITE), 0));

    if (lockad == NULL) {
        rho_errno_warn(PAL_ERRNO, "mmap lockad");
        goto done;
    }

    lockad->tl.ticket_number = 0;
    lockad->tl.turn = 0;

done:
    RHO_TRACE_EXIT();
    return (lockad);
}

static void
sm0_lockad_destroy(struct sm0_lockad *lockad)
{
    RHO_TRACE_ENTER();
    
    DkVirtualMemoryFree(lockad, sizeof(struct sm0_lockad)); 

    RHO_TRACE_EXIT();
}

static int
sm0_lockad_lock(struct sm0_lockad *lockad)
{
    int my_turn = 0;
    struct rho_ticketlock *tl = &lockad->tl;

    my_turn = rho_atomic_fetch_inc(&tl->ticket_number);
    while (my_turn != tl->turn) { /* spin */ ; }
    return (my_turn);
}

static void
sm0_lockad_unlock(struct sm0_lockad *lockad)
{
    struct rho_ticketlock *tl = &lockad->tl;
    rho_atomic_fetch_inc(&tl->turn);
}

/********************************* 
 * AES-CTR
 *********************************/

static void
sm0_encrypt(uint8_t *data, size_t data_len, const uint8_t *key,
        const uint8_t *iv)
{
#if 0
    br_aes_x86ni_ctr_keys ctx;
    uint32_t cc = 0;
    uint32_t cc_out = 0;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, SM0_KEY_SIZE);
    cc_out = br_aes_x86ni_ctr_run(&ctx, iv, cc, data, data_len);
    (void)cc_out;

    RHO_TRACE_EXIT();
#endif
}

static void
sm0_decrypt(uint8_t *data, size_t data_len, const uint8_t *key,
        const uint8_t *iv)
{
#if 0
    br_aes_x86ni_ctr_keys ctx;
    uint32_t cc = 0;
    uint32_t cc_out = 0;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, SM0_KEY_SIZE);
    cc_out = br_aes_x86ni_ctr_run(&ctx, iv, cc, data, data_len);
    (void)cc_out;

    RHO_TRACE_EXIT();
#endif
}

/******************************************
 * MEMFILE
 *
 * A MEMFILE is either a lock file or a lock
 * file with associated shared memory.
 ******************************************/ 

static int
sm0_memfile_make_map(struct sm0_memfile *mf, size_t size)
{
    int error = 0;

    RHO_TRACE_ENTER();

    mf->size = size;

    mf->pub_mem =  DkVirtualMemoryAlloc(NULL, size, PAL_ALLOC_UNTRUSTED,
            PAL_PROT((PROT_READ|PROT_WRITE), 0));
    if (mf->pub_mem == NULL) {
        rho_errno_warn(PAL_ERRNO, "mmap public");
        error = -1;
        goto fail;
    }

    mf->priv_mem = DkVirtualMemoryAlloc(NULL, size, 0,
            PAL_PROT((PROT_READ|PROT_WRITE), 0));
    if (mf->priv_mem == NULL) {
        rho_errno_warn(PAL_ERRNO, "mmap private");
        error = -1;
        goto fail;
    }

    rho_rand_bytes(mf->lockad->iv, SM0_IV_SIZE);
    rho_rand_bytes(mf->key, SM0_KEY_SIZE);
    sm0_encrypt(mf->priv_mem, mf->size, mf->key, mf->lockad->iv);
    memcpy(mf->pub_mem, mf->priv_mem, mf->size);

    goto succeed;

fail:
    if (mf->pub_mem != NULL)
        DkVirtualMemoryFree(mf->pub_mem, size);
succeed:
    RHO_TRACE_EXIT();
    return (error);
}

static void
sm0_memfile_clear(struct sm0_memfile *mf)
{
    RHO_TRACE_ENTER();

    if (mf->pub_mem != NULL)
        DkVirtualMemoryFree(mf->pub_mem, mf->size);

    if (mf->priv_mem != NULL)
        DkVirtualMemoryFree(mf->priv_mem, mf->size);

    if (mf->lockad != NULL)
        sm0_lockad_destroy(mf->lockad);

    rho_memzero(mf, sizeof(*mf));

    RHO_TRACE_EXIT();
}

static void
sm0_memfile_map_in(struct sm0_memfile *mf)
{
    RHO_TRACE_ENTER();

    memcpy(mf->priv_mem, mf->pub_mem, mf->size);
    sm0_decrypt(mf->priv_mem, mf->size, mf->key, mf->lockad->iv);

    RHO_TRACE_EXIT();
}

static void
sm0_memfile_map_out(struct sm0_memfile *mf)
{
    uint8_t iv[SM0_IV_SIZE] = {0};

    RHO_TRACE_ENTER();

    rho_rand_bytes(iv, SM0_IV_SIZE);
    sm0_encrypt(mf->priv_mem, mf->size, mf->key, iv);
    memcpy(mf->pub_mem, mf->priv_mem, mf->size);
    memcpy(mf->lockad->iv, iv, sizeof(iv));

    RHO_TRACE_EXIT();
}

/**********************************************************
 * MOUNT DATA
 *
 * Data for the mount point.  sm0 uses it as an fs-specific
 * file descriptor table.
 **********************************************************/

static int
sm0_fd_bitmap_ffc(uint32_t bitmap)
{
    int i = 0;
    int val = 0;

    RHO_BITOPS_FOREACH(i, val, (uint8_t *)&bitmap, sizeof(bitmap)) {
        if (val == 0)
            return (i);
    }

    /* TODO: assert error, because bitmap is full */
    return (-1);
}

static struct sm0_mdata *
sm0_mdata_create(void)
{
    struct sm0_mdata *mdata = NULL;
    
    RHO_TRACE_ENTER();

    mdata = rhoL_zalloc(sizeof(*mdata));

    RHO_TRACE_EXIT();
    return (mdata);
}

static struct sm0_memfile *
sm0_mdata_new_memfile(struct sm0_mdata *mdata, const char *name)
{
    int i = 0;
    struct sm0_memfile *mf = NULL;

    i = sm0_fd_bitmap_ffc(mdata->fd_bitmap);
    if (i == -1)
        goto done;  /* fd table full */

    RHO_BITOPS_SET((uint8_t *)&mdata->fd_bitmap, i);
    mf = &(mdata->fd_tab[i]);
    rho_memzero(mf, sizeof(*mf));
    memcpy(mf->name, name, strlen(name));
    mf->lockad = sm0_lockad_create();

done:
    return (mf);
}

/********************************* 
 * FILE/FILESYSTEM OPERATIONS
 *********************************/

static int
sm0_mount(const char *uri, const char *root, void **mount_data)
{
    struct sm0_mdata *mdata = NULL;

    RHO_TRACE_ENTER("uri=\"%s\", root=\"%s\"", uri, root);

    mdata = sm0_mdata_create();
    *mount_data = mdata;

    RHO_TRACE_EXIT();
    return (0);
}

static int
sm0_close(struct shim_handle *hdl)
{
    struct sm0_mdata *mdata = hdl->fs->data;
    uint32_t fd = hdl->info.sm0.fd;
    struct sm0_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    mf = &(mdata->fd_tab[fd]);
    sm0_memfile_clear(mf);
    RHO_BITOPS_CLR((uint8_t *)&mdata->fd_tab, fd);

    RHO_TRACE_EXIT();
    return (0);
}

static int
sm0_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    struct sm0_mdata *mdata = hdl->fs->data;
    uint32_t fd = hdl->info.sm0.fd;
    struct sm0_memfile *mf = NULL;

    (void)prot;
    (void)flags;
    (void)offset;

    RHO_TRACE_ENTER();

    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    mf = &(mdata->fd_tab[fd]);
    error = sm0_memfile_make_map(mf, size);
    if (error == -1)
        error = -PAL_ERRNO;

    RHO_TRACE_EXIT();
    return (error);
}

static int
sm0_advlock_lock(struct shim_handle *hdl, struct flock *flock)
{
    struct sm0_mdata *mdata = hdl->fs->data;
    uint32_t fd = hdl->info.sm0.fd;
    struct sm0_memfile *mf = NULL;

    (void)flock;

    RHO_TRACE_ENTER();

    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    mf = &(mdata->fd_tab[fd]);
    (void)sm0_lockad_lock(mf->lockad);
    sm0_memfile_map_in(mf);

    RHO_TRACE_EXIT();
    return (0);
}

static int
sm0_advlock_unlock(struct shim_handle *hdl, struct flock *flock)
{
    struct sm0_mdata *mdata = hdl->fs->data;
    uint32_t fd = hdl->info.sm0.fd;
    struct sm0_memfile *mf = NULL;

    (void)flock;

    RHO_TRACE_ENTER();

    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    /* 
     * FIXME: should we return an error if the client does not
     * possess the lock?
     */

    mf = &(mdata->fd_tab[fd]);
    sm0_memfile_map_out(mf);
    sm0_lockad_unlock(mf->lockad);

    RHO_TRACE_EXIT();
    return (0);
}

static int
sm0_advlock(struct shim_handle *hdl, int op, struct flock *flock)
{
    int error = 0;

    (void)op;

    RHO_TRACE_ENTER();

    if (flock->l_type == F_WRLCK)
        error = sm0_advlock_lock(hdl, flock);
    else if (flock->l_type == F_UNLCK)
        error = sm0_advlock_unlock(hdl, flock);
    else
        error = -EINVAL;

    RHO_TRACE_EXIT();
    return (error);
}

static int
sm0_checkpoint(void **checkpoint, void *mount_data)
{
    struct sm0_mdata *mdata = mount_data;

    RHO_TRACE_ENTER();

    *checkpoint = mdata;

    RHO_TRACE_ENTER();

    return (sizeof(*mdata));
}

static int
sm0_migrate(void *checkpoint, void **mount_data)
{
    struct sm0_mdata *mdata = NULL;

    RHO_TRACE_ENTER();

    mdata = rhoL_zalloc(sizeof(struct sm0_mdata));
    memcpy(mdata, checkpoint, sizeof(struct sm0_mdata));
    *mount_data = mdata;

    RHO_TRACE_EXIT();
    return (0);
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/

static int
sm0_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    struct sm0_mdata *mdata = dent->fs->data;
    uint32_t fd = 0;
    char name[TCAD_MAX_NAME_SIZE] = { 0 };
    struct sm0_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    rho_shim_dentry_relpath(dent, name, sizeof(name));

    /* TODO: we need this call to return an fd */
    mf = sm0_mdata_new_memfile(mdata, name);
    if (mf == NULL) {
        error = -ENFILE;
        goto done;
    }

    /* fill in handle */
    hdl->type = TYPE_SM0;
    hdl->flags = flags;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);
    hdl->info.sm0.fd = fd;

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
sm0_lookup(struct shim_dentry *dent, bool force)
{
    debug("> sm0_lookup(dent=*, force=%d)\n", force);
    (void)force;

    rho_shim_dentry_print(dent);
    debug("dent->fs=%p\n", dent->fs);
    debug("dent->fs->data=%p\n", dent->fs->data);

    /* XXX: I know fs/shim_namei.c:297 asserts this condition, but why? */
    if (qstrempty(&dent->rel_path)) {
        dent->state |= DENTRY_ISDIRECTORY;
        goto done;
    }

    /* TODO: set ino? */

done:
    debug("< sm0_lookup\n");
    return (0);
}

static int 
sm0_mode(struct shim_dentry *dent, mode_t *mode, bool force)
{
    debug("> sm0_mode\n");
    (void)mode;

    rho_shim_dentry_print(dent);
    debug("dent->fs=%p\n", dent->fs);
    debug("dent->fs->data=%p\n", dent->fs->data);
    debug("mode=%p\n", mode);

    *mode = 0777;

    debug("< sm0_mode\n");
    return (0);
}

static int
sm0_unlink(struct shim_dentry *dir, struct shim_dentry *dent)
{
    debug("> sm0_unlink(dir=*, dent=*)\n");
    (void)dir; (void)dent;
    debug("< sm0_unlink\n");
    return (-ENOSYS);
}

struct shim_fs_ops sm0_fs_ops = {
        .mount       = &sm0_mount,
        .close       = &sm0_close,
        .mmap        = &sm0_mmap,
        .advlock     = &sm0_advlock,
        .checkpoint  = &sm0_checkpoint,
        .migrate     = &sm0_migrate,
    };

struct shim_d_ops sm0_d_ops = {
        .open       = &sm0_open,
        .lookup     = &sm0_lookup,
        .mode       = &sm0_mode,
        .unlink     = &sm0_unlink,
    };
