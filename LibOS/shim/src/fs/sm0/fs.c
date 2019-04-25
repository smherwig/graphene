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
#include <rho_buf.h>
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

#define URI_MAX_SIZE    STR_SIZE

#define TTY_FILE_MODE   0666

#define FILE_BUFMAP_SIZE (PAL_CB(pagesize) * 4)
#define FILE_BUF_SIZE (PAL_CB(pagesize))

/*****/

/* TODO: move to errno.h */
#define ERPC                            999

#define SM0_LOCKOP_LOCK       1
#define SM0_LOCKOP_UNLOCK     2

#define SM0_IV_SIZE 12
#define SM0_KEY_SIZE 32

/* ticketlock with associated data (the iv) */
struct sm0_lockad {
    struct rho_ticketlock tl; 
    uint8_t iv[SM0_IV_SIZE];
}; 

struct sm0_memfile {
    char name[TCAD_MAX_NAME_SIZE];
    size_t size;
    void *pub_mem;
    void *priv_mem;
    uint8_t key[32];
    struct sm0_lockad *lockad;
    int turn;
};

/*
 * For now, we have a hard limit of 32 memfiles opened.
 * The implementation is simplistic because the struct
 * is (I believe) shallow-copied during migration/fork,
 * and a more robus data structure (with internal pointers)
 * would require additional work to reconstitute during
 * migration/fork.
 */
struct sm0_mdata {
    char url[512];           /* URL for server */
    uint64_t ident;             /* auth cookie for child */
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

    /* this memory will be untrusted: need to make MAP_SHARED */
    lockad =  DkVirtualMemoryAlloc(NULL, 
            sizeof(struct sm0_lockad), 0, PAL_PROT((PROT_READ|PROT_WRITE), 0));

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
    int my_turn;
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
    br_aes_x86ni_ctr_keys ctx;
    uint32_t cc = 0;
    uint32_t cc_out = 0;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, SM0_KEY_SIZE);
    cc_out = br_aes_x86ni_ctr_run(&ctx, iv, cc, data, data_len);
    (void)cc_out;

    RHO_TRACE_EXIT();
}

static void
sm0_decrypt(uint8_t *data, size_t data_len, const uint8_t *key,
        const uint8_t *iv)
{
    br_aes_x86ni_ctr_keys ctx;
    uint32_t cc = 0;
    uint32_t cc_out = 0;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, SM0_KEY_SIZE);
    cc_out = br_aes_x86ni_ctr_run(&ctx, iv, cc, data, data_len);
    (void)cc_out;

    RHO_TRACE_EXIT();
}

/******************************************
 * MEMFILE
 *
 * A MEMFILE is either a file that acts as
 * a lock, or a file that acts as a lock
 * with some associated memory.
 ******************************************/ 
static int
sm0_memfile_make_map(struct sm0_memfile *mf, size_t size)
{
    int error = 0;

    RHO_TRACE_ENTER();

    mf->size = size;

    /* TODO: need to make SHAREABLE, outside of enclave */
    mf->pub_mem =  DkVirtualMemoryAlloc(NULL, size, 0,
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
 * (acts like a fs-specific file descriptor table
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

    mdata = rhoL_zalloc(sizeof(struct sm0_mdata));

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

/*
 * Mount should allocated a struct sm0_mountdata and return it
 * in the mount_data out parameter.
 *
 * uri is the host URI for the resource to be "mounted", and
 * root is the guest mountpoint.
 */
static int
sm0_mount(const char *uri, const char *root, void **mount_data)
{
    int error = 0;
    struct sm0_mdata *mdata = NULL;

    debug("> sm0_mount(uri=%s, root=%s, mount_data=*)\n", uri, root);

    mdata = sm0_mdata_create();
    *mount_data = mdata;
    debug("setting sm0 mount data (%p)\n", mdata);

    debug("< sm0_mount\n");
    return (error);
}

static int
sm0_close(struct shim_handle *hdl)
{
    int error = 0;
    struct sm0_mdata *mdata = hdl->fs->data;
    struct sm0_memfile *mf = NULL;
    uint32_t fd = 0;

    fd = hdl->info.sm0.fd;
    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    debug("> sm0_close(fd=%u)\n", fd);

    mf = &(mdata->fd_tab[fd]);
    sm0_memfile_clear(mf);
    RHO_BITOPS_CLR((uint8_t *)&mdata->fd_tab, fd);

    debug("< sm0_close (ret=%d)\n", error);
    return (error);
}

static int
sm0_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    struct sm0_mdata *mdata = hdl->fs->data;
    char name[TCAD_MAX_NAME_SIZE] = { 0 };
    struct sm0_memfile *mf = NULL;
    uint32_t fd = 0;

    (void)prot;
    (void)flags;
    (void)offset;

    fd = hdl->info.sm0.fd;
    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    rho_shim_dentry_relpath(hdl->dentry, name, sizeof(name));
    debug("> sm0_mmap(fd=%u (%s), size=%lu)\n",
            fd, name, (unsigned long) size);

    mf = &(mdata->fd_tab[fd]);
    error = sm0_memfile_make_map(mf, size);
    if (error == -1)
        error = -PAL_ERRNO;

    debug("< sm0_mmap (ret=%d)\n", error);
    return (error);
}

static int
sm0_advlock_lock(struct shim_handle *hdl, struct flock *flock)
{
    struct sm0_mdata *mdata = NULL;
    uint32_t fd = 0;
    struct sm0_memfile *mf = NULL;

    fd = hdl->info.sm0.fd;
    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    debug("> sm0_advlock_lock(fd=%u, hdl=%p, hdl->fs=%p, hdl->fs->data=%p)\n",
            fd, hdl, hdl->fs, hdl->fs->data);

    mf = &(mdata->fd_tab[fd]);
    mdata = hdl->fs->data;

    mf->turn = sm0_lockad_lock(mf->lockad);
    sm0_memfile_map_in(mf);

    debug("< sm0_advlock_lock\n");
    return (0);
}

static int
sm0_advlock_unlock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct sm0_mdata *mdata = hdl->fs->data;
    uint32_t fd = 0;
    struct sm0_memfile *mf = NULL;

    fd = hdl->info.sm0.fd;
    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    mf = &(mdata->fd_tab[fd]);

    debug("> sm0_advlock_unlock(fd=%u), mf->size:%lu\n",
            fd, (unsigned long)mf->size);

    sm0_memfile_map_out(mf);
    sm0_lockad_unlock(mf->lockad);

    debug("< sm0_advlock_unlock (ret=%d)\n", error);
    return (error);
}

static int
sm0_advlock(struct shim_handle *hdl, int op, struct flock *flock)
{
    int error = 0;

    debug("> sm0_advlock(op=%d)\n", op);

    if (flock->l_type == F_WRLCK)
        error = sm0_advlock_lock(hdl, flock);
    else if (flock->l_type == F_UNLCK)
        error = sm0_advlock_unlock(hdl, flock);
    else
        error = -EINVAL;

    debug("< sm0_advlock\n");
    return (error);
}

static int
sm0_checkpoint(void **checkpoint, void *mount_data)
{
    struct sm0_mdata *mdata = mount_data;
    uint64_t ident = 0;

    debug("> sm0_checkpoint\n");

    debug("sm0 child ident = %llu\n", (unsigned long long)ident);

    mdata->ident = ident;
    *checkpoint = mdata;

    debug("< sm0_checkpoint\n");
    return (sizeof(struct sm0_mdata));
}

static int
sm0_migrate(void *checkpoint, void **mount_data)
{
    struct sm0_mdata *mdata = NULL;

    debug("> sm0_migrate\n");

    mdata = rhoL_zalloc(sizeof(struct sm0_mdata));
    memcpy(mdata, checkpoint, sizeof(struct sm0_mdata));
    *mount_data = mdata;

    debug("< sm0_migrate\n");
    return (0);
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/
static int
sm0_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    struct sm0_mdata *mdata = NULL;
    uint32_t fd = 0;
    struct sm0_memfile *mf = NULL;
    char name[TCAD_MAX_NAME_SIZE] = { 0 };

    debug("> sm0_open(hdl=(%p), dent=(%p), dent->fs=(%p), dent->fs->data=(%p), flags=0x%08x\n", 
            hdl, dent, dent->fs, dent->fs->data, flags);
    rho_shim_dentry_print(dent);
    //debug("hdl->fs->data=%p\n", hdl->fs->data);
    debug("dent->fs->data=%p\n", dent->fs->data);

    mdata = dent->fs->data;

    /* get path */
    rho_shim_dentry_relpath(dent, name, sizeof(name));

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
    debug("< sm0_open (ret=%d)\n", error);
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
        .mount       = &sm0_mount,      /**/
        .close       = &sm0_close,      /**/
        .mmap        = &sm0_mmap,       /**/
        .advlock     = &sm0_advlock,
        .checkpoint  = &sm0_checkpoint, /**/
        .migrate     = &sm0_migrate,    /**/
    };

struct shim_d_ops sm0_d_ops = {
        .open       = &sm0_open,        /**/
        .lookup     = &sm0_lookup,      /**/
        .mode       = &sm0_mode,        /**/
        .unlink     = &sm0_unlink,      /**/
    };