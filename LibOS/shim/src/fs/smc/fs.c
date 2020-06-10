/*
 * fs.c
 *
 * The 'smc' filesystem.
 */

#include "shim_flags_conv.h"
#include "shim_internal.h"
#include "shim_thread.h"
#include "shim_handle.h"
#include "shim_vma.h"
#include "shim_fs.h"
#include "shim_utils.h"

#include "pal.h"
#include "pal_debug.h"
#include "pal_error.h"

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

#include "rho_binascii.h"
#include "rho_bitops.h"
#include "rho_buf.h"
#include "rho_endian.h"
#define RHO_LOG_PREFIX "SMC"
#include "rho_log.h"
#include "rho_mem.h"
#include "rho_misc.h"
#include "rho_queue.h"
#include "rho_rand.h"
#include "rho_shim_dentry.h"
#include "rho_shim_handle.h"
#include "rho_sock.h"
#include "rho_ssl.h"
#include "rho_str.h"
#include "rho_ticketlock.h"

#define SMC_OP_NEW_FDTABLE    0
#define SMC_OP_FORK           1
#define SMC_OP_CHILD_ATTACH   2
#define SMC_OP_OPEN           3
#define SMC_OP_CLOSE          4
#define SMC_OP_LOCK           5
#define SMC_OP_UNLOCK         6
#define SMC_OP_MMAP           7

#define SMC_MAX_NAME_SIZE          128
#define SMC_MAX_PATH_SIZE          256
#define SMC_MAX_URI_SIZE           512

/*
 *  bytes
 *   [ 0 -  3]:  ticket_number
 *   [ 4 -  7]:  turn
 *   [ 8 - 11]:  refcnt
 *   [12     ]:  type
 *   [13 - 24]:  iv
 */
#define SMC_LOCKFILE_SIZE          4096
#define SMC_LOCKFILE_REFCNT_OFFSET      8
#define SMC_LOCKFILE_TYPE_OFFSET        12
#define SMC_LOCKFILE_IV_OFFSET          13

#define SMC_REFCNT_SIZE 4
#define SMC_TYPE_SIZE 1
#define SMC_IV_SIZE 12
#define SMC_KEY_SIZE 32

#define SMC_TYPE_PURE_LOCK                 0
#define SMC_TYPE_LOCK_WITH_SEGMENT         1
#define SMC_TYPE_LOCK_WITH_UNINIT_SEGMENT  2

struct smc_memfile {
    char        f_name[SMC_MAX_NAME_SIZE];

    char        f_segment_uri[SMC_MAX_URI_SIZE];
    char        f_lock_uri[SMC_MAX_URI_SIZE];

    int         f_fd_refcnt;

    void        *f_pub_lock;
    uint8_t     f_type;
    uint8_t     f_iv[SMC_IV_SIZE];

    uint8_t     f_key[SMC_KEY_SIZE];

    void        *f_pub_seg;
    void        *f_priv_seg;
    size_t      f_map_size;
};

/*
 * For now, we have a hard limit of 32 memfiles opened.
 * The implementation is simplistic because the struct
 * is (I believe) shallow-copied during migration/fork,
 * and a more robus data structure (with internal pointers)
 * would require additional work to reconstitute during
 * migration/fork.
 *
 * fd_bitmap is a map of the remote descriptors we have open.
 */
struct smc_mdata {
    uint32_t mf_bitmap;
    char mf_memdir_uri[SMC_MAX_URI_SIZE];
    struct smc_memfile mf_tab[32];
};

/******************************************
 * GLOBALS
 ******************************************/

/**********************************************************
 * U32 Bitmap operations
 **********************************************************/
static int
smc_bitmap_u32_ffc(uint32_t bitmap)
{
    int i = 0;
    int val = 0;

    RHO_BITOPS_FOREACH(i, val, (uint8_t *)&bitmap, 32) {
        if (val == 0)
            return (i);
    }

    /* TODO: assert error, because bitmap is full */
    return (-1);
}

/********************************* 
 * AES-CTR
 *********************************/

static void
smc_encrypt(uint8_t *data, size_t data_len, const uint8_t *key,
        const uint8_t *iv)
{
    br_aes_x86ni_ctr_keys ctx;
    uint32_t cc = 0;
    uint32_t cc_out = 0;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, SMC_KEY_SIZE);
    cc_out = br_aes_x86ni_ctr_run(&ctx, iv, cc, data, data_len);
    (void)cc_out;

    RHO_TRACE_EXIT();
}

static void
smc_decrypt(uint8_t *data, size_t data_len, const uint8_t *key, const uint8_t *iv)
{
    br_aes_x86ni_ctr_keys ctx;
    uint32_t cc = 0;
    uint32_t cc_out = 0;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, SMC_KEY_SIZE);
    cc_out = br_aes_x86ni_ctr_run(&ctx, iv, cc, data, data_len);
    (void)cc_out;

    RHO_TRACE_EXIT();
}

/********************************* 
 * UNTRUSTED HOST FILE
 *********************************/

static int
smc_create_fileuri(const char *uri, size_t file_size)
{
    int error = 0;
    PAL_HANDLE pal_hdl;
    uint64_t rv = 0;

    RHO_TRACE_ENTER("uri=\"%s\", file_size=%lu", uri, (unsigned long)file_size);

    pal_hdl = DkStreamOpen(uri, PAL_ACCESS_RDWR, 0660, PAL_CREATE_TRY, 0);
    if (!pal_hdl) {
        rho_warn("DkStreamOpen(\"%s\") failed", uri);
        error = -PAL_ERRNO;
        goto done;
    }

    /* returns 0 on success, a positive errno on failure */
    rv = DkStreamSetLength(pal_hdl, file_size);
    if (rv) {
        rho_warn("DkStreamSetLength(\"%s\", %lu) failed",
                uri, (unsigned long)file_size);
        /* for an error, cast it back down to an int return code */
        error = -((int)rv);
        goto done;
    }

done:
    if (pal_hdl)
        DkObjectClose(pal_hdl);

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smc_delete_fileuri(const char *uri)
{
    int error = 0;
    PAL_HANDLE pal_hdl;

    RHO_TRACE_ENTER("uri=\"%s\"", uri);

    pal_hdl = DkStreamOpen(uri, 0, 0, 0, 0);
    if (!pal_hdl) {
        rho_warn("DkStreamOpen(\"%s\") failed", uri);
        error = -PAL_ERRNO;
        goto done;
    }

    DkStreamDelete(pal_hdl, 0);

done:
    if (pal_hdl)
        DkObjectClose(pal_hdl);

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smc_map_fileuri(const char *uri, size_t size, void **addr)
{
    int error = 0;
    PAL_HANDLE pal_hdl;
    PAL_STREAM_ATTR pal_attr;
    size_t pending_size = 0;
    void *mem = NULL;
    int pal_prot = LINUX_PROT_TO_PAL(PROT_READ|PROT_WRITE, 0);

    RHO_TRACE_ENTER("uri=\"%s\", size=%lu", uri, (unsigned long)size);

    pal_hdl = DkStreamOpen(uri, PAL_ACCESS_RDWR, 0, 0, 0);
    if (!pal_hdl) {
        rho_warn("DkStreamOpen(\"%s\") failed", uri);
        error = -PAL_ERRNO;
        goto done;
    }

    if (DkStreamAttributesQueryByHandle(pal_hdl, &pal_attr) == PAL_FALSE) {
        rho_warn("DkStreamAttributesQueryByHandle(\"%s\") failed", uri);
        error = -PAL_ERRNO;
        goto done;
    }

    pending_size = pal_attr.pending_size;

    if (pending_size != size) {
        rho_warn("pending size (%lu) does not equal expected (%lu) for \"%s\"",
                (unsigned long)pending_size, (unsigned long)size, uri);
        error = -EPROTO;
        goto done;
    }

    /* XXX: do we need to bkeep before this call? */

    mem = DkStreamMap(pal_hdl, NULL, pal_prot, 0, ALLOC_ALIGN_UP(size));
    if (mem == NULL) {
        rho_warn("DkStreamMap(\"%s\") failed", uri);
        error = -EFAULT;
        goto done;
    }

    *addr = mem;

done:
    if (pal_hdl)
        DkObjectClose(pal_hdl);

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

/******************************************
 * MEMFILE
 ******************************************/ 
static void
smc_memfile_init(const char *memdir_uri, struct smc_memfile *mf,
        const char *name)
{
    size_t n = 0;

    RHO_TRACE_ENTER("name=\"%s\"", name);

    rho_memzero(mf, sizeof(*mf));

    /* name relative to mount, (e.g., /foo) */
    n = rho_strlcpy(mf->f_name, name, SMC_MAX_NAME_SIZE);
    RHO_ASSERT(n < SMC_MAX_NAME_SIZE);

    /*
     * FIXME:
     *  We assume memdir_uri does not end in '/' and that
     *  f_name starts with a '/'.
     */

    /* construct lockfile uri (e.g, file:/home/bar/foo) */
    n = rho_strlcpy(mf->f_lock_uri, memdir_uri, SMC_MAX_URI_SIZE);
    RHO_ASSERT(n < SMC_MAX_URI_SIZE);

    n = rho_strlcat(mf->f_lock_uri, mf->f_name, SMC_MAX_URI_SIZE);
    RHO_ASSERT(n < SMC_MAX_URI_SIZE);

    /* construct segment file uri (e.g., file:/home/bar/foo.segment) */
    n = rho_strlcpy(mf->f_segment_uri, memdir_uri, SMC_MAX_URI_SIZE);
    RHO_ASSERT(n < SMC_MAX_URI_SIZE);

    n = rho_strlcat(mf->f_segment_uri, mf->f_name, SMC_MAX_URI_SIZE);
    RHO_ASSERT(n < SMC_MAX_URI_SIZE);

    n = rho_strlcat(mf->f_segment_uri, ".segment", SMC_MAX_URI_SIZE);
    RHO_ASSERT(n < SMC_MAX_URI_SIZE);

    mf->f_fd_refcnt = 1;
    mf->f_type = SMC_TYPE_PURE_LOCK;

    RHO_TRACE_EXIT();
}

static void
smc_memfile_print(const struct smc_memfile *mf)
{
    debug("smc_memfile = {\n");
    debug("  f_name: \"%s\"\n", mf->f_name);
    debug("  f_lock_uri: \"%s\"\n", mf->f_lock_uri);
    debug("  f_segment_uri: \"%s\"\n", mf->f_segment_uri);
    debug("  f_fd_refcnt: %d\n", mf->f_fd_refcnt);
    debug("  f_type: %u\n", (unsigned)mf->f_type);
    debug("  f_pub_lock: %p\n", mf->f_pub_lock);
    debug("  f_pub_seg: %p\n", mf->f_pub_seg);
    debug("  f_priv_seg: %p\n", mf->f_priv_seg);
    debug("  f_map_size: %lu\n", mf->f_map_size);
    debug("}\n");
}

static uint32_t
smc_memfile_incref_lockfile(struct smc_memfile *mf)
{
    struct rho_ticketlock *tl = NULL;
    uint32_t refcnt = 0;

    RHO_TRACE_ENTER();

    tl = (struct rho_ticketlock *)mf->f_pub_lock;
    (void)rho_ticketlock_lock(tl);

    memcpy(&refcnt, mf->f_pub_lock + SMC_LOCKFILE_REFCNT_OFFSET,
            SMC_REFCNT_SIZE);
    refcnt++;
    memcpy(mf->f_pub_lock + SMC_LOCKFILE_REFCNT_OFFSET, &refcnt,
        SMC_REFCNT_SIZE);

     rho_ticketlock_unlock(tl);


    RHO_TRACE_EXIT();
    return (refcnt);
}

static uint32_t
smc_memfile_decref_lockfile(struct smc_memfile *mf)
{
    struct rho_ticketlock *tl = NULL;
    uint32_t refcnt = 0;

    RHO_TRACE_ENTER();

    tl = (struct rho_ticketlock *)mf->f_pub_lock;
    (void)rho_ticketlock_lock(tl);

    memcpy(&refcnt, mf->f_pub_lock + SMC_LOCKFILE_REFCNT_OFFSET,
            SMC_REFCNT_SIZE);
    refcnt--;
    memcpy(mf->f_pub_lock + SMC_LOCKFILE_REFCNT_OFFSET, &refcnt,
        SMC_REFCNT_SIZE);

    rho_ticketlock_unlock(tl);

    RHO_TRACE_EXIT();
    return (refcnt);
}

/* decrypt file into private memory */
static int
smc_memfile_copyin_segment(struct smc_memfile *mf)
{
    int error = 0;

    RHO_TRACE_ENTER();

    memcpy(mf->f_iv, mf->f_pub_lock + SMC_LOCKFILE_IV_OFFSET, SMC_IV_SIZE);
    memcpy(mf->f_priv_seg, mf->f_pub_seg, mf->f_map_size);
    smc_decrypt(mf->f_priv_seg, mf->f_map_size, mf->f_key, mf->f_iv);

    RHO_TRACE_EXIT();
    return (error);
}

/*  encrypt private memory to file */
static void
smc_memfile_copyout_segment(struct smc_memfile *mf)
{
    void *tmp = NULL;

    RHO_TRACE_ENTER();

    tmp = rhoL_zalloc(mf->f_map_size);
    memcpy(tmp, mf->f_priv_seg, mf->f_map_size);

    rho_rand_bytes(mf->f_iv, SMC_IV_SIZE);
    memcpy(mf->f_pub_lock + SMC_LOCKFILE_IV_OFFSET, mf->f_iv, SMC_IV_SIZE);

    smc_encrypt(tmp, mf->f_map_size, mf->f_key, mf->f_iv);
    memcpy(mf->f_pub_seg, tmp, mf->f_map_size);

    rhoL_free(tmp);

    RHO_TRACE_EXIT();
}

static int
smc_memfile_do_open(struct smc_memfile *mf)
{
    int error = 0;

    RHO_TRACE_ENTER();

    error = smc_create_fileuri(mf->f_lock_uri, SMC_LOCKFILE_SIZE);
    error = smc_map_fileuri(mf->f_lock_uri, SMC_LOCKFILE_SIZE,
            &mf->f_pub_lock);

    (void)smc_memfile_incref_lockfile(mf);

    RHO_TRACE_EXIT();
    return (error);
}

static int
smc_memfile_do_close(struct smc_memfile *mf)
{
    int error = 0;
    uint32_t client_refcnt = 0;

    RHO_TRACE_ENTER();

    /* FIXME: check return values */
    client_refcnt = smc_memfile_decref_lockfile(mf);
    if (client_refcnt == 0) {
        (void)smc_delete_fileuri(mf->f_lock_uri);
        if (mf->f_type != SMC_TYPE_PURE_LOCK) {
            (void)smc_delete_fileuri(mf->f_segment_uri);
        }
    }

    /* TODO: unmap lock file */
    if (mf->f_type != SMC_TYPE_PURE_LOCK) {
        /* TODO: unmap segment file -- currently not possible */
        ;
    }

    RHO_TRACE_EXIT();
    return (error);
}

static int
smc_memfile_do_mmap(struct smc_memfile *mf, void **addr, size_t map_size)
{
    int error = 0;
    int pal_prot = LINUX_PROT_TO_PAL(PROT_READ|PROT_WRITE, 0);

    RHO_TRACE_ENTER();

    mf->f_map_size = map_size;
    mf->f_type = SMC_TYPE_LOCK_WITH_UNINIT_SEGMENT;
    rho_rand_bytes(mf->f_key, SMC_KEY_SIZE);

    error = smc_create_fileuri(mf->f_segment_uri, map_size);
    if (error != 0)
        goto done;

    error = smc_map_fileuri(mf->f_segment_uri, mf->f_map_size, &mf->f_pub_seg);
    if (error != 0)
        goto done;

    mf->f_priv_seg = DkVirtualMemoryAlloc(*addr, map_size, 0, pal_prot);
    if (mf->f_priv_seg == NULL) {
        error = -ENOMEM;
        /* TODO: better cleanup on failure */
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smc_memfile_do_lock(struct smc_memfile *mf)
{
    int error = 0;
    struct rho_ticketlock *tl = NULL; 

    RHO_TRACE_ENTER();
    
    tl = (struct rho_ticketlock *)mf->f_pub_lock;
    (void)rho_ticketlock_lock(tl);

    memcpy(&mf->f_type, mf->f_pub_lock + SMC_LOCKFILE_TYPE_OFFSET, SMC_TYPE_SIZE);

    if (mf->f_type == SMC_TYPE_LOCK_WITH_SEGMENT)
        error = smc_memfile_copyin_segment(mf);

    RHO_TRACE_EXIT();
    return (error);
}

static int
smc_memfile_do_unlock(struct smc_memfile *mf)
{
    int error = 0;
    struct rho_ticketlock *tl = NULL; 

    RHO_TRACE_ENTER();

    tl = (struct rho_ticketlock *)mf->f_pub_lock;

    if (mf->f_type == SMC_TYPE_LOCK_WITH_SEGMENT || 
            mf->f_type == SMC_TYPE_LOCK_WITH_UNINIT_SEGMENT) 
        smc_memfile_copyout_segment(mf);

    if (mf->f_type == SMC_TYPE_LOCK_WITH_UNINIT_SEGMENT) {
        mf->f_type = SMC_TYPE_LOCK_WITH_SEGMENT;
        memcpy(mf->f_pub_lock + SMC_LOCKFILE_TYPE_OFFSET, &mf->f_type,
            SMC_TYPE_SIZE);
    }

    rho_ticketlock_unlock(tl);

    RHO_TRACE_EXIT();
    return (error);
}

/**********************************************************
 * MOUNT DATA
 *
 * (acts like a fs-specific file descriptor table
 **********************************************************/
static struct smc_mdata *
smc_get_mdata_from_dentry(const struct shim_dentry *dentry)
{
    struct shim_mount *fs = NULL; 
    struct smc_mdata *mdata = NULL;

    RHO_ASSERT(dentry != NULL);

    fs = dentry->fs;
    RHO_ASSERT(fs != NULL);

    mdata = fs->data;
    RHO_ASSERT(mdata != NULL);

    return (mdata);
}

static struct smc_mdata *
smc_get_mdata_from_handle(const struct shim_handle *hdl)
{
    struct shim_mount *fs = NULL; 
    struct smc_mdata *mdata = NULL;

    fs = hdl->fs;
    if (fs == NULL)
        mdata = smc_get_mdata_from_dentry(hdl->dentry);
    else
        mdata = fs->data;

    RHO_ASSERT(mdata != NULL);
    return (mdata);
}

static struct smc_mdata *
smc_mdata_create(const char *memdir_uri)
{
    struct smc_mdata *mdata = NULL;
    size_t n = 0;
    
    RHO_TRACE_ENTER();

    mdata = rhoL_zalloc(sizeof(struct smc_mdata));
    n = rho_strlcpy(mdata->mf_memdir_uri, memdir_uri, SMC_MAX_URI_SIZE);
    RHO_ASSERT(n < SMC_MAX_URI_SIZE);

    RHO_TRACE_EXIT();
    return (mdata);
}

static struct smc_memfile *
smc_mdata_find_memfile(const struct smc_mdata *mdata, const char *name,
        int *mf_idx)
{
    size_t i = 0;
    int val = 0;
    const struct smc_memfile *mf = NULL;

    RHO_TRACE_ENTER("name=\"%s\"", name);

    RHO_BITOPS_FOREACH(i, val, (uint8_t *)&mdata->mf_bitmap, 32) {
        if (val == 1) {
            mf = &(mdata->mf_tab[i]);
            if (rho_str_equal(mf->f_name, name)) {
                if (mf_idx != NULL)
                    *mf_idx = (int)i;
                goto done;
            }
        }
    }
    mf = NULL;

done:
    RHO_TRACE_EXIT("mf=%p", mf);
    return ((struct smc_memfile *)mf);
}

static struct smc_memfile *
smc_mdata_get_memfile_at_idx(const struct smc_mdata *mdata, int mf_idx)
{
    const struct smc_memfile *mf = NULL;

    RHO_TRACE_ENTER("mf_idx=%d", mf_idx);

    if (!RHO_BITOPS_ISSET((uint8_t *)&mdata->mf_bitmap, mf_idx)) {
        rho_warn("smc memfile bitmap index not set");
        goto done;
    }

    mf = &(mdata->mf_tab[mf_idx]);

done:
    RHO_TRACE_EXIT("mf=%p", mf);
    return ((struct smc_memfile *)mf);
}

/* returns 0 on success; a negative ernro value on failure */
static int
smc_mdata_new_memfile(struct smc_mdata *mdata, const char *name,
        struct smc_memfile **mf, int *mf_idx)
{
    int error = 0;
    int i = 0;
    RHO_TRACE_ENTER();

    i = smc_bitmap_u32_ffc(mdata->mf_bitmap);
    if (i == -1) {
        rho_warn("smc memfile bitmap is full!");
        error = -ENFILE;
        goto done; 
    }

    RHO_BITOPS_SET((uint8_t *)&mdata->mf_bitmap, i);

    *mf = &(mdata->mf_tab[i]);
    smc_memfile_init(mdata->mf_memdir_uri, *mf, name);
    if (mf_idx != NULL)
        *mf_idx = i;

done:
    RHO_TRACE_EXIT("error=%d, i=%d", error, i);
    return (error);
}

static int
smc_mdata_remove_memfile_at_idx(struct smc_mdata *mdata,
        int mf_idx)
{
    int error = 0;

    RHO_TRACE_ENTER("mf_idx=%d", mf_idx);

    if (!RHO_BITOPS_ISSET((uint8_t *)&mdata->mf_bitmap, mf_idx)) {
        rho_warn("smc memfile bitmap index not set");
        error = -EBADF;
        goto done;
    }

    RHO_BITOPS_CLR((uint8_t *)&mdata->mf_bitmap, mf_idx);
    rho_memzero(&(mdata->mf_tab[mf_idx]), sizeof(struct smc_memfile));

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smc_mdata_inc_lockfile_refcnts(struct smc_mdata *mdata)
{
    int error = 0;
    size_t i = 0;
    int val = 0;
    struct smc_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    RHO_BITOPS_FOREACH(i, val, (uint8_t *)&mdata->mf_bitmap, 32) {
        if (val == 1) {
            mf = &(mdata->mf_tab[i]);
            smc_memfile_incref_lockfile(mf);
        }
    }

    RHO_TRACE_EXIT();
    return (error);
}

/********************************* 
 * FILE/FILESYSTEM OPERATIONS
 *********************************/

/*
 * Mount should allocated a struct smc_mountdata and return it
 * in the mount_data out parameter.
 *
 * uri is the host URI for the resource to be "mounted", and
 * root is the guest mountpoint.
 */
static int
smc_mount(const char *uri, void **mount_data)
{
    struct smc_mdata *mdata = NULL;

    RHO_TRACE_ENTER("uri=\"%s\", mount_data=*", uri);

    mdata = smc_mdata_create(uri);
    *mount_data = mdata;

    RHO_TRACE_EXIT("return 0");
    return (0);
}

static int
smc_close(struct shim_handle *hdl)
{
    int error = 0;
    struct smc_mdata *mdata = hdl->fs->data;
    struct shim_smc_handle *smh = &(hdl->info.smc);
    struct smc_memfile *mf = NULL;

    RHO_TRACE_ENTER();
    rho_shim_handle_print(hdl);

    mf = smc_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smc_memfile_print(mf);

    mf->f_fd_refcnt--;
    if (mf->f_fd_refcnt == 0 && mf->f_priv_seg == NULL) {
        error = smc_memfile_do_close(mf);
        smc_mdata_remove_memfile_at_idx(mdata, smh->mf_idx);
    }

done:
    RHO_TRACE_EXIT("return %d", error);
    return (error);
}

static int
smc_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    struct smc_mdata *mdata = hdl->fs->data;
    struct shim_smc_handle *smh = &(hdl->info.smc);
    struct smc_memfile *mf = NULL;
    uint8_t type = 0;

    (void)prot;
    (void)flags;
    (void)offset;

    RHO_TRACE_ENTER("addr=%p, *addr=%p, size=%lu, prot=%08x, flags=%08x, offset=%ld",
            addr, *addr, size, prot, flags, offset);

    rho_shim_handle_print(hdl);
    rho_shim_dentry_print(hdl->dentry);

    mf = smc_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smc_memfile_print(mf);

    error = smc_memfile_do_mmap(mf, addr, size);
    if (!error) {
        type = SMC_TYPE_LOCK_WITH_UNINIT_SEGMENT;
        memcpy(mf->f_pub_lock + SMC_LOCKFILE_TYPE_OFFSET, &type,
                SMC_TYPE_SIZE);
    }

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smc_advlock_lock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smc_mdata *mdata = NULL; 
    struct shim_smc_handle *smh = &(hdl->info.smc);
    struct smc_memfile *mf = NULL;

    (void)flock;

    RHO_TRACE_ENTER();

    rho_shim_handle_print(hdl);
    mdata = smc_get_mdata_from_handle(hdl);
    
    mf = smc_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smc_memfile_print(mf);

    error = smc_memfile_do_lock(mf);

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smc_advlock_unlock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smc_mdata *mdata = hdl->fs->data;
    struct shim_smc_handle *smh = &(hdl->info.smc);
    struct smc_memfile *mf = NULL;

    (void)flock;

    RHO_TRACE_EXIT();
    rho_shim_handle_print(hdl);

    mf = smc_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smc_memfile_print(mf);

    smc_memfile_do_unlock(mf);

done:
    RHO_TRACE_ENTER();
    return (error);
}

static int
smc_advlock(struct shim_handle *hdl, int op, struct flock *flock)
{
    int error = 0;

    (void)op;

    RHO_TRACE_ENTER();

    if (flock->l_type == F_WRLCK)
        error = smc_advlock_lock(hdl, flock);
    else if (flock->l_type == F_UNLCK)
        error = smc_advlock_unlock(hdl, flock);
    else
        error = -EINVAL;

    RHO_TRACE_EXIT();
    return (error);
}

static int
smc_hstat(struct shim_handle *hdl, struct stat *stat)
{
    int error = 0;
    struct smc_mdata *mdata = NULL; 
    struct shim_smc_handle *smh = &(hdl->info.smc);
    struct smc_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    rho_shim_handle_print(hdl);
    mdata = smc_get_mdata_from_handle(hdl);

    mf = smc_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smc_memfile_print(mf);

    stat->st_size = mf->f_map_size;

done:
    RHO_TRACE_EXIT();
    return (error);
}

/* 
 * TODO: what are the semantics of checkout and checkin?
 * I'm pretty sure checkin is called by the parent
 * and checkout by the child, and, vaguely, this has soemthign
 * to do with altering the hdl state, but beyond that, I don't
 * understand.
 */
static int
smc_checkout(struct shim_handle *hdl)
{
    RHO_TRACE_ENTER();

    rho_shim_handle_print(hdl);
    hdl->fs = NULL;

    RHO_TRACE_EXIT();
    return (0);
}

static int
smc_checkin(struct shim_handle *hdl)
{
    int error = 0;
    struct smc_mdata *mdata = NULL; 
    struct shim_smc_handle *smh = &(hdl->info.smc);
    struct smc_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    rho_shim_handle_print(hdl);
    mdata = smc_get_mdata_from_handle(hdl);

    mf = smc_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }

    error = smc_map_fileuri(mf->f_lock_uri, SMC_LOCKFILE_SIZE,
            &mf->f_pub_lock);
        
    if (mf->f_map_size > 0) {
        /* FIXME: check error value */
        (void)smc_map_fileuri(mf->f_segment_uri, mf->f_map_size,
                &mf->f_pub_seg);
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

static ssize_t
smc_checkpoint(void **checkpoint, void *mount_data)
{
    struct smc_mdata *mdata = mount_data;

    RHO_TRACE_ENTER();

    smc_mdata_inc_lockfile_refcnts(mdata);
    *checkpoint = mdata;

    RHO_TRACE_EXIT();
    return (sizeof(*mdata));
}

static int
smc_migrate(void *checkpoint, void **mount_data)
{
    int error = 0;
    struct smc_mdata *mdata = NULL;

    RHO_TRACE_ENTER();

    mdata = rhoL_zalloc(sizeof(struct smc_mdata));
    memcpy(mdata, checkpoint, sizeof(struct smc_mdata));

    *mount_data = mdata;

    RHO_TRACE_EXIT();
    return (error);
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/

static int
smc_open_new(struct smc_mdata *mdata, const char *name, int *mf_idx)
{
    int error = 0;
    struct smc_memfile *mf = NULL;

    RHO_TRACE_ENTER("name=\%s\"", name);

    error = smc_mdata_new_memfile(mdata, name, &mf, mf_idx);
    if (error != 0)
        goto done;

    error = smc_memfile_do_open(mf);
    if (error != 0)
        smc_mdata_remove_memfile_at_idx(mdata, *mf_idx);

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smc_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    struct smc_mdata * mdata = NULL;
    struct shim_smc_handle *smh = &(hdl->info.smc);
    char name[SMC_MAX_NAME_SIZE] = {0};
    struct smc_memfile *mf = NULL;
    int mf_idx = 0;

    RHO_TRACE_ENTER("flags=%d", flags);

    rho_shim_handle_print(hdl);
    mdata = smc_get_mdata_from_dentry(dent);

    rho_shim_dentry_relpath(dent, name, sizeof(name));

    mf = smc_mdata_find_memfile(mdata, name, &mf_idx);
    if (mf != NULL) {
        mf->f_fd_refcnt++;
        goto done;
    }

    error = smc_open_new(mdata, name, &mf_idx);

done:
   if (error == 0) {
        hdl->type = TYPE_SMC;
        hdl->flags = flags;
        hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);

        smh->mf_idx = mf_idx;
    }

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smc_lookup(struct shim_dentry *dent)
{
    RHO_TRACE_ENTER();

    /* XXX: I know fs/shim_namei.c:297 asserts this condition, but why? */
    if (qstrempty(&dent->rel_path)) {
        dent->state |= DENTRY_ISDIRECTORY;
        goto done;
    }

    /* TODO: set ino? */

done:
    RHO_TRACE_EXIT();
    return (0);
}

static int 
smc_mode(struct shim_dentry *dent, mode_t *mode)
{
    (void)mode;

    RHO_TRACE_ENTER();

    rho_shim_dentry_print(dent);
    debug("dent->fs=%p\n", dent->fs);
    debug("dent->fs->data=%p\n", dent->fs->data);
    debug("mode=%p\n", mode);

    *mode = 0777;

    RHO_TRACE_EXIT();
    return (0);
}

static int
smc_unlink(struct shim_dentry *dir, struct shim_dentry *dent)
{
    (void)dir; 
    (void)dent;

    RHO_TRACE_ENTER();
    RHO_TRACE_EXIT();
    return (-ENOSYS);
}

struct shim_fs_ops smc_fs_ops = {
        .mount       = &smc_mount,
        .close       = &smc_close,
        .mmap        = &smc_mmap,
        .advlock     = &smc_advlock,
        .hstat       = &smc_hstat,
        .checkout    = &smc_checkout,
        .checkin     = &smc_checkin,
        .checkpoint  = &smc_checkpoint,
        .migrate     = &smc_migrate,
    };

struct shim_d_ops smc_d_ops = {
        .open       = &smc_open,
        .lookup     = &smc_lookup,
        .mode       = &smc_mode,
        .unlink     = &smc_unlink,
    };
