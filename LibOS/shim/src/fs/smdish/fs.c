/*
 * fs.c
 *
 * The 'smdish' filesystem.
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

#include "rho_binascii.h"
#include "rho_bitops.h"
#include "rho_buf.h"
#define RHO_LOG_PREFIX "SMDISH"
#include "rho_log.h"
#include "rho_mem.h"
#include "rho_queue.h"
#include "rho_rand.h"
#include "rho_shim_dentry.h"
#include "rho_shim_handle.h"
#include "rho_sock.h"
#include "rho_ssl.h"
#include "rho_str.h"

#include "rpc.h"

#define SMDISH_OP_NEW_FDTABLE    0
#define SMDISH_OP_FORK           1
#define SMDISH_OP_CHILD_ATTACH   2
#define SMDISH_OP_OPEN           3
#define SMDISH_OP_CLOSE          4
#define SMDISH_OP_LOCK           5
#define SMDISH_OP_UNLOCK         6
#define SMDISH_OP_MMAP           7

#define SMDISH_MAX_NAME_SIZE     256

#define SMDISH_TYPE_PURE_LOCK                 0
#define SMDISH_TYPE_LOCK_WITH_SEGMENT         1
#define SMDISH_TYPE_LOCK_WITH_UNINIT_SEGMENT  2  /* unusued */

/*
 * For now, we have a hard limit of 32 memfiles opened.
 * The implementation is simplistic because the struct
 * is (I believe) shallow-copied during migration/fork,
 * and a more robust data structure (with pointers)
 * would require additional work to reconstitute during
 * migration/fork.
 */


/* 
 * represents an open memfile (the name we give files in this filesystem)
 * Multiple handles may point to the same open memfile, even handles
 * created by distince calls to open.  The abstraction is similar to an
 * inode.
 */
struct smdish_memfile {
    char        f_name[SMDISH_MAX_NAME_SIZE];
    int         f_fd_refcnt;
    uint32_t    f_remote_fd;

    uint8_t     f_type;

    void        *f_addr;
    size_t      f_map_size;
};

struct smdish_mdata {
    char url[512];           /* URL for server */
    uint64_t ident;             /* auth cookie for child */
    unsigned char ca_der[4096];
    size_t  ca_der_len;
    struct rpc_agent *agent;
    uint32_t mf_bitmap;
    struct smdish_memfile mf_tab[32];
};


/******************************************
 * GLOBALS
 ******************************************/

struct smdish_mdata *g_smdish_mdata = NULL;

/**********************************************************
 * U32 Bitmap operations
 **********************************************************/
static int
smdish_bitmap_u32_ffc(uint32_t bitmap)
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


/**********************************************************
 * MEMFILE
 **********************************************************/
static void
smdish_memfile_init(struct smdish_memfile *mf, const char *name)
{
    RHO_TRACE_ENTER("name=\"%s\"", name);

    rho_memzero(mf, sizeof(*mf));
    /* TODO: use strlcpy */
    memcpy(mf->f_name, name, strlen(name));
    mf->f_fd_refcnt = 1;
    mf->f_type = SMDISH_TYPE_PURE_LOCK;

    RHO_TRACE_EXIT();
}

static void
smdish_memfile_print(const struct smdish_memfile *mf)
{
    rho_debug("smdish_memfile: {name=\"%s\", fd_refcnt=%d, remote_fd=%lu, type=%u, addr=%p, size=%lu}",
            mf->f_name, mf->f_fd_refcnt, (unsigned long)mf->f_remote_fd,
            mf->f_type, mf->f_addr, (unsigned long)mf->f_map_size);
}

/**********************************************************
 * MOUNT DATA
 *
 * Mount data contains the rpc agent and a table of open
 * memfiles.
 **********************************************************/ 
static struct smdish_mdata *
smdish_mdata_create(const char *uri, unsigned char *ca_der, size_t ca_der_len)
{
    struct smdish_mdata *mdata = NULL;

    RHO_TRACE_ENTER();

    mdata = rhoL_zalloc(sizeof(*mdata));
    memcpy(mdata->url, uri, strlen(uri));
    if (ca_der != NULL) {
        memcpy(mdata->ca_der, ca_der, ca_der_len);
        mdata->ca_der_len = ca_der_len;
    }

    RHO_TRACE_EXIT();
    return (mdata);
}

static struct smdish_memfile *
smdish_mdata_find_memfile(const struct smdish_mdata *mdata, const char *name,
        int *mf_idx)
{
    size_t i = 0;
    int val = 0;
    const struct smdish_memfile *mf = NULL;

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
    return ((struct smdish_memfile *)mf);
}

static struct smdish_memfile *
smdish_mdata_get_memfile_at_idx(const struct smdish_mdata *mdata, int mf_idx)
{
    const struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER("mf_idx=%d", mf_idx);

    if (!RHO_BITOPS_ISSET((uint8_t *)&mdata->mf_bitmap, mf_idx)) {
        rho_warn("smdish memfile bitmap index not set");
        goto done;
    }

    mf = &(mdata->mf_tab[mf_idx]);

done:
    RHO_TRACE_EXIT("mf=%p", mf);
    return ((struct smdish_memfile *)mf);
}

/* returns 0 on success; a negative errno value on failure */
static int
smdish_mdata_new_memfile(struct smdish_mdata *mdata, const char *name,
        struct smdish_memfile **mf, int *mf_idx)
{
    int error = 0;
    int i = 0;
    RHO_TRACE_ENTER();

    i = smdish_bitmap_u32_ffc(mdata->mf_bitmap);
    if (i == -1) {
        rho_warn("smdish memfile bitmap is full!");
        error = -ENFILE;
        goto done; 
    }

    RHO_BITOPS_SET((uint8_t *)&mdata->mf_bitmap, i);

    *mf = &(mdata->mf_tab[i]);
    smdish_memfile_init(*mf, name);

    if (mf_idx != NULL)
        *mf_idx = i;

done:
    RHO_TRACE_EXIT("error=%d, i=%d", error, i);
    return (error);
}

static int
smdish_mdata_remove_memfile_at_idx(struct smdish_mdata *mdata,
        int mf_idx)
{
    int error = 0;

    RHO_TRACE_ENTER("mf_idx=%d", mf_idx);

    if (!RHO_BITOPS_ISSET((uint8_t *)&mdata->mf_bitmap, mf_idx)) {
        rho_warn("smdish memfile bitmap index not set");
        error = -EBADF;
        goto done;
    }

    RHO_BITOPS_CLR((uint8_t *)&mdata->mf_bitmap, mf_idx);
    rho_memzero(&(mdata->mf_tab[mf_idx]), sizeof(struct smdish_memfile));

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

/**********************************************************
 * RPC AGENT
 *
 * These functions return 0 on success,
 * or a negative errno on failure.
 **********************************************************/

static struct rpc_agent *
smdish_agent_open(const char *url, unsigned char *ca_der, size_t ca_der_len)
{
    struct rpc_agent *agent = NULL;
    struct rho_sock *sock = NULL;
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *ctx = NULL;

    RHO_TRACE_ENTER();

    sock = rho_sock_open_url(url);
    if (sock == NULL) {
        rho_warn("failed to connect to mdish server at \"%s\"", url);
        goto done;
    }

    if (ca_der != NULL) {
        rho_debug("smdish client using TLS");
        params = rho_ssl_params_create();
        rho_ssl_params_set_mode(params, RHO_SSL_MODE_CLIENT);
        rho_ssl_params_set_protocol(params, RHO_SSL_PROTOCOL_TLSv1_2);
        rho_ssl_params_set_ca_der(params, ca_der, ca_der_len);
        ctx = rho_ssl_ctx_create(params);
        rho_ssl_wrap(sock, ctx);
        //rho_ssl_params_destroy(params);
    }

    agent = rpc_agent_create(sock);

done:
    RHO_TRACE_EXIT();
    return (agent);
}

/**********************************************************
 * RPCs
 *
 * These functions return 0 on success; a negative errno
 * on failure.
 **********************************************************/

static int
smdish_new_fdtable_rpc(struct rpc_agent *agent)
{
    int error = 0;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_NEW_FDTABLE);
    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
smdish_fork_rpc(struct rpc_agent *agent, uint64_t *child_ident)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_FORK);
    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu64be(buf, child_ident);
	if (error != 0) {
		error = -EPROTO;
    }

    rho_debug("child_ident=0x%lx", *child_ident);

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
smdish_child_attach_rpc(struct rpc_agent *agent, uint64_t child_ident)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("child_ident=0x%lx", child_ident);

    rpc_agent_new_msg(agent, SMDISH_OP_CHILD_ATTACH);
    rho_buf_writeu64be(buf, child_ident);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

/* returns 0 on success; a negative errno value on failure */
static int
smdish_open_rpc(struct rpc_agent *agent, const char *name, uint32_t *remote_fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("name=\"%s\"", name);

    rpc_agent_new_msg(agent, SMDISH_OP_OPEN);
    rho_buf_write_u32size_str(buf, name);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu32be(buf, remote_fd);
    if (error != 0)
        error = -EPROTO;

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
smdish_close_rpc(struct rpc_agent *agent, uint32_t remote_fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("remote_fd=%u", remote_fd);

    rpc_agent_new_msg(agent, SMDISH_OP_CLOSE);
    rho_buf_writeu32be(buf, remote_fd);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
smdish_lock_rpc(struct rpc_agent *agent, uint32_t remote_fd, uint8_t type,
        uint8_t *mem, uint32_t memsize)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint8_t remote_type = 0;
    uint32_t size = 0;
    size_t n = 0;

    RHO_TRACE_ENTER("remote_fd=%u, mem=%p, memsize=%u\n",
            remote_fd, mem, memsize);
    
    rpc_agent_new_msg(agent, SMDISH_OP_LOCK);
    rho_buf_writeu32be(buf, remote_fd);
    rho_buf_writeu8(buf, type);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu8(buf, &remote_type);
    if (error != 0) {
        error = -EPROTO;
        goto done;
    }

    /* server detects type mismatch, so we don't have to */
    if (remote_type != SMDISH_TYPE_LOCK_WITH_SEGMENT)
        goto done;

    error = rho_buf_readu32be(buf, &size);
    if (error == -1) {
        error = -EPROTO;
        goto done;
    }

    if (size != memsize) {
        rho_warn("size=%lu, but memsize=%lu",
                (unsigned long)size, (unsigned long)memsize);
        RHO_ASSERT(size == memsize);
    }

    n = rho_buf_left(buf);
    if (n != memsize) {
        rho_warn("expect %lu bytes in buf, but only has %lu",
                (unsigned long)memsize, (unsigned long)n);
        RHO_ASSERT(memsize == n);
    }

    (void)rho_buf_read(buf, mem, size);
    error = 0;

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
smdish_unlock_rpc(struct rpc_agent *agent, uint32_t remote_fd, uint8_t type,
        uint8_t *mem, uint32_t memsize)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("remote_fd=%u, mem=%p, memsize=%u",
            remote_fd, mem, memsize);

    rpc_agent_new_msg(agent, SMDISH_OP_UNLOCK);
    rho_buf_writeu32be(buf, remote_fd);
    rho_buf_writeu8(buf, type);

    if (type == SMDISH_TYPE_LOCK_WITH_SEGMENT) {
        RHO_ASSERT(mem != NULL);
        RHO_ASSERT(memsize > 0);
        rho_buf_writeu32be(buf, memsize);
        rho_buf_write(buf, mem, memsize);
    }
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d\n", error);
    return (error);
}

static int
smdish_mmap_rpc(struct rpc_agent *agent, uint32_t remote_fd, uint32_t size)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("remote_fd=%u, size=%u", remote_fd, size);

    rpc_agent_new_msg(agent, SMDISH_OP_MMAP);
    rho_buf_writeu32be(buf, remote_fd);
    rho_buf_writeu32be(buf, size);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d\n", error);
    return (error);
}

/********************************* 
 * FILE/FILESYSTEM OPERATIONS
 *********************************/

/*
 * Mount should allocated a struct smdish_mountdata and return it
 * in the mount_data out parameter.
 *
 * uri is the host URI for the resource to be "mounted", and
 * root is the guest mountpoint.
 */
static int
smdish_mount(const char *uri, void **mount_data)
{
    int error = 0;
    char ca_hex[CONFIG_MAX] = { 0 };
    unsigned char *ca_der = NULL;
    ssize_t len = 0;
    struct smdish_mdata *mdata = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER("uri=\"%s\"", uri);

    len = get_config(root_config, "phoenix.ca_der", ca_hex, sizeof(ca_hex));
    if (len > 0) {
        rho_debug("READ phoenix.ca_der (size=%ld)", len);
        ca_der = rhoL_malloc(len / 2);
        rho_binascii_hex2bin(ca_der, ca_hex);
    }

    agent = smdish_agent_open(uri, ca_der, len / 2);
    if (agent == NULL) {
        /* FIXME: better errno; what's in PAL_ERRNO? */
        error = -ENXIO;
        goto fail;
    }

    error = smdish_new_fdtable_rpc(agent);
    if (error != 0)
        goto fail;

    mdata = smdish_mdata_create(uri, ca_der, len / 2);
    mdata->agent = agent;
    *mount_data = mdata;
    g_smdish_mdata = mdata;

    goto succeed;

fail:
    if (agent != NULL)
        rpc_agent_destroy(agent);

succeed:
    if (ca_der != NULL)
        rhoL_free(ca_der);

    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_close(struct shim_handle *hdl)
{
    int error = 0;
    struct smdish_mdata *mdata = g_smdish_mdata;
    struct shim_smdish_handle *smh = &(hdl->info.smdish);
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();
    rho_shim_handle_print(hdl);

    mf = smdish_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smdish_memfile_print(mf);

    mf->f_fd_refcnt--;
    if (mf->f_fd_refcnt == 0 && mf->f_addr == NULL) {
        error = smdish_close_rpc(mdata->agent, mf->f_remote_fd);
        smdish_mdata_remove_memfile_at_idx(mdata, smh->mf_idx);
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    struct smdish_mdata *mdata = g_smdish_mdata;
    struct shim_smdish_handle *smh = &(hdl->info.smdish);
    struct smdish_memfile *mf = NULL;
    int pal_prot = LINUX_PROT_TO_PAL(PROT_READ|PROT_WRITE, 0);

    (void)prot;
    (void)flags;
    (void)offset;

    RHO_TRACE_ENTER("size=%lu", (unsigned long)size);
    rho_shim_handle_print(hdl);

    mf = smdish_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smdish_memfile_print(mf);

    error = smdish_mmap_rpc(mdata->agent, mf->f_remote_fd, size);
    if (error != 0)
        goto done;

    mf->f_addr = DkVirtualMemoryAlloc(*addr, size, 0, pal_prot);
    if (mf->f_addr == NULL) {
        error = -ENOMEM;
        goto done;
    }

    mf->f_map_size = size;
    mf->f_type = SMDISH_TYPE_LOCK_WITH_SEGMENT;
    *addr = mf->f_addr;

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smdish_advlock_lock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smdish_mdata *mdata = NULL;
    struct shim_smdish_handle *smh = NULL;
    struct smdish_memfile *mf = NULL;

    (void)flock;

    RHO_TRACE_ENTER("hdl=%p", hdl);
    mdata = g_smdish_mdata;
    smh = &(hdl->info.smdish);
    rho_shim_handle_print(hdl);

    mf = smdish_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smdish_memfile_print(mf);

    error = smdish_lock_rpc(mdata->agent, mf->f_remote_fd, mf->f_type,
            mf->f_addr, mf->f_map_size);
    while (error == (-EAGAIN)) {
        rho_debug("********** waiting on lock");
        thread_sleep(100000);
        error = smdish_lock_rpc(mdata->agent, mf->f_remote_fd, mf->f_type,
                mf->f_addr, mf->f_map_size);
    }

done:
    RHO_TRACE_EXIT("error=%d\n", error);
    return (error);
}

static int
smdish_advlock_unlock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smdish_mdata *mdata = g_smdish_mdata;
    struct shim_smdish_handle *smh = &(hdl->info.smdish);
    struct smdish_memfile *mf = NULL;

    (void)flock;

    RHO_TRACE_ENTER();
    rho_shim_handle_print(hdl);

    mf = smdish_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smdish_memfile_print(mf);

    error = smdish_unlock_rpc(mdata->agent, mf->f_remote_fd, mf->f_type,
            mf->f_addr, mf->f_map_size);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_advlock(struct shim_handle *hdl, int op, struct flock *flock)
{
    int error = 0;

    (void)op;

    RHO_TRACE_ENTER();

    if (flock->l_type == F_WRLCK)
        error = smdish_advlock_lock(hdl, flock);
    else if (flock->l_type == F_UNLCK)
        error = smdish_advlock_unlock(hdl, flock);
    else
        error = -EINVAL;

    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_hstat(struct shim_handle *hdl, struct stat *stat)
{
    int error = 0;
    struct smdish_mdata *mdata = g_smdish_mdata;
    struct shim_smdish_handle *smh = &(hdl->info.smdish);
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();
    rho_shim_handle_print(hdl);

    mf = smdish_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smdish_memfile_print(mf);

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
smdish_checkout(struct shim_handle *hdl)
{
    RHO_TRACE_ENTER();

    rho_shim_handle_print(hdl);
    hdl->fs = NULL;

    RHO_TRACE_EXIT();
    return (0);
}

static int
smdish_checkin(struct shim_handle *hdl)
{
    RHO_TRACE_ENTER();

    rho_shim_handle_print(hdl);

    RHO_TRACE_EXIT();
    return (0);
}

static ssize_t
smdish_checkpoint(void **checkpoint, void *mount_data)
{
    int error = 0;
    struct smdish_mdata *mdata = mount_data;
    uint64_t child_ident = 0;

    RHO_TRACE_ENTER();
    
    error = smdish_fork_rpc(mdata->agent, &child_ident);
    if (error != 0)
        goto done;

    rho_debug("smdish child ident = %lu", child_ident);

    mdata->ident = child_ident;
    *checkpoint = mdata;

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (sizeof(struct smdish_mdata));
}

static int
smdish_migrate(void *checkpoint, void **mount_data)
{
    int error = 0;
    struct smdish_mdata *mdata = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER();

    mdata = rhoL_zalloc(sizeof(struct smdish_mdata));
    memcpy(mdata, checkpoint, sizeof(struct smdish_mdata));

    //smdish_client_close(mdata->client); 
    agent = smdish_agent_open(mdata->url, 
            mdata->ca_der[0] == 0x00 ? NULL : mdata->ca_der,
            mdata->ca_der_len);

    mdata->agent = agent;
    //buf = client->buf;

    error = smdish_child_attach_rpc(agent, mdata->ident);
    *mount_data = mdata;
    g_smdish_mdata = mdata;

    RHO_TRACE_EXIT("error=%d", error);
    return (error); /* return 0 on success */
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/ 
static int
smdish_open_new(struct smdish_mdata *mdata, const char *name, int *mf_idx)
{
    int error = 0;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER("name=\%s\"", name);

    error = smdish_mdata_new_memfile(mdata, name, &mf, mf_idx);
    if (error != 0)
        goto done;

    error = smdish_open_rpc(mdata->agent, name, &mf->f_remote_fd);
    if (error != 0)
        smdish_mdata_remove_memfile_at_idx(mdata, *mf_idx);

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smdish_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    struct smdish_mdata *mdata = g_smdish_mdata;
    struct shim_smdish_handle *smh = &(hdl->info.smdish);
    char name[SMDISH_MAX_NAME_SIZE] = {0};
    struct smdish_memfile *mf = NULL;
    int mf_idx = 0;

    RHO_TRACE_ENTER("flags=%d", flags);
    rho_shim_handle_print(hdl);

    rho_shim_dentry_relpath(dent, name, sizeof(name));

    mf = smdish_mdata_find_memfile(mdata, name, &mf_idx);
    if (mf != NULL) {
        mf->f_fd_refcnt++;
        goto done;
    } 

    error = smdish_open_new(mdata, name, &mf_idx);

done:
    if (error == 0) {
        hdl->type = TYPE_SMDISH;
        hdl->flags = flags;
        hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);

        smh->mf_idx = mf_idx;
    }

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smdish_lookup(struct shim_dentry *dent)
{
    int error = 0;

    RHO_TRACE_ENTER();
    rho_shim_dentry_print(dent);

    /* XXX: I know fs/shim_namei.c:297 asserts this condition, but why? */
    if (qstrempty(&dent->rel_path)) {
        dent->state |= DENTRY_ISDIRECTORY;
        goto done;
    }

    /* TODO: set ino? */

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int 
smdish_mode(struct shim_dentry *dent, mode_t *mode)
{
    int error = 0;

    RHO_TRACE_ENTER();
    rho_shim_dentry_print(dent);

    *mode = 0777;

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
smdish_unlink(struct shim_dentry *dir, struct shim_dentry *dent)
{
    int error = -ENOSYS;

    RHO_TRACE_ENTER();
    rho_shim_dentry_print(dir);
    rho_shim_dentry_print(dent);

    __UNUSED(dir);
    __UNUSED(dent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

struct shim_fs_ops smdish_fs_ops = {
        .mount       = &smdish_mount,      /**/
        .close       = &smdish_close,      /**/
        .mmap        = &smdish_mmap,       /**/
        .advlock     = &smdish_advlock,
        .hstat       = &smdish_hstat,      /**/
        .checkout    = &smdish_checkout,   /**/
        .checkin     = &smdish_checkin,
        .checkpoint  = &smdish_checkpoint, /**/
        .migrate     = &smdish_migrate,    /**/
    };

struct shim_d_ops smdish_d_ops = {
        .open       = &smdish_open,        /**/
        .lookup     = &smdish_lookup,      /**/
        .mode       = &smdish_mode,        /**/
        .unlink     = &smdish_unlink,      /**/
    };
