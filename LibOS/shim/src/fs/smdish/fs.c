/*
 * fs.c
 *
 * The 'smdish' filesystem.
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

#include <rho_binascii.h>
#include <rho_bitops.h>
#include <rho_buf.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_queue.h>
#include <rho_rand.h>
#include <rho_shim_dentry.h>
#include <rho_sock.h>
#include <rho_ssl.h>
#include <rho_str.h>

#include <rpc.h>

#define URI_MAX_SIZE    STR_SIZE

#define TTY_FILE_MODE   0666

#define FILE_BUFMAP_SIZE (PAL_CB(pagesize) * 4)
#define FILE_BUF_SIZE (PAL_CB(pagesize))

/*****/

#define SMDISH_OP_NEW_FDTABLE    0
#define SMDISH_OP_FORK           1
#define SMDISH_OP_CHILD_ATTACH   2
#define SMDISH_OP_OPEN           3
#define SMDISH_OP_CLOSE          4
#define SMDISH_OP_LOCK           5
#define SMDISH_OP_UNLOCK         6
#define SMDISH_OP_MMAP           7
#define SMDISH_OP_MUNMAP         8

#define SMDISH_MAX_NAME_SIZE     256

struct smdish_memfile {
    char name[SMDISH_MAX_NAME_SIZE];
    size_t size;
    void *addr;
};

/*
 * For now, we have a hard limit of 32 memfiles opened.
 * The implementation is simplistic because the struct
 * is (I believe) shallow-copied during migration/fork,
 * and a more robust data structure (with pointers)
 * would require additional work to reconstitute during
 * migration/fork.
 */
struct smdish_mdata {
    char url[512];           /* URL for server */
    uint64_t ident;             /* auth cookie for child */
    unsigned char ca_der[4096];
    size_t  ca_der_len;
    uint32_t fd_bitmap;
    struct smdish_memfile fd_tab[32];
    struct rpc_agent *agent;
};

/********************************* 
 * RPC
 *
 * These functions return 0 on success,
 * or a negative errno on failure.
 *********************************/
static int
smdish_rpc_new_fdtable(struct rpc_agent *agent)
{
    int error = 0;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_NEW_FDTABLE);
    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_rpc_fork(struct rpc_agent *agent, uint64_t *child_ident)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_FORK);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu64be(buf, child_ident);
	if (error != 0)
		error = EPROTO;

done:
    RHO_TRACE_EXIT();
    return (-error);
}

static int
smdish_rpc_child_attach(struct rpc_agent *agent, uint64_t child_ident)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_CHILD_ATTACH);
    rho_buf_writeu64be(buf, child_ident);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT();
    return (-error);
}

static int
smdish_rpc_open(struct rpc_agent *agent, const char *name, uint32_t *fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_OPEN);
    rho_buf_write_u32size_str(buf, name);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu32be(buf, fd);
    if (error != 0)
        error = EPROTO;

done:
    RHO_TRACE_EXIT();
    return (-error);
}

static int
smdish_rpc_close(struct rpc_agent *agent, uint32_t fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_CLOSE);
    rho_buf_writeu32be(buf, fd);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT();
    return (-error);
}

static int
smdish_rpc_lock(struct rpc_agent *agent, uint32_t fd, uint8_t *mem,
        uint32_t memsize)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t size = 0;

    RHO_TRACE_ENTER();
    
    rpc_agent_new_msg(agent, SMDISH_OP_LOCK);
    rho_buf_writeu32be(buf, fd);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    /* file is a pure lock file */
    if (mem == NULL)
        goto done;

    /* file has associated shared memory; copy-in the server's replica */
    error = rho_buf_readu32be(buf, &size);
    if (error == -1) {
        error = EPROTO;
        goto done;
    }

    RHO_ASSERT(size == memsize);

    /* 
     * FIXME: make sure buf has the correct amount of space before copying
     * in
     */
    (void)rho_buf_read(buf, mem, size);
    error = 0;

done:
    RHO_TRACE_EXIT();
    return (-error);
}

static int
smdish_rpc_unlock(struct rpc_agent *agent, uint32_t fd, uint8_t *mem,
        uint32_t memsize)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_UNLOCK);
    rho_buf_writeu32be(buf, fd);

    if (mem != NULL) {
        rho_buf_writeu32be(buf, memsize);
        rho_buf_write(buf, mem, memsize);
    }
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT();
    return (-error);
}

static int
smdish_rpc_mmap(struct rpc_agent *agent, uint32_t fd, uint32_t size)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_MMAP);
    rho_buf_writeu32be(buf, fd);
    rho_buf_writeu32be(buf, size);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT();
    return (-error);
}

#if 0
static int
smdish_rpc_munmap(struct rpc_agent *agent, uint32_t fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_MUNMAP);
    rho_buf_writeu32be(buf, fd);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT();
    return (-error);
}
#endif

/********************************* 
 * MOUNT DATA
 *
 * Mount data contains the rpc agent
 * and serves as a client-side fdtable
 *********************************/

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
smdish_mdata_getfile(struct smdish_mdata *mdata, uint32_t fd)
{
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    if (!RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd))
        goto done;

    mf = &(mdata->fd_tab[fd]);
    RHO_ASSERT(mf != NULL);

done:
    RHO_TRACE_EXIT();
    return (mf);
}

/********************************* 
 * SEGMENT
 *********************************/

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
        debug("smdish client using TLS\n");
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
smdish_mount(const char *uri, const char *root, void **mount_data)
{
    int error = 0;
    char ca_hex[CONFIG_MAX] = { 0 };
    unsigned char *ca_der = NULL;
    ssize_t len = 0;
    struct smdish_mdata *mdata = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER("uri=\"%s\", root=\"%s\"", uri, root);

    len = get_config(root_config, "phoenix.ca_der", ca_hex, sizeof(ca_hex));
    if (len > 0) {
        debug("READ phoenix.ca_der (size=%ld)\n", len);
        ca_der = rhoL_malloc(len / 2);
        rho_binascii_hex2bin(ca_der, ca_hex);
    }

    agent = smdish_agent_open(uri, ca_der, len / 2);
    if (agent != NULL) {
        /* FIXME: better errno; what's in PAL_ERRNO? */
        error = -ENXIO;
        goto fail;
    }

    error = smdish_rpc_new_fdtable(agent);
    if (error != 0)
        goto fail;

    mdata = smdish_mdata_create(uri, ca_der, len / 2);
    mdata->agent = agent;
    *mount_data = mdata;

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
smdish_unmount(void *mount_data)
{
    RHO_TRACE_ENTER();

    (void)mount_data;

    RHO_TRACE_EXIT();
    return (-ENOSYS);
}

static int
smdish_close(struct shim_handle *hdl)
{
    int error = 0;
    struct smdish_mdata *mdata = hdl->fs->data;
    uint32_t fd = hdl->info.smdish.fd;

    RHO_TRACE_ENTER();

    error = smdish_rpc_close(mdata->agent, fd);

    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    struct smdish_mdata *mdata = hdl->fs->data;
    uint32_t fd = hdl->info.smdish.fd;
    struct smdish_memfile *mf = NULL;

    (void)prot;
    (void)flags;
    (void)offset;

    RHO_TRACE_ENTER();

    mf = smdish_mdata_getfile(mdata, fd);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }

    error = smdish_rpc_mmap(mdata->agent, fd, size);
    if (error != 0)
        goto done;

    mf->addr = DkVirtualMemoryAlloc(*addr, size, 0,
            PAL_PROT((PROT_READ|PROT_WRITE), 0));
    if (mf->addr == NULL) {
        error = -ENOMEM;
        goto done;
    }

    mf->size = size;
    *addr = mf->addr;

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_advlock_lock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smdish_mdata *mdata = hdl->fs->data;
    uint32_t fd = hdl->info.smdish.fd;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = smdish_mdata_getfile(mdata, fd);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }

    error = smdish_rpc_lock(mdata->agent, fd, mf->addr, mf->size);
    while (error == (-EAGAIN)) {
        thread_sleep(100000);
        error = smdish_rpc_lock(mdata->agent , fd, mf->addr, mf->size);
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_advlock_unlock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smdish_mdata *mdata = hdl->fs->data;
    uint32_t fd = hdl->info.smdish.fd;
    struct smdish_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    mf = smdish_mdata_getfile(mdata, fd);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }

    error = smdish_rpc_unlock(mdata->agent, fd, mf->addr, mf->size);

done:
    RHO_TRACE_EXIT();
    return (error);
}


static int
smdish_advlock(struct shim_handle *hdl, int op, struct flock *flock)
{
    int error = 0;

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

    debug("checkout hdl = {path:%s}\n", qstrgetstr(&hdl->path));
    hdl->fs = NULL;

    RHO_TRACE_EXIT();
    return (0);
}

static int
smdish_checkin(struct shim_handle *hdl)
{
    RHO_TRACE_ENTER();

    debug("checkin hdl = {path:%s}\n", qstrgetstr(&hdl->path));

    RHO_TRACE_EXIT();
    return (-ENOSYS);
}

static int
smdish_checkpoint(void **checkpoint, void *mount_data)
{
    int error = 0;
    struct smdish_mdata *mdata = mount_data;
    uint64_t child_ident = 0;

    RHO_TRACE_ENTER();
    
    /* make request */
    error = smdish_rpc_fork(mdata->agent, &child_ident);
    if (error != 0)
        goto done;

    debug("smdish child ident = %llu\n", (unsigned long long)child_ident);

    mdata->ident = child_ident;
    *checkpoint = mdata;

done:
    RHO_TRACE_EXIT();
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

    error = smdish_rpc_child_attach(agent, mdata->ident);
    *mount_data = mdata;

    RHO_TRACE_EXIT();
    return (error); /* return 0 on success */
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/
static int
smdish_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    struct smdish_mdata *mdata = dent->fs->data;
    uint32_t fd = 0;
    char name[SMDISH_MAX_NAME_SIZE] = { 0 };

    RHO_TRACE_ENTER();

    rho_shim_dentry_relpath(dent, name, sizeof(name));

    error = smdish_rpc_open(mdata->agent, name, &fd);
    if (error != 0)
        goto done;

    /* update client-side fdtab */

    hdl->type = TYPE_SMDISH;
    hdl->flags = flags;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);
    hdl->info.smdish.fd = fd;

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_lookup(struct shim_dentry *dent, bool force)
{
    debug("> smdish_lookup(dent=*, force=%d)\n", force);
    (void)force;

    debug("dent->fs=%p\n", dent->fs);
    debug("dent->fs->data=%p\n", dent->fs->data);

    /* XXX: I know fs/shim_namei.c:297 asserts this condition, but why? */
    if (qstrempty(&dent->rel_path)) {
        dent->state |= DENTRY_ISDIRECTORY;
        goto done;
    }

    /* TODO: set ino? */

done:
    debug("< smdish_lookup\n");
    return (0);
}

static int 
smdish_mode(struct shim_dentry *dent, mode_t *mode, bool force)
{
    debug("> smdish_mode\n");
    (void)mode;

    debug("dent->fs=%p\n", dent->fs);
    debug("dent->fs->data=%p\n", dent->fs->data);
    debug("mode=%p\n", mode);

    *mode = 0777;

    debug("< smdish_mode\n");
    return (0);
}

static int
smdish_unlink(struct shim_dentry *dir, struct shim_dentry *dent)
{
    debug("> smdish_unlink(dir=*, dent=*)\n");
    (void)dir; (void)dent;
    debug("< smdish_unlink\n");
    return (-ENOSYS);
}

struct shim_fs_ops smdish_fs_ops = {
        .mount       = &smdish_mount,      /**/
        .unmount     = &smdish_unmount,    /**/
        .close       = &smdish_close,      /**/
        .mmap        = &smdish_mmap,       /**/
        .advlock     = &smdish_advlock,
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
