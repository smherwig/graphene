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
#include <rho_buf.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_queue.h>
#include <rho_rand.h>
#include <rho_shim_dentry.h>
#include <rho_sock.h>
#include <rho_ssl.h>
#include <rho_str.h>

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

struct smdish_client {
    struct rpc_agent *agent;
};

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
    struct smdish_client *client;
};

static struct smdish_mdata * smdish_mdata_create(const char *uri,
        unsigned char *ca_der, size_t ca_der_len);
static void smdish_mdata_print(const struct smdish_mdata *mdata);
static struct smdish_memfile * smdish_mdata_new_memfile(
        struct smdish_mdata *mdata, const char *name);
static struct smdish_memfile * smdish_mdata_memfile_by_name(
        struct smdish_mdata *mdata, const char *name);

static struct smdish_memfile * smdish_shim_handle_to_memfile(
        const struct shim_handle *hdl);

static struct smdish_client * smdish_client_open(const char *url,
        unsigned char *ca_der, size_t ca_der_len);

static void smdish_client_close(struct smdish_client *client);
static int smdish_client_request(struct smdish_client *client,
        uint32_t *status, uint32_t *bodylen);

/********************************* 
 * RPC
 *********************************/
static int
smdish_do_rpc(struct rpc_agent *agent)
{
    int error = 0;

    RHO_TRACE_ENTER();

    /* make request */
    error = rpc_agent_request(agent);
    if (error != 0) {
        /* RPC/transport error (EPROTO) */
        rho_warn("RPC error");
        goto done;
    }

    if (hdr->rh_code != 0) {
        /* method error */
        error = hdr->rh_code;
        rho_errno_warn(error, "RPC returned an error");
        goto done;
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_rpc_new_fdtable(struct rpc_agent *agent)
{
    int error = 0;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_NEW_FDTABLE);
    error = smdish_do_rpc(agent);

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

    error = smdish_do_rpc(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu64be(buf, &child_ident);
	if (error != 0)
		error = EPROTO;

done:
    RHO_TRACE_EXIT();
    return (error);
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

    error = smdish_do_rpc(agent);

    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_rpc_open(struct rpc_agent *agent, const char *name, uint32_t *fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    rpc_agent_new_msg(agent, SMDISH_OP_OPEN);
    rho_buf_write_u32size_str(buf, name);
    rpc_agent_autoset_bodylen(agent);

    error = smdish_do_rpc(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu32be(buf, &fd);
    if (error != 0)
        error = EPROTO;

done:
    return (error);
}

static int
smdish_rpc_close(struct rpc_agent *agent, uint32_t fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_CLOSE);
    rho_buf_writeu32(buf, fd);
    rpc_agent_autoset_bodylen(agent);

    error = smdish_do_rpc(agent);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_rpc_lock(struct rpc_agent *agent, uint32_t fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();
    
    rpc_agent_new_msg(agent, SMDISH_OP_LOCK);
    rho_buf_writeu32(buf, fd);
    rpc_agent_autoset_bodylen(agent);

    error = smdish_do_rpc(agent);
    if (error != 0)
        goto done;

	/* TODO: read mem */

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_rpc_unlock(struct rpc_agent *agent, uint32_t fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_UNLOCK);
    rho_buf_writeu32(buf, fd);
	/* TODO: write mem */
    rpc_agent_autoset_bodylen(agent);

    error = smdish_do_rpc(agent);

    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_rpc_mmap(struct rpc_agent *agent, uint32_t fd, uint32_t size)
{
    int error = 0;
    struct rpc_hdr *hdr = &agent->ra_hdr;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_MMAP);
    rho_buf_writeu32be(buf, fd);
    rho_buf_writeu32be(buf, size);
    rpc_agent_autoset_bodylen(agent);

    error = smdish_do_rpc(agent);

    RHO_TRACE_EXIT();
    return (error);
}

static int
smdish_rpc_munmap(struct rpc_agent *agent, uint32_t fd)
{
    int error = 0;
    struct rpc_hdr *hdr = &agent->ra_hdr;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMDISH_OP_MUNMAP);
    rho_buf_writeu32be(buf, fd);
    rpc_agent_autoset_bodylen(agent);

    error = smdish_do_rpc(agent);

    RHO_TRACE_EXIT();
    return (error);
}


/* TODO: smdish_rpc_munmap */

/********************************* 
 * MOUNT DATA
 *********************************/

static int
smdish_fd_bitmap_ffc(uint32_t bitmap)
{
    int i = 0;
    int val = 0;

    SMDISH_SEGMENTS_BITMAP_FOREACH(i, val, bitmap) {
        if (val == 0)
            return (i);
    }

    /* TODO: assert error, because bitmap is full */
    return (-1);
}

static struct smdish_mdata *
smdish_mdata_create(const char *uri, unsigned char *ca_der,
        size_t ca_der_len)
{
    struct smdish_mdata *mdata = NULL;
    
    debug("> smdish_mdata_create\n");

    mdata = rhoL_zalloc(sizeof(struct smdish_mdata));
    memcpy(mdata->url, uri, strlen(uri));
    if (ca_der != NULL) {
        memcpy(mdata->ca_der, ca_der, ca_der_len);
        mdata->ca_der_len = ca_der_len;
    }

    debug("< smdish_mdata_create\n");
    return (mdata);
}

static void
smdish_mdata_print(const struct smdish_mdata *mdata)
{
    debug("smdish_mdata = {url: %s, ident:%llu, ca_der[0]:%02x, ca_der_len:%u}\n",
            mdata->url, (unsigned long long)mdata->ident, mdata->ca_der[0],
            mdata->ca_der_len);
}

static int
smdish_memfile_initialize(struct smdish_memfile *mf, void **addr, size_t size)
{
    int error = 0;

    if (mf->addr != NULL) {
        error = -EEXIST;
        goto done;
    }

    //mf->addr = rhoL_zalloc(size);

done:
    return (error);
}

static struct smdish_memfile *
smdish_mdata_new_memfile(struct smdish_mdata *mdata, const char *name)
{
    int i = 0;
    struct smdish_memfile *mf = NULL;

    i = smtcad_fd_bitmap_ffc(mdata->fd_bitmap);
    if (i == -1)
        goto done;  /* fd table full */

    RHO_BITOPS_SET((uint8_t *)&mdata->fd_bitmap, i);
    mf = &(mdata->memfiles[i]);
    rho_memzero(mf, sizeof(*mf));
    memcpy(mf->name, name, strlen(name));
    
    /*
     * I'm still groking Graphene's memory management (mm), but
     * I think for mmap, Graphene's mm finds an address that should
     * be good, and mmap is responsible for actually allocating at
     * that address.
     */
    mf->addr = DkVirtualMemoryAlloc(*addr, size, 0, 
            PAL_PROT((PROT_READ|PROT_WRITE), 0));
    debug("addr=%p, *addr=%p, mf->addr=%p\n", addr, *addr, mf->addr);
    if (mf->addr == NULL) {
        error = -ENOMEM;
        goto done;
    }

    mf->size = size;
    *addr = mf->addr;


    return (mf);
}

/********************************* 
 * SEGMENT
 *********************************/

static struct smdish_client *
smdish_client_open(const char *url, unsigned char *ca_der, size_t ca_der_len)
{
    struct smdish_client *client = NULL;
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *ctx = NULL;

    debug("> smdish_client_open(url=%s)\n", url);

    client = rhoL_zalloc(sizeof(*client));
    client->buf = rho_buf_create();
    client->url = rhoL_strdup(url);
    client->sock = rho_sock_open_url(url);
    client->debug_cookie = rho_rand_u32();

    if (ca_der != NULL) {
        debug("smdish client using TLS\n");
        params = rho_ssl_params_create();
        rho_ssl_params_set_mode(params, RHO_SSL_MODE_CLIENT);
        rho_ssl_params_set_protocol(params, RHO_SSL_PROTOCOL_TLSv1_2);
        rho_ssl_params_set_ca_der(params, ca_der, ca_der_len);
        ctx = rho_ssl_ctx_create(params);
        rho_ssl_wrap(client->sock, ctx);
        //rho_ssl_params_destroy(params);
    }

    debug("< smdish_client_open\n");
    return (client);
}

static void
smdish_client_close(struct smdish_client *client)
{
    debug("> smdish_client_close(url=\"%s\")\n", client->url);

    rho_sock_destroy(client->sock);
    rhoL_free(client->url);
    rho_buf_destroy(client->buf);
    rhoL_free(client);

    debug("< smdish_client_close\n");
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
    struct smdish_client *client = NULL;

    debug("> smdish_mount(uri=%s, root=%s, mount_data=*)\n", uri, root);

    len = get_config(root_config, "phoenix.ca_der", ca_hex, sizeof(ca_hex));
    if (len > 0) {
        debug("READ phoenix.ca_der (size=%ld)\n", len);
        ca_der = rhoL_malloc(len / 2);
        rho_binascii_hex2bin(ca_der, ca_hex);
    }
    client = smdish_client_open(uri, ca_der, len / 2);

    error = smdish_rpc_new_fdtable(client->agent);

    mdata = smdish_mdata_create(uri, ca_der, len / 2);
    mdata->client = client;
    *mount_data = mdata;
    debug("setting smdish mount data (%p)\n", mdata);

done:
    /* TODO: need to propagate an error if we can't open the client */
    if (ca_der != NULL)
        rhoL_free(ca_der);
    debug("< smdish_mount\n");
    return (error);
}

static int 
smdish_unmount(void *mount_data)
{
    debug("> smdish_unmount\n");
    (void)mount_data;
    debug("< smdish_unmount\n");
    return (-ENOSYS);
}

static int
smdish_close(struct shim_handle *hdl)
{
    int error = 0;
    struct smdish_mdata *mdata = hdl->fs->data;
    struct smdish_client *client = mdata->client;
    uint32_t smdish_fd = 0;

    smdish_fd = hdl->info.smdish.fd;

    debug("> smdish_close(fd=%u)\n", smdish_fd);

    error = smdish_rpc_close(client->agent, fd);

done:
    rho_buf_clear(buf);
    debug("< smdish_close\n");
    return (error);
}

static int
smdish_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    struct smdish_mdata *mdata = hdl->fs->data;
    struct smdish_client *client = mdata->client;
    uint32_t smdish_fd = 0;
    char name[SMDISH_MAX_NAME_LENGTH + 1] = { 0 };
    struct smdish_memfile *mf = NULL;

    (void)prot;
    (void)flags;
    (void)offset;

    smdish_fd = hdl->info.smdish.fd;
    rho_shim_dentry_relpath(hdl->dentry, name, sizeof(name));

    debug("> smdish_mmap(fd=%u (%s), size=%lu)\n",
            smdish_fd, name, (unsigned long) size);

    smdish_rpc_mmap(client->agent);

done:
    debug("< smdish_mmap\n");
    return (error);
}

static int
smdish_advlock(struct shim_handle *hdl, int op, struct flock *flock)
{
    int error = 0;

    debug("> smdish_advlock(op=%d)\n", op);

    if (flock->l_type == F_WRLCK)
        error = smdish_advlock_lock(hdl, flock);
    else if (flock->l_type == F_UNLCK)
        error = smdish_advlock_unlock(hdl, flock);
    else
        error = -EINVAL;

    debug("< smdish_advlock\n");
    return (error);
}

static int
smdish_advlock_lock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct smdish_mdata *mdata = NULL;
    struct smdish_client *client = NULL;
    struct rho_buf *buf = NULL;
    uint32_t smdish_fd = 0;
    struct smdish_memfile *mf = NULL;

    smdish_fd = hdl->info.smdish.fd;
    debug("> smdish_advlock_lock(fd=%u, hdl=%p, hdl->fs=%p, hdl->fs->data=%p)\n",
            smdish_fd, hdl, hdl->fs, hdl->fs->data);
    mf = smdish_shim_handle_to_memfile(hdl);

    mdata = hdl->fs->data;
    client = mdata->client;
    debug("smdish_advlock_lock: client=(%p)\n", client);
    buf = client->buf;

again:
    rho_buf_clear(buf);
    /* build request */
    rho_buf_seek(buf, SMDISH_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, smdish_fd);
    rho_buf_writeu32be(buf, SMDISH_LOCKOP_LOCK);

    bodylen = rho_buf_length(buf) - SMDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    smdish_pmarshal_hdr(buf, SMDISH_OP_FILE_ADVLOCK, bodylen);

    /* make request */
    error = smdish_client_request(client, &status, &bodylen);
    debug("unlock {error=%d, status=%lu, bodylen=%lu}........................\n",
            error, (unsigned long)status, (unsigned long)bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status == EAGAIN) {
        /* 
         * TODO: perhaps sleep here briefly for random amount of time
         * before again trying to acquire the lock.
         */
        thread_sleep(100000);
        debug("again try to unlock ........................\n");
        goto again;
    } else if (status != 0) {
        error = -status;
        goto done;
    }


    /*
     * XXX: This is a little messy.  We have a few cases:
     *
     * case 0 - just a lock file
     *
     *          mf == NULL, bodylen == 0
     *
     * case 1 - lock file with associated memory, but this
     *          is the first time locking, so don't download
     *          the server's view of the memory (which would be
     *          all zeroes)
     *
     *          mf != NULL, bodylen == 0
     *
     * case 2 - lock file with associated memroy, and this
     *          is not the first tiem locking, so download
     *          the server's view of the memory and make that
     *          the client's view.
     *
     *          mf != NULL, bodylen > 0
     */
    if (bodylen == 0)
        goto done;

    if (bodylen != mf->size) {
        debug("bodylen=%lu, mf->size=%lu\n", bodylen, mf->size);
        /* TODO: how should we handle this error? 
         * XXX: this might be the problem.
         */
        error = -ERPC;
        goto done;
    }

    debug("smdish_advlock_lock: memcpy: %p <- %p\n",
            mf->addr, rho_buf_raw(buf, 0, SEEK_SET));
    memcpy(mf->addr, rho_buf_raw(buf, 0, SEEK_SET), bodylen);

done:
    rho_buf_clear(buf);
    debug("< smdish_advlock_lock\n");
    return (error);
}

static int
smdish_advlock_unlock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smdish_mdata *mdata = hdl->fs->data;
    struct smdish_client *client = mdata->client;
    uint32_t smdish_fd = 0;
    struct smdish_memfile *mf = NULL;

    smdish_fd = hdl->info.smdish.fd;
    mf = smdish_shim_handle_to_memfile(hdl);

    debug("> smdish_advlock_unlock(fd=%u), mf->size:%lu\n",
            smdish_fd, (unsigned long)mf->size);

    error = smdish_rpc_unlock(client->agent, fd);

done:
    debug("< smdish_advlock_unlock\n");
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
    debug("> smdish_checkout\n");
    debug("checkout hdl = {path:%s}\n", qstrgetstr(&hdl->path));
    hdl->fs = NULL;
    debug("< smdish_checkout\n");
    return (0);
}

static int
smdish_checkin(struct shim_handle *hdl)
{
    debug("> smdish_checkin\n");
    debug("checkin hdl = {path:%s}\n", qstrgetstr(&hdl->path));
    debug("< smdish_checkin\n");
    return (-ENOSYS);
}

static int
smdish_checkpoint(void **checkpoint, void *mount_data)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct smdish_mdata *mdata = mount_data;
    struct smdish_client *client = mdata->client;
    struct rho_buf *buf = client->buf;
    uint64_t ident = 0;

    debug("> smdish_checkpoint\n");
    
    rho_buf_rewind(buf);
    smdish_pmarshal_hdr(buf, SMDISH_OP_FORK, 0);

    /* make request */
    error = smdish_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    error = rho_buf_readu64be(buf, &ident);
    if (error == -1) {
        error = -ERPC;
        goto done;
    }

    debug("smdish child ident = %llu\n", (unsigned long long)ident);

    mdata->ident = ident;
    *checkpoint = mdata;

done:
    rho_buf_clear(buf);
    debug("< smdish_checkpoint\n");
    return (sizeof(struct smdish_mdata));
}

static int
smdish_migrate(void *checkpoint, void **mount_data)
{
    int error = 0;
    struct smdish_mdata *mdata = NULL;
    struct smdish_client *client = NULL;
    struct rho_buf *buf = NULL;
    uint32_t status = 0;
    uint32_t bodylen = 0;

    debug("> smdish_migrate\n");

    mdata = rhoL_zalloc(sizeof(struct smdish_mdata));
    memcpy(mdata, checkpoint, sizeof(struct smdish_mdata));
    smdish_mdata_print(mdata);

    //smdish_client_close(mdata->client); 
    client = smdish_client_open(mdata->url, 
            mdata->ca_der[0] == 0x00 ? NULL : mdata->ca_der,
            mdata->ca_der_len);

    debug("smdish migrate: client=%p, mdata=%p\n", client, mdata);

    mdata->client = client;
    buf = client->buf;

    rho_buf_seek(buf, SMDISH_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu64be(buf, mdata->ident);
    bodylen = rho_buf_length(buf) - SMDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    smdish_pmarshal_hdr(buf, SMDISH_OP_CHILD_ATTACH, bodylen);
    error = smdish_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    *mount_data = mdata;

done:
    rho_buf_clear(buf);
    debug("< smdish_migrate\n");
    return (0);
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/
static int
smdish_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    struct smdish_mdata *mdata = NULL;
    struct smdish_client *client = NULL; 
    uint32_t fd = 0;
    char name[SMDISH_MAX_NAME_LENGTH + 1] = { 0 };

    debug("> smdish_open(hdl=(%p), dent=(%p), dent->fs=(%p), dent->fs->data=(%p), flags=0x%08x\n", 
            hdl, dent, dent->fs, dent->fs->data, flags);

    rho_shim_dentry_print(dent);

    //debug("hdl->fs->data=%p\n", hdl->fs->data);
    debug("dent->fs->data=%p\n", dent->fs->data);
    mdata = dent->fs->data;
    smdish_mdata_print(mdata);
    client = mdata->client;
    buf = client->buf;

    /* get path */
    rho_shim_dentry_relpath(dent, name, sizeof(name));

    smdish_rpc_open(client->agent, name);

    /* fill in handle */
    hdl->type = TYPE_SMDISH;
    hdl->flags = flags;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);
    hdl->info.smdish.fd = fd;

done:
    rho_buf_clear(buf);
    debug("< smdish_open\n");
    return (error);
}

static int
smdish_lookup(struct shim_dentry *dent, bool force)
{
    debug("> smdish_lookup(dent=*, force=%d)\n", force);
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
    debug("< smdish_lookup\n");
    return (0);
}

static int 
smdish_mode(struct shim_dentry *dent, mode_t *mode, bool force)
{
    debug("> smdish_mode\n");
    (void)mode;

    rho_shim_dentry_print(dent);
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
