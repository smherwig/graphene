/*
 * fs.c
 *
 * The 'mdish' filesystem.
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

#include <rho_buf.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_queue.h>
#include <rho_shim_dentry.h>
#include <rho_sock.h>
#include <rho_ssl.h>
#include <rho_str.h>

#define URI_MAX_SIZE    STR_SIZE

#define TTY_FILE_MODE   0666

#define FILE_BUFMAP_SIZE (PAL_CB(pagesize) * 4)
#define FILE_BUF_SIZE (PAL_CB(pagesize))

/*****/

#define MDISH_HEADER_LENGTH            8
#define MDISH_MAX_NAME_LENGTH   255

/* TODO: move to errno.h */
#define ERPC                            999

#define MDISH_OP_FILE_OPEN      0
#define MDISH_OP_FILE_CLOSE     1
#define MDISH_OP_FILE_ADVLOCK   2
#define MDISH_OP_MMAP           3
#define MDISH_OP_MUNMAP         4

#define MDISH_OP_FORK           5
#define MDISH_OP_CHILD_ATTACH   6
#define MDISH_OP_NEW_FDTABLE    7

#define MDISH_LOCKOP_LOCK       1
#define MDISH_LOCKOP_UNLOCK     2

struct mdish_segment {
    char name[MDISH_MAX_NAME_LENGTH + 1];
    void *addr;
    size_t size;
};

/*
 * For now, we have a hard limit of 32 segments opened.
 * The implementation is simplistic because the struct
 * is (I believe) shallow-copied during migration/fork,
 * and a more robus data structure (with internal pointers)
 * would require additional work to reconstitute during
 * migration/fork.
 */
struct mdish_mount_data {
    char    url[512];           /* URL for server */
    uint64_t ident;             /* auth cookie for child */
    uint32_t segments_bitmap;
    struct mdish_segment segments[32];
};

struct mdish_client {
    struct rho_sock *sock;
    struct rho_buf *buf;
    char *url;      /* URL for server */
};

static struct mdish_mount_data * mdish_mount_data_create(const char *uri);
static void mdish_mount_data_print(const struct mdish_mount_data *mdata);
static struct mdish_segment * mdish_mount_data_new_segment(
        struct mdish_mount_data *mdata, const char *name);
static struct mdish_segment * mdish_mount_data_segment_by_name(
        struct mdish_mount_data *mdata, const char *name);

static int mdish_segment_initialize(struct mdish_segment *seg, void **addr,
        size_t size);
static struct mdish_segment * mdish_shim_handle_to_segment(
        const struct shim_handle *hdl);

static void mdish_marshal_str(struct rho_buf *buf, const char *s);
static void mdish_pmarshal_hdr(struct rho_buf *buf, uint32_t op,
        uint32_t bodylen);
static void mdish_demarshal_hdr(struct rho_buf *buf, uint32_t *status,
        uint32_t *bodylen);

static struct mdish_client * mdish_client_open(const char *url);
static void mdish_client_close(struct mdish_client *client);
static int mdish_client_request(struct mdish_client *client,
        uint32_t *status, uint32_t *bodylen);

static int mdish_mount(const char *uri, const char *root, void **mount_data);
static int mdish_unmount(void *mount_data);
static int mdish_close(struct shim_handle *hdl);
static int mdish_write(struct shim_handle *hdl, const void *data,
        size_t count);
static int mdish_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset);
static int mdish_flush(struct shim_handle *hdl);
static int mdish_seek(struct shim_handle *hdl, off_t offset, int whence);
static int mdish_move(const char *trim_old_name, const char *trim_new_name);
static int mdish_copy(const char *trim_old_name, const char *trim_new_name);
static int mdish_truncate(struct shim_handle *hdl, uint64_t len);
static int mdish_hstat(struct shim_handle *hdl, struct stat *stat);
static int mdish_setflags(struct shim_handle *hdl, int flags);
static void mdish_hput(struct shim_handle *hdl);
static int mdish_advlock(struct shim_handle *hdl, int op, struct flock *flock);
static int mdish_advlock_lock(struct shim_handle *hdl, struct flock *flock);
static int mdish_advlock_unlock(struct shim_handle *hdl, struct flock *flock);
static int mdish_lock(const char *trim_name);
static int mdish_unlock(const char *trim_name);
static int mdish_lockfs(void);
static int mdish_unlockfs(void);
static int mdish_checkout(struct shim_handle *hdl);
static int mdish_checkin(struct shim_handle *hdl);
static int mdish_poll(struct shim_handle *hdl, int poll_type);
static int mdish_checkpoint(void **checkpoint, void *mount_data);
static int mdish_migrate(void *checkpoint, void **mount_data);

static int mdish_open(struct shim_handle *hdl, struct shim_dentry *dent,
        int flags);
static int mdish_lookup(struct shim_dentry *dent, bool force);
static int mdish_mode(struct shim_dentry *dent, mode_t *mode, bool force);
static int mdish_dput(struct shim_dentry *dent);
static int mdish_creat(struct shim_handle *hdl, struct shim_dentry *dir,
        struct shim_dentry *dent, int flags, mode_t mode);
static int mdish_unlink(struct shim_dentry *dir, struct shim_dentry *dent);
static int mdish_mkdir(struct shim_dentry *dir, struct shim_dentry *dent,
        mode_t mode);
static int mdish_stat(struct shim_dentry *dent, struct stat *stat);
static int mdish_follow_link(struct shim_dentry *dent, struct shim_qstr *link);
static int mdish_set_link(struct shim_dentry *dent, const char *link);
static int mdish_chmod(struct shim_dentry *dent, mode_t mode);
static int mdish_chown(struct shim_dentry *dent, int uid, int gid);
static int mdish_rename(struct shim_dentry *old, struct shim_dentry *new);
static int mdish_readdir(struct shim_dentry *dent,
        struct shim_dirent **dirent);

static struct mdish_client *g_client = NULL;
static struct mdish_mount_data *g_mount_data = NULL;

/********************************* 
 * SEGMENTS BITMAP
 *********************************/
#define MDISH_SEGMENTS_BITMAP_SET(bitmap, i) \
    (bitmap) |= (1 << (i))

#define MDISH_SEGMENTS_BITMAP_CLEAR(bitmap, i) \
    (bitmap) &= (~(1 << (i)))

#define MDISH_SEGMENTS_BITMAP_FOREACH(i, val, bitmap) \
    for ( \
            (i) = 0, (val) = (((bitmap) & (1 << (i))) ? 1 : 0); \
            (i) < 32; \
            (i)++,   (val) = (((bitmap) & (1 << (i))) ? 1 : 0) \
        )

static int
mdish_segments_bitmap_ffc(uint32_t bitmap)
{
    int i = 0;
    int val = 0;

    MDISH_SEGMENTS_BITMAP_FOREACH(i, val, bitmap) {
        if (val == 0)
            return (i);
    }

    /* TODO: assert error, because bitmap is full */
    return (-1);
}

/********************************* 
 * MOUNT DATA
 *********************************/
static struct mdish_mount_data *
mdish_mount_data_create(const char *uri)
{
    struct mdish_mount_data *mdata = NULL;
    
    debug("> mdish_mount_data_create\n");

    mdata = rhoL_zalloc(sizeof(struct mdish_mount_data));
    memcpy(mdata->url, uri, strlen(uri));

    debug("< mdish_mount_data_create\n");
    return (mdata);
}

static void
mdish_mount_data_print(const struct mdish_mount_data *mdata)
{
    debug("mdish_mount_data = {url: %s, ident:%llu}\n",
            mdata->url, (unsigned long long)mdata->ident);
}

/* TODO: for munmap, need mdish_mount_dat_segment_by_addr() */

static struct mdish_segment *
mdish_mount_data_new_segment(struct mdish_mount_data *mdata,
        const char *name)
{
    int i = 0;
    struct mdish_segment *seg = NULL;

    i = mdish_segments_bitmap_ffc(mdata->segments_bitmap);
    seg = &(mdata->segments[i]);
    memcpy(seg->name, name, strlen(name));
    MDISH_SEGMENTS_BITMAP_SET(mdata->segments_bitmap, i);

    return (seg);
}

static struct mdish_segment *
mdish_mount_data_segment_by_name(struct mdish_mount_data *mdata,
        const char *name)
{
    int i = 0;
    int bitval = 0;
    struct mdish_segment *seg = NULL;

    MDISH_SEGMENTS_BITMAP_FOREACH(i, bitval, mdata->segments_bitmap) {
        if (bitval == 0)
            continue;
        seg = &(mdata->segments[i]);
        if (rho_str_equal(seg->name, name))
            goto done;
    }
    seg = NULL;

done:
    return (seg);
}

/********************************* 
 * SEGMENT
 *********************************/
static int
mdish_segment_initialize(struct mdish_segment *seg, void **addr, size_t size)
{
    int error = 0;

    if (seg->addr != NULL) {
        error = -EEXIST;
        goto done;
    }

    //seg->addr = rhoL_zalloc(size);
    
    /*
     * I'm still groking Graphene's memory management (mm), but
     * I think for mmap, Graphene's mm finds an address that should
     * be good, and mmap is responsible for actually allocating at
     * that address.
     */
    seg->addr = DkVirtualMemoryAlloc(*addr, size, 0, 
            PAL_PROT((PROT_READ|PROT_WRITE), 0));
    debug("addr=%p, *addr=%p, seg->addr=%p\n", addr, *addr, seg->addr);
    if (seg->addr == NULL) {
        error = -ENOMEM;
        goto done;
    }

    seg->size = size;
    *addr = seg->addr;

done:
    return (error);
}

static struct mdish_segment *
mdish_shim_handle_to_segment(const struct shim_handle *hdl)
{
    struct mdish_segment *seg = NULL;
    char name[MDISH_MAX_NAME_LENGTH + 1] = { 0 };


    rho_shim_dentry_relpath(hdl->dentry, name, sizeof(name));
    seg = mdish_mount_data_segment_by_name(g_mount_data, name);
    debug("> mdish_shim_handle_to_segment(path=%s) -> %p\n", name, seg);
    if (seg != NULL) {
        debug("< mdish_shim_handle_to_segment: (name=\"%s\", addr=%p, size=%lu)\n",
                seg->name, seg->addr, (unsigned long)seg->size);
    }

    /* TODO: assert that seg is not NULL */
    return (seg);
}

/********************************* 
 * RPC HELPERS
 *********************************/

static void
mdish_marshal_str(struct rho_buf *buf, const char *s)
{
    size_t len = strlen(s);
    rho_buf_writeu32be(buf, len);
    rho_buf_puts(buf, s);
}

static void
mdish_pmarshal_hdr(struct rho_buf *buf, uint32_t op, uint32_t bodylen)
{
    rho_buf_pwriteu32be_at(buf, op, 0);
    rho_buf_pwriteu32be_at(buf, bodylen, 4);
}

static void
mdish_demarshal_hdr(struct rho_buf *buf, uint32_t *status, uint32_t *bodylen)
{
    *status = 0;
    *bodylen = 0;

    rho_buf_readu32be(buf, status);
    rho_buf_readu32be(buf, bodylen);
}

static struct mdish_client *
mdish_client_open(const char *url)
{
    struct mdish_client *client = NULL;
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *ctx = NULL;
    char cafile[CONFIG_MAX] = { 0 };
    ssize_t len = 0;

    debug("> mdish_client_open(url=%s)\n", url);

    client = rhoL_zalloc(sizeof(*client));
    client->buf = rho_buf_create();
    client->url = rhoL_strdup(url);
    client->sock = rho_sock_open_url(url);

    len = get_config(root_config, "phoenix.cafile", cafile, sizeof(cafile));
    if (len > 0) {
        debug("mdish client using TLS; cafile=\"%s\"\n", cafile);
        params = rho_ssl_params_create();
        rho_ssl_params_set_mode(params, RHO_SSL_MODE_CLIENT);
        rho_ssl_params_set_protocol(params, RHO_SSL_PROTOCOL_TLSv1_2);
        //rho_ssl_params_set_ca_file(params, "/etc/root.crt");
        rho_ssl_params_set_ca_file(params, cafile);
        ctx = rho_ssl_ctx_create(params);
        rho_ssl_wrap(client->sock, ctx);
        //rho_ssl_params_destroy(params);
    }

    debug("< mdish_client_open\n");
    return (client);
}

static void
mdish_client_close(struct mdish_client *client)
{
    debug("> mdish_client_close\n");

    rho_sock_destroy(client->sock);
    rhoL_free(client->url);
    rho_buf_destroy(client->buf);
    rhoL_free(client);

    debug("< mdish_client_close\n");
}

/*
 * return 0 on success, or -errno on failure?
 *
 * On success, status and bodylen point to the responses'
 * status and bodylen, and client->buf holds the reponse
 * (starting at offset=0, with buf cursor at 0).
 */
static int
mdish_client_request(struct mdish_client *client,
        uint32_t *status, uint32_t *bodylen)
{
    int error = 0;
    ssize_t n = 0;
    struct rho_sock *sock = client->sock;
    struct rho_buf *buf = client->buf;

    debug("> mdish_client_request (buf_length(buf)=%lu, buf_tell=%ld, raw=%p\n",
            (unsigned long)rho_buf_length(buf), 
            (long)rho_buf_tell(buf),
            rho_buf_raw(buf, 0, SEEK_SET));

    n = rho_sock_sendn_buf(sock, buf, rho_buf_length(buf));
    debug("request: wanted to send %lu; sent %ld\n",
            (unsigned long)rho_buf_length(buf), (long)n);
    if (n == -1) {
        error = -1;
        goto done;
    }

    debug("receiving mdish header\n");
    rho_buf_clear(buf);
    n = rho_sock_precvn_buf(sock, buf, 8);
    debug("response: wanted to recv 8; got %ld\n", (long)n);
    if (n == -1) {
        error = -1;
        goto done;
    }

    debug("demarshaling mdish header (n=%ld)\n", n);

    mdish_demarshal_hdr(buf, status, bodylen);
    if (*bodylen > 0) {
        rho_buf_clear(buf);
        debug("response status=%u, len=%u\n", *status, *bodylen);
        debug("receiving mdish body\n");
        n = rho_sock_precvn_buf(sock, buf, *bodylen);
        debug("received %ld bytes of mdish body\n", (long)n);
        if (n == -1) {
            error = -1;
            goto done;
        }
    }

done:
    debug("< mdish_client_request\n");
    return (error);
}

/********************************* 
 * FILE/FILESYSTEM OPERATIONS
 *********************************/

/*
 * XXX: For now, we assume that only one mdish is mounted, and that
 * it is a unix domain socket.
 */

/*
 * Mount should allocated a struct mdish_mountdata and return it
 * in the mount_data out parameter.
 *
 * uri is the host URI for the resource to be "mounted", and
 * root is the guest mountpoint.
 *
 * Note that you're g_client is more or less acting as the mount_data.
 */
static int
mdish_mount(const char *uri, const char *root, void **mount_data)
{
    int error = 0;
    uint32_t status = 0;
    uint32_t bodylen = 0;

    debug("> mdish_mount(uri=%s, root=%s, mount_data=*)\n", uri, root);

    g_client = mdish_client_open(uri);

    rho_buf_rewind(g_client->buf);
    mdish_pmarshal_hdr(g_client->buf, MDISH_OP_NEW_FDTABLE, 0);
    error = mdish_client_request(g_client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    g_mount_data = mdish_mount_data_create(uri);
    *mount_data = g_mount_data;

done:
    /* TODO: need to propagate an error if we can't open the client */
    rho_buf_clear(g_client->buf);
    debug("< mdish_mount\n");
    return (error);
}

static int 
mdish_unmount(void *mount_data)
{
    debug("> mdish_unmount\n");
    (void)mount_data;
    debug("< mdish_unmount\n");
    return (-ENOSYS);
}

static int
mdish_close(struct shim_handle *hdl)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct rho_buf *buf = g_client->buf;
    uint32_t mdish_fd = 0;

    mdish_fd = hdl->info.mdish.fd;

    debug("> mdish_close(fd=%u)\n", mdish_fd);

    /* build request */
    rho_buf_seek(buf, MDISH_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, mdish_fd);
    bodylen = rho_buf_length(buf) - MDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    mdish_pmarshal_hdr(buf, MDISH_OP_FILE_CLOSE, bodylen);

    /* make request */
    error = mdish_client_request(g_client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

done:
    rho_buf_clear(buf);
    debug("< mdish_close\n");
    return (error);
}

static int
mdish_read(struct shim_handle *hdl, void *data, size_t count)
{
    debug("> mdish_read\n");
    (void)hdl; (void)data; (void)count;
    debug("< mdish_read\n");
    return (-ENOSYS);
}

static int
mdish_write(struct shim_handle *hdl, const void *data, size_t count)
{
    debug("> mdish_write\n");
    (void)hdl; (void)data; (void)count;
    debug("< mdish_write\n");
    return (-ENOSYS);
}

static int
mdish_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct rho_buf *buf = g_client->buf;
    uint32_t mdish_fd = 0;
    char name[MDISH_MAX_NAME_LENGTH + 1] = { 0 };
    struct mdish_segment *seg = NULL;
    uint32_t mdish_sd = 0;

    (void)prot;
    (void)flags;
    (void)offset;

    mdish_fd = hdl->info.mdish.fd;
    rho_shim_dentry_relpath(hdl->dentry, name, sizeof(name));

    debug("> mdish_mmap(fd=%u (%s), size=%lu)\n",
            mdish_fd, name, (unsigned long) size);

    /* build request */
    rho_buf_seek(buf, MDISH_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, mdish_fd);
    rho_buf_writeu32be(buf, size);
    bodylen = rho_buf_length(buf) - MDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    mdish_pmarshal_hdr(buf, MDISH_OP_MMAP, bodylen);

    /* make request */
    error = mdish_client_request(g_client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    if (bodylen != 4) {
        error = -ERPC;
        goto done;
    }

    rho_buf_readu32be(buf, &mdish_sd);
    seg = mdish_mount_data_new_segment(g_mount_data, name);
    error = mdish_segment_initialize(seg, addr, size);

done:
    rho_buf_clear(buf);
    debug("< mdish_mmap\n");
    return (error);
}

static int
mdish_flush(struct shim_handle *hdl)
{
    debug("> mdish_flush\n");
    (void)hdl;
    debug("< mdish_flush\n");
    return (-ENOSYS);
}

static int
mdish_seek(struct shim_handle *hdl, off_t offset, int whence)
{
    debug("> mdish_seek\n");
    (void)hdl; (void)offset; (void)whence;
    debug("< mdish_seek\n");
    return (-ENOSYS);
}

static int
mdish_move(const char *trim_old_name, const char *trim_new_name)
{
    debug("> mdish_move(%s, %s)\n", trim_old_name, trim_new_name);
    debug("< mdish_move\n");
    return (-ENOSYS);
}

static int
mdish_copy(const char *trim_old_name, const char *trim_new_name)
{
    debug("> mdish_copy\n");
    (void)trim_old_name; (void)trim_new_name;
    debug("< mdish_copy\n");
    return (-ENOSYS);
}

static int
mdish_truncate(struct shim_handle *hdl, uint64_t len)
{
    debug("> mdish_truncate(len=%lu)\n", len);
    (void)hdl;
    debug("< mdish_truncate returns\n");
    return (-ENOSYS);
}

static int
mdish_hstat(struct shim_handle *hdl, struct stat *stat)
{
    debug("> mdish_hstat(hdl=*, stat=*)\n");
    (void)hdl; (void)stat;
    debug("< mdish_hstat\n");
    return (-ENOSYS);
}

static int
mdish_setflags(struct shim_handle *hdl, int flags)
{
    debug("> mdish_setflags\n");
    (void)hdl; (void)flags;
    debug("< mdish_setflags\n");
    return (-ENOSYS);
}

static void
mdish_hput(struct shim_handle *hdl)
{
    debug("> mdish_hput\n");
    (void)hdl;
    debug("< mdish_hput\n");
    return;
}

static int
mdish_advlock(struct shim_handle *hdl, int op, struct flock *flock)
{
    int error = 0;

    debug("> mdish_advlock(op=%d)\n", op);

    if (flock->l_type == F_WRLCK)
        error = mdish_advlock_lock(hdl, flock);
    else if (flock->l_type == F_UNLCK)
        error = mdish_advlock_unlock(hdl, flock);
    else
        error = -EINVAL;

    debug("< mdish_advlock\n");
    return (error);
}

static int
mdish_advlock_lock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct rho_buf *buf = g_client->buf;
    uint32_t mdish_fd = 0;
    struct mdish_segment *seg = NULL;

    mdish_fd = hdl->info.mdish.fd;
    debug("> mdish_advlock_lock(fd=%u)\n", mdish_fd);
    seg = mdish_shim_handle_to_segment(hdl);

again:
    rho_buf_clear(buf);
    /* build request */
    rho_buf_seek(buf, MDISH_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, mdish_fd);
    rho_buf_writeu32be(buf, MDISH_LOCKOP_LOCK);

    bodylen = rho_buf_length(buf) - MDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    mdish_pmarshal_hdr(buf, MDISH_OP_FILE_ADVLOCK, bodylen);

    /* make request */
    error = mdish_client_request(g_client, &status, &bodylen);
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
     *          seg == NULL, bodylen == 0
     *
     * case 1 - lock file with associated memory, but this
     *          is the first time locking, so don't download
     *          the server's view of the memory (which would be
     *          all zeroes)
     *
     *          seg != NULL, bodylen == 0
     *
     * case 2 - lock file with associated memroy, and this
     *          is not the first tiem locking, so download
     *          the server's view of the memory and make that
     *          the client's view.
     *
     *          seg != NULL, bodylen > 0
     */
    if (bodylen == 0)
        goto done;

    if (bodylen != seg->size) {
        debug("bodylen=%lu, seg->size=%lu\n", bodylen, seg->size);
        /* TODO: how should we handle this error? 
         * XXX: this might be the problem.
         */
        error = -ERPC;
        goto done;
    }

    debug("mdish_advlock_lock: memcpy: %p <- %p\n",
            seg->addr, rho_buf_raw(buf, 0, SEEK_SET));
    memcpy(seg->addr, rho_buf_raw(buf, 0, SEEK_SET), bodylen);

done:
    rho_buf_clear(buf);
    debug("< mdish_advlock_lock\n");
    return (error);
}

static int
mdish_advlock_unlock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct rho_buf *buf = g_client->buf;
    uint32_t mdish_fd = 0;
    struct mdish_segment *seg = NULL;

    mdish_fd = hdl->info.mdish.fd;
    seg = mdish_shim_handle_to_segment(hdl);

    debug("> mdish_advlock_unlock(fd=%u), seg->size:%lu\n",
            mdish_fd, (unsigned long)seg->size);

    /* build request */
    rho_buf_seek(buf, MDISH_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, mdish_fd);
    rho_buf_writeu32be(buf, MDISH_LOCKOP_UNLOCK);

    if (seg != NULL)
        rho_buf_write(buf, seg->addr, seg->size); 

    bodylen = rho_buf_length(buf) - MDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    mdish_pmarshal_hdr(buf, MDISH_OP_FILE_ADVLOCK, bodylen);

    rho_hexdump(rho_buf_raw(buf, 0, SEEK_SET), 32, "request ");

    /* make request */
    error = mdish_client_request(g_client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }
done:
    rho_buf_clear(buf);
    debug("< mdish_advlock_unlock\n");
    return (error);
}

/* POSTPONE: */
static int
mdish_lock(const char *trim_name)
{
    debug("> mdish_lock\n");
    (void)trim_name;
    debug("< mdish_lock\n");
    return (-ENOSYS);
}

static int
mdish_unlock(const char *trim_name)
{
    debug("> mdish_unlock\n");
    (void)trim_name;
    debug("< mdish_unlock\n");
    return (-ENOSYS);
}

static int
mdish_lockfs(void)
{
    debug("> mdish_lockfs\n");
    debug("< mdish_lockfs\n");
    return (-ENOSYS);
}

static int
mdish_unlockfs(void)
{
    debug("> mdish_lockfs\n");
    debug("< mdish_lockfs\n");
    return (-ENOSYS);
}

/* 
 * TODO: what are the semantics of checkout and checkin?
 * I'm pretty sure checkin is called by the parent
 * and checkout by the child, and, vaguely, this has soemthign
 * to do with altering the hdl state, but beyond that, I don't
 * understand.
 */
static int
mdish_checkout(struct shim_handle *hdl)
{
    debug("> mdish_checkout\n");
    debug("checkout hdl = {path:%s}\n", qstrgetstr(&hdl->path));
    debug("< mdish_checkout\n");
    return (-ENOSYS);
}

static int
mdish_checkin(struct shim_handle *hdl)
{
    debug("> mdish_checkin\n");
    debug("checkin hdl = {path:%s}\n", qstrgetstr(&hdl->path));
    debug("< mdish_checkin\n");
    return (-ENOSYS);
}

static int
mdish_poll(struct shim_handle *hdl, int poll_type)
{
    debug("> mdish_poll\n");
    (void)hdl; (void)poll_type;
    debug("< mdish_poll\n");
    return (-ENOSYS);
}

static int
mdish_checkpoint(void **checkpoint, void *mount_data)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct rho_buf *buf = g_client->buf;
    uint64_t ident = 0;
    struct mdish_mount_data *mdata = NULL;

    debug("> mdish_checkpoint\n");
    
    rho_buf_rewind(buf);
    mdish_pmarshal_hdr(buf, MDISH_OP_FORK, 0);

    /* make request */
    error = mdish_client_request(g_client, &status, &bodylen);
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

    debug("mdish child ident = %llu\n", (unsigned long long)ident);

    mdata = mount_data;
    mdata->ident = ident;
    *checkpoint = mdata;

done:
    rho_buf_clear(buf);
    debug("< mdish_checkpoint\n");
    return (sizeof(struct mdish_mount_data));
}

static int
mdish_migrate(void *checkpoint, void **mount_data)
{
    int error = 0;
    struct rho_buf *buf = NULL;
    uint32_t status = 0;
    uint32_t bodylen = 0;

    debug("> mdish_migrate\n");

    g_mount_data = checkpoint;
    mdish_mount_data_print(g_mount_data);

    g_client = mdish_client_open(g_mount_data->url);
    buf = g_client->buf;

    rho_buf_seek(buf, MDISH_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu64be(buf, g_mount_data->ident);
    bodylen = rho_buf_length(buf) - MDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    mdish_pmarshal_hdr(g_client->buf, MDISH_OP_CHILD_ATTACH, bodylen);
    error = mdish_client_request(g_client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    *mount_data = g_mount_data;

done:
    rho_buf_clear(buf);
    debug("< mdish_migrate\n");
    return (0);
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/
static int
mdish_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct rho_buf *buf = g_client->buf;
    uint32_t fd = 0;
    char name[MDISH_MAX_NAME_LENGTH + 1] = { 0 };

    debug("> mdish_open(hdl=(%p), dent=(%p), flags=0x%08x\n", hdl, dent, flags);
    rho_shim_dentry_print(dent);

    /* get path */
    rho_shim_dentry_relpath(dent, name, sizeof(name));

    /* build request */
    rho_buf_seek(buf, MDISH_HEADER_LENGTH, SEEK_SET); 
    mdish_marshal_str(buf, name);
    bodylen = rho_buf_length(buf) - MDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    mdish_pmarshal_hdr(buf, MDISH_OP_FILE_OPEN, bodylen);

    /* make request */
    error = mdish_client_request(g_client, &status, &bodylen);
    debug("mdish_client_request returned %d\n", error);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    rho_buf_readu32be(buf, &fd);

    debug("mdish_open returned fd=%lu", (unsigned long)fd);

    /* fill in handle */
    hdl->type = TYPE_MDISH;
    hdl->flags = flags;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);
    hdl->info.mdish.fd = fd;

done:
    rho_buf_clear(buf);
    debug("< mdish_open\n");
    return (error);
}

static int
mdish_lookup(struct shim_dentry *dent, bool force)
{
    debug("> mdish_lookup(dent=*, force=%d)\n", force);
    (void)dent; (void)force;

    /* XXX: I know fs/shim_namei.c:297 asserts this condition, but why? */
    if (qstrempty(&dent->rel_path)) {
        dent->state |= DENTRY_ISDIRECTORY;
        goto done;
    }

    /* TODO: set ino? */

done:
    debug("< mdish_lookup\n");
    return (0);
}

static int 
mdish_mode(struct shim_dentry *dent, mode_t *mode, bool force)
{
    debug("> mdish_mode\n");
    (void)mode;

    *mode = 0777;

    debug("< mdish_mode\n");
    return (0);
}

static int 
mdish_dput(struct shim_dentry *dent)
{
    debug("> mdish_dput\n");
    (void)dent;
    debug("< mdish_dput\n");
    return (-ENOSYS);
}

static int
mdish_creat(struct shim_handle *hdl, struct shim_dentry *dir,
        struct shim_dentry *dent, int flags, mode_t mode)
{
    debug("> mdish_creat\n");
    (void)hdl; (void)dir; (void)dent; (void)flags; (void)mode;
    debug("< mdish_creat\n");
    return (-ENOSYS);
}

static int
mdish_unlink(struct shim_dentry *dir, struct shim_dentry *dent)
{
    debug("> mdish_unlink(dir=*, dent=*)\n");
    (void)dir; (void)dent;
    debug("< mdish_unlink\n");
    return (-ENOSYS);
}

static int
mdish_mkdir(struct shim_dentry *dir, struct shim_dentry *dent, mode_t mode)
{
    debug("> mdish_mkdir\n");
    (void)dir; (void)dent; (void)mode;
    debug("< mdish_mkdir\n");
    return (-ENOSYS);
}

static int
mdish_stat(struct shim_dentry *dent, struct stat *stat)
{
    debug("> mdish_stat\n");
    (void)dent; (void)stat;
    debug("< mdish_stat\n");
    return (-ENOSYS);
}

static int
mdish_follow_link(struct shim_dentry *dent, struct shim_qstr *link)
{
    debug("> mdish_follow_link\n");
    (void)dent; (void)link;
    debug("< mdish_follow_link\n");
    return (-ENOSYS);
}

static int
mdish_set_link(struct shim_dentry *dent, const char *link)
{
    debug("> mdish_set_link\n");
    (void)dent;(void)link;
    debug("< mdish_set_link\n");
    return (-ENOSYS);
}

static int
mdish_chmod(struct shim_dentry *dent, mode_t mode)
{
    debug("> mdish_chmod\n");
    (void)dent; (void)mode;
    debug("< mdish_chmod\n");
    return (-ENOSYS);
}

static int
mdish_chown(struct shim_dentry *dent, int uid, int gid)
{
    debug("> mdish_chown\n");
    (void)dent; (void)uid; (void)gid;
    debug("< mdish_chown\n");
    return (-ENOSYS);
} 

static int
mdish_rename(struct shim_dentry *old, struct shim_dentry *new)
{
    debug("> mdish_rename\n");
    (void)old; (void)new;
    debug("< mdish_rename\n");
    return (-ENOSYS);
}

static int
mdish_readdir(struct shim_dentry *dent, struct shim_dirent **dirent)
{
    debug("> mdish_readdir\n");
    (void)dent; (void)dirent;
    debug("< mdish_readdir\n");
    return (-ENOSYS);
}

struct shim_fs_ops mdish_fs_ops = {
        .mount       = &mdish_mount,      /**/
        .unmount     = &mdish_unmount,    /**/
        .close       = &mdish_close,      /**/
        .read        = &mdish_read,       /**/
        .write       = &mdish_write,      /**/
        .mmap        = &mdish_mmap,       /**/
        .flush       = &mdish_flush,      /**/
        .seek        = &mdish_seek,       /**/
        .move        = &mdish_move,
        .copy        = &mdish_copy,
        .truncate    = &mdish_truncate,   /**/
        .hstat       = &mdish_hstat,      /**/
        .setflags    = &mdish_setflags,
        .hput        = &mdish_hput,
        .advlock     = &mdish_advlock,
        .lock        = &mdish_lock,
        .unlock      = &mdish_unlock,
        .lockfs      = &mdish_lockfs,
        .unlockfs    = &mdish_unlockfs,
        .checkout    = &mdish_checkout,   /**/
        .checkin     = &mdish_checkin,
        .poll        = &mdish_poll,       /**/
        .checkpoint  = &mdish_checkpoint, /**/
        .migrate     = &mdish_migrate,    /**/
    };

struct shim_d_ops mdish_d_ops = {
        .open       = &mdish_open,        /**/
        .lookup     = &mdish_lookup,      /**/
        .mode       = &mdish_mode,        /**/
        .dput       = &mdish_dput,        /**/
        .creat      = &mdish_creat,       /**/
        .unlink     = &mdish_unlink,      /**/
        .mkdir      = &mdish_mkdir,       /**/
        .stat       = &mdish_stat,        /**/
        .follow_link = &mdish_follow_link,
        .set_link = &mdish_set_link,
        .chmod      = &mdish_chmod,       /**/
        .chown      = &mdish_chown,       /**/
        .rename     = &mdish_rename,      /**/
        .readdir    = &mdish_readdir,     /**/
    };

#if 0
struct mount_data mdish_data = { .root_uri_len = 5,
                                  .root_uri = "file:", };

struct shim_mount mdish_builtin_fs = { .type   = "mdish",
                                        .fs_ops = &mdish_fs_ops,
                                        .d_ops  = &mdish_d_ops,
                                        .data   = &mdish_data, };
#endif
