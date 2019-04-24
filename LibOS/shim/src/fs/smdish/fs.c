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

#define SMDISH_HEADER_LENGTH            8
#define SMDISH_MAX_NAME_LENGTH   255

/* TODO: move to errno.h */
#define ERPC                            999

#define SMDISH_OP_FILE_OPEN      0
#define SMDISH_OP_FILE_CLOSE     1
#define SMDISH_OP_FILE_ADVLOCK   2
#define SMDISH_OP_MMAP           3
#define SMDISH_OP_MUNMAP         4

#define SMDISH_OP_FORK           5
#define SMDISH_OP_CHILD_ATTACH   6
#define SMDISH_OP_NEW_FDTABLE    7

#define SMDISH_LOCKOP_LOCK       1
#define SMDISH_LOCKOP_UNLOCK     2

struct smdish_client {
    struct rho_sock *sock;
    struct rho_buf *buf;
    char *url;      /* URL for server */
    uint32_t    debug_cookie;
};

struct smdish_segment {
    char name[SMDISH_MAX_NAME_LENGTH + 1];
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
struct smdish_mdata {
    char url[512];           /* URL for server */
    uint64_t ident;             /* auth cookie for child */
    unsigned char ca_der[4096];
    size_t  ca_der_len;
    uint32_t segments_bitmap;
    struct smdish_segment segments[32];
    struct smdish_client *client;
};


static struct smdish_mdata * smdish_mdata_create(const char *uri,
        unsigned char *ca_der, size_t ca_der_len);
static void smdish_mdata_print(const struct smdish_mdata *mdata);
static struct smdish_segment * smdish_mdata_new_segment(
        struct smdish_mdata *mdata, const char *name);
static struct smdish_segment * smdish_mdata_segment_by_name(
        struct smdish_mdata *mdata, const char *name);

static int smdish_segment_initialize(struct smdish_segment *seg, void **addr,
        size_t size);
static struct smdish_segment * smdish_shim_handle_to_segment(
        const struct shim_handle *hdl);

static void smdish_marshal_str(struct rho_buf *buf, const char *s);
static void smdish_pmarshal_hdr(struct rho_buf *buf, uint32_t op,
        uint32_t bodylen);
static void smdish_demarshal_hdr(struct rho_buf *buf, uint32_t *status,
        uint32_t *bodylen);

static struct smdish_client * smdish_client_open(const char *url,
        unsigned char *ca_der, size_t ca_der_len);

static void smdish_client_close(struct smdish_client *client);
static int smdish_client_request(struct smdish_client *client,
        uint32_t *status, uint32_t *bodylen);

static int smdish_mount(const char *uri, const char *root, void **mount_data);
static int smdish_unmount(void *mount_data);
static int smdish_close(struct shim_handle *hdl);
static int smdish_write(struct shim_handle *hdl, const void *data,
        size_t count);
static int smdish_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset);
static int smdish_flush(struct shim_handle *hdl);
static int smdish_seek(struct shim_handle *hdl, off_t offset, int whence);
static int smdish_move(const char *trim_old_name, const char *trim_new_name);
static int smdish_copy(const char *trim_old_name, const char *trim_new_name);
static int smdish_truncate(struct shim_handle *hdl, uint64_t len);
static int smdish_hstat(struct shim_handle *hdl, struct stat *stat);
static int smdish_setflags(struct shim_handle *hdl, int flags);
static void smdish_hput(struct shim_handle *hdl);
static int smdish_advlock(struct shim_handle *hdl, int op, struct flock *flock);
static int smdish_advlock_lock(struct shim_handle *hdl, struct flock *flock);
static int smdish_advlock_unlock(struct shim_handle *hdl, struct flock *flock);
static int smdish_lock(const char *trim_name);
static int smdish_unlock(const char *trim_name);
static int smdish_lockfs(void);
static int smdish_unlockfs(void);
static int smdish_checkout(struct shim_handle *hdl);
static int smdish_checkin(struct shim_handle *hdl);
static int smdish_poll(struct shim_handle *hdl, int poll_type);
static int smdish_checkpoint(void **checkpoint, void *mount_data);
static int smdish_migrate(void *checkpoint, void **mount_data);

static int smdish_open(struct shim_handle *hdl, struct shim_dentry *dent,
        int flags);
static int smdish_lookup(struct shim_dentry *dent, bool force);
static int smdish_mode(struct shim_dentry *dent, mode_t *mode, bool force);
static int smdish_dput(struct shim_dentry *dent);
static int smdish_creat(struct shim_handle *hdl, struct shim_dentry *dir,
        struct shim_dentry *dent, int flags, mode_t mode);
static int smdish_unlink(struct shim_dentry *dir, struct shim_dentry *dent);
static int smdish_mkdir(struct shim_dentry *dir, struct shim_dentry *dent,
        mode_t mode);
static int smdish_stat(struct shim_dentry *dent, struct stat *stat);
static int smdish_follow_link(struct shim_dentry *dent, struct shim_qstr *link);
static int smdish_set_link(struct shim_dentry *dent, const char *link);
static int smdish_chmod(struct shim_dentry *dent, mode_t mode);
static int smdish_chown(struct shim_dentry *dent, int uid, int gid);
static int smdish_rename(struct shim_dentry *old, struct shim_dentry *new);
static int smdish_readdir(struct shim_dentry *dent,
        struct shim_dirent **dirent);

/********************************* 
 * SEGMENTS BITMAP
 *********************************/
#define SMDISH_SEGMENTS_BITMAP_SET(bitmap, i) \
    (bitmap) |= (1 << (i))

#define SMDISH_SEGMENTS_BITMAP_CLEAR(bitmap, i) \
    (bitmap) &= (~(1 << (i)))

#define SMDISH_SEGMENTS_BITMAP_FOREACH(i, val, bitmap) \
    for ( \
            (i) = 0, (val) = (((bitmap) & (1 << (i))) ? 1 : 0); \
            (i) < 32; \
            (i)++,   (val) = (((bitmap) & (1 << (i))) ? 1 : 0) \
        )

static int
smdish_segments_bitmap_ffc(uint32_t bitmap)
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

/********************************* 
 * MOUNT DATA
 *********************************/
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

/* TODO: for munmap, need smdish_mount_dat_segment_by_addr() */

static struct smdish_segment *
smdish_mdata_new_segment(struct smdish_mdata *mdata, const char *name)
{
    int i = 0;
    struct smdish_segment *seg = NULL;

    i = smdish_segments_bitmap_ffc(mdata->segments_bitmap);
    seg = &(mdata->segments[i]);
    memcpy(seg->name, name, strlen(name));
    SMDISH_SEGMENTS_BITMAP_SET(mdata->segments_bitmap, i);

    return (seg);
}

static struct smdish_segment *
smdish_mdata_segment_by_name(struct smdish_mdata *mdata,
        const char *name)
{
    int i = 0;
    int bitval = 0;
    struct smdish_segment *seg = NULL;

    SMDISH_SEGMENTS_BITMAP_FOREACH(i, bitval, mdata->segments_bitmap) {
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
smdish_segment_initialize(struct smdish_segment *seg, void **addr, size_t size)
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

static struct smdish_segment *
smdish_shim_handle_to_segment(const struct shim_handle *hdl)
{
    struct smdish_segment *seg = NULL;
    char name[SMDISH_MAX_NAME_LENGTH + 1] = { 0 };
    struct smdish_mdata *mdata = hdl->fs->data;

    rho_shim_dentry_relpath(hdl->dentry, name, sizeof(name));
    seg = smdish_mdata_segment_by_name(mdata, name);
    debug("> smdish_shim_handle_to_segment(path=%s) -> %p\n", name, seg);
    if (seg != NULL) {
        debug("< smdish_shim_handle_to_segment: (name=\"%s\", addr=%p, size=%lu)\n",
                seg->name, seg->addr, (unsigned long)seg->size);
    }

    /* TODO: assert that seg is not NULL */
    return (seg);
}

/********************************* 
 * RPC HELPERS
 *********************************/

static void
smdish_marshal_str(struct rho_buf *buf, const char *s)
{
    size_t len = strlen(s);
    rho_buf_writeu32be(buf, len);
    rho_buf_puts(buf, s);
}

static void
smdish_pmarshal_hdr(struct rho_buf *buf, uint32_t op, uint32_t bodylen)
{
    rho_buf_pwriteu32be_at(buf, op, 0);
    rho_buf_pwriteu32be_at(buf, bodylen, 4);
}

static void
smdish_demarshal_hdr(struct rho_buf *buf, uint32_t *status, uint32_t *bodylen)
{
    *status = 0;
    *bodylen = 0;

    rho_buf_readu32be(buf, status);
    rho_buf_readu32be(buf, bodylen);
}

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

/*
 * return 0 on success, or -errno on failure?
 *
 * On success, status and bodylen point to the responses'
 * status and bodylen, and client->buf holds the reponse
 * (starting at offset=0, with buf cursor at 0).
 */
static int
smdish_client_request(struct smdish_client *client,
        uint32_t *status, uint32_t *bodylen)
{
    int error = 0;
    ssize_t n = 0;
    struct rho_sock *sock = client->sock;
    struct rho_buf *buf = client->buf;

    debug("> smdish_client_request debug_cookie=%lu, (buf_length(buf)=%lu, buf_tell=%ld, raw=%p\n",
            (unsigned long)client->debug_cookie,
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

    debug("receiving smdish header\n");
    rho_buf_clear(buf);
    n = rho_sock_precvn_buf(sock, buf, 8);
    debug("response: wanted to recv 8; got %ld\n", (long)n);
    if (n == -1) {
        error = -1;
        goto done;
    }

    debug("demarshaling smdish header (n=%ld)\n", n);

    smdish_demarshal_hdr(buf, status, bodylen);
    if (*bodylen > 0) {
        rho_buf_clear(buf);
        debug("response status=%u, len=%u\n", *status, *bodylen);
        debug("receiving smdish body\n");
        n = rho_sock_precvn_buf(sock, buf, *bodylen);
        debug("received %ld bytes of smdish body\n", (long)n);
        if (n == -1) {
            error = -1;
            goto done;
        }
    }

done:
    debug("< smdish_client_request\n");
    return (error);
}

/********************************* 
 * FILE/FILESYSTEM OPERATIONS
 *********************************/

/*
 * XXX: For now, we assume that only one smdish is mounted, and that
 * it is a unix domain socket.
 */

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
    uint32_t status = 0;
    uint32_t bodylen = 0;
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
    rho_buf_rewind(client->buf);
    smdish_pmarshal_hdr(client->buf, SMDISH_OP_NEW_FDTABLE, 0);
    error = smdish_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    mdata = smdish_mdata_create(uri, ca_der, len / 2);
    mdata->client = client;
    *mount_data = mdata;
    debug("setting smdish mount data (%p)\n", mdata);

done:
    /* TODO: need to propagate an error if we can't open the client */
    rho_buf_clear(client->buf);
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
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct smdish_mdata *mdata = hdl->fs->data;
    struct smdish_client *client = mdata->client;
    struct rho_buf *buf = client->buf;
    uint32_t smdish_fd = 0;

    smdish_fd = hdl->info.smdish.fd;

    debug("> smdish_close(fd=%u)\n", smdish_fd);

    /* build request */
    rho_buf_seek(buf, SMDISH_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, smdish_fd);
    bodylen = rho_buf_length(buf) - SMDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    smdish_pmarshal_hdr(buf, SMDISH_OP_FILE_CLOSE, bodylen);

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

done:
    rho_buf_clear(buf);
    debug("< smdish_close\n");
    return (error);
}

static int
smdish_read(struct shim_handle *hdl, void *data, size_t count)
{
    debug("> smdish_read\n");
    (void)hdl; (void)data; (void)count;
    debug("< smdish_read\n");
    return (-ENOSYS);
}

static int
smdish_write(struct shim_handle *hdl, const void *data, size_t count)
{
    debug("> smdish_write\n");
    (void)hdl; (void)data; (void)count;
    debug("< smdish_write\n");
    return (-ENOSYS);
}

static int
smdish_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct smdish_mdata *mdata = hdl->fs->data;
    struct smdish_client *client = mdata->client;
    struct rho_buf *buf = client->buf;
    uint32_t smdish_fd = 0;
    char name[SMDISH_MAX_NAME_LENGTH + 1] = { 0 };
    struct smdish_segment *seg = NULL;
    uint32_t smdish_sd = 0;

    (void)prot;
    (void)flags;
    (void)offset;

    smdish_fd = hdl->info.smdish.fd;
    rho_shim_dentry_relpath(hdl->dentry, name, sizeof(name));

    debug("> smdish_mmap(fd=%u (%s), size=%lu)\n",
            smdish_fd, name, (unsigned long) size);

    /* build request */
    rho_buf_seek(buf, SMDISH_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, smdish_fd);
    rho_buf_writeu32be(buf, size);
    bodylen = rho_buf_length(buf) - SMDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    smdish_pmarshal_hdr(buf, SMDISH_OP_MMAP, bodylen);

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

    if (bodylen != 4) {
        error = -ERPC;
        goto done;
    }

    rho_buf_readu32be(buf, &smdish_sd);
    seg = smdish_mdata_new_segment(mdata, name);
    error = smdish_segment_initialize(seg, addr, size);

done:
    rho_buf_clear(buf);
    debug("< smdish_mmap\n");
    return (error);
}

static int
smdish_flush(struct shim_handle *hdl)
{
    debug("> smdish_flush\n");
    (void)hdl;
    debug("< smdish_flush\n");
    return (-ENOSYS);
}

static int
smdish_seek(struct shim_handle *hdl, off_t offset, int whence)
{
    debug("> smdish_seek\n");
    (void)hdl; (void)offset; (void)whence;
    debug("< smdish_seek\n");
    return (-ENOSYS);
}

static int
smdish_move(const char *trim_old_name, const char *trim_new_name)
{
    debug("> smdish_move(%s, %s)\n", trim_old_name, trim_new_name);
    debug("< smdish_move\n");
    return (-ENOSYS);
}

static int
smdish_copy(const char *trim_old_name, const char *trim_new_name)
{
    debug("> smdish_copy\n");
    (void)trim_old_name; (void)trim_new_name;
    debug("< smdish_copy\n");
    return (-ENOSYS);
}

static int
smdish_truncate(struct shim_handle *hdl, uint64_t len)
{
    debug("> smdish_truncate(len=%lu)\n", len);
    (void)hdl;
    debug("< smdish_truncate returns\n");
    return (-ENOSYS);
}

static int
smdish_hstat(struct shim_handle *hdl, struct stat *stat)
{
    debug("> smdish_hstat(hdl=*, stat=*)\n");
    (void)hdl; (void)stat;
    debug("< smdish_hstat\n");
    return (-ENOSYS);
}

static int
smdish_setflags(struct shim_handle *hdl, int flags)
{
    debug("> smdish_setflags\n");
    (void)hdl; (void)flags;
    debug("< smdish_setflags\n");
    return (-ENOSYS);
}

static void
smdish_hput(struct shim_handle *hdl)
{
    debug("> smdish_hput\n");
    (void)hdl;
    debug("< smdish_hput\n");
    return;
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
    struct smdish_segment *seg = NULL;

    smdish_fd = hdl->info.smdish.fd;
    debug("> smdish_advlock_lock(fd=%u, hdl=%p, hdl->fs=%p, hdl->fs->data=%p)\n",
            smdish_fd, hdl, hdl->fs, hdl->fs->data);
    seg = smdish_shim_handle_to_segment(hdl);

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

    debug("smdish_advlock_lock: memcpy: %p <- %p\n",
            seg->addr, rho_buf_raw(buf, 0, SEEK_SET));
    memcpy(seg->addr, rho_buf_raw(buf, 0, SEEK_SET), bodylen);

done:
    rho_buf_clear(buf);
    debug("< smdish_advlock_lock\n");
    return (error);
}

static int
smdish_advlock_unlock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct smdish_mdata *mdata = hdl->fs->data;
    struct smdish_client *client = mdata->client;
    struct rho_buf *buf = client->buf;
    uint32_t smdish_fd = 0;
    struct smdish_segment *seg = NULL;

    smdish_fd = hdl->info.smdish.fd;
    seg = smdish_shim_handle_to_segment(hdl);

    debug("> smdish_advlock_unlock(fd=%u), seg->size:%lu\n",
            smdish_fd, (unsigned long)seg->size);

    /* build request */
    rho_buf_seek(buf, SMDISH_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, smdish_fd);
    rho_buf_writeu32be(buf, SMDISH_LOCKOP_UNLOCK);

    if (seg != NULL)
        rho_buf_write(buf, seg->addr, seg->size); 

    bodylen = rho_buf_length(buf) - SMDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    smdish_pmarshal_hdr(buf, SMDISH_OP_FILE_ADVLOCK, bodylen);

    //rho_hexdump(rho_buf_raw(buf, 0, SEEK_SET), 32, "request ");

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
done:
    rho_buf_clear(buf);
    debug("< smdish_advlock_unlock\n");
    return (error);
}

/* POSTPONE: */
static int
smdish_lock(const char *trim_name)
{
    debug("> smdish_lock\n");
    (void)trim_name;
    debug("< smdish_lock\n");
    return (-ENOSYS);
}

static int
smdish_unlock(const char *trim_name)
{
    debug("> smdish_unlock\n");
    (void)trim_name;
    debug("< smdish_unlock\n");
    return (-ENOSYS);
}

static int
smdish_lockfs(void)
{
    debug("> smdish_lockfs\n");
    debug("< smdish_lockfs\n");
    return (-ENOSYS);
}

static int
smdish_unlockfs(void)
{
    debug("> smdish_lockfs\n");
    debug("< smdish_lockfs\n");
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
smdish_poll(struct shim_handle *hdl, int poll_type)
{
    debug("> smdish_poll\n");
    (void)hdl; (void)poll_type;
    debug("< smdish_poll\n");
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
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct smdish_mdata *mdata = NULL;
    struct smdish_client *client = NULL; 
    struct rho_buf *buf = NULL; 
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

    /* build request */
    rho_buf_seek(buf, SMDISH_HEADER_LENGTH, SEEK_SET); 
    smdish_marshal_str(buf, name);
    bodylen = rho_buf_length(buf) - SMDISH_HEADER_LENGTH;
    rho_buf_rewind(buf);
    smdish_pmarshal_hdr(buf, SMDISH_OP_FILE_OPEN, bodylen);

    /* make request */
    error = smdish_client_request(client, &status, &bodylen);
    debug("smdish_client_request returned %d\n", error);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    rho_buf_readu32be(buf, &fd);

    debug("smdish_open returned fd=%lu\n", (unsigned long)fd);

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
smdish_dput(struct shim_dentry *dent)
{
    debug("> smdish_dput\n");
    (void)dent;
    debug("< smdish_dput\n");
    return (-ENOSYS);
}

static int
smdish_creat(struct shim_handle *hdl, struct shim_dentry *dir,
        struct shim_dentry *dent, int flags, mode_t mode)
{
    debug("> smdish_creat\n");
    (void)hdl; (void)dir; (void)dent; (void)flags; (void)mode;
    debug("< smdish_creat\n");
    return (-ENOSYS);
}

static int
smdish_unlink(struct shim_dentry *dir, struct shim_dentry *dent)
{
    debug("> smdish_unlink(dir=*, dent=*)\n");
    (void)dir; (void)dent;
    debug("< smdish_unlink\n");
    return (-ENOSYS);
}

static int
smdish_mkdir(struct shim_dentry *dir, struct shim_dentry *dent, mode_t mode)
{
    debug("> smdish_mkdir\n");
    (void)dir; (void)dent; (void)mode;
    debug("< smdish_mkdir\n");
    return (-ENOSYS);
}

static int
smdish_stat(struct shim_dentry *dent, struct stat *stat)
{
    debug("> smdish_stat\n");
    (void)dent; (void)stat;
    debug("< smdish_stat\n");
    return (-ENOSYS);
}

static int
smdish_follow_link(struct shim_dentry *dent, struct shim_qstr *link)
{
    debug("> smdish_follow_link\n");
    (void)dent; (void)link;
    debug("< smdish_follow_link\n");
    return (-ENOSYS);
}

static int
smdish_set_link(struct shim_dentry *dent, const char *link)
{
    debug("> smdish_set_link\n");
    (void)dent;(void)link;
    debug("< smdish_set_link\n");
    return (-ENOSYS);
}

static int
smdish_chmod(struct shim_dentry *dent, mode_t mode)
{
    debug("> smdish_chmod\n");
    (void)dent; (void)mode;
    debug("< smdish_chmod\n");
    return (-ENOSYS);
}

static int
smdish_chown(struct shim_dentry *dent, int uid, int gid)
{
    debug("> smdish_chown\n");
    (void)dent; (void)uid; (void)gid;
    debug("< smdish_chown\n");
    return (-ENOSYS);
} 

static int
smdish_rename(struct shim_dentry *old, struct shim_dentry *new)
{
    debug("> smdish_rename\n");
    (void)old; (void)new;
    debug("< smdish_rename\n");
    return (-ENOSYS);
}

static int
smdish_readdir(struct shim_dentry *dent, struct shim_dirent **dirent)
{
    debug("> smdish_readdir\n");
    (void)dent; (void)dirent;
    debug("< smdish_readdir\n");
    return (-ENOSYS);
}

struct shim_fs_ops smdish_fs_ops = {
        .mount       = &smdish_mount,      /**/
        .unmount     = &smdish_unmount,    /**/
        .close       = &smdish_close,      /**/
        .read        = &smdish_read,       /**/
        .write       = &smdish_write,      /**/
        .mmap        = &smdish_mmap,       /**/
        .flush       = &smdish_flush,      /**/
        .seek        = &smdish_seek,       /**/
        .move        = &smdish_move,
        .copy        = &smdish_copy,
        .truncate    = &smdish_truncate,   /**/
        .hstat       = &smdish_hstat,      /**/
        .setflags    = &smdish_setflags,
        .hput        = &smdish_hput,
        .advlock     = &smdish_advlock,
        .lock        = &smdish_lock,
        .unlock      = &smdish_unlock,
        .lockfs      = &smdish_lockfs,
        .unlockfs    = &smdish_unlockfs,
        .checkout    = &smdish_checkout,   /**/
        .checkin     = &smdish_checkin,
        .poll        = &smdish_poll,       /**/
        .checkpoint  = &smdish_checkpoint, /**/
        .migrate     = &smdish_migrate,    /**/
    };

struct shim_d_ops smdish_d_ops = {
        .open       = &smdish_open,        /**/
        .lookup     = &smdish_lookup,      /**/
        .mode       = &smdish_mode,        /**/
        .dput       = &smdish_dput,        /**/
        .creat      = &smdish_creat,       /**/
        .unlink     = &smdish_unlink,      /**/
        .mkdir      = &smdish_mkdir,       /**/
        .stat       = &smdish_stat,        /**/
        .follow_link = &smdish_follow_link,
        .set_link = &smdish_set_link,
        .chmod      = &smdish_chmod,       /**/
        .chown      = &smdish_chown,       /**/
        .rename     = &smdish_rename,      /**/
        .readdir    = &smdish_readdir,     /**/
    };

#if 0
struct mount_data smdish_data = { .root_uri_len = 5,
                                  .root_uri = "file:", };

struct shim_mount smdish_builtin_fs = { .type   = "smdish",
                                        .fs_ops = &smdish_fs_ops,
                                        .d_ops  = &smdish_d_ops,
                                        .data   = &smdish_data, };
#endif
