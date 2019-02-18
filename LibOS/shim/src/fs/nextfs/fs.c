/*
 * fs.c
 *
 * The 'nextfs' filesystem.
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

#define CRYPTO_USE_MBEDTLS
#include <pal_crypto.h>

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
#include <rho_rand.h>
#include <rho_shim_dentry.h>
#include <rho_sock.h>
#include <rho_ssl.h>

#define URI_MAX_SIZE    STR_SIZE

#define TTY_FILE_MODE   0666

#define FILE_BUFMAP_SIZE (PAL_CB(pagesize) * 4)
#define FILE_BUF_SIZE (PAL_CB(pagesize))

/*****/

#define NEXTFS_HEADER_LENGTH            8
#define NEXTFS_MAX_PATH_LENGTH          255

/* TODO: move to errno.h */
#define ERPC                            999

#define NEXTFS_OP_DEVICE_REGISTER       0
#define NEXTFS_OP_MOUNT                 1
#define NEXTFS_OP_UMOUNT                2
#define NEXTFS_OP_MOUNT_POINT_STATS     3
#define NEXTFS_OP_CACHE_WRITE_BACK      4

#define NEXTFS_OP_FILE_REMOVE           5
#define NEXTFS_OP_FILE_LINK             6
#define NEXTFS_OP_FILE_RENAME           7
#define NEXTFS_OP_FILE_OPEN             8
#define NEXTFS_OP_FILE_OPEN2            9
#define NEXTFS_OP_FILE_CLOSE            10
#define NEXTFS_OP_FILE_TRUNCATE         11
#define NEXTFS_OP_FILE_READ             12
#define NEXTFS_OP_FILE_WRITE            13
#define NEXTFS_OP_FILE_SEEK             14
#define NEXTFS_OP_FILE_TELL             15
#define NEXTFS_OP_FILE_SIZE             16

#define NEXTFS_OP_DIR_RM                17
#define NEXTFS_OP_DIR_MV                18
#define NEXTFS_OP_DIR_MK                19
#define NEXTFS_OP_DIR_MKDIR             20
#define NEXTFS_OP_DIR_OPEN              21
#define NEXTFS_OP_DIR_CLOSE             22
#define NEXTFS_OP_DIR_ENTRY_NEXT        23
#define NEXTFS_OP_DIR_ENTRY_REWIND      24
#define NEXTFS_OP_DIR_LIST              25

#define NEXTFS_OP_SYMLINK               26
#define NEXTFS_OP_MKNOD                 27
#define NEXTFS_OP_READLINK              28

#define NEXTFS_OP_RAW_INODE             29
#define NEXTFS_OP_MODE_SET              30
#define NEXTFS_OP_MODE_GET              31
#define NEXTFS_OP_OWNER_SET             32
#define NEXTFS_OP_OWNER_GET             33
#define NEXTFS_OP_ATIME_SET             34
#define NEXTFS_OP_ATIME_GET             35
#define NEXTFS_OP_MTIME_SET             36
#define NEXTFS_OP_MTIME_GET             37
#define NEXTFS_OP_CTIME_SET             38
#define NEXTFS_OP_CTIME_GET             39

#define NEXTFS_OP_FORK                  40
#define NEXTFS_OP_CHILD_ATTACH          41
#define NEXTFS_OP_NEW_FDTABLE           42


struct nextfs_client {
    struct rho_sock *sock;
    struct rho_buf *buf;
};

struct nextfs_mdata {
    char    url[512];       /* URL for server */
    uint64_t ident;     /* auth cookie for child */
    unsigned char ca_der[4096];
    size_t  ca_der_len;
    struct nextfs_client *client;
    uint32_t debug_cookie;
};

static void nextfs_marshal_str(struct rho_buf *buf, const char *s);
static void nextfs_pmarshal_hdr(struct rho_buf *buf, uint32_t op,
        uint32_t bodylen);
static void nextfs_demarshal_hdr(struct rho_buf *buf, uint32_t *status,
        uint32_t *bodylen);

static struct nextfs_client * nextfs_client_open(const char *url, 
        unsigned char *ca_der, size_t ca_der_len);

static int nextfs_client_request(struct nextfs_client *client,
        uint32_t *status, uint32_t *bodylen);

static int nextfs_mount(const char *uri, const char *root, void **mount_data);
static int nextfs_unmount(void *mount_data);
static int nextfs_close(struct shim_handle *hdl);
static int nextfs_read(struct shim_handle *hdl, void *data, size_t count);
static int nextfs_write(struct shim_handle *hdl, const void *data,
        size_t count);
#if 0
static int nextfs_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset);
#endif
static int nextfs_flush(struct shim_handle *hdl);
static int nextfs_seek(struct shim_handle *hdl, off_t offset, int whence);
static int nextfs_move(const char *trim_old_name, const char *trim_new_name);
static int nextfs_copy(const char *trim_old_name, const char *trim_new_name);
static int nextfs_truncate(struct shim_handle *hdl, uint64_t len);
static int nextfs_hstat(struct shim_handle *hdl, struct stat *stat);
static int nextfs_setflags(struct shim_handle *hdl, int flags);
static void nextfs_hput(struct shim_handle *hdl);
static int nextfs_advlock(struct shim_handle *hdl, int op, struct flock *flock);
static int nextfs_lock(const char *trim_name);
static int nextfs_unlock(const char *trim_name);
static int nextfs_lockfs(void);
static int nextfs_unlockfs(void);
static int nextfs_checkout(struct shim_handle *hdl);
static int nextfs_checkin(struct shim_handle *hdl);
static int nextfs_poll(struct shim_handle *hdl, int poll_type);
static int nextfs_checkpoint(void **checkpoint, void *mount_data);
static int nextfs_migrate(void *checkpoint, void **mount_data);

static int nextfs_opendir(struct shim_handle *hdl, struct shim_dentry *dent,
        int flags);
static int nextfs_open(struct shim_handle *hdl, struct shim_dentry *dent,
        int flags);
static int nextfs_lookup(struct shim_dentry *dent, bool force);
static int nextfs_mode(struct shim_dentry *dent, mode_t *mode, bool force);
static int nextfs_dput(struct shim_dentry *dent);
static int nextfs_creat(struct shim_handle *hdl, struct shim_dentry *dir,
        struct shim_dentry *dent, int flags, mode_t mode);
static int nextfs_unlink(struct shim_dentry *dir, struct shim_dentry *dent);
static int nextfs_mkdir(struct shim_dentry *dir, struct shim_dentry *dent,
        mode_t mode);
static int nextfs_stat(struct shim_dentry *dent, struct stat *stat);
static int nextfs_follow_link(struct shim_dentry *dent, struct shim_qstr *link);
static int nextfs_set_link(struct shim_dentry *dent, const char *link);
static int nextfs_chmod(struct shim_dentry *dent, mode_t mode);
static int nextfs_chown(struct shim_dentry *dent, int uid, int gid);
static int nextfs_rename(struct shim_dentry *old, struct shim_dentry *new);
static int nextfs_readdir(struct shim_dentry *dent,
        struct shim_dirent **dirent);

/********************************* 
 * RETRIEVE DATA FROM HDL/DENTRY
 *********************************/
#define NEXTFS_HDL_GET_FD(hdl) \
    hdl->info.nextfs.fd

struct nextfs_client *
nextfs_hdl_get_client(struct shim_handle *hdl)
{
    struct shim_mount *fs = NULL;
    struct nextfs_mdata *mdata = NULL;
    struct nextfs_client *client = NULL;

    debug("nextfs_hdl_get_client: (path=\"%s\")\n",
            qstrgetstr(&hdl->path));

    fs = hdl->fs;
    if (fs == NULL) {
        debug("nextfs_hdl_get_client: hdl->fs is NULL");
    } else {
        RHO_ASSERT(hdl->dentry != NULL);
        rho_shim_dentry_print(hdl->dentry);
        fs = hdl->dentry->fs;
    }
    RHO_ASSERT(fs != NULL);
    
    mdata = fs->data;
    RHO_ASSERT(mdata != NULL);

    client = mdata->client;
    RHO_ASSERT(client != NULL);

    debug("nextfs_mdata debug_cookie=%lu\n", mdata->debug_cookie);
    return (client);
}

struct nextfs_client *
nextfs_dentry_get_client(struct shim_dentry *dentry)
{
    struct shim_mount *fs = NULL;
    struct nextfs_mdata *mdata = NULL;
    struct nextfs_client *client = NULL;

    fs = dentry->fs;
    RHO_ASSERT(fs != NULL);
    
    mdata = fs->data;
    RHO_ASSERT(mdata != NULL);

    client = mdata->client;
    RHO_ASSERT(client != NULL);

    debug("nextfs_mdata debug_cookie=%lu\n", mdata->debug_cookie);
    return (client);
}

/********************************* 
 * MOUNT DATA
 *********************************/
static struct nextfs_mdata *
nextfs_mdata_create(const char *uri, unsigned char *ca_der,
        size_t ca_der_len)
{
    struct nextfs_mdata *mdata = NULL;
    
    debug("> nextfs_mdata_create\n");

    mdata = rhoL_zalloc(sizeof(struct nextfs_mdata));
    memcpy(mdata->url, uri, strlen(uri));
    if (ca_der != NULL) {
        memcpy(mdata->ca_der, ca_der, ca_der_len);
        mdata->ca_der_len = ca_der_len;
    }

    mdata->debug_cookie = rho_rand_u32();

    debug("< nextfs_mdata_create\n");
    return (mdata);
}

static void
nextfs_mdata_print(const struct nextfs_mdata *mdata)
{
    debug("nextfs_mdata = {url: %s, ident:%llu, debug_cookie:%lu}\n",
            mdata->url, (unsigned long long)mdata->ident,
            (unsigned long)mdata->debug_cookie);
}

/********************************* 
 * RPC UTILS
 *********************************/

static void
nextfs_marshal_str(struct rho_buf *buf, const char *s)
{
    size_t len = strlen(s);
    rho_buf_writeu32be(buf, len);
    rho_buf_puts(buf, s);
}

static void
nextfs_pmarshal_hdr(struct rho_buf *buf, uint32_t op, uint32_t bodylen)
{
    rho_buf_pwriteu32be_at(buf, op, 0);
    rho_buf_pwriteu32be_at(buf, bodylen, 4);
}

static void
nextfs_demarshal_hdr(struct rho_buf *buf, uint32_t *status, uint32_t *bodylen)
{
    rho_buf_readu32be(buf, status);
    rho_buf_readu32be(buf, bodylen);
}

/********************************* 
 * NEXTFS RPC CLIENT
 *********************************/

static struct nextfs_client *
nextfs_client_open(const char *url, unsigned char *ca_der, size_t ca_der_len)
{
    struct nextfs_client *client = NULL;
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *ctx = NULL;

    debug("> nextfs_client_open(url=%s)\n", url);

    client = rhoL_zalloc(sizeof(*client));
    client->buf = rho_buf_create();
    client->sock = rho_sock_open_url(url);

    if (ca_der != NULL) {
        debug("nextfs client using TLS\n");
        params = rho_ssl_params_create();
        rho_ssl_params_set_mode(params, RHO_SSL_MODE_CLIENT);
        rho_ssl_params_set_protocol(params, RHO_SSL_PROTOCOL_TLSv1_2);
        rho_ssl_params_set_ca_der(params, ca_der, ca_der_len);
        ctx = rho_ssl_ctx_create(params);
        rho_ssl_wrap(client->sock, ctx);
        //rho_ssl_params_destroy(params);
    }

    debug("< nextfs_client_open\n");
    return (client);
}

static void
nextfs_client_close(struct nextfs_client *client)
{
    debug("> nextfs_client_close\n");

    rho_sock_destroy(client->sock);
    rho_buf_destroy(client->buf);
    rhoL_free(client);

    debug("< nextfs_client_close\n");
}

/*
 * return 0 on success, or -errno on failure?
 *
 * On success, status and bodylen point to the responses'
 * status and bodylen, and client->buf holds the reponse
 * (starting at offset=0, with buf cursor at 0).
 */
static int
nextfs_client_request(struct nextfs_client *client,
        uint32_t *status, uint32_t *bodylen)
{
    int error = 0;
    ssize_t n = 0;
    struct rho_sock *sock = client->sock;
    struct rho_buf *buf = client->buf;

    debug("> nextfs_client_request\n");

    n = rho_sock_sendn_buf(sock, buf, rho_buf_length(buf));
    if (n == -1) {
        error = -1;
        goto done;
    }

    debug("receiving nextfs header\n");

    rho_buf_clear(buf);
    n = rho_sock_precvn_buf(sock, buf, 8);
    if (n == -1) {
        error = -1;
        goto done;
    }

    debug("demarshaling nextfs header (n=%ld)\n", n);

    nextfs_demarshal_hdr(buf, status, bodylen);
    if (*bodylen > 0) {
        rho_buf_clear(buf);
        debug("response status=%u, len=%u\n", *status, *bodylen);
        debug("receiving nextfs body\n");
        n = rho_sock_precvn_buf(sock, buf, *bodylen);
        if (n == -1) {
            error = -1;
            goto done;
        }
    }

done:
    debug("< nextfs_client_request\n");
    return (error);
}

/********************************* 
 * FILE/FILESYSTEM OPERATIONS
 *********************************/

/*
 * XXX: For now, we assume that only one nextfs is mounted, and that
 * it is a unix domain socket.
 */

/*
 * Mount should allocated a struct nextfs_mountdata and return it
 * in the mount_data out parameter.
 *
 * uri is the host URI for the resource to be "mounted", and
 * root is the guest mountpoint.
 */
static int
nextfs_mount(const char *uri, const char *root, void **mount_data)
{
    int error = 0;
    uint32_t status = 0;
    uint32_t bodylen = 0;
    char ca_hex[CONFIG_MAX] = { 0 };
    unsigned char *ca_der = NULL;
    ssize_t len = 0;
    struct nextfs_mdata *mdata = NULL;
    struct nextfs_client *client = NULL;

    debug("> nextfs_mount(uri=%s, root=%s, mount_data=*)\n", uri, root);

    len = get_config(root_config, "phoenix.ca_der", ca_hex, sizeof(ca_hex));
    if (len > 0) {
        debug("READ phoenix.ca_der (size=%ld)\n", len);
        ca_der = rhoL_malloc(len / 2);
        rho_binascii_hex2bin(ca_der, ca_hex);
    }
    client = nextfs_client_open(uri, ca_der, len / 2);
    rho_buf_rewind(client->buf);
    nextfs_pmarshal_hdr(client->buf, NEXTFS_OP_NEW_FDTABLE, 0);
    error = nextfs_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    mdata = nextfs_mdata_create(uri, ca_der, len / 2);
    mdata->client = client;
    *mount_data = mdata;

done:
    /* TODO: need to propagate an error if we can't open the client */
    rho_buf_clear(client->buf);
    if (ca_der != NULL)
        rhoL_free(ca_der);
    debug("< nextfs_mount\n");
    return (error);
}

/* POSTPONE: 
 *
 * You need to close the client and rfree the global struct nextfs_mountdata 
 *
 * Currently, Graphene never calls unmount.
 */
static int 
nextfs_unmount(void *mount_data)
{
    struct nextfs_mdata *mdata = mount_data;

    debug("> nextfs_unmount\n");

    nextfs_client_close(mdata->client);
    rhoL_free(mdata);

    debug("< nextfs_unmount\n");
    return (0);
}

static int
nextfs_close(struct shim_handle *hdl)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    uint32_t nextfs_fd = 0;

    client = nextfs_hdl_get_client(hdl);
    buf = client->buf;
    nextfs_fd = NEXTFS_HDL_GET_FD(hdl);

    debug("> nextfs_close(fd=%u)\n", nextfs_fd);

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, nextfs_fd);
    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_FILE_CLOSE, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
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
    debug("< nextfs_close\n");
    return (error);
}

static int
nextfs_read(struct shim_handle *hdl, void *data, size_t count)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    uint32_t nextfs_fd = 0;

    client = nextfs_hdl_get_client(hdl);
    buf = client->buf;
    nextfs_fd = NEXTFS_HDL_GET_FD(hdl);

    debug("> nextfs_read(fd=%u, count=%lu), fs=%p, mdata=%p, client=%p\n", 
        nextfs_fd, (unsigned long)count, hdl->fs, hdl->fs->data,
        ((struct nextfs_mdata *)hdl->fs->data)->client);

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, nextfs_fd);
    rho_buf_writeu32be(buf, count);
    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_FILE_READ, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    /* copy result */
    memcpy(data, rho_buf_raw(buf, 0, SEEK_SET), bodylen); 
    error = (int)bodylen;

done:
    rho_buf_clear(buf);
    debug("< nextfs_read\n");
    return (error);
}

static int
nextfs_write(struct shim_handle *hdl, const void *data, size_t count)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    uint32_t nextfs_fd = 0;
    uint32_t wcnt = 0;

    client = nextfs_hdl_get_client(hdl);
    buf = client->buf;
    nextfs_fd = NEXTFS_HDL_GET_FD(hdl);

    debug("> nextfs_write\n");

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, nextfs_fd);
    /* TODO: make rho_buf_write_u32size_blob */
    rho_buf_writeu32be(buf, count);
    rho_buf_write(buf, data, count);
    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_FILE_WRITE, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    error = rho_buf_readu32be(buf, &wcnt);
    if (error == -1) {
        error = -ERPC;
        goto done;
    }

    error = (int)wcnt;

done:
    rho_buf_clear(buf);
    debug("< nextfs_write returns %d\n", error);
    return (error);
}

/* POSTPONE: */
#if 0
static int
nextfs_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    debug("> nextfs_mmap\n");

    (void)hdl;
    (void)addr;
    (void)size;
    (void)prot;
    (void)flags;
    (void)offset;

    debug("< nextfs_mmap\n");
    return (0);
}
#endif

/* POSTPONE: */
static int
nextfs_flush(struct shim_handle *hdl)
{
    debug("> nextfs_flush\n");
    (void)hdl;
    debug("< nextfs_flush\n");
    return (0);
}

static int
nextfs_seek(struct shim_handle *hdl, off_t offset, int whence)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    int nextfs_fd = 0;
    uint64_t newoffset = 0;

    client = nextfs_hdl_get_client(hdl);
    buf = client->buf;
    nextfs_fd = NEXTFS_HDL_GET_FD(hdl);

    debug("> nextfs_seek\n");

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, nextfs_fd);
    rho_buf_write64be(buf, offset);
    rho_buf_writeu32be(buf, whence);

    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_FILE_SEEK, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    error = rho_buf_readu64be(buf, &newoffset);
    if (error == -1) {
        error = -ERPC;
        goto done;
    } else {
        /* FIXME: there's an int-size type mismatch */
        error = (int)newoffset;
    }

done:
    rho_buf_clear(buf);
    debug("< nextfs_seek\n");
    return (error);
}

/* XXX: what does "trim_name" mean? 
 *
 * FIXME: I don't think this function is ever called.  The problem
 * is that there is no way to go from a path name to the mountdata
 * without us keeping some lookup table.
 */
static int
nextfs_move(const char *trim_old_name, const char *trim_new_name)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;

    debug("> nextfs_move(%s, %s)\n", trim_old_name, trim_new_name);

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, trim_old_name);
    nextfs_marshal_str(buf, trim_new_name);

    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_FILE_RENAME, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
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
    debug("< nextfs_move\n");
    return (error);
}

/* POSTPONE: */
static int
nextfs_copy(const char *trim_old_name, const char *trim_new_name)
{
    debug("> nextfs_copy\n");

    (void)trim_old_name;
    (void)trim_new_name;

    debug("< nextfs_copy\n");
    return (0);
}

static int
nextfs_truncate(struct shim_handle *hdl, uint64_t len)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    int nextfs_fd = 0;

    client = nextfs_hdl_get_client(hdl);
    buf = client->buf;
    nextfs_fd = NEXTFS_HDL_GET_FD(hdl);

    debug("> nextfs_truncate(len=%lu)\n", len);

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, nextfs_fd);
    rho_buf_writeu64be(buf, len);

    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_FILE_TRUNCATE, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
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
    debug("< nextfs_truncate returns %d\n", error);
    return (error);
}

static int
nextfs_hstat(struct shim_handle *hdl, struct stat *stat)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };
    uint32_t deletion_time = 0;
    uint32_t flags = 0;

    client = nextfs_hdl_get_client(hdl);
    buf = client->buf;

    debug("> nextfs_hstat(hdl=*, stat=*)\n");

    rho_shim_dentry_print(hdl->dentry);
    debug("hstat: hdl->path: %s\n", qstrgetstr(&hdl->path));
    debug("hstat: hdl->uri: %s\n", qstrgetstr(&hdl->uri));

    /* get path */
    rho_shim_dentry_relpath(hdl->dentry, path, sizeof(path));

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, path);

    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_RAW_INODE, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    /* fill in stat buf */
    /* TODO: fill in st_dev */
    rho_memzero(stat, sizeof(*stat));
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_ino);   /* XXX is unsigned long */
    rho_buf_readu16be(buf, (uint16_t *)&stat->st_mode);  /* XXX is unsigned int */
    rho_buf_readu16be(buf, (uint16_t *)&stat->st_uid);   /* XXX is unsigned int */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_size);  /* XXX is long int */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_atime); /* XXX is unsigned long */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_ctime); /* XXX is unsigned long */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_mtime); /* XXX is unsigned long */

    rho_buf_readu32be(buf, &deletion_time);

    rho_buf_readu16be(buf, (uint16_t *)&stat->st_gid);   /* XXX is unsinged int */
    rho_buf_readu16be(buf, (uint16_t *)&stat->st_nlink); /* XXX is unsigned long */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_blocks);/* XXX is long int */

    rho_buf_readu32be(buf, &flags);

    /* XXX: st_dev can probably be anything, as long as it's unique */
    stat->st_dev = 0x1234;
    /* XXX: check with lwext4; 1024 seems like a reasonable guess, though */
    stat->st_blksize = 1024;

    debug("st_size=%ld\n", stat->st_size);

done:
    rho_buf_clear(buf);
    debug("< nextfs_hstat (error=%d)\n", error);
    return (error);
}

/* POSTPONE: */
static int
nextfs_setflags(struct shim_handle *hdl, int flags)
{
    debug("> nextfs_setflags\n");

    (void)hdl;
    (void)flags;

    debug("< nextfs_setflags\n");
    return (0);
}

static int
nextfs_advlock(struct shim_handle *hdl, int op, struct flock *flock)
{
    debug("> nextfs_advlock(op=%d)\n", op);
    (void)hdl; (void)flock;
    debug("< nextfs_advlock\n");
    return (-ENOSYS);
}

/* POSTPONE: */
static void
nextfs_hput(struct shim_handle *hdl)
{
    debug("> nextfs_hput\n");
    (void)hdl;
    debug("< nextfs_hput\n");
    return;
}

/* POSTPONE: */
static int
nextfs_lock(const char *trim_name)
{
    debug("> nextfs_lock\n");
    (void)trim_name;
    debug("< nextfs_lock\n");
    return (0);
}

/* POSTPONE: */
static int
nextfs_unlock(const char *trim_name)
{
    debug("> nextfs_unlock\n");
    (void)trim_name;
    debug("< nextfs_unlock\n");
    return (0);
}

/* POSTPONE: */
static int
nextfs_lockfs(void)
{
    debug("> nextfs_lockfs\n");
    debug("< nextfs_lockfs\n");
    return (0);
}

/* POSTPONE: */
static int
nextfs_unlockfs(void)
{
    debug("> nextfs_lockfs\n");
    debug("< nextfs_lockfs\n");
    return (0);
}

/* POSTPONE: NEED */
static int
nextfs_checkout(struct shim_handle *hdl)
{
    debug("> nextfs_checkout\n");
    debug("checkout hdl = {path:%s}\n", qstrgetstr(&hdl->path));
    hdl->fs = NULL;
    debug("< nextfs_checkout\n");
    return (0);
}

/* POSTPONE: */
static int
nextfs_checkin(struct shim_handle *hdl)
{
    struct nextfs_mdata *mdata = NULL;
    debug("> nextfs_checkin\n");
    debug("checkin hdl = {path:%s, fs=%p}\n",
            qstrgetstr(&hdl->path), hdl->fs);

    if (hdl->fs != NULL && hdl->fs->data != NULL) {
        mdata = hdl->fs->data;
        nextfs_mdata_print(mdata);
    }

    debug("< nextfs_checkin\n");
    return (0);
}

/* POSTPONE: */
static int
nextfs_poll(struct shim_handle *hdl, int poll_type)
{
    debug("> nextfs_poll\n");
    (void)hdl;
    (void)poll_type;
    debug("< nextfs_poll\n");
    return (0);
}

/* POSTPONE: NEED */
static int
nextfs_checkpoint(void **checkpoint, void *mount_data)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_mdata *mdata = mount_data;
    struct nextfs_client *client = mdata->client;;
    struct rho_buf *buf = client->buf;
    uint64_t ident = 0;

    debug("> nextfs_checkpoint\n");

    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_FORK, 0);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
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

    debug("nextfs child ident = %llu\n", (unsigned long long)ident);

    mdata = mount_data;
    mdata->ident = ident;
    *checkpoint = mdata;

done:
    rho_buf_clear(buf);
    debug("< nextfs_checkpoint\n");
    return (sizeof(struct nextfs_mdata));
}

/* 
 * POSTPONE: NEED
 *
 * Not clear to be the memory management for this function:
 * should the parent's client be free'd.  Should hte
 * old mdata be free'd?
 *
 * I think this function must return 0 on success.
 */
static int
nextfs_migrate(void *checkpoint, void **mount_data)
{
    int error = 0;
    struct nextfs_mdata *mdata = NULL;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    uint32_t status = 0;
    uint32_t bodylen = 0;

    debug("> nextfs_migrate\n");

    mdata = rhoL_zalloc(sizeof(struct nextfs_mdata));
    memcpy(mdata, checkpoint, sizeof(struct nextfs_mdata));
    mdata->debug_cookie = rho_rand_u32();
    nextfs_mdata_print(mdata);

    client = nextfs_client_open(mdata->url, 
            mdata->ca_der[0] == 0x00 ? NULL : mdata->ca_der,
            mdata->ca_der_len);

    debug("nextfs migrate: client=%p, mdata=%p\n", client, mdata);

    mdata->client = client;
    buf = client->buf;

    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu64be(buf, mdata->ident);
    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_CHILD_ATTACH, bodylen);
    error = nextfs_client_request(client, &status, &bodylen);
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
    debug("< nextfs_migrate\n");
    return (0);
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/
static int
nextfs_opendir(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    uint32_t fd = 0;
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    client = nextfs_dentry_get_client(dent);
    buf = client->buf;

    debug("> nextfs_opendir\n");

    (void)flags;

    /* get path */
    rho_shim_dentry_relpath(dent, path, sizeof(path));
    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, path);
    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_DIR_OPEN, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
    debug("nextfs_client_request returned %d\n", error);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    rho_buf_readu32be(buf, &fd);

    debug("nextfs_opendir returned fd=%lu\n", (unsigned long)fd);

    /* fill in handle */
    hdl->info.nextfs.fd = fd;
    hdl->type = TYPE_NEXTFS;
    hdl->flags = flags;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);

done:
    rho_buf_clear(buf);
    debug("< nextfs_opendir\n");
    return (error);
}

static int
nextfs_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    uint32_t fd = 0;
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    client = nextfs_dentry_get_client(dent);
    buf = client->buf;

    debug("> nextfs_open(hdl=(%p), dent=(%p), flags=0x%08x\n", hdl, dent, flags);
    rho_shim_dentry_print(dent);

    /* XXX: probably also want to make sure that O_RDONLY is specified */
    if (flags & O_DIRECTORY) {
        error = nextfs_opendir(hdl, dent, flags);
        goto done;
    }

    /* get path */
    rho_shim_dentry_relpath(dent, path, sizeof(path));

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, path);
    rho_buf_writeu32be(buf, flags);
    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_FILE_OPEN2, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
    debug("nextfs_client_request returned %d\n", error);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    rho_buf_readu32be(buf, &fd);

    debug("nextfs_open returned fd=%lu\n", (unsigned long)fd);

    /* fill in handle */
    hdl->info.nextfs.fd = fd;
    hdl->type = TYPE_NEXTFS;
    hdl->flags = flags;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);

done:
    rho_buf_clear(buf);
    debug("< nextfs_open\n");
    return (error);
}

/* POSTPONE: */
static int
nextfs_lookup(struct shim_dentry *dent, bool force)
{
    int error = 0;
    struct stat sb;

    debug("> nextfs_lookup(dent=*, force=%d)\n", force);
    rho_shim_dentry_print(dent);

    if (qstrempty(&dent->rel_path)) {
        dent->state |= DENTRY_ISDIRECTORY;
        goto done;
    }

    rho_memzero(&sb, sizeof(struct stat));
    error = nextfs_stat(dent, &sb);
    if (error != 0)
        goto done;

    dent->ino = sb.st_ino;

    if (S_ISDIR(sb.st_mode))
        dent->state |= DENTRY_ISDIRECTORY;
    else if (S_ISLNK(sb.st_mode))
        dent->state |= DENTRY_ISLINK;

done:
    debug("< nextfs_lookup\n");
    return (error);
}

static int 
nextfs_mode(struct shim_dentry *dent, mode_t *mode, bool force)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    client = nextfs_dentry_get_client(dent);
    buf = client->buf;

    debug("> nextfs_mode(dent=*, mode=*, force=%d\n", force);
    rho_shim_dentry_print(dent);

    /* get path */
    rho_shim_dentry_relpath(dent, path, sizeof(path));
    debug("relpath=%s\n", path);

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, path);
    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_MODE_GET, bodylen);

    /* make request */
    nextfs_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    rho_buf_readu32be(buf, mode);
    
done:
    rho_buf_clear(buf);
    debug("< nextfs_mode (error=%d, mode=%08x)\n", error, mode);
    return (error);
}

/* POSTPONE: */
static int 
nextfs_dput(struct shim_dentry *dent)
{
    debug("> nextfs_dput\n");
    (void)dent;
    debug("< nextfs_dput\n");
    return (0);
}

/* TODO: */
static int
nextfs_creat(struct shim_handle *hdl, struct shim_dentry *dir,
        struct shim_dentry *dent, int flags, mode_t mode)
{
    int error = 0;

    debug("> nextfs_creat\n");

    debug("> nextfs_creat print dir\n");
    rho_shim_dentry_print(dir);

    debug("> nextfs_creat print dent\n");
    rho_shim_dentry_print(dent);

    /* 
     * TODO: perhaps change the open RPC to also
     * take a mode argument.
     *
     * TODO: are we suppose to change anything in dir?
     */

    error = nextfs_open(hdl, dent, flags);
    if (error != 0)
        goto done;
    
    error = nextfs_chmod(dent, mode);

    /*
     * TODO: deal with an error from chmod by
     * closing the handle.
     */

done:
    debug("< nextfs_creat returning %d\n", error);
    return (error);
}

static int
nextfs_unlink(struct shim_dentry *dir, struct shim_dentry *dent)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    client = nextfs_dentry_get_client(dent);
    buf = client->buf;

    debug("> nextfs_unlink(dir=*, dent=*)\n");
    rho_shim_dentry_print(dir);
    rho_shim_dentry_print(dent);

    /* get path */
    rho_shim_dentry_relpath(dent, path, sizeof(path));

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, path);
    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_FILE_REMOVE, bodylen);

    /* make request */
    nextfs_client_request(client, &status, &bodylen);
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
    debug("< nextfs_unlink\n");
    return (error);
}

static int
nextfs_mkdir(struct shim_dentry *dir, struct shim_dentry *dent, mode_t mode)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    client = nextfs_dentry_get_client(dent);
    buf = client->buf;

    debug("> nextfs_mkdir\n");

    /* get path */
    rho_shim_dentry_relpath(dent, path, sizeof(path));

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, path);
    rho_buf_writeu32be(buf, mode);

    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_DIR_MK, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
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
    debug("< nextfs_mkdir\n");
    return (error);
}

static int
nextfs_stat(struct shim_dentry *dent, struct stat *stat)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };
    uint32_t deletion_time = 0;
    uint32_t flags = 0;

    client = nextfs_dentry_get_client(dent);
    buf = client->buf;

    debug("> nextfs_stat\n");

    /* get path */
    rho_shim_dentry_relpath(dent, path, sizeof(path));

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, path);

    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_RAW_INODE, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    /* fill in stat buf */
    rho_memzero(stat, sizeof(*stat));
    /* TODO: need to fill in st_dev */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_ino);   /* XXX is unsigned long */
    rho_buf_readu16be(buf, (uint16_t *)&stat->st_mode);  /* XXX is unsigned int */
    rho_buf_readu16be(buf, (uint16_t *)&stat->st_uid);   /* XXX is unsigned int */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_size);  /* XXX is long int */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_atime); /* XXX is unsigned long */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_ctime); /* XXX is unsigned long */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_mtime); /* XXX is unsigned long */

    rho_buf_readu32be(buf, &deletion_time);

    rho_buf_readu16be(buf, (uint16_t *)&stat->st_gid);   /* XXX is unsinged int */
    rho_buf_readu16be(buf, (uint16_t *)&stat->st_nlink); /* XXX is unsigned long */
    rho_buf_readu32be(buf, (uint32_t *)&stat->st_blocks);/* XXX is long int */

    rho_buf_readu32be(buf, &flags);

    /* XXX: st_dev can probably be anything, as long as it's unique */
    stat->st_dev = 0x1234;
    /* XXX: check with lwext4; 1024 seems like a reasonable guess, though */
    stat->st_blksize = 1024;

    debug("st_size=%ld\n", stat->st_size);

done:
    rho_buf_clear(buf);
    debug("< nextfs_stat\n");
    return (error);
}

/* TODO:  (are these hardlinks or softlinks? */
static int
nextfs_follow_link(struct shim_dentry *dent, struct shim_qstr *link)
{
    debug("> nextfs_follow_link\n");
    (void)dent;
    (void)link;
    debug("< nextfs_follow_link\n");
    return (0);
}

/* TODO: (are these hard links or softlinks? */
static int
nextfs_set_link(struct shim_dentry *dent, const char *link)
{
    debug("> nextfs_set_link\n");
    (void)dent;
    (void)link;
    debug("< nextfs_set_link\n");
    return (0);
}

static int
nextfs_chmod(struct shim_dentry *dent, mode_t mode)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    client = nextfs_dentry_get_client(dent);
    buf = client->buf;

    debug("> nextfs_chmod\n");

    /* get path */
    rho_shim_dentry_relpath(dent, path, sizeof(path));

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, path);
    rho_buf_writeu32be(buf, mode);

    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_MODE_SET, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
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
    debug("< nextfs_chmod\n");
    return (error);
}

static int
nextfs_chown(struct shim_dentry *dent, int uid, int gid)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    client = nextfs_dentry_get_client(dent);
    buf = client->buf;

    debug("> nextfs_chown\n");

    /* get path */
    rho_shim_dentry_relpath(dent, path, sizeof(path));

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, path);
    rho_buf_writeu32be(buf, uid);
    rho_buf_writeu32be(buf, gid);

    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_OWNER_SET, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
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
    debug("< nextfs_chown\n");
    return (error);
} 

static int
nextfs_rename(struct shim_dentry *old, struct shim_dentry *new)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    char oldpath[NEXTFS_MAX_PATH_LENGTH] = { 0 };
    char newpath[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    client = nextfs_dentry_get_client(old);
    buf = client->buf;

    debug("> nextfs_rename\n");

    /* get paths */
    rho_shim_dentry_relpath(old, oldpath, sizeof(oldpath));
    rho_shim_dentry_relpath(new, newpath, sizeof(newpath));

    /* build request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    nextfs_marshal_str(buf, oldpath);
    nextfs_marshal_str(buf, newpath);

    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_FILE_RENAME, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto done;
    }

    if (status != 0) {
        error = -status;
        goto done;
    }

    /* 
     * update old dentry name
     * TODO: I'm shaky on graphene's management of handles;
     * I'm assuming if the application has an fd open to the old dentry,
     * that that fd points to this handle.
     *
     * rel_path and name are a struct shim_qstr
     *
     * Do we need to update old->parent or any other fields?
     */
    qstrcopy(&old->rel_path, &new->rel_path);
    qstrcopy(&old->name, &new->name);

done:
    rho_buf_clear(buf);
    debug("< nextfs_rename\n");
    return (error);
}

/* 
 * Based on chroot-fs's implementation, as well as on the implementation
 * of the getdents syscall, this function is suppose to list 
 * the entire directory, rather than just return 'the next' entry
 * in the directory.
 *
 * This function is a bit odd in that operates on a shim_dentry (aka a
 * pathname) rather than a shim_handle (aka, a file descriptor).  You can go
 * from handle to entry, but not viceversa.  We could correct this upstram in
 * the call stack, but for now, we're just going to be inefficient and have
 * this function
 *
 *  - open the directory
 *  - list the directory
 *  - close the directory
 * 
 * Eventually, we'll have to fix the upstream callstack.  For instance, the
 * sham_namei.c::list_directory_handle function (which, by the way, doesn't
 * operates on shim_dentry, not a shim_handle /eyeroll) sets a flag in the
 * shim_dentry *dent, which says that the directory has already been listed and
 * it's contents are cached.  This behavior is fine for the chroot filesystem,
 * which is read-only, but not for us.
 */
static int
nextfs_readdir(struct shim_dentry *dent, struct shim_dirent **dirent)
{
    int error = 0;
    uint32_t bodylen = 0;
    uint32_t status = 0;
    struct nextfs_client *client = NULL;
    struct rho_buf *buf = NULL;
    struct shim_handle hdl;
    uint32_t nextfs_fd =-1;
    struct shim_dirent *array = NULL;
    struct shim_dirent *pd = NULL;
    uint32_t namelen = 0;
    uint32_t i = 0;
    uint32_t n = 0;

    client = nextfs_dentry_get_client(dent);
    buf = client->buf;

    debug("> nextfs_readdir\n");

    /* open directory */
    memset(&hdl, 0x00, sizeof(struct shim_handle));
    error = nextfs_opendir(&hdl, dent, O_DIRECTORY);
    if (error != 0)
        goto fail;

    nextfs_fd = hdl.info.nextfs.fd;

    /* build dir_list request */
    rho_buf_seek(buf, NEXTFS_HEADER_LENGTH, SEEK_SET); 
    rho_buf_writeu32be(buf, nextfs_fd);
    bodylen = rho_buf_length(buf) - NEXTFS_HEADER_LENGTH;
    rho_buf_rewind(buf);
    nextfs_pmarshal_hdr(buf, NEXTFS_OP_DIR_LIST, bodylen);

    /* make request */
    error = nextfs_client_request(client, &status, &bodylen);
    if (error != 0) {
        error = -ERPC;
        goto fail;
    }

    if (status != 0) {
        error = -status;
        goto fail;
    }

    /* 
     * The RPC response is an array, where each entry is:
     * First is a u32 of the number of entries.  Then, each entry:
     *
     * {u32 inode, u8 inode_type, u32 name length, name[255] (null terminated)}
     *
     * The current implementation is simple but fairly wasteful:
     *  1. each pathname occupies 255 bytes
     *  2. we double copy between the representation of the array in 
     *     RPC response and the "return value" represenation.
     */

    error = rho_buf_readu32be(buf, &n);
    if (error == -1) {
        error = -ERPC;
        goto fail;
    }

    debug("received %lu direntries\n", (unsigned long)n);

    array = rhoL_mallocarray(n, (sizeof(struct shim_dirent) + 255), RHO_MEM_ZERO);

    for (i = 0; i < n; i++) {
        /* 
         * XXX: flexible array members (aka, last member of struct is
         * a zero-length array) are evil 
         */
        pd = (struct shim_dirent *)
            (((uint8_t *)array) + (i * (sizeof(struct shim_dirent) + 255)));

        /* XXX: &pd->ino is unsigned long */
        error = rho_buf_readu32be(buf, (uint32_t *)(&pd->ino));
        if (error == -1) {
            error = -ERPC;
            goto fail;
        }

        error = rho_buf_readu8(buf, &pd->type);
        if (error == -1) {
            error = -ERPC;
            goto fail;
        }

        /* convert types from lwext4 to graphene */
        switch (pd->type) {
        case 0: /* EXT4_DE_UNKNOWN */
            pd->type = LINUX_DT_UNKNOWN;
            break;
        case 1: /* EXT4_DE_REG_FILE */
            pd->type = LINUX_DT_REG;
            break;
        case 2: /* EXT4_DE_DIR */
            pd->type = LINUX_DT_DIR;
            break;
        case 3: /* EXT4_DE_CHRDEV */
            pd->type = LINUX_DT_CHR;
            break;
        case 4: /* EXT4_DE_BLKDEV */
            pd->type = LINUX_DT_BLK;
            break;
        case 5: /* EXT4_DE_FIFO */
            pd->type = LINUX_DT_FIFO;
            break;
        case 6: /* EXT4_DE_SOCK */
            pd->type = LINUX_DT_SOCK;
            break;
        case 7: /* EXT4_DE_SYMLINK */
            pd->type = LINUX_DT_LNK;
            break;
        default:
            pd->type = LINUX_DT_UNKNOWN;
        }

        error = rho_buf_readu32be(buf, &namelen);
        if (error == -1) {
            error = -ERPC;
            goto fail;
        }

        error = rho_buf_read(buf, pd->name, 255);
        if (error == -1) {
            error = -ERPC;
            goto fail;
        }

        debug("direntry: ino:%lu, name:\"%s\", type:%d\n",
                (unsigned long)pd->ino, pd->name, pd->type);

        if ((i + 1) < n) {
            pd->next = (struct shim_dirent *)
                (((uint8_t *)array) + ((i+1) * (sizeof(struct shim_dirent) + 255)));
        } else {
            pd->next = NULL;
        }
    }

    *dirent = array;
    error = 0;
    goto succeed;

fail:
    if (array != NULL)
        rhoL_free(array);
succeed:
    if (((int)nextfs_fd) != -1)
        nextfs_close(&hdl);

    rho_buf_clear(buf);
    debug("< nextfs_readdir\n");
    return (error);
}

struct shim_fs_ops nextfs_fs_ops = {
        .mount       = &nextfs_mount,      /**/
        .unmount     = &nextfs_unmount,    /**/
        .close       = &nextfs_close,      /**/
        .read        = &nextfs_read,       /**/
        .write       = &nextfs_write,      /**/
        //.mmap        = &nextfs_mmap,       /**/
        .flush       = &nextfs_flush,      /**/
        .seek        = &nextfs_seek,       /**/
        .move        = &nextfs_move,
        .copy        = &nextfs_copy,
        .truncate    = &nextfs_truncate,   /**/
        .hstat       = &nextfs_hstat,      /**/
        .setflags    = &nextfs_setflags,
        .hput        = &nextfs_hput,
        .advlock     = &nextfs_advlock,
        .lock        = &nextfs_lock,
        .unlock      = &nextfs_unlock,
        .lockfs      = &nextfs_lockfs,
        .unlockfs    = &nextfs_unlockfs,
        .checkout    = &nextfs_checkout,   /**/
        .checkin     = &nextfs_checkin,
        .poll        = &nextfs_poll,       /**/
        .checkpoint  = &nextfs_checkpoint, /**/
        .migrate     = &nextfs_migrate,    /**/
    };

struct shim_d_ops nextfs_d_ops = {
        .open       = &nextfs_open,        /**/
        .lookup     = &nextfs_lookup,      /**/
        .mode       = &nextfs_mode,        /**/
        .dput       = &nextfs_dput,        /**/
        .creat      = &nextfs_creat,       /**/
        .unlink     = &nextfs_unlink,      /**/
        .mkdir      = &nextfs_mkdir,       /**/
        .stat       = &nextfs_stat,        /**/
        .follow_link = &nextfs_follow_link,
        .set_link = &nextfs_set_link,
        .chmod      = &nextfs_chmod,       /**/
        .chown      = &nextfs_chown,       /**/
        .rename     = &nextfs_rename,      /**/
        .readdir    = &nextfs_readdir,     /**/
    };

#if 0
struct mount_data nextfs_data = { .root_uri_len = 5,
                                  .root_uri = "file:", };

struct shim_mount nextfs_builtin_fs = { .type   = "nextfs",
                                        .fs_ops = &nextfs_fs_ops,
                                        .d_ops  = &nextfs_d_ops,
                                        .data   = &nextfs_data, };
#endif
