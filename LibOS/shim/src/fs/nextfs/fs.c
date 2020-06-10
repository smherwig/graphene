/*
 * fs.c
 *
 * The 'nextfs' filesystem.
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

#include <string.h>

#include "rho_binascii.h"
#include "rho_buf.h"
#define RHO_LOG_PREFIX "NEXTFS"
#include "rho_log.h"
#include "rho_mem.h"
#include "rho_rand.h"
#include "rho_shim_dentry.h"
#include "rho_shim_handle.h"
#include "rho_sock.h"
#include "rho_ssl.h"

#include "rpc.h"


#define NEXTFS_HEADER_LENGTH            8
#define NEXTFS_MAX_PATH_LENGTH          255

#define NEXTFS_OP_FILE_REMOVE           5
#define NEXTFS_OP_FILE_RENAME           7
#define NEXTFS_OP_FILE_OPEN2            9
#define NEXTFS_OP_FILE_CLOSE            10
#define NEXTFS_OP_FILE_TRUNCATE         11
#define NEXTFS_OP_FILE_READ             12
#define NEXTFS_OP_FILE_WRITE            13
#define NEXTFS_OP_FILE_SEEK             14

#define NEXTFS_OP_DIR_RM                17
#define NEXTFS_OP_DIR_MK                19
#define NEXTFS_OP_DIR_OPEN              21
#define NEXTFS_OP_DIR_CLOSE             22
#define NEXTFS_OP_DIR_LIST              25

#define NEXTFS_OP_RAW_INODE             29
#define NEXTFS_OP_MODE_SET              30
#define NEXTFS_OP_MODE_GET              31
#define NEXTFS_OP_OWNER_SET             32

#define NEXTFS_OP_FORK                  40
#define NEXTFS_OP_CHILD_ATTACH          41
#define NEXTFS_OP_NEW_FDTABLE           42

#define NEXTFS_OP_FILE_MMAP             43

struct nextfs_mdata {
    char    url[512];       /* URL for server */
    uint64_t ident;     /* auth cookie for child */
    unsigned char ca_der[4096];
    size_t  ca_der_len;
    struct rpc_agent *agent;
    uint32_t debug_cookie;
};

/********************************* 
 * RETRIEVE DATA FROM HDL/DENTRY
 *********************************/
#define NEXTFS_HDL_GET_MDATA(hdl) \
    (hdl)->fs->data

#define NEXTFS_HDL_GET_AGENT(hdl) \
    (hdl)->fs->data->agent

#define NEXTFS_HDL_GET_FD(hdl) \
    (hdl)->info.nextfs.fd

struct rpc_agent *
nextfs_hdl_get_agent(struct shim_handle *hdl)
{
    struct shim_mount *fs = NULL;
    struct nextfs_mdata *mdata = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER(); 
    rho_shim_handle_print(hdl);

    fs = hdl->fs;
    if (fs == NULL) {
        debug("nextfs_hdl_get_agent: hdl->fs is NULL");
    } else {
        RHO_ASSERT(hdl->dentry != NULL);
        rho_shim_dentry_print(hdl->dentry);
        fs = hdl->dentry->fs;
    }
    RHO_ASSERT(fs != NULL);
    
    mdata = fs->data;
    RHO_ASSERT(mdata != NULL);

    agent = mdata->agent;
    RHO_ASSERT(agent != NULL);

    RHO_TRACE_EXIT("return: agent=%p", agent);
    return (agent);
}

struct rpc_agent *
nextfs_dentry_get_agent(struct shim_dentry *dentry)
{
    struct shim_mount *fs = NULL;
    struct nextfs_mdata *mdata = NULL;
    struct rpc_agent *agent = NULL;

    fs = dentry->fs;
    RHO_ASSERT(fs != NULL);
    
    mdata = fs->data;
    RHO_ASSERT(mdata != NULL);

    agent = mdata->agent;
    RHO_ASSERT(agent != NULL);

    //debug("nextfs_mdata debug_cookie=%u\n", mdata->debug_cookie);
    return (agent);
}

/********************************* 
 * MOUNT DATA
 *********************************/
static struct nextfs_mdata *
nextfs_mdata_create(const char *uri, unsigned char *ca_der,
        size_t ca_der_len)
{
    struct nextfs_mdata *mdata = NULL;
    
    RHO_TRACE_ENTER("uri=\"%s\", ca_cer_len=%lu", uri, ca_der_len);

    mdata = rhoL_zalloc(sizeof(struct nextfs_mdata));
    memcpy(mdata->url, uri, strlen(uri));
    if (ca_der != NULL) {
        memcpy(mdata->ca_der, ca_der, ca_der_len);
        mdata->ca_der_len = ca_der_len;
    }

    mdata->debug_cookie = rho_rand_u32();

    RHO_TRACE_EXIT("return: mdata=%p", mdata);
    return (mdata);
}

static void
nextfs_mdata_print(const struct nextfs_mdata *mdata)
{
    rho_debug("nextfs_mdata = {url: %s, ident:%llu, debug_cookie:%lu}\n",
            mdata->url, (unsigned long long)mdata->ident,
            (unsigned long)mdata->debug_cookie);
}

/**********************************************************
 * RPC AGENT
 **********************************************************/

static struct rpc_agent *
nextfs_agent_open(const char *url, unsigned char *ca_der, size_t ca_der_len)
{
    struct rpc_agent *agent = NULL;
    struct rho_sock *sock = NULL;
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *ctx = NULL;

    RHO_TRACE_ENTER("url=\"%s\", ca_der_len=%lu", url, ca_der_len);

    sock = rho_sock_open_url(url);
    if (sock == NULL) {
        rho_warn("failed to connect to nextfs server at \"%s\"", url);
        goto done;
    }

    if (ca_der != NULL) {
        rho_debug("nextfs client using TLS\n");
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
    RHO_TRACE_EXIT("return: agent=%p", agent);
    return (agent);
}

#if 0
static void
nextfs_client_close(struct nextfs_client *client)
{
    RHO_TRACE_ENTER();

    rho_sock_destroy(client->sock);
    rho_buf_destroy(client->buf);
    rhoL_free(client);

    RHO_TRACE_EXIT();
}
#endif

/**********************************************************
 * RPC HELPERS
 **********************************************************/

static void
nextfs_marshal_str(struct rho_buf *buf, const char *s)
{
    size_t len = strlen(s);
    rho_buf_writeu32be(buf, len);
    rho_buf_puts(buf, s);
}

/**********************************************************
 * RPCs
 *
 * These functions return 0 on success; a negative errno
 * on failure.
 *
 * - rpc_agent_request rurns 0 on success, -errno on failure.
 * - rho_buf_readINT return 0 on success, -1 on failure.
 **********************************************************/

static int
nextfs_new_fdtable_rpc(struct rpc_agent *agent)
{
    int error = 0;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, NEXTFS_OP_NEW_FDTABLE);
    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_fork_rpc(struct rpc_agent *agent, uint64_t *child_ident)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, NEXTFS_OP_FORK);
    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu64be(buf, child_ident);
	if (error != 0) {
		error = -EPROTO;
        goto done;
    }

    rho_debug("child_ident=0x%lx", *child_ident);

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_child_attach_rpc(struct rpc_agent *agent, uint64_t child_ident)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("child_ident=0x%lx", child_ident);

    rpc_agent_new_msg(agent, NEXTFS_OP_CHILD_ATTACH);
    rho_buf_writeu64be(buf, child_ident);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_file_close_rpc(struct rpc_agent *agent, uint32_t nextfs_fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("nextfs_fd=%u", nextfs_fd);

    rpc_agent_new_msg(agent, NEXTFS_OP_FILE_CLOSE);
    rho_buf_writeu32be(buf, nextfs_fd);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_file_read_rpc(struct rpc_agent *agent, uint32_t nextfs_fd,
        void *data, size_t count, size_t *rcnt)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t bodylen = 0;

    RHO_TRACE_ENTER("nextfs_fd=%u, count=%lu", nextfs_fd, count);

    rpc_agent_new_msg(agent, NEXTFS_OP_FILE_READ);
    rho_buf_writeu32be(buf, nextfs_fd);
    rho_buf_writeu32be(buf, count); /* FIXME: either cast or make u64 */
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    bodylen = rpc_agent_get_bodylen(agent);
    memcpy(data, rho_buf_raw(buf, 0, SEEK_SET), bodylen); 
    *rcnt = bodylen;

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_file_write_rpc(struct rpc_agent *agent, uint32_t nextfs_fd,
        const void *data, uint32_t count, uint32_t *wcnt)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("nextfs_fd=%u, count=%u", nextfs_fd, count);

    rpc_agent_new_msg(agent, NEXTFS_OP_FILE_WRITE);
    rho_buf_writeu32be(buf, nextfs_fd);
    rho_buf_writeu32be(buf, count); /* FIXME: either cast or make u64 */
    rho_buf_write(buf, data, count);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu32be(buf, (uint32_t *)wcnt);
    if (error != 0) {
        error = -EPROTO;
        goto done;
    }

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_file_mmap_rpc(struct rpc_agent *agent, uint32_t nextfs_fd, size_t size,
        off_t offset)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("nextfs_fd=%ud, size=%lu, offset=%ld",
            nextfs_fd, size, offset);

    rpc_agent_new_msg(agent, NEXTFS_OP_FILE_MMAP);
    rho_buf_writeu32be(buf, nextfs_fd);
    rho_buf_writeu32be(buf, size);
    rho_buf_writeu32be(buf, offset);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_file_seek_rpc(struct rpc_agent *agent, uint32_t nextfs_fd,
        off_t offset, int whence, off_t *new_offset)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("nextfs_fd=%u, offset=%ld, whence=%d",
            nextfs_fd, offset, whence);

    rpc_agent_new_msg(agent, NEXTFS_OP_FILE_SEEK);
    rho_buf_writeu32be(buf, nextfs_fd);
    rho_buf_write64be(buf, offset);
    rho_buf_writeu32be(buf, whence);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu64be(buf, (uint64_t*)new_offset);
    if (error != 0) {
        error = -EPROTO;
        goto done;
    }

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_file_truncate_rpc(struct rpc_agent *agent, uint32_t nextfs_fd,
        off_t len)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_EXIT("nextfs_fd=%u, len=%ld", nextfs_fd, len);

    rpc_agent_new_msg(agent, NEXTFS_OP_FILE_TRUNCATE);
    rho_buf_writeu32be(buf, nextfs_fd);
    rho_buf_writeu64be(buf, len);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_file_open2_rpc(struct rpc_agent *agent, const char *path, int flags,
        uint32_t *nextfs_fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("path=\"%s\" flags=0x%x", path, flags);

    rpc_agent_new_msg(agent, NEXTFS_OP_FILE_OPEN2);
    nextfs_marshal_str(buf, path);
    rho_buf_writeu32be(buf, flags);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0) {
        goto done;
    }

    error = rho_buf_readu32be(buf, nextfs_fd);
    if (error == -1) {
        error = -EPROTO;
        goto done;
    }

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_dir_open_rpc(struct rpc_agent *agent, const char *path,
        uint32_t *nextfs_fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("path=\"%s\"", path);

    rpc_agent_new_msg(agent, NEXTFS_OP_DIR_OPEN);
    nextfs_marshal_str(buf, path);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0) {
        goto done;
    }

    error = rho_buf_readu32be(buf, nextfs_fd);
    if (error != 0) {
        error = -EPROTO;
        goto done;
    }

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_dir_close_rpc(struct rpc_agent *agent, uint32_t nextfs_fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("nextfs_fd=%u", nextfs_fd);

    rpc_agent_new_msg(agent, NEXTFS_OP_DIR_CLOSE);
    rho_buf_writeu32be(buf, nextfs_fd);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_dir_rm_rpc(struct rpc_agent *agent, const char *path)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("path=\"%s\"", path);

    rpc_agent_new_msg(agent, NEXTFS_OP_DIR_RM);
    nextfs_marshal_str(buf, path);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static unsigned char
nextfs_lwext4_dirent_type_to_linux(unsigned char d_type)
{
    switch (d_type) {
    case 0: /* EXT4_DE_UNKNOWN */
        return LINUX_DT_UNKNOWN;
    case 1: /* EXT4_DE_REG_FILE */
        return LINUX_DT_REG;
    case 2: /* EXT4_DE_DIR */
        return LINUX_DT_DIR;
    case 3: /* EXT4_DE_CHRDEV */
        return LINUX_DT_CHR;
    case 4: /* EXT4_DE_BLKDEV */
        return LINUX_DT_BLK;
    case 5: /* EXT4_DE_FIFO */
        return LINUX_DT_FIFO;
    case 6: /* EXT4_DE_SOCK */
        return LINUX_DT_SOCK;
    case 7: /* EXT4_DE_SYMLINK */
        return LINUX_DT_LNK;
    default:
        return LINUX_DT_UNKNOWN;
    }
}

static int
nextfs_dir_list_rpc(struct rpc_agent *agent, uint32_t nextfs_fd,
        struct shim_dirent **dirent)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t i = 0;
    uint32_t n = 0;
    struct shim_dirent *array = NULL;
    struct shim_dirent *pd = NULL;
    uint32_t namelen = 0;

    RHO_TRACE_ENTER("nextfs_fd=%u", nextfs_fd);

    rpc_agent_new_msg(agent, NEXTFS_OP_DIR_LIST);
    rho_buf_writeu32be(buf, nextfs_fd);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

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
    if (error != 0) {
        error = -EPROTO;
        goto done;
    }

    rho_debug("received %u direntries\n", n);

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
        if (error != 0) {
            error = -EPROTO;
            goto done;
        }

        error = rho_buf_readu8(buf, &pd->type);
        if (error != 0) {
            error = -EPROTO;
            goto done;
        }

        pd->type = nextfs_lwext4_dirent_type_to_linux(pd->type);

        error = rho_buf_readu32be(buf, &namelen);
        if (error != 0) {
            error = -EPROTO;
            goto done;
        }

        if (rho_buf_read(buf, pd->name, 255) != 255) {
            error = -EPROTO;
            goto done;
        }

        rho_debug("dirent: ino:%lu, name:\"%s\", type:%u\n",
                pd->ino, pd->name, pd->type);

        if ((i + 1) < n) {
            pd->next = (struct shim_dirent *)
                (((uint8_t *)array) + ((i+1) * (sizeof(struct shim_dirent) + 255)));
        } else {
            pd->next = NULL;
        }
    }

    *dirent = array;

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_mode_get_rpc(struct rpc_agent *agent, const char *path, mode_t *mode)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("path=\"%s\"", path);

    rpc_agent_new_msg(agent, NEXTFS_OP_MODE_GET);
    nextfs_marshal_str(buf, path);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu32be(buf, mode);
    if (error != 0) {
        error = -EPROTO;
        goto done;
    }

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_raw_inode_rpc(struct rpc_agent *agent, const char *path,
        struct stat *stat)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t deletion_time = 0;
    uint32_t flags = 0;

    RHO_TRACE_ENTER("path=\"%s\"", path);

    rpc_agent_new_msg(agent, NEXTFS_OP_RAW_INODE);
    nextfs_marshal_str(buf, path);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

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
    stat->st_blksize = 4096;

    rho_debug("st_size=%ld", stat->st_size);

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_file_remove_rpc(struct rpc_agent *agent, const char *path)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("path=\"%s\"", path);

    rpc_agent_new_msg(agent, NEXTFS_OP_FILE_REMOVE);
    nextfs_marshal_str(buf, path);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_dir_mk_rpc(struct rpc_agent *agent, const char *path, mode_t mode)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("path=\"%s\" mode=0x%x", path, mode);

    rpc_agent_new_msg(agent, NEXTFS_OP_DIR_MK);
    nextfs_marshal_str(buf, path);
    rho_buf_writeu32be(buf, mode);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_mode_set_rpc(struct rpc_agent *agent, const char *path, mode_t mode)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("path=\"%s\", mode=0x%x", path, mode);

    rpc_agent_new_msg(agent, NEXTFS_OP_MODE_SET);
    nextfs_marshal_str(buf, path);
    rho_buf_writeu32be(buf, mode);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_owner_set_rpc(struct rpc_agent *agent, const char *path, int uid,
        int gid)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("path=\"%s\", uid=%d, gid=%d", path, uid, gid);

    rpc_agent_new_msg(agent, NEXTFS_OP_OWNER_SET);
    nextfs_marshal_str(buf, path);
    rho_buf_writeu32be(buf, uid);
    rho_buf_writeu32be(buf, gid);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_file_rename_rpc(struct rpc_agent *agent, const char *old_path, 
        const char *new_path)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("old_path=\"%s\", new_path=\"%s\"", old_path, new_path);

    rpc_agent_new_msg(agent, NEXTFS_OP_FILE_RENAME);
    nextfs_marshal_str(buf, old_path);
    nextfs_marshal_str(buf, new_path);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

/********************************* 
 * FILE/FILESYSTEM OPERATIONS
 *********************************/

/*
 * Mount should allocated a struct nextfs_mountdata and return it
 * in the mount_data out parameter.
 *
 * uri is the host URI for the resource to be "mounted"
 */
static int
nextfs_mount(const char *uri, void **mount_data)
{
    int error = 0;
    char ca_hex[CONFIG_MAX] = { 0 };
    unsigned char *ca_der = NULL;
    ssize_t len = 0;
    struct nextfs_mdata *mdata = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER("uri=\"%s\"", uri);

    len = get_config(root_config, "phoenix.ca_der", ca_hex, sizeof(ca_hex));
    if (len > 0) {
        rho_debug("READ phoenix.ca_der (size=%ld)\n", len);
        ca_der = rhoL_malloc(len / 2);
        rho_binascii_hex2bin(ca_der, ca_hex);
    }

    agent = nextfs_agent_open(uri, ca_der, len / 2);
    if (agent == NULL) {
        /* FIXME: better errno; what's in PAL_ERRNO? */
        error = -ENXIO;
        goto fail;
    }

    error = nextfs_new_fdtable_rpc(agent);
    if (error != 0)
        goto fail;

    mdata = nextfs_mdata_create(uri, ca_der, len / 2);
    mdata->agent = agent;
    *mount_data = mdata;

    goto succeed;

fail:
    if (agent != NULL)
        rpc_agent_destroy(agent);

succeed:
    if (ca_der != NULL)
        rhoL_free(ca_der);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_close(struct shim_handle *hdl)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_hdl_get_agent(hdl);
    uint32_t nextfs_fd =  NEXTFS_HDL_GET_FD(hdl);

    RHO_TRACE_ENTER();
    rho_shim_handle_print(hdl);

    error = nextfs_file_close_rpc(agent, nextfs_fd);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static ssize_t
nextfs_read(struct shim_handle *hdl, void *data, size_t count)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_hdl_get_agent(hdl);
    uint32_t nextfs_fd =  NEXTFS_HDL_GET_FD(hdl);
    size_t rcnt = 0;

    RHO_TRACE_ENTER("count=%lu", count);
    rho_shim_handle_print(hdl);

    error = nextfs_file_read_rpc(agent, nextfs_fd, data, count, &rcnt);
    if (error == 0)
        error = (int)rcnt;

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static ssize_t
nextfs_write(struct shim_handle *hdl, const void *data, size_t count)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_hdl_get_agent(hdl);
    uint32_t nextfs_fd =  NEXTFS_HDL_GET_FD(hdl);
    uint32_t wcnt = 0;

    RHO_TRACE_ENTER("count=%lu", count);
    rho_shim_handle_print(hdl);

    /* FIXME: check if count exceeds a u32 */
    error = nextfs_file_write_rpc(agent, nextfs_fd, data, (uint32_t)count,
            &wcnt);
    if (error == 0)
        error = (int)wcnt;

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_hdl_get_agent(hdl);
    uint32_t nextfs_fd =  NEXTFS_HDL_GET_FD(hdl);
    /* XXX: was previously hardcoded to prot=PROT_READ|PROT_WRITE, flags=0; */
    int pal_prot = LINUX_PROT_TO_PAL(prot, flags);
    struct rho_buf *buf = NULL;
    uint32_t bodylen = 0;

    RHO_TRACE_ENTER("addr=%p, *addr=%p, size=%lu, prot=0x%x, flags=0x%x, offset=%ld",
            addr, *addr, size, prot, flags, offset);
    rho_shim_handle_print(hdl);

    error = nextfs_file_mmap_rpc(agent, nextfs_fd, size, offset);
    if (error != 0)
        goto done;

    bodylen = rpc_agent_get_bodylen(agent);
    /* XXX: make this a rho_bug call */
    if (bodylen > size) {
        error = -EPROTO;
        goto done;
    }

    *addr = DkVirtualMemoryAlloc(*addr, size, 0, pal_prot);
    if (*addr == NULL) {
        error = -ENOMEM;
        goto done;
    }

    memset(*addr, 0x00, size);
    /* copy result */
    memcpy(*addr, rho_buf_raw(buf, 0, SEEK_SET), bodylen); 

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static off_t
nextfs_seek(struct shim_handle *hdl, off_t offset, int whence)
{
    off_t ret = 0;
    int error = 0;
    struct rpc_agent *agent = nextfs_hdl_get_agent(hdl);
    uint32_t nextfs_fd =  NEXTFS_HDL_GET_FD(hdl);
    off_t new_offset = 0;

    RHO_TRACE_ENTER("offset=%ld, whence=%d", offset, whence);
    rho_shim_handle_print(hdl);

    error = nextfs_file_seek_rpc(agent, nextfs_fd, offset, whence, &new_offset);
    if (error == 0)
        ret = new_offset;
    else
        ret = error;

    RHO_TRACE_EXIT("return=%ld", ret);
    return (ret);
}

/* FIXME: I don't think you take into accuont that off_t could be negative */
static int
nextfs_truncate(struct shim_handle *hdl, off_t len)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_hdl_get_agent(hdl);
    uint32_t nextfs_fd =  NEXTFS_HDL_GET_FD(hdl);

    RHO_TRACE_ENTER("len=%ld", len);
    rho_shim_handle_print(hdl);

    error = nextfs_file_truncate_rpc(agent, nextfs_fd, len);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_hstat(struct shim_handle *hdl, struct stat *stat)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_hdl_get_agent(hdl);
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    RHO_TRACE_ENTER();
    rho_shim_handle_print(hdl);

    rho_shim_dentry_relpath(hdl->dentry, path, sizeof(path));
    error = nextfs_raw_inode_rpc(agent, path, stat);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_checkout(struct shim_handle *hdl)
{
    RHO_TRACE_ENTER("hdl path=%s", qstrgetstr(&hdl->path));
    hdl->fs = NULL;
    RHO_TRACE_EXIT("return=0");
    return (0);
}

static int
nextfs_checkin(struct shim_handle *hdl)
{
    struct nextfs_mdata *mdata = NULL;

    RHO_TRACE_ENTER();
    rho_shim_handle_print(hdl);

    if (hdl->fs != NULL && hdl->fs->data != NULL) {
        mdata = hdl->fs->data;
        nextfs_mdata_print(mdata);
    }

    RHO_TRACE_EXIT("return=0");
    return (0);
}

static ssize_t
nextfs_checkpoint(void **checkpoint, void *mount_data)
{
    ssize_t ret = 0;
    int error = 0;
    struct nextfs_mdata *mdata = mount_data;
    uint64_t child_ident = 0;

    RHO_TRACE_ENTER();

    error = nextfs_fork_rpc(mdata->agent, &child_ident);
    if (error != 0) {
        ret = error;
        goto done;
    }

    rho_debug("nextfs child_ident=0x%lx", child_ident);

    mdata->ident = child_ident;
    *checkpoint = mdata;
    ret = sizeof(struct nextfs_mdata);

done:
    RHO_TRACE_EXIT("return=%ld", ret);
    return (ret);
}

/* 
 * What is the memory management for this function?
 * Should the parent's client be free'd.  Should the
 * old mdata be free'd?
 *
 * I think this function must return 0 on success.
 */
static int
nextfs_migrate(void *checkpoint, void **mount_data)
{
    int error = 0;
    struct nextfs_mdata *mdata = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER();

    mdata = rhoL_zalloc(sizeof(struct nextfs_mdata));
    memcpy(mdata, checkpoint, sizeof(struct nextfs_mdata));
    mdata->debug_cookie = rho_rand_u32();
    nextfs_mdata_print(mdata);

    agent = nextfs_agent_open(mdata->url, 
            mdata->ca_der[0] == 0x00 ? NULL : mdata->ca_der,
            mdata->ca_der_len);

    mdata->agent = agent;

    error = nextfs_child_attach_rpc(agent, mdata->ident);
    *mount_data = mdata;

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}


/***********************************
 * FS_OPS STUBS: NOT YET IMPLEMENTED
 ***********************************/
static int
nextfs_flush(struct shim_handle *hdl)
{
    RHO_TRACE_ENTER();
    __UNUSED(hdl);
    RHO_TRACE_EXIT("return=0");
    return (0);
}

static int
nextfs_setflags(struct shim_handle *hdl, int flags)
{
    RHO_TRACE_ENTER("flags=%d", flags);
    __UNUSED(hdl);
    __UNUSED(flags);
    RHO_TRACE_EXIT("return=0");
    return (0);
}

static void
nextfs_hput(struct shim_handle *hdl)
{
    RHO_TRACE_ENTER();
    __UNUSED(hdl);
    RHO_TRACE_EXIT();
    return;
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/

static int
nextfs_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    /* XXX: should we get the agent form hdl or dent? */
    struct rpc_agent *agent = nextfs_dentry_get_agent(dent);
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };
    uint32_t nextfs_fd = 0;

    RHO_TRACE_ENTER("flags=0x%x", flags);
    rho_shim_handle_print(hdl);
    rho_shim_dentry_print(dent);

    rho_shim_dentry_relpath(dent, path, sizeof(path));

    /* XXX: probably also want to make sure that O_RDONLY is specified */
    if (flags & O_DIRECTORY)
        error = nextfs_dir_open_rpc(agent, path, &nextfs_fd);
    else
        error = nextfs_file_open2_rpc(agent, path, flags, &nextfs_fd);

    if (error != 0)
        goto done;

    hdl->info.nextfs.fd = nextfs_fd;
    hdl->type = TYPE_NEXTFS;
    hdl->flags = flags;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_lookup(struct shim_dentry *dent)
{
    int error = 0;
    struct stat sb;
    struct rpc_agent *agent = nextfs_dentry_get_agent(dent);
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    RHO_TRACE_ENTER();
    rho_shim_dentry_print(dent);

    if (qstrempty(&dent->rel_path)) {
        dent->state |= DENTRY_ISDIRECTORY;
        goto done;
    }

    rho_memzero(&sb, sizeof(struct stat));
    rho_shim_dentry_relpath(dent, path, sizeof(path));
    error = nextfs_raw_inode_rpc(agent, path, &sb);
    if (error != 0) {
        dent->state |= DENTRY_NEGATIVE;
        goto done;
    }

    /* 
     * XXX: it's unclear to me the difference between 
     * dent's state, type, and mode fields; set all;
     * internally, nextfs will rely on mode, which contains
     * the most information.
     */

    dent->ino = sb.st_ino;
    dent->mode = sb.st_mode;
    dent->type = S_IFMT & sb.st_mode;
    if (S_ISDIR(sb.st_mode))
        dent->state |= DENTRY_ISDIRECTORY;
    else if (S_ISLNK(sb.st_mode))
        dent->state |= DENTRY_ISLINK;

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int 
nextfs_mode(struct shim_dentry *dent, mode_t *mode)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_dentry_get_agent(dent);
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    RHO_TRACE_ENTER();
    rho_shim_dentry_print(dent);

    rho_shim_dentry_relpath(dent, path, sizeof(path));
    error = nextfs_mode_get_rpc(agent, path, mode);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

/* 
 * TODO: 
 *  - are we suppose to change anything in dir
 *  - deal with error if chmod fails.
 */
static int
nextfs_creat(struct shim_handle *hdl, struct shim_dentry *dir,
        struct shim_dentry *dent, int flags, mode_t mode)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_dentry_get_agent(dent);
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    RHO_TRACE_ENTER("flags=0x%x, mode=0x%x", flags, mode);
    rho_shim_handle_print(hdl);
    rho_shim_dentry_print(dir);
    rho_shim_dentry_print(dent);

    error = nextfs_open(hdl, dent, flags);
    if (error != 0)
        goto done;
    
    rho_shim_dentry_relpath(dent, path, sizeof(path));
    error = nextfs_mode_set_rpc(agent, path, mode);

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_unlink(struct shim_dentry *dir, struct shim_dentry *dent)
{
    int error = 0;
    /* XXX: should we get the agent from dir or dent? */
    struct rpc_agent *agent = nextfs_dentry_get_agent(dent);
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    RHO_TRACE_ENTER();
    rho_shim_dentry_print(dir);
    rho_shim_dentry_print(dent);

    rho_shim_dentry_relpath(dent, path, sizeof(path));

    if (S_ISDIR(dent->mode))
        error = nextfs_dir_rm_rpc(agent, path);
    else
        error = nextfs_file_remove_rpc(agent, path);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_mkdir(struct shim_dentry *dir, struct shim_dentry *dent, mode_t mode)
{
    int error = 0;
    /* XXX: should we get the agent from dir or dent? */
    struct rpc_agent *agent = nextfs_dentry_get_agent(dent);
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    RHO_TRACE_ENTER("mode=0x%x", mode);
    rho_shim_dentry_print(dir);
    rho_shim_dentry_print(dent);

    __UNUSED(dir);

    rho_shim_dentry_relpath(dent, path, sizeof(path));
    error = nextfs_dir_mk_rpc(agent, path, mode);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_stat(struct shim_dentry *dent, struct stat *stat)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_dentry_get_agent(dent);
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    RHO_TRACE_ENTER();
    rho_shim_dentry_print(dent);

    rho_shim_dentry_relpath(dent, path, sizeof(path));
    error = nextfs_raw_inode_rpc(agent, path, stat);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_chmod(struct shim_dentry *dent, mode_t mode)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_dentry_get_agent(dent);
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    RHO_TRACE_ENTER("mode=0x%x", mode);
    rho_shim_dentry_print(dent);

    rho_shim_dentry_relpath(dent, path, sizeof(path));
    error = nextfs_mode_set_rpc(agent, path, mode);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
nextfs_chown(struct shim_dentry *dent, int uid, int gid)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_dentry_get_agent(dent);
    char path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    RHO_TRACE_ENTER("uid=%d, gid=%d", uid, gid);
    rho_shim_dentry_print(dent);

    rho_shim_dentry_relpath(dent, path, sizeof(path));
    error = nextfs_owner_set_rpc(agent, path, uid, gid);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
} 

static int
nextfs_rename(struct shim_dentry *old, struct shim_dentry *new)
{
    int error = 0;
    struct rpc_agent *agent = nextfs_dentry_get_agent(old);
    char old_path[NEXTFS_MAX_PATH_LENGTH] = { 0 };
    char new_path[NEXTFS_MAX_PATH_LENGTH] = { 0 };

    RHO_TRACE_ENTER();
    rho_shim_dentry_print(old);
    rho_shim_dentry_print(new);

    rho_shim_dentry_relpath(old, old_path, sizeof(old_path));
    rho_shim_dentry_relpath(new, new_path, sizeof(new_path));

    error = nextfs_file_rename_rpc(agent, old_path, new_path);
    if (error != 0)
        goto done;

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
    RHO_TRACE_EXIT("return=%d", error);
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
    struct rpc_agent *agent = nextfs_dentry_get_agent(dent);
    struct shim_handle hdl;

    RHO_TRACE_ENTER();
    rho_shim_dentry_print(dent);

    memset(&hdl, 0x00, sizeof(struct shim_handle));
    error = nextfs_open(&hdl, dent, O_DIRECTORY);
    if (error != 0)
        goto done;

    error = nextfs_dir_list_rpc(agent, hdl.info.nextfs.fd, dirent);
    (void)nextfs_dir_close_rpc(agent, hdl.info.nextfs.fd);

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

struct shim_fs_ops nextfs_fs_ops = {
        .mount       = &nextfs_mount,
        .close       = &nextfs_close,
        .read        = &nextfs_read,
        .write       = &nextfs_write,
        .mmap        = &nextfs_mmap,
        .flush       = &nextfs_flush,
        .seek        = &nextfs_seek,
        .truncate    = &nextfs_truncate,
        .hstat       = &nextfs_hstat,
        .setflags    = &nextfs_setflags,
        .hput        = &nextfs_hput,
        .checkout    = &nextfs_checkout,
        .checkin     = &nextfs_checkin,
        .checkpoint  = &nextfs_checkpoint,
        .migrate     = &nextfs_migrate,
    };

struct shim_d_ops nextfs_d_ops = {
        .open       = &nextfs_open,
        .lookup     = &nextfs_lookup,
        .mode       = &nextfs_mode,
        .creat      = &nextfs_creat,
        .unlink     = &nextfs_unlink,
        .mkdir      = &nextfs_mkdir,
        .stat       = &nextfs_stat,
        .chmod      = &nextfs_chmod,
        .chown      = &nextfs_chown,
        .rename     = &nextfs_rename,
        .readdir    = &nextfs_readdir,
    };
