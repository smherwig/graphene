/*
 * fs.c
 *
 * The 'smuf' filesystem.
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

#include <bearssl.h>

#include "rho_binascii.h"
#include "rho_bitops.h"
#include "rho_buf.h"
#include "rho_endian.h"
#define RHO_LOG_PREFIX "SMUF"
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

#include "rpc.h"

#define SMUF_OP_NEW_FDTABLE    0
#define SMUF_OP_FORK           1
#define SMUF_OP_CHILD_ATTACH   2
#define SMUF_OP_OPEN           3
#define SMUF_OP_CLOSE          4
#define SMUF_OP_LOCK           5
#define SMUF_OP_UNLOCK         6
#define SMUF_OP_MMAP           7

#define SMUF_MAX_URI_SIZE           512
#define SMUF_MAX_NAME_SIZE          128
#define SMUF_MAX_PATH_SIZE          256

#define SMUF_LOCKFILE_SIZE          4096

#define SMUF_IV_SIZE 12
#define SMUF_KEY_SIZE 32
#define SMUF_TAG_SIZE 16

#define SMUF_TYPE_PURE_LOCK                 0
#define SMUF_TYPE_LOCK_WITH_SEGMENT         1
#define SMUF_TYPE_LOCK_WITH_UNINIT_SEGMENT  2

struct smuf_memfile {
    char        f_name[SMUF_MAX_NAME_SIZE];

    char        f_lock_uri[SMUF_MAX_URI_SIZE];
    char        f_segment_uri[SMUF_MAX_URI_SIZE];

    int         f_fd_refcnt;
    uint32_t    f_remote_fd;
    void        *f_pub_lock;
    int         f_turn;

    uint8_t     f_type;

    void        *f_pub_seg;
    void        *f_priv_seg;
    size_t      f_map_size;

    uint8_t     f_iv[SMUF_IV_SIZE];
    uint8_t     f_key[SMUF_KEY_SIZE];
    uint8_t     f_tag[SMUF_TAG_SIZE];
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
struct smuf_mdata {
    char server_uri[SMUF_MAX_URI_SIZE];
    char memdir_uri[SMUF_MAX_URI_SIZE];
    uint64_t ident;             /* auth cookie for child */
    unsigned char ca_der[4096];
    size_t  ca_der_len;
    struct rpc_agent *agent;
    uint32_t mf_bitmap;
    struct smuf_memfile mf_tab[32];
};

/******************************************
 * GLOBALS
 ******************************************/

struct smuf_mdata *g_smuf_mdata = NULL;

/**********************************************************
 * U32 Bitmap operations
 **********************************************************/
static int
smuf_bitmap_u32_ffc(uint32_t bitmap)
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
 * AES-GCM
 *********************************/

static void
smuf_encrypt(uint8_t *data, size_t data_len, const uint8_t *key,
        const uint8_t *iv, uint8_t *tag)
{
    br_aes_x86ni_ctr_keys ctx;
    br_gcm_context gc;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, SMUF_KEY_SIZE);
    br_gcm_init(&gc, &ctx.vtable, br_ghash_pclmul);
    br_gcm_reset(&gc, iv, SMUF_IV_SIZE); 
    /* use br_gc_aad_inject, if needed */
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 1, data, data_len); /* encrypts in-place */
    br_gcm_get_tag(&gc, tag);

    RHO_TRACE_EXIT();
}

static void
smuf_decrypt(uint8_t *data, size_t data_len, const uint8_t *key,
        const uint8_t *iv, uint8_t *tag)
{
    br_aes_x86ni_ctr_keys ctx;
    br_gcm_context gc;

    RHO_TRACE_ENTER();

    br_aes_x86ni_ctr_init(&ctx, key, SMUF_KEY_SIZE);
    br_gcm_init(&gc, &ctx.vtable, br_ghash_pclmul);
    br_gcm_reset(&gc, iv, SMUF_IV_SIZE); 
    /* use br_gc_aad_inject, if needed */
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 0, data, data_len); /* encrypts in-place */
    br_gcm_get_tag(&gc, tag);

    RHO_TRACE_EXIT();
}

/********************************* 
 * MAPPING UNTRUSTED HOST FILE
 *********************************/

static int
smuf_map_fileuri(const char *fileuri, size_t size, void **addr)
{
    int error = 0;
    PAL_HANDLE file;
    PAL_STREAM_ATTR pal_attr;
    size_t pending_size = 0;
    void *mem = NULL;
    int pal_prot = LINUX_PROT_TO_PAL(PROT_READ|PROT_WRITE, 0);

    RHO_TRACE_ENTER("fileuri=\"%s\", size=%lu", fileuri, (unsigned long)size);

    file = DkStreamOpen(fileuri, PAL_ACCESS_RDWR, 0, 0, 0);
    if (!file) {
        rho_warn("DkStreamOpen(\"%s\") failed", fileuri);
        error = -PAL_ERRNO();
        goto done;
    }

    if (DkStreamAttributesQueryByHandle(file, &pal_attr) == PAL_FALSE) {
        rho_warn("DkStreamAttributesQueryByHandle(\"%s\") failed", fileuri);
        error = -PAL_ERRNO();
        goto done;
    }

    pending_size = pal_attr.pending_size;

    if (pending_size != size) {
        rho_warn("pending size (%lu) does not equal expected (%lu) for \"%s\"",
                (unsigned long)pending_size, (unsigned long)size, fileuri);
        error = -EPROTO;
        goto done;
    }

    /* 
     * XXX: do we need to bkeep before this call?
     * We should call bkeep_unmapped_any, however, the problem is that
     * we well then pass an address into DkStreamMap (instead of NULL), which
     * will error due to the problems with untrusted mappings.
     */

    mem = DkStreamMap(file, NULL, pal_prot, 0, ALLOC_ALIGN_UP(size));
    if (mem == NULL) {
        rho_warn("DkStreamMap(\"%s\") failed", fileuri);
        error = -EFAULT;
        goto done;
    }

    *addr = mem;

done:
    if (file)
        DkObjectClose(file);

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

/******************************************
 * MEMFILE
 ******************************************/ 

static void
smuf_memfile_init(const char *memdir_uri, struct smuf_memfile *mf,
        const char *name)
{
    size_t n = 0;

    RHO_TRACE_ENTER("name=\"%s\"", name);

    rho_memzero(mf, sizeof(*mf));

    /* name relative to mount, (e.g., /foo) */
    n = rho_strlcpy(mf->f_name, name, SMUF_MAX_NAME_SIZE);
    RHO_ASSERT(n < SMUF_MAX_NAME_SIZE);

    /*
     * FIXME:
     *  We assume memdir_uri does not end in '/' and that
     *  f_name starts with a '/'.
     */

    /* construct lockfile uri (e.g, file:/home/bar/foo) */
    n = rho_strlcpy(mf->f_lock_uri, memdir_uri, SMUF_MAX_URI_SIZE);
    RHO_ASSERT(n < SMUF_MAX_URI_SIZE);

    n = rho_strlcat(mf->f_lock_uri, mf->f_name, SMUF_MAX_URI_SIZE);
    RHO_ASSERT(n < SMUF_MAX_URI_SIZE);

    /* construct segment file uri (e.g., file:/home/bar/foo.segment) */
    n = rho_strlcpy(mf->f_segment_uri, memdir_uri, SMUF_MAX_URI_SIZE);
    RHO_ASSERT(n < SMUF_MAX_URI_SIZE);

    n = rho_strlcat(mf->f_segment_uri, mf->f_name, SMUF_MAX_URI_SIZE);
    RHO_ASSERT(n < SMUF_MAX_URI_SIZE);

    n = rho_strlcat(mf->f_segment_uri, ".segment", SMUF_MAX_URI_SIZE);
    RHO_ASSERT(n < SMUF_MAX_URI_SIZE);


    mf->f_fd_refcnt = 1;
    mf->f_type = SMUF_TYPE_PURE_LOCK;

    RHO_TRACE_EXIT();
}

static void
smuf_memfile_print(const struct smuf_memfile *mf)
{
    debug("smuf_memfile = {\n");
    debug("  f_name: \"%s\"\n", mf->f_name);
    debug("  f_lock_uri: \"%s\"\n", mf->f_lock_uri);
    debug("  f_segment_uri: \"%s\"\n", mf->f_segment_uri);
    debug("  f_fd_refcnt: %d\n", mf->f_fd_refcnt);
    debug("  f_remote_fd: %lu\n", (unsigned long)mf->f_remote_fd);
    debug("  f_type: %u\n", (unsigned)mf->f_type);
    debug("  f_pub_lock: %p\n", mf->f_pub_lock);
    debug("  f_pub_seg: %p\n", mf->f_pub_seg);
    debug("  f_priv_seg: %p\n", mf->f_priv_seg);
    debug("  f_map_size: %lu\n", mf->f_map_size);
    debug("  f_turn: %d\n", mf->f_turn);
    debug("}\n");
}

/* decrypt file into private memory */
static int
smuf_memfile_copyin_segment(struct smuf_memfile *mf)
{
    int error = 0;
    uint8_t actual_tag[SMUF_TAG_SIZE] = {0};

    RHO_TRACE_ENTER();

    memcpy(mf->f_priv_seg, mf->f_pub_seg, mf->f_map_size);
    smuf_decrypt(mf->f_priv_seg, mf->f_map_size, mf->f_key, mf->f_iv,
            actual_tag);
    if (!rho_mem_equal(mf->f_tag, actual_tag, SMUF_TAG_SIZE)) {
        rho_warn("on memfile \"%s\" map in, tag does not match trusted tag",
                mf->f_name);
        error = -EBADE;  /* invalid exchange */
    }

    RHO_TRACE_EXIT();
    return (error);
}

/* 
 * encrypt private memory to file
 * sets new iv and tag on mf
 */
static void
smuf_memfile_copyout_segment(struct smuf_memfile *mf)
{
    void *tmp = NULL;

    RHO_TRACE_ENTER();

    tmp = rhoL_zalloc(mf->f_map_size);
    memcpy(tmp, mf->f_priv_seg, mf->f_map_size);

    rho_rand_bytes(mf->f_iv, SMUF_IV_SIZE);
    smuf_encrypt(tmp, mf->f_map_size, mf->f_key, mf->f_iv,
            mf->f_tag);
    memcpy(mf->f_pub_seg, tmp, mf->f_map_size);

    rhoL_free(tmp);

    RHO_TRACE_EXIT();
}

/**********************************************************
 * MOUNT DATA
 *
 * (acts like a fs-specific file descriptor table
 **********************************************************/

static struct smuf_mdata *
smuf_mdata_create(const char *server_uri, const char *memdir_uri,
        unsigned char *ca_der, size_t ca_der_len)
{
    struct smuf_mdata *mdata = NULL;
    size_t n = 0;
    
    RHO_TRACE_ENTER();

    mdata = rhoL_zalloc(sizeof(struct smuf_mdata));
    n = rho_strlcpy(mdata->server_uri, server_uri, SMUF_MAX_URI_SIZE);
    RHO_ASSERT(n < SMUF_MAX_URI_SIZE);
    n = rho_strlcpy(mdata->memdir_uri, memdir_uri, SMUF_MAX_URI_SIZE);
    RHO_ASSERT(n < SMUF_MAX_URI_SIZE);

    if (ca_der != NULL) {
        memcpy(mdata->ca_der, ca_der, ca_der_len);
        mdata->ca_der_len = ca_der_len;
    }

    RHO_TRACE_EXIT();
    return (mdata);
}

static void
smuf_mdata_print(const struct smuf_mdata *mdata)
{
    debug("smuf_mdata = {server_uri: %s, memdir_uri: %s, ident:%llu, ca_der[0]:%02x, ca_der_len:%lu}\n",
            mdata->server_uri, mdata->memdir_uri, (unsigned long long)mdata->ident,
            mdata->ca_der[0], (unsigned long)mdata->ca_der_len);
}

static struct smuf_memfile *
smuf_mdata_find_memfile(const struct smuf_mdata *mdata, const char *name,
        int *mf_idx)
{
    size_t i = 0;
    int val = 0;
    const struct smuf_memfile *mf = NULL;

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
    return ((struct smuf_memfile *)mf);
}

static struct smuf_memfile *
smuf_mdata_get_memfile_at_idx(const struct smuf_mdata *mdata, int mf_idx)
{
    const struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER("mf_idx=%d", mf_idx);

    if (!RHO_BITOPS_ISSET((uint8_t *)&mdata->mf_bitmap, mf_idx)) {
        rho_warn("smuf memfile bitmap index not set");
        goto done;
    }

    mf = &(mdata->mf_tab[mf_idx]);

done:
    RHO_TRACE_EXIT("mf=%p", mf);
    return ((struct smuf_memfile *)mf);
}

/* returns 0 on success; a negative ernro value on failure */
static int
smuf_mdata_new_memfile(struct smuf_mdata *mdata, const char *name,
        struct smuf_memfile **mf, int *mf_idx)
{
    int error = 0;
    int i = 0;
    RHO_TRACE_ENTER();

    i = smuf_bitmap_u32_ffc(mdata->mf_bitmap);
    if (i == -1) {
        rho_warn("smuf memfile bitmap is full!");
        error = -ENFILE;
        goto done; 
    }

    RHO_BITOPS_SET((uint8_t *)&mdata->mf_bitmap, i);

    *mf = &(mdata->mf_tab[i]);
    smuf_memfile_init(mdata->memdir_uri, *mf, name);
    if (mf_idx != NULL)
        *mf_idx = i;

done:
    RHO_TRACE_EXIT("error=%d, i=%d", error, i);
    return (error);
}

static int
smuf_mdata_remove_memfile_at_idx(struct smuf_mdata *mdata,
        int mf_idx)
{
    int error = 0;

    RHO_TRACE_ENTER("mf_idx=%d", mf_idx);

    if (!RHO_BITOPS_ISSET((uint8_t *)&mdata->mf_bitmap, mf_idx)) {
        rho_warn("smuf memfile bitmap index not set");
        error = -EBADF;
        goto done;
    }

    RHO_BITOPS_CLR((uint8_t *)&mdata->mf_bitmap, mf_idx);
    rho_memzero(&(mdata->mf_tab[mf_idx]), sizeof(struct smuf_memfile));

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

/**********************************************************
 * RPC AGENT
 **********************************************************/

static struct rpc_agent *
smuf_agent_open(const char *url, unsigned char *ca_der, size_t ca_der_len)
{
    struct rpc_agent *agent = NULL;
    struct rho_sock *sock = NULL;
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *ctx = NULL;

    sock = rho_sock_open_url(url);

    if (ca_der != NULL) {
        debug("smuf rpc agent using TLS\n");
        params = rho_ssl_params_create();
        rho_ssl_params_set_mode(params, RHO_SSL_MODE_CLIENT);
        rho_ssl_params_set_protocol(params, RHO_SSL_PROTOCOL_TLSv1_2);
        rho_ssl_params_set_ca_der(params, ca_der, ca_der_len);
        ctx = rho_ssl_ctx_create(params);
        rho_ssl_wrap(sock, ctx);
        //rho_ssl_params_destroy(params);
    }

    agent = rpc_agent_create(sock);

    return (agent);
}

/**********************************************************
 * RPCs
 *
 * These functions return 0 on success; a negative errno
 * on failure.
 **********************************************************/

static int
smuf_new_fdtable_rpc(struct rpc_agent *agent)
{
    int error = 0;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMUF_OP_NEW_FDTABLE);
    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
smuf_fork_rpc(struct rpc_agent *agent, uint64_t *child_ident)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER();

    rpc_agent_new_msg(agent, SMUF_OP_FORK);

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
smuf_child_attach_rpc(struct rpc_agent *agent, uint64_t child_ident)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("child_ident=0x%lx", child_ident);

    rpc_agent_new_msg(agent, SMUF_OP_CHILD_ATTACH);
    rho_buf_writeu64be(buf, child_ident);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

/* returns 0 on success; a negative errno value on failure */
static int
smuf_open_rpc(struct rpc_agent *agent, const char *name, uint32_t *remote_fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("name=\"%s\"", name);

    rpc_agent_new_msg(agent, SMUF_OP_OPEN);
    rho_buf_write_u32size_str(buf, name);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu32be(buf, remote_fd);
    if (error != 0) {
        error = -EPROTO;
        goto done;
    }

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
smuf_close_rpc(struct rpc_agent *agent, uint32_t remote_fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("remote_fd=%u", remote_fd);

    rpc_agent_new_msg(agent, SMUF_OP_CLOSE);
    rho_buf_writeu32be(buf, remote_fd);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
smuf_lock_rpc(struct rpc_agent *agent, uint32_t remote_fd, int turn, uint8_t my_type,
        uint8_t *remote_type, void *iv, void *key, void *tag)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;
    uint32_t n = 0;

    RHO_TRACE_ENTER("remote_fd=%u, turn=%d, my_type=%u",
            remote_fd, turn, my_type);
    
    rpc_agent_new_msg(agent, SMUF_OP_LOCK);
    rho_buf_writeu32be(buf, remote_fd);
    rho_buf_write32be(buf, turn);
    rho_buf_writeu8(buf, my_type);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);
    if (error != 0)
        goto done;

    error = rho_buf_readu8(buf, remote_type);
    if (error != 0) {
        error = -EPROTO;
        goto done;
    }

    /* server detects type mismatch, so we don't have to */
    if (*remote_type != SMUF_TYPE_LOCK_WITH_SEGMENT)
        goto done;

    /* iv */
    error = rho_buf_readu32be(buf, &n);
    if ((error != 0) || (n != SMUF_IV_SIZE)) {
        error  = -EPROTO;
        goto done;
    }

    if (rho_buf_read(buf, iv, SMUF_IV_SIZE) != SMUF_IV_SIZE) {
        error = -EPROTO;
        goto done;
    }

    /* key */
    error = rho_buf_readu32be(buf, &n);
    if ((error != 0) || (n != SMUF_KEY_SIZE)) {
        error = -EPROTO;
        goto done;
    }

    if (rho_buf_read(buf, key, SMUF_KEY_SIZE) != SMUF_KEY_SIZE) {
        error = -EPROTO;
        goto done;
    }

    /* tag */
    error = rho_buf_readu32be(buf, &n);
    if ((error != 0) || (n != SMUF_TAG_SIZE)) {
        error = -EPROTO;
        goto done;
    }

    if (rho_buf_read(buf, tag, SMUF_TAG_SIZE) != SMUF_TAG_SIZE) {
        error = -EPROTO;
        goto done;
    }

done:
    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

static int
smuf_unlock_rpc(struct rpc_agent *agent, uint32_t remote_fd, uint8_t my_type,
        uint8_t *iv, uint8_t *key, uint8_t *tag)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("remote_fd=%u, my_type=%u", remote_fd, my_type);

    rpc_agent_new_msg(agent, SMUF_OP_UNLOCK);
    rho_buf_writeu32be(buf, remote_fd);
    rho_buf_writeu8(buf, my_type);

    if (my_type == SMUF_TYPE_LOCK_WITH_SEGMENT) {
        RHO_ASSERT(iv != NULL);
        rho_buf_writeu32be(buf, SMUF_IV_SIZE);
        rho_buf_write(buf, iv, SMUF_IV_SIZE);

        RHO_ASSERT(key != NULL);
        rho_buf_writeu32be(buf, SMUF_KEY_SIZE);
        rho_buf_write(buf, key, SMUF_KEY_SIZE);

        RHO_ASSERT(tag != NULL);
        rho_buf_writeu32be(buf, SMUF_TAG_SIZE);
        rho_buf_write(buf, tag, SMUF_TAG_SIZE);
    }

    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d\n", error);
    return (error);
}

static int
smuf_mmap_rpc(struct rpc_agent *agent, uint32_t remote_fd, uint32_t map_size)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    RHO_TRACE_ENTER("remote_fd=%u, map_size=%u", remote_fd, map_size);

    rpc_agent_new_msg(agent, SMUF_OP_MMAP);
    rho_buf_writeu32be(buf, remote_fd);
    rho_buf_writeu32be(buf, map_size);
    rpc_agent_autoset_bodylen(agent);

    error = rpc_agent_request(agent);

    RHO_TRACE_EXIT("return=%d", error);
    return (error);
}

/********************************* 
 * FILE/FILESYSTEM OPERATIONS
 *********************************/

/*
 * Mount should allocated a struct smuf_mountdata and return it
 * in the mount_data out parameter.
 *
 * uri is the host URI for the resource to be "mounted", and
 * root is the guest mountpoint.
 */
static int
smuf_mount(const char *uri, void **mount_data)
{
    int error = 0;
    char ca_hex[CONFIG_MAX] = { 0 };
    unsigned char *ca_der = NULL;
    ssize_t len = 0;
    struct smuf_mdata *mdata = NULL;
    struct rpc_agent *agent = NULL;
    size_t n = 0;
    char **uris = NULL;

    RHO_TRACE_ENTER("uri=\"%s\"", uri);

    len = get_config(root_config, "phoenix.ca_der", ca_hex, sizeof(ca_hex));
    if (len > 0) {
        debug("READ phoenix.ca_der (size=%ld)\n", len);
        ca_der = rhoL_malloc(len / 2);
        rho_binascii_hex2bin(ca_der, ca_hex);
    }

    uris = rho_str_splitc(uri, ',', &n);

    agent = smuf_agent_open(uris[0], ca_der, len / 2);
    if (agent == NULL) {
        /* FIXME: better errno; what's in PAL_ERRNO? */
        error = -ENXIO;
        goto fail;

    }

    error = smuf_new_fdtable_rpc(agent);
    if (error != 0)
        goto fail;

    mdata = smuf_mdata_create(uris[0], uris[1], ca_der, len / 2);
    mdata->agent = agent;
    *mount_data = mdata;
    g_smuf_mdata = mdata;

    goto succeed;

fail:
    if (agent != NULL)
        rpc_agent_destroy(agent);

succeed:
    if (ca_der != NULL)
        rhoL_free(ca_der);
    if (uris != NULL)
        rho_str_array_destroy(uris);
    RHO_TRACE_EXIT();
    return (error);
}

static int
smuf_close(struct shim_handle *hdl)
{
    int error = 0;
    struct smuf_mdata *mdata = hdl->fs->data;
    struct shim_smuf_handle *smh = &(hdl->info.smuf);
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER();
    rho_shim_handle_print(hdl);

    mf = smuf_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smuf_memfile_print(mf);

    mf->f_fd_refcnt--;
    if (mf->f_fd_refcnt == 0 && mf->f_priv_seg == NULL) {
        error = smuf_close_rpc(mdata->agent, mf->f_remote_fd);
        smuf_mdata_remove_memfile_at_idx(mdata, smh->mf_idx);
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

static int
smuf_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    struct smuf_mdata *mdata = hdl->fs->data;
    struct shim_smuf_handle *smh = &(hdl->info.smuf);
    struct smuf_memfile *mf = NULL;
    int pal_prot = LINUX_PROT_TO_PAL(PROT_READ|PROT_WRITE, 0);

    (void)prot;
    (void)flags;
    (void)offset;

    RHO_TRACE_ENTER("addr=%p, *addr=%p, size=%lu, prot=%08x, flags=%08x, offset=%ld",
            addr, *addr, size, prot, flags, offset);

    rho_shim_handle_print(hdl);
    rho_shim_dentry_print(hdl->dentry);

    mf = smuf_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smuf_memfile_print(mf);

    if (mf->f_type == SMUF_TYPE_LOCK_WITH_SEGMENT) {
        /* 
         * On migrate, mmap recalls mmap on any handle that was mmap'd.
         * In our case, this is superflous.  With NGINX, it actually
         * causes issues, since the lock file information is stored in the
         * shared memory segment, and re-mmaping would zero out the client's
         * segment and thereofre prevent it from knowing the name of the lock.
         * -- this isn't true any more
         */
        debug("smuf_mmap: mfile already has a segment (%p, %p); skipping RPC call\n",
                mf->f_priv_seg, *((void **)mf->f_priv_seg));
        *addr = mf->f_priv_seg;
    } else {
        error = smuf_mmap_rpc(mdata->agent, mf->f_remote_fd, size);
        if (error != 0)
            goto done;

        mf->f_map_size = size;
        mf->f_type = SMUF_TYPE_LOCK_WITH_SEGMENT;
        rho_rand_bytes(mf->f_key, SMUF_KEY_SIZE);

        mf->f_priv_seg = DkVirtualMemoryAlloc(*addr, size, 0, pal_prot);
        if (mf->f_priv_seg == NULL) {
            error = -ENOMEM;
            /* TODO: better cleanup on failure */
            goto done;
        }
    }

    /* 
     * XXX: if this error's then we have orphaned a segmentfile on the
     * server
     */
    error = smuf_map_fileuri(mf->f_segment_uri, mf->f_map_size,
            &mf->f_pub_seg);
    if (error != 0)
        goto done;

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smuf_advlock_lock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smuf_mdata *mdata = g_smuf_mdata;
    struct shim_smuf_handle *smh = &(hdl->info.smuf);
    struct smuf_memfile *mf = NULL;
    struct rho_ticketlock *tl = NULL;
    uint8_t remote_type = 0;
    uint8_t iv[SMUF_IV_SIZE] = { 0 };
    uint8_t key[SMUF_KEY_SIZE] = { 0 };
    uint8_t tag[SMUF_TAG_SIZE] = { 0 };

    (void)flock;

    RHO_TRACE_ENTER();
    rho_shim_handle_print(hdl);

    mf = smuf_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smuf_memfile_print(mf);

    tl = (struct rho_ticketlock *)mf->f_pub_lock;

    mf->f_turn = rho_ticketlock_lock(tl);
    error = smuf_lock_rpc(mdata->agent, mf->f_remote_fd, mf->f_turn, mf->f_type,
            &remote_type, iv, key, tag);

    if (error != 0)
        goto done;

    if (remote_type == SMUF_TYPE_LOCK_WITH_SEGMENT) {
        memcpy(mf->f_iv, iv, SMUF_IV_SIZE);
        memcpy(mf->f_key, key, SMUF_KEY_SIZE);
        memcpy(mf->f_tag, tag, SMUF_TAG_SIZE);
        error = smuf_memfile_copyin_segment(mf);
    }

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smuf_advlock_unlock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smuf_mdata *mdata = hdl->fs->data;
    struct shim_smuf_handle *smh = &(hdl->info.smuf);
    struct smuf_memfile *mf = NULL;
    struct rho_ticketlock *tl = NULL;

    (void)flock;

    RHO_TRACE_EXIT();
    rho_shim_handle_print(hdl);

    mf = smuf_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smuf_memfile_print(mf);

    if (mf->f_type == SMUF_TYPE_LOCK_WITH_SEGMENT)
        smuf_memfile_copyout_segment(mf);

    error = smuf_unlock_rpc(mdata->agent, mf->f_remote_fd, mf->f_type,
                mf->f_iv, mf->f_key, mf->f_tag);

    tl = (struct rho_ticketlock *)mf->f_pub_lock;
    rho_ticketlock_unlock(tl);

done:
    RHO_TRACE_ENTER();
    return (error);
}

static int
smuf_advlock(struct shim_handle *hdl, int op, struct flock *flock)
{
    int error = 0;

    (void)op;

    RHO_TRACE_ENTER();

    if (flock->l_type == F_WRLCK)
        error = smuf_advlock_lock(hdl, flock);
    else if (flock->l_type == F_UNLCK)
        error = smuf_advlock_unlock(hdl, flock);
    else
        error = -EINVAL;

    RHO_TRACE_EXIT();
    return (error);
}

static int
smuf_hstat(struct shim_handle *hdl, struct stat *stat)
{
    int error = 0;
    struct smuf_mdata *mdata = g_smuf_mdata;
    struct shim_smuf_handle *smh = &(hdl->info.smuf);
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER();
    rho_shim_handle_print(hdl);

    mf = smuf_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }
    smuf_memfile_print(mf);

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
smuf_checkout(struct shim_handle *hdl)
{
    RHO_TRACE_ENTER();

    rho_shim_handle_print(hdl);
    hdl->fs = NULL;

    RHO_TRACE_EXIT();
    return (0);
}

static int
smuf_checkin(struct shim_handle *hdl)
{
    int error = 0;
    struct smuf_mdata *mdata = g_smuf_mdata;
    struct shim_smuf_handle *smh = &(hdl->info.smuf);
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER();

    rho_shim_handle_print(hdl);

    mf = smuf_mdata_get_memfile_at_idx(mdata, smh->mf_idx);
    if (mf == NULL) {
        error = -EBADF;
        goto done;
    }

    error = smuf_map_fileuri(mf->f_lock_uri, SMUF_LOCKFILE_SIZE,
            &mf->f_pub_lock);
        
    if (mf->f_map_size > 0)
        error = smuf_map_fileuri(mf->f_segment_uri, mf->f_map_size,
                &mf->f_pub_seg);

done:
    RHO_TRACE_EXIT();
    return (error);
}

static ssize_t
smuf_checkpoint(void **checkpoint, void *mount_data)
{
    struct smuf_mdata *mdata = mount_data;
    uint64_t ident = 0;

    RHO_TRACE_ENTER();

    /* TODO: check error */
    (void)smuf_fork_rpc(mdata->agent, &ident);
    
    debug("smuf child ident = %llu\n", (unsigned long long)ident);

    mdata->ident = ident;
    *checkpoint = mdata;

    RHO_TRACE_EXIT();
    return (sizeof(*mdata));
}

static int
smuf_migrate(void *checkpoint, void **mount_data)
{
    int error = 0;
    struct smuf_mdata *mdata = NULL;
    struct rpc_agent *agent = NULL;

    RHO_TRACE_ENTER();

    mdata = rhoL_zalloc(sizeof(struct smuf_mdata));
    memcpy(mdata, checkpoint, sizeof(struct smuf_mdata));
    smuf_mdata_print(mdata);

    /* 
     * TODO: need to check if smuf_agent_open or smuf_rpc_child_attach
     * fails
     */
    // smuf_agent_close(mdata->agent); 
    agent = smuf_agent_open(mdata->server_uri, 
            mdata->ca_der[0] == 0x00 ? NULL : mdata->ca_der,
            mdata->ca_der_len);

    mdata->agent = agent;

    (void)smuf_child_attach_rpc(agent, mdata->ident);

    *mount_data = mdata;
    g_smuf_mdata = mdata;


    RHO_TRACE_EXIT();
    return (error);
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/

static int
smuf_open_new(struct smuf_mdata *mdata, const char *name, int *mf_idx)
{
    int error = 0;
    struct smuf_memfile *mf = NULL;

    RHO_TRACE_ENTER("name=\%s\"", name);

    error = smuf_mdata_new_memfile(mdata, name, &mf, mf_idx);
    if (error != 0)
        goto done;

    error = smuf_open_rpc(mdata->agent, name, &mf->f_remote_fd);
    if (error != 0)
        smuf_mdata_remove_memfile_at_idx(mdata, *mf_idx);

    error = smuf_map_fileuri(mf->f_lock_uri, SMUF_LOCKFILE_SIZE,
            &mf->f_pub_lock);
    if (error != 0) {
        /* 
         * XXX: corrupted state, as the server has created the
         * file, but we were unable to map it.
         */
        smuf_mdata_remove_memfile_at_idx(mdata, *mf_idx);
    }

done:
    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smuf_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    struct smuf_mdata * mdata = g_smuf_mdata;
    struct shim_smuf_handle *smh = &(hdl->info.smuf);
    char name[SMUF_MAX_NAME_SIZE] = {0};
    struct smuf_memfile *mf = NULL;
    int mf_idx = 0;

    RHO_TRACE_ENTER("flags=%d", flags);
    rho_shim_handle_print(hdl);

    rho_shim_dentry_relpath(dent, name, sizeof(name));

    mf = smuf_mdata_find_memfile(mdata, name, &mf_idx);
    if (mf != NULL) {
        mf->f_fd_refcnt++;
        goto done;
    }

    error = smuf_open_new(mdata, name, &mf_idx);

done:
   if (error == 0) {
        hdl->type = TYPE_SMUF;
        hdl->flags = flags;
        hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);

        smh->mf_idx = mf_idx;
    }

    RHO_TRACE_EXIT("error=%d", error);
    return (error);
}

static int
smuf_lookup(struct shim_dentry *dent)
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
smuf_mode(struct shim_dentry *dent, mode_t *mode)
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
smuf_unlink(struct shim_dentry *dir, struct shim_dentry *dent)
{
    (void)dir; 
    (void)dent;

    RHO_TRACE_ENTER();
    RHO_TRACE_EXIT();
    return (-ENOSYS);
}

struct shim_fs_ops smuf_fs_ops = {
        .mount       = &smuf_mount,
        .close       = &smuf_close,
        .mmap        = &smuf_mmap,
        .advlock     = &smuf_advlock,
        .hstat       = &smuf_hstat,
        .checkout    = &smuf_checkout,
        .checkin     = &smuf_checkin,
        .checkpoint  = &smuf_checkpoint,
        .migrate     = &smuf_migrate,
    };

struct shim_d_ops smuf_d_ops = {
        .open       = &smuf_open,
        .lookup     = &smuf_lookup,
        .mode       = &smuf_mode,
        .unlink     = &smuf_unlink,
    };
