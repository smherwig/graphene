/*
 * fs.c
 *
 * The 'smtcad' filesystem.
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

#define SMTCAD_LOCKOP_LOCK       1
#define SMTCAD_LOCKOP_UNLOCK     2

#define SMTCAD_COUNTER_SIZE 4
#define SMTCAD_IV_SIZE 12
#define SMTCAD_KEY_SIZE 32
#define SMTCAD_TAG_SIZE 16

#define SMTCAD_AD_SIZE \
    (SMTCAD_COUNTER_SIZE + SMTCAD_KEY_SIZE + SMTCAD_IV_SIZE + SMTCAD_TAG_SIZE)

#define SMTCAD_AD_COUNTER_POS  0
#define SMTCAD_AD_KEY_POS      SMTCAD_COUNTER_SIZE
#define SMTCAD_AD_IV_POS       SMTCAD_AD_KEY_POS + SMTCAD_KEY_SIZE
#define SMTCAD_AD_TAG_POS      SMTCAD_AD_IV_POS + SMTCAD_IV_SIZE

struct smtcad_client {
    struct rpc_agent *agent;
};

struct smtcad_memfile {
    char name[TCAD_MAX_NAME_SIZE];
    size_t size;
    void *pub_mem;
    void *priv_mem;
    uint8_t iv[SMTCAD_IV_SIZE];
    uint8_t key[SMTCAD_KEY_SIZE];
    uint8_t tag[SMTCAD_TAG_SIZE];
    struct rho_ticketlock *tl;
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
struct smtcad_mdata {
    char url[512];           /* URL for server */
    uint64_t ident;             /* auth cookie for child */
    unsigned char ca_der[4096];
    size_t  ca_der_len;
    uint32_t fd_bitmap;
    struct smtcad_memfile fd_tab[32];
    struct smtcad_client *client;
};


/******************************************
 * SERIALIZE/DESERIALIZE HELPERS
 ******************************************/

static void
smtcad_pack_assocdata(const struct smtcad_memfile *mf, void *ad)
{
    int32_t turn_be = htobe32(mf->turn);

    memcpy(ad,                    &turn_be, sizeof(turn_be));
    memcpy(ad + SMTCAD_AD_KEY_POS, mf->key, SMTCAD_KEY_SIZE);
    memcpy(ad + SMTCAD_AD_IV_POS,  mf->iv,  SMTCAD_IV_SIZE);
    memcpy(ad + SMTCAD_AD_TAG_POS, mf->tag, SMTCAD_TAG_SIZE);
}

static void
smtcad_unpack_assocdata(const void *ad, struct smtcad_memfile *mf)
{
    memcpy(mf->iv,  ad + SMTCAD_AD_IV_POS,  SMTCAD_IV_SIZE);
    memcpy(mf->tag, ad + SMTCAD_AD_TAG_POS, SMTCAD_TAG_SIZE);
}

/********************************* 
 * AES-GCM
 *********************************/

static void
smtcad_encrypt(uint8_t *data, size_t data_len, const uint8_t *key,
        const uint8_t *iv, uint8_t *tag)
{
    br_aes_x86ni_ctr_keys ctx;
    br_gcm_context gc;

    br_aes_x86ni_ctr_init(&ctx, key, SMTCAD_KEY_SIZE);
    br_gcm_init(&gc, &ctx.vtable, br_ghash_pclmul);
    br_gcm_reset(&gc, iv, SMTCAD_IV_SIZE); 
    /* use br_gc_aad_inject, if needed */
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 1, data, data_len); /* encrypts in-place */
    br_gcm_get_tag(&gc, tag);
}

static void
smtcad_decrypt(uint8_t *data, size_t data_len, const uint8_t *key,
        const uint8_t *iv, uint8_t *tag)
{
    br_aes_x86ni_ctr_keys ctx;
    br_gcm_context gc;

    br_aes_x86ni_ctr_init(&ctx, key, SMTCAD_KEY_SIZE);
    br_gcm_init(&gc, &ctx.vtable, br_ghash_pclmul);
    br_gcm_reset(&gc, iv, SMTCAD_IV_SIZE); 
    /* use br_gc_aad_inject, if needed */
    br_gcm_flip(&gc);
    br_gcm_run(&gc, 0, data, data_len); /* encrypts in-place */
    br_gcm_get_tag(&gc, tag);
}

/******************************************
 * MEMFILE
 *
 * A MEMFILE is either a file that acts as
 * a lock, or a file that acts as a lock
 * with some associated memory.
 ******************************************/ 
static int
smtcad_memfile_make_map(struct smtcad_memfile *mf, size_t size)
{
    int error = 0;

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

    rho_rand_bytes(mf->iv, SMTCAD_IV_SIZE);
    rho_rand_bytes(mf->key, SMTCAD_KEY_SIZE);
    smtcad_encrypt(mf->priv_mem, mf->size, mf->key, mf->iv, mf->tag);
    memcpy(mf->pub_mem, mf->priv_mem, mf->size);

    goto succeed;

fail:
    if (mf->pub_mem != NULL)
        DkVirtualMemoryFree(mf->pub_mem, size);
succeed:
    return (error);
}

static void
smtcad_memfile_clear(struct smtcad_memfile *mf)
{
    if (mf->pub_mem != NULL)
        DkVirtualMemoryFree(mf->pub_mem, mf->size);

    if (mf->priv_mem != NULL)
        DkVirtualMemoryFree(mf->priv_mem, mf->size);

    if (mf->tl != NULL)
        DkVirtualMemoryFree(mf->tl, sizeof(struct rho_ticketlock));

    rho_memzero(mf, sizeof(*mf));
}

/* decrypt file into private memory */
static int
smtcad_memfile_map_in(struct smtcad_memfile *mf)
{
    int error = 0;
    uint8_t actual_tag[SMTCAD_TAG_SIZE] = {0};

    memcpy(mf->priv_mem, mf->pub_mem, mf->size);
    smtcad_decrypt(mf->priv_mem, mf->size, mf->key, mf->iv, actual_tag);
    if (!rho_mem_equal(mf->tag, actual_tag, SMTCAD_TAG_SIZE)) {
        rho_warn("on memfile \"%s\"map in, tag does not match trusted tag",
                mf->name);
        error = -EBADE;  /* invalid exchange */
    }

    return (error);
}

/* encrypt private memory to file */
static void
smtcad_memfile_map_out(struct smtcad_memfile *mf)
{
    rho_rand_bytes(mf->iv, SMTCAD_IV_SIZE);
    smtcad_encrypt(mf->priv_mem, mf->size, mf->key, mf->iv, mf->tag);
    memcpy(mf->pub_mem, mf->priv_mem, mf->size);
}

/**********************************************************
 * MOUNT DATA
 *
 * (acts like a fs-specific file descriptor table
 **********************************************************/
static int
smtcad_fd_bitmap_ffc(uint32_t bitmap)
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

static struct smtcad_mdata *
smtcad_mdata_create(const char *uri, unsigned char *ca_der,
        size_t ca_der_len)
{
    struct smtcad_mdata *mdata = NULL;
    
    debug("> smtcad_mdata_create\n");

    mdata = rhoL_zalloc(sizeof(struct smtcad_mdata));
    memcpy(mdata->url, uri, strlen(uri));
    if (ca_der != NULL) {
        memcpy(mdata->ca_der, ca_der, ca_der_len);
        mdata->ca_der_len = ca_der_len;
    }

    debug("< smtcad_mdata_create\n");
    return (mdata);
}

static void
smtcad_mdata_print(const struct smtcad_mdata *mdata)
{
    debug("mtcad_mdata = {url: %s, ident:%llu, ca_der[0]:%02x, ca_der_len:%u}\n",
            mdata->url, (unsigned long long)mdata->ident, mdata->ca_der[0],
            mdata->ca_der_len);
}

static struct smtcad_memfile *
smtcad_mdata_new_memfile(struct smtcad_mdata *mdata, const char *name)
{
    int i = 0;
    struct smtcad_memfile *mf = NULL;
    struct rho_ticketlock *tl = NULL;

    i = smtcad_fd_bitmap_ffc(mdata->fd_bitmap);
    if (i == -1)
        goto done;  /* fd table full */

    RHO_BITOPS_SET((uint8_t *)&mdata->fd_bitmap, i);
    mf = &(mdata->fd_tab[i]);
    rho_memzero(mf, sizeof(*mf));
    memcpy(mf->name, name, strlen(name));

    /* TODO: need to make this memory outside-of-enclave and SHARED */
    tl = DkVirtualMemoryAlloc(NULL, sizeof(struct rho_ticketlock), 0,
            PAL_PROT((PROT_READ|PROT_WRITE), 0));
    if (tl == NULL)
        rho_errno_die(PAL_ERRNO, "mmap");

    tl->ticket_number = 0;
    tl->turn = 0;

    mf->tl = tl;

done:
    return (mf);
}

/**********************************************************
 * SMTCAD CLIENT
 * (mostly a wrapper around an rpc_agent)
 **********************************************************/

static struct smtcad_client *
smtcad_client_open(const char *url, unsigned char *ca_der, size_t ca_der_len)
{
    struct smtcad_client *client = NULL;
    struct rho_ssl_params *params = NULL;
    struct rho_ssl_ctx *ctx = NULL;
    struct rho_sock *sock = NULL;

    sock = rho_sock_open_url(url);
    client = rhoL_zalloc(sizeof(*client));
    client->agent = rpc_agent_create(sock);

    if (ca_der != NULL) {
        debug("smtcad client using TLS\n");
        params = rho_ssl_params_create();
        rho_ssl_params_set_mode(params, RHO_SSL_MODE_CLIENT);
        rho_ssl_params_set_protocol(params, RHO_SSL_PROTOCOL_TLSv1_2);
        rho_ssl_params_set_ca_der(params, ca_der, ca_der_len);
        ctx = rho_ssl_ctx_create(params);
        rho_ssl_wrap(sock, ctx);
        //rho_ssl_params_destroy(params);
    }

    return (client);
}

static void
smtcad_client_close(struct smtcad_client *client)
{
    rpc_agent_destroy(client->agent);
    rhoL_free(client);
}

/********************************* 
 * FILE/FILESYSTEM OPERATIONS
 *********************************/

/*
 * Mount should allocated a struct smtcad_mountdata and return it
 * in the mount_data out parameter.
 *
 * uri is the host URI for the resource to be "mounted", and
 * root is the guest mountpoint.
 */
static int
smtcad_mount(const char *uri, const char *root, void **mount_data)
{
    int error = 0;
    char ca_hex[CONFIG_MAX] = { 0 };
    unsigned char *ca_der = NULL;
    ssize_t len = 0;
    struct smtcad_mdata *mdata = NULL;
    struct smtcad_client *client = NULL;

    debug("> smtcad_mount(uri=%s, root=%s, mount_data=*)\n", uri, root);

    len = get_config(root_config, "phoenix.ca_der", ca_hex, sizeof(ca_hex));
    if (len > 0) {
        debug("READ phoenix.ca_der (size=%ld)\n", len);
        ca_der = rhoL_malloc(len / 2);
        rho_binascii_hex2bin(ca_der, ca_hex);
    }

    client = smtcad_client_open(uri, ca_der, len / 2);
    error = tcad_new_fdtable(client->agent);
    mdata = smtcad_mdata_create(uri, ca_der, len / 2);
    mdata->client = client;
    *mount_data = mdata;
    debug("setting smtcad mount data (%p)\n", mdata);

    /* TODO: need to propagate an error if we can't open the client */
    if (ca_der != NULL)
        rhoL_free(ca_der);
    debug("< smtcad_mount\n");
    return (error);
}

static int
smtcad_close(struct shim_handle *hdl)
{
    int error = 0;
    struct smtcad_mdata *mdata = hdl->fs->data;
    struct smtcad_client *client = mdata->client;
    struct smtcad_memfile *mf = NULL;
    uint32_t fd = 0;

    fd = hdl->info.smtcad.fd;
    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    debug("> smtcad_close(fd=%u)\n", fd);

    mf = &(mdata->fd_tab[fd]);
    smtcad_memfile_clear(mf);
    RHO_BITOPS_CLR((uint8_t *)&mdata->fd_tab, fd);
    error = tcad_destroy_entry(client->agent, fd);
    if (error != 0)
        error = -error;

    debug("< smtcad_close (ret=%d)\n", error);
    return (error);
}

static int
smtcad_mmap(struct shim_handle *hdl, void **addr, size_t size,
                        int prot, int flags, off_t offset)
{
    int error = 0;
    struct smtcad_mdata *mdata = hdl->fs->data;
    char name[TCAD_MAX_NAME_SIZE] = { 0 };
    struct smtcad_memfile *mf = NULL;
    uint32_t fd = 0;

    (void)prot;
    (void)flags;
    (void)offset;

    fd = hdl->info.smtcad.fd;
    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    rho_shim_dentry_relpath(hdl->dentry, name, sizeof(name));
    debug("> smtcad_mmap(fd=%u (%s), size=%lu)\n",
            fd, name, (unsigned long) size);

    mf = &(mdata->fd_tab[fd]);
    error = smtcad_memfile_make_map(mf, size);
    if (error == -1)
        error = -PAL_ERRNO;

    debug("< smtcad_mmap (ret=%d)\n", error);
    return (error);
}

static int
smtcad_advlock_lock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smtcad_mdata *mdata = NULL;
    struct smtcad_client *client = NULL;
    uint32_t fd = 0;
    struct smtcad_memfile *mf = NULL;
    uint8_t ad[SMTCAD_AD_SIZE] = {0};
    size_t ad_size = 0;

    fd = hdl->info.smtcad.fd;
    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    debug("> smtcad_advlock_lock(fd=%u, hdl=%p, hdl->fs=%p, hdl->fs->data=%p)\n",
            fd, hdl, hdl->fs, hdl->fs->data);

    mf = &(mdata->fd_tab[fd]);
    mdata = hdl->fs->data;
    client = mdata->client;

    mf->turn = rho_ticketlock_lock(mf->tl);
    error = tcad_cmp_and_get(client->agent, fd, mf->turn, ad, &ad_size);
    if (error != 0) {
        error = -error;
        goto done;
    }
        
    smtcad_unpack_assocdata(ad, mf);
    error = smtcad_memfile_map_in(mf);

done:
    debug("< smtcad_advlock_lock\n");
    return (error);
}

static int
smtcad_advlock_unlock(struct shim_handle *hdl, struct flock *flock)
{
    int error = 0;
    struct smtcad_mdata *mdata = hdl->fs->data;
    struct smtcad_client *client = mdata->client;
    uint32_t fd = 0;
    struct smtcad_memfile *mf = NULL;
    uint8_t ad[SMTCAD_AD_SIZE] = {0};

    fd = hdl->info.smtcad.fd;
    RHO_ASSERT(RHO_BITOPS_ISSET((uint8_t *)&mdata->fd_bitmap, fd));

    mf = &(mdata->fd_tab[fd]);

    debug("> smtcad_advlock_unlock(fd=%u), mf->size:%lu\n",
            fd, (unsigned long)mf->size);

    smtcad_memfile_map_out(mf);
    smtcad_pack_assocdata(mf, ad);

    error = tcad_inc_and_set(client->agent, fd, ad, sizeof(ad));
    if (error != 0) {
        error = -error;
        goto done;
    }

    /* XXX: not sure what to do here to avoid an inconsistent state */
    rho_ticketlock_unlock(mf->tl);

done:
    debug("< smtcad_advlock_unlock (ret=%d)\n", error);
    return (error);
}

static int
smtcad_advlock(struct shim_handle *hdl, int op, struct flock *flock)
{
    int error = 0;

    debug("> smtcad_advlock(op=%d)\n", op);

    if (flock->l_type == F_WRLCK)
        error = smtcad_advlock_lock(hdl, flock);
    else if (flock->l_type == F_UNLCK)
        error = smtcad_advlock_unlock(hdl, flock);
    else
        error = -EINVAL;

    debug("< smtcad_advlock\n");
    return (error);
}

static int
smtcad_checkpoint(void **checkpoint, void *mount_data)
{
    struct smtcad_mdata *mdata = mount_data;
    struct smtcad_client *client = mdata->client;
    uint64_t ident = 0;

    debug("> smtcad_checkpoint\n");

    /* TODO: check error */
    (void)tcad_fork(client->agent, &ident);
    
    debug("smtcad child ident = %llu\n", (unsigned long long)ident);

    mdata->ident = ident;
    *checkpoint = mdata;

    debug("< smtcad_checkpoint\n");
    return (sizeof(struct smtcad_mdata));
}

static int
smtcad_migrate(void *checkpoint, void **mount_data)
{
    struct smtcad_mdata *mdata = NULL;
    struct smtcad_client *client = NULL;

    debug("> smtcad_migrate\n");

    mdata = rhoL_zalloc(sizeof(struct smtcad_mdata));
    memcpy(mdata, checkpoint, sizeof(struct smtcad_mdata));
    smtcad_mdata_print(mdata);

    /* 
     * TODO: need to check if smtcad_client_open or tcad_child_attach
     * fails
     */
    //mtcad_client_close(mdata->client); 
    client = smtcad_client_open(mdata->url, 
            mdata->ca_der[0] == 0x00 ? NULL : mdata->ca_der,
            mdata->ca_der_len);

    (void)tcad_child_attach(client->agent, mdata->ident);

    *mount_data = mdata;

    debug("< smtcad_migrate\n");
    return (0);
}

/********************************* 
 * DIRECTORY OPERATIONS
 *********************************/
static int
smtcad_open(struct shim_handle *hdl, struct shim_dentry *dent, int flags)
{
    int error = 0;
    uint8_t ad[SMTCAD_AD_SIZE] = {0};
    struct smtcad_mdata *mdata = NULL;
    struct smtcad_client *client = NULL; 
    uint32_t fd = 0;
    struct smtcad_memfile *mf = NULL;
    char name[TCAD_MAX_NAME_SIZE] = { 0 };

    debug("> smtcad_open(hdl=(%p), dent=(%p), dent->fs=(%p), dent->fs->data=(%p), flags=0x%08x\n", 
            hdl, dent, dent->fs, dent->fs->data, flags);
    rho_shim_dentry_print(dent);
    //debug("hdl->fs->data=%p\n", hdl->fs->data);
    debug("dent->fs->data=%p\n", dent->fs->data);

    mdata = dent->fs->data;
    smtcad_mdata_print(mdata);
    client = mdata->client;

    /* get path */
    rho_shim_dentry_relpath(dent, name, sizeof(name));

    mf = smtcad_mdata_new_memfile(mdata, name);
    if (mf == NULL) {
        error = -ENFILE;
        goto done;
    }

    smtcad_pack_assocdata(mf, ad);
    error = tcad_create_entry(client->agent, name, ad, sizeof(ad), &fd);
    if (error != 0) {
        error= -error;
        goto done;
    }

    /* fill in handle */
    hdl->type = TYPE_SMTCAD;
    hdl->flags = flags;
    hdl->acc_mode = ACC_MODE(flags & O_ACCMODE);
    hdl->info.smtcad.fd = fd;

done:
    debug("< smtcad_open (ret=%d)\n", error);
    return (error);
}

static int
smtcad_lookup(struct shim_dentry *dent, bool force)
{
    debug("> smtcad_lookup(dent=*, force=%d)\n", force);
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
    debug("< smtcad_lookup\n");
    return (0);
}

static int 
smtcad_mode(struct shim_dentry *dent, mode_t *mode, bool force)
{
    debug("> smtcad_mode\n");
    (void)mode;

    rho_shim_dentry_print(dent);
    debug("dent->fs=%p\n", dent->fs);
    debug("dent->fs->data=%p\n", dent->fs->data);
    debug("mode=%p\n", mode);

    *mode = 0777;

    debug("< smtcad_mode\n");
    return (0);
}

static int
smtcad_unlink(struct shim_dentry *dir, struct shim_dentry *dent)
{
    debug("> smtcad_unlink(dir=*, dent=*)\n");
    (void)dir; (void)dent;
    debug("< smtcad_unlink\n");
    return (-ENOSYS);
}

struct shim_fs_ops smtcad_fs_ops = {
        .mount       = &smtcad_mount,      /**/
        .close       = &smtcad_close,      /**/
        .mmap        = &smtcad_mmap,       /**/
        .advlock     = &smtcad_advlock,
        .checkpoint  = &smtcad_checkpoint, /**/
        .migrate     = &smtcad_migrate,    /**/
    };

struct shim_d_ops smtcad_d_ops = {
        .open       = &smtcad_open,        /**/
        .lookup     = &smtcad_lookup,      /**/
        .mode       = &smtcad_mode,        /**/
        .unlink     = &smtcad_unlink,      /**/
    };
