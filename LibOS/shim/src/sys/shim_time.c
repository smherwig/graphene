/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * shim_time.c
 *
 * Implementation of system call "gettimeofday", "time" and "clock_gettime".
 */

#include <errno.h>
#include <pal.h>
#include <pal_error.h>
#include <shim_fs.h>
#include <shim_handle.h>
#include <shim_internal.h>
#include <shim_table.h>

#include <bearssl.h>

#include <rho_binascii.h>
#include <rho_buf.h>
#include <rho_crypto.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_rand.h>
#include <rho_sock.h>
#include <rho_str.h>

#define TNT_DEFAULT_TOLERANCE   (10 * 1000000L) /* microseconds */

/*
 * TNT response is 288 bytes:
 *   8 bytes for header (status:u32, bodylen:u32)
 *  20 bytes for body  (nonce:u64, sec:u64, usec:u32)
 *   4 bytes for sigsize (sigsize:u32)
 * 256 bytes for sig
 */
#define TNT_HEADER_LEN          8       /* status, bodylen */
#define TNT_BODY_LEN           20      /* nonce, sec, usec */
#define TNT_SIG_LEN           256      

struct tnt_client {
    struct rho_sock *sock;
    struct rho_buf *buf;
    char *url;  /* URL for server */

    br_rsa_public_key rsa_pk;

    long last_trusted_time; /* the last time we got from the trusted server */
    long last_host_time;    /* the last time we got from the untrusted host */

    uint32_t rate;        /* the % of times to get time from timeserver */ 
};

static struct tnt_client * tnt_client_create(const char *url,
        unsigned char *rsa_n, size_t rsa_n_len, unsigned char *rsa_e,
        size_t rsa_e_len, uint32_t rate);

static struct tnt_client * tnt_client_from_config(void);
static struct tnt_client * tnt_client_singleton(void);

static bool tnt_client_verify_signature(struct tnt_client *client,
        uint8_t *body, size_t bodylen, uint8_t *sig, size_t siglen);

static long tnt_client_request(struct tnt_client *client);
static long tnt_client_get_trusted_time_usec(struct tnt_client *client);
static long tnt_client_get_host_time_usec(struct tnt_client *client);
static long tnt_client_get_time_usec(struct tnt_client *client);
static long get_time_usec(void);


static bool did_read_config = false;
static struct tnt_client *g_tnt_client = NULL;


static struct tnt_client *
tnt_client_create(const char *url, unsigned char *rsa_n, size_t rsa_n_len,
        unsigned char *rsa_e, size_t rsa_e_len, uint32_t rate)
{
    struct tnt_client *client = NULL;

    //RHO_TRACE_ENTER("url=\"%s\" rate=%lu", url, (unsigned long)rate);

    client = rhoL_zalloc(sizeof(*client));
    client->buf = rho_buf_create();
    client->sock = rho_sock_open_url(url);
    if (client->sock == NULL) {
        rho_warn("rho_sock_open_url(\"%s\") returned NULL", url);
        goto done;
    }

    client->rsa_pk.n = rhoL_malloc(rsa_n_len);
    memcpy(client->rsa_pk.n, rsa_n, rsa_n_len);
    client->rsa_pk.nlen = rsa_n_len;

    client->rsa_pk.e = rhoL_malloc(rsa_e_len);
    memcpy(client->rsa_pk.e, rsa_e, rsa_e_len);
    client->rsa_pk.elen = rsa_e_len;

    client->rate= rate;

done:
    //RHO_TRACE_EXIT();
    return (client);
}

static struct tnt_client *
tnt_client_from_config(void)
{
    struct tnt_client *client = NULL;
    ssize_t len = 0;
    char cfgval[CONFIG_MAX] = { 0 };
	unsigned char rsa_n[256];
    size_t rsa_n_len = 0;
	unsigned char rsa_e[3];
    size_t rsa_e_len = 0;
    uint32_t rate = 0;
    char *url = NULL;

    //RHO_TRACE_ENTER();

    len = get_config(root_config, "timeserver.rsa_n", cfgval, sizeof(cfgval));
    if (len <= 0) {
        rho_warn("timeserver.rsa_n not in config");
        goto done;
    }
    rsa_n_len = rho_binascii_hex2bin(rsa_n, cfgval);

    rho_memzero(cfgval, sizeof(cfgval));
    len = get_config(root_config, "timeserver.rsa_e", cfgval, sizeof(cfgval));
    if (len <= 0) {
        rho_warn("timeserver.rsa_e not in config");
        goto done;
    }
    rsa_e_len = rho_binascii_hex2bin(rsa_e, cfgval);

    rho_memzero(cfgval, sizeof(cfgval));
    len = get_config(root_config, "timeserver.rate", cfgval, sizeof(cfgval));
    if (len <= 0) {
        rho_warn("timeserver.rate not in config");
        goto done;
    }
    rate = rho_str_touint32(cfgval, 10);

    rho_memzero(cfgval, sizeof(cfgval));
    len = get_config(root_config, "timeserver.url", cfgval, sizeof(cfgval));
    if (len <= 0) {
        rho_warn("timeserver.url not in config");
        goto done;
    }
    url = rhoL_strdup(cfgval);
    client = tnt_client_create(url, rsa_n, rsa_n_len, rsa_e, rsa_e_len, rate);

done:
    //RHO_TRACE_EXIT("client=%p", client);
    return (client);
}

static struct tnt_client *
tnt_client_singleton(void)
{
    //RHO_TRACE_ENTER();

    if (!did_read_config) {
        g_tnt_client = tnt_client_from_config();
        did_read_config = true;
    }

    //RHO_TRACE_EXIT("g_tnt_client=%p", g_tnt_client);
    return (g_tnt_client);
}

static bool
tnt_client_verify_signature(struct tnt_client *client, uint8_t *body,
        size_t bodylen, uint8_t *sig, size_t siglen)
{
    bool ret = false;
    uint32_t vrfy_ret = 0;
    br_rsa_pkcs1_vrfy vrfy = NULL;
    unsigned char hashval[32] = { 0 };
    struct rho_md *md = NULL;
    uint8_t bodyhash[32] = { 0 };

    //RHO_TRACE_ENTER("bodylen=%lu, siglen=%lu", 
    //        (unsigned long)bodylen, (unsigned long)siglen);

    /* returns 1 if verification is good; 0 if bad */
    vrfy = br_rsa_pkcs1_vrfy_get_default();
    vrfy_ret = vrfy(
            sig,
            siglen,
            BR_HASH_OID_SHA256,
            32,
            &client->rsa_pk,
            hashval);

    if (vrfy_ret == 0) {
        rho_warn("tnt rsa verification failed!\n");
        goto done;
    }

    md = rho_md_create(RHO_MD_SHA256, NULL, 0);
    rho_md_update(md, body, bodylen);
    rho_md_finish(md, bodyhash);
    rho_md_destroy(md);
    if (!rho_mem_equal(hashval, bodyhash, 32)) {
        rho_warn("tnt signature does not match hash value!\n");
        goto done;
    }

    ret = true;

done:
    //RHO_TRACE_EXIT("ret=%d\n", ret);
    return (ret);
}

static long
tnt_client_request(struct tnt_client *client)
{
    struct rho_buf *buf = client->buf;
    struct rho_sock *sock = client->sock;
    ssize_t n = 0;
    uint64_t nonce = 0;
    uint32_t status = 0;
    uint32_t bodylen = 0;
    uint64_t nonce_resp = 0;
    uint64_t sec = 0;
    uint32_t usec = 0;
    uint32_t sigsize = 0;
    uint8_t body[TNT_BODY_LEN] = { 0 };
    uint8_t sig[TNT_SIG_LEN] = { 0 };

    //RHO_TRACE_ENTER();

    nonce = rho_rand_u64();

    rho_buf_clear(buf);
    rho_buf_writeu64be(buf, nonce);
    rho_buf_rewind(buf);
    n = rho_sock_send_buf(sock, buf, rho_buf_length(buf));
    if (n < 0 || ((unsigned long)n) != rho_buf_length(buf)) {
        rho_warn("error: only sent %ld", n);
        goto done;
    }

    rho_buf_clear(buf);
    /* TODO: how big is the expected response? */
    n = rho_sock_recv_buf(sock, buf, 1024);
    if (n <= 0) {
        rho_warn("error: received %ld", n);
        goto done;
    }


    rho_buf_rewind(buf);

    /* header */
    rho_buf_readu32be(buf, &status);
    rho_buf_readu32be(buf, &bodylen);

    /* body */
    rho_buf_readu64be(buf, &nonce_resp);
    rho_buf_readu64be(buf, &sec);
    rho_buf_readu32be(buf, &usec);

    rho_buf_seek(buf, TNT_HEADER_LEN, SEEK_SET);
    rho_buf_read(buf, body, TNT_BODY_LEN);

    /* signature */
    rho_buf_readu32be(buf, &sigsize);
    rho_buf_read(buf, sig, sigsize);

    if (nonce != nonce_resp)
        rho_warn("nonce (%llu) does not match nonce returned by timerserver (%llu)\n",
                (unsigned long long)nonce, (unsigned long long)nonce_resp);

    if (!tnt_client_verify_signature(client, body, TNT_BODY_LEN, sig,
                TNT_SIG_LEN)) {
        rho_warn("tnt signature is invalid!\n");
    }
    
done:
    /* TODO: return sec + usec */
    return ((sec * 1000000UL) + usec);
}

static long
tnt_client_get_trusted_time_usec(struct tnt_client *client)
{
    long trusted_time = 0;
    long host_time = 0;
    long diff = 0;

    RHO_TRACE_ENTER();

    host_time = DkSystemTimeQuery();
    client->last_host_time = host_time;

    trusted_time = tnt_client_request(client);
    if (trusted_time > host_time)
        diff = trusted_time - host_time;
    else
        diff = host_time - trusted_time;

    if (diff > TNT_DEFAULT_TOLERANCE)
        rho_warn("trusted time %ld and host time %ld differ significanly!\n",
                trusted_time, host_time);

    RHO_TRACE_EXIT();
    return (trusted_time);
}

static long
tnt_client_get_host_time_usec(struct tnt_client *client)
{
    long time = 0;

    RHO_TRACE_ENTER();

    time = DkSystemTimeQuery();
    if (time < client->last_host_time)
        rho_warn("current host time %ld is behind preivous host time %ld!\n",
                time, client->last_host_time);

    client->last_host_time = time;

    RHO_TRACE_EXIT();
    return (time);
}

/*
 * TODO: allow different strategies for when to call to the
 * timerserver.  Currently, we only support configuration of
 * a percent value (that is, of all time-related syscalls, what
 * percentage should go to the timeserver).  We then uniformly,
 * at random draw, when each such timeserver request occurs.
 *
 *
 *  If you want 10% of the time, then 0.1
 *      0.1 * 10000 = 1000
 *  If you want 1% of the time, then 0.01
 *  If you want 0.1% of the time, then 0.001
 *  If you want 0.01% of the time, then 0.0001
 */
static long
tnt_client_get_time_usec(struct tnt_client *client)
{
    long time = 0;
    uint32_t r = 0;

    RHO_TRACE_ENTER();

    r = rho_rand_uniform_u32(0, 10000);
    if (r < client->rate)
        time = tnt_client_get_trusted_time_usec(client);
    else
        time = tnt_client_get_host_time_usec(client);

    RHO_TRACE_EXIT();
    return (time);
}

/* this function will replace the calls to DkSystemTimeQuery */
static long
get_time_usec(void)
{
    struct tnt_client *client = NULL;
    long time = 0;

    /* get client singleton */
    client = tnt_client_singleton();
    if (client != NULL)
        time = tnt_client_get_time_usec(client);
    else
        time = DkSystemTimeQuery();
    return (time);
}



int shim_do_gettimeofday(struct __kernel_timeval* tv, struct __kernel_timezone* tz) {
    if (!tv)
        return -EINVAL;

    if (test_user_memory(tv, sizeof(*tv), true))
        return -EFAULT;

    if (tz && test_user_memory(tz, sizeof(*tz), true))
        return -EFAULT;

    //long time = DkSystemTimeQuery(); SMHERWIG
    long time = get_time_usec();

    if (time == -1)
        return -PAL_ERRNO();

    tv->tv_sec  = time / 1000000;
    tv->tv_usec = time % 1000000;
    return 0;
}

time_t shim_do_time(time_t* tloc) {
    //long time = DkSystemTimeQuery(); SMHERWIG
    long time = get_time_usec();

    if (time == -1)
        return -PAL_ERRNO();

    if (tloc && test_user_memory(tloc, sizeof(*tloc), true))
        return -EFAULT;

    time_t t = time / 1000000;

    if (tloc)
        *tloc = t;

    return t;
}

int shim_do_clock_gettime(clockid_t which_clock, struct timespec* tp) {
    /* all clock are the same */
    __UNUSED(which_clock);

    if (!tp)
        return -EINVAL;

    if (test_user_memory(tp, sizeof(*tp), true))
        return -EFAULT;

    //long time = DkSystemTimeQuery(); SMHERWIG
    long time = get_time_usec();

    if (time == -1)
        return -PAL_ERRNO();

    tp->tv_sec  = time / 1000000;
    tp->tv_nsec = (time % 1000000) * 1000;
    return 0;
}

int shim_do_clock_getres(clockid_t which_clock, struct timespec* tp) {
    /* all clock are the same */
    __UNUSED(which_clock);

    if (!tp)
        return -EINVAL;

    if (test_user_memory(tp, sizeof(*tp), true))
        return -EFAULT;

    tp->tv_sec  = 0;
    tp->tv_nsec = 1000;
    return 0;
}
