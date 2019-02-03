/* -*- mode:c; c-file-style:"k&r"; c-basic-offset: 4; tab-width:4; indent-tabs-mode:nil; mode:auto-fill; fill-column:78; -*- */
/* vim: set ts=4 sw=4 et tw=78 fo=cqt wm=0: */

/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/*
 * shim_time.c
 *
 * Implementation of system call "gettimeofday", "time" and "clock_gettime".
 */

#include <shim_internal.h>
#include <shim_table.h>
#include <shim_handle.h>
#include <shim_fs.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

#include <bearssl.h>

#include <rho_buf.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_rand.h>
#include <rho_sock.h>

#define TNT_DEFAULT_TOLERANCE   (10 * 1000000UL) /* microseconds */
#define TNT_DEFAULT_PERIOD      5       /* check server every 5 calls */
#define TNT_BODYLEN             20      /* nonce, sec, usec */

struct tnt_client {
    struct rho_sock *sock;
    struct rho_buf *buf;
    char *url;  /* URL for server */

    br_rsa_public_key rsa_pk;

    long last_trusted_time; /* the last time we got from the trusted server */
    long last_host_time;    /* the last time we got from the untrusted host */

    uint32_t period;        /* the number of times to get from untrusted host
                               between getting from trusted server */
    uint32_t n;
};

static size_t hextobin(unsigned char *dst, const char *src);

static struct tnt_client * tnt_client_create(const char *url,
        unsigned char *rsa_n, size_t rsa_n_len, unsigned char *rsa_e,
        size_t rsa_e_len);

static struct tnt_client * tnt_client_from_config(void);
static struct tnt_client * tnt_client_singleton(void);

#if 0
static void tnt_client_verify_signature(struct tnt_client *client,
        uint8_t *body, size_t bodylen, uint8_t *sig, size_t siglen);
#endif

static long tnt_client_request(struct tnt_client *client);
static long tnt_client_get_trusted_time_usec(struct tnt_client *client);
static long tnt_client_get_host_time_usec(struct tnt_client *client);
static long tnt_client_get_time_usec(struct tnt_client *client);
static long get_time_usec(void);


static bool did_read_config = false;
static struct tnt_client *g_tnt_client = NULL;

static size_t
hextobin(unsigned char *dst, const char *src)
{
    size_t num; 
    unsigned acc; 
    int z;

    num = 0; 
    z = 0; 
    acc = 0; 
    while (*src != 0) { 
        int c = *src ++;
        if (c >= '0' && c <= '9') {
            c -= '0'; 
        } else if (c >= 'A' && c <= 'F') {
            c -= ('A' - 10); 
        } else if (c >= 'a' && c <= 'f') {
            c -= ('a' - 10); 
        } else {
            continue;
        }
        if (z) {
            *dst ++ = (acc << 4) + c; 
            num ++;
        } else {
            acc = c; 
        }
        z = !z;
    }    
    return num; 
}

static struct tnt_client *
tnt_client_create(const char *url, unsigned char *rsa_n, size_t rsa_n_len,
        unsigned char *rsa_e, size_t rsa_e_len)
{
    struct tnt_client *client = NULL;

    debug("> tnt_client_create(url=\"%s\")\n", url);

    client = rhoL_zalloc(sizeof(*client));
    client->buf = rho_buf_create();
    client->sock = rho_sock_open_url(url);

    client->rsa_pk.n = rhoL_malloc(rsa_n_len);
    memcpy(client->rsa_pk.n, rsa_n, rsa_n_len);
    client->rsa_pk.nlen = rsa_n_len;

    client->rsa_pk.e = rhoL_malloc(rsa_e_len);
    memcpy(client->rsa_pk.e, rsa_e, rsa_e_len);
    client->rsa_pk.elen = rsa_e_len;

    client->period = TNT_DEFAULT_PERIOD;

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
    char *url = NULL;

    len = get_config(root_config, "timeserver.rsa_n", cfgval, sizeof(cfgval));
    if (len <= 0)
        goto done;
    rsa_n_len = hextobin(rsa_n, cfgval);

    rho_memzero(cfgval, sizeof(cfgval));
    len = get_config(root_config, "timeserver.rsa_e", cfgval, sizeof(cfgval));
    if (len <= 0)
        goto done;
    rsa_e_len = hextobin(rsa_e, cfgval);

    rho_memzero(cfgval, sizeof(cfgval));
    len = get_config(root_config, "timeserver.url", cfgval, sizeof(cfgval));
    if (len <= 0)
        goto done;
    url = rhoL_strdup(cfgval);
    client = tnt_client_create(url, rsa_n, rsa_n_len, rsa_e, rsa_e_len);

done:
    return (client);
}

static struct tnt_client *
tnt_client_singleton(void)
{
    if (!did_read_config) {
        g_tnt_client = tnt_client_from_config();
        did_read_config = true;
    }

    return (g_tnt_client);
}

#if 0
static void
tnt_client_verify_signature(struct tnt_client *client, uint8_t *body,
        size_t bodylen, uint8_t *sig, size_t siglen)
{
    (void)client;
    (void)body;
    (void)bodylen;
    (void)sig;
    (void)siglen;

    br_rsa_pkcs1_vrfy vrfy = NULL;
    unsigned char hashval[32] = { 0 };

    vrfy = br_rsa_pkcs1_vrfy_get_default();
    vrfy_ret = vrfy(
            sig,
            siglen,
            BR_HASH_OID_SHA256,
            32,
            &rsa_pk,
            hashval);

    /* XXX: necessary? */
    memcmp(hashval, msg_sha256, 32);
}
#endif

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
    uint8_t body[TNT_BODYLEN] = { 0 };
    uint8_t sig[TNT_BODYLEN] = { 0 };

    nonce = rho_rand_uint64();
    debug("timeclient nonce=%llu\n", (unsigned long long)nonce);
    
    rho_buf_clear(buf);
    rho_buf_writeu64be(buf, nonce);
    rho_buf_rewind(buf);
    n = rho_sock_send_buf(sock, buf, rho_buf_length(buf));
    if (n != rho_buf_length(buf))
        goto done;

    rho_buf_clear(buf);
    /* TODO: how big is the expected response? */
    n = rho_sock_recv_buf(sock, buf, 1024);
    if (n <= 0)
        goto done;

    debug("timeserver response is %ld bytes\n", (long)n);
    rho_buf_rewind(buf);

    /* header */
    rho_buf_readu32be(buf, &status);
    rho_buf_readu32be(buf, &bodylen);

    debug("timeserver status=%u, bodylen=%u\n", (unsigned)status,
            (unsigned)bodylen);

    /* body */
    rho_buf_readu64be(buf, &nonce_resp);
    debug("timeserver nonce=%llu\n", (unsigned long long)nonce_resp);
    rho_buf_readu64be(buf, &sec);
    rho_buf_readu32be(buf, &usec);

#if 0
    rho_buf_seek(buf, -(TNT_BODYLEN), SEEK_CUR);
    rho_buf_read(buf, body, TNT_BODYLEN);

    /* signature */
    rho_buf_readu32be(buf, &sigsize);
    rho_buf_read(buf, sig, sigsize);
#endif


    /* TODO:
     *  - check that nonce and nonce_resp are equal
     *  - verify signature
     */

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

    return (trusted_time);
}

static long
tnt_client_get_host_time_usec(struct tnt_client *client)
{
    long time = 0;

    time = DkSystemTimeQuery();
    if (time < client->last_host_time)
        rho_warn("current host time %ld is behind preivous host time %ld!\n",
                time, client->last_host_time);

    client->last_host_time = time;

    return (time);
}

static long
tnt_client_get_time_usec(struct tnt_client *client)
{
    long time = 0;

    if ((client->n % client->period) == 0)
        time = tnt_client_get_trusted_time_usec(client);
    else
        time = tnt_client_get_host_time_usec(client);

    client->n++;

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

int shim_do_gettimeofday (struct __kernel_timeval * tv,
                          struct __kernel_timezone * tz)
{
    if (!tv)
        return -EINVAL;

    if (test_user_memory(tv, sizeof(*tv), true))
        return -EFAULT;

    if (tz && test_user_memory(tz, sizeof(*tz), true))
        return -EFAULT;

    //long time = DkSystemTimeQuery();
    long time = get_time_usec();

    if (time == -1)
        return -PAL_ERRNO;

    tv->tv_sec  = time / 1000000;
    tv->tv_usec = time % 1000000;
    return 0;
}

time_t shim_do_time (time_t * tloc)
{
    //long time = DkSystemTimeQuery();
    long time = get_time_usec();

    if (time == -1)
        return -PAL_ERRNO;

    if (tloc && test_user_memory(tloc, sizeof(*tloc), true))
        return -EFAULT;

    time_t t = time / 1000000;

    if (tloc)
        *tloc = t;

    return t;
}

int shim_do_clock_gettime (clockid_t which_clock,
                           struct timespec * tp)
{
    /* all clock are the same */

    if (!tp)
        return -EINVAL;

    if (test_user_memory(tp, sizeof(*tp), true))
        return -EFAULT;

    //long time = DkSystemTimeQuery();
    long time = get_time_usec();

    if (time == -1)
        return -PAL_ERRNO;

    tp->tv_sec  = time / 1000000;
    tp->tv_nsec = (time % 1000000) * 1000;
    return 0;
}

int shim_do_clock_getres (clockid_t which_clock,
                          struct timespec * tp)
{
    /* all clock are the same */

    if (!tp)
        return -EINVAL;

    if (test_user_memory(tp, sizeof(*tp), true))
        return -EFAULT;

    tp->tv_sec  = 0;
    tp->tv_nsec = 1000;
    return 0;
}
