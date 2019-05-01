#include <shim_internal.h>
#include <shim_types.h>
#include <shim_table.h>
#include <shim_handle.h>

#include <pal.h>
#include <pal_error.h>

#include <errno.h>

#include <asm/socket.h>

#include <api.h>    /* memset/memcpy */

#include <rho_buf.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_sock.h>
#include <rho_str.h>
#include <rho_url.h>

static ssize_t rho_sock_stream_recv(struct rho_sock *sock, void *buf, 
        size_t len);
static ssize_t rho_sock_stream_send(struct rho_sock *sock, const void *buf,
        size_t len);
static void rho_sock_stream_destroy(struct rho_sock *sock);

static struct rho_sock_ops rho_sock_stream_ops = {
    .recv = rho_sock_stream_recv,
    .send = rho_sock_stream_send,
    .destroy = rho_sock_stream_destroy,
};

struct rho_sock *
rho_sock_open_url(const char *url)
{
    struct rho_sock *sock = NULL;
    PAL_HANDLE pal_hdl = NULL;

    debug("> rho_sock_open_url(url=%s)\n", url);

    pal_hdl = DkStreamOpen(url, 0, 0, 0, 0);
    if (pal_hdl == NULL)
        debug("DkStreamOpen returned NULL\n");

    sock = rhoL_zalloc(sizeof(*sock));
    sock->pal_hdl = pal_hdl;
    sock->ops = &rho_sock_stream_ops;

    debug("< rho_sock_open_url\n");
    return (sock);
}

ssize_t
rho_sock_recv(struct rho_sock *sock, void *buf, size_t len)
{
    return (sock->ops->recv(sock, buf, len));
}

ssize_t
rho_sock_recv_buf(struct rho_sock *sock, struct rho_buf *buf, size_t len)
{
    ssize_t n = 0;

    n = rho_sock_precv_buf(sock, buf, len);
    if (n > 0)
        rho_buf_seek(buf, n, SEEK_CUR);

    return (n);
}

ssize_t
rho_sock_precv_buf(struct rho_sock *sock, struct rho_buf *buf, size_t len)
{
    ssize_t n = 0;
    void *b = NULL;

    rho_buf_ensure(buf, len);
    b = rho_buf_raw(buf, 0, SEEK_CUR);
    n = rho_sock_recv(sock, b, len);

    return (n);
}

ssize_t 
rho_sock_recvn(struct rho_sock *sock, void *buf, size_t n)
{
    ssize_t nr = 0;
    size_t tot = 0;
    char *p = NULL;

    p = buf;
    for (tot = 0; tot < n; ) {
        nr = rho_sock_recv(sock, p, n - tot);

        if (nr == 0)
            return (tot); /* EOF */

        if (nr == -1)
            return (-1);

        tot += nr;
        p += nr;
    }

    return (tot);
}

ssize_t
rho_sock_recvn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t n)
{
    ssize_t got = 0;

    got = rho_sock_precvn_buf(sock, buf, n);
    if (got > 0)
        rho_buf_seek(buf, got, SEEK_CUR);

    return (got);
}

ssize_t
rho_sock_precvn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t n)
{
    char *p = NULL;
    ssize_t got = 0;

    rho_buf_ensure(buf, n);
    p = rho_buf_raw(buf, 0, SEEK_CUR);
    got = rho_sock_recvn(sock, p, n);
    if (got > 0) {
        /* TODO: check overflow */
        if ((buf->pos + ((size_t)got)) > buf->len)
            buf->len = buf->pos + (size_t)got;
    }
    return (got);
}

ssize_t
rho_sock_send(struct rho_sock *sock, const void *buf, size_t len)
{
    return (sock->ops->send(sock, buf, len));
}

ssize_t
rho_sock_send_buf(struct rho_sock *sock, struct rho_buf *buf, size_t len)
{
    ssize_t n = rho_sock_psend_buf(sock, buf, len);
    if (n > 0)
        rho_buf_seek(buf, n, SEEK_CUR);
    return (n);
}
ssize_t
rho_sock_psend_buf(struct rho_sock *sock, struct rho_buf *buf, size_t len)
{
    void *b = rho_buf_raw(buf, 0, SEEK_CUR);
    return (rho_sock_send(sock, b, len));
}

/*
 * Note that the semantics are similar to Python's socket.sendall;
 * namely, in the case of an error, the function does not return
 * how many bytes were sent, but simply returns -1.
 */
ssize_t
rho_sock_sendn(struct rho_sock *sock, const void *buf, size_t n)
{
    ssize_t nw = 0;
    size_t tot = 0;
    const char *p = NULL;

    p = buf;
    for (tot = 0; tot < n; ) {
        nw = rho_sock_send(sock, p, n - tot);
        if (nw == -1)
            return (-1);
        tot += nw;
        p += nw;
    }

    return (tot);
}

ssize_t
rho_sock_sendn_buf(struct rho_sock *sock, struct rho_buf *buf, size_t n)
{
    ssize_t put = 0;
    
    put = rho_sock_psendn_buf(sock, buf, n);
    if (put > 0)
        rho_buf_seek(buf, put, SEEK_CUR);
    return (put);
}

ssize_t
rho_sock_psendn_buf(struct rho_sock *sock, struct rho_buf *buf, size_t n)
{
    const char *p = rho_buf_raw(buf, 0, SEEK_CUR);
    return (rho_sock_sendn(sock, p, n));
}

void
rho_sock_destroy(struct rho_sock *sock)
{
    sock->ops->destroy(sock);
}

/*
 * TCP/TCP6/UNIX-SPECIFIC OPS
 */

static ssize_t
rho_sock_stream_recv(struct rho_sock *sock, void *buf, size_t len)
{
    PAL_NUM n = 0;

    
again:
    n = DkStreamRead(sock->pal_hdl, 0, len, buf, NULL, 0);
    if ((n == 0) && PAL_NATIVE_ERRNO  == PAL_ERROR_INTERRUPTED) {
        debug("rho_sock: DkStreamRead interrupted; trying again\n");
        goto again;
    }

    /* 
     * DkStreamRead returns 0 on failure, and the number of bytes read
     * on success.  We intervene by returning -1 on failure; the caller
     * can check PAL_ERRNO for the resultant UNIX errno value.
     */
    if ((n == 0) && (PAL_NATIVE_ERRNO != PAL_ERROR_ENDOFSTREAM))
        n = -1;

    return (n);
}

static ssize_t
rho_sock_stream_send(struct rho_sock *sock, const void *buf, size_t len)
{
    PAL_NUM n = 0;

again:
    n = DkStreamWrite(sock->pal_hdl, 0, len, buf, NULL);
    if ((n == 0) && PAL_NATIVE_ERRNO  == PAL_ERROR_INTERRUPTED) {
        debug("rho_sock: DkStreamRead interrupted; trying again\n");
        goto again;
    }
    /* 
     * DkStreamWrite returns 0 on failure, and the number of bytes
     * written on succes.  We intervene by returning -1 on fialure;
     * the caller can check PAL_ERRNO forthe resultant UNIX errno value.
     */
    if (n == 0)
        n = -1;

    return (n);
}

static void
rho_sock_stream_destroy(struct rho_sock *sock)
{
    DkStreamDelete(sock->pal_hdl, 0);
    rhoL_free(sock);
}
