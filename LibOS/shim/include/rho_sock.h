#ifndef _RHO_SOCKET_H_
#define _RHO_SOCKET_H_

#include <shim_types.h>

#include <linux/in.h>
#include <linux/un.h>

#include <rho_decls.h>
#include <rho_buf.h>

RHO_DECLS_BEGIN

struct rho_ssl_ctx;

struct rho_sock {
    PAL_HANDLE pal_hdl;
    int af;     /* address family (e.g., AF_INET) */
    int error;
    struct rho_sock_ops {
        ssize_t (*recv)     (struct rho_sock *, void *, size_t);
        ssize_t (*send)     (struct rho_sock *, const void *, size_t);
        void    (*destroy)  (struct rho_sock *);
    } *ops;
    struct rho_ssl_ctx *ssl_ctx;
};

struct rho_sock * rho_sock_open_url(const char *url);

ssize_t rho_sock_recv(struct rho_sock *sock, void *buf, size_t len);
ssize_t rho_sock_recv_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_precv_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_recvn(struct rho_sock *sock, void *buf, size_t len);
ssize_t rho_sock_recvn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_precvn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);

ssize_t rho_sock_send(struct rho_sock *sock, const void *buf, size_t len);
ssize_t rho_sock_send_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_psend_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_sendn(struct rho_sock *sock, const void *buf, size_t len);
ssize_t rho_sock_sendn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);
ssize_t rho_sock_psendn_buf(struct rho_sock *sock, struct rho_buf *buf,
        size_t len);

void rho_sock_destroy(struct rho_sock *sock);

RHO_DECLS_END

#endif /* _RHO_SOCKET_H_ */
