#ifndef _RPC_H_
#define _RPC_H_

#include <shim_types.h>

#include <rho_decls.h>

#include <rho_buf.h>
#include <rho_sock.h>

RHO_DECLS_BEGIN

#define RPC_HDR_LENGTH  8

/* 
 * for requests, rh_code is the request's opcode;
 * for respones, rh_code is the status (i.e., error) code
 */
struct rpc_hdr {
    uint32_t    rh_code;
    uint32_t    rh_bodylen;
};

#define RPC_STATE_HANDSHAKE       1
#define RPC_STATE_RECV_HDR        2
#define RPC_STATE_RECV_BODY       3
#define RPC_STATE_DISPATCHABLE    4
#define RPC_STATE_SEND_HDR        5
#define RPC_STATE_SEND_BODY       6
#define RPC_STATE_CLOSED          7
#define RPC_STATE_ERROR           8

struct rpc_agent {
    int ra_state;
    struct rpc_hdr  ra_hdr;     /* parsed out header */
    struct rho_buf *ra_hdrbuf;  /* buffer for recv/send of headr */
    struct rho_buf *ra_bodybuf; /* holds body of req/resp */
    struct rho_sock *ra_sock;
};

const char * rpc_state_to_str(int state);
void rpc_agent_ready_send(struct rpc_agent *agent);

struct rpc_agent * rpc_agent_create(struct rho_sock *sock);

void rpc_agent_destroy(struct rpc_agent *agent);

void rpc_agent_recv_hdr(struct rpc_agent *agent);
void rpc_agent_recv_body(struct rpc_agent *agent);
void rpc_agent_recv_msg(struct rpc_agent *agent);

void rpc_agent_send_hdr(struct rpc_agent *agent);
void rpc_agent_send_body(struct rpc_agent *agent);
void rpc_agent_send_msg(struct rpc_agent *agent);

int rpc_agent_transport(struct rpc_agent *agent);
int rpc_agent_request(struct rpc_agent *agent);

void rpc_agent_new_msg(struct rpc_agent *agent, uint32_t code);

#define rpc_agent_set_code(agent, code) \
    (agent)->ra_hdr.rh_code = code

#define rpc_agent_set_bodylen(agent, bodylen) \
    (agent)->ra_hdr.rh_bodylen = bodylen

#define rpc_agent_get_bodylen(agent) \
    ((agent)->ra_hdr.rh_bodylen)

#define rpc_agent_set_hdr(agent, code, bodylen) \
    do { \
        rpc_agent_set_code(agent, code); \
        rpc_agent_set_bodylen(agent, bodylen); \
    } while (0)

#define rpc_agent_autoset_bodylen(agent) \
    rpc_agent_set_bodylen(agent, rho_buf_length((agent)->ra_bodybuf))

RHO_DECLS_END

#endif /* _RPC_H_ */
