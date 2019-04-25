#include <rho_buf.h>
#include <rho_log.h>
#include <rho_mem.h>
#include <rho_sock.h>

#include <rpc.h>

#include <tcad.h>

/* returns 0 on success, or an errno value on failure */
static int
tcad_do_rpc(struct rpc_agent *agent)
{
    int error = 0;

    RHO_TRACE_ENTER();

    /* make request */
    error = rpc_agent_request(agent);
    if (error != 0) {
        /* RPC/transport error (EPROTO) */
        rho_warn("RPC error");
        goto done;
    }

    if (hdr->rh_code != 0) {
        /* method error */
        error = hdr->rh_code;
        rho_errno_warn(error, "RPC returned an error");
        goto done;
    }

done:
    RHO_TRACE_EXIT();
    return (error);
}

int
tcad_create_entry(struct rpc_agent *agent, const char *name, void *data,
        size_t data_len, int *fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    rpc_agent_new_msg(agent, TCAD_OP_CREATE_ENTRY);
    rho_buf_write_u32size_str(buf, name);
    rho_buf_write_u32size_blob(buf, data, data_len);
    rpc_agent_autoset_bodylen(agent);

    error = tcad_do_rpc(agent);
    if (error != 0)
        goto done;

    rho_buf_readu32be(buf, (uint32_t *)&fd);

done:
    return (error);
}

int
tcad_destroy_entry(struct rpc_agent *agent, int fd)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    rpc_agent_new_msg(agent, TCAD_OP_DESTROY_ENTRY);
    rho_buf_writeu32be(buf, fd);
    rpc_agent_autoset_bodylen(agent);

    error = tcad_do_rpc(agent);

    return (error);
}

int
tcad_cmp_and_get(struct rpc_agent *agent, int fd, int expected_count,
        void *data, size_t *data_len)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    rpc_agent_new_msg(agent, TCAD_OP_CMP_AND_GET);
    rho_buf_writeu32be(buf, fd);
    rho_buf_write32be(buf, expected_count); 
    rpc_agent_autoset_bodylen(agent);

    error = tcad_do_rpc(agent);
    if (error != 0)
        goto done;

    rho_buf_read_u32size_blob(buf, data, 256, data_len);

done:
    return (error);
}

int
tcad_inc_and_set(struct rpc_agent *agent, int fd, void *data,
        size_t data_len)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    rpc_agent_new_msg(agent, TCAD_OP_INC_AND_SET);
    rho_buf_writeu32be(buf, fd);
    rho_buf_write_u32size_blob(buf, data, data_len);
    rpc_agent_autoset_bodylen(agent);

    error = tcad_do_rpc(agent);

    return (error);
}

int
tcad_new_fdtable(struct rpc_agent *agent)
{
    int error = 0;

    rpc_agent_new_msg(agent, TCAD_OP_NEW_FDTABLE);
    error = tcad_do_rpc(agent);

    return (error);
} 

int
tcad_fork(struct rpc_agent *agent, uint64_t *child_ident)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    rpc_agent_new_msg(agent, TCAD_OP_FORK);

    error = tcad_do_rpc(agent);
    if (error != 0)
        goto done;

    rho_buf_readu64be(buf, child_ident);

done:
    return (error);
}

int
tcad_child_attach(struct rpc_agent *agent, uint64_t child_ident)
{
    int error = 0;
    struct rho_buf *buf = agent->ra_bodybuf;

    rpc_agent_new_msg(agent, TCAD_OP_CHILD_ATTACH);
    rho_buf_writeu64be(buf, child_ident);
    rpc_agent_autoset_bodylen(agent);

    error = tcad_do_rpc(agent);

    return (error);
}
