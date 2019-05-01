#ifndef _TCAD_H_
#define _TCAD_H_

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_decls.h>

#include <rpc.h>

RHO_DECLS_BEGIN

/* limits */
#define TCAD_MAX_NAME_SIZE      256
#define TCAD_MAX_VALUE_SIZE     4096

/* RPC odcodes */
#define TCAD_OP_NEW_FDTABLE     0
#define TCAD_OP_FORK            1
#define TCAD_OP_CHILD_ATTACH    2
#define TCAD_OP_CREATE_ENTRY    3
#define TCAD_OP_DESTROY_ENTRY   4
#define TCAD_OP_SET             5
#define TCAD_OP_CMP_AND_GET     6
#define TCAD_OP_INC_AND_SET     7

int tcad_new_fdtable(struct rpc_agent *agent);

int tcad_fork(struct rpc_agent *agent, uint64_t *child_ident);

int tcad_child_attach(struct rpc_agent *agent, uint64_t child_ident);

int tcad_create_entry(struct rpc_agent *agent, const char *name,
        void *data, size_t data_len, uint32_t *fd);

int tcad_destroy_entry(struct rpc_agent *agent, uint32_t fd);

int tcad_set(struct rpc_agent *agent, uint32_t fd, void *data,
        size_t data_len);

int tcad_cmp_and_get(struct rpc_agent *agent, uint32_t fd, int expected_count,
        void *data, size_t *data_len);

int tcad_inc_and_set(struct rpc_agent *agent, uint32_t fd, void *data,
        size_t data_len);

RHO_DECLS_END

#endif /* ! _TCAD_H */
