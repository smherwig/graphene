#include <stddef.h>

#include "rho_mem.h"
#include "rho_pem.h"

void
rho_pem_destroy(struct rho_pem *pem)
{
    rhoL_free(pem->name);
    rhoL_free(pem->data);
}
