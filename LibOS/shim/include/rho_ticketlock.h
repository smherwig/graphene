#include <rho_atomic.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

struct rho_ticketlock {
    int ticket_number;
    int turn;
};

static inline int
rho_ticketlock_lock(struct rho_ticketlock *tl)
{
    int my_turn;

    my_turn = rho_atomic_fetch_inc(&tl->ticket_number);
    while (my_turn != tl->turn) { /* spin */ ; }
    return (my_turn);
}

static inline void
rho_ticketlock_unlock(struct rho_ticketlock *tl)
{
    rho_atomic_fetch_inc(&tl->turn);
}

RHO_DECLS_END
