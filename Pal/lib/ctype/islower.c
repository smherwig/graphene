#include "api.h"

/* SMHERWIG: from muslibc */

int
islower(int c)
{
    return ((((unsigned)c) - 'a') < 26);
}
