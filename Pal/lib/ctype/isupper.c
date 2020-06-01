#include "api.h"

/* SMHERWIG: from muslibc */

int
isupper(int c)
{
    return ((((unsigned)c) - 'A') < 26);
}
