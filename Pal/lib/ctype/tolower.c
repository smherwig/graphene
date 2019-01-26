#include "api.h"

/* SMHERWIG: from muslibc */

int
tolower(int c)
{
    if (isupper(c))
        return (c | 32);
    return (c);
}
