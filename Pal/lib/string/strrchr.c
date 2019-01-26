#include "api.h"

/* SMHERWIG: from muslibc */

char *strrchr(const char *s, int c)
{
	return memrchr(s, c, strlen(s) + 1);
}
