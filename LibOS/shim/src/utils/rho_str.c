#include <limits.h>
#include <string.h>

#include <api.h>

#include <shim_internal.h>
#include <shim_utils.h>

#include <rho_log.h>
#include <rho_mem.h>
#include <rho_str.h>

/*
 * XXX: The implementation of strtol is in Pal/lib/string/atoi.c.
 * The implementation does not use errno (the kernel env doesn't
 * use errno anyway).
 */
static long long
rho_str_tolonglong(const char *s, int base)
{
    long long i = 0;
    char *ep = NULL;

    i = strtol(s, &ep, base);

    /* no digits at all -- not a number */
    if (ep == s)
        rho_die("strtol: '%s' is not a number", s);

    /* trailing garbage */
    if (*ep != '\0')
        rho_die("strtol: '%s' has trailing non-digits", s);

    return (i);
}

short
rho_str_toshort(const char *s, int base)
{
    long long i = 0;
    i = rho_str_tolonglong(s, base); 
    if (i < SHRT_MIN || i > SHRT_MAX)
        rho_die("cannot convert '%s' (base %d) to short", s, base);
    return ((short)i);
}

unsigned short
rho_str_toushort(const char *s, int base)
{
    long long i = 0;
    i = rho_str_tolonglong(s, base); 
    if (i < 0 || i > USHRT_MAX)
        rho_die("cannot convert '%s' (base %d) to unsigned short", s, base);
    return ((unsigned short)i);
}

int
rho_str_toint(const char *s, int base)
{
    long long i = 0;
    i = rho_str_tolonglong(s, base); 
    if (i < INT_MIN || i > INT_MAX)
        rho_die("cannot convert '%s' (base %d) to int", s, base);
    return ((int)i);
}

unsigned int
rho_str_touint(const char *s, int base)
{
    long long i = 0;
    i = rho_str_tolonglong(s, base); 
    if (i < 0 || i > UINT_MAX)
        rho_die("cannot convert '%s' (base %d) to unsigned int", s, base);
    return ((int)i);
}

uint8_t
rho_str_touint8(const char *s, int base)
{
    long long i = 0;
    i = rho_str_tolonglong(s, base); 
    if (i < 0 || i > UINT8_MAX)
        rho_die("cannot convert '%s' (base %d) to uint8", s, base);
    return ((uint8_t)i);
}

int8_t
rho_str_toint8(const char *s, int base)
{
    long long i = 0;
    i = rho_str_tolonglong(s, base); 
    if (i < INT8_MIN || i > INT8_MAX)
        rho_die("cannot convert '%s' (base %d) to int8", s, base);
    return ((int8_t)i);
}

uint16_t
rho_str_touint16(const char *s, int base)
{
    long long i = 0;
    i = rho_str_tolonglong(s, base); 
    if (i < 0 || i > UINT16_MAX)
        rho_die("cannot convert '%s' (base %d) to uint16", s, base);
    return ((uint16_t)i);
}

int16_t
rho_str_toint16(const char *s, int base)
{
    long long i = 0;
    i = rho_str_tolonglong(s, base); 
    if (i < INT16_MIN || i > INT16_MAX)
        rho_die("cannot convert '%s' (base %d) to int16", s, base);
    return ((int16_t)i);
} 

uint32_t
rho_str_touint32(const char *s, int base)
{
    long long i = 0;
    i = rho_str_tolonglong(s, base); 
    if (i < 0 || i > UINT32_MAX)
        rho_die("cannot convert '%s' (base %d) to uint32", s, base);
    return ((uint32_t)i);
}

int32_t
rho_str_toint32(const char *s, int base)
{
    long long i = 0;
    i = rho_str_tolonglong(s, base); 
    if (i < INT32_MIN || i > INT32_MAX)
        rho_die("cannot convert '%s' (base %d) to int32", s, base);
    return ((int32_t)i);
}

/*
 * Get next non-ignored character, normalised:
 *    ASCII letters are converted to lowercase
 *    control characters, space, '-', '_', '.', '/', '+' and ':' are ignored
 * A terminating zero is returned as 0.
 */
static int
rho_str_fuzzy_next_char(const char **ps, const char *limit, bool ci, 
        const char *ignore)
{
	int c;
    const char *ign;
    char ign_norm;

	while (1) {
		if (*ps == limit)
			return 0;

		c = *(*ps)++;
		if (c == 0)
			return 0;

        if (ci)
            c = tolower(c);

        if (ignore == NULL)
            return (c);

        for (ign = ignore; *ign != '\0'; ign++) {
            if (ci)
                ign_norm = tolower(*ign);
            else
                ign_norm = *ign;

            if (c == ign_norm)
                break;
        }

        if (*ign == '\0')
            return (c);
	}
}

static bool
rho_str_substr_fuzzy_equal(const char *s1, size_t s1_len,
        const char *s2, size_t s2_len, bool ci, const char *ignore)
{
    const char *lim1, *lim2;
    int c1, c2;

    lim1 = s1 + s1_len;
    lim2 = s2 + s2_len;

    while (1) {
        c1 = rho_str_fuzzy_next_char(&s1, lim1, ci, ignore);
        c2 = rho_str_fuzzy_next_char(&s2, lim2, ci, ignore);
        if (c1 != c2)
            return (false);
        if (c1 == '\0')
            return (true);
    }
}

bool
rho_str_equal(const char *s1, const char *s2)
{
    return (strcmp(s1, s2) == 0);
}

/*
 * compares s1 to s2, but, when performing the comparison, skips
 * over any characters given in ignore.
 */
bool
rho_str_equal_ignore(const char *s1, const char *s2, const char *ignore)
{

    return (rho_str_substr_fuzzy_equal(s1, strlen(s1), s2, strlen(s2), 
                false, ignore));
}

bool
rho_str_equal_ci(const char *s1, const char *s2)
{
    return (strcasecmp(s1, s2) == 0);
}

bool
rho_str_equal_ci_ignore(const char *s1, const char *s2, const char *ignore)
{
    return (rho_str_substr_fuzzy_equal(s1, strlen(s1), s2, strlen(s2), 
                true, ignore));
}

bool
rho_str_startswith(const char *s, const char *prefix)
{
    size_t prefix_len = strlen(prefix);

    return (strncmp(s, prefix, prefix_len) == 0);
}

bool
rho_str_startswith_ci(const char *s, const char *prefix)
{
    size_t prefix_len = strlen(prefix);

    return (strncasecmp(s, prefix, prefix_len) == 0);
}

bool
rho_str_endswith(const char *s, const char *suffix)
{
    size_t s_len = strlen(s);
    size_t suffix_len  = strlen(suffix);
    const char *p = NULL;

    /* quick exit */
    if (suffix_len > s_len)
        return (false);

    /*
     *
     * string (len = 7)
     * 0 1 2 3 4 5 6 7
     * a b c d e f g \0
     * 
     * suffix   (len= 3)
     * 0 1 2 3
     * e f g \0
     *
     * (s + s_len - suffix_len) = 0 + 7 - 3 = 4
     */
    p = s + s_len - suffix_len;

    return (strncmp(p, suffix, suffix_len) == 0);
}

bool
rho_str_endswith_ci(const char *s, const char *suffix)
{
    size_t s_len = strlen(s);
    size_t suffix_len  = strlen(suffix);
    const char *p = NULL;

    /* quick exit */
    if (suffix_len > s_len)
        return (false);
    p = s + s_len - suffix_len;
    return (strncasecmp(p, suffix, suffix_len) == 0);
}

/* always add a NULL entry to the end to allow 
 * that style of iteration
 *
 * if n is NULL, don't set
 *
 * destructive vs non-destructive of original string
 * 
 * how to handle contiguous delimiters
 *
 * TODO: rhoL_strtok()
 */

void
rho_str_array_destroy(char **array)
{
    char **it = NULL;

    for (it = array; *it != NULL; it++) {
        rhoL_free(*it);
    }
    rhoL_free(array);
} 

/* TODO: we could easily generalize to splitstr -- which
 * would have python semantics, perhaps add a macro for
 * splitc?
 */
char **
rho_str_splitc(const char *s, char c, size_t *n)
{
    size_t ndelimiters = 0;
    size_t nitems = 0;
    size_t i = 0;
    char **a = 0;
    const char *mark = s;
    const char *forward = NULL;

    RHO_ASSERT(s != NULL);

    /* get number of delimiters */
    while ((forward = strchr(mark, c)) != NULL) {
        ndelimiters++;
        mark = forward + 1;
    }

    nitems = ndelimiters + 1;

    /* allocate -- include an extra item for trailing NULL */
    a = rhoL_mallocarray(nitems + 1, sizeof(char *), RHO_MEM_ZERO);

    if (nitems == 1) {
        a[0] = rhoL_strdup(s);
        goto done;
    }

    /* get number of items */
    mark = s;
    while ((forward = strchr(mark, c)) != NULL) {
        a[i] = rhoL_strndup(mark, forward - mark);
        i++;
        mark = forward + 1;
    }
    
    /* copy last item */
    a[i] = rhoL_strdup(mark);

done:
    if (n != NULL)
        *n = nitems;

    return (a);
}

char *
rho_str_lstrip_alloc(const char *s, const char *removeset)
{
    const char *p = s;
    const char *x = NULL;
    int found = 0;

    while (*p) {
        x = removeset;
        found = 0;
        while (*x) {
            if (*p == *x) {
                found = 1;
                break;
            }
            x++;
        }

        if (!found)
            break;

        p++;
    }

   return (strdup(p));
}

char *
rho_str_lstrip(char *s, const char *removeset)
{
    const char *p = s;
    const char *x = NULL;
    int found = 0;

    while (*p) {
        x = removeset;
        found = 0;
        while (*x) {
            if (*p == *x) {
                found = 1;
                break;
            }
            x++;
        }

        if (!found)
            break;

        p++;
    }

   return ((char *)p);
}

char *
rho_str_rstrip_alloc(const char *s, const char *removeset)
{
    size_t i = 0 ;
    const char *p = NULL;
    const char *x = NULL;
    int found = 0;

    p = s;
    i = strlen(s);
    if (i == 0)
        goto done;

    p = s + (i - 1);
    while (*p) {
        x = removeset;
        found = 0;
        while (*x) {
            if (*p == *x) {
                found = 1;
                break;
            }
            x++;
        }

        if (!found)
            break;

        p--;
    }

done:
    return (strndup(s, p == s ? 0 : p + 1 - s ));
}

char *
rho_str_rstrip(char *s, const char *removeset)
{
    size_t i = 0 ;
    const char *p = NULL;
    const char *x = NULL;
    int found = 0;

    i = strlen(s);
    if (i == 0)
        goto done;

    p = s + (i - 1);
    while (*p) {
        x = removeset;
        found = 0;
        while (*x) {
            if (*p == *x) {
                found = 1;
                break;
            }
            x++;
        }

        if (!found)
            break;

        p--;
    }

    s[p - s + 1] = '\0';

done:
    return (s);
} 
