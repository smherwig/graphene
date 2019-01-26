#include <api.h>

#include <rho_mem.h>
#include <rho_path.h>

/*
 * Does nothing more than concatenate a and b and ensure that
 * a slash separates the two.
 */
int
rho_path_join(const char *a, const char *b, char *buf, size_t buflen)
{
    size_t outlen = 0;
    size_t a_len = 0;
    size_t b_len = 0;
    bool a_end_slash = false;
    bool b_start_slash = false;
    const char *p = NULL;
    char *c = NULL;

    a_len = strlen(a);
    b_len = strlen(b);

    if (a_len > 0) {
        p = a + a_len - 1;
        if (*p == '/')
            a_end_slash = true;
    }

    if (b_len > 0) {
        if (*b == '/')
            b_start_slash = true;
    }

    if (a_end_slash) {
        if (b_start_slash)
            outlen = a_len + b_len - 1; 
        else
            outlen = a_len + b_len;
    } else {
        if (b_start_slash)
            outlen = a_len + b_len;
        else
            outlen = a_len + b_len + 1;
    }

    /* not enough space to write a nul-terminated joined path */
    if ((outlen + 1) > buflen)
        return (-1);

    memcpy(buf, a, a_len);
    c = buf + a_len;
    p = b;
    if (a_end_slash && b_start_slash) {
        p = b+1; 
        b_len--;
    }
    if (!a_end_slash && !b_start_slash) {
        *c = '/';
        c++;
    }
    memcpy(c, p, b_len);

    /* nul-terminate */
    c += b_len;
    *c = '\0';

    return (0);
}

char *
rho_path_join_alloc(const char *a, const char *b)
{
    size_t n = 0;
    char *joined = NULL;

    n = strlen(a) + strlen(b) + 2;
    joined = rhoL_zalloc(n);
    rho_path_join(a, b, joined, n);

    return (joined);
}
