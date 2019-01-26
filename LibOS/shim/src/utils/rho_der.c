#include <stddef.h>
#include <stdbool.h>

#include "rho_der.h"

/*
 * Adapted from BearSSL:
 * TODO: add license
 */

/*
 * This function returns non-zero if the provided buffer "looks like"
 * a DER-encoded ASN.1 object (criteria: it has the tag for a SEQUENCE
 * with a definite length that matches the total object length).
 */
bool
rho_der_looks_like_der(const unsigned char *buf, size_t len)
{
    int fb; 
    size_t dlen;

    if (len < 2) {
        return (false);
    }   
    if (*buf ++ != 0x30) {
        return (false);
    }   
    fb = *buf ++; 
    len -= 2;
    if (fb < 0x80) {
        return (size_t)fb == len;
    } else if (fb == 0x80) {
        return (false);
    } else {
        fb -= 0x80;
        if (len < (size_t)fb + 2) {
            return (false);
        }
        len -= (size_t)fb;
        dlen = 0;
        while (fb -- > 0) {
            if (dlen > (len >> 8)) {
                return (false);
            }
            dlen = (dlen << 8) + (size_t)*buf ++; 
        }
        return (dlen == len);
    }   
}
