#ifndef _RHO_BITOPS_H_
#define _RHO_BITOPS_H_

#include <rho_decls.h>

RHO_DECLS_BEGIN

/*                     
 * Assumes array is of type unsigned char.  Thus, if you are using, for
 * instance, a uint32_t as a bitarray, then you must cast appropriately:
 *
 *  uint32_t a = 0;
 *  RHO_BITOPS((uint8_t *)&a, 4);
 *
 * Bits numbers increase from left to right:
 *                       111111
 *   bit #: 01234567 | 89012345
 * example: 00000000 | 01000000
 *
 *
 * TODO: RHO_BITOPS is similar to OpenBSD's setbit(9), whereas rho_bitarray is
 * similar to bitstring(3).   A more general version of RHO_BITOPS (that
 * operates on different intregral types, and not just bytes) would be modeled
 * after bitmap(3).
 */
#define RHO_BITOPS_ISSET(a, bit) \
    ((a)[(int)((bit) / 8)] & (0x80 >> ((bit) % 8)))

#define RHO_BITOPS_SET(a, bit) \
    ((a)[(int)((bit) / 8)] |= (0x80 >> ((bit) % 8)))

#define RHO_BITOPS_CLR(a, bit) \
    ((a)[(int)((bit) / 8)] &= ~(0x80 >> ((bit) % 8)))

#define RHO_BITOPS_FOREACH(i, val, a, sizebits) \
    for (\
            (i) = 0, (val) = (RHO_BITOPS_ISSET((a), (i)) ? 1 : 0); \
            (i) < (sizebits); \
            (i)++,   (val) = (RHO_BITOPS_ISSET((a), (i)) ? 1 : 0) \
        )

RHO_DECLS_END

#endif /* _RHO_BITOPS_H_ */
