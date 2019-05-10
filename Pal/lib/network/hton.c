/* Copyright (C) 1993,97,2002 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#include "api.h"
#include <host_endian.h>

// SMHERWIG
static inline uint16_t
rho_swap_u16(uint16_t x)
{
    return ( (x >> 8) | (x << 8) );
}

static inline uint32_t
rho_swap_u32(uint32_t x)
{
    return (
        ((x >> 24) & 0x000000ff) | 
        ((x >>  8) & 0x0000ff00) | 
        ((x <<  8) & 0x00ff0000) | 
        ((x << 24) & 0xff000000)
    );
}

uint32_t __htonl (uint32_t x)
{
// SMHERWIG
#if 0
#if BYTE_ORDER == BIG_ENDIAN
    return x;
#elif BYTE_ORDER == LITTLE_ENDIAN
    return __bswap_32 (x);
#else
# error "What kind of system is this?"
#endif
#endif
    return rho_swap_u32(x);
}

uint32_t __ntohl (uint32_t x)
{
    return __htonl (x);
}

uint16_t __htons (uint16_t x)
{
// SMHERWIG
#if 0
#if BYTE_ORDER == BIG_ENDIAN
#error "Graphene thinks byte order is BIG_ENDIAN!"
    return x;
#elif BYTE_ORDER == LITTLE_ENDIAN
    return __bswap_16 (x);
#else
# error "What kind of system is this?"
#endif
#endif
    return rho_swap_u16(x);
}

uint16_t __ntohs (uint16_t x)
{
    return __htons (x);
}
