#ifndef _RHO_ENDIAN_H_
#define _RHO_ENDIAN_H_

/* based on https://gist.github.com/panzi/6856583: 
 *
 * "License": Public Domain
 * I, Mathias Panzenböck, place this file hereby into the public domain. Use it
 * at your own risk for whatever you like.  In case there are jurisdictions that
 * don't support putting things in the public domain you can also consider it to
 * be "dual licensed" under the BSD, MIT and Apache licenses, if you want to. This
 * code is trivial anyway. Consider it an example on how to get the endian
 * conversion functions on different platforms.
 */

#include "rho_decls.h"

RHO_DECLS_BEGIN

/* XXX: for now, hardcode to linux */
#ifndef RHO_OS_LINUX
#   define RHO_OS_LINUX
#endif

#if defined(RHO_OS_LINUX)
#	include <endian.h>
#elif defined(RHO_OS_MACOS)
#	include <libkern/OSByteOrder.h>

#	define htobe16(x) OSSwapHostToBigInt16(x)
#	define htole16(x) OSSwapHostToLittleInt16(x)
#	define be16toh(x) OSSwapBigToHostInt16(x)
#	define le16toh(x) OSSwapLittleToHostInt16(x)
 
#	define htobe32(x) OSSwapHostToBigInt32(x)
#	define htole32(x) OSSwapHostToLittleInt32(x)
#	define be32toh(x) OSSwapBigToHostInt32(x)
#	define le32toh(x) OSSwapLittleToHostInt32(x)
 
#	define htobe64(x) OSSwapHostToBigInt64(x)
#	define htole64(x) OSSwapHostToLittleInt64(x)
#	define be64toh(x) OSSwapBigToHostInt64(x)
#	define le64toh(x) OSSwapLittleToHostInt64(x)

#	define __BYTE_ORDER    BYTE_ORDER
#	define __BIG_ENDIAN    BIG_ENDIAN
#	define __LITTLE_ENDIAN LITTLE_ENDIAN
#	define __PDP_ENDIAN    PDP_ENDIAN

#elif defined(RHO_OS_OPENBSD)
#	include <sys/endian.h>

#elif defined(RHO_OS_NETBSD) || defined(RHO_OS_FREEBSD)

#	include <sys/endian.h>

#	define be16toh(x) betoh16(x)
#	define le16toh(x) letoh16(x)

#	define be32toh(x) betoh32(x)
#	define le32toh(x) letoh32(x)

#	define be64toh(x) betoh64(x)
#	define le64toh(x) letoh64(x)
#else
#	error Must define one of: RHO_OS_{LINUX, MACOS, OPENBSD, NETBSD, FREEBSD}
#endif

RHO_DECLS_END

#endif /* ! _RHO_ENDIAN_H_ */
