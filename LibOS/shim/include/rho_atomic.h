#ifndef _RHO_ATOMIC_H_
#define _RHO_ATOMIC_H_

#include <shim_internal.h>
#include <shim_types.h>

#include <rho_decls.h>

RHO_DECLS_BEGIN

/*
 * Atomic operations; mostly based on musl libc's 
 * arch/x86_64/atomic_arch.h.  musl's copyright is reproduced below :
 *
 * musl as a whole is licensed under the following standard MIT license:
 *
 * ----------------------------------------------------------------------
 * Copyright © 2005-2014 Rich Felker, et al. 
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY 
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 * ----------------------------------------------------------------------
 */


/*/
 * If t == *p:
 *  *p = s
 * else
 *   t = *p
 *
 * return t
 */
static inline int
rho_atomic_cas(volatile int *p, int t, int s)
{
	__asm__ __volatile__ (
		"lock ; cmpxchg %3, %1"
		: "=a"(t), "=m"(*p) : "a"(t), "r"(s) : "memory" );
	return t;
}

static inline void *
rho_atomic_cas_p(volatile void *p, void *t, void *s)
{
	__asm__( "lock ; cmpxchg %3, %1"
		: "=a"(t), "=m"(*(void *volatile *)p)
		: "a"(t), "r"(s) : "memory" );
	return t;
}

static inline int
rho_atomic_swap(volatile int *p, int v)
{
	__asm__ __volatile__(
		"xchg %0, %1"
		: "=r"(v), "=m"(*p) : "0"(v) : "memory" );
	return v;
}

static inline int
rho_atomic_fetch_add(volatile int *p, int v)
{
	__asm__ __volatile__(
		"lock ; xadd %0, %1"
		: "=r"(v), "=m"(*p) : "0"(v) : "memory" );
	return v;
}

#define rho_atomic_fetch_inc(p) rho_atomic_fetch_add(p, 1)

static inline void
rho_atomic_and(volatile int *p, int v)
{
	__asm__ __volatile__(
		"lock ; and %1, %0"
		: "=m"(*p) : "r"(v) : "memory" );
}

static inline void
rho_atomic_or(volatile int *p, int v)
{
	__asm__ __volatile__(
		"lock ; or %1, %0"
		: "=m"(*p) : "r"(v) : "memory" );
}

static inline void 
rho_atomic_and_64(volatile uint64_t *p, uint64_t v)
{
	__asm__ __volatile(
		"lock ; and %1, %0"
		 : "=m"(*p) : "r"(v) : "memory" );
}

static inline void
rho_atomic_or_64(volatile uint64_t *p, uint64_t v)
{
	__asm__ __volatile__(
		"lock ; or %1, %0"
		 : "=m"(*p) : "r"(v) : "memory" );
}

static inline void
rho_atomic_inc(volatile int *p)
{
	__asm__ __volatile__(
		"lock ; incl %0"
		: "=m"(*p) : "m"(*p) : "memory" );
}

static inline void
rho_atomic_dec(volatile int *p)
{
	__asm__ __volatile__(
		"lock ; decl %0"
		: "=m"(*p) : "m"(*p) : "memory" );
}

static inline void
rho_atomic_store(volatile int *p, int x)
{
	__asm__ __volatile__(
		"mov %1, %0 ; lock ; orl $0,(%%rsp)"
		: "=m"(*p) : "r"(x) : "memory" );
}

static inline void
rho_atomic_barrier(void)
{
	__asm__ __volatile__( "" : : : "memory" );
}

static inline void
rho_atomic_spin(void)
{
	__asm__ __volatile__( "pause" : : : "memory" );
}

static inline void 
rho_atomic_crash(void)
{
	__asm__ __volatile__( "hlt" : : : "memory" );
}

static inline int
rho_atomic_ctz_64(uint64_t x)
{
	__asm__( "bsf %1,%0" : "=r"(x) : "r"(x) );
	return x;
}

static inline int 
rho_atomic_clz_64(uint64_t x)
{
	__asm__( "bsr %1,%0 ; xor $63,%0" : "=r"(x) : "r"(x) );
	return x;
}


RHO_DECLS_END

#endif /* _RHO_ATOMIC_H_ */
