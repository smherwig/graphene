#ifndef _RHO_VECTOR_H_
#define _RHO_VECTOR_H_

/* 
 * Macros for growable arrays.
 *
 * RHO_VECTOR is based on the VEC*() macros in BearSSL, the copyright
 * of which is presented below:
 *
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
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
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stddef.h>
#include <string.h>

#include <rho_decls.h>
#include <rho_mem.h>

RHO_DECLS_BEGIN

/*
 * Make a structure type for a vector of 'type'.  Like rho_queue.h, name leaves
 * off the struct prefix.  However, unlinke rho_queue.h, type may be a base-type, and
 * thus, if it is a struct, the struct must also be included.
 */
#define RHO_VECTOR(name, type) \
struct name {   \
    type *buf;  \
    size_t ptr; \
    size_t len; \
}

/*
 * Convenience for the common case of a byte vector.
 */
typedef RHO_VECTOR(rho_bytevector, unsigned char) rho_bytevector;


/*
 * Constant initialiser for a vector.
 */
#define RHO_VECTOR_INIT   { NULL, 0, 0 }

/*
 * Clear a vector.
 */
#define RHO_VECTOR_CLEAR(vec)   do { \
        rhoL_free((vec).buf); \
        (vec).buf = NULL; \
        (vec).ptr = 0; \
        (vec).len = 0; \
    } while (0)

/*
 * Clear a vector, first calling the provided function on each vector
 * element.
 */
#define RHO_VECTOR_CLEAREXT(vec, fun)   do { \
        size_t vec_tmp; \
        for (vec_tmp = 0; vec_tmp < (vec).ptr; vec_tmp ++) { \
            (fun)(&(vec).buf[vec_tmp]); \
        } \
        RHO_VECTOR_CLEAR(vec); \
    } while (0)

/*
 * Add a value at the end of a vector.
 */
#define RHO_VECTOR_ADD(vec, x)   do { \
        (vec).buf = rho_vector_expand((vec).buf, sizeof *((vec).buf), \
            &(vec).ptr, &(vec).len, 1); \
        (vec).buf[(vec).ptr ++] = (x); \
    } while (0)

/*
 * Add several values at the end of a vector.
 */
#define RHO_VECTOR_ADDMANY(vec, xp, num)   do { \
        size_t vec_num = (num); \
        (vec).buf = rho_vector_expand((vec).buf, sizeof *((vec).buf), \
            &(vec).ptr, &(vec).len, vec_num); \
        memcpy((vec).buf + (vec).ptr, \
            (xp), vec_num * sizeof *((vec).buf)); \
        (vec).ptr += vec_num; \
    } while (0)

/*
 * Access a vector element by index. This is a lvalue, and can be modified.
 */
#define RHO_VECTOR_ELT(vec, idx)   ((vec).buf[idx])

/*
 * Get current vector length.
 */
#define RHO_VECTOR_LEN(vec)   ((vec).ptr)

/*
 * Copy all vector elements into a newly allocated block.
 */
#define RHO_VECTOR_TOARRAY(vec) \
    rhoL_memdup((vec).buf, sizeof *((vec).buf) * (vec).ptr)

/*
 * Internal function used to handle memory allocations for vectors.
 */
void * rho_vector_expand(void *buf, size_t esize, size_t *ptr, size_t *len,
        size_t extra);

RHO_DECLS_END

#endif /* _RHO_VECTOR_H_ */
