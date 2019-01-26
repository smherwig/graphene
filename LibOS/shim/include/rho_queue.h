/*	$OpenBSD: queue.h,v 1.44 2016/09/09 20:31:46 millert Exp $	*/
/*	$NetBSD: queue.h,v 1.11 1996/05/16 05:17:14 mycroft Exp $	*/

/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)queue.h	8.5 (Berkeley) 8/20/94
 */

#ifndef	_RHO_QUEUE_H_
#define	_RHO_QUEUE_H_

/* SMHERWIG -- add stddef.h for NULL definition.  I also removed
 * THE XOR SIMPLEQ functions, as its use seems niche.
 */
//#include <sys/_null.h>    SMHERWIG
#include <stddef.h>         // SMHERWIG

/*
 * This file defines five types of data structures: singly-linked lists,
 * lists, simple queues, tail queues and XOR simple queues.
 *
 *
 * A singly-linked list is headed by a single forward pointer. The elements
 * are singly linked for minimum space and pointer manipulation overhead at
 * the expense of O(n) removal for arbitrary elements. New elements can be
 * added to the list after an existing element or at the head of the list.
 * Elements being removed from the head of the list should use the explicit
 * macro for this purpose for optimum efficiency. A singly-linked list may
 * only be traversed in the forward direction.  Singly-linked lists are ideal
 * for applications with large datasets and few or no removals or for
 * implementing a LIFO queue.
 *
 * A list is headed by a single forward pointer (or an array of forward
 * pointers for a hash table header). The elements are doubly linked
 * so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before
 * or after an existing element or at the head of the list. A list
 * may only be traversed in the forward direction.
 *
 * A simple queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are singly
 * linked to save space, so elements can only be removed from the
 * head of the list. New elements can be added to the list before or after
 * an existing element, at the head of the list, or at the end of the
 * list. A simple queue may only be traversed in the forward direction.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * An XOR simple queue is used in the same way as a regular simple queue.
 * The difference is that the head structure also includes a "cookie" that
 * is XOR'd with the queue pointer (first, last or next) to generate the
 * real pointer value.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 */

#if defined(RHO_QUEUE_MACRO_DEBUG) || (defined(_KERNEL) && defined(DIAGNOSTIC))
#define _RHO_Q_INVALIDATE(a) (a) = ((void *)-1)
#else
#define _RHO_Q_INVALIDATE(a)
#endif

/*
 * Singly-linked List definitions.
 */
#define RHO_SLIST_HEAD(name, type)						\
struct name {								\
	struct type *slh_first;	/* first element */			\
}

#define	RHO_SLIST_HEAD_INITIALIZER(head)					\
	{ NULL }

#define RHO_SLIST_ENTRY(type)						\
struct {								\
	struct type *sle_next;	/* next element */			\
}

/*
 * Singly-linked List access methods.
 */
#define	RHO_SLIST_FIRST(head)	((head)->slh_first)
#define	RHO_SLIST_END(head)		NULL
#define	RHO_SLIST_EMPTY(head)	(RHO_SLIST_FIRST(head) == RHO_SLIST_END(head))
#define	RHO_SLIST_NEXT(elm, field)	((elm)->field.sle_next)

#define	RHO_SLIST_FOREACH(var, head, field)					\
	for((var) = RHO_SLIST_FIRST(head);					\
	    (var) != RHO_SLIST_END(head);					\
	    (var) = RHO_SLIST_NEXT(var, field))

#define	RHO_SLIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = RHO_SLIST_FIRST(head);				\
	    (var) && ((tvar) = RHO_SLIST_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * Singly-linked List functions.
 */
#define	RHO_SLIST_INIT(head) {						\
	RHO_SLIST_FIRST(head) = RHO_SLIST_END(head);				\
}

#define	RHO_SLIST_INSERT_AFTER(slistelm, elm, field) do {			\
	(elm)->field.sle_next = (slistelm)->field.sle_next;		\
	(slistelm)->field.sle_next = (elm);				\
} while (0)

#define	RHO_SLIST_INSERT_HEAD(head, elm, field) do {			\
	(elm)->field.sle_next = (head)->slh_first;			\
	(head)->slh_first = (elm);					\
} while (0)

#define	RHO_SLIST_REMOVE_AFTER(elm, field) do {				\
	(elm)->field.sle_next = (elm)->field.sle_next->field.sle_next;	\
} while (0)

#define	RHO_SLIST_REMOVE_HEAD(head, field) do {				\
	(head)->slh_first = (head)->slh_first->field.sle_next;		\
} while (0)

#define RHO_SLIST_REMOVE(head, elm, type, field) do {			\
	if ((head)->slh_first == (elm)) {				\
		RHO_SLIST_REMOVE_HEAD((head), field);			\
	} else {							\
		struct type *curelm = (head)->slh_first;		\
									\
		while (curelm->field.sle_next != (elm))			\
			curelm = curelm->field.sle_next;		\
		curelm->field.sle_next =				\
		    curelm->field.sle_next->field.sle_next;		\
	}								\
	_RHO_Q_INVALIDATE((elm)->field.sle_next);				\
} while (0)

/*
 * List definitions.
 */
#define RHO_LIST_HEAD(name, type)						\
struct name {								\
	struct type *lh_first;	/* first element */			\
}

#define RHO_LIST_HEAD_INITIALIZER(head)					\
	{ NULL }

#define RHO_LIST_ENTRY(type)						\
struct {								\
	struct type *le_next;	/* next element */			\
	struct type **le_prev;	/* address of previous next element */	\
}

/*
 * List access methods.
 */
#define	RHO_LIST_FIRST(head)		((head)->lh_first)
#define	RHO_LIST_END(head)			NULL
#define	RHO_LIST_EMPTY(head)		(RHO_LIST_FIRST(head) == RHO_LIST_END(head))
#define	RHO_LIST_NEXT(elm, field)		((elm)->field.le_next)

#define RHO_LIST_FOREACH(var, head, field)					\
	for((var) = RHO_LIST_FIRST(head);					\
	    (var)!= RHO_LIST_END(head);					\
	    (var) = RHO_LIST_NEXT(var, field))

#define	RHO_LIST_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = RHO_LIST_FIRST(head);				\
	    (var) && ((tvar) = RHO_LIST_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * List functions.
 */
#define	RHO_LIST_INIT(head) do {						\
	RHO_LIST_FIRST(head) = RHO_LIST_END(head);				\
} while (0)

#define RHO_LIST_INSERT_AFTER(listelm, elm, field) do {			\
	if (((elm)->field.le_next = (listelm)->field.le_next) != NULL)	\
		(listelm)->field.le_next->field.le_prev =		\
		    &(elm)->field.le_next;				\
	(listelm)->field.le_next = (elm);				\
	(elm)->field.le_prev = &(listelm)->field.le_next;		\
} while (0)

#define	RHO_LIST_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.le_prev = (listelm)->field.le_prev;		\
	(elm)->field.le_next = (listelm);				\
	*(listelm)->field.le_prev = (elm);				\
	(listelm)->field.le_prev = &(elm)->field.le_next;		\
} while (0)

#define RHO_LIST_INSERT_HEAD(head, elm, field) do {				\
	if (((elm)->field.le_next = (head)->lh_first) != NULL)		\
		(head)->lh_first->field.le_prev = &(elm)->field.le_next;\
	(head)->lh_first = (elm);					\
	(elm)->field.le_prev = &(head)->lh_first;			\
} while (0)

#define RHO_LIST_REMOVE(elm, field) do {					\
	if ((elm)->field.le_next != NULL)				\
		(elm)->field.le_next->field.le_prev =			\
		    (elm)->field.le_prev;				\
	*(elm)->field.le_prev = (elm)->field.le_next;			\
	_RHO_Q_INVALIDATE((elm)->field.le_prev);				\
	_RHO_Q_INVALIDATE((elm)->field.le_next);				\
} while (0)

#define RHO_LIST_REPLACE(elm, elm2, field) do {				\
	if (((elm2)->field.le_next = (elm)->field.le_next) != NULL)	\
		(elm2)->field.le_next->field.le_prev =			\
		    &(elm2)->field.le_next;				\
	(elm2)->field.le_prev = (elm)->field.le_prev;			\
	*(elm2)->field.le_prev = (elm2);				\
	_RHO_Q_INVALIDATE((elm)->field.le_prev);				\
	_RHO_Q_INVALIDATE((elm)->field.le_next);				\
} while (0)

/*
 * Simple queue definitions.
 */
#define RHO_SIMPLEQ_HEAD(name, type)					\
struct name {								\
	struct type *sqh_first;	/* first element */			\
	struct type **sqh_last;	/* addr of last next element */		\
}

#define RHO_SIMPLEQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).sqh_first }

#define RHO_SIMPLEQ_ENTRY(type)						\
struct {								\
	struct type *sqe_next;	/* next element */			\
}

/*
 * Simple queue access methods.
 */
#define	RHO_SIMPLEQ_FIRST(head)	    ((head)->sqh_first)
#define	RHO_SIMPLEQ_END(head)	    NULL
#define	RHO_SIMPLEQ_EMPTY(head)	    (RHO_SIMPLEQ_FIRST(head) == RHO_SIMPLEQ_END(head))
#define	RHO_SIMPLEQ_NEXT(elm, field)    ((elm)->field.sqe_next)

#define RHO_SIMPLEQ_FOREACH(var, head, field)				\
	for((var) = RHO_SIMPLEQ_FIRST(head);				\
	    (var) != RHO_SIMPLEQ_END(head);					\
	    (var) = RHO_SIMPLEQ_NEXT(var, field))

#define	RHO_SIMPLEQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = RHO_SIMPLEQ_FIRST(head);				\
	    (var) && ((tvar) = RHO_SIMPLEQ_NEXT(var, field), 1);		\
	    (var) = (tvar))

/*
 * Simple queue functions.
 */
#define	RHO_SIMPLEQ_INIT(head) do {						\
	(head)->sqh_first = NULL;					\
	(head)->sqh_last = &(head)->sqh_first;				\
} while (0)

#define RHO_SIMPLEQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.sqe_next = (head)->sqh_first) == NULL)	\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(head)->sqh_first = (elm);					\
} while (0)

#define RHO_SIMPLEQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.sqe_next = NULL;					\
	*(head)->sqh_last = (elm);					\
	(head)->sqh_last = &(elm)->field.sqe_next;			\
} while (0)

#define RHO_SIMPLEQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.sqe_next = (listelm)->field.sqe_next) == NULL)\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
	(listelm)->field.sqe_next = (elm);				\
} while (0)

#define RHO_SIMPLEQ_REMOVE_HEAD(head, field) do {			\
	if (((head)->sqh_first = (head)->sqh_first->field.sqe_next) == NULL) \
		(head)->sqh_last = &(head)->sqh_first;			\
} while (0)

#define RHO_SIMPLEQ_REMOVE_AFTER(head, elm, field) do {			\
	if (((elm)->field.sqe_next = (elm)->field.sqe_next->field.sqe_next) \
	    == NULL)							\
		(head)->sqh_last = &(elm)->field.sqe_next;		\
} while (0)

#define RHO_SIMPLEQ_CONCAT(head1, head2) do {				\
	if (!RHO_SIMPLEQ_EMPTY((head2))) {					\
		*(head1)->sqh_last = (head2)->sqh_first;		\
		(head1)->sqh_last = (head2)->sqh_last;			\
		RHO_SIMPLEQ_INIT((head2));					\
	}								\
} while (0)

/*
 * Tail queue definitions.
 */
#define RHO_TAILQ_HEAD(name, type)						\
struct name {								\
	struct type *tqh_first;	/* first element */			\
	struct type **tqh_last;	/* addr of last next element */		\
}

#define RHO_TAILQ_HEAD_INITIALIZER(head)					\
	{ NULL, &(head).tqh_first }

#define RHO_TAILQ_ENTRY(type)						\
struct {								\
	struct type *tqe_next;	/* next element */			\
	struct type **tqe_prev;	/* address of previous next element */	\
}

/*
 * Tail queue access methods.
 */
#define	RHO_TAILQ_FIRST(head)		((head)->tqh_first)
#define	RHO_TAILQ_END(head)			NULL
#define	RHO_TAILQ_NEXT(elm, field)		((elm)->field.tqe_next)
#define RHO_TAILQ_LAST(head, headname)					\
	(*(((struct headname *)((head)->tqh_last))->tqh_last))
/* XXX */
#define RHO_TAILQ_PREV(elm, headname, field)				\
	(*(((struct headname *)((elm)->field.tqe_prev))->tqh_last))
#define	RHO_TAILQ_EMPTY(head)						\
	(RHO_TAILQ_FIRST(head) == RHO_TAILQ_END(head))

#define RHO_TAILQ_FOREACH(var, head, field)					\
	for((var) = RHO_TAILQ_FIRST(head);					\
	    (var) != RHO_TAILQ_END(head);					\
	    (var) = RHO_TAILQ_NEXT(var, field))

#define	RHO_TAILQ_FOREACH_SAFE(var, head, field, tvar)			\
	for ((var) = RHO_TAILQ_FIRST(head);					\
	    (var) != RHO_TAILQ_END(head) &&					\
	    ((tvar) = RHO_TAILQ_NEXT(var, field), 1);			\
	    (var) = (tvar))


#define RHO_TAILQ_FOREACH_REVERSE(var, head, headname, field)		\
	for((var) = RHO_TAILQ_LAST(head, headname);				\
	    (var) != RHO_TAILQ_END(head);					\
	    (var) = RHO_TAILQ_PREV(var, headname, field))

#define	RHO_TAILQ_FOREACH_REVERSE_SAFE(var, head, headname, field, tvar)	\
	for ((var) = RHO_TAILQ_LAST(head, headname);			\
	    (var) != RHO_TAILQ_END(head) &&					\
	    ((tvar) = RHO_TAILQ_PREV(var, headname, field), 1);		\
	    (var) = (tvar))

/*
 * Tail queue functions.
 */
#define	RHO_TAILQ_INIT(head) do {						\
	(head)->tqh_first = NULL;					\
	(head)->tqh_last = &(head)->tqh_first;				\
} while (0)

#define RHO_TAILQ_INSERT_HEAD(head, elm, field) do {			\
	if (((elm)->field.tqe_next = (head)->tqh_first) != NULL)	\
		(head)->tqh_first->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(head)->tqh_first = (elm);					\
	(elm)->field.tqe_prev = &(head)->tqh_first;			\
} while (0)

#define RHO_TAILQ_INSERT_TAIL(head, elm, field) do {			\
	(elm)->field.tqe_next = NULL;					\
	(elm)->field.tqe_prev = (head)->tqh_last;			\
	*(head)->tqh_last = (elm);					\
	(head)->tqh_last = &(elm)->field.tqe_next;			\
} while (0)

#define RH_TAILQ_INSERT_AFTER(head, listelm, elm, field) do {		\
	if (((elm)->field.tqe_next = (listelm)->field.tqe_next) != NULL)\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    &(elm)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm)->field.tqe_next;		\
	(listelm)->field.tqe_next = (elm);				\
	(elm)->field.tqe_prev = &(listelm)->field.tqe_next;		\
} while (0)

#define	RHO_TAILQ_INSERT_BEFORE(listelm, elm, field) do {			\
	(elm)->field.tqe_prev = (listelm)->field.tqe_prev;		\
	(elm)->field.tqe_next = (listelm);				\
	*(listelm)->field.tqe_prev = (elm);				\
	(listelm)->field.tqe_prev = &(elm)->field.tqe_next;		\
} while (0)

#define RHO_TAILQ_REMOVE(head, elm, field) do {				\
	if (((elm)->field.tqe_next) != NULL)				\
		(elm)->field.tqe_next->field.tqe_prev =			\
		    (elm)->field.tqe_prev;				\
	else								\
		(head)->tqh_last = (elm)->field.tqe_prev;		\
	*(elm)->field.tqe_prev = (elm)->field.tqe_next;			\
	_RHO_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_RHO_Q_INVALIDATE((elm)->field.tqe_next);				\
} while (0)

#define RHO_TAILQ_REPLACE(head, elm, elm2, field) do {			\
	if (((elm2)->field.tqe_next = (elm)->field.tqe_next) != NULL)	\
		(elm2)->field.tqe_next->field.tqe_prev =		\
		    &(elm2)->field.tqe_next;				\
	else								\
		(head)->tqh_last = &(elm2)->field.tqe_next;		\
	(elm2)->field.tqe_prev = (elm)->field.tqe_prev;			\
	*(elm2)->field.tqe_prev = (elm2);				\
	_RHO_Q_INVALIDATE((elm)->field.tqe_prev);				\
	_RHO_Q_INVALIDATE((elm)->field.tqe_next);				\
} while (0)

#define RHO_TAILQ_CONCAT(head1, head2, field) do {				\
	if (!RHO_TAILQ_EMPTY(head2)) {					\
		*(head1)->tqh_last = (head2)->tqh_first;		\
		(head2)->tqh_first->field.tqe_prev = (head1)->tqh_last;	\
		(head1)->tqh_last = (head2)->tqh_last;			\
		RHO_TAILQ_INIT((head2));					\
	}								\
} while (0)

#endif	/* !_RHO_QUEUE_H_ */
