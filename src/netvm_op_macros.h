/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * netvm_op_macros.h -- APIs for interaction with NetVM internals, including
 *   and especially for NetVM coprocessors.
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __netvm_op_macros_h
#define __netvm_op_macros_h

extern int netvm_dbgabrt();

#define VMERR(__vm, __e) \
	do { __vm->status = __e; netvm_dbgabrt(); return; } while (0)

#define VMERRRET(__vm, __e, __r) \
	do { __vm->status = __e; netvm_dbgabrt(); return __r; } while (0)

#define FATAL(__vm, __e, __cond) \
	if (__cond) { __vm->status = __e; netvm_dbgabrt(); return; }

/* check our run status and return if we it is not 'RUNNING' */
#define VMCKRET(__vm) \
	do { if ((__vm)->status != NETVM_STATUS_RUNNING) return; } while (0)

#define S_EMPTY(__vm)           (__vm->sp == __vm->bp)
#define S_HAS(__vm, __n)        (__vm->sp - __vm->bp >= __n)
#define S_FULL(__vm)            (__vm->sp >= __vm->stksz)
#define S_AVAIL(__vm)           (__vm->stksz - __vm->sp)

#define S_TOP(__vm, __v)                                                \
	do {                                                            \
		FATAL((__vm), NETVM_ERR_STKUNDF, S_EMPTY(__vm));        \
		__v = __vm->stack[__vm->sp-1];                          \
	} while (0)

/* __n is a 0-based index from the top of the stack */
#define S_GET(__vm, __n)        (__vm->stack[__vm->sp - __n - 1])
#define S_SET(__vm, __n, __val) (__vm->stack[__vm->sp - __n - 1] = __val)

#define S_POP(__vm, __v)                                                \
	do {                                                            \
		FATAL((__vm), NETVM_ERR_STKUNDF, S_EMPTY(__vm));        \
		__v = __vm->stack[--__vm->sp];                          \
	} while (0)

#define S_PUSH(__vm, __v)                                               \
	do {                                                            \
		FATAL((__vm), NETVM_ERR_STKOVFL, S_FULL(__vm));         \
		__vm->stack[__vm->sp++] = (__v);                        \
	} while (0)

#define S_POP_NOCK(__vm, __v)                                           \
	do {                                                            \
		__v = __vm->stack[--__vm->sp];                          \
	} while (0)

#define S_PUSH_NOCK(__vm, __v)                                          \
	do {                                                            \
		__vm->stack[__vm->sp++] = (__v);                        \
	} while (0)


/* Get a protocol descriptor */
void netvm_get_pd(struct netvm *vm, struct netvm_prp_desc *pd, int onstack);

/* Get a protocol descriptor and find the prp of the given packet */
struct prparse *netvm_find_header(struct netvm *vm, struct netvm_prp_desc *pd,
				  int onstack);

void netvm_get_prp_ptr(struct netvm *vm, int onstack, int width, byte_t **p);

void netvm_get_seg_ptr(struct netvm *vm, uint seg, ulong addr, int iswr, 
		       ulong len, byte_t **p);

void netvm_get_mem_ptr(struct netvm *vm, uint seg, ulong addr, int iswr, 
		       ulong len, byte_t **p);

void netvm_get_pkt_ptr(struct netvm *vm, uint pkt, ulong addr, int iswr, 
		       ulong len, byte_t **p);

void netvm_get_uaddr_ptr(struct netvm *vm, ulong uaddr, int iswr,
		         ulong len, byte_t **p);

void netvm_p2stk(struct netvm *vm, byte_t *p, int width);

void netvm_stk2p(struct netvm *vm, byte_t *p, ulong val, int width);

int netvm_valid_width(int width);

#endif /*__netvm_op_macros_h */
