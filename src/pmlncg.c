/*
 * ONICS
 * Copyright 2012-2015
 * Christopher Adam Telfer
 *
 * pmlncg.c -- PML code generation for the NetVM platform.
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
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <cat/cat.h>
#include <cat/str.h>

#include "pmlncg.h"
#include "netvm_std_coproc.h"

#define l_to_node(p) (union pml_node *)container(p, struct pml_node_base, ln)
#define MEMADDR(_a, _s)	NETVM_UADDR(0, (_s), (_a))
#define PKTADDR(_a, _p) NETVM_UADDR(1, (_p), (_a))

#define SCALAROP(_op) (((_op) >= PMLOP_EQ) && ((_op) <= PMLOP_NEG))

/* some forward declarations of commonly needed functions */
static int val32(struct pmlncg *cg, union pml_node *n, ulong *v);
static int cg_expr(struct pmlncg *cg, union pml_node *n, int etype);
static int cg_stmt(struct pmlncg *cg, union pml_node *n);
static int typecast(struct pmlncg *cg, int otype, int ntype);


struct cg_pdesc {
	int 			oc;
	int 			oci;
	uint8_t			x;
	uint			field;
	uint			prid;
	ulong			pfoff;
	union pml_expr_u *	pkt;
	union pml_expr_u *	idx;
	union pml_expr_u *	off;
};


struct cg_func_ctx {
	uint resolved;
	uint addr;
	uint called;
};


struct cg_lit_ctx {
	uint rexidx;
};


static void cgpd_init(struct cg_pdesc *cgpd, int oc, int oci, uint8_t x,
		      struct pml_locator *loc);
static int cg_pdop(struct pmlncg *cg, struct cg_pdesc *cgpd);



struct cgeaux {
	struct pmlncg *		cg;
	int			etype;
};


struct cgestk {
	uint			etype;
	uint			iaddr;
};


/* A numeric result of an expression that may or may not be on the stack. */
struct numval {
	int			onstack;
	ulong			val;
};


struct cg_intr;
typedef int (*cg_intr_func_f)(struct pmlncg *cg, struct pml_function *f,
			      struct cg_intr *intr);
typedef int (*cg_intr_call_f)(struct pmlncg *cg, struct pml_call *c,
			      struct cg_intr *intr);


#define CG_INTR_MAXOPS	4
struct cg_intr {
	const char *		name;
	cg_intr_func_f		cgfunc;
	cg_intr_call_f		cgcall;
	void *			ctx;
	uint			numop;
	struct netvm_inst	ops[CG_INTR_MAXOPS];
};


enum {
	TAG_OTHER = 0,
	TAG_TS = 1,
};
struct cg_meta_ctx {
	uchar			len;
	uchar			type;
	uchar			addr;
	uchar			tag_type;
	ulong			taghdr;
};


void cgerr(struct pmlncg *cg, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(cg->err, sizeof(cg->err), fmt, ap);
	va_end(ap);
}


void pib_init(struct pml_ibuf *b)
{
	abort_unless(b);
	b->inst = NULL;
	b->ninst = 0;
	b->size = 0;
}


void pib_clear(struct pml_ibuf *b)
{
	abort_unless(b);
	abort_unless((b->size == 0) == (b->inst == NULL));
	free(b->inst);
	b->ninst = 0;
	b->size = 0;
	b->addr = 0;
}


int pib_add(struct pml_ibuf *b, struct netvm_inst *i)
{
	struct netvm_inst *inst;
	uint sz;
	const uint maxsize = (UINT_MAX / sizeof(struct netvm_inst));

	abort_unless(b);
	abort_unless(i);
	abort_unless((b->size == 0) == (b->inst == NULL));

	if (b->ninst >= b->size) {
		abort_unless(b->ninst == b->size);
		if (b->size == 0) {
			sz = 1;
		} else {
			if (b->size > (maxsize >> 2)) {
				fprintf(stderr, "out of space for code\n");
				return -1;
			}
			sz = b->size << 2;
		}
		inst = realloc(b->inst, sz * sizeof(struct netvm_inst));
		if (inst == NULL) {
			fprintf(stderr, "out of space for code\n");
			return -1;
		}
		b->inst = inst;
		b->size = sz;
	}

	b->inst[b->ninst++] = *i;

	return 0;
}


static int pib_add_ixyzw(struct pml_ibuf *b, uint8_t oc, uint8_t x, uint8_t y,
			 uint8_t z, uint32_t w)
{
	struct netvm_inst in = { oc, x, y, z, w };
	return pib_add(b, &in);
}

#define EMIT_XYZW(_cg, SYM, _x, _y, _z, _w) 				\
	do { 		   						\
		if (pib_add_ixyzw(&(_cg)->ibuf, NETVM_OC_##SYM,         \
		    		  _x,_y,_z,_w) < 0) {			\
			cgerr(_cg, "out of instructions on %s:%d",	\
			      __FILE__, __LINE__);			\
			return -1;					\
		}							\
	} while (0)

#define EMIT_NULL(_ibuf, SYM) EMIT_XYZW(_ibuf, SYM, 0, 0, 0, 0)
#define EMIT_X(_ibuf, SYM, _x) EMIT_XYZW(_ibuf, SYM, _x, 0, 0, 0)
#define EMIT_Z(_ibuf, SYM, _z) EMIT_XYZW(_ibuf, SYM, 0, 0, _z, 0)
#define EMIT_W(_ibuf, SYM, _w) EMIT_XYZW(_ibuf, SYM, 0, 0, 0, _w)
#define EMIT_XW(_ibuf, SYM, _x, _w) EMIT_XYZW(_ibuf, SYM, _x, 0, 0, _w)
#define EMIT_XY(_ibuf, SYM, _x, _y) EMIT_XYZW(_ibuf, SYM, _x, _y, 0, 0)
#define EMIT_XYW(_ibuf, SYM, _x, _y, _w) EMIT_XYZW(_ibuf, SYM, _x, _y, 0, _w)


#define PUSH(_cg, _v) EMIT_W((_cg), PUSH, ((_v) & 0xFFFFFFFF))

#define UNIMPL(cg, s)							\
	do {								\
		cgerr(cg, "unimplemented operation" #s); 		\
		return -1;						\
	} while (0)


#define LDSREF_X(_cg, _l, _x) 					\
	do { 		 					\
		if (cg_load_strref_val((_cg), (_l), (_x)) < 0)	\
			return -1;				\
	} while(0)

#define LDSREF_ADDR(_cg, _l) LDSREF_X((_cg), (_l), 0)
#define LDSREF_LEN(_cg, _l) LDSREF_X((_cg), (_l), 1)


static uint8_t retlen(struct pml_function *f)
{
	switch (f->rtype) {
	case PML_ETYPE_VOID: return 0;
	case PML_ETYPE_SCALAR: return 1;
	case PML_ETYPE_BYTESTR: return 2; /* future */
	case PML_ETYPE_MASKVAL: return 3; /* future */
	case PML_ETYPE_STRREF: return 2;
	default:
		abort_unless(0);
		return 255;
	}
}

#define EMIT_RET_I(_cg, _f, _retlen) \
	EMIT_XW((_cg), RET, _retlen, ((_f)->pstksz / PML_SCALAR_SIZE))

#define EMIT_RET(_cg, _f) \
	EMIT_XW((_cg), RET, retlen(_f), ((_f)->pstksz / PML_SCALAR_SIZE))


static uint nexti(struct pml_ibuf *b)
{
	abort_unless(b);
	return b->ninst;
}


static ulong lvaraddr(struct pml_variable *var)
{
	struct pml_function *func = var->func;
	if (var->vtype == PML_VTYPE_LOCAL) {
		return var->addr / PML_SCALAR_SIZE; /* above BP */
	} else if (PML_FUNC_IS_INLINE(func)) {
		return var->addr / PML_SCALAR_SIZE + 1; /* below BP */
	} else {
		return var->addr / PML_SCALAR_SIZE + 2; /* below BP */
	}
}


static int cg_read_strref_var(struct pmlncg *cg, struct pml_locator *loc,
			      int getlen)
{
	struct pml_variable *v;

	v = loc->u.varref;
	abort_unless(v->etype == PML_ETYPE_STRREF);
	if (v->vtype == PML_VTYPE_LOCAL) {
		EMIT_XW(cg, LDBPI, 0, lvaraddr(v) + (getlen ? 1 : 0));
	} else if (v->vtype == PML_VTYPE_PARAM) {
		EMIT_XW(cg, LDBPI, 1, lvaraddr(v) + (getlen ? 0 : 1));
	} else {
		abort_unless(v->vtype == PML_VTYPE_GLOBAL);
		EMIT_XYW(cg, LDI, 4, PML_SEG_RWMEM, 
			 v->addr + (getlen ? 4 : 0));
	}

	return 0;
}


static int cg_load_strref_val(struct pmlncg *cg, struct pml_locator *loc,
			      int getlen)
{
	ulong val;
	struct pml_bytestr *bs;
	struct pml_variable *var;

	if (loc->reftype == PML_REF_LITERAL) {
		abort_unless(loc->u.litref->etype == PML_ETYPE_BYTESTR);
		bs = &loc->u.litref->u.bytestr;
		if (getlen) {
			PUSH(cg, bs->len);
		} else {
			val = MEMADDR(bs->addr, bs->segnum);
			PUSH(cg, val);
		}
	} else {
		abort_unless(loc->reftype == PML_REF_VAR);
		var = loc->u.varref;
		if (var->etype == PML_ETYPE_BYTESTR) {
			abort_unless(var->vtype == PML_VTYPE_GLOBAL);
			if (getlen)
				val = var->width;
			else
				val = MEMADDR(var->addr, PML_SEG_RWMEM);
			PUSH(cg, val);
		} else {
			abort_unless(var->etype == PML_ETYPE_STRREF);
			if (cg_read_strref_var(cg, loc, getlen) < 0)
				return -1;
		}
	}

	return 0;
}


/* 
 * rv == 1 means that the function was able to generated optimized string 
 * reference instructions.  rv < 0 means an error occurred.
 */
static int _cg_i_str_optimized(struct pmlncg *cg, struct pml_locator *loc,
			       struct cg_intr *intr)
{
	int accept;

	if (loc->off != NULL || loc->len != NULL)
		return 0;

	accept = (loc->reftype == PML_REF_LITERAL) && 
	         (loc->u.litref->type == PMLTT_BYTESTR);
	accept |= (loc->reftype == PML_REF_VAR) &&
	           ((loc->u.varref->etype == PML_ETYPE_BYTESTR) || 
	            (loc->u.varref->etype == PML_ETYPE_STRREF));
	if (!accept)
		return 0;

	if (strcmp(intr->name, "str_len") == 0) {
		LDSREF_LEN(cg, loc); 
	} else if (strcmp(intr->name, "str_addr") == 0) {
		LDSREF_ADDR(cg, loc); 
		EMIT_W(cg, ANDI, NETVM_UA_OFF_MASK);
	} else if (strcmp(intr->name, "str_ispkt") == 0) {
		if ((loc->reftype == PML_REF_LITERAL) || 
		    ((loc->reftype == PML_REF_VAR) && 
		     (loc->u.varref->etype != PML_ETYPE_STRREF))) {
			PUSH(cg, 0);
		} else {
			LDSREF_ADDR(cg, loc); 
			EMIT_W(cg, SHRI, NETVM_UA_ISPKT_OFF);
		}
	} else if (strcmp(intr->name, "str_seg") == 0) {
		LDSREF_ADDR(cg, loc); 
		EMIT_W(cg, SHRI, NETVM_UA_SEG_OFF);
		EMIT_W(cg, ANDI, NETVM_SEG_SEGMASK);
	} else if (strcmp(intr->name, "str_isnull") == 0) {
		LDSREF_LEN(cg, loc); 
		EMIT_W(cg, EQI, 0);
	} else {
		return 0;
	}

	return 1;
}


static int _i_str(struct pmlncg *cg, struct pml_call *c, struct cg_intr *intr)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct pml_list *pl = c->args;
	struct pml_function *f = c->func;
	union pml_node *e;
	int i, rv;

	abort_unless(f->arity == 1);
	e = l_to_node(l_head(&pl->list));

	if (e->base.type == PMLTT_LOCATOR) {
		rv = _cg_i_str_optimized(cg, (struct pml_locator *)e, intr);
		if (rv < 0)
			return -1;
		if (rv == 1)
			return 0;
	}
	if (cg_expr(cg, e, PML_ETYPE_STRREF) < 0)
		return -1;

	for (i = 0; i < intr->numop; ++i) {
		if (pib_add(b, &intr->ops[i]) < 0) {
			cgerr(cg, "out of instructions adding scalar intrinsic"
				  " '%s'", f->name);
			return -1;
		}
	}

	return 0;
}


static int _i_str_mkref(struct pmlncg *cg, struct pml_call *c,
			struct cg_intr *intr)
{
	struct pml_list *pl = c->args;
	union pml_node *e;

	/* ispkt */
	e = l_to_node(l_head(&pl->list));
	if (cg_expr(cg, e, PML_ETYPE_SCALAR) < 0)
		return -1;
	EMIT_W(cg, SHLI, NETVM_UA_ISPKT_OFF);

	/* seg */
	e = l_to_node(l_next(&e->base.ln));
	if (cg_expr(cg, e, PML_ETYPE_SCALAR) < 0)
		return -1;
	EMIT_W(cg, ANDI, NETVM_SEG_SEGMASK);
	EMIT_W(cg, SHLI, NETVM_UA_SEG_OFF);
	EMIT_NULL(cg, OR);

	/* addr */
	e = l_to_node(l_next(&e->base.ln));
	if (cg_expr(cg, e, PML_ETYPE_SCALAR) < 0)
		return -1;
	EMIT_W(cg, ANDI, NETVM_UA_OFF_MASK);
	EMIT_NULL(cg, OR);

	/* len */
	e = l_to_node(l_next(&e->base.ln));
	if (cg_expr(cg, e, PML_ETYPE_SCALAR) < 0)
		return -1;

	return 0;
}


static int _i_scarg(struct pmlncg *cg, struct pml_call *c, struct cg_intr *intr)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct pml_list *pl = c->args;
	struct pml_function *f = c->func;
	union pml_node *e;
	int i;

	e = l_to_node(l_head(&pl->list));
	if (cg_expr(cg, e, PML_ETYPE_SCALAR) < 0)
		return -1;

	for (i = 1; i < f->arity; ++i) {
		e = l_to_node(l_next(&e->base.ln));
		if (cg_expr(cg, e, PML_ETYPE_SCALAR) < 0)
			return -1;
	}

	for (i = 0; i < intr->numop; ++i) {
		if (pib_add(b, &intr->ops[i]) < 0) {
			cgerr(cg, "out of instructions adding scalar intrinsic"
				  " '%s'", f->name);
			return -1;
		}
	}

	return 0;
}


int _i_loc_to_pdesc(struct pmlncg *cg, struct pml_locator *loc,
		    struct cg_intr *intr, int oc, int oci)
{
	struct cg_pdesc cgpd;
	if (loc->off) {
		cgerr(cg, "offset not allowed in locator for intrinsic '%s'",
		      intr->name);
		return -1;
	}
	if (loc->len) {
		cgerr(cg, "length not allowed in locator for intrinsic '%s'",
		      intr->name);
		return -1;
	}
	cgpd_init(&cgpd, oc, oci, 0, loc);
	return cg_pdop(cg, &cgpd);
}


static int _i_pdarg(struct pmlncg *cg, struct pml_call *c, struct cg_intr *intr)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct pml_list *pl = c->args;
	struct pml_locator *loc;
	int i;

	loc = (struct pml_locator *)l_to_node(l_head(&pl->list));
	if (loc->type != PMLTT_LOCATOR) {
		cgerr(cg, "intrinsic '%s' requires a protocol field",
		      intr->name);
		return -1;
	}

	if (_i_loc_to_pdesc(cg, loc, intr, -1, -1) < 0)
		return -1;

	for (i = 0; i < intr->numop; ++i) {
		if (pib_add(b, &intr->ops[i]) < 0) {
			cgerr(cg, "out of instructions generating packet"
				  " intrinsic %s", c->func->name);
			return -1;
		}
	}

	return 0;
}


static int _i_prpfunc(struct pmlncg *cg, struct pml_call *c,
		      struct cg_intr *intr)
{
	struct pml_list *pl = c->args;
	struct pml_locator *loc;
	union pml_node *e;

	loc = (struct pml_locator *)l_to_node(l_head(&pl->list));
	if (loc->type != PMLTT_LOCATOR) {
		cgerr(cg, "intrinsic '%s' requires a protocol field",
		      intr->name);
		return -1;
	}

	/* numop overloaded to indicate # of additional args */
	if (intr->numop > 0) {
		e = l_to_node(l_next(&loc->ln));
		if (cg_expr(cg, e, PML_ETYPE_SCALAR) < 0)
			return -1;
	}

	/* ops overloaded to store opcode for regular vs indirect ops */
	return _i_loc_to_pdesc(cg, loc, intr, intr->ops[0].op,
			       intr->ops[1].op);
}


static int _i_ins(struct pmlncg *cg, struct pml_call *c,
		  struct cg_intr *intr)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct pml_list *pl = c->args;
	union pml_node *pkt, *off, *len;
	ulong pv, ov;

	pkt = l_to_node(l_head(&pl->list));
	off = l_to_node(l_next(&pkt->base.ln));
	len = l_to_node(l_next(&off->base.ln));

	if (PML_EXPR_IS_LITERAL(pkt) && PML_EXPR_IS_LITERAL(off)) {
		if (val32(cg, pkt, &pv) < 0)
			return -1;
		if (val32(cg, off, &ov) < 0)
			return -1;
		PUSH(cg, PKTADDR(ov, pv));
	} else {
		if (cg_expr(cg, pkt, PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_W(cg, ORI, NETVM_SEG_ISPKT);
		EMIT_W(cg, SHLI, NETVM_UA_SEG_OFF);
		if (cg_expr(cg, off, PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_W(cg, ANDI, NETVM_UA_OFF_MASK);
		EMIT_NULL(cg, OR);
	}

	if (cg_expr(cg, len, PML_ETYPE_SCALAR) < 0)
		return -1;

	if (pib_add(b, &intr->ops[0]) < 0) {
		cgerr(cg, "out of instructions adding pml_ins_* intrinsic");
		return -1;
	}

	return 0;
}


static int _i_cut(struct pmlncg *cg, struct pml_call *c,
		  struct cg_intr *intr)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct pml_list *pl = c->args;
	union pml_node *str;

	str = l_to_node(l_head(&pl->list));
	if (cg_expr(cg, str, PML_ETYPE_STRREF) < 0)
		return -1;
	if (pib_add(b, &intr->ops[0]) < 0) {
		cgerr(cg, "out of instructions adding pml_ins_* intrinsic");
		return -1;
	}

	return 0;
}


static int _i_pktoff(struct pmlncg *cg, struct pml_call *c,
		     struct cg_intr *intr)
{
	struct pml_list *pl = c->args;
	union pml_node *pnum, *prid, *idx, *oid, *amt = NULL;
	int isadj;

	isadj = strcmp(intr->name, "pkt_adj_off") == 0;

	pnum = l_to_node(l_head(&pl->list));
	prid = l_to_node(l_next(&pnum->base.ln));
	idx = l_to_node(l_next(&prid->base.ln));
	oid = l_to_node(l_next(&idx->base.ln));
	if (isadj)
		amt = l_to_node(l_next(&oid->base.ln));

	/* generate the packet number */
	if (cg_expr(cg, pnum, PML_ETYPE_SCALAR) < 0)
		return -1;
	EMIT_W(cg, ORI, NETVM_SEG_ISPKT);
	EMIT_W(cg, SHLI, NETVM_PD_PKT_OFF);

	/* generate the PRID */
	if (cg_expr(cg, prid, PML_ETYPE_SCALAR) < 0)
		return -1;
	EMIT_W(cg, SHLI, NETVM_PD_PRID_OFF);

	/* generate the index */
	if (cg_expr(cg, idx, PML_ETYPE_SCALAR) < 0)
		return -1;
	EMIT_W(cg, ANDI, NETVM_PD_IDX_MASK);
	EMIT_W(cg, SHLI, NETVM_PD_IDX_OFF);
	EMIT_NULL(cg, OR);

	/* generate offset ID (field) */
	if (cg_expr(cg, oid, PML_ETYPE_SCALAR) < 0)
		return -1;
	EMIT_W(cg, ADDI, NETVM_PRP_OFF_BASE);
	EMIT_W(cg, ANDI, NETVM_PD_FLD_MASK);
	EMIT_W(cg, SHLI, NETVM_PD_FLD_OFF);
	EMIT_NULL(cg, OR);

	if (isadj) {
		if (cg_expr(cg, amt, PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_NULL(cg, PKADJ);
	} else {
		EMIT_NULL(cg, LDPF);
	}
		
	return 0;
}


static int _i_cg_listop(struct pmlncg *cg, struct pml_call *c,
		        struct cg_intr *intr)
{
	struct pml_list *pl = c->args;
	union pml_node *list, *pnum;
	int cpop;

	if (strcmp(intr->name, "pkt_nlists") == 0) {
		cpop = NETVM_CPOC_NUMQ;
	} else if (strcmp(intr->name, "pkt_lempty") == 0) {
		list = l_to_node(l_head(&pl->list));
		if (cg_expr(cg, list, PML_ETYPE_SCALAR) < 0)
			return -1;
		cpop = NETVM_CPOC_QEMPTY;
	} else {
		list = l_to_node(l_head(&pl->list));
		pnum = l_to_node(l_next(&list->base.ln));
		if (cg_expr(cg, list, PML_ETYPE_SCALAR) < 0)
			return -1;
		if (cg_expr(cg, pnum, PML_ETYPE_SCALAR) < 0)
			return -1;
		if (strcmp(intr->name, "pkt_enq") == 0) {
			cpop = NETVM_CPOC_ENQ;
		} else if (strcmp(intr->name, "pkt_deq") == 0 || 
			   strcmp(intr->name, "pkt_pop") == 0) {
			cpop = NETVM_CPOC_DEQ;
		} else if (strcmp(intr->name, "pkt_push") == 0) {
			cpop = NETVM_CPOC_PUSH;
		} else {
			abort_unless(0);
		}
	}

	EMIT_XY(cg, CPOPI, NETVM_CPI_PKTQ, cpop);

	return 0;
}


/*
 * generate a metadata get function based on parameters from
 * a cg_meta_ctx structure
 */
static int _i_cg_mget(struct pmlncg *cg, struct pml_function *f,
		      struct cg_intr *intr)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct cg_meta_ctx *x = intr->ctx;
	struct cg_func_ctx *fc = (struct cg_func_ctx *)f->cgctx;

	abort_unless(x);

	fc->addr = nexti(b);
	fc->resolved = 1;

	/* [] form tag descriptor and copy */
	EMIT_XW(cg, LDBPI, 1, 2);
	EMIT_W(cg, ORI, x->type << 8);
	EMIT_W(cg, DUP, 0);

	/* [td, td] check whether tag is present */
	PUSH(cg, NETVM_CPOC_HASTAG);
	PUSH(cg, NETVM_CPI_XPKT);
	EMIT_NULL(cg, CPOP);
	EMIT_W(cg, BNZI, 3);

	/* [td] if no tag, then return -1  */
	PUSH(cg, 0xFFFFFFFF);
	EMIT_RET_I(cg, f, 1);

	/* [td] read the tag into the coprocessor mem */
	PUSH(cg, NETVM_CPOC_LDTAG);
	PUSH(cg, NETVM_CPI_XPKT);
	EMIT_NULL(cg, CPOP);

	/* [] copy the value out of coprocessor memory */
	PUSH(cg, x->addr);
	PUSH(cg, NETVM_CPOC_LDTB);
	PUSH(cg, NETVM_CPI_XPKT);
	EMIT_Z(cg, CPOP, x->len);

	EMIT_RET_I(cg, f, 1);

	return 0;
}


/*
 * generate a metadata set function based on parameters from
 * a cg_meta_ctx structure
 */
static int _i_cg_mset(struct pmlncg *cg, struct pml_function *f,
		      struct cg_intr *intr)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct cg_meta_ctx *x = intr->ctx;
	struct cg_func_ctx *fc = (struct cg_func_ctx *)f->cgctx;

	abort_unless(x);
	fc->addr = nexti(b);
	fc->resolved = 1;

	/* [] form tag descriptor and copy */
	EMIT_XW(cg, LDBPI, 1, 2);
	EMIT_W(cg, ORI, x->type << 8);
	EMIT_W(cg, DUP, 0);

	/* [td,td]: check whether tag is present and skip if not so */
	PUSH(cg, NETVM_CPOC_HASTAG);
	PUSH(cg, NETVM_CPI_XPKT);
	EMIT_NULL(cg, CPOP);
	EMIT_W(cg, BZI, 5);

	/* [td] delete the current tag */
	EMIT_W(cg, DUP, 0);
	EMIT_W(cg, PUSH, NETVM_CPOC_DELTAG);
	EMIT_W(cg, PUSH, NETVM_CPI_XPKT);
	EMIT_NULL(cg, CPOP);

	/* [td] if tag to add is -1 then we are done:  return */
	EMIT_XW(cg, LDBPI, 1, 3);
	if (x->tag_type == TAG_TS) {
		EMIT_XW(cg, LDBPI, 1, 4);
		EMIT_NULL(cg, AND);
	}
	EMIT_W(cg, ADDI, 1);
	EMIT_W(cg, BNZI, 2);
	EMIT_RET_I(cg, f, 0);

	/* [td] clear the tag buffer */
	PUSH(cg, NETVM_CPOC_CLRTBUF);
	PUSH(cg, NETVM_CPI_XPKT);
	EMIT_NULL(cg, CPOP);

	/* [td] write the tag header */
	PUSH(cg, x->taghdr);
	PUSH(cg, 0);
	PUSH(cg, NETVM_CPOC_STTB);
	PUSH(cg, NETVM_CPI_XPKT);
	EMIT_Z(cg, CPOP, 4);

	/* [td] Load the tag value */
	EMIT_XW(cg, LDBPI, 1, 3);
	PUSH(cg, x->addr);
	PUSH(cg, NETVM_CPOC_STTB);
	PUSH(cg, NETVM_CPI_XPKT);
	EMIT_Z(cg, CPOP, x->len);

	if (x->tag_type == TAG_TS) {
		/* [td]: store nanosecond value to the tag buffer */
		EMIT_XW(cg, LDBPI, 1, 4);
		PUSH(cg, x->addr + x->len);
		PUSH(cg, NETVM_CPOC_STTB);
		PUSH(cg, NETVM_CPI_XPKT);
		EMIT_Z(cg, CPOP, x->len);
	}

	/* [td]: add the new tag */
	PUSH(cg, NETVM_CPOC_ADDTAG);
	PUSH(cg, NETVM_CPI_XPKT);
	EMIT_NULL(cg, CPOP);

	EMIT_RET_I(cg, f, 0);

	return 0;
}

/*
 * generate a generic metadata function based on parameters from
 * a cg_meta_ctx structure
 */
static int _i_cg_meta(struct pmlncg *cg, struct pml_function *f,
		      struct cg_intr *intr)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct cg_meta_ctx *x = intr->ctx;
	struct cg_func_ctx *fc = (struct cg_func_ctx *)f->cgctx;
	int nr = 0;

	abort_unless(x);
	fc->addr = nexti(b);
	fc->resolved = 1;

	if (x->type == NETVM_CPOC_ADDXTAG) {
		/* test whether type is APPINFO and push a 0 if so */
		/* if not, push the length given as a parameter. */
		if (x->len == 0) {
			EMIT_XW(cg, LDBPI, 1, 3);
			EMIT_W(cg, SUBI, XPKT_TAG_APPINFO);
			EMIT_W(cg, BZI, 2);
			PUSH(cg, 0);
		} else {
			EMIT_XW(cg, LDBPI, 1, 3);
		}
	}

	switch(x->type) {
	case NETVM_CPOC_HASTAG:
	case NETVM_CPOC_ADDXTAG:
	case NETVM_CPOC_DELTAG:
		EMIT_XW(cg, LDBPI, 1, 2);
		if (x->type != NETVM_CPOC_ADDXTAG || x->len == 0) {
			EMIT_XW(cg, LDBPI, 1, 3);
			EMIT_W(cg, SHLI, 8);
			EMIT_NULL(cg, OR);
		} else {
			EMIT_W(cg, ORI, (XPKT_TAG_APPINFO << 8));
		}
		PUSH(cg, x->type);
		PUSH(cg, NETVM_CPI_XPKT);
		EMIT_NULL(cg, CPOP);
		nr = (x->type == NETVM_CPOC_HASTAG);
		EMIT_RET_I(cg, f, nr);
		break;

	case NETVM_CPOC_RDTAG:
		/* [pnum, type, off] -> [td, off] */
		EMIT_XW(cg, LDBPI, 1, 4);
		EMIT_XW(cg, LDBPI, 1, 2);
		EMIT_XW(cg, LDBPI, 1, 3);
		EMIT_W(cg, SHLI, 8);
		EMIT_NULL(cg, OR);
		PUSH(cg, x->type);
		PUSH(cg, NETVM_CPI_XPKT);
		EMIT_Z(cg, CPOP, x->len);
		EMIT_RET_I(cg, f, 1);
		break;

	case NETVM_CPOC_WRTAG:
		/* [pnum, type, off, val] -> [td, val, off] */
		EMIT_XW(cg, LDBPI, 1, 4);
		EMIT_XW(cg, LDBPI, 1, 5);
		EMIT_XW(cg, LDBPI, 1, 2);
		EMIT_XW(cg, LDBPI, 1, 3);
		EMIT_W(cg, SHLI, 8);
		EMIT_NULL(cg, OR);
		PUSH(cg, x->type);
		PUSH(cg, NETVM_CPI_XPKT);
		EMIT_Z(cg, CPOP, x->len);
		EMIT_RET_I(cg, f, 0);
		break;
	default:
		abort_unless(0);
	}

	return 0;
}

struct cg_meta_ctx _i_ts_sec_ctx = 
	{ 4, XPKT_TAG_TIMESTAMP, 4, TAG_TS, 0x01020000 };
struct cg_meta_ctx _i_ts_nsec_ctx =
	{ 4, XPKT_TAG_TIMESTAMP, 8, TAG_TS, 0x01020000 };
struct cg_meta_ctx _i_snap_ctx =
	{ 4, XPKT_TAG_SNAPINFO, 4, TAG_OTHER, 0x02010000 };
struct cg_meta_ctx _i_inp_ctx =
	{ 2, XPKT_TAG_INIFACE, 2, TAG_OTHER, 0x03000000 };
struct cg_meta_ctx _i_outp_ctx =
	{ 2, XPKT_TAG_OUTIFACE, 2, TAG_OTHER, 0x04000000 };
struct cg_meta_ctx _i_flow_ctx =
	{ 4, XPKT_TAG_FLOW, 8, TAG_OTHER, 0x05020000 };
struct cg_meta_ctx _i_class_ctx =
	{ 4, XPKT_TAG_CLASS, 8, TAG_OTHER, 0x06020000 };
struct cg_meta_ctx _i_seq_ctx =
	{ 4, XPKT_TAG_SEQ, 8, TAG_OTHER, 0x07020000 };
struct cg_meta_ctx _i_has_ctx =
	{ 0, NETVM_CPOC_HASTAG, 0, 0, 0 };
struct cg_meta_ctx _i_add_ctx =
	{ 0, NETVM_CPOC_ADDXTAG, 0, 0, 0 };
struct cg_meta_ctx _i_add_info_ctx =
	{ 1, NETVM_CPOC_ADDXTAG, 0, 0, 0 };
struct cg_meta_ctx _i_rem_ctx =
	{ 0, NETVM_CPOC_DELTAG, 0, 0, 0 };
struct cg_meta_ctx _i_rd8_ctx =
	{ 1, NETVM_CPOC_RDTAG, 0, 0, 0 };
struct cg_meta_ctx _i_rd16_ctx =
	{ 2, NETVM_CPOC_RDTAG, 0, 0, 0 };
struct cg_meta_ctx _i_rd32_ctx =
	{ 4, NETVM_CPOC_RDTAG, 0, 0, 0 };
struct cg_meta_ctx _i_wr8_ctx =
	{ 1, NETVM_CPOC_WRTAG, 0, 0, 0 };
struct cg_meta_ctx _i_wr16_ctx =
	{ 2, NETVM_CPOC_WRTAG, 0, 0, 0 };
struct cg_meta_ctx _i_wr32_ctx =
	{ 4, NETVM_CPOC_WRTAG, 0, 0, 0 };

struct cg_intr intrinsics[] = { 
	{ "str_len", NULL, _i_str, NULL, 2, 
		{ NETVM_OP(SWAP,0,0,0,1),
		  NETVM_OP(POP,0,0,0,1) } },
	{ "str_addr", NULL, _i_str, NULL, 2, 
		{ NETVM_OP(POP,0,0,0,1),
		  NETVM_OP(ANDI,0,0,0,NETVM_UA_OFF_MASK) } },
	{ "str_ispkt", NULL, _i_str, NULL, 2, 
		{ NETVM_OP(POP,0,0,0,1), 
		  NETVM_OP(SHRI,0,0,0,NETVM_UA_ISPKT_OFF) } },
	{ "str_seg", NULL, _i_str, NULL, 3, 
		{ NETVM_OP(POP,0,0,0,1), 
		  NETVM_OP(SHRI,0,0,0,NETVM_UA_SEG_OFF),
		  NETVM_OP(ANDI,0,0,0,NETVM_SEG_SEGMASK) } },
	{ "str_isnull", NULL, _i_str, NULL, 3, 
		{ NETVM_OP(SWAP,0,0,0,1),
		  NETVM_OP(POP,0,0,0,1),
	          NETVM_OP(EQI,0,0,0,0)	} },
	{ "str_mkref", NULL, _i_str_mkref, NULL, 0, { {0} } },
	{ "pkt_new", NULL, _i_scarg, NULL, 1, { NETVM_OP(PKNEW,1,0,0,0) } },
	{ "pkt_new_z", NULL, _i_scarg, NULL, 1, { NETVM_OP(PKNEW,0,0,0,0) } },
	{ "pkt_swap", NULL, _i_scarg, NULL, 1, { NETVM_OP(PKSWAP,0,0,0,0) } },
	{ "pkt_copy", NULL, _i_scarg, NULL, 1, { NETVM_OP(PKCOPY,0,0,0,0) } },
	{ "pkt_ins_u", NULL, _i_ins, NULL, 1, { NETVM_OP(PKINS,1,0,0,0) } },
	{ "pkt_ins_d", NULL, _i_ins, NULL, 1, { NETVM_OP(PKINS,0,0,0,0) } },
	{ "pkt_cut_u", NULL, _i_cut, NULL, 1, { NETVM_OP(PKCUT,1,0,0,0) } },
	{ "pkt_cut_d", NULL, _i_cut, NULL, 1, { NETVM_OP(PKCUT,0,0,0,0) } },
	{ "pkt_parse", NULL, _i_scarg, NULL, 1, { NETVM_OP(PKPRS,0,0,0,0) } },
	{ "pkt_get_off", NULL, _i_pktoff, NULL, 0, { {0} } },
	{ "pkt_adj_off", NULL, _i_pktoff, NULL, 0, { {0} } },
	{ "pkt_nlists", NULL, _i_cg_listop, NULL, 0, { {0} } },
	{ "pkt_lempty", NULL, _i_cg_listop, NULL, 0, { {0} } },
	{ "pkt_enq",    NULL, _i_cg_listop, NULL, 0, { {0} } },
	{ "pkt_deq",    NULL, _i_cg_listop, NULL, 0, { {0} } },
	{ "pkt_push",   NULL, _i_cg_listop, NULL, 0, { {0} } },
	{ "pkt_pop",    NULL, _i_cg_listop, NULL, 0, { {0} } },
	{ "parse_push_back",  NULL, _i_scarg, NULL, 1,
		{ NETVM_OP(PKPPSH,0,0,0,0) } },
	{ "parse_pop_back",   NULL, _i_scarg, NULL, 1,
		{ NETVM_OP(PKPPOP,0,0,0,0) } },
	{ "parse_push_front", NULL, _i_scarg, NULL, 1,
		{ NETVM_OP(PKPPSH,1,0,0,0) } },
	{ "parse_pop_front",  NULL, _i_scarg, NULL, 1,
		{ NETVM_OP(PKPPOP,1,0,0,0) } },
	{ "parse_update", NULL, _i_pdarg, NULL, 1, 
		{ NETVM_OP(PKPUP,0,0,0,0) } },
	{ "prp_insert", NULL, _i_prpfunc, NULL, 1 /* override */,
		{ NETVM_OP(PKPI,0,0,0,0), NETVM_OP(PKPII,0,0,0,0) } },
	{ "prp_delete", NULL, _i_prpfunc, NULL, 0 /* override */,
		{ NETVM_OP(PKPD,0,0,0,0), NETVM_OP(PKPDI,0,0,0,0) } },
	{ "fix_dltype", NULL, _i_scarg, NULL, 1, { NETVM_OP(PKFXD,0,0,0,0) } },
	{ "fix_len", NULL, _i_pdarg, NULL, 1, { NETVM_OP(PKFXL,0,0,0,0) } },
	{ "fix_lens",  NULL, _i_scarg, NULL, 4, 
		{ NETVM_OP(ORI,0,0,0,NETVM_SEG_ISPKT),
		  NETVM_OP(SHLI,0,0,0,NETVM_PD_PKT_OFF),
		  NETVM_OP(PUSH,0,0,0,NETVM_PDESC_W0(PRID_NONE,0,0)),
		  NETVM_OP(PKFXL,0,0,0,0), } },
	{ "fix_csum", NULL, _i_pdarg, NULL, 1, { NETVM_OP(PKFXC,0,0,0,0) } },
	{ "fix_csums", NULL, _i_scarg, NULL, 4,
		{ NETVM_OP(ORI,0,0,0,NETVM_SEG_ISPKT),
		  NETVM_OP(SHLI,0,0,0,NETVM_PD_PKT_OFF),
		  NETVM_OP(PUSH,0,0,0,NETVM_PDESC_W0(PRID_NONE,0,0)),
		  NETVM_OP(PKFXC,0,0,0,0), } },

	/* 
	 * these get full regular function implementations and require 
	 * no special calling conventions.
	 */
	{ "meta_get_ts_sec",  _i_cg_mget, NULL, &_i_ts_sec_ctx,  0, { {0} } },
	{ "meta_get_ts_nsec", _i_cg_mget, NULL, &_i_ts_nsec_ctx, 0, { {0} } },
	{ "meta_get_presnap", _i_cg_mget, NULL, &_i_snap_ctx,    0, { {0} } },
	{ "meta_get_inport",  _i_cg_mget, NULL, &_i_inp_ctx,     0, { {0} } },
	{ "meta_get_outport", _i_cg_mget, NULL, &_i_outp_ctx,    0, { {0} } },
	{ "meta_get_flowid",  _i_cg_mget, NULL, &_i_flow_ctx,    0, { {0} } },
	{ "meta_get_class",   _i_cg_mget, NULL, &_i_class_ctx,   0, { {0} } },
	{ "meta_get_seq",     _i_cg_mget, NULL, &_i_seq_ctx,     0, { {0} } },
	{ "meta_set_ts",      _i_cg_mset, NULL, &_i_ts_sec_ctx,  0, { {0} } },
	{ "meta_set_presnap", _i_cg_mset, NULL, &_i_snap_ctx,    0, { {0} } },
	{ "meta_set_inport",  _i_cg_mset, NULL, &_i_inp_ctx,     0, { {0} } },
	{ "meta_set_outport", _i_cg_mset, NULL, &_i_outp_ctx,    0, { {0} } },
	{ "meta_set_flowid",  _i_cg_mset, NULL, &_i_flow_ctx,    0, { {0} } },
	{ "meta_set_class",   _i_cg_mset, NULL, &_i_class_ctx,   0, { {0} } },
	{ "meta_set_seq",     _i_cg_mset, NULL, &_i_seq_ctx,     0, { {0} } },
	{ "meta_has",         _i_cg_meta, NULL, &_i_has_ctx,     0, { {0} } },
	{ "meta_add",         _i_cg_meta, NULL, &_i_add_ctx,     0, { {0} } },
	{ "meta_add_info",    _i_cg_meta, NULL, &_i_add_info_ctx,0, { {0} } },
	{ "meta_rem",         _i_cg_meta, NULL, &_i_rem_ctx,     0, { {0} } },
	{ "meta_rd8",         _i_cg_meta, NULL, &_i_rd8_ctx,     0, { {0} } },
	{ "meta_rd16",        _i_cg_meta, NULL, &_i_rd16_ctx,    0, { {0} } },
	{ "meta_rd32",        _i_cg_meta, NULL, &_i_rd32_ctx,    0, { {0} } },
	{ "meta_wr8",         _i_cg_meta, NULL, &_i_wr8_ctx,     0, { {0} } },
	{ "meta_wr16",        _i_cg_meta, NULL, &_i_wr16_ctx,    0, { {0} } },
	{ "meta_wr32",        _i_cg_meta, NULL, &_i_wr32_ctx,    0, { {0} } },

	{ "exit", NULL, _i_scarg, 0, 1, 
		{ NETVM_OP(HALT,0,0,0,NVMP_STATUS_EXIT) } },
	{ "pop", NULL, _i_scarg, 0, 1, { NETVM_OP(POPL,4,0,0,0) } },
	{ "log2", NULL, _i_scarg, 0, 2, 
		{ NETVM_OP(NLZ,4,0,0,0), NETVM_OP(SUBI,1,0,0,31) } },
	{ "min", NULL, _i_scarg, 0, 1, { NETVM_OP(MIN,0,0,0,0) } },
	{ "max", NULL, _i_scarg, 0, 1, { NETVM_OP(MAX,0,0,0,0) } },
	{ NULL, NULL, NULL, 0, 0, { {0} } },
};


struct cg_intr *find_intrinsic(struct pml_function *f)
{
	struct cg_intr *intr;
	for (intr = intrinsics; 
	     intr->name != NULL && (strcmp(intr->name, f->name) != 0);
	     ++intr) ;
	return (intr->name == NULL) ? NULL : intr;
}


static int cg_intrinsic(struct pmlncg *cg, struct pml_call *c, int etype)
{
	struct cg_intr *intr;
	struct pml_function *f = c->func;

	intr = find_intrinsic(f);

	if (intr == NULL) {
		cgerr(cg, "cg_intrinsic: intrinsic function '%s' not found",
		      f->name);
		return -1;
	}

	/* if callf == NULL, then the function call is by normal conventions */
	if (intr->cgcall == NULL)
		return 1;

	if ((*intr->cgcall)(cg, c, intr) < 0)
		return -1;

	if (typecast(cg, c->etype, etype) < 0)
		return -1;

	return 0;
}


static int pcg_save_iaddr(struct pml_ibuf *b, struct dynbuf *dyb)
{
	uint iaddr;
	abort_unless(b->ninst > 0);
	iaddr = b->ninst - 1;
	return dyb_cat_a(dyb, &iaddr, sizeof(iaddr));
}


void pcg_get_saved_iaddrs(struct dynbuf *dyb, uint **arr, uint *alen)
{
	*alen = dyb->len / sizeof(uint);
	*arr = (uint *)dyb->data;
}


static int pcg_save_callsite(struct pml_ibuf *b, struct dynbuf *dyb,
			     struct pml_function *func)
{
	struct callsite cs;
	abort_unless(b->ninst > 0);
	cs.func = func;
	cs.iaddr = b->ninst - 1;
	return dyb_cat_a(dyb, &cs, sizeof(cs));
}


void pcg_get_saved_callsites(struct dynbuf *dyb, struct callsite **arr,
			     uint *alen)
{
	*alen = dyb->len / sizeof(struct callsite);
	*arr = (struct callsite *)dyb->data;
}


static void pcg_resolve_branches(struct pml_ibuf *b, uint *iaddrs, uint naddrs,
				 uint addr)
{
	struct netvm_inst *inst;

	while (naddrs > 0) {
		abort_unless(*iaddrs < b->ninst);
		inst = b->inst + *iaddrs;
		inst->w = (ulong)addr - *iaddrs;
		++iaddrs;
		--naddrs;
	}
}


static int pcg_save_break(struct pmlncg *cg)
{
	return pcg_save_iaddr(&cg->ibuf, &cg->breaks);
}


static uint pcg_get_nbreaks(struct pmlncg *cg)
{
	return cg->breaks.len / sizeof(uint);
}


static void pcg_resolve_breaks(struct pmlncg *cg, uint bskip, uint addr)
{
	uint *iaddrs, naddrs;
	pcg_get_saved_iaddrs(&cg->breaks, &iaddrs, &naddrs);
	abort_unless(bskip <= naddrs);
	iaddrs += bskip;
	naddrs -= bskip;
	pcg_resolve_branches(&cg->ibuf, iaddrs, naddrs, addr);
	cg->breaks.len -= bskip * sizeof(uint);
}


static int pcg_save_continue(struct pmlncg *cg)
{
	return pcg_save_iaddr(&cg->ibuf, &cg->continues);
}


static uint pcg_get_ncontinues(struct pmlncg *cg)
{
	return cg->continues.len / sizeof(uint);
}


static void pcg_resolve_continues(struct pmlncg *cg, uint cskip, uint addr)
{
	uint *iaddrs, naddrs;
	pcg_get_saved_iaddrs(&cg->continues, &iaddrs, &naddrs);
	abort_unless(cskip <= naddrs);
	iaddrs += cskip;
	naddrs -= cskip;
	pcg_resolve_branches(&cg->ibuf, iaddrs, naddrs, addr);
	cg->continues.len -= naddrs * sizeof(uint);
}


static int pcg_save_nextrule(struct pmlncg *cg)
{
	return pcg_save_iaddr(&cg->ibuf, &cg->nextrules);
}


static void pcg_resolve_nextrules(struct pmlncg *cg, uint addr)
{
	uint *iaddrs, naddrs;
	pcg_get_saved_iaddrs(&cg->nextrules, &iaddrs, &naddrs);
	pcg_resolve_branches(&cg->ibuf, iaddrs, naddrs, addr);
	dyb_empty(&cg->nextrules);
}


static int copy_meminits(struct pml_ast *ast, struct netvm_program *prog,
		         int copy)
{
	struct netvm_meminit *inits = prog->inits;
	struct pml_symtab *st;
	struct dynbuf tb;
	void *p;
	int esave;
	uint len;
	int i;

	abort_unless(ast->mi_bufs[PML_SEG_ROMEM].off == 0);
	abort_unless(ast->mi_bufs[PML_SEG_RWMEM].off == 0);

	dyb_init(&tb, NULL);

	prog->ninits = 0;

	len = ast->mi_bufs[PML_SEG_ROMEM].len;
	if (len > 0) {
		inits->segnum = PML_SEG_ROMEM;
		inits->off = 0;
		inits->val.len = len;
		if (copy) {
			if (dyb_copy(&tb, &ast->mi_bufs[PML_SEG_ROMEM]) < 0)
				goto err_free;
			inits->val.data = dyb_release(&tb);
		} else {
			inits->val.data = ast->mi_bufs[PML_SEG_ROMEM].data;
		}
		++inits;
		++prog->ninits;
	}

	len = ast->vars.addr_rw1;
	if (len > 0) {
		inits->segnum = PML_SEG_RWMEM;
		inits->off = 0;
		inits->val.len = len;
		p = ast->mi_bufs[PML_SEG_RWMEM].data;
		if (copy) {
			if (dyb_set_a(&tb, 0, p, len) < 0)
				goto err_free;
			inits->val.data = dyb_release(&tb);
		} else {
			inits->val.data = p;
		}
		++inits;
		++prog->ninits;
	}

	st = &ast->vars;
	len = st->addr_rw2 - st->addr_rw1;
	if (len > 0) {
		inits->segnum = PML_SEG_RWMEM;
		inits->off = st->addr_rw1;
		inits->val.len = len;
		inits->val.data = NULL;
		++inits;
		++prog->ninits;
	}
	
	return 0;

err_free:
	esave = errno;
	for (i = 0; i < prog->ninits; ++i) {
		if (prog->inits[i].val.data != NULL) {
			free(prog->inits[i].val.data);
			prog->inits[i].val.data = NULL;
		}
	}
	prog->ninits = 0;
	errno = esave;
	return -1;
}


static void init_segs(struct pmlncg *cg)
{
	struct pml_ast *ast;
	struct netvm_program *prog;
	struct netvm_segdesc *sd;

	abort_unless(cg && cg->ast && cg->prog);
	ast = cg->ast;
	prog = cg->prog;

	sd = &prog->sdescs[PML_SEG_ROMEM];
	sd->len = ast->mi_bufs[PML_SEG_ROMEM].len;
	if (sd->len > 0)
		sd->perms = NETVM_SEG_RD;
	else
		sd->perms = 0;
	
	sd = &prog->sdescs[PML_SEG_RWMEM];
	sd->len = ast->vars.addr_rw2;
	if (sd->len > 0)
		sd->perms = NETVM_SEG_RD|NETVM_SEG_WR;
	else
		sd->perms = 0;
}


static void init_coproc(struct pmlncg *cg)
{
	int i;
	struct netvm_program *prog;

	abort_unless(cg && cg->prog);
	prog = cg->prog;

	for (i = 0; i < NETVM_MAXCOPROC; ++i)
		prog->cpreqs[i] = NETVM_CPT_NONE;

	prog->cpreqs[NETVM_CPI_XPKT] = NETVM_CPT_XPKT;
	prog->cpreqs[NETVM_CPI_OUTPORT] = NETVM_CPT_OUTPORT;
	prog->cpreqs[NETVM_CPI_PKTQ] = NETVM_CPT_PKTQ;
	prog->cpreqs[NETVM_CPI_REX] = NETVM_CPT_REX;
}


static int cg_scalar(struct pmlncg *cg, struct pml_literal *l)
{
	abort_unless(cg && l);
	PUSH(cg, l->u.scalar);
	return 0;
}


static int cg_bytestr(struct pmlncg *cg, struct pml_literal *l, int withlen)
{
	struct pml_bytestr *bs;

	abort_unless(cg && l);
	bs = &l->u.bytestr;

	PUSH(cg, bs->addr);
	if (bs->segnum != 0)
		EMIT_W(cg, ORI, (bs->segnum << NETVM_UA_SEG_OFF));
	if (withlen)
		PUSH(cg, bs->len);

	return 0;
}


static int cg_maskval(struct pmlncg *cg, struct pml_literal *l)
{
	struct pml_bytestr *val, *mask;

	abort_unless(cg && l);
	val = &l->u.maskval.val;
	mask = &l->u.maskval.mask;

	PUSH(cg, val->addr);
	if (val->segnum != 0)
		EMIT_W(cg, ORI, (val->segnum << NETVM_UA_SEG_OFF));
	PUSH(cg, mask->addr);
	if (mask->segnum != 0)
		EMIT_W(cg, ORI, (mask->segnum << NETVM_UA_SEG_OFF));
	PUSH(cg, mask->len);

	return 0;
}


static int mask2scalar(struct pmlncg *cg)
{
	EMIT_W(cg, UMINI, 4);		/* len = min(len, 4) */
	EMIT_W(cg, DUP, 0);		/* dup len */
	EMIT_XW(cg, SWAP, 0, 3);	/* swap with val addr */
	EMIT_XW(cg, SWAP, 0, 1);	/* swap with orig len */
	EMIT_NULL(cg, LD);
	EMIT_XW(cg, SWAP, 0, 2);	/* swap with dup len */
	EMIT_NULL(cg, LD);
	EMIT_NULL(cg, AND);
	return 0;
}


static int mask2bytes(struct pmlncg *cg)
{
	/* simply get rid of the mask address */
	EMIT_XW(cg, SWAP, 0, 1);
	EMIT_NULL(cg, POP);
	return 0;
}


static int typecast(struct pmlncg *cg, int otype, int ntype)
{
	if ((ntype == PML_ETYPE_UNKNOWN) || (otype == ntype))
		return 0;

	switch (ntype) {
	case PML_ETYPE_SCALAR:
		if (otype == PML_ETYPE_MASKVAL) {
			return mask2scalar(cg);
		} else if (otype == PML_ETYPE_BYTESTR) {
			EMIT_W(cg, UMINI, 4);
			EMIT_NULL(cg, LD);
			return 0;
		} else {
			/* intrinsics only */
			abort_unless(otype == PML_ETYPE_VOID);
			PUSH(cg, 0);
		}
		break;

	case PML_ETYPE_BYTESTR:
		if (otype != PML_ETYPE_MASKVAL) {
			cgerr(cg, "Can not convert type '%d' to byte string",
			      otype);
			return -1;
		}
		return mask2bytes(cg);


	case PML_ETYPE_MASKVAL:
		cgerr(cg, "Can not convert type '%d' to mask value", otype);
		return -1;

	case PML_ETYPE_VOID:
		if (otype == PML_ETYPE_SCALAR) {
			EMIT_W(cg, POP, 1);
		} else if (otype == PML_ETYPE_BYTESTR ||
			   otype == PML_ETYPE_STRREF) {
			EMIT_W(cg, POP, 2);
		} else {
			abort_unless(otype == PML_ETYPE_MASKVAL);
			EMIT_W(cg, POP, 3);
		}
		break;

	case PML_ETYPE_STRREF:
		abort_unless(otype == PML_ETYPE_BYTESTR);
		/* nothing needed:  value of string is value for string ref */
		break;

	default:
		abort_unless(0);
	}

	return 0;
}


static int cg_matchop(struct pmlncg *cg, struct pml_op *op)
{
	union pml_expr_u *rhs;

	abort_unless(cg && op);
	rhs = op->arg2;

	if (rhs->expr.etype == PML_ETYPE_BYTESTR) {
		/* We start with: len2, addr2, len1, addr1 */
		EMIT_XW(cg, SWAP, 1, 2); /* len2, len1, addr2, addr1 */
		EMIT_W(cg, DUP, 0);
		EMIT_XW(cg, SWAP, 0, 2); /* len1, len2, len2, addr1, addr2 */
		EMIT_NULL(cg, EQ);
		EMIT_W(cg, BZI, 3);	/* len1=len2?, len2, addr1, addr2 */
		EMIT_NULL(cg, CMP);
		EMIT_W(cg, BRI, 3);	/* str cmp -> skip to end */
		EMIT_W(cg, POP, 3);	/* len2, addr1, addr2 */
		EMIT_W(cg, PUSH, 0);
	} else {
		/* We start with: len2, mkaddr, paddr, len1, addr1 */
		abort_unless(rhs->base.type == PMLTT_MASKVAL);
		EMIT_XW(cg, SWAP, 1, 3); /* len2, len1, paddr, mkaddr, addr1 */
		EMIT_XW(cg, SWAP, 2, 3); /* len2, len1, mkaddr, paddr, addr1 */
		EMIT_W(cg, DUP, 0);
		EMIT_XW(cg, SWAP, 0, 2); /* len1,len2,len2,mkaddr,paddr,addr1 */
		EMIT_NULL(cg, EQ);
		EMIT_W(cg, BZI, 3); /* (eq?), len2, mkaddr, paddr, addr1 */
		EMIT_NULL(cg, MSKCMP);
		EMIT_W(cg, BRI, 3); /* mask cmp -> skip to end */
		EMIT_W(cg, POP, 4); /* len2, mkaddr, paddr, addr1 */
		EMIT_W(cg, PUSH, 0);
	}
	if (op->op == PMLOP_NOTMATCH)
		EMIT_NULL(cg, NOT);

	return 0;
}


static int cg_op(struct pmlncg *cg, struct pml_op *op, struct cgestk *es)
{
	struct netvm_inst *inst;
	struct pml_ibuf *b = &cg->ibuf;

	switch(op->op) {

	case PMLOP_OR:
	case PMLOP_AND:
		/* patch up branch */
		abort_unless(es->iaddr < b->ninst);
		inst = b->inst + es->iaddr;
		inst->w = nexti(b) - es->iaddr;
		return 0;

	case PMLOP_MATCH:
	case PMLOP_NOTMATCH:
		return cg_matchop(cg, op);

	case PMLOP_REXMATCH:
	case PMLOP_NOTREXMATCH:
		abort_unless(0);
		break;

	case PMLOP_EQ:
		EMIT_NULL(cg, EQ);
		break;
	case PMLOP_NEQ:
		EMIT_NULL(cg, NEQ);
		break;
	case PMLOP_LT:
		EMIT_NULL(cg, LT);
		break;
	case PMLOP_GT:
		EMIT_NULL(cg, GT);
		break;
	case PMLOP_LEQ:
		EMIT_NULL(cg, LE);
		break;
	case PMLOP_GEQ:
		EMIT_NULL(cg, GE);
		break;
	case PMLOP_BOR:
		EMIT_NULL(cg, OR);
		break;
	case PMLOP_BXOR:
		EMIT_NULL(cg, XOR);
		break;
	case PMLOP_BAND:
		EMIT_NULL(cg, AND);
		break;
	case PMLOP_PLUS:
		EMIT_NULL(cg, ADD);
		break;
	case PMLOP_MINUS:
		EMIT_NULL(cg, SUB);
		break;
	case PMLOP_TIMES:
		EMIT_NULL(cg, MUL);
		break;
	case PMLOP_DIV:
		EMIT_NULL(cg, DIV);
		break;
	case PMLOP_MOD:
		EMIT_NULL(cg, MOD);
		break;
	case PMLOP_SHL:
		EMIT_NULL(cg, SHL);
		break;
	case PMLOP_SHR:
		EMIT_NULL(cg, SHR);
		break;

	case PMLOP_NOT:
		EMIT_NULL(cg, NOT);
		break;
	case PMLOP_BINV:
		EMIT_NULL(cg, INVERT);
		break;
	case PMLOP_NEG:
		EMIT_NULL(cg, INVERT);
		EMIT_W(cg, ADDI, 1);
		break;

	default:
		abort_unless(0);
		break;
	}

	return 0;
}


/* 
 * generate code for a scalar binary operation where one of the
 * operands is a constant.  If the constant is sufficiently small
 * (i.e. fits in 'w') we can emit less code this way.
 */
static int cg_scalar_binop(struct pmlncg *cg, struct pml_op *op)
{
	int doswap = 0;
	int rv;
	ulong v;

	if (!PML_EXPR_IS_LITERAL(op->arg1) && !PML_EXPR_IS_LITERAL(op->arg2))
		return 0;

	if (PML_EXPR_IS_LITERAL(op->arg2)) {
		rv = cg_expr(cg, (union pml_node *)op->arg1, PML_ETYPE_SCALAR);
		if (rv < 0)
			return -1;
		if (val32(cg, (union pml_node *)op->arg2, &v) < 0)
			return -1;
	} else {
		if (val32(cg, (union pml_node *)op->arg1, &v) < 0)
			return -1;
		rv = cg_expr(cg, (union pml_node *)op->arg2, PML_ETYPE_SCALAR);
		if (rv < 0)
			return -1;
		doswap = 1;
	}

	switch(op->op) {
	case PMLOP_EQ:
		EMIT_XW(cg, EQI, doswap, v);
		break;
	case PMLOP_NEQ:
		EMIT_XW(cg, NEQI, doswap, v);
		break;
	case PMLOP_LT:
		EMIT_XW(cg, LTI, doswap, v);
		break;
	case PMLOP_GT:
		EMIT_XW(cg, GTI, doswap, v);
		break;
	case PMLOP_LEQ:
		EMIT_XW(cg, LEI, doswap, v);
		break;
	case PMLOP_GEQ:
		EMIT_XW(cg, GEI, doswap, v);
		break;
	case PMLOP_BOR:
		EMIT_XW(cg, ORI, doswap, v);
		break;
	case PMLOP_BXOR:
		EMIT_XW(cg, XORI, doswap, v);
		break;
	case PMLOP_BAND:
		EMIT_XW(cg, ANDI, doswap, v);
		break;
	case PMLOP_PLUS:
		EMIT_XW(cg, ADDI, doswap, v);
		break;
	case PMLOP_MINUS:
		EMIT_XW(cg, SUBI, doswap, v);
		break;
	case PMLOP_TIMES:
		EMIT_XW(cg, MULI, doswap, v);
		break;
	case PMLOP_DIV:
		EMIT_XW(cg, DIVI, doswap, v);
		break;
	case PMLOP_MOD:
		EMIT_XW(cg, MODI, doswap, v);
		break;
	case PMLOP_SHL:
		EMIT_XW(cg, SHLI, doswap, v);
		break;
	case PMLOP_SHR:
		EMIT_XW(cg, SHRI, doswap, v);
		break;
	default:
		abort_unless(0);
	}

	/* return 1 to indicate we need do no more on this node */
	return 1;
}


STATIC_BUG_ON(UINTMAX_LE_2_to_32, UINT_MAX > 0xFFFFFFFF);
static int cg_call(struct pmlncg *cg, struct pml_call *c, int etype)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct list *n, *pn = NULL;
	struct pml_function *f;
	struct pml_variable *p;
	struct cg_func_ctx *fc;
	int i, rv;

	abort_unless(c->args && c->func);
	f = c->func;

	if (PML_FUNC_IS_INTRINSIC(f)) {
		rv = cg_intrinsic(cg, c, etype);
		if (rv <= 0)
			return rv;
		/* if cg_intrinsic > 0 call as regular function */
	}

	/* find the last parameter */
	if (f->arity > 0)
		for (i = 0, pn = l_head(&f->vars.list); i < f->arity-1; ++i)
			pn = l_next(pn);
	/* push arguments in reverse order */
	l_for_each_rev(n, &c->args->list) {
		/* type cast to the type of the parameter */
		p = (struct pml_variable *)l_to_node(pn);
		if (cg_expr(cg, l_to_node(n), p->etype) < 0)
			return -1;
		pn = l_prev(pn);
	}

	if (PML_FUNC_IS_INLINE(f)) {
		EMIT_NULL(cg, PUSHFR);
		if (cg_expr(cg, f->body, PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_XW(cg, POPFR, 1, f->arity);
	} else {
		fc = (struct cg_func_ctx *)f->cgctx;
		/* if unresolved: save the site */
		if (!fc->resolved) {
			PUSH(cg, 0xFFFFFFFFul);
			if (pcg_save_callsite(b, &cg->calls, f) < 0) {
				cgerr(cg, "out of memory saving call '%s'",
				      f->name);
				return -1;
			}
		} else {
			PUSH(cg, fc->addr);
		}
		EMIT_NULL(cg, CALL);
	}

	if (typecast(cg, c->etype, etype) < 0)
		return -1;

	return 0;
}


static int val32(struct pmlncg *cg, union pml_node *n, ulong *v)
{
	if (!PML_EXPR_IS_LITERAL(n)) {
		cgerr(cg, "val32(): node of type '%d' is not literal",
		      n->base.type);
		return -1;
	}
	if (pml_lit_val(cg->ast, &n->literal, v) < 0) {
		cgerr(cg, "error determining literal value of type %d\n",
		      n->literal.type);
		return -1;
	}
	return 0;
}


static int cg_numval(struct pmlncg *cg, union pml_expr_u *e, struct numval *val)
{
	if (e == NULL) {
		val->onstack = 0;
		val->val = 0;
	} else if (!PML_EXPR_IS_LITERAL(e)) {
		val->onstack = 1;
		if (cg_expr(cg, (union pml_node *)e, PML_ETYPE_SCALAR) < 0)
			return -1;
	} else {
		val->onstack = 0;
		if (val32(cg, (union pml_node *)e, &val->val) < 0)
			return -1;
	}

	return 0;
}


static void cgpd_init(struct cg_pdesc *cgpd, int oc, int oci, uint8_t x,
		      struct pml_locator *loc)
{
	struct ns_elem *e = loc->u.nsref;
	struct ns_namespace *ns;
	struct ns_pktfld *pf;

	cgpd->oc = oc;
	cgpd->oci = oci;
	cgpd->x = x;
	cgpd->pfoff = 0;

	if (e->type == NST_NAMESPACE) {
		ns = (struct ns_namespace *)e;
		abort_unless(ns->prid != PRID_INVALID);

		if (PML_RPF_IS_BYTESTR(loc->rpfld)) {
			if (ns->oidx == PRP_OI_SOFF) {
				cgpd->field = PML_RPF_TO_NVMOFF(loc->rpfld);
			} else {
				abort_unless(loc->rpfld == PML_RPF_PARSE ||
					     loc->rpfld == PML_RPF_EXISTS);
				cgpd->field = NETVM_PRP_OFF_BASE + ns->oidx;
			}
		} else {
			if (loc->rpfld == PML_RPF_EXISTS) {
				/*
				 * We are testing for parse existence here.
				 * If the offset index for the namespace is
				 * PRP_OI_SOFF, then we can check for the
				 * parse index of the parse. (must be > 0).
				 * Otherwise we have to load the actual
				 * offset and test for NETVM_PRP_INVALID.
				 * See cg_rpf().
				 */
				if (ns->oidx == PRP_OI_SOFF)
					cgpd->field = NETVM_PRP_PIDX;
				else
					cgpd->field = NETVM_PRP_OFF_BASE +
						      ns->oidx;
			} else {
				cgpd->field = PML_RPF_TO_NVMFIELD(loc->rpfld);
			}
		}
		cgpd->prid = ns->prid;
	} else {
		abort_unless(e->type == NST_PKTFLD);
		pf = (struct ns_pktfld *)e;
		abort_unless(pf->prid != PRID_INVALID);

		if (loc->rpfld == PML_RPF_NONE) {
			cgpd->field = NETVM_PRP_OFF_BASE + pf->oidx;
			cgpd->prid = pf->prid;
			cgpd->pfoff = pf->off;
		} else {
			abort_unless(loc->rpfld == PML_RPF_EXISTS);
			/* see comment above in namespace block */
			if (pf->oidx == PRP_OI_SOFF)
				cgpd->field = NETVM_PRP_PIDX;
			else
				cgpd->field = NETVM_PRP_OFF_BASE + pf->oidx;
			cgpd->prid = pf->prid;
			cgpd->pfoff = 0;
		}
	}
	cgpd->pkt = loc->pkt;
	cgpd->idx = loc->idx;
	cgpd->off = loc->off;
}


/* this function assumes that ldpXi opcode is ldpX plus 1 */
/* check this to be sure.  It also assumes that the offset */
/* part of a packet descriptor is at bit 0 */
STATIC_BUG_ON(LDPFI_is_LDPF_plus_1, NETVM_OC_LDPFI != NETVM_OC_LDPF + 1);
STATIC_BUG_ON(LDPDI_is_LDPD_plus_1, NETVM_OC_LDPDI != NETVM_OC_LDPD + 1);
STATIC_BUG_ON(STPDI_is_STPD_plus_1, NETVM_OC_STPDI != NETVM_OC_STPD + 1);
STATIC_BUG_ON(NETVM_PD_OFF_OFF_is_not_zero, NETVM_PD_OFF_OFF != 0);
static void cgpd_init2(struct cg_pdesc *cgpd, int oc, uint8_t x,
		          struct pml_locator *loc)
{
	cgpd_init(cgpd, oc, oc+1, x, loc);
}


/* 
 * Generate an instruction that takes a packet descriptor argument.
 * Fortunately, all the netvm instructions that we use that take a
 * packet descriptor do so as their top of stack argument.  This function
 * forms the packet desciptor taking into account potentially variable
 * header packet, field index, and offset.
 * 
 */
static int cg_pdop(struct pmlncg *cg, struct cg_pdesc *cgpd)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct numval lpkt, lidx, loff;
	ulong w0, w1;

	if (cg_numval(cg, cgpd->idx, &lidx) < 0)
		return -1;
	if (lidx.onstack) {
		EMIT_W(cg, ANDI, NETVM_PD_IDX_MASK);
		EMIT_W(cg, SHLI, NETVM_PD_IDX_OFF);
	}

	if (cg_numval(cg, cgpd->pkt, &lpkt) < 0)
		return -1;
	if (lpkt.onstack) {
		EMIT_W(cg, ANDI, NETVM_PD_PKT_MASK);
		EMIT_W(cg, SHLI, NETVM_PD_PKT_OFF);
	}

	if (cgpd->off != NULL) {
		if (cg_numval(cg, cgpd->off, &loff) < 0)
			return -1;
		if (loff.onstack) {
			if (cgpd->pfoff > 0)
				EMIT_W(cg, ADDI, cgpd->pfoff);
			EMIT_W(cg, UMINI, NETVM_PD_OFF_MASK);
		} else {
			loff.val += cgpd->pfoff;
			if (loff.val >= NETVM_PD_OFF_MASK)
				loff.val = NETVM_PD_OFF_MASK;
		}
	} else {
		loff.onstack = 0;
		loff.val = cgpd->pfoff;
		if (loff.val >= NETVM_PD_OFF_MASK)
			loff.val = NETVM_PD_OFF_MASK;
	}

	if (cgpd->oci >= 0 && !lpkt.onstack && !lidx.onstack && !loff.onstack &&
	    (cgpd->field <= NETVM_PPD_FLD_MASK) && 
	    (loff.val <= NETVM_PPD_OFF_MASK)) {
		uint y = lpkt.val & NETVM_PPD_PKT_MASK;
		uint z = ((lidx.val & NETVM_PPD_IDX_MASK)
				<< NETVM_PPD_IDX_OFF) |
			 ((cgpd->field & NETVM_PPD_FLD_MASK)
				<< NETVM_PPD_FLD_OFF);
		ulong w = ((cgpd->prid & NETVM_PPD_PRID_MASK)
				<< NETVM_PPD_PRID_OFF) |
			  ((loff.val & NETVM_PPD_OFF_MASK)
			   	<< NETVM_PPD_OFF_OFF);


		if (pib_add_ixyzw(b, cgpd->oci, cgpd->x, y, z, w) < 0)
			return -1;
	} else {
		w0 = 0;
		w1 = ((cgpd->prid & NETVM_PD_PRID_MASK) << NETVM_PD_PRID_OFF) |
		     ((cgpd->field & NETVM_PD_FLD_MASK) << NETVM_PD_FLD_OFF);

		if (!lpkt.onstack)
			w0 |= ((lpkt.val & NETVM_PD_PKT_MASK) | NETVM_SEG_ISPKT)
					<< NETVM_PD_PKT_OFF;
		if (!loff.onstack)
			w0 |= (loff.val & NETVM_PD_OFF_MASK)
					<< NETVM_PD_OFF_OFF;
		if (!lidx.onstack)
			w1 |= (lidx.val & NETVM_PD_IDX_MASK)
					<< NETVM_PD_IDX_OFF;

		PUSH(cg, w0);
		if (lpkt.onstack)
			EMIT_NULL(cg, OR);
		if (loff.onstack)
			EMIT_NULL(cg, OR);

		if (lidx.onstack)
			EMIT_XW(cg, SWAP, 0, 1);
		PUSH(cg, w1);
		if (lidx.onstack)
			EMIT_NULL(cg, OR);

		if (cgpd->oc >= 0) {
			if (pib_add_ixyzw(b, cgpd->oc, cgpd->x, 0, 0, 0) < 0)
				return -1;
		}
	}

	return 0;
}


static int must_calc_ns_len(struct ns_namespace *ns)
{
	return NSF_IS_VARLEN(ns->flags) &&
		ns->oidx != PRP_OI_SOFF;
}


/* 
 * Calculate the adjusted length of the location.
 *  - This is the length of the field minus the offset.
 *  - If the length can be determined statically, return it in *known_len
 *  - If *known_len == 0 it usually indicates that the length isn't known
 *    but is on the stack.  It can _happen_ that this isn't the case, but
 *    the code will still be correct as the instructions will push a 0
 *    onto the stack just like any other dynamic length.  It just won't
 *    be optimial.
 *
 * NOTE: in order to work with cg_loclen(), if the *known_len value is set
 * to a real value, then the last instruction in the stream must be a push
 * of that value.  This allows cg_loclen() to replace that push with one
 * of a shorter length if the location specifies it.
 */
int cg_adjlen(struct pmlncg *cg, struct pml_locator *loc, ulong *known_len)
{
	struct cg_pdesc cgpd;
	struct pml_variable *var;
	struct pml_literal *lit;
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	struct numval loff;
	ulong len;

	*known_len = 0;

	/* Length of a literal byte string or masked string */
	if (loc->reftype == PML_REF_LITERAL) {
		lit = loc->u.litref;
		if (lit->type == PMLTT_BYTESTR) {
			len = lit->u.bytestr.len;
		} else if (lit->type == PMLTT_MASKVAL) {
			len = lit->u.maskval.val.len;
		} else {
			len = 0;
			abort_unless(0);
		}
		if (loc->off != NULL) {
			if (cg_numval(cg, loc->off, &loff) < 0)
				return -1;
			if (!loff.onstack) {
				if (loff.val >= len) {
					cgerr(cg, 
					      "offset out of range for '%s'"
					      ": %lu >= %lu", loc->name,
					      loff.val, len);
					return -1;
				}
				PUSH(cg, len - loff.val);
				*known_len = len - loff.val;
			} else {
				EMIT_W(cg, UMINI, len);
				EMIT_XW(cg, SUBI, 1, len);
			}
		} else { 
			PUSH(cg, len);
			*known_len = len;
		}

	/* Length of a global byte string */
	} else if (loc->reftype == PML_REF_VAR) {
		var = loc->u.varref;
		abort_unless(var->vtype == PML_VTYPE_GLOBAL);
		if (loc->off != NULL) {
			if (cg_numval(cg, loc->off, &loff) < 0)
				return -1;
			if (!loff.onstack) {
				if (loff.val >= var->width) {
					cgerr(cg, 
					      "offset out of range for '%s'"
					      ": %lu >= %lu", loc->name,
					      (ulong)loff.val,
					      (ulong)var->width);
					return -1;
				}
				PUSH(cg, var->width - loff.val);
				*known_len = var->width - loff.val;
			} else {
				EMIT_W(cg, UMINI, var->width);
				EMIT_XW(cg, SUBI, 1, var->width);
			}
		} else {
			PUSH(cg, var->width);
			*known_len = var->width;
		}

	/* Length of a packet header */
	} else if (loc->rpfld != PML_RPF_NONE) {
		ns = (struct ns_namespace *)loc->u.nsref;
		abort_unless(ns->type == NST_NAMESPACE);
		abort_unless(PML_RPF_IS_BYTESTR(loc->rpfld));

		if (must_calc_ns_len(ns)) {
			cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
			cgpd.off = NULL;
			cgpd.field = NETVM_PRP_OFF_BASE + ns->len;
			if (cg_pdop(cg, &cgpd) < 0)
				return -1;
			cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
			if (cg_pdop(cg, &cgpd) < 0)
				return -1;
			EMIT_NULL(cg, SUB);
			EMIT_W(cg, MAXI, 0);
		} else {
			cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
			cgpd.off = NULL;
			cgpd.field = PML_RPF_TO_NVMLEN(loc->rpfld);
			if (cg_pdop(cg, &cgpd) < 0)
				return -1;
			if (loc->off != NULL) {
				if (cg_numval(cg, loc->off, &loff) < 0)
					return -1;
				if (!loff.onstack)
					EMIT_W(cg, SUBI, loff.val);
				else
					EMIT_NULL(cg, SUB);
				EMIT_W(cg, MAXI, 0);
			}
		}

	/* Length of a packet field */
	} else {
		pf = (struct ns_pktfld *)loc->u.nsref;
		abort_unless(pf->type == NST_PKTFLD);

		if (NSF_IS_VARLEN(pf->flags)) {
			cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
			cgpd.off = NULL;
			cgpd.field = NETVM_PRP_OFF_BASE + pf->len;
			if (cg_pdop(cg, &cgpd) < 0)
				return -1;
			cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
			if (cg_pdop(cg, &cgpd) < 0)
				return -1;
			EMIT_NULL(cg, SUB);
			EMIT_W(cg, MAXI, 0);
		} else {
			if (loc->off != NULL) {
				if (cg_numval(cg, loc->off, &loff) < 0)
					return -1;
				if (!loff.onstack) {
					if (loff.val >= pf->len) {
						cgerr(cg, 
						      "offset out of range for"
						      " '%s': %lu >= %lu",
						      loc->name,
						      (ulong)loff.val,
						      (ulong)pf->len);
						return -1;
					}
					PUSH(cg, pf->len - loff.val);
					*known_len = pf->len -= loff.val;
				} else {
					EMIT_W(cg, UMINI, pf->len);
					EMIT_XW(cg, SUBI, 1, pf->len);
				}
			} else {
				PUSH(cg, pf->len);
				*known_len = pf->len;
			}
		}

	}

	return 0;
}


/* 
 * To generate the actual length of a field we need to take the
 * minimum of the length field given in the locator and the length
 * computed from the location itself.  That's what this function does.
 */
int cg_loclen(struct pmlncg *cg, struct pml_locator *loc)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct numval llen;
	ulong len = 0;

	if (cg_adjlen(cg, loc, &len) < 0)
		return -1;

	if (loc->len != NULL) {
		if (cg_numval(cg, loc->len, &llen) < 0)
			return -1;
		if (!llen.onstack) {
			if (len == 0) {
				EMIT_W(cg, MINI, llen.val);
			} else if (llen.val < len) {
				/*
				 * we have a a known field length and a known
				 * locator length less than the field length.
				 * The last operation in the instruction list
				 * is a push of the length.  Replace this
				 * push) with a pushes of the locator length.
				 */
				b->ninst -= 1;
				PUSH(cg, llen.val);
			}
		} else {
			EMIT_NULL(cg, MIN);
		}
	} 

	return 0;
}


static int cg_memref(struct pmlncg *cg, struct pml_locator *loc)
{
	struct pml_ast *ast = cg->ast;
	struct pml_literal *lit;
	struct pml_variable *var;
	ulong addr, addr2 = 0, len;
	int seg, seg2 = 0;
	struct numval loff;
	ulong n;
	int ismask = 0;

	if (loc->reftype == PML_REF_LITERAL) {
		lit = loc->u.litref;
		if (lit->type == PMLTT_BYTESTR) {
			addr = lit->u.bytestr.addr;
			len = lit->u.bytestr.len;
			seg = lit->u.bytestr.segnum;
		} else {
			abort_unless(lit->type == PMLTT_MASKVAL);
			ismask = 1;
			addr = lit->u.maskval.val.addr;
			seg = lit->u.maskval.val.segnum;
			len = lit->u.maskval.val.len;
			addr2 = lit->u.maskval.mask.addr;
			seg2 = lit->u.maskval.mask.segnum;
		}
	} else {
		var = loc->u.varref;
		addr = var->addr;
		len = var->width;
		seg = PML_SEG_RWMEM;
	}

	loff.onstack = 0;
	if (loc->off != NULL) {
		if (PML_EXPR_IS_LITERAL(loc->off)) {
			lit = &loc->off->literal;
			if (pml_lit_val(ast, lit, &n) < 0) {
				cgerr(cg, "error reading literal offset "
					  "for locator '%s'",
				      loc->name);
				return -1;
			}
			if (n >= len) {
				cgerr(cg, "offset for out of range for '%s':"
					  " %lu >= %lu",
				      loc->name, (ulong)n, (ulong)len);
				return -1;
			} else {
				addr += n;
				len -= n;
			}
			PUSH(cg, MEMADDR(addr, seg));
			if (ismask) {
				addr2 += n;
				PUSH(cg, MEMADDR(addr2, seg2));
			}
		} else {
			if (cg_numval(cg, loc->off, &loff) < 0)
				return -1;
			/* do not allow offsets to overflow address */
			EMIT_W(cg, UMINI, len);
			if (ismask)
				EMIT_NULL(cg, DUP);
			EMIT_W(cg, ADDI, addr);
			EMIT_W(cg, ORI, (seg << NETVM_UA_SEG_OFF));
			if (ismask) {
				EMIT_XW(cg, SWAP, 0, 1);
				EMIT_W(cg, ADDI, addr2);
				EMIT_W(cg, ORI, (seg2 << NETVM_UA_SEG_OFF));
			}
		}

	} else {
		PUSH(cg, MEMADDR(addr, seg));
		if (ismask)
			PUSH(cg, MEMADDR(addr2, seg2));
	}

	if (cg_loclen(cg, loc) < 0)
		return -1;

	return 0;
}


static int cg_rpf(struct pmlncg *cg, struct pml_locator *loc, int etype)
{
	struct cg_pdesc cgpd;
	struct ns_elem *e = loc->u.nsref;
	uint oidx;

	abort_unless(e->type == NST_NAMESPACE || e->type == NST_PKTFLD);
	if (e->type == NST_NAMESPACE)
		oidx = ((struct ns_namespace *)e)->oidx;
	else
		oidx = ((struct ns_pktfld *)e)->oidx;

	cgpd_init2(&cgpd, NETVM_OC_LDPF, 
	           PML_RPF_IS_BYTESTR(loc->rpfld) != 0, loc);

	if (cg_pdop(cg, &cgpd) < 0)
		return -1;

	if (PML_RPF_IS_BYTESTR(loc->rpfld)) {
		if (cg_loclen(cg, loc) < 0)
			return -1;
	} else if (oidx != PRP_OI_SOFF) {
		abort_unless(loc->rpfld == PML_RPF_EXISTS);
		/*
		 * If we have a namespace referring to a subfield 
		 * within a protocol then we have to test explicitly
		 * for invalid rather than implicitly by getting
		 * the header's parse index.  See cgpd_init2().
		 */
		EMIT_W(cg, NEQI, NETVM_PF_INVALID);
	}


	if (typecast(cg, loc->etype, etype) < 0)
		return -1;

	return 0;
}


static int cg_pfbitfield(struct pmlncg *cg, struct pml_locator *loc)
{
	struct cg_pdesc cgpd;
	struct ns_pktfld *pf = (struct ns_pktfld *)loc->u.nsref;
	ulong bitoff = NSF_BITOFF(pf->flags);
	ulong bytelen = ((pf->len + bitoff + 7) & ~(ulong)7) >> 3;
	ulong remlen = bytelen * 8 - bitoff - pf->len;
	ulong mask;

	abort_unless(loc->off == NULL && loc->len == NULL);

	if (bytelen > 4) {
		cgerr(cg, "Unable to generate bitfield %s:  "
			  "read byte length = %lu",
		      pf->name, bytelen);
		return -1;
	}

	cgpd_init2(&cgpd, NETVM_OC_LDPD, bytelen, loc);
	if (cg_pdop(cg, &cgpd) < 0)
		return -1;

	if (remlen > 0)
		EMIT_W(cg, SHRI, remlen);


	mask = ((ulong)1 << pf->len) - 1;
	EMIT_W(cg, ANDI, mask);

	return 0;
}


/*
  Cases:
  pdesc in instr:
   - etype == SCALAR
     * len is static 
       use ldpdi with len = max(4, len)
     * len is dynamic
       use ldpfi, eval len, ldu
   - etype == BYTESTR
     * len is static
       use ldpfi, push len
     * len is dynamic
       use ldpfi, eval len

  pdesc on stack:
   - etype == SCALAR
     * len is static
       use ldpd with len = max(4, len)
     * len is dynamic
       use ldpd, eval len, ldu
   - etype == BYTESTR
     * len is static
       use ldpf, push len
     * len is dynamic
       use ldpf, eval len
 */
static int cg_pfbytefield(struct pmlncg *cg, struct pml_locator *loc, int etype)
{
	struct pml_ast *ast = cg->ast;
	struct cg_pdesc cgpd;
	struct ns_pktfld *pf = (struct ns_pktfld *)loc->u.nsref;
	int fixedlen = 0;
	ulong len = 0, n;
	struct pml_literal *lit;

	if (!NSF_IS_VARLEN(pf->flags)) {
		fixedlen = 1;
		len = pf->len;
	}
	if (loc->off != NULL) {
		if (PML_EXPR_IS_LITERAL(loc->off) && fixedlen) {
			lit = (struct pml_literal *)loc->off;
			if (pml_lit_val(ast, lit, &n) < 0) {
				cgerr(cg, "error reading literal offset "
					   "for locator '%s'",
				      loc->name);
				return -1;
			}
			if (n >= len) {
				cgerr(cg, "offset for out of range for '%s':"
					  " %lu >= %lu",
				      loc->name, (ulong)n, (ulong)len);
				return -1;
			}
			len -= n;
		} else {
			fixedlen = 0;
		}
	}
	if (loc->len != NULL) {
		if (PML_EXPR_IS_LITERAL(loc->len) && fixedlen) {
			lit = (struct pml_literal *)loc->len;
			if (pml_lit_val(ast, lit, &n) < 0) {
				cgerr(cg, "error reading literal length "
					  "for locator '%s'",
				      loc->name);
				return -1;
			}
			if (n > len) {
				cgerr(cg, "length for out of range for '%s':"
					  " %lu >= %lu",
				      loc->name, (ulong)n, (ulong)len);
				return -1;
			}
			len = n;
		} else {
			fixedlen = 0;
		}
	}


	if (etype == PML_ETYPE_SCALAR && fixedlen) {
		if (len > PML_SCALAR_SIZE)
			len = PML_SCALAR_SIZE;
		cgpd_init2(&cgpd, NETVM_OC_LDPD, len, loc);
		return cg_pdop(cg, &cgpd);
	} else {
		cgpd_init2(&cgpd, NETVM_OC_LDPF, 1, loc);
		if (cg_pdop(cg, &cgpd) < 0)
			return -1;
		if (cg_loclen(cg, loc) < 0)
			return -1;
		if (etype == PML_ETYPE_SCALAR)
			EMIT_NULL(cg, LD);
		return 0;
	}
}


/* generate the address/length on the stack for the string reference */
/* taking into account the offset and length fields ensuring no overflow */
static int cg_strref(struct pmlncg *cg, struct pml_locator *loc)
{
	struct numval llen;


	LDSREF_ADDR(cg, loc); 
	if (loc->off != NULL) {
		/* XXX assumes var length can't overflow address */
		/* Our code should ensure that this is true by */
		/* ensuring that no string ref length is larger than */
		/* the field that it refers to. */

		/* calculate adjusted address */
		if (cg_expr(cg, (union pml_node *)loc->off, 
			    PML_ETYPE_SCALAR) < 0)
			return -1;
		LDSREF_LEN(cg, loc);
		EMIT_NULL(cg, UMIN);
		EMIT_NULL(cg, ADD);

		/* get length to end of string */
		LDSREF_ADDR(cg, loc); 
		LDSREF_LEN(cg, loc); 
		EMIT_NULL(cg, ADD);
		EMIT_W(cg, DUP, 1);
		EMIT_NULL(cg, SUB);
	} else { /* no offset */
		LDSREF_LEN(cg, loc);
	}

	/* if there is a length expression, generate the length */
	/* and take the minimum of that and the ref's length */
	if (loc->len != NULL) {
		if (cg_numval(cg, loc->len, &llen) < 0)
			return -1;
		if (llen.onstack) {
			EMIT_NULL(cg, MIN);
		} else {
			EMIT_W(cg, MINI, llen.val);
		}
	}

	return 0;
}


static int cg_local_varref(struct pmlncg *cg, struct pml_locator *loc,
			   int etype)
{
	struct pml_variable *v = loc->u.varref;
	int belowbp;
	ulong addr;

	addr = lvaraddr(v);
	if (v->func != NULL && PML_FUNC_IS_INTRINSIC(v->func)) {
		cgerr(cg, "can't generate varref code for an "
			  "intrinsic function (%s)", v->func->name);
		return -1;
	} 
		
	if (v->etype == PML_ETYPE_SCALAR) {
		belowbp = (v->vtype == PML_VTYPE_PARAM);
		EMIT_XW(cg, LDBPI, belowbp, addr);
	} else if (v->etype == PML_ETYPE_STRREF) {
		if (cg_strref(cg, loc) < 0)
			return -1;
	} else {
		UNIMPL(cg, ref_local_non_scalar_non_strref_var);
	}
	if (typecast(cg, loc->etype, etype) < 0)
		return -1;
	return 0;
}


static int cg_global_varref(struct pmlncg *cg, struct pml_locator *loc,
			    int etype)
{
	struct pml_variable *v = loc->u.varref;

	if (v->etype == PML_ETYPE_SCALAR) {
		abort_unless(loc->off == NULL && loc->len == NULL);
		EMIT_XYW(cg, LDI, v->width, PML_SEG_RWMEM, v->addr);
	} else if (v->etype == PML_ETYPE_STRREF) {
		if (cg_strref(cg, loc) < 0)
			return -1;
	} else if (v->etype == PML_ETYPE_BYTESTR) {
		if (cg_memref(cg, loc) < 0)
			return -1;
	} else {
		UNIMPL(cg, ref_global_non_scalar_strref_bytestr_var);
	}

	if (typecast(cg, loc->etype, etype) < 0)
		return -1;
	return 0;
}


static int cg_varref(struct pmlncg *cg, struct pml_locator *loc, int etype)
{
	struct pml_variable *v = loc->u.varref;

	abort_unless(loc->pkt == NULL && loc->idx == NULL);

	if (v->vtype == PML_VTYPE_PARAM || v->vtype == PML_VTYPE_LOCAL) {
		return cg_local_varref(cg, loc, etype);
	} else if (v->vtype == PML_VTYPE_GLOBAL) {
		return cg_global_varref(cg, loc, etype);
	} else {
		cgerr(cg, "Unsupported variable type: %d", v->vtype);
		return -1;
	}
	return 0;
}


static int cg_pfref(struct pmlncg *cg, struct pml_locator *loc, int etype)
{
	struct ns_elem *nse = loc->u.nsref;

	if (loc->rpfld != PML_RPF_NONE) {
		return cg_rpf(cg, loc, etype);
	} else if ((nse->type == NST_PKTFLD) && NSF_IS_INBITS(nse->flags)) {
		return cg_pfbitfield(cg, loc);
	} else {
		abort_unless(nse->type == NST_PKTFLD);
		return cg_pfbytefield(cg, loc, etype);
	}

	return 0;
}


static int cg_litref(struct pmlncg *cg, struct pml_locator *loc, int etype)
{
	struct pml_literal *lit = loc->u.litref;

	abort_unless(loc->pkt == NULL && loc->idx == NULL);

	if (lit->etype == PML_ETYPE_SCALAR) {
		abort_unless(loc->pkt == NULL && loc->idx == NULL);
		return cg_scalar(cg, lit);
	}

	if (cg_memref(cg, loc) , 0)
		return -1;

	if (typecast(cg, loc->etype, etype) < 0)
		return -1;

	return 0;
}


/* generate code for a locator with a final type of etype */
static int cg_locator(struct pmlncg *cg, struct pml_locator *loc, int etype)
{
	switch (loc->reftype) {
	case PML_REF_VAR:
		return cg_varref(cg, loc, etype);
	case PML_REF_PKTFLD:
		return cg_pfref(cg, loc, etype);
	case PML_REF_LITERAL:
		return cg_litref(cg, loc, etype);
	default:
		cgerr(cg, "unresolved locator '%s'", loc->name);
		return -1;
	}
}


static int cg_rexmatch(struct pmlncg *cg, struct pml_op *op, int etype)
{
	struct pml_literal *lit;
	struct cg_lit_ctx *lc;

	if (etype != PML_ETYPE_SCALAR) {
		cgerr(cg, "Unable to type cast regex match to non-scalar"
		          " return type '%d'", etype);
		return -1;
	}

	/* generate the byte string on top */
	if (cg_expr(cg, (union pml_node *)op->arg1, PML_ETYPE_BYTESTR) < 0)
		return -1;

	abort_unless(op->arg2->base.type == PMLTT_BYTESTR);
	lit = &op->arg2->literal;
	lc = (struct cg_lit_ctx *)lit->cgctx;
	PUSH(cg, lc->rexidx);
	EMIT_XY(cg, CPOPI, NETVM_CPI_REX, NETVM_CPOC_REX_MATCH);

	return 0;
}


static int w_expr_pre(union pml_node *n, void *auxp, void *xstk)
{
	struct cgeaux *ea = auxp;
	struct cgestk *es = xstk;
	struct pml_op *op;
	int rv;

	/* save the expected type */
	es->etype = ea->etype;
	ea->etype = PML_ETYPE_UNKNOWN;

	switch (n->base.type) {
	case PMLTT_BINOP:
		op = &n->op;
		switch (op->op) {
		case PMLOP_MATCH:
		case PMLOP_NOTMATCH:
			ea->etype = PML_ETYPE_BYTESTR;
			break;

		case PMLOP_REXMATCH:
		case PMLOP_NOTREXMATCH:
			if (cg_rexmatch(ea->cg, op, es->etype) < 0)
				return -1;
			return 1;
			break;

		default:
			ea->etype = PML_ETYPE_SCALAR;
			if (SCALAROP(op->op)) {
				rv = cg_scalar_binop(ea->cg, op);
				if (rv)
					return rv;
			}
			break;
		}
		break;

	case PMLTT_UNOP:
		ea->etype = PML_ETYPE_SCALAR;
		break;

	case PMLTT_CALL:
		abort_unless(es->etype == PML_ETYPE_SCALAR ||
			     es->etype == PML_ETYPE_STRREF||
			     es->etype == PML_ETYPE_VOID ||
			     es->etype == PML_ETYPE_UNKNOWN);
		/* prune walk for calls:  cg_call will walk subfields */
		if (cg_call(ea->cg, &n->call, es->etype) < 0)
			return -1;
		return 1;

	case PMLTT_LOCATOR:
		/* prune walk for locators:  cg_locator will walk its own */
		/* sub-fields as needed.  */
		if (cg_locator(ea->cg, &n->locator, es->etype) < 0)
			return -1;
		return 1;

	default:
		break;
	}	

	return 0;
}


static int w_expr_in(union pml_node *n, void *auxp, void *xstk)
{
	struct cgeaux *ea = auxp;
	struct pmlncg *cg = ea->cg;
	struct pml_ibuf *b = &cg->ibuf;
	struct pml_op *op;
	struct cgestk *es = xstk;

	switch (n->base.type) {
	case PMLTT_BINOP:
		op = &n->op;
		if (op->op == PMLOP_OR) {
			EMIT_W(cg, BZI, 3);
			EMIT_W(cg, PUSH, 1);
			es->iaddr = nexti(b);
			EMIT_W(cg, BRI, 0); /* fill in during post */
		} else if (op->op == PMLOP_AND) { 
			EMIT_W(cg, BNZI, 3);
			EMIT_W(cg, PUSH, 0);
			es->iaddr = nexti(b);
			EMIT_W(cg, BRI, 0); /* fill in during post */
		}
		if (op->op == PMLOP_MATCH || op->op == PMLOP_NOTMATCH) {
			ea->etype = n->op.arg2->expr.etype;
		} else {
			ea->etype = PML_ETYPE_SCALAR;
		}
		break;
	}

	return 0;
}


static int w_expr_post(union pml_node *n, void *auxp, void *xstk)
{
	int rv = 0;
	struct cgeaux *ea = auxp;
	struct cgestk *es = xstk;
	struct pmlncg *cg = ea->cg;

	switch (n->base.type) {
	case PMLTT_SCALAR:
		rv = cg_scalar(cg, &n->literal);
		break;
	case PMLTT_BYTESTR:
		/* a byte string in an expression walk can only be for a */
		/* operation of some sort which requires the length */
		rv = cg_bytestr(cg, &n->literal, 1);
		break;
	case PMLTT_MASKVAL:
		rv = cg_maskval(cg, &n->literal);
		break;
	case PMLTT_BINOP:
	case PMLTT_UNOP:
		rv = cg_op(cg, &n->op, es);
		break;
	case PMLTT_CALL:
	case PMLTT_LOCADDR:
	case PMLTT_LOCATOR:
	default:
		abort_unless(0);
		break;
	}

	if (rv >= 0)
		rv = typecast(cg, n->expr.etype, es->etype);

	return rv;
}


int cg_expr(struct pmlncg *cg, union pml_node *n, int etype)
{
	struct cgeaux ea = { cg, etype };
	return pmln_walk(n, &ea, w_expr_pre, w_expr_in, w_expr_post);
}


static int cg_list(struct pmlncg *cg, struct pml_list *list)
{
	struct list *trav;
	union pml_node *n;

	l_for_each(trav, &list->list) {
		n = l_to_node(trav);
		if (cg_stmt(cg, n) < 0)
			return -1;
	}

	return 0;
}


static int cg_if(struct pmlncg *cg, struct pml_if *ifstmt)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct netvm_inst *inst;
	uint bra;

	if (cg_expr(cg, (union pml_node *)ifstmt->test, PML_ETYPE_SCALAR) < 0)
		return -1;

	bra = nexti(b);
	EMIT_W(cg, BZI, 0);

	if (cg_stmt(cg, (union pml_node *)ifstmt->tbody) < 0)
		return -1;

	if (ifstmt->fbody != NULL) {
		/* skip the next instruction we will emit */
		inst = b->inst + bra;
		inst->w = nexti(b) - bra + 1;

		bra = nexti(b);
		EMIT_W(cg, BRI, 0);

		if (cg_stmt(cg, (union pml_node *)ifstmt->fbody) < 0)
			return -1;

		inst = b->inst + bra;
		inst->w = nexti(b) - bra;
	} else {
		inst = b->inst + bra;
		inst->w = nexti(b) - bra;
	}


	return 0;
}


static int cg_cfmod(struct pmlncg *cg, struct pml_cfmod *cfm)
{
	struct pml_function *f;

	switch (cfm->cftype) {
	case PML_CFM_RETURN:
		f = cg->curfunc;
		abort_unless(f != NULL);
		if (cg_expr(cg, (union pml_node *)cfm->expr, f->rtype) < 0)
			return -1;
		EMIT_RET(cg, f);
		break;
	case PML_CFM_BREAK:
		EMIT_W(cg, BRI, 0);
		if (pcg_save_break(cg) < 0)
			return -1;
		break;
	case PML_CFM_CONTINUE:
		EMIT_W(cg, BRI, 0);
		if (pcg_save_continue(cg) < 0)
			return -1;
		break;
	case PML_CFM_NEXTRULE:
		EMIT_W(cg, BRI, 0);
		if (pcg_save_nextrule(cg) < 0)
			return -1;
		break;
	case PML_CFM_SENDALL:
		EMIT_W(cg, HALT, NVMP_STATUS_SENDALL);
		break;
	case PML_CFM_DROPALL:
		EMIT_W(cg, HALT, NVMP_STATUS_DROPALL);
		break;
	case PML_CFM_SENDONE:
		if (cg_expr(cg, (union pml_node *)cfm->expr,
			    PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_W(cg, HALT, NVMP_STATUS_SEND);
		break;
	case PML_CFM_DROPONE:
		if (cg_expr(cg, (union pml_node *)cfm->expr,
			    PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_NULL(cg, PKDEL);
		break;
	case PML_CFM_SENDNOFREE:
		if (cg_expr(cg, (union pml_node *)cfm->expr,
			    PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_W(cg, HALT, NVMP_STATUS_SENDKEEP);
		break;
	}

	return 0;
}


int cg_while(struct pmlncg *cg, struct pml_while *loop)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct netvm_inst *inst;
	union pml_node *n;
	struct pml_while *oloop;
	uint nb;
	uint nc;
	uint testaddr;
	uint tbraddr;
	uint endaddr;

	oloop = cg->curloop;
	cg->curloop = loop;
	nb = pcg_get_nbreaks(cg);
	nc = pcg_get_ncontinues(cg);

	/* generate test and branch on the test: resolve branch later */
	testaddr = nexti(b);
	n = (union pml_node *)loop->test;
	if (cg_expr(cg, n, PML_ETYPE_SCALAR) < 0)
		return -1;
	tbraddr = nexti(b);
	EMIT_W(cg, BZI, 0);

	/* generate the loop body */
	n = (union pml_node *)loop->body;
	if (cg_stmt(cg, n) < 0)
		return -1;

	/* branch back to test */
	endaddr = nexti(b);
	EMIT_W(cg, BRI, (ulong)testaddr - endaddr);
	++endaddr;

	/* resolve branch past body */
	inst = b->inst + tbraddr;
	inst->w = (ulong)endaddr - tbraddr;

	/* resolve breaks and continues */
	pcg_resolve_breaks(cg, nb, endaddr);
	pcg_resolve_continues(cg, nc, testaddr);

	cg->curloop = oloop;
	return 0;
}


int cg_assign_strref_nonref(struct pmlncg *cg, struct pml_assign *a)
{
	union pml_expr_u *e = a->expr;
	if (e->expr.etype == PML_ETYPE_SCALAR) {
		/* scalar to pointer area */
		if (cg_expr(cg, (union pml_node *)e, PML_ETYPE_SCALAR) < 0)
			return -1;
		if (cg_strref(cg, a->loc) < 0)
			return -1;
		EMIT_W(cg, UMINI, 4);
		EMIT_NULL(cg, ST);
	} else {
		if (cg_expr(cg, (union pml_node *)e, PML_ETYPE_BYTESTR) < 0)
			return -1;
		if (cg_strref(cg, a->loc) < 0)
			return -1;
		EMIT_XW(cg, SWAP, 1, 2);
		EMIT_NULL(cg, UMIN);
		EMIT_NULL(cg, MOVE);
	}
	return 0;
}


int cg_assign_stack_var(struct pmlncg *cg, struct pml_assign *a)
{
	struct pml_variable *v = a->loc->u.varref;
	ulong vaddr = lvaraddr(v);
	union pml_expr_u *e =  a->expr;

	if (v->etype == PML_ETYPE_SCALAR) {
		abort_unless(a->loc->type == PMLTT_LOCATOR);
		if (cg_expr(cg, (union pml_node *)e, PML_ETYPE_SCALAR) < 0)
			return -1;
		if (v->vtype == PML_VTYPE_LOCAL) {
			EMIT_XW(cg, STBPI, 0, vaddr);
		} else {
			abort_unless(v->vtype == PML_VTYPE_PARAM);
			EMIT_XW(cg, STBPI, 1, vaddr);
		}
	} else if (v->etype == PML_ETYPE_STRREF) {
		if (a->loc->type == PMLTT_LOCADDR) {
			/* string ref -> string ref */
			if (cg_expr(cg, (union pml_node *)e,
				    PML_ETYPE_STRREF) < 0)
				return -1;
			if (v->vtype == PML_VTYPE_LOCAL) {
				EMIT_XW(cg, STBPI, 0, vaddr+1); /* length */
				EMIT_XW(cg, STBPI, 0, vaddr); /* address */
			} else {
				abort_unless(v->vtype == PML_VTYPE_PARAM);
				/* string references are in reverse order */
				/* from STBPI standpoint */
				EMIT_XW(cg, STBPI, 1, vaddr); /* length */
				EMIT_XW(cg, STBPI, 1, vaddr+1); /* address */
			}
		} else {
			if (cg_assign_strref_nonref(cg, a) < 0)
				return -1;
		}
	} else {
		UNIMPL(cg, assign_local_non_scalar_non_ref_var);
	}

	return 0;
}


int cg_assign_global_var(struct pmlncg *cg, struct pml_assign *a)
{
	struct pml_locator *loc = a->loc;
	struct pml_variable *v = loc->u.varref;
	union pml_expr_u *e = a->expr;
	ulong vlen;

	if (v->etype == PML_ETYPE_SCALAR ||
	    (v->etype == PML_ETYPE_BYTESTR && 
	     e->expr.etype == PML_ETYPE_SCALAR)) {
		abort_unless(loc->type == PMLTT_LOCATOR);
		if (cg_expr(cg, (union pml_node *)e, PML_ETYPE_SCALAR) < 0)
			return -1;

		if (loc->off == NULL && loc->len == NULL) {
			vlen = v->width;
			if (vlen > 4)
				vlen = 4;
			EMIT_XYW(cg, STI, vlen, PML_SEG_RWMEM, v->addr);
		} else {
			if (cg_memref(cg, loc) < 0)
				return -1;
			EMIT_NULL(cg, ST);
		}
	} else if (v->etype == PML_ETYPE_BYTESTR) {
		abort_unless(loc->type == PMLTT_LOCATOR);
		/* byte string to byte string copy */
		if (cg_expr(cg, (union pml_node *)e, PML_ETYPE_BYTESTR) < 0)
			return -1;
		if (cg_memref(cg, loc) < 0)
			return -1;
		EMIT_XW(cg, SWAP, 1, 2);
		EMIT_NULL(cg, UMIN);
		EMIT_NULL(cg, MOVE);
	} else if (v->etype == PML_ETYPE_STRREF) {
		if (loc->type == PMLTT_LOCADDR) {
			/* overwrite string ref */
			if (cg_expr(cg, (union pml_node *)e,
				    PML_ETYPE_STRREF) < 0)
				return -1;
			EMIT_XYW(cg, STI, 4, PML_SEG_RWMEM, v->addr + 4);
			EMIT_XYW(cg, STI, 4, PML_SEG_RWMEM, v->addr);
		} else {
			/* string copy */
			if (cg_assign_strref_nonref(cg, a) < 0)
				return -1;
		}
	} else {
		UNIMPL(cg, non_scalar_strref_bytestr_global_var_assign);
	}

	return 0;
}


/*
 * Check whether a packet field reference has a fixed length.  Return 1
 * if true, 0 if false and -1 on error.  If the length is fixed, return
 * it in *outlen.
 */
static int pfref_check_fixed(struct pmlncg *cg, struct pml_locator *loc,
			     ulong *outlen)
{
	struct pml_ast *ast = cg->ast;
	ulong v, len, off;
	struct pml_literal *lit;
	struct ns_namespace *ns;
	struct ns_pktfld *pf;

	if (loc->rpfld != PML_RPF_NONE) {
		ns = (struct ns_namespace *)loc->u.nsref;
		if (NSF_IS_VARLEN(ns->flags))
			return 0;
		len = ns->len;
	} else {
		pf = (struct ns_pktfld *)loc->u.nsref;
		if (NSF_IS_VARLEN(pf->flags))
			return 0;
		len = pf->len;
	}
	 
	if (loc->pkt != NULL) {
		if (!PML_EXPR_IS_LITERAL(loc->pkt))
			return 0;
		lit = &loc->pkt->literal;
		if (pml_lit_val(ast, lit, &v) < 0) {
			cgerr(cg, "error reading literal packet for locator "
				  "'%s'", loc->name);
			return -1;
		}
		if (v > NETVM_PD_PKT_MASK)
			return 0;
	}
	if (loc->idx != NULL) {
		if (!PML_EXPR_IS_LITERAL(loc->idx))
			return 0;
		lit = &loc->idx->literal;
		if (pml_lit_val(ast, lit, &v) < 0) {
			cgerr(cg, "error reading literal index for locator "
				  "'%s'", loc->name);
			return -1;
		}
		if (v > NETVM_PD_IDX_MASK)
			return 0;
	}
	off = 0;
	if (loc->off != NULL) {
		if (!PML_EXPR_IS_LITERAL(loc->off))
			return 0;
		lit = &loc->off->literal;
		if (pml_lit_val(ast, lit, &off) < 0) {
			cgerr(cg, "error reading literal offset for locator "
				  "'%s'", loc->name);
			return -1;
		}
		if (off > NETVM_PD_IDX_MASK)
			return 0;
		if (off >= len) {
			cgerr(cg, "offset out of range for field '%s':"
				  " %lu >= %lu", 
			      loc->name, (ulong)off, (ulong)len);
			return -1;
		}
		len -= off;
	}
	if (loc->len != NULL) {
		if (!PML_EXPR_IS_LITERAL(loc->len))
			return 0;
		lit = &loc->len->literal;
		if (pml_lit_val(ast, lit, &v) < 0) {
			cgerr(cg, "error reading literal length for locator "
				  "'%s'", loc->name);
			return -1;
		}
		if (v > NETVM_PD_IDX_MASK)
			return 0;
		if (v > len) {
			cgerr(cg, "length out of range for field '%s'"
				  " with offset %lu: %lu >= %lu",
			      loc->name, (ulong)off, (ulong)v, (ulong)len);
			return -1;
		}
		len = v;
	}

	if (outlen != NULL)
		*outlen = len;

	return 1;
}


int cg_assign_pkt_bitfield(struct pmlncg *cg, struct pml_assign *a)
{
	struct pml_locator *loc = a->loc;
	struct ns_pktfld *pf = (struct ns_pktfld *)loc->u.nsref;
	ulong bitoff = NSF_BITOFF(pf->flags);
	ulong bytelen = ((pf->len + bitoff + 7) & ~(ulong)7) >> 3;
	ulong remlen = bytelen * 8 - bitoff - pf->len;
	ulong mask = (((ulong)1 << pf->len) - 1);
	ulong invmask;
	struct cg_pdesc cgpd;
	struct numval val;

	/* max bytes should be 5:  32-bit field overlapping on two ends */
	if (bytelen > 4) {
		cgerr(cg, "code gen can not currently support 4-byte bitfields"
			  "overlapping bytes at both ends");
		return -1; 
	}

	/* so we have bitoff at the front and remlen at the end */
	cgpd_init2(&cgpd, NETVM_OC_LDPD, bytelen, loc);
	if (cg_pdop(cg, &cgpd) < 0)
		return -1;

	/* clear bits for the field */
	invmask = ~(mask << remlen);
	invmask &= 0xFFFFFFFF;
	EMIT_W(cg, ANDI, invmask);

	/* generate the data to insert, mask it and shift it into position */
	/* and OR with the previous data */
	if (cg_numval(cg, a->expr, &val) < 0)
		return -1;
	if (!val.onstack) {
		EMIT_W(cg, ORI, ((val.val & mask) << remlen));
	} else {
		EMIT_W(cg, ANDI, mask);
		EMIT_W(cg, SHLI, remlen);
		EMIT_NULL(cg, OR);
	}

	/* store it in the packet */
	cgpd_init2(&cgpd, NETVM_OC_STPD, bytelen, loc);
	if (cg_pdop(cg, &cgpd) < 0)
		return -1;

	return 0;
}


int cg_assign_pktfld(struct pmlncg *cg, struct pml_assign *a)
{
	struct pml_locator *loc = a->loc;
	int etype = a->expr->expr.etype;
	int rv;
	struct cg_pdesc cgpd;
	ulong flen;
	struct ns_elem *nse = loc->u.nsref;

	if ((nse->type == NST_PKTFLD) && NSF_IS_INBITS(nse->flags))
		return cg_assign_pkt_bitfield(cg, a);

	/* string references in an rvalue position become strings */
	/* when the LHS is not a string reference.  Packet fields */
	/* never have string reference variable type.  */
	if (etype == PML_ETYPE_STRREF)
		etype = PML_ETYPE_BYTESTR;

	if (cg_expr(cg, (union pml_node *)a->expr, etype) < 0)
		return -1;

	if (etype == PML_ETYPE_SCALAR) {
		rv = pfref_check_fixed(cg, loc, &flen);
		if (rv < 0) {
			return -1;
		} else if (rv > 0) {
			if (flen > 4)
				flen = 4;
			cgpd_init2(&cgpd, NETVM_OC_STPD, flen, loc);
			if (cg_pdop(cg, &cgpd) < 0)
				return -1;
			return 0;
		} 
	} else if (etype == PML_ETYPE_MASKVAL) {
		if (typecast(cg, PML_ETYPE_BYTESTR, etype) < 0)
			return -1;
		etype = PML_ETYPE_BYTESTR;
	}

	cgpd_init2(&cgpd, NETVM_OC_LDPF, 1, loc);
	if (cg_pdop(cg, &cgpd) < 0)
		return -1;
	if (cg_loclen(cg, loc) < 0)
		return -1;

	if (etype == PML_ETYPE_SCALAR) {
		EMIT_NULL(cg, ST);
	} else {
		EMIT_XW(cg, SWAP, 1, 2);
		EMIT_NULL(cg, UMIN);
		EMIT_NULL(cg, MOVE);
	}

	return 0;
}


int cg_assign(struct pmlncg *cg, struct pml_assign *a)
{
	struct pml_locator *loc = a->loc;
	struct pml_variable *v;

	if (loc->reftype == PML_REF_VAR) {
		v = loc->u.varref;
		if (v->vtype == PML_VTYPE_LOCAL ||
		    v->vtype == PML_VTYPE_PARAM) {
			return cg_assign_stack_var(cg, a);
		} else {
			return cg_assign_global_var(cg, a);
		}
	} else {
		abort_unless(loc->reftype == PML_REF_PKTFLD);
		return cg_assign_pktfld(cg, a);
	}

	return 0;
}


int cg_print(struct pmlncg *cg, struct pml_print *pr)
{
	uchar y = 0;
	uchar z = 0;
	int etype;

	abort_unless(cg && pr);

	etype = PML_FMT_TO_ETYPE(pr->fmt);
	if (cg_expr(cg, (union pml_node *)pr->expr, etype) < 0)
		return -1;

	switch(pr->fmt) {
	case PML_FMT_BIN: y = NETVM_CPOC_PRBIN; break;
	case PML_FMT_OCT: y = NETVM_CPOC_PROCT; break;
	case PML_FMT_DEC: y = NETVM_CPOC_PRDEC; break;
	case PML_FMT_UDEC: y = NETVM_CPOC_PRUDEC; break;
	case PML_FMT_HEX: y = NETVM_CPOC_PRHEX; break;
	case PML_FMT_STR: y = NETVM_CPOC_PRSTR; break;
	case PML_FMT_HEXSTR: y = NETVM_CPOC_PRXSTR; break;

	case PML_FMT_IPA:
		y = NETVM_CPOC_PRIP;
		EMIT_W(cg, EQI, 4);
		EMIT_W(cg, BNZI, 3);
		EMIT_W(cg, PUSH, 0);
		EMIT_W(cg, HALT, NETVM_ERR_BADCPOP);
		break;
	case PML_FMT_IP6A:
		y = NETVM_CPOC_PRIPV6;
		EMIT_W(cg, EQI, 16);
		EMIT_W(cg, BNZI, 3);
		EMIT_W(cg, PUSH, 0);
		EMIT_W(cg, HALT, NETVM_ERR_BADCPOP);
		break;
	case PML_FMT_ETHA:
		y = NETVM_CPOC_PRETH;
		EMIT_W(cg, EQI, 6);
		EMIT_W(cg, BNZI, 3);
		EMIT_W(cg, PUSH, 0);
		EMIT_W(cg, HALT, NETVM_ERR_BADCPOP);
		break;

	default:
		abort_unless(0);
	}

	if (pr->flags & PML_PFLAG_LJUST)
		z |= NETVM_CPOC_LJUST;
	if (pr->flags & PML_PFLAG_NEWLINE)
		z |= NETVM_CPOC_NEWLINE;

	EMIT_XYZW(cg, CPOPI, NETVM_CPI_OUTPORT, y, z, pr->width);

	return 0;
}


int cg_stmt(struct pmlncg *cg, union pml_node *n)
{
	if (n == NULL)
		return 0;

	switch (n->base.type) {
	case PMLTT_LIST:
		return cg_list(cg, &n->list);
	case PMLTT_IF:
		return cg_if(cg, &n->ifstmt);
	case PMLTT_WHILE:
		return cg_while(cg, &n->whilestmt);
	case PMLTT_ASSIGN:
		return cg_assign(cg, &n->assign);
	case PMLTT_CFMOD:
		return cg_cfmod(cg, &n->cfmod);
	case PMLTT_PRINT:
		return cg_print(cg, &n->print);
	default:
		if (!PML_TYPE_IS_EXPR(n->base.type)) {
			cgerr(cg, "cg_stmt(): unknown statement type %d",
			      n->base.type);
			return -1;
		}
		if (cg_expr(cg, n, PML_ETYPE_VOID) < 0)
			return -1;
	}

	return 0;
}


static void cg_func_mark_walk(union pml_node *n);


static int cg_func_mark_walker(union pml_node *n, void *ctx, void *xstk)
{
	struct pml_call *call;
	struct pml_function *f;
	struct cg_func_ctx *fc;

	if (n->base.type != PMLTT_CALL)
		return 0;
	call = &n->call;
	f = call->func;
	abort_unless(f != NULL);
	if (PML_FUNC_IS_INLINE(f))
		return 0;
	fc = (struct cg_func_ctx *)f->cgctx;
	++fc->called;
	if (fc->called == 1 && f->body != NULL)
		cg_func_mark_walk(f->body);

	return 0;
}


static void cg_func_mark_walk(union pml_node *n)
{
	pmln_walk(n, NULL, cg_func_mark_walker, NULL, NULL);
}


static void cg_mark_functions_used(struct pmlncg *cg)
{
	struct list *flist, *n;
	struct cg_func_ctx *fc;
	struct pml_rule *r;
	struct pml_function *f;

	flist = &cg->ast->funcs.list;
	l_for_each(n, flist) {
		f = (struct pml_function *)l_to_node(n);
		fc = (struct cg_func_ctx *)f->cgctx;
		fc->called = 0;
	}

	if (cg->ast->b_rule != NULL) {
		cg_func_mark_walk((union pml_node *)cg->ast->b_rule->pattern);
		cg_func_mark_walk((union pml_node *)cg->ast->b_rule->stmts);
	}
	if (cg->ast->t_rule != NULL) {
		cg_func_mark_walk((union pml_node *)cg->ast->t_rule->pattern);
		cg_func_mark_walk((union pml_node *)cg->ast->t_rule->stmts);
	}
	if (cg->ast->e_rule != NULL) {
		cg_func_mark_walk((union pml_node *)cg->ast->e_rule->pattern);
		cg_func_mark_walk((union pml_node *)cg->ast->e_rule->stmts);
	}
	l_for_each(n, &cg->ast->p_rules) {
		r = (struct pml_rule *)l_to_node(n);
		cg_func_mark_walk((union pml_node *)r->pattern);
		cg_func_mark_walk((union pml_node *)r->stmts);
	}
}


static int cg_func(struct pmlncg *cg, struct pml_function *f)
{
	struct pml_ibuf *b = &cg->ibuf;
	ulong vlen;
	struct cg_func_ctx *fc = (struct cg_func_ctx *)f->cgctx;

	abort_unless(cg->curfunc == NULL);
	cg->curfunc = f;

	fc->addr = nexti(b);
	fc->resolved = 1;

	if (f->vstksz > 0) {
		abort_unless(f->vstksz % PML_SCALAR_SIZE == 0);
		vlen = f->vstksz / PML_SCALAR_SIZE;
		EMIT_W(cg, ZPUSH, vlen);
	}

	if (cg_stmt(cg, f->body) < 0)
		return -1;

	if (retlen(f) > 0)
		EMIT_W(cg, PUSH, 0);

	EMIT_RET(cg, f);

	cg->curfunc = NULL;
	return 0;
}


static int cg_funcs(struct pmlncg *cg)
{
	struct pml_function *f;
	struct cg_func_ctx *fc;
	struct list *flist, *n;
	struct callsite *csarr;
	uint cslen;
	flist = &cg->ast->funcs.list;
	struct netvm_inst *inst;
	struct cg_intr *intr;

	cg_mark_functions_used(cg);

	l_for_each(n, flist) {
		f = (struct pml_function *)l_to_node(n);
		if (PML_FUNC_IS_INLINE(f))
			continue;

		/* We don't support indirect calling at the moment, so it is safe */
		/* to omit functions that don't actually have callers. */
		fc = (struct cg_func_ctx *)f->cgctx;
		if (fc->called == 0)
			continue;

		if (PML_FUNC_IS_INTRINSIC(f)) {
			intr = find_intrinsic(f);
			if (intr == NULL) {
				cgerr(cg, "cg_funcs: unable to find codegen "
					  "for intrinsic function '%s'", 
				      f->name);
				return -1;
			}
			abort_unless(intr->cgfunc || intr->cgcall);
			if (intr->cgfunc != NULL)
				if ((*intr->cgfunc)(cg, f, intr) < 0)
					return -1;
		} else {
			if (cg_func(cg, f) < 0)
				return -1;
		}
	}

	pcg_get_saved_callsites(&cg->calls, &csarr, &cslen);
	while (cslen > 0) {
		inst = &cg->ibuf.inst[csarr->iaddr];
		f = csarr->func;
		fc = (struct cg_func_ctx *)f->cgctx;
		inst->w = fc->addr;
		++csarr;
		--cslen;
	}

	return 0;
}


STATIC_BUG_ON(UINTMAX_LT_MAXREXPAT, UINT_MAX < NETVM_MAXREXPAT);
static int add_regexes(struct pmlncg *cg, struct pml_literal **rexarr,
		       ulong nrex)
{
	struct pml_literal *lit;
	struct cg_lit_ctx *lc;
	uint i = 0;

	if (nrex > NETVM_MAXREXPAT) {
		cgerr(cg, "Too many regular expressions (> %d) for the "
			  "netvm regex coprocessor", NETVM_MAXREXPAT);
		return -1;
	}
	while (nrex > 0) {
		lit = *rexarr;
		abort_unless(lit->type == PMLTT_BYTESTR);

		PUSH(cg, MEMADDR(lit->u.bytestr.addr, PML_SEG_ROMEM));
		PUSH(cg, lit->u.bytestr.len);
		PUSH(cg, i);
		EMIT_XY(cg, CPOPI, NETVM_CPI_REX, NETVM_CPOC_REX_INIT);
		lc = (struct cg_lit_ctx *)lit->cgctx;
		lc->rexidx = i;

		--nrex;
		++rexarr;
	}
	
	return 0;
}


static int cg_begin_tick_end(struct pmlncg *cg)
{
	struct pml_rule *r;
	ulong nwords;
	struct pml_literal **rexarr;
	ulong nrex;

	pml_ast_get_rexarr(cg->ast, &rexarr, &nrex);

	/* Do BEGIN if there's a rule OR if there are regexes to initialize */
	if (nrex > 0 || cg->ast->b_rule != NULL) {
		cg->prog->eps[NVMP_EP_START] = nexti(&cg->ibuf);

		if (add_regexes(cg, rexarr, nrex) < 0)
			return -1;

		if (cg->ast->b_rule != NULL) {
			r = cg->ast->b_rule;
			nwords = r->vars.addr_rw2 / PML_SCALAR_SIZE;
			if (nwords > 0)
				EMIT_W(cg, ZPUSH, nwords);
			if (cg_stmt(cg, (union pml_node *)r->stmts) < 0)
				return -1;
		}

		EMIT_W(cg, HALT, NVMP_STATUS_DONE);
	}

	if (cg->ast->t_rule != NULL) {
		cg->prog->eps[NVMP_EP_TICK] = nexti(&cg->ibuf);
		r = cg->ast->t_rule;
		nwords = r->vars.addr_rw2 / PML_SCALAR_SIZE;
		if (nwords > 0)
			EMIT_W(cg, ZPUSH, nwords);
		if (cg_stmt(cg, (union pml_node *)r->stmts) < 0)
			return -1;
		EMIT_W(cg, HALT, NVMP_STATUS_DONE);
	}

	if (cg->ast->e_rule != NULL) {
		cg->prog->eps[NVMP_EP_END] = nexti(&cg->ibuf);
		r = cg->ast->e_rule;
		nwords = r->vars.addr_rw2 / PML_SCALAR_SIZE;
		if (nwords > 0)
			EMIT_W(cg, ZPUSH, nwords);
		if (cg_stmt(cg, (union pml_node *)r->stmts) < 0)
			return -1;
		EMIT_W(cg, HALT, NVMP_STATUS_DONE);
	}

	return 0;
}


static int cg_rules(struct pmlncg *cg)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct netvm_inst *inst;
	struct list *n;
	struct pml_rule *r;
	union pml_node *pat;
	uint eaddr;
	uint tbaddr = 0;
	ulong nwords;

	if (l_isempty(&cg->ast->p_rules))
		return 0;

	cg->prog->eps[NVMP_EP_PACKET] = nexti(&cg->ibuf);

	l_for_each(n, &cg->ast->p_rules) {
		r = (struct pml_rule *)l_to_node(n);
		pat = (union pml_node *)r->pattern;
		nwords= r->vars.addr_rw2 / PML_SCALAR_SIZE;

		if (pat != NULL) {
			if (cg_expr(cg, pat, PML_ETYPE_SCALAR) < 0)
				return -1;
			tbaddr = nexti(b);
			EMIT_W(cg, BZI, 0);
		}

		if (nwords > 0)
			EMIT_W(cg, ZPUSH, nwords);

		if (cg_stmt(cg, (union pml_node *)r->stmts) < 0)
			return -1;

		if (nwords > 0)
			EMIT_W(cg, POP, nwords);

		eaddr = nexti(&cg->ibuf);
		if (pat != NULL) {
			inst = b->inst + tbaddr;
			inst->w = eaddr - tbaddr;
		}

		pcg_resolve_nextrules(cg, eaddr);
	}

	EMIT_W(cg, PUSH, 1);
	EMIT_W(cg, HALT, NVMP_STATUS_DONE);

	return 0;
}


static void clearcg(struct pmlncg *cg, int copied, int clearall)
{
	struct netvm_meminit *inits;

	abort_unless(cg);

	dyb_clear(&cg->calls);
	dyb_clear(&cg->breaks);
	dyb_clear(&cg->continues);
	dyb_clear(&cg->nextrules);

	if (clearall) {
		pib_clear(&cg->ibuf);
		if (copied) {
			inits = cg->prog->inits;
			free(inits[0].val.data);
			free(inits[1].val.data);
		}
	}
}


int pml_to_nvmp(struct pml_ast *ast, struct netvm_program *prog, int copy,
		char estr[PMLNCG_MAXERR])
{
	struct pmlncg cg;
	struct netvm_meminit *inits;

	cg.ast = ast;
	cg.prog = prog;
	pib_init(&cg.ibuf);
	dyb_init(&cg.calls, NULL);
	dyb_init(&cg.breaks, NULL);
	dyb_init(&cg.continues, NULL);
	dyb_init(&cg.nextrules, NULL);
	cg.curfunc = NULL;
	cg.curloop = NULL;
	str_copy(cg.err, "", sizeof(cg.err));

	if (!ast || !prog || prog->inits != NULL || prog->inst != NULL) {
		cgerr(&cg, "Invalid argument");
		return -1;
	}

	inits = calloc(sizeof(struct netvm_meminit), PMLCG_MI_NUM);
	if (inits == NULL) {
		cgerr(&cg, "Out of memory for memory initializations base");
		return -1;
	}


	prog->inits = inits;
	prog->ninits = 0;
	prog->matchonly = 0;
	prog->eps[NVMP_EP_START] = NVMP_EP_INVALID;
	prog->eps[NVMP_EP_PACKET] = NVMP_EP_INVALID;
	prog->eps[NVMP_EP_TICK] = NVMP_EP_INVALID;
	prog->eps[NVMP_EP_END] = NVMP_EP_INVALID;

	if (copy_meminits(ast, prog, copy) < 0) {
		cgerr(&cg, "Out of memory for memory initializations");
		goto err;
	}

	init_segs(&cg);

	init_coproc(&cg);

	if (cg_funcs(&cg) < 0)
		goto err;

	if (cg_begin_tick_end(&cg) < 0)
		goto err;

	if (cg_rules(&cg) < 0)
		goto err;

	/* if we got to here we are good to go! */

	/* clean up memory if this was a destructive transformation */
	if (!copy) {
		/* the program keeps the initializations: remove from AST */
		dyb_release(&ast->mi_bufs[PML_SEG_ROMEM]);
		dyb_release(&ast->mi_bufs[PML_SEG_RWMEM]);
		pml_ast_clear(ast);
	}

	/* program takes ownership of instruction buffer */
	prog->inst = cg.ibuf.inst;
	prog->ninst = cg.ibuf.ninst;

	clearcg(&cg, copy, 0);

	return 0;

err:
	str_copy(estr, cg.err, PMLNCG_MAXERR);
	clearcg(&cg, copy, 1);
	return -1;
}
