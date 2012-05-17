#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <cat/cat.h>
#include <string.h>

#include "pmlncg.h"
#include "netvm_std_coproc.h"

#define l_to_node(p) (union pml_node *)container(p, struct pml_node_base, ln)
#define MEMADDR(_a, _s)	\
	(((uint64_t)(_a) & 0xFFFFFFFFFFFFFFull) | \
	 (((uint64_t)(_s) & NETVM_SEG_SEGMASK) << NETVM_UA_SEG_OFF))
#define PKTADDR(_a, _p) MEMADDR(_a, ((_p) | NETVM_SEG_ISPKT))

/* some forward declarations of commonly needed functions */
static int val64(struct pml_ast *ast, union pml_node *n, uint64_t *v);
int cg_expr(struct pml_ibuf *b, struct pml_ast *ast, union pml_node *n,
	    int etype);
int cg_stmt(struct pmlncg *cg, union pml_node *n);
static int typecast(struct pml_ibuf *b, int otype, int ntype);


struct cg_pdesc {
	int oc;
	int oci;
	uint8_t x;
	uint field;
	uint prid;
	ulong pfoff;
	union pml_expr_u *pkt;
	union pml_expr_u *idx;
	union pml_expr_u *off;
};


static void cgpd_init(struct cg_pdesc *cgpd, int oc, int oci, uint8_t x,
		      struct pml_locator *loc);
static int cg_pdop(struct pml_ibuf *b, struct pml_ast *ast,
		   struct cg_pdesc *cgpd);



struct cgeaux {
	struct pml_ibuf *	ibuf;
	struct pml_ast *	ast;
	int			etype;
};


struct cgestk {
	uint			etype;
	uint			iaddr;
};


struct locval {
	int			onstack;
	uint64_t		val;
};


struct cg_intr;
typedef int (*cg_intr_call_f)(struct pml_ibuf *b, struct pml_ast *ast,
			      struct pml_call *c, struct cg_intr *intr);


#define CG_INTR_MAXOPS	4
struct cg_intr {
	const char *		name;
	cg_intr_call_f		cgf;
	uint			numop;
	struct netvm_inst	ops[CG_INTR_MAXOPS];
};


const static struct locval locval_0 = { 0, 0 };


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

#define EMIT_XYZW(_ibuf, SYM, _x, _y, _z, _w) 				\
	do { 		   						\
		if (pib_add_ixyzw(_ibuf, NETVM_OC_##SYM,_x,_y,_z,_w) < 0)\
			return -1;					\
	} while (0)

#define EMIT_NULL(_ibuf, SYM) EMIT_XYZW(_ibuf, SYM, 0, 0, 0, 0)
#define EMIT_X(_ibuf, SYM, _x) EMIT_XYZW(_ibuf, SYM, _x, 0, 0, 0)
#define EMIT_W(_ibuf, SYM, _w) EMIT_XYZW(_ibuf, SYM, 0, 0, 0, _w)
#define EMIT_XW(_ibuf, SYM, _x, _w) EMIT_XYZW(_ibuf, SYM, _x, 0, 0, _w)
#define EMIT_XY(_ibuf, SYM, _x, _y) EMIT_XYZW(_ibuf, SYM, _x, _y, 0, 0)
#define EMIT_XYW(_ibuf, SYM, _x, _y, _w) EMIT_XYZW(_ibuf, SYM, _x, _y, 0, _w)


static int push64(struct pml_ibuf *b, uint64_t v)
{
	EMIT_W(b, PUSH, (uint32_t)(v & 0xFFFFFFFF));
	if ((v >> 32) != 0)
		EMIT_W(b, ORHI, (uint32_t)((v >> 32) & 0xFFFFFFFF));
	return 0;
}


#define PUSH64(_b, _v)					\
	do { 						\
		if (push64(_b, _v) < 0) return -1;	\
	} while (0)


#define EMIT_IBINOP(_ibuf, SYM, _w)			\
	do {						\
		if ((_w) <= 0xFFFFFFFF) {		\
			EMIT_W(_ibuf, SYM##I, _w);	\
		} else {				\
			PUSH64(_ibuf, _w);		\
			EMIT_NULL(_ibuf, SYM);		\
		}					\
	} while (0)

#define EMIT_SWAP_IBINOP(_ibuf, SYM, _w)		\
	do {						\
		if ((_w) <= 0xFFFFFFFF) {		\
			EMIT_XW(_ibuf, SYM##I, 1, _w);	\
		} else {				\
			PUSH64(_ibuf, _w);		\
			EMIT_X(_ibuf, SYM, 1);		\
		}					\
	} while (0)



#define UNIMPL(s)							\
	do {								\
		fprintf(stderr, "unimplemented operation" #s "\n"); 	\
		return -1;						\
	} while (0)


static uint nexti(struct pml_ibuf *b)
{
	abort_unless(b);
	return b->ninst;
}


static int _i_scarg(struct pml_ibuf *b, struct pml_ast *ast, struct pml_call *c,
		    struct cg_intr *intr)
{
	struct pml_list *pl = c->args;
	struct pml_function *f = c->func;
	union pml_node *e;
	int i;

	e = l_to_node(l_head(&pl->list));
	if (cg_expr(b, ast, e, PML_ETYPE_SCALAR) < 0)
		return -1;

	for (i = 1; i < f->arity; ++i) {
		e = l_to_node(l_next(&e->base.ln));
		if (cg_expr(b, ast, e, PML_ETYPE_SCALAR) < 0)
			return -1;
	}

	for (i = 0; i < intr->numop; ++i) {
		if (pib_add(b, &intr->ops[i]) < 0)
			return -1;
	}

	return 0;
}


int _i_loc_to_pdesc(struct pml_ibuf *b, struct pml_ast *ast,
		    struct pml_locator *loc, struct cg_intr *intr)
{
	struct cg_pdesc cgpd;
	if (loc->off) {
		fprintf(stderr,
			"offset not allowed in locator for intrinsic '%s'\n",
			intr->name);
		return -1;
	}
	if (loc->len) {
		fprintf(stderr,
			"length not allowed in locator for intrinsic '%s'\n",
			intr->name);
		return -1;
	}
	cgpd_init(&cgpd, -1, -1, 0, loc);
	return cg_pdop(b, ast, &cgpd);
}


static int _i_pdarg(struct pml_ibuf *b, struct pml_ast *ast, struct pml_call *c,
		    struct cg_intr *intr)
{
	int i;
	struct pml_list *pl = c->args;
	struct pml_locator *loc;

	loc = (struct pml_locator *)l_to_node(l_head(&pl->list));
	if (loc->type != PMLTT_LOCATOR) {
		fprintf(stderr, "intrinsic '%s' requires a protocol field\n",
			intr->name);
		return -1;
	}

	if (_i_loc_to_pdesc(b, ast, loc, intr) < 0)
		return -1;

	for (i = 0; i < intr->numop; ++i) {
		if (pib_add(b, &intr->ops[i]) < 0)
			return -1;
	}

	return 0;
}


static int _i_inscut(struct pml_ibuf *b, struct pml_ast *ast,
		     struct pml_call *c, struct cg_intr *intr)
{
	struct pml_list *pl = c->args;
	union pml_node *pkt, *off, *len;
	uint64_t pv, ov;

	pkt = l_to_node(l_head(&pl->list));
	off = l_to_node(l_next(&pkt->base.ln));
	len = l_to_node(l_next(&off->base.ln));

	if (PML_EXPR_IS_LITERAL(pkt) && PML_EXPR_IS_LITERAL(off)) {
		if (val64(ast, pkt, &pv) < 0)
			return -1;
		if (val64(ast, off, &ov) < 0)
			return -1;
		pv &= NETVM_SEG_SEGMASK;
		pv |= NETVM_SEG_ISPKT;
		ov &= 0xFFFFFFFF;
		PUSH64(b, (pv << NETVM_UA_SEG_OFF) | ov);
	} else {
		if (cg_expr(b, ast, pkt, PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_W(b, ORI, NETVM_SEG_ISPKT);
		EMIT_W(b, SHLI, NETVM_UA_SEG_OFF);
		if (cg_expr(b, ast, off, PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_W(b, ANDI, 0xFFFFFFFF);
		EMIT_NULL(b, OR);
	}

	if (cg_expr(b, ast, len, PML_ETYPE_SCALAR) < 0)
		return -1;

	if (pib_add(b, &intr->ops[0]) < 0)
		return -1;

	return 0;
}


struct cg_intr intrinsics[] = { 
	{ "pkt_new", _i_scarg, 1, { NETVM_OP(PKNEW,0,0,0,0) } },
	{ "pkt_swap", _i_scarg, 1, { NETVM_OP(PKSWAP,0,0,0,0) } },
	{ "pkt_copy", _i_scarg, 1, { NETVM_OP(PKCOPY,0,0,0,0) } },
	{ "pkt_del", _i_scarg, 1, { NETVM_OP(PKDEL,0,0,0,0) }  },
	{ "pkt_ins_u", _i_inscut, 1, { NETVM_OP(PKINS,0,0,0,0) } },
	{ "pkt_ins_d", _i_inscut, 1, { NETVM_OP(PKINS,0,0,0,0) } },
	{ "pkt_cut_u", _i_inscut, 1, { NETVM_OP(PKCUT,0,0,0,0) } },
	{ "pkt_cut_d", _i_inscut, 1, { NETVM_OP(PKCUT,0,0,0,0) } },
	{ "pkt_parse", _i_scarg, 1, { NETVM_OP(PKPRS,0,0,0,0) } },
	{ "parse_push_back",  _i_scarg, 1, { NETVM_OP(PKPPSH,0,0,0,0) } },
	{ "parse_pop_back",   _i_scarg, 1, { NETVM_OP(PKPPOP,0,0,0,0) } },
	{ "parse_push_front", _i_scarg, 1, { NETVM_OP(PKPPSH,1,0,0,0) } },
	{ "parse_pop_front",  _i_scarg, 1, { NETVM_OP(PKPPOP,1,0,0,0) } },
	{ "parse_update", _i_pdarg, 1, { NETVM_OP(PKPUP,0,0,0,0) } },
	{ "fix_dltype", _i_scarg, 1, { NETVM_OP(PKFXD,0,0,0,0) } },
	{ "fix_len", _i_pdarg, 1, { NETVM_OP(PKFXL,0,0,0,0) } },
	{ "fix_all_len",  _i_scarg, 3, 
		{ NETVM_OP(ORI,0,0,0,(PRID_NONE<<4)),
		  NETVM_OP(SHLI,0,0,0,44),
		  NETVM_OP(PKFXL,0,0,0,0), } },
	{ "fix_csum", _i_pdarg, 1, { NETVM_OP(PKFXC,0,0,0,0) } },
	{ "fix_all_csum", _i_scarg, 3,
		{ NETVM_OP(ORI,0,0,0,(PRID_NONE<<4)),
		  NETVM_OP(SHLI,0,0,0,44),
		  NETVM_OP(PKFXC,0,0,0,0), } },
	{ "pop", _i_scarg, 1, { NETVM_OP(POPL,8,0,0,0) } },
	{ "log2", _i_scarg, 2, 
		{ NETVM_OP(NLZ,8,0,0,0), NETVM_OP(SUBI,1,0,0,64) } },
	{ "min", _i_scarg, 1, { NETVM_OP(MIN,0,0,0,0) } },
	{ "max", _i_scarg, 1, { NETVM_OP(MAX,0,0,0,0) } },
	{ NULL, NULL, 0, { {0} } },
};


static int cg_intrinsic(struct pml_ibuf *b, struct pml_ast *ast,
			struct pml_call *c, int etype)
{
	struct cg_intr *intr;
	struct pml_function *f = c->func;

	for (intr = intrinsics; 
	     intr->name != NULL && (strcmp(intr->name, f->name) != 0);
	     ++intr) ;

	if (intr->name == NULL) {
		fprintf(stderr, "intrinsic function '%s' not found\n", f->name);
		return -1;
	}

	if (intr->cgf == NULL) {
		fprintf(stderr, "intrinsic function '%s' is unimplemented\n",
			f->name);
		return -1;
	}

	if ((*intr->cgf)(b, ast, c, intr) < 0)
		return -1;

	if (typecast(b, c->etype, etype) < 0)
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
	return cg->breaks.len / sizeof(uint);
}


static void pcg_resolve_continues(struct pmlncg *cg, uint cskip, uint addr)
{
	uint *iaddrs, naddrs;
	pcg_get_saved_iaddrs(&cg->continues, &iaddrs, &naddrs);
	abort_unless(cskip <= naddrs);
	iaddrs += cskip;
	naddrs -= cskip;
	pcg_resolve_branches(&cg->ibuf, iaddrs, naddrs, addr);
	cg->continues.len -= cskip * sizeof(uint);
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


static int cg_scalar(struct pml_ibuf *b, struct pml_literal *l)
{
	abort_unless(b && l);
	return push64(b, l->u.scalar);
}


static int cg_bytestr(struct pml_ibuf *b, struct pml_literal *l, int withlen)
{
	struct pml_bytestr *v;

	abort_unless(b && l);
	v = &l->u.bytestr;

	PUSH64(b, v->addr);
	if (v->segnum != 0)
		EMIT_W(b, ORHI, (v->segnum << 24));
	if (withlen)
		PUSH64(b, v->len);

	return 0;
}


static int cg_maskval(struct pml_ibuf *b, struct pml_literal *l)
{
	struct pml_bytestr *v, *m;

	abort_unless(b && l);
	v = &l->u.maskval.val;
	m = &l->u.maskval.mask;

	PUSH64(b, v->addr);
	if (v->segnum != 0)
		EMIT_W(b, ORHI, (v->segnum << 24));
	PUSH64(b, m->addr);
	if (v->segnum != 0)
		EMIT_W(b, ORHI, (m->segnum << 24));
	PUSH64(b, m->len);

	return 0;
}


static int mask2scalar(struct pml_ibuf *b)
{
	EMIT_W(b, UMINI, 8);	/* len = min(len, 8) */
	EMIT_W(b, DUP, 0);	/* dup len */
	EMIT_XW(b, SWAP, 0, 3);	/* swap with val addr */
	EMIT_XW(b, SWAP, 0, 1);	/* swap with orig len */
	EMIT_NULL(b, LD);
	EMIT_XW(b, SWAP, 0, 2);	/* swap with dup len */
	EMIT_NULL(b, LD);
	EMIT_NULL(b, AND);
	return 0;
}


static int mask2bytes(struct pml_ibuf *b)
{
	/* simply get rid of the mask address */
	EMIT_XW(b, SWAP, 0, 1);
	EMIT_NULL(b, POP);
	return 0;
}


static int typecast(struct pml_ibuf *b, int otype, int ntype)
{
	if ((ntype == PML_ETYPE_UNKNOWN) || (otype == ntype))
		return 0;

	switch (ntype) {
	case PML_ETYPE_SCALAR:
		if (otype == PML_ETYPE_MASKVAL) {
			return mask2scalar(b);
		} else if (otype == PML_ETYPE_BYTESTR) {
			EMIT_W(b, UMINI, 8);
			EMIT_NULL(b, LD);
			return 0;
		} else {
			abort_unless(otype == PML_ETYPE_VOID);
			EMIT_W(b, PUSH, 0);
		}
		break;

	case PML_ETYPE_BYTESTR:
		if (otype != PML_ETYPE_MASKVAL) {
			fprintf(stderr, 
				"Can not convert type '%d' to byte string\n",
				otype);
			return -1;
		}
		return mask2bytes(b);


	case PML_ETYPE_MASKVAL:
		fprintf(stderr, "Can not convert type '%d' to mask value\n",
			otype);
		return -1;

	case PML_ETYPE_VOID:
		if (otype == PML_ETYPE_SCALAR) {
			EMIT_W(b, POP, 1);
		} else if (otype == PML_ETYPE_BYTESTR) {
			EMIT_W(b, POP, 2);
		} else {
			abort_unless(otype == PML_ETYPE_MASKVAL);
			EMIT_W(b, POP, 3);
		}
		break;

	default:
		abort_unless(0);
	}

	return 0;
}


static int cg_matchop(struct pml_ibuf *b, struct pml_op *op)
{
	union pml_expr_u *lhs;
	union pml_expr_u *rhs;

	abort_unless(b && op);
	lhs = op->arg1;
	rhs = op->arg2;

	if (rhs->base.type == PMLTT_BYTESTR) {
		abort_unless(lhs->expr.etype == PML_ETYPE_BYTESTR);
		/* We start with: len2, addr2, len1, addr1 */
		EMIT_XW(b, SWAP, 1, 2); /* now we have: len2, len1, addr2, addr1 */
		EMIT_W(b, DUP, 0);
		EMIT_XW(b, SWAP, 0, 2); /* now we have: len1, len2, len2, addr1, addr2 */
		EMIT_NULL(b, EQ);
		EMIT_W(b, BZI, 3);
		EMIT_NULL(b, CMP);
		EMIT_W(b, BRI, 3);
		EMIT_W(b, POP, 3);
		EMIT_W(b, PUSH, 0);
	} else {
		/* We start with: len2, mkaddr, paddr, len1, addr1 */
		abort_unless(rhs->base.type == PMLTT_MASKVAL);
		EMIT_XW(b, SWAP, 1, 3); /* len2, len1, paddr, mkaddr, addr1 */
		EMIT_XW(b, SWAP, 2, 3); /* len2, len1, mkaddr, paddr, addr1 */
		EMIT_W(b, DUP, 0);
		EMIT_XW(b, SWAP, 0, 2); /* len1, len2, len2, mkaddr, paddr, addr1 */
		EMIT_NULL(b, EQ);
		EMIT_W(b, BZI, 3); /* (eq?), len2, mkaddr, paddr, addr1 */
		EMIT_NULL(b, MSKCMP);
		EMIT_W(b, BRI, 3);
		EMIT_W(b, POP, 4);
		EMIT_W(b, PUSH, 0);
	}
	if (op->op == PMLOP_NOTMATCH)
		EMIT_NULL(b, NOT);

	return 0;
}


static int cg_op(struct pml_ibuf *b, struct pml_op *op, struct cgestk *es)
{
	struct netvm_inst *inst;

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
		return cg_matchop(b, op);

	case PMLOP_REXMATCH:
	case PMLOP_NOTREXMATCH:
		UNIMPL(rexmatch);
		break;

	case PMLOP_EQ:
		EMIT_NULL(b, EQ);
		break;
	case PMLOP_NEQ:
		EMIT_NULL(b, NEQ);
		break;
	case PMLOP_LT:
		EMIT_NULL(b, LT);
		break;
	case PMLOP_GT:
		EMIT_NULL(b, GT);
		break;
	case PMLOP_LEQ:
		EMIT_NULL(b, LE);
		break;
	case PMLOP_GEQ:
		EMIT_NULL(b, GE);
		break;
	case PMLOP_BOR:
		EMIT_NULL(b, OR);
		break;
	case PMLOP_BXOR:
		EMIT_NULL(b, XOR);
		break;
	case PMLOP_BAND:
		EMIT_NULL(b, AND);
		break;
	case PMLOP_PLUS:
		EMIT_NULL(b, ADD);
		break;
	case PMLOP_MINUS:
		EMIT_NULL(b, SUB);
		break;
	case PMLOP_TIMES:
		EMIT_NULL(b, MUL);
		break;
	case PMLOP_DIV:
		EMIT_NULL(b, DIV);
		break;
	case PMLOP_MOD:
		EMIT_NULL(b, MOD);
		break;
	case PMLOP_SHL:
		EMIT_NULL(b, SHL);
		break;
	case PMLOP_SHR:
		EMIT_NULL(b, SHR);
		break;

	case PMLOP_NOT:
		EMIT_NULL(b, NOT);
		break;
	case PMLOP_BINV:
		EMIT_NULL(b, INVERT);
		break;
	case PMLOP_NEG:
		EMIT_NULL(b, INVERT);
		EMIT_W(b, ADDI, 1);
		break;

	default:
		abort_unless(0);
		break;
	}

	return 0;
}


static int cg_call(struct pml_ibuf *b, struct pml_ast *ast, struct pml_call *c,
		   int etype)
{
	struct list *n;
	struct pml_function *f;

	abort_unless(c->args && c->func);
	f = c->func;

	if (PML_FUNC_IS_INTRINSIC(f))
		return cg_intrinsic(b, ast, c, etype);

	l_for_each_rev(n, &c->args->list) {
		if (cg_expr(b, ast, l_to_node(n), PML_ETYPE_SCALAR) < 0)
			return -1;
	}

	if (PML_FUNC_IS_INLINE(f)) {
		EMIT_NULL(b, PUSHFR);
		if (cg_expr(b, ast, f->body, PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_XW(b, POPFR, 1, f->arity);
	} else {
		PUSH64(b, f->addr);
		EMIT_NULL(b, CALL);
	}

	if (typecast(b, c->etype, etype) < 0)
		return -1;

	return 0;
}


static int val64(struct pml_ast *ast, union pml_node *n, uint64_t *v)
{
	if (!PML_EXPR_IS_LITERAL(n)) {
		fprintf(stderr, "val64(): node of type '%d' is not literal\n",
			n->base.type);
		return -1;
	}
	if (pml_lit_val64(ast, &n->literal, v) < 0) {
		fprintf(stderr, "error determining literal value of type %d\n",
			n->literal.type);
		return -1;
	}
	return 0;
}


static int cg_locval(struct pml_ibuf *b, struct pml_ast *ast,
		     union pml_expr_u *e, struct locval *val)
{
	if (e == NULL) {
		val->onstack = 0;
		val->val = 0;
	} else if (!PML_EXPR_IS_LITERAL(e)) {
		val->onstack = 1;
		if (cg_expr(b, ast, (union pml_node *)e, PML_ETYPE_SCALAR) < 0)
			return -1;
	} else {
		val->onstack = 0;
		if (val64(ast, (union pml_node *)e, &val->val) < 0)
			return -1;
	}

	return 0;
}


static ulong lvaraddr(struct pml_variable *var)
{
	struct pml_function *func = var->func;
	if (var->vtype == PML_VTYPE_LOCAL) {
		return var->addr; /* above BP */
	} else if (PML_FUNC_IS_INLINE(func)) {
		return var->addr + 1; /* below BP */
	} else {
		return var->addr + 2; /* below BP */
	}
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

		cgpd->field = NETVM_PRP_OFF_BASE + pf->oidx;
		cgpd->prid = pf->prid;
		cgpd->pfoff = pf->off;
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


static int cg_pdop(struct pml_ibuf *b, struct pml_ast *ast,
		   struct cg_pdesc *cgpd)
{
	struct locval lpkt, lidx, loff;

	if (cg_locval(b, ast, cgpd->pkt, &lpkt) < 0)
		return -1;
	if (lpkt.onstack) {
		EMIT_W(b, ANDI, NETVM_PD_PKT_MASK);
		EMIT_W(b, SHLI, NETVM_PD_PKT_OFF);
	}

	if (cg_locval(b, ast, cgpd->idx, &lidx) < 0)
		return -1;
	if (lidx.onstack) {
		EMIT_W(b, ANDI, NETVM_PD_IDX_MASK);
		EMIT_W(b, SHLI, NETVM_PD_IDX_OFF);
	}

	if (cgpd->off != NULL) {
		if (cg_locval(b, ast, cgpd->off, &loff) < 0)
			return -1;
		if (loff.onstack) {
			if (cgpd->pfoff > 0)
				EMIT_W(b, ADDI, cgpd->pfoff);
			EMIT_W(b, UMINI, NETVM_PD_OFF_MASK);
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
		uint64_t spd = (((uint64_t)cgpd->prid & NETVM_PD_PRID_MASK)
					<< NETVM_PD_PRID_OFF) |
			       (((uint64_t)cgpd->field & NETVM_PD_FLD_MASK)
					<< NETVM_PD_FLD_OFF);

		if (!lpkt.onstack)
			spd |= (lpkt.val & NETVM_PD_PKT_MASK)
					<< NETVM_PD_PKT_OFF;
		if (!lidx.onstack)
			spd |= (lidx.val & NETVM_PD_IDX_MASK)
					<< NETVM_PD_IDX_OFF;
		if (!loff.onstack)
			spd |= (loff.val & NETVM_PD_OFF_MASK)
					<< NETVM_PD_OFF_OFF;

		PUSH64(b, spd);
		if (loff.onstack)
			EMIT_NULL(b, OR);
		if (lidx.onstack)
			EMIT_NULL(b, OR);
		if (lpkt.onstack)
			EMIT_NULL(b, OR);

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


int cg_adjlen(struct pml_ibuf *b, struct pml_ast *ast,
	      struct pml_locator *loc, uint64_t *known_len)
{
	struct cg_pdesc cgpd;
	struct pml_variable *var;
	struct pml_literal *lit;
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	struct locval loff;
	uint64_t len;

	*known_len = 0;

	if (loc->reftype == PML_REF_LITERAL) {
		lit = loc->u.litref;
		if (lit->type == PMLTT_BYTESTR) {
			len = lit->u.bytestr.len;
		} else if (lit->type == PMLTT_MASKVAL) {
			len = lit->u.maskval.val.len;
		} else {
			abort_unless(0);
		}
		if (loc->off != NULL) {
			if (cg_locval(b, ast, loc->off, &loff) < 0)
				return -1;
			if (!loff.onstack) {
				if (loff.val >= len) {
					fprintf(stderr, 
						"offset out of range for '%s'"
						": %llu >= %llu\n", loc->name,
						(ullong)loff.val,
						(ullong)len);
					return -1;
				}
				PUSH64(b, len - loff.val);
				*known_len = len - loff.val;
			} else {
				EMIT_IBINOP(b, UMIN, len);
				EMIT_SWAP_IBINOP(b, SUB, len);
			}
		} else { 
			PUSH64(b, len);
			*known_len = len;
		}
	} else if (loc->reftype == PML_REF_VAR) {
		var = loc->u.varref;
		abort_unless(var->vtype == PML_VTYPE_GLOBAL);
		if (loc->off != NULL) {
			if (cg_locval(b, ast, loc->off, &loff) < 0)
				return -1;
			if (!loff.onstack) {
				if (loff.val >= var->width) {
					fprintf(stderr, 
						"offset out of range for '%s'"
						": %llu >= %llu\n", loc->name,
						(ullong)loff.val,
						(ullong)var->width);
					return -1;
				}
				PUSH64(b, var->width - loff.val);
				*known_len = var->width - loff.val;
			} else {
				EMIT_IBINOP(b, UMIN, var->width);
				EMIT_SWAP_IBINOP(b, SUB, var->width);
			}
		} else {
			*known_len = var->width;
			PUSH64(b, var->width);
		}
	} else if (loc->rpfld != PML_RPF_NONE) {
		ns = (struct ns_namespace *)loc->u.nsref;
		abort_unless(ns->type == NST_NAMESPACE);
		abort_unless(PML_RPF_IS_BYTESTR(loc->rpfld));

		if (must_calc_ns_len(ns)) {
			cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
			cgpd.off = NULL;
			cgpd.field = NETVM_PRP_OFF_BASE + ns->len;
			if (cg_pdop(b, ast, &cgpd) < 0)
				return -1;
			cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
			if (cg_pdop(b, ast, &cgpd) < 0)
				return -1;
			EMIT_NULL(b, SUB);
			EMIT_W(b, MAXI, 0);
		} else {
			cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
			cgpd.off = NULL;
			cgpd.field = PML_RPF_TO_NVMLEN(loc->rpfld);
			if (cg_pdop(b, ast, &cgpd) < 0)
				return -1;
			if (loc->off != NULL) {
				if (cg_locval(b, ast, loc->off, &loff) < 0)
					return -1;
				if (!loff.onstack)
					PUSH64(b, loff.val);
				EMIT_NULL(b, SUB);
				EMIT_W(b, MAXI, 0);
			}
		}
	} else {
		pf = (struct ns_pktfld *)loc->u.nsref;
		abort_unless(pf->type == NST_PKTFLD);

		if (NSF_IS_VARLEN(pf->flags)) {
			cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
			cgpd.off = NULL;
			cgpd.field = NETVM_PRP_OFF_BASE + pf->len;
			if (cg_pdop(b, ast, &cgpd) < 0)
				return -1;
			cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
			if (cg_pdop(b, ast, &cgpd) < 0)
				return -1;
			EMIT_NULL(b, SUB);
			EMIT_W(b, MAXI, 0);
		} else {
			if (loc->off != NULL) {
				if (cg_locval(b, ast, loc->off, &loff) < 0)
					return -1;
				if (!loff.onstack) {
					if (loff.val >= pf->len) {
						fprintf(stderr, 
							"offset out of range"
							"for '%s': "
							"%llu >= %llu\n",
							loc->name,
							(ullong)loff.val,
							(ullong)pf->len);
						return -1;
					}
					PUSH64(b, pf->len - loff.val);
					*known_len = pf->len -= loff.val;
				} else {
					EMIT_IBINOP(b, UMIN, pf->len);
					EMIT_SWAP_IBINOP(b, SUB, pf->len);
				}
			} else {
				PUSH64(b, pf->len);
				*known_len = pf->len;
			}
		}

	}

	return 0;
}


int cg_loclen(struct pml_ibuf *b, struct pml_ast *ast,
	      struct pml_locator *loc)
{
	struct locval llen;
	uint64_t len = 0;
	int npush;

	if (cg_adjlen(b, ast, loc, &len) < 0)
		return -1;

	if (loc->len != NULL) {
		if (cg_locval(b, ast, loc->len, &llen) < 0)
			return -1;
		if (!llen.onstack) {
			if (len == 0) {
				EMIT_IBINOP(b, MIN, llen.val);
			} else if (llen.val < len) {
				/*
				 * we have a a known field length and a known
				 * locator length less than the field length.
				 * The last one or two operations on the stack
				 * are a push of the length.  Replace these
				 * push(es) with pushes of the locator length.
				 */
				npush = ((len >> 32) == 0) ? 1 : 2;
				b->ninst -= npush;
				PUSH64(b, llen.val);
			}
		} else {
			EMIT_NULL(b, MIN);
		}
	} 

	return 0;
}


static int cg_memref(struct pml_ibuf *b, struct pml_ast *ast,
		     struct pml_locator *loc)
{
	struct pml_literal *lit;
	struct pml_variable *var;
	uint64_t addr, addr2 = 0, len;
	int seg, seg2;
	struct locval loff;
	uint64_t n;
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
			if (pml_lit_val64(ast, lit, &n) < 0) {
				fprintf(stderr, "error reading literal offset "
						"for locator '%s'\n",
					loc->name);
				return -1;
			}
			if (n >= len) {
				fprintf(stderr,
					"offset for out of range for '%s':"
					" %llu >= %llu\n", loc->name,
					(ullong)n, (ullong)len);
				return -1;
			} else {
				addr += n;
				len -= n;
			}
			PUSH64(b, MEMADDR(addr, seg));
			if (ismask) {
				addr2 += n;
				PUSH64(b, MEMADDR(addr2, seg2));
			}
		} else {
			if (cg_locval(b, ast, loc->off, &loff) < 0)
				return -1;
			/* do not allow offsets to overflow address */
			EMIT_IBINOP(b, UMIN, len);
			if (ismask)
				EMIT_NULL(b, DUP);
			EMIT_IBINOP(b, ADD, addr);
			EMIT_W(b, ORHI, (seg << NETVM_UA_SEG_HI_OFF));
			if (ismask) {
				EMIT_XW(b, SWAP, 0, 1);
				EMIT_IBINOP(b, ADD, addr2);
				EMIT_W(b, ORHI, (seg2 << NETVM_UA_SEG_HI_OFF));
			}
		}

	} else {
		PUSH64(b, MEMADDR(addr, seg));
		if (ismask)
			PUSH64(b, MEMADDR(addr2, seg2));
	}

	if (cg_loclen(b, ast, loc) < 0)
		return -1;

	return 0;
}


static int cg_rpf(struct pml_ibuf *b, struct pml_ast *ast,
		  struct pml_locator *loc, int etype)
{
	struct cg_pdesc cgpd;
	struct ns_namespace *ns = (struct ns_namespace *)loc->u.nsref;

	abort_unless(ns->type == NST_NAMESPACE);
	cgpd_init2(&cgpd, NETVM_OC_LDPF, 
	           PML_RPF_IS_BYTESTR(loc->rpfld) != 0, loc);

	if (cg_pdop(b, ast, &cgpd) < 0)
		return -1;

	if (PML_RPF_IS_BYTESTR(loc->rpfld)) {
		if (cg_loclen(b, ast, loc) < 0)
			return -1;
	} else if (ns->oidx != PRP_OI_SOFF) {
		/*
		 * If we have a namespace referring to a subfield 
		 * within a protocol then we have to test explicitly
		 * for invalid rather than implicitly by getting
		 * the header's parse index.  See cgpd_init2().
		 */
		EMIT_W(b, EQI, NETVM_PF_INVALID);
	}


	if (typecast(b, loc->etype, etype) < 0)
		return -1;

	return 0;
}


static int cg_pfbitfield(struct pml_ibuf *b, struct pml_ast *ast,
			 struct pml_locator *loc)
{
	struct cg_pdesc cgpd;
	struct ns_pktfld *pf = (struct ns_pktfld *)loc->u.nsref;
	ulong bitoff = NSF_BITOFF(pf->flags);
	ulong bytelen = ((pf->len + bitoff + 7) & ~(ulong)7) >> 3;
	ulong remlen = bytelen * 8 - bitoff - pf->len;
	uint64_t mask;

	abort_unless(loc->off == NULL && loc->len == NULL);

	if (bytelen > 8) {
		fprintf(stderr,
			"Unable to generate bitfield %s:  "
			"read byte length = %lu\n",
			pf->name, bytelen);
		return -1;
	}

	cgpd_init2(&cgpd, NETVM_OC_LDPD, bytelen, loc);
	if (cg_pdop(b, ast, &cgpd) < 0)
		return -1;

	if (remlen > 0)
		EMIT_W(b, SHRI, remlen);


	mask = ((uint64_t)1 << pf->len) - 1;
	if (mask <= 0xFFFFFFFF) {
		EMIT_W(b, ANDI, mask);
	} else {
		PUSH64(b, mask);
		EMIT_NULL(b, AND);
	}

	return 0;
}


/*
  Cases:
  pdesc in instr:
   - etype == SCALAR
     * len is static 
       use ldpdi with len = max(8, len)
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
       use ldpd with len = max(8, len)
     * len is dynamic
       use ldpd, eval len, ldu
   - etype == BYTESTR
     * len is static
       use ldpf, push len
     * len is dynamic
       use ldpf, eval len
 */
static int cg_pfbytefield(struct pml_ibuf *b, struct pml_ast *ast,
			  struct pml_locator *loc, int etype)
{
	struct cg_pdesc cgpd;
	struct ns_pktfld *pf = (struct ns_pktfld *)loc->u.nsref;
	int fixedlen = 0;
	uint64_t len, n;
	struct pml_literal *lit;

	if (!NSF_IS_VARLEN(pf->flags)) {
		fixedlen = 1;
		len = pf->len;
	}
	if (loc->off != NULL) {
		if (PML_EXPR_IS_LITERAL(loc->off) && fixedlen) {
			lit = (struct pml_literal *)loc->off;
			if (pml_lit_val64(ast, lit, &n) < 0) {
				fprintf(stderr, "error reading literal offset "
						"for locator '%s'\n",
					loc->name);
				return -1;
			}
			if (n >= len) {
				fprintf(stderr,
					"offset for out of range for '%s':"
					" %llu >= %llu\n", loc->name,
					(ullong)n, (ullong)len);
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
			if (pml_lit_val64(ast, lit, &n) < 0) {
				fprintf(stderr, "error reading literal length "
						"for locator '%s'\n",
					loc->name);
				return -1;
			}
			if (n > len) {
				fprintf(stderr,
					"length for out of range for '%s':"
					" %llu >= %llu\n", loc->name,
					(ullong)n, (ullong)len);
				return -1;
			}
			len = n;
		} else {
			fixedlen = 0;
		}
	}


	if (etype == PML_ETYPE_SCALAR && fixedlen &&
	    cgpd.field <= NETVM_PPD_FLD_MASK) {
		if (len > 8)
			len = 8;
		cgpd_init2(&cgpd, NETVM_OC_LDPD, len, loc);
		return cg_pdop(b, ast, &cgpd);
	} else {
		cgpd_init2(&cgpd, NETVM_OC_LDPF, 1, loc);
		if (cg_pdop(b, ast, &cgpd) < 0)
			return -1;
		if (cg_loclen(b, ast, loc) < 0)
			return -1;
	}

	if (etype == PML_ETYPE_SCALAR)
		EMIT_NULL(b, LD);

	return 0;
}


static int cg_varref(struct pml_ibuf *b, struct pml_ast *ast,
		     struct pml_locator *loc, int etype)
{
	struct pml_variable *var = loc->u.varref;
	ulong addr;
	struct pml_function *func;
	int belowbp;

	abort_unless(loc->pkt == NULL && loc->idx == NULL);

	if ((var->vtype == PML_VTYPE_PARAM) ||
	    (var->vtype == PML_VTYPE_LOCAL)) {

		abort_unless(etype == PML_ETYPE_SCALAR);
		addr = lvaraddr(var);
		func = var->func;
		belowbp = (var->vtype == PML_VTYPE_PARAM);

		if (func != NULL && PML_FUNC_IS_INTRINSIC(func)) {
			fprintf(stderr, "can't generate varref code for"
					"an intrinsic function (%s)\n",
				func->name);
			return -1;
		} 
		
		EMIT_XW(b, LDBPI, belowbp, addr);

	} else if (var->vtype == PML_VTYPE_GLOBAL) {

		if (var->etype == PML_ETYPE_SCALAR) {
			abort_unless(loc->off == NULL && loc->len == NULL);
			EMIT_XYW(b, LDI, var->width, PML_SEG_RWMEM, var->addr);
		} else {
			if (cg_memref(b, ast, loc) < 0)
				return -1;
			if (typecast(b, loc->etype, etype) < 0)
				return -1;
		}

	} else {
		fprintf(stderr, "Unsupported variable type: %d\n", var->vtype);
		return -1;
	}

	return 0;
}


static int cg_pfref(struct pml_ibuf *b, struct pml_ast *ast,
		    struct pml_locator *loc, int etype)
{
	struct ns_elem *nse = loc->u.nsref;

	if (loc->rpfld != PML_RPF_NONE) {
		return cg_rpf(b, ast, loc, etype);
	} else if ((nse->type == NST_PKTFLD) && NSF_IS_INBITS(nse->flags)) {
		return cg_pfbitfield(b, ast, loc);
	} else {
		abort_unless(nse->type == NST_PKTFLD);
		return cg_pfbytefield(b, ast, loc, etype);
	}

	return 0;
}


static int cg_litref(struct pml_ibuf *b, struct pml_ast *ast, 
		    struct pml_locator *loc, int etype)
{
	struct pml_literal *lit = loc->u.litref;

	abort_unless(loc->pkt == NULL && loc->idx == NULL);

	if (lit->etype == PML_ETYPE_SCALAR) {
		abort_unless(loc->pkt == NULL && loc->idx == NULL);
		return cg_scalar(b, lit);
	}

	if (cg_memref(b, ast, loc) , 0)
		return -1;

	if (typecast(b, loc->etype, etype) < 0)
		return -1;

	return 0;
}


/* generate code for a locator with a final type of etype */
static int cg_locator(struct pml_ibuf *b, struct pml_ast *ast, 
		      struct pml_locator *loc, int etype)
{
	switch (loc->reftype) {
	case PML_REF_VAR:
		return cg_varref(b, ast, loc, etype);
	case PML_REF_PKTFLD:
		return cg_pfref(b, ast, loc, etype);
	case PML_REF_LITERAL:
		return cg_litref(b, ast, loc, etype);
	default:
		fprintf(stderr, "unresolved locator '%s'\n", loc->name);
		return -1;
	}
}


static int cg_locaddr(struct pml_ibuf *b, struct pml_ast *ast,
		      struct pml_locator *loc)
{
	uint64_t addr;
	struct pml_literal *lit;
	struct pml_variable *var;
	struct cg_pdesc cgpd;

	switch (loc->reftype) {
	case PML_REF_VAR:
		var = loc->u.varref;
		if ((var->vtype == PML_VTYPE_PARAM) ||
		    (var->vtype == PML_VTYPE_LOCAL)) {
			addr = lvaraddr(var);
		} else {
			abort_unless(var->vtype == PML_VTYPE_GLOBAL);
			addr = var->addr;
		}
		PUSH64(b, addr);
		break;

	case PML_REF_PKTFLD:
		cgpd_init2(&cgpd, NETVM_OC_LDPF, 0, loc);
		if (cg_pdop(b, ast, &cgpd) < 0)
			return -1;
		break;

	case PML_REF_LITERAL:
		lit = loc->u.litref;
		abort_unless((lit->type == PMLTT_BYTESTR) ||
			     (lit->type == PMLTT_MASKVAL));
		addr = MEMADDR(lit->u.bytestr.addr, lit->u.bytestr.segnum);
		PUSH64(b, addr);
		break;

	default:
		abort_unless(0);
	}

	return 0;
}


static int w_expr_pre(union pml_node *n, void *auxp, void *xstk)
{
	struct cgeaux *ea = auxp;
	struct cgestk *es = xstk;
	struct pml_op *op;

	/* save the expected type */
	es->etype = ea->etype;
	ea->etype = PML_ETYPE_UNKNOWN;

	switch (n->base.type) {
	case PMLTT_BINOP:
		op = &n->op;
		/* TODO: optimize for constant on RHS or on LHS of */
		/* commutative operation. */
		switch (op->op) {
		case PMLOP_MATCH:
		case PMLOP_NOTMATCH:
		case PMLOP_REXMATCH:
		case PMLOP_NOTREXMATCH:
			ea->etype = PML_ETYPE_BYTESTR;
			break;
		default:
			/* coerce non-mask expressions to scalars */
			ea->etype = PML_ETYPE_SCALAR;
			break;
		}
		break;

	case PMLTT_UNOP:
		ea->etype = PML_ETYPE_SCALAR;
		break;

	case PMLTT_CALL:
		abort_unless(es->etype == PML_ETYPE_SCALAR ||
			     es->etype == PML_ETYPE_VOID ||
			     es->etype == PML_ETYPE_UNKNOWN);
		/* prune walk for calls:  cg_call will walk subfields */
		if (cg_call(ea->ibuf, ea->ast, &n->call, es->etype) < 0)
			return -1;
		return 1;

	case PMLTT_LOCATOR:
		/* prune walk for locators:  cg_locator will walk its own */
		/* sub-fields as needed.  */
		if (cg_locator(ea->ibuf, ea->ast, &n->locator, es->etype) < 0)
			return -1;
		return 1;

	case PMLTT_LOCADDR:
		if (cg_locaddr(ea->ibuf, ea->ast, &n->locator) < 0)
			return -1;
		/* prune walk for locators:  no need to walk subfields */
		return 1;

	default:
		break;
	}	

	return 0;
}


static int w_expr_in(union pml_node *n, void *auxp, void *xstk)
{
	struct cgeaux *ea = auxp;
	struct pml_ibuf *b = ea->ibuf;
	struct pml_op *op;
	struct cgestk *es = xstk;

	switch (n->base.type) {
	case PMLTT_BINOP:
		op = &n->op;
		if (op->op == PMLOP_OR) {
			EMIT_W(b, BZI, 3);
			EMIT_W(b, PUSH, 1);
			es->iaddr = nexti(b);
			EMIT_W(b, BRI, 0); /* fill in during post */
		} else if (op->op == PMLOP_AND) { 
			EMIT_W(b, BNZI, 3);
			EMIT_W(b, PUSH, 0);
			es->iaddr = nexti(b);
			EMIT_W(b, BRI, 0); /* fill in during post */
		}
		/* TODO: handle regular expressions as a type here */
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
	struct pml_ibuf *b = ea->ibuf;

	switch (n->base.type) {
	case PMLTT_SCALAR:
		rv = cg_scalar(b, &n->literal);
		break;
	case PMLTT_BYTESTR:
		/* a byte string in an expression walk can only be for a */
		/* operation of some sort which requires the length */
		rv = cg_bytestr(b, &n->literal, 1);
		break;
	case PMLTT_MASKVAL:
		rv = cg_maskval(b, &n->literal);
		break;
	case PMLTT_BINOP:
	case PMLTT_UNOP:
		rv = cg_op(b, &n->op, es);
		break;
	case PMLTT_CALL:
	case PMLTT_LOCADDR:
	case PMLTT_LOCATOR:
	default:
		abort_unless(0);
		break;
	}

	if (rv >= 0)
		rv = typecast(b, n->expr.etype, es->etype);

	return rv;
}


int cg_expr(struct pml_ibuf *b, struct pml_ast *ast, union pml_node *n,
	    int etype)
{
	struct cgeaux ea = { b, ast, etype };
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
	struct pml_ast *ast = cg->ast;
	struct netvm_inst *inst;
	uint bra;

	if (cg_expr(b, ast, (union pml_node *)ifstmt->test,
		    PML_ETYPE_SCALAR) < 0)
		return -1;

	bra = nexti(b);
	EMIT_W(b, BZI, 0);

	if (cg_stmt(cg, (union pml_node *)ifstmt->tbody) < 0)
		return -1;

	if (ifstmt->fbody != NULL) {
		/* skip the next instruction we will emit */
		inst = b->inst + bra;
		inst->w = nexti(b) - bra + 1;

		bra = nexti(b);
		EMIT_W(b, BRI, 0);

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


static uint8_t retlen(struct pml_function *f)
{
	if (f->rtype == PML_ETYPE_SCALAR) {
		return 1;
	} else if (f->rtype == PML_ETYPE_VOID) {
		return 0;
	} else {
		abort_unless(0);
		return 255;
	}
}


static int cg_cfmod(struct pmlncg *cg, struct pml_cfmod *cfm)
{
	struct pml_ibuf *b = &cg->ibuf;
	union pml_node *n;

	switch (cfm->cftype) {
	case PML_CFM_RETURN:
		abort_unless(cg->curfunc != NULL);
		n = (union pml_node *)cfm->expr;
		if (cg_expr(b, cg->ast, n, PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_XW(b, RET, retlen(cg->curfunc), cg->curfunc->arity);
		break;
	case PML_CFM_BREAK:
		EMIT_W(b, BRI, 0);
		if (pcg_save_break(cg) < 0)
			return -1;
		break;
	case PML_CFM_CONTINUE:
		EMIT_W(b, BRI, 0);
		if (pcg_save_continue(cg) < 0)
			return -1;
		break;
	case PML_CFM_NEXTRULE:
		EMIT_W(b, BRI, 0);
		if (pcg_save_nextrule(cg) < 0)
			return -1;
		break;
	case PML_CFM_SENDPKT:
		EMIT_W(b, PUSH, 1);
		EMIT_NULL(b, HALT);
		break;
	case PML_CFM_DROP:
		EMIT_W(b, PUSH, 0);
		EMIT_NULL(b, HALT);
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
	if (cg_expr(b, cg->ast, n, PML_ETYPE_SCALAR) < 0)
		return -1;
	tbraddr = nexti(b);
	EMIT_W(b, BZI, 0);

	/* generate the loop body */
	n = (union pml_node *)loop->body;
	if (cg_stmt(cg, n) < 0)
		return -1;

	/* branch back to test */
	endaddr = nexti(b);
	EMIT_W(b, BRI, (ulong)testaddr - endaddr);
	++endaddr;

	/* resolve branch past body */
	inst = b->inst + tbraddr;
	inst->w = (ulong)endaddr - tbraddr;

	/* resolve breaks and continues */
	pcg_resolve_breaks(cg, nb, endaddr);
	pcg_resolve_continues(cg, nc, testaddr);

	cg->curloop = loop;
	return 0;
}


int cg_assign_scalar_var(struct pmlncg *cg, struct pml_assign *a)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct pml_variable *var = a->loc->u.varref;

	if (cg_expr(b, cg->ast, (union pml_node *)a->expr,
		    PML_ETYPE_SCALAR) < 0)
		return -1;

	if (var->vtype == PML_VTYPE_LOCAL) {
		EMIT_XW(b, STBPI, 0, lvaraddr(var));
	} else {
		abort_unless(var->vtype == PML_VTYPE_PARAM);
		EMIT_XW(b, STBPI, 1, lvaraddr(var));
	}

	return 0;
}


int cg_assign_bytestr_var(struct pmlncg *cg, struct pml_assign *a)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct pml_locator *loc = a->loc;
	struct pml_variable *var = loc->u.varref;
	int etype = a->expr->expr.etype;
	uint64_t vlen;

	if (cg_expr(b, cg->ast, (union pml_node *)a->expr, etype) < 0)
		return -1;

	if (etype == PML_ETYPE_SCALAR) {
		if (loc->off == NULL && loc->len == NULL &&
		    var->addr <= 0xFFFFFFFFul) {
			vlen = var->width;
			if (vlen > 8)
				vlen = 8;
			EMIT_XYW(b, STI, vlen, PML_SEG_RWMEM, var->addr);
			return 0;
		} 
		PUSH64(b, 8);
	} else if (etype == PML_ETYPE_MASKVAL) {
		if (typecast(b, PML_ETYPE_BYTESTR, etype) < 0)
			return -1;
	}

	if (cg_memref(b, cg->ast, loc) < 0)
		return -1;

	if (etype == PML_ETYPE_SCALAR) {
		EMIT_NULL(b, ST);
	} else {
		EMIT_XW(b, SWAP, 1, 2);
		EMIT_NULL(b, UMIN);
		EMIT_NULL(b, MOVE);
	}

	return 0;
}


static int pfref_check_fixed(struct pml_locator *loc, struct pml_ast *ast,
			     uint64_t *outlen)
{
	uint64_t v, len, off;
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
		if (pml_lit_val64(ast, lit, &v) < 0) {
			fprintf(stderr, "error reading literal packet "
					"for locator '%s'\n",
				loc->name);
			return -1;
		}
		if (v > NETVM_PD_PKT_MASK)
			return 0;
	}
	if (loc->idx != NULL) {
		if (!PML_EXPR_IS_LITERAL(loc->idx))
			return 0;
		lit = &loc->idx->literal;
		if (pml_lit_val64(ast, lit, &v) < 0) {
			fprintf(stderr, "error reading literal index "
					"for locator '%s'\n",
				loc->name);
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
		if (pml_lit_val64(ast, lit, &off) < 0) {
			fprintf(stderr, "error reading literal offset "
					"for locator '%s'\n",
				loc->name);
			return -1;
		}
		if (off > NETVM_PD_IDX_MASK)
			return 0;
		if (off >= len) {
			fprintf(stderr,
				"offset out of range for field '%s':"
				" %llu >= %llu\n", loc->name,
				(ullong)off, (ullong)len);
			return -1;
		}
		len -= off;
	}
	if (loc->len != NULL) {
		if (!PML_EXPR_IS_LITERAL(loc->len))
			return 0;
		lit = &loc->len->literal;
		if (pml_lit_val64(ast, lit, &v) < 0) {
			fprintf(stderr, "error reading literal length "
					"for locator '%s'\n",
				loc->name);
			return -1;
		}
		if (v > NETVM_PD_IDX_MASK)
			return 0;
		if (v > len) {
			fprintf(stderr,
				"length out of range for field '%s'"
				" with offset %llu: %llu >= %llu\n",
				loc->name, (ullong)off, (ullong)v,
				(ullong)len);
			return -1;
		}
		len = v;
	}

	if (outlen != NULL)
		*outlen = len;

	return 1;
}


int cg_assign_pktfld(struct pmlncg *cg, struct pml_assign *a)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct pml_locator *loc = a->loc;
	int etype = a->expr->expr.etype;
	int rv;
	struct cg_pdesc cgpd;
	uint64_t flen;

	if (cg_expr(b, cg->ast, (union pml_node *)a->expr, etype) < 0)
		return -1;

	if (etype == PML_ETYPE_SCALAR) {
		rv = pfref_check_fixed(loc, cg->ast, &flen);
		if (rv < 0) {
			return -1;
		} else if (rv > 0) {
			if (flen > sizeof(uint64_t))
				flen = sizeof(uint64_t);
			cgpd_init2(&cgpd, NETVM_OC_STPD, flen , loc);
			if (cg_pdop(b, cg->ast, &cgpd) < 0)
				return -1;
			return 0;
		} 
	} else if (etype == PML_ETYPE_MASKVAL) {
		if (typecast(b, PML_ETYPE_BYTESTR, etype) < 0)
			return -1;
		etype = PML_ETYPE_BYTESTR;
	}

	cgpd_init2(&cgpd, NETVM_OC_LDPF, 1, loc);
	if (cg_pdop(b, cg->ast, &cgpd) < 0)
		return -1;
	if (cg_loclen(b, cg->ast, loc) < 0)
		return -1;

	if (etype == PML_ETYPE_SCALAR) {
		EMIT_NULL(b, ST);
	} else {
		EMIT_XW(b, SWAP, 1, 2);
		EMIT_NULL(b, UMIN);
		EMIT_NULL(b, MOVE);
	}

	return 0;
}


int cg_assign(struct pmlncg *cg, struct pml_assign *a)
{
	struct pml_locator *loc = a->loc;
	struct pml_variable *var;

	if (loc->reftype == PML_REF_VAR) {
		var = loc->u.varref;
		if (var->vtype == PML_VTYPE_LOCAL ||
		    var->vtype == PML_VTYPE_PARAM) {
			return cg_assign_scalar_var(cg, a);
		} else {
			return cg_assign_bytestr_var(cg, a);
		}
	} else {
		return cg_assign_pktfld(cg, a);
	}

	return 0;
}


int cg_print(struct pmlncg *cg, struct pml_print *pr)
{
	struct pml_ibuf *b = &cg->ibuf;
	struct list *arglist;
	
	abort_unless(pr->args);

	arglist = &pr->args->list;
	if (!l_isempty(arglist))
		UNIMPL(cg_argument_print);

	PUSH64(b, MEMADDR(pr->fmt.addr, pr->fmt.segnum));
	PUSH64(b, pr->fmt.len);
	EMIT_XY(b, CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRSTR);

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
			fprintf(stderr, "cg_stmt(): unknown statement type %d\n",
				n->base.type);
			return -1;
		}
		if (cg_expr(&cg->ibuf, cg->ast, n, PML_ETYPE_VOID) < 0)
			return -1;
	}

	return 0;
}


static int cg_func(struct pmlncg *cg, struct pml_function *f)
{
	struct pml_ibuf *b = &cg->ibuf;
	ulong vlen;
	int rl;

	abort_unless(cg->curfunc == NULL);
	cg->curfunc = f;

	/* XXX TODO:  this really doesn't belong in the AST does it? */
	f->addr = nexti(b);

	if (f->vstksz > 0) {
		abort_unless(f->vstksz % 8 == 0);
		vlen = f->vstksz / 8;
		EMIT_W(b, ZPUSH, vlen);
	}

	if (cg_stmt(cg, f->body) < 0)
		return -1;

	rl = retlen(f);
	if (retlen > 0) {
		/* XXX just to be safe */
		EMIT_W(b, PUSH, 0);
	}
	EMIT_XW(b, RET, rl, f->arity);

	cg->curfunc = NULL;
	return 0;
}


static int cg_funcs(struct pmlncg *cg)
{
	struct pml_function *f;
	struct list *flist, *n;
	flist = &cg->ast->funcs.list;

	l_for_each(n, flist) {
		f = (struct pml_function *)l_to_node(n);
		if (!PML_FUNC_IS_INTRINSIC(f) && !PML_FUNC_IS_INLINE(f)) {
			if (cg_func(cg, f) < 0)
				return -1;
		}
	}

	return 0;
}


static int cg_be(struct pmlncg *cg)
{
	struct pml_rule *r;
	ulong nvars;

	if (cg->ast->b_rule != NULL) {
		cg->prog->eps[NVMP_EP_START] = nexti(&cg->ibuf);
		r = cg->ast->b_rule;
		nvars = r->vars.addr_rw2;
		if (nvars > 0)
			EMIT_W(&cg->ibuf, ZPUSH, nvars);
		if (cg_stmt(cg, (union pml_node *)r->stmts) < 0)
			return -1;
		EMIT_NULL(&cg->ibuf, HALT);
	}

	if (cg->ast->e_rule != NULL) {
		cg->prog->eps[NVMP_EP_END] = nexti(&cg->ibuf);
		r = cg->ast->e_rule;
		nvars = r->vars.addr_rw2;
		if (nvars > 0)
			EMIT_W(&cg->ibuf, ZPUSH, nvars);
		if (cg_stmt(cg, (union pml_node *)r->stmts) < 0)
			return -1;
		EMIT_NULL(&cg->ibuf, HALT);
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
	uint tbaddr;
	ulong nvars;

	if (l_isempty(&cg->ast->p_rules))
		return 0;

	cg->prog->eps[NVMP_EP_PACKET] = nexti(&cg->ibuf);

	l_for_each(n, &cg->ast->p_rules) {
		r = (struct pml_rule *)l_to_node(n);
		pat = (union pml_node *)r->pattern;
		nvars = r->vars.addr_rw2;

		if (pat != NULL) {
			if (cg_expr(b, cg->ast, pat, PML_ETYPE_SCALAR) < 0)
				return -1;
			tbaddr = nexti(b);
			EMIT_W(b, BZI, 0);
		}

		if (nvars > 0)
			EMIT_W(&cg->ibuf, ZPUSH, nvars);

		if (cg_stmt(cg, (union pml_node *)r->stmts) < 0)
			return -1;

		if (nvars > 0)
			EMIT_W(&cg->ibuf, POP, nvars);

		eaddr = nexti(&cg->ibuf);
		if (pat != NULL) {
			inst = b->inst + tbaddr;
			inst->w = eaddr - tbaddr;
		}

		pcg_resolve_nextrules(cg, eaddr);
	}

	EMIT_W(&cg->ibuf, PUSH, 1);
	EMIT_NULL(&cg->ibuf, HALT);

	return 0;
}


static void clearcg(struct pmlncg *cg, int copied, int clearall)
{
	struct netvm_meminit *inits;

	abort_unless(cg);

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


int pml_to_nvmp(struct pml_ast *ast, struct netvm_program *prog, int copy)
{
	struct pmlncg cg;
	struct netvm_meminit *inits;
	int esave;

	if (!ast || !prog || prog->inits != NULL || prog->inst != NULL) {
		errno = EINVAL;
		return -1;
	}

	inits = calloc(sizeof(struct netvm_meminit), PMLCG_MI_NUM);
	if (inits == NULL)
		return -1;

	cg.ast = ast;
	cg.prog = prog;
	pib_init(&cg.ibuf);
	dyb_init(&cg.breaks, NULL);
	dyb_init(&cg.continues, NULL);
	dyb_init(&cg.nextrules, NULL);
	cg.curfunc = NULL;
	cg.curloop = NULL;

	prog->inits = inits;
	prog->ninits = 0;
	prog->matchonly = 0;
	prog->eps[NVMP_EP_START] = NVMP_EP_INVALID;
	prog->eps[NVMP_EP_PACKET] = NVMP_EP_INVALID;
	prog->eps[NVMP_EP_END] = NVMP_EP_INVALID;

	if (copy_meminits(ast, prog, copy) < 0)
		goto err;

	init_segs(&cg);

	init_coproc(&cg);

	if (cg_funcs(&cg) < 0)
		goto err;

	if (cg_be(&cg) < 0)
		goto err;

	if (cg_rules(&cg) < 0)
		goto err;

	/* if we got to here we are good to go! */

	/* clean up memory if this was a destructive transformation */
	if (copy) {
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
	esave = errno;
	clearcg(&cg, copy, 1);
	errno = esave;
	return -1;
}
