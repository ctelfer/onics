#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <cat/cat.h>

#include "pmlncg.h"
#include "netvm_std_coproc.h"

#define l_to_node(p) (union pml_node *)container(p, struct pml_node_base, ln)

int cgexpr(struct pml_ibuf *b, struct pml_ast *ast, union pml_node *n,
	   int etype);

struct cgeaux {
	struct pml_ibuf *	ibuf;
	struct pml_ast *	ast;
	int			etype;
};

struct cgestk {
	uint			etype;
	uint			iaddr;
};


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
			if (b->size > (maxsize >> 2))
				return -1;
			sz = b->size << 2;
		}
		inst = realloc(b->inst, sz * sizeof(struct netvm_inst));
		if (inst == NULL)
			return -1;
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
#define EMIT_W(_ibuf, SYM, _w) EMIT_XYZW(_ibuf, SYM, 0, 0, 0, _w)
#define EMIT_XW(_ibuf, SYM, _x, _w) EMIT_XYZW(_ibuf, SYM, _x, 0, 0, _w)


#define UNIMPL(s)							\
	do {								\
		fprintf(stderr, "unimplemented operation" #s "\n"); 	\
		return -1;						\
	} while (0)




static struct pml_nvm_code *newcode(union pml_node *pmln)
{
	struct pml_nvm_code *c;
	struct pml_node_base *n;
	int i;

	abort_unless(pmln && pmln->base.aux == NULL);
	n = &pmln->base;

	c = malloc(sizeof(c));
	if (c == NULL)
		return NULL;

	c->node = pmln;
	n->aux = c;

	for (i = 0; i < PNC_MAX_PIBS; ++i)
		pib_init(&c->pib[i]);

	return c;
}


static void freecode(union pml_node *pmln)
{
	struct pml_nvm_code *c;
	int i;

	abort_unless(pmln);
	c = pmln->base.aux;

	if (c != NULL) {
		c->node = NULL;
		for (i = 0; i < PNC_MAX_PIBS; ++i)
			pib_clear(&c->pib[i]);
		pmln->base.aux = NULL;
	}
}


static int copy_meminits(struct pml_ast *ast, struct netvm_meminit *inits,
		         int copy)
{
	struct pml_symtab *st;
	struct dynbuf tb;
	int esave;

	abort_unless(ast->mi_bufs[PML_SEG_ROMEM].off == 0);
	abort_unless(ast->mi_bufs[PML_SEG_RWMEM].off == 0);

	dyb_init(&tb, NULL);

	inits[0].segnum = PML_SEG_ROMEM;
	inits[0].off = 0;
	inits[0].val.len = ast->mi_bufs[PML_SEG_ROMEM].len;
	if (copy) {
		if (dyb_copy(&tb, &ast->mi_bufs[PML_SEG_ROMEM]) < 0)
			return -1;
		inits[0].val.data = dyb_release(&tb);
	} else {
		inits[0].val.data = ast->mi_bufs[PML_SEG_ROMEM].data;
	}

	inits[1].segnum = PML_SEG_RWMEM;
	inits[1].off = 0;
	inits[1].val.len = ast->mi_bufs[PML_SEG_RWMEM].len;
	if (copy) {
		if (dyb_copy(&tb, &ast->mi_bufs[PML_SEG_RWMEM]) < 0) {
			esave = errno;
			free(inits[0].val.data);
			errno = esave;
			return -1;
		}
		inits[1].val.data = dyb_release(&tb);
	} else {
		inits[1].val.data = ast->mi_bufs[PML_SEG_RWMEM].data;
	}

	st = &ast->vars;
	inits[2].segnum = PML_SEG_RWMEM;
	inits[2].off = st->addr_rw1;
	inits[2].val.len = st->addr_rw2 - st->addr_rw1;
	inits[2].val.data = NULL;

	return 0;
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
	sd->perms = NETVM_SEG_RD;
	
	sd = &prog->sdescs[PML_SEG_RWMEM];
	sd->len = ast->vars.addr_rw2;
	sd->perms = NETVM_SEG_RD|NETVM_SEG_WR;
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


/* 
 * Instructions:
 *  + nxtpkt
 *    pushi 1
 *    halt
 *  + drop
 *    pushi 0
 *    halt
 */
static int init_pktact(struct pmlncg *cg)
{
	EMIT_W(&cg->ibuf, PUSH, 1);
	EMIT_NULL(&cg->ibuf, HALT);
	EMIT_W(&cg->ibuf, PUSH, 0);
	EMIT_NULL(&cg->ibuf, HALT);

	cg->nxtpaddr = 0;
	cg->dropaddr = 2;
	return 0;
}


static uint nexti(struct pml_ibuf *b)
{
	abort_unless(b);
	return b->ninst;
}


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


static int cgscalar(struct pml_ibuf *b, struct pml_literal *l)
{
	abort_unless(b && l);
	return push64(b, l->u.scalar);
}


static int cgbytestr(struct pml_ibuf *b, struct pml_literal *l, int withlen)
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


static int cgmaskval(struct pml_ibuf *b, struct pml_literal *l)
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
	EMIT_W(b, DUP, 0);	 /* dup len */
	EMIT_XW(b, SWAP, 0, 3);	 /* swap with val addr */
	EMIT_XW(b, SWAP, 0, 1);	 /* swap with orig len */
	EMIT_NULL(b, LDU);
	EMIT_XW(b, SWAP, 0, 2);	 /* swap with dup len */
	EMIT_NULL(b, LDU);
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
		} else {
			EMIT_NULL(b, LDU);
			return 0;
		}

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

	default:
		abort_unless(0);
	}

	return 0;
}


static int cgmatchop(struct pml_ibuf *b, struct pml_op *op)
{
	union pml_expr_u *rhs;

	abort_unless(b && op);
	rhs = op->arg2;

	if (rhs->base.type == PMLTT_BYTESTR) {
		EMIT_NULL(b, CMP);
	} else {
		abort_unless(rhs->base.type == PMLTT_MASKVAL);
		EMIT_NULL(b, MSKCMP);
	}
	if (op->op == PMLOP_NOTMATCH)
		EMIT_NULL(b, NOT);

	return 0;
}


static int cgop(struct pml_ibuf *b, struct pml_op *op, struct cgestk *es)
{
	struct netvm_inst *inst;

	switch(op->op) {

	case PMLOP_OR:
	case PMLOP_AND:
		/* patch up branch */
		abort_unless(es->iaddr < b->ninst);
		inst = b->inst + es->iaddr;
		inst->w = nexti(b);
		return 0;

	case PMLOP_MATCH:
	case PMLOP_NOTMATCH:
		return cgmatchop(b, op);

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


static int cgcall(struct pml_ibuf *b, struct pml_ast *ast, struct pml_call *c)
{
	struct list *n;
	struct pml_function *f;

	abort_unless(c->args && c->func);
	f = c->func;

	l_for_each_rev(n, &c->args->list) {
		if (cgexpr(b, ast, l_to_node(n), PML_ETYPE_SCALAR) < 0)
			return -1;
	}

	if (PML_FUNC_IS_INTRINSIC(f)) {
		UNIMPL(intrinsics);
	} else if (PML_FUNC_IS_INLINE(f)) {
		EMIT_NULL(b, PUSHFR);
		if (cgexpr(b, ast, f->body, PML_ETYPE_SCALAR) < 0)
			return -1;
		EMIT_XW(b, POPFR, 1, f->arity);
	} else {
		PUSH64(b, f->addr);
	}

	return 0;
}


struct locval {
	int			onstack;
	uint64_t		val;
};


static int cglocval(struct pml_ibuf *b, struct pml_ast *ast,
		    union pml_expr_u *e, struct locval *val)
{
	if (e == NULL) {
		val->onstack = 0;
		val->val = 0;
	} else if (!PML_EXPR_IS_LITERAL(e)) {
		val->onstack = 1;
		if (cgexpr(b, ast, (union pml_node *)e, PML_ETYPE_SCALAR) < 0)
			return -1;
	} else {
		val->onstack = 0;
		if (pml_lit_val64(ast, &e->literal, &val->val) < 0)
			return -1;
	}

	return 0;
}


static int cgmemaddr(struct pml_ibuf *b, uint64_t addr, int segnum,
		     struct locval *off)
{
	if (off->onstack) {
		PUSH64(b, addr);
		EMIT_NULL(b, ADD);
		EMIT_W(b, SHLI, 8);
		EMIT_W(b, SHRI, 8);
		if (segnum > 0) {
			EMIT_W(b, ORHI, 
			       ((segnum & NETVM_SEG_SEGMASK) 
				<< NETVM_UA_SEG_HI_OFF));
		}
	} else {
		addr += off->val & ~(0xFFllu << NETVM_UA_SEG_OFF);
		addr |= ((uint64_t)segnum & NETVM_SEG_SEGMASK) 
				<< NETVM_UA_SEG_OFF;
		PUSH64(b, addr);
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


static int cgvarref(struct pml_ibuf *b, struct pml_ast *ast,
		    struct pml_locator *loc, int etype)
{
	struct pml_variable *var = loc->u.varref;
	struct locval lv;
	ulong addr;
	struct pml_function *func;
	int belowbp;

	abort_unless(loc->pkt == NULL && loc->idx == NULL);

	if ((var->vtype == PML_VTYPE_PARAM) ||
	    (var->vtype == PML_VTYPE_LOCAL)) {
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

		/* TODO add offset and length checks */
		if (cglocval(b, ast, loc->off, &lv) < 0)
			return -1;
		if (cgmemaddr(b, var->addr, PML_SEG_RWMEM, &lv) < 0)
			return -1;

		if (loc->off != NULL) {
			abort_unless(loc->len != NULL);
			if (cglocval(b, ast, loc->len, &lv) < 0)
				return -1;
			if (!lv.onstack)
				PUSH64(b, lv.val);
		} else {
			PUSH64(b, var->width);
		}

	} else {
		fprintf(stderr, "Unsupported variable type: %d\n", var->vtype);
		return -1;
	}

	return 0;
}


/* this function assumes that ldpXi opcode is ldpX plus 1 */
/* check this to be sure.  It also assumes that the offset */
/* part of a packet descriptor is at bit 0 */
STATIC_BUG_ON(LDPFI_is_LDPF_plus_1, NETVM_OC_LDPF == NETVM_OC_LDPF + 1);
STATIC_BUG_ON(LDPDI_is_LDPD_plus_1, NETVM_OC_LDPD == NETVM_OC_LDPD + 1);
STATIC_BUG_ON(NETVM_PD_OFF_OFF_is_not_zero, NETVM_PD_OFF_OFF != 0);

static int cgldp(struct pml_ibuf *b, struct pml_ast *ast,
		 struct pml_locator *loc, uint prid, uint field,
		 int oc, byte_t x)
{
	struct locval lpkt, lidx, loff;
	struct ns_pktfld *pf = NULL;
	long toff;

	if (loc->u.nsref->type == NST_PKTFLD)
		pf = (struct ns_pktfld *)loc->u.nsref;

	if (cglocval(b, ast, loc->pkt, &lpkt) < 0)
		return -1;
	if (lpkt.onstack) {
		EMIT_W(b, ANDI, NETVM_PD_PKT_MASK);
		EMIT_W(b, SHLI, NETVM_PD_PKT_OFF);
	}

	if (cglocval(b, ast, loc->idx, &lidx) < 0)
		return -1;
	if (lidx.onstack) {
		EMIT_W(b, ANDI, NETVM_PD_IDX_MASK);
		EMIT_W(b, SHLI, NETVM_PD_IDX_OFF);
	}

	if (cglocval(b, ast, loc->off, &loff) < 0)
		return -1;
	if (loff.onstack) {
		if (pf != NULL && pf->off != 0) {
			abort_unless(!NSF_IS_INBITS(pf->flags));
			EMIT_W(b, ADDI, pf->off);
		}
		EMIT_W(b, ANDI, NETVM_PD_OFF_MASK);
	} else {
		toff = pf->off + loff.val;
	}

	if (!lpkt.onstack && !lidx.onstack && !loff.onstack &&
	    (toff <= NETVM_PPD_OFF_MASK)) {
		uint y = lpkt.val & NETVM_PPD_PKT_MASK;
		uint z = ((lidx.val & NETVM_PPD_IDX_MASK) << 
				NETVM_PPD_IDX_OFF) |
			 ((field & NETVM_PPD_FLD_MASK) <<
				NETVM_PPD_FLD_OFF);
		ulong w = ((prid & NETVM_PPD_PRID_MASK)
				<< NETVM_PPD_PRID_OFF) |
			  ((toff & NETVM_PPD_OFF_MASK)
			   	<< NETVM_PPD_OFF_OFF);


		if (pib_add_ixyzw(b, oc+1, x, y, z, w) < 0)
			return -1;
	} else {
		uint64_t spd = (((uint64_t)prid & NETVM_PD_PRID_MASK)
					<< NETVM_PD_PRID_OFF) |
			       (((uint64_t)field & NETVM_PD_FLD_MASK)
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

		if (pib_add_ixyzw(b, oc, 0, 0, 0, 0) < 0)
			return -1;
	}

	return 0;
}


static int cgrpf(struct pml_ibuf *b, struct pml_ast *ast,
		 struct pml_locator *loc, int etype)
{
	uint field;
	struct ns_namespace *ns = (struct ns_namespace *)loc->u.nsref;
	struct locval lpkt, llen;

	abort_unless(ns->type == NST_NAMESPACE);

	if (PML_RPF_IS_BYTESTR(loc->rpfld)) {
		abort_unless(loc->etype == PML_ETYPE_BYTESTR);
		field = PML_RPF_TO_NVMOFF(loc->rpfld);
	} else {
		abort_unless(loc->etype == PML_ETYPE_SCALAR);
		abort_unless(loc->off == NULL && loc->len == NULL);
		if (loc->rpfld == PML_RPF_EXISTS)
			field = NETVM_PRP_PIDX;
		else
			field = PML_RPF_TO_NVMFIELD(loc->rpfld);
	}

	if (cgldp(b, ast, loc, ns->prid, field, NETVM_OC_LDPF, 0) < 0)
		return -1;

	if (PML_RPF_IS_BYTESTR(loc->rpfld)) {
		/* now form into a UA and add length */
		if (cglocval(b, ast, loc->pkt, &lpkt) < 0)
			return -1;
		if (lpkt.onstack) {
			EMIT_W(b, ANDI, NETVM_SEG_SEGMASK);
			EMIT_W(b, ORI, NETVM_SEG_ISPKT);
			EMIT_W(b, SHLI, NETVM_UA_SEG_OFF);
			EMIT_NULL(b, OR);
		} else {
			ulong w = lpkt.val & NETVM_SEG_SEGMASK;
			w |= NETVM_SEG_ISPKT;
			w <<= NETVM_UA_SEG_HI_OFF;
			EMIT_W(b, ORHI, w);
		}

		if (cglocval(b, ast, loc->pkt, &llen) < 0)
			return -1;
		if (!lpkt.onstack)
			PUSH64(b, llen.val);
	}

	if (typecast(b, loc->etype, etype) < 0)
		return -1;

	return 0;
}


static int cgpktfld(struct pml_ibuf *b, struct pml_ast *ast,
		    struct pml_locator *loc, int etype)
{
	struct ns_elem *nse = loc->u.nsref;

	if (loc->rpfld != PML_RPF_NONE) {
		return cgrpf(b, ast, loc, etype);
	} else if ((nse->type == NST_PKTFLD) && NSF_IS_INBITS(nse->flags)) {
		abort_unless(loc->off == NULL && loc->len == NULL);
		UNIMPL(pktfld_bitfield);
	} else {
		UNIMPL(pktfld_bytefield);
	}

	return 0;
}


static int cglitref(struct pml_ibuf *b, struct pml_ast *ast, 
		    struct pml_locator *loc, int etype)
{
	struct locval lv;
	struct pml_literal *lit = loc->u.litref;

	abort_unless(loc->pkt == NULL && loc->idx == NULL);

	if (lit->etype == PML_ETYPE_SCALAR) {
		abort_unless(loc->pkt == NULL && loc->idx == NULL);
		return cgscalar(b, lit);
	}

	/* TODO add offset and length checks */
	if (cglocval(b, ast, loc->off, &lv) < 0)
		return -1;
	
	if (lit->type == PMLTT_BYTESTR) {
		struct pml_bytestr *bs = &lit->u.bytestr;
		if (cgmemaddr(b, bs->addr, bs->segnum, &lv) < 0)
			return -1;
	} else {
		struct pml_bytestr *bs = &lit->u.maskval.val;
		abort_unless(lit->type == PMLTT_MASKVAL);

		if (lv.onstack)
			EMIT_NULL(b, DUP);
		if (cgmemaddr(b, bs->addr, bs->segnum, &lv) < 0)
			return -1;
		if (lv.onstack)
			EMIT_XW(b, SWAP, 0, 1);
		bs = &lit->u.maskval.mask;
		if (cgmemaddr(b, bs->addr, bs->segnum, &lv) < 0)
			return -1;
	}

	if (loc->off != NULL) {
		abort_unless(loc->len != NULL);
		if (cglocval(b, ast, loc->len, &lv) < 0)
			return -1;
		if (!lv.onstack)
			PUSH64(b, lv.val);
	} else {
		if (lit->type == PMLTT_BYTESTR)
			PUSH64(b, lit->u.bytestr.len);
		else
			PUSH64(b, lit->u.maskval.val.len);
	}

	return 0;
}


/* generate code for a locator with a final type of etype */
static int cglocator(struct pml_ibuf *b, struct pml_ast *ast, 
		     struct pml_locator *loc, int etype)
{
	switch (loc->reftype) {
	case PML_REF_VAR:
		return cgvarref(b, ast, loc, etype);
	case PML_REF_PKTFLD:
		return cgpktfld(b, ast, loc, etype);
	case PML_REF_LITERAL:
		return cglitref(b, ast, loc, etype);
	default:
		fprintf(stderr, "unresolved locator '%s'\n", loc->name);
		return -1;
	}
}


static int cglocaddr(struct pml_ibuf *b, struct pml_ast *ast,
		     struct pml_locator *loc)
{
	uint64_t addr;
	struct pml_literal *lit;
	struct pml_variable *var;
	struct ns_pktfld *pf;
	struct ns_namespace *ns;

	switch (loc->etype) {
	case PML_REF_VAR:
		var = loc->u.varref;
		if ((var->vtype == PML_VTYPE_PARAM) ||
		    (var->vtype == PML_VTYPE_LOCAL)) {
			addr = lvaraddr(var);
		} else {
			abort_unless(var->vtype == PML_VTYPE_GLOBAL);
			addr = var->addr |
			       ((uint64_t)PML_SEG_RWMEM << NETVM_UA_SEG_OFF);
		}
		PUSH64(b, addr);
		break;

	case PML_REF_PKTFLD:
		if (loc->u.nsref->type == NST_NAMESPACE) {
			pf = (struct ns_pktfld *)loc->u.nsref;
			if (cgldp(b, ast, loc, pf->prid, 
				  NETVM_PRP_SOFF + pf->oidx,
				  NETVM_OC_LDPF, 0) < 0)
				return -1;
		} else {
			ns = (struct ns_namespace *)loc->u.nsref;
			abort_unless(PML_RPF_IS_BYTESTR(loc->rpfld));
			if (cgldp(b, ast, loc, ns->prid, 
				  PML_RPF_TO_NVMFIELD(loc->rpfld), 
				  NETVM_OC_LDPF, 0) < 0)
				return -1;
		}
		break;

	case PML_REF_LITERAL:
		lit = loc->u.litref;
		abort_unless((lit->type == PMLTT_BYTESTR) ||
			     (lit->type == PMLTT_MASKVAL));
		addr = (uint64_t)lit->u.bytestr.addr | 
		       ((uint64_t)lit->u.bytestr.segnum << NETVM_UA_SEG_OFF);
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
	struct pml_locator *loc;

	/* save the expected type */
	es->etype = ea->etype;
	
	ea->etype = PML_ETYPE_UNKNOWN;
	switch (n->base.type) {
	case PMLTT_BINOP:
		op = (struct pml_op *)n;
		/* TODO: optimize for constant on RHS or on LHS of */
		/* commutative operation. */
		switch (op->op) {
		case PMLOP_MATCH:
		case PMLOP_NOTMATCH:
		case PMLOP_REXMATCH:
		case PMLOP_NOTREXMATCH:
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

	case PMLTT_LOCATOR:
		loc = (struct pml_locator *)n;
		/* prune walk for locators:  cglocator will walk it's own */
		/* sub-fields as needed.  */
		if (cglocator(ea->ibuf, ea->ast, loc, es->etype) < 0)
			return -1;
		return 1;

	case PMLTT_LOCADDR:
		loc = (struct pml_locator *)n;
		if (cglocaddr(ea->ibuf, ea->ast, loc) < 0)
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
			EMIT_W(b, PUSH, 1);
			es->iaddr = nexti(b);
			EMIT_W(b, BRI, 0); /* fill in during post */
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
		rv = cgscalar(b, &n->literal);
		break;
	case PMLTT_BYTESTR:
		/* a byte string in an expression walk can only be for a */
		/* operation of some sort which requires the length */
		rv = cgbytestr(b, &n->literal, 1);
		break;
	case PMLTT_MASKVAL:
		rv = cgmaskval(b, &n->literal);
		break;
	case PMLTT_BINOP:
	case PMLTT_UNOP:
		rv = cgop(b, &n->op, es);
		break;
	case PMLTT_CALL:
		rv = cgcall(b, ea->ast, &n->call);
		break;
	case PMLTT_LOCADDR:
	case PMLTT_LOCATOR:
	default:
		abort_unless(0);
		break;
	}

	if (rv >= 0)
		rv = typecast(b, ((struct pml_expr_base *)n)->etype, es->etype);

	return rv;
}


int cgexpr(struct pml_ibuf *b, struct pml_ast *ast, union pml_node *n,
	   int etype)
{
	struct cgeaux ea = { b, ast, etype };
	return pmln_walk(n, &ea, w_expr_pre, w_expr_in, w_expr_post);
}


int clearaux(union pml_node *node, void *ctx, void *xstk)
{
	freecode(node);
	return 0;
}


static int cgfunc(struct pmlncg *cg)
{
	/* TODO: add code to generate functions */
	return 0;
}


static int cgbe(struct pmlncg *cg)
{
	/* TODO: add code to generate BEGIN & END segments */

	/* DUMMY CODE */
	cg->prog->eps[NVMP_EP_START] = nexti(&cg->ibuf);
	EMIT_W(&cg->ibuf, PUSH, 0xdeadbeef);
	EMIT_NULL(&cg->ibuf, HALT);

	return 0;
}


static int cgrules(struct pmlncg *cg)
{
	/* TODO: add code to generate rules */
	return 0;
}


static void clearcg(struct pmlncg *cg, int copied, int clearall)
{
	struct netvm_meminit *inits;

	abort_unless(cg);

	dyb_clear(&cg->brks);
	dyb_clear(&cg->conts);
	dyb_clear(&cg->nxtrules);

	pml_ast_walk(cg->ast, cg, clearaux, NULL, NULL);

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
	dyb_init(&cg.brks, NULL);
	dyb_init(&cg.conts, NULL);
	dyb_init(&cg.nxtrules, NULL);

	prog->inits = inits;
	prog->ninits = PMLCG_MI_NUM;
	prog->matchonly = 0;
	prog->eps[NVMP_EP_START] = NVMP_EP_INVALID;
	prog->eps[NVMP_EP_PACKET] = NVMP_EP_INVALID;
	prog->eps[NVMP_EP_END] = NVMP_EP_INVALID;

	if (copy_meminits(ast, inits, copy) < 0)
		goto err;

	init_segs(&cg);

	init_coproc(&cg);

	if (init_pktact(&cg) < 0)
		goto err;

	if (cgfunc(&cg) < 0)
		goto err;

	if (cgbe(&cg) < 0)
		goto err;

	if (cgrules(&cg < 0))
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
