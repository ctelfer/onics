#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <cat/cat.h>

#include "pmlncg.h"
#include "netvm_std_coproc.h"

#define l_to_node(p) (union pml_node *)container(p, struct pml_node_base, ln)

int cgexpr(struct pml_ibuf *b, union pml_node *n);


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
#define EMIT_NULL(_ibuf, SYM) 						    \
	do { 		   						    \
		if (pib_add_ixyzw(_ibuf, NETVM_OC_##SYM,0,0,0,0) < 0)	    \
			return -1;					    \
	} while (0);

#define EMIT_W(_ibuf, SYM, w) 						    \
	do { 		   						    \
		if (pib_add_ixyzw(_ibuf, NETVM_OC_##SYM,0,0,0,w) < 0)	    \
			return -1;					    \
	} while (0);

#define EMIT_XYZW(_ibuf, SYM, x, y, z, w) 				    \
	do { 		   						    \
		if (pib_add_ixyzw(_ibuf, NETVM_OC_##SYM,x,y,z,w) < 0)	    \
			return -1;					    \
	} while (0);


#define UNIMPL(s)							\
	do {								\
		fprintf(stderr, "unimplemented operation" #s "\n"); 	\
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


static int cgscalar(struct pml_ibuf *b, struct pml_literal *l)
{
	return push64(b, l->u.scalar);
}


static int cgbytestr(struct pml_ibuf *b, struct pml_literal *l, int withlen)
{
	struct pml_bytestr *v = &l->u.bytestr;
	if (push64(b, v->addr) < 0)
		return -1;
	if (v->segnum != 0)
		EMIT_W(b, ORHI, (v->segnum << 24));
	if (withlen) {
		if (push64(b, v->len) < 0)
			return -1;
	}
	return 0;
}


static int cgmaskval(struct pml_ibuf *b, struct pml_literal *l)
{
	struct pml_bytestr *v = &l->u.maskval.val;
	struct pml_bytestr *m = &l->u.maskval.mask;
	if (push64(b, v->addr) < 0)
		return -1;
	if (v->segnum != 0)
		EMIT_W(b, ORHI, (v->segnum << 24));
	if (push64(b, m->addr) < 0)
		return -1;
	if (v->segnum != 0)
		EMIT_W(b, ORHI, (m->segnum << 24));
	if (push64(b, m->len) < 0)
		return -1;
	return 0;
}


static int cgop(struct pml_ibuf *b, struct pml_op *op, void *xstk)
{
	uint *iaddr;
	struct netvm_inst *inst;

	switch(op->op) {

	case PMLOP_OR:
	case PMLOP_AND:
		/* patch up branch */
		iaddr = xstk;
		abort_unless(*iaddr < b->ninst);
		inst = b->inst + *iaddr;
		inst->w = nexti(b);
		return 0;

	case PMLOP_MATCH:
	case PMLOP_NOTMATCH:
		UNIMPL(match);
		break;

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


static int cgcall(struct pml_ibuf *b, struct pml_call *c)
{
	struct list *n;
	struct pml_function *f;

	abort_unless(c->args && c->func);
	f = c->func;

	l_for_each_rev(n, &c->args->list) {
		if (cgexpr(b, l_to_node(n)) < 0)
			return -1;
	}

	if (PML_FUNC_IS_INTRINSIC(f)) {
		UNIMPL(intrinsics);
	} else if (PML_FUNC_IS_INLINE(f)) {
		EMIT_NULL(b, PUSHFR);
		if (cgexpr(b, f->body) < 0)
			return -1;
		EMIT_XYZW(b, POPFR, 1, 0, 0, f->arity);
	} else {
		if (push64(b, f->addr) < 0)
			return -1;
	}

	return 0;
}


static int w_expr_post(union pml_node *n, void *bp, void *xstk)
{
	struct pml_ibuf *b = bp;
	switch (n->base.type) {
	case PMLTT_SCALAR:
		return cgscalar(b, &n->literal);
	case PMLTT_BYTESTR:
		/* a byte string in an expression walk can only be for a */
		/* operation of some sort which requires the length */
		return cgbytestr(b, &n->literal, 1);
	case PMLTT_MASKVAL:
		return cgmaskval(b, &n->literal);
	case PMLTT_BINOP:
	case PMLTT_UNOP:
		return cgop(b, &n->op, xstk);
	case PMLTT_CALL:
		return cgcall(b, &n->call);
	case PMLTT_LOCATOR:
		UNIMPL(locator);
	case PMLTT_LOCADDR:
		UNIMPL(locaddr);
	default:
		abort_unless(0);
		break;
	}

	return 0;
}

static int w_expr_in(union pml_node *n, void *bp, void *xstk)
{
	struct pml_ibuf *b = bp;
	struct pml_op *op;
	uint *iaddr = xstk;

	switch (n->base.type) {
	case PMLTT_BINOP:
		op = &n->op;
		if (op->op == PMLOP_OR) {
			EMIT_W(b, BZI, 3);
			EMIT_W(b, PUSH, 1);
			*iaddr = nexti(b);
			EMIT_W(b, BRI, 0); /* fill in during post */
		} else if (op->op == PMLOP_AND) { 
			EMIT_W(b, BNZI, 3);
			EMIT_W(b, PUSH, 1);
			*iaddr = nexti(b);
			EMIT_W(b, BRI, 0); /* fill in during post */
		}
		break;

		/* TODO: optimize for constant on RHS or on LHS of */
		/* commutative operation. */
	}

	return 0;
}


int cgexpr(struct pml_ibuf *b, union pml_node *n)
{
	return pmln_walk(n, b, NULL, w_expr_in, w_expr_post);
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
