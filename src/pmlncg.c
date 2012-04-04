#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <cat/cat.h>

#include "pmlncg.h"
#include "netvm_std_coproc.h"


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
#define EMIT_NULL(cg, SYM) 						    \
	do { 		   						    \
		if (pib_add_ixyzw(&(cg)->ibuf, NETVM_OC_##SYM,0,0,0,0) < 0) \
			return -1;					    \
	} while (0);

#define EMIT_W(cg, SYM, w) 						    \
	do { 		   						    \
		if (pib_add_ixyzw(&(cg)->ibuf, NETVM_OC_##SYM,0,0,0,w) < 0) \
			return -1;					    \
	} while (0);

#define EMIT_XYZW(cg, SYM, x, y, z, w) 					    \
	do { 		   						    \
		if (pib_add_ixyzw(&(cg)->ibuf, NETVM_OC_##SYM,x,y,z,w) < 0) \
			return -1;					    \
	} while (0);




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

	prog->cpreqs[NETVM_CPI_XPKT] = prog->cpreqs[NETVM_CPT_XPKT];
	prog->cpreqs[NETVM_CPI_OUTPORT] = prog->cpreqs[NETVM_CPT_OUTPORT];
	prog->cpreqs[NETVM_CPI_PKTQ] = prog->cpreqs[NETVM_CPT_PKTQ];
	prog->cpreqs[NETVM_CPI_REX] = prog->cpreqs[NETVM_CPT_REX];
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
	EMIT_W(cg, PUSH, 1);
	EMIT_NULL(cg, HALT);
	EMIT_W(cg, PUSH, 0);
	EMIT_NULL(cg, HALT);

	cg->nxtpaddr = 0;
	cg->dropaddr = 2;
	return 0;
}


int clearaux(union pml_node *node, void *ctx, void *xstk)
{
	freecode(node);
	return 0;
}


static uint nxti(struct pmlncg *cg)
{
	abort_unless(cg);
	return cg->ibuf.ninst;
}


static void clearcg(struct pmlncg *cg, int copied, int clearall)
{
	struct netvm_meminit *inits;

	abort_unless(cg);

	dyb_clear(&cg->brks);
	dyb_clear(&cg->conts);
	dyb_clear(&cg->nxtrules);

	pml_ast_walk(cg->ast, cg, clearaux, NULL, NULL);

	if (!clearall) {
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

	/* DUMMY CODE */
	prog->eps[NVMP_EP_START] = nxti(&cg);
	EMIT_W(&cg, PUSH, 0xdeadbeef);
	EMIT_NULL(&cg, HALT);

	/* TODO: add initialization of regexes before BEGIN */

	/* TODO: walk begin and end rules */

	/* TODO: walk packet rules */

	/* if we got to here we are good to go! */

	/* clean up memory if this was a destructive transformation */
	if (copy) {
		/* the program keeps the initializations: remove from AST */
		dyb_release(&ast->mi_bufs[PML_SEG_ROMEM]);
		dyb_release(&ast->mi_bufs[PML_SEG_RWMEM]);
		pml_ast_clear(ast);
	}

	clearcg(&cg, copy, 0);

	return 0;

err:
	esave = errno;
	clearcg(&cg, copy, 1);
	errno = esave;
	return -1;
}
