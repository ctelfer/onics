/*
 * Copyright 2012 -- Christopher Telfer
 * See attached licence.
 */
#include "pmltree.h"
#include "ns.h"
#include "util.h"
#include <cat/aux.h>
#include <cat/str.h>
#include <cat/bitops.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define l_to_node(p) (union pml_node *)container(p, struct pml_node_base, ln)
#define SYMTABSIZE    256


static uint64_t val64(struct pml_ast *ast, struct pml_retval *v);


static int is_expr(void *nodep)
{
	int type;
	if (nodep == NULL)
		return 0;
	type = ((union pml_node *)nodep)->base.type;
	return (type == PMLTT_SCALAR || type == PMLTT_BYTESTR ||
		type == PMLTT_MASKVAL || type == PMLTT_BINOP ||
		type == PMLTT_UNOP || type == PMLTT_CALL ||
		type == PMLTT_LOCATOR || type == PMLTT_LOCADDR);
}


static void *pml_bytestr_ptr(struct pml_ast *ast, struct pml_bytestr *bs)
{
	struct dynbuf *dyb;
	abort_unless(ast && bs);
       	abort_unless(bs->segnum >= PML_SEG_MIN && bs->segnum <= PML_SEG_MAX);

	dyb = &ast->mi_bufs[bs->segnum];
	abort_unless(bs->addr < dyb->len && dyb->len - bs->addr >= bs->len);

	return dyb->data + bs->addr;
}


static int symtab_init(struct pml_symtab *t)
{
	struct hnode **bins;

	abort_unless(t);
	if ((bins = malloc(SYMTABSIZE * sizeof(struct hnode *))) == NULL) {
		return -1;
	}
	ht_init(&t->tab, bins, SYMTABSIZE, cmp_str, ht_shash, NULL);
	l_init(&t->list);
	t->addr_rw1 = 0;
	t->addr_rw2 = 0;
	return 0;
}


static union pml_node *symtab_lookup(struct pml_symtab *t, const char *s)
{
	uint h;
	struct hnode *hn;

	abort_unless(t && s);
	if ((hn = ht_lkup(&t->tab, (void *)s, &h)) == NULL)
		return NULL;

	return (union pml_node *)container(hn, struct pml_sym, hn);
}


static int symtab_add(struct pml_symtab *t, struct pml_sym *sym) 
{
	uint h;
	struct hnode *hn;

	abort_unless(t && sym);
	if (ht_lkup(&t->tab, sym->name, &h) != NULL)
		return -1;
	hn = &sym->hn;
	ht_ninit(hn, sym->name, sym);
	ht_ins(&t->tab, hn, h);
	l_enq(&t->list, &sym->ln);

	return 0;
}


static void symtab_destroy(struct pml_symtab *t)
{
	struct list *n, *x;

	abort_unless(t);
	if (t->tab.bkts == NULL)
		return;
	l_for_each_safe(n, x, &t->list) {
		pmln_free(l_to_node(n));
	}
	free(t->tab.bkts);
	t->tab.bkts = NULL;
	abort_unless(l_isempty(&t->list));
}


/* A symbol table can allocate variables in two read-write blocks. */
/* For global variables, the first block is variables with explicit */
/* initializers and the second is for variables without them.  The */
/* program initializeds the latter to 0.  For functions, the first */
/* block is for parameters and the second is for local variables.  */
/* This function adjusts the addresses variables in the second block */
/* by the size of the first block.  */
static void symtab_adj_var_addrs(struct pml_symtab *t)
{
	struct list *n;
	struct pml_variable *v;

	abort_unless(t);
	l_for_each(n, &t->list) {
		v = (struct pml_variable *)l_to_node(n);
		if ((v->vtype == PML_VTYPE_LOCAL) || 
		    ((v->vtype == PML_VTYPE_GLOBAL) && (v->init == NULL)))
			v->addr += t->addr_rw1;
	}
	t->addr_rw2 += t->addr_rw1;
}


int pml_ast_init(struct pml_ast *ast)
{
	int i;
	ast->error = 0;
	ast->done = 0;
	ast->line = 0;
	if (symtab_init(&ast->vars) < 0)
		return -1;
	if (symtab_init(&ast->funcs) < 0) {
		symtab_destroy(&ast->vars);
		return -1;
	}
	l_init(&ast->b_rules);
	l_init(&ast->p_rules);
	l_init(&ast->e_rules);
	for (i = PML_SEG_MIN; i <= PML_SEG_MAX; ++i)
		dyb_init(&ast->mi_bufs[i], NULL);
	str_copy(ast->errbuf, "", sizeof(ast->errbuf));
	return 0;
}


static struct pml_idef stdintr[] = {
	{ "pnew", 3, 0, NULL, { "pnum", "hdrm", "len" } },

	{ "pdel", 2, 0, NULL, { "pnum" } },

	{ "pswap", 2, 0, NULL, { "pnum1", "pnum2" } },

	{ "pcopy", 2, 0, NULL, { "pnsrc", "pndst" } },

	{ "pinsu", 3, 0, NULL, { "pnum", "off", "len" } },

	{ "pinsd", 3, 0, NULL, { "pnum", "off", "len" } },

	{ "pcutu", 3, 0, NULL, { "pnum", "off", "len" } },

	{ "pcutu", 3, 0, NULL, { "pnum", "off", "len" } },

	{ "happend", 3, 0, NULL, { "pnum", "prid", "hlen" } },

	{ "hchop", 1, 0, NULL, { "pnum" } },

	{ "hpush", 3, 0, NULL, { "pnum", "prid", "plen" } },

	{ "hpop", 1, 0, NULL, { "pnum" } },

	{ "hadj", 3, 0, NULL, { "ploc", "oidx", "amt" } },

	{ "fixdlt", 1, 0, NULL, { "pnum" } },

	{ "reparse", 1, 0, NULL, { "pnum" } },

	{ "fixlen", 1, 0, NULL, { "ploc" } },

	{ "fixlens", 1, 0, NULL, { "pnum" } },

	{ "fixcksum", 1, 0, NULL, { "ploc" } },

	{ "fixcksums", 1, 0, NULL, { "pnum" } },

	{ "nbset", 1, PML_FF_PCONST|PML_FF_INLINE, NULL, { "num" } },

	{ "fbsetl", 1, PML_FF_PCONST|PML_FF_INLINE, NULL, { "num" } },

	{ "fbsetr", 1, PML_FF_PCONST|PML_FF_INLINE, NULL, { "num" } },

	{ "log2", 1, PML_FF_PCONST|PML_FF_INLINE, NULL, { "num" } },

	{ "clog2", 1, PML_FF_PCONST|PML_FF_INLINE, NULL, { "num" } },

	{ "min", 2, PML_FF_PCONST|PML_FF_INLINE, NULL, { "num1", "num2" } },

	{ "max", 2, PML_FF_PCONST|PML_FF_INLINE, NULL, { "num1", "num2" } },
};


int pml_ast_add_std_intrinsics(struct pml_ast *ast)
{
	int i;
	int rv;
	abort_unless(ast);
	for (i = 0; i < array_length(stdintr); ++i) {
		rv = pml_ast_add_intrinsic(ast, &stdintr[i]);
		if (rv < 0)
			return rv;
	}
	return 0;
}


void pml_ast_clear(struct pml_ast *ast)
{
	struct list *n, *x;
	int i;

	ast->error = 0;
	ast->done = 0;
	ast->line = 0;

	symtab_destroy(&ast->vars);
	symtab_destroy(&ast->funcs);

	l_for_each_safe(n, x, &ast->b_rules) {
		pmln_free(l_to_node(n));
	}
	abort_unless(l_isempty(&ast->b_rules));

	l_for_each_safe(n, x, &ast->p_rules) {
		pmln_free(l_to_node(n));
	}
	abort_unless(l_isempty(&ast->p_rules));

	l_for_each_safe(n, x, &ast->e_rules) {
		pmln_free(l_to_node(n));
	}
	abort_unless(l_isempty(&ast->e_rules));

	for (i = PML_SEG_MIN; i <= PML_SEG_MAX; ++i)
		dyb_clear(&ast->mi_bufs[i]);

	str_copy(ast->errbuf, "", sizeof(ast->errbuf));
}


void pml_ast_err(struct pml_ast *ast, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(ast->errbuf, sizeof(ast->errbuf), fmt, ap);
	va_end(ap);

	ast->error = 1;
}


struct pml_function *pml_ast_lookup_func(struct pml_ast *ast, char *name)
{
	return (struct pml_function *)symtab_lookup(&ast->funcs, name);
}


int pml_ast_add_func(struct pml_ast *ast, struct pml_function *func)
{
	if (symtab_add(&ast->funcs, (struct pml_sym *)func) < 0) {
		pml_ast_err(ast, "Duplicate function: %s\n", func->name);
		return -1;
	}

	if (pml_resolve_refs(ast, (union pml_node *)func) < 0)
		return -1;

	return 0;
}


int pml_ast_add_intrinsic(struct pml_ast *ast, struct pml_idef *intr)
{
	char *ncpy;
	struct pml_function *f = NULL;
	struct pml_variable *v;
	int i;

	abort_unless(intr && intr->name && intr->arity >= 0 && ast);
	abort_unless((intr->flags & 
			~(PML_FF_INLINE|PML_FF_INTRINSIC|PML_FF_PCONST)) == 0);
	

	if (symtab_lookup(&ast->funcs, intr->name) != NULL)
		pml_ast_err(ast, "Duplicate function: %s\n", intr->name);
		return -1;

	f = (struct pml_function *)pmln_alloc(PMLTT_FUNCTION);
	if (f == NULL)
		goto enomem;
	if ((f->name = strdup(intr->name)) == NULL)
		goto enomem;
	for (i = 0; i < intr->arity; ++i) {
		abort_unless(intr->pnames[i]);
		if ((ncpy = strdup(intr->pnames[i])) == NULL)
			goto enomem;
		v = pml_var_alloc(ncpy, 0, PML_VTYPE_PARAM, NULL);
		if (v == NULL) {
			free(ncpy);
			goto enomem;
		}
		if (pml_func_add_param(f, v) < 0) {
			pmln_free((union pml_node *)f);
			return -1;
		}
	}
	f->arity = intr->arity;
	f->ieval = intr->eval;
	f->flags = intr->flags | PML_FF_INTRINSIC;

	abort_unless(symtab_add(&ast->funcs, (struct pml_sym *)f) >= 0);

	return 0;

enomem:
	pml_ast_err(ast, "pml_ast_add_intrinsic: (%s) out of memory\n",
		    intr->name);
	pmln_free((union pml_node *)f);
	return -1;
}


struct pml_variable *pml_ast_lookup_var(struct pml_ast *ast, char *name)
{
	return (struct pml_variable *)symtab_lookup(&ast->vars, name);
}


int pml_ast_add_var(struct pml_ast *ast, struct pml_variable *var)
{
	uint64_t max;

	if (symtab_add(&ast->vars, (struct pml_sym *)var) < 0) {
		pml_ast_err(ast, "Duplicate global variable: %s\n", var->name);
		return -1;
	}

	if (pml_resolve_refs(ast, (union pml_node *)var) < 0)
		return -1;

	if (var->vtype != PML_VTYPE_CONST) {
		/* NOTE: pad global vars to 8-byte sizes */
		max = (uint64_t)-1 - ast->vars.addr_rw1 - ast->vars.addr_rw2;
		if (rup2_64(var->width, 3) > max) {
			pml_ast_err(ast, 
				    "global read-write address space overflow");
			return -1;
		}
		if (var->init != NULL) {
			var->addr = ast->vars.addr_rw1;
			ast->vars.addr_rw1 += rup2_64(var->width, 3);
		} else { 
			var->addr = ast->vars.addr_rw2;
			ast->vars.addr_rw2 += rup2_64(var->width, 3);
		}
	}

	return 0;
}


int pml_ast_add_rule(struct pml_ast *ast, struct pml_rule *rule)
{
	abort_unless(rule->trigger >= PML_RULE_BEGIN &&
		     rule->trigger <= PML_RULE_END);
	if (pml_resolve_refs(ast, (union pml_node *)rule) < 0)
		return -1;
	switch(rule->trigger) {
	case PML_RULE_BEGIN:
		abort_unless(rule->pattern == NULL);
		l_enq(&ast->b_rules, &rule->ln);
		break;
	case PML_RULE_PACKET:
		l_enq(&ast->p_rules, &rule->ln);
		break;
	case PML_RULE_END:
		abort_unless(rule->pattern == NULL);
		l_enq(&ast->e_rules, &rule->ln);
		break;
	}
	return 0;
}


struct pml_variable *pml_func_lookup_param(struct pml_function *f, char *s)
{
	struct pml_variable *v = 
		(struct pml_variable *)symtab_lookup(&f->vars, s);
	if (v && v->vtype == PML_VTYPE_PARAM)
		return v;
	else
		return NULL;
}


int pml_func_add_param(struct pml_function *f, struct pml_variable *v)
{
	abort_unless(v && v->vtype == PML_VTYPE_PARAM);
	if (symtab_add(&f->vars, (struct pml_sym *)v) < 0)
		return -1;
	v->addr = f->vars.addr_rw1;
	f->vars.addr_rw1 += 1;

	return 0;
}


void pml_ast_finalize(struct pml_ast *ast)
{
	ulong gsz;
	if (ast->error)
		return;

	gsz = ast->vars.addr_rw1 + ast->vars.addr_rw2;
	symtab_adj_var_addrs(&ast->vars);
	if (dyb_resv(&ast->mi_bufs[PML_SEG_RWMEM], gsz) < 0) {
		pml_ast_err(ast, "can't allocate %lu bytes for global mem\n",
			    gsz);
		ast->error = 1;
		return;
	}
}


union pml_node *pmln_alloc(int type)
{
	union pml_node *np;
	struct pml_node_base *node;

	np = calloc(1, sizeof(*np));
	if (np == NULL)
		return NULL;

	/* initialize the common elements of each node */
	node = &np->base;
	node->type = type;
	l_init(&node->ln);
	node->aux = NULL;

	/* Initialize the rest of the fields based on type. */
	/* A function pointer table based on type would be more */
	/* extensible, but overkill. */
	switch (type) {

	case PMLTT_LIST: {
		struct pml_list *p = &np->list;
		l_init(&p->list);
	} break;

	case PMLTT_SCALAR:
	case PMLTT_BYTESTR:
	case PMLTT_MASKVAL: {
		struct pml_literal *p = &np->literal;
		p->eflags = PML_EFLAG_CONST;
		if (type == PMLTT_SCALAR) {
			p->etype = PML_ETYPE_SCALAR;
			p->u.scalar = 0;
			p->width = 8;
		} else if (type == PMLTT_BYTESTR) {
			p->etype = PML_ETYPE_BYTESTR;
			p->u.bytestr.addr = 0;
			p->u.bytestr.len = 0;
			p->u.bytestr.segnum = PML_SEG_NONE;
		} else if (type == PMLTT_MASKVAL) {
			p->etype = PML_ETYPE_MASKVAL;
			p->u.maskval.val.addr = 0;
			p->u.maskval.val.len = 0;
			p->u.maskval.val.segnum = PML_SEG_NONE;
			p->u.maskval.mask.addr = 0;
			p->u.maskval.mask.len = 0;
			p->u.maskval.mask.segnum = PML_SEG_NONE;
		}
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &np->variable;
		ht_ninit(&p->hn, "", p);
		p->vtype = PML_VTYPE_UNKNOWN;
		p->etype = PML_ETYPE_UNKNOWN;
		p->width = 0;
		p->name = NULL;
		p->init = NULL;
	} break;

	case PMLTT_UNOP:
	case PMLTT_BINOP: {
		struct pml_op *p = &np->op;
		p->etype = PML_ETYPE_UNKNOWN;
		p->eflags = 0;
		p->width = 0;
		p->op = 0;
		p->arg1 = NULL;
		p->arg2 = NULL;
		return (union pml_node *)p;
	} break;

	case PMLTT_CALL: {
		struct pml_call *p = &np->call;
		p->etype = PML_ETYPE_SCALAR;
		p->eflags = 0;
		p->width = 8;
		p->func = NULL;
		p->args = NULL;
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &np->ifstmt;
		p->test = NULL;
		p->tbody = NULL;
		p->fbody = NULL;
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &np->whilestmt;;
		p->test = NULL;
		p->body = NULL;
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *p = &np->locator;
		p->eflags = 0;
		if (type == PMLTT_LOCATOR) {
			p->etype = PML_ETYPE_UNKNOWN;
			p->width = 0;
		} else {
			p->etype = PML_ETYPE_SCALAR;
			p->width = 8;
		}
		p->reftype = PML_REF_UNKNOWN;
		p->rpfld = PML_RPF_NONE;
		p->name = NULL;
		p->pkt = NULL;
		p->idx = NULL;
		p->off = NULL;
		p->len = NULL;
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *p = &np->assign;
		p->loc = NULL;
		p->expr = NULL;
	} break;

	case PMLTT_CFMOD: {
		struct pml_cfmod *p = &np->cfmod;
		p->cftype = PML_CFM_UNKNOWN;
		p->expr = NULL;
        } break;

	case PMLTT_PRINT: {
		struct pml_print *p = &np->print;
		p->fmt = NULL;
		p->args = NULL;
	} break;

	case PMLTT_FUNCTION: {
		struct pml_function *p = &np->function;
		ht_ninit(&p->hn, "", p);
		if (symtab_init(&p->vars) < 0) {
			symtab_destroy(&p->vars);
			free(np);
			return NULL;
		}
		p->flags = 0;
		p->width = 8;
		p->name = NULL;
		p->arity = 0;
		p->body = NULL;
		p->ieval = NULL;
		p->pstksz = 0;
		p->vstksz = 0;
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &np->rule;
		symtab_init(&p->vars);
		p->pattern = NULL;
		p->stmts = NULL;
		p->vstksz = 0;
		p->trigger = PML_RULE_PACKET;
	} break;

	default: {
		free(np);
		np = NULL;
	} break;

	}
	return np;
}


void pmln_free(union pml_node *node)
{
	if (node == NULL)
		return;

	/* remove from whatever list it is on, if any */
	l_rem(&node->base.ln);

	switch (node->base.type) {

	case PMLTT_LIST: {
		struct pml_list *p = &node->list;
		struct list *l;
		while ((l = l_deq(&p->list)) != NULL)
			pmln_free((union pml_node *)l_to_node(l));
	} break;

	case PMLTT_SCALAR:
	case PMLTT_BYTESTR:
	case PMLTT_MASKVAL:
		break;

	case PMLTT_VAR: {
		struct pml_variable *p = &node->variable;
		ht_rem(&p->hn);
		free(p->name);
		pmln_free((union pml_node *)p->init);
	} break;

	case PMLTT_BINOP: {
		struct pml_op *p = &node->op;
		pmln_free((union pml_node *)p->arg1);
		pmln_free((union pml_node *)p->arg2);
	} break;

	case PMLTT_UNOP: {
		struct pml_op *p = &node->op;
		pmln_free((union pml_node *)p->arg1);
	} break;

	case PMLTT_CALL: {
		struct pml_call *p = &node->call;
		pmln_free((union pml_node *)p->args);
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &node->ifstmt;
		pmln_free((union pml_node *)p->test);
		pmln_free((union pml_node *)p->tbody);
		pmln_free((union pml_node *)p->fbody);
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &node->whilestmt;
		pmln_free((union pml_node *)p->test);
		pmln_free((union pml_node *)p->body);
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *p = &node->locator;
		free(p->name);
		pmln_free((union pml_node *)p->pkt);
		pmln_free((union pml_node *)p->idx);
		pmln_free((union pml_node *)p->off);
		pmln_free((union pml_node *)p->len);
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *p = &node->assign;
		pmln_free((union pml_node *)p->loc);
		pmln_free((union pml_node *)p->expr);
	} break;

	case PMLTT_CFMOD: {
		struct pml_cfmod *p = &node->cfmod;
		pmln_free((union pml_node *)p->expr);
	} break;

	case PMLTT_PRINT: {
		struct pml_print *p = &node->print;
		free(p->fmt);
		pmln_free((union pml_node *)p->args);
	} break;

	case PMLTT_FUNCTION: {
		struct pml_function *p = &node->function;
		ht_rem(&p->hn);
		free(p->name);
		p->name = NULL;
		symtab_destroy(&p->vars);
		pmln_free(p->body);
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &node->rule;
		pmln_free((union pml_node *)p->pattern);
		pmln_free((union pml_node *)p->stmts);
	} break;

	default:
		abort_unless(0);
	}

	free(node);
}


union pml_expr_u *pml_binop_alloc(int op, union pml_expr_u *left, 
		                  union pml_expr_u *right)
{
	struct pml_op *o = (struct pml_op *)pmln_alloc(PMLTT_BINOP);
	o->op = op;
	o->arg1 = left;
	o->arg2 = right;
	return (union pml_expr_u *)o;
}


union pml_expr_u *pml_unop_alloc(int op, union pml_expr_u *ex)
{
	struct pml_op *o = (struct pml_op *)pmln_alloc(PMLTT_UNOP);
	o->op = op;
	o->arg1 = ex;
	return (union pml_expr_u *)o;
}


struct pml_variable *pml_var_alloc(char *name, int width, int vtype,
		                   union pml_expr_u *init)
{
	struct pml_variable *v = (struct pml_variable *)
		pmln_alloc(PMLTT_VAR);
	v->name = name;

	if (width == 0) {
		v->width = 8;
		v->etype = PML_ETYPE_SCALAR;
	} else {
		v->width = width;
		v->etype = PML_ETYPE_BYTESTR;
	}
	v->vtype = vtype;
	v->init = init;
	return v;
}


struct pml_call *pml_call_alloc(struct pml_ast *ast, struct pml_function *func,
				struct pml_list *args)
{
	uint alen;
	struct pml_call *c = (struct pml_call *)pmln_alloc(PMLTT_CALL);
	struct list *n;

	alen = l_length(&args->list);
	if (alen != func->arity) {
		pml_ast_err(ast, "argument length for call of '%s' does"
				 "not match function arity (%u vs %u)\n)",
			    alen, func->arity);
		return NULL;
	}

	c->func = func;
	c->args = args;
	c->width = func->width;
	c->etype = PML_ETYPE_SCALAR;
	c->eflags = 0;

	/* a call is a constant expression if the function is an inline */
	/* and if the arguments to the function are all constant */
	if (PML_FUNC_IS_PCONST(func)) {
		c->eflags = PML_EFLAG_CONST;
		l_for_each(n, &args->list) {
			struct pml_expr_base *b = 
				container(n, struct pml_expr_base, ln);
			if (!PML_EXPR_IS_CONST(b)) {
				c->eflags = 0;
				break;
			}
		}
	}

	return c;
}


int pml_bytestr_copy(struct pml_ast *ast, struct pml_bytestr *bs, int seg,
		     void *data, ulong len)
{
	abort_unless(ast && bs && data && len > 0);

	if (seg < PML_SEG_MIN || seg > PML_SEG_MAX)
		return -1;

	bs->segnum = seg;
	bs->addr = dyb_last(&ast->mi_bufs[seg]);
	bs->len = len;
	return dyb_cat_a(&ast->mi_bufs[seg], data, len);
}


int pml_locator_extend_name(struct pml_locator *l, char *name, ulong elen)
{
	ulong olen, len;
	char *newname;

	olen = len = strlen(l->name);
	if (len + 2 < len)
		return -1;
	len += 2;
	if (((ulong)-1) - len < elen)
		return -1;
	len += elen;

	newname = realloc(l->name, len);
	if (newname == NULL)
		return -1;

	newname[olen] = '.';
	memcpy(newname + olen + 1, name, elen);
	newname[len-1] = '\0';
	l->name = newname;

	return 0;
}


static void indent(uint depth)
{
	static const char *idstr = "   ";
	while (depth > 0) {
		fputs(idstr, stdout);
		depth--;
	}
}


static void print_bytes(struct pml_ast *ast, struct pml_bytestr *bs, uint depth)
{
	ulong i = 0;
	uint8_t *data;

	indent(depth);

	if (bs->segnum == PML_SEG_NONE) {
		printf("No actual bytes\n");
		return;
	} else if (bs->segnum == PML_SEG_ROMEM) {
		printf("%lu bytes in read-only segment at address %lu\n",
		       bs->len, bs->addr);
	} else {
		abort_unless(bs->segnum == PML_SEG_RWMEM);
		printf("%lu bytes in read-write segment at address %lu\n",
		       bs->len, bs->addr);
	}

	data = pml_bytestr_ptr(ast, bs);
	for (i = 0; i < bs->len; ++i) {
		if (i % 8 == 0)
			indent(depth);
		printf("%02x", data[i]);
		if ((i == bs->len - 1) || (i % 8 == 7))
			fputc('\n', stdout);
	}
}


static const char *eflag_strs[] = {
	"[]", "[c]", "[p]", "[c,p]",
	"[v]", "[cv]", "[pv]", "[cpv]"
};


static const char *efs(void *p, char s[80])
{
	struct pml_expr_base *e = p;
	abort_unless(p);
	abort_unless((e->eflags & ~(PML_EFLAG_CONST|
				    PML_EFLAG_PCONST|
				    PML_EFLAG_VARLEN)) == 0);

	snprintf(s, 80, "[%s; width=%lu]", eflag_strs[e->eflags], 
		 e->width);
	return s;
}


static const char *etype_strs[] = {
	"unknown", "scalar", "byte string", "masked string"
};
static const char *ets(void *p) {
	struct pml_expr_base *e = p;
	abort_unless(p);
	abort_unless(e->etype >= PML_ETYPE_UNKNOWN && 
		     e->etype <= PML_ETYPE_MASKVAL);
	return etype_strs[e->etype];
}


static const char *vtype_strs[] = {
	"unknown", "const", "global", "param", "local"
};
static const char *vts(struct pml_variable *v)
{
	abort_unless(v && v->vtype >= PML_VTYPE_UNKNOWN &&
		     v->vtype <= PML_VTYPE_LOCAL);
	return vtype_strs[v->vtype];
}


static const char *rtype_strs[] = {
	"unknown", "variable", "packet field", "proto const",
	"unknown namespace elem"
};
static const char *rts(struct pml_locator *l)
{
	abort_unless(l && l->reftype >= PML_REF_UNKNOWN &&
		     l->reftype <= PML_REF_UNKNOWN_NS_ELEM);
	return rtype_strs[l->reftype];
}


static const char *rule_trigger_strs[] = {
	"begin", "packet", "end"
};
const char *rulestr(struct pml_rule *r)
{
	abort_unless(r && r->trigger >= PML_RULE_BEGIN &&
		     r->trigger <= PML_RULE_END);
	return rule_trigger_strs[r->trigger];
}


static const char *op_strs[] = {
	"logical OR", "logical AND", "match", "notmatch", "rex match",
	"rex not match", "equals", "not equals", "less than", "greater than",
	"less or equal to", "greater or equal to", "binary OR", "binary XOR",
	"binary AND", "add", "subtract", "multiply", "divide", "modulus",
	"shift left", "shift right", "logical NOT", "binary compliment",
	"negative"
};
static const char *opstr(struct pml_op *op)
{
	abort_unless(op && op->op >= PMLOP_OR && op->op <= PMLOP_NEG);
	return op_strs[op->op];
}


static const char *cfm_strs[] = {
	"unknown", "return", "break", "continue", "nextrule", "nextpkt",
	"drop"
};
static const char *cfmstr(struct pml_cfmod *m)
{
	abort_unless(m && m->cftype >= PML_CFM_UNKNOWN && 
		     m->cftype <= PML_CFM_DROP);
	return cfm_strs[m->cftype];
}


static const char *rpfld_strs[] = {
	"none", "len", "hlen", "plen", "tlen", "error", "prid",
	"index", "header", "payload", "trailer",
};
static const char *rpfstr(int field)
{
	abort_unless(field >= PML_RPF_NONE && field <= PML_RPF_LAST);
	return rpfld_strs[field];
}

static char *funcstr(struct pml_function *f, char s[80])
{
	int nflags = 0;
	abort_unless(f->type == PMLTT_FUNCTION);
	str_copy(s, "Function", 80);
	if (f->flags) {
		str_cat(s, "[", 80);
		if (PML_FUNC_IS_INLINE(f)) {
			str_cat(s, "inline", 80);
			++nflags;
		}
		if (PML_FUNC_IS_INTRINSIC(f)) {
			if (nflags > 0)
				str_cat(s, ", ", 80);
			str_cat(s, "intrinsic", 80);
			++nflags;
		}
		if (PML_FUNC_IS_PCONST(f)) {
			if (nflags > 0)
				str_cat(s, ", ", 80);
			str_cat(s, "pconst", 80);
			++nflags;
		}
		str_cat(s, "]", 80);
	}
	return s;
}


/* Basically a pre-order printing traversal of the tree */
void pmlt_print(struct pml_ast *ast, union pml_node *np, uint depth)
{
	char estr[80];

	if (np == NULL) {
		indent(depth);
		printf("(null)\n");
		return;
	}

	switch (np->base.type) {

	case PMLTT_LIST: {
		struct pml_list *p = &np->list;
		struct list *e;
		indent(depth);
		printf("List:\n");
		indent(depth);
		printf("-----\n");
		l_for_each(e, &p->list) {
			pmlt_print(ast, l_to_node(e), depth);
			indent(depth);
			printf("-----\n");
		}
	} break;

	case PMLTT_SCALAR: {
		struct pml_literal *p = &np->literal;
		indent(depth);
		printf("Scalar %s -- width %d: %ld (%lu,0x%lx)\n",
		       efs(p, estr), (unsigned)p->width, 
		       (long)p->u.scalar, (ulong)p->u.scalar,
		       (long)p->u.scalar);
	} break;

	case PMLTT_BYTESTR: {
		struct pml_literal *p = &np->literal;
		indent(depth);
		printf("Byte string %s -- \n", efs(p, estr));
		print_bytes(ast, &p->u.bytestr, depth);
	} break;

	case PMLTT_MASKVAL: {
		struct pml_literal *p = &np->literal;
		indent(depth);
		printf("Masked Pattern %s \n", efs(p, estr));
		indent(depth);
		printf("Value --\n");
		print_bytes(ast, &p->u.maskval.val, depth);
		indent(depth);
		printf("Mask --\n");
		print_bytes(ast, &p->u.maskval.mask, depth);
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &np->variable;
		indent(depth);
		printf("Variable: %s [%s; width=%lu, addr=%lu]\n", p->name,
		       vts(p), (ulong)p->width, (ulong)p->addr);
		if (p->init != NULL) {
			indent(depth+1);
			printf("Initialization value -- \n");
			pmlt_print(ast, (union pml_node *)p->init, depth+1);
		}
	} break;

	case PMLTT_UNOP: {
		struct pml_op *p = &np->op;
		indent(depth);
		printf("Unary Operation: '%s' %s\n", opstr(p), efs(p, estr));

		indent(depth);
		printf("Operand -- \n");
		pmlt_print(ast, (union pml_node *)p->arg1, depth+1);
	} break;

	case PMLTT_BINOP: {
		struct pml_op *p = &np->op;
		indent(depth);
		printf("Binary Operation: '%s' %s\n", opstr(p), efs(p, estr));

		indent(depth);
		printf("Left Operand -- \n");
		pmlt_print(ast, (union pml_node *)p->arg1, depth+1);

		indent(depth);
		printf("Right Operand -- \n");
		pmlt_print(ast, (union pml_node *)p->arg2, depth+1);
	} break;

	case PMLTT_CALL: {
		struct pml_call *p = &np->call;
		struct pml_function *f = p->func;
		indent(depth);
		printf("Function call to: %s %s\n", f->name, efs(p, estr));
		indent(depth);
		printf("Arguments -- \n");
		pmlt_print(ast, (union pml_node *)p->args, depth+1);
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &np->ifstmt;
		indent(depth);
		printf("If Statement\n");

		indent(depth);
		printf("Test -- \n");
		pmlt_print(ast, (union pml_node *)p->test, depth+1);

		indent(depth);
		printf("True body -- \n");
		pmlt_print(ast, (union pml_node *)p->tbody, depth+1);

		if (p->fbody != NULL) {
			indent(depth);
			printf("False body -- \n");
			pmlt_print(ast, (union pml_node *)p->fbody, depth+1);
		}
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &np->whilestmt;
		indent(depth);
		printf("While Statement\n");

		indent(depth);
		printf("Loop Test -- \n");
		pmlt_print(ast, (union pml_node *)p->test, depth+1);

		indent(depth);
		printf("Loop Body -- \n");
		pmlt_print(ast, (union pml_node *)p->body, depth+1);
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *p = &np->locator;
		indent(depth);
		printf("%s: %s(%s) %s\n", 
		       (p->type == PMLTT_LOCATOR) ? 
		           "Locator"              : 
			   "Location Address",
		       rts(p), p->name, efs(p, estr));

		if (p->reftype == PML_REF_VAR) {
			indent(depth);
			printf("Variable -- \n");
			pmlt_print(ast, (union pml_node *)p->u.varref, depth+1);
		} else if (p->reftype == PML_REF_PKTFLD) {
			indent(depth);
			if (p->rpfld == PML_RPF_NONE)
				printf("Packet field\n");
			else
				printf("Reserved packet field (%s)\n",
				       rpfstr(p->rpfld));
		} else if (p->reftype == PML_REF_NS_CONST) {
			indent(depth);
			printf("Protocol Constant --\n");
		}

		if (p->pkt != NULL) {
			indent(depth);
			printf("Packet -- \n");
			pmlt_print(ast, (union pml_node *)p->pkt, depth+1);
		}

		if (p->idx != NULL) {
			indent(depth);
			printf("Header Index -- \n");
			pmlt_print(ast, (union pml_node *)p->idx, depth+1);
		}

		if (p->off != NULL) {
			indent(depth);
			printf("Offset -- \n");
			pmlt_print(ast, (union pml_node *)p->off, depth+1);
		}

		if (p->len != NULL) {
			indent(depth);
			printf("Length -- \n");
			pmlt_print(ast, (union pml_node *)p->len, depth+1);
		}
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *p = &np->assign;
		indent(depth);
		printf("Assignment to %s\n", p->loc->name);

		if (p->expr != NULL) {
			indent(depth);
			printf("Value -- \n");
			pmlt_print(ast, (union pml_node *)p->expr, depth+1);
		}
	} break;

	case PMLTT_CFMOD: {
		struct pml_cfmod *p = &np->cfmod;
		indent(depth);
		printf("Control Flow Modification: '%s'\n", cfmstr(p));
		if (p->expr != NULL)
			pmlt_print(ast, (union pml_node *)p->expr, depth+1);

        } break;

	case PMLTT_PRINT: {
		struct pml_print *p = &np->print;
		indent(depth);
		printf("Print Statement: \"%s\"\n", p->fmt);
		if (p->args != NULL) {
			indent(depth);
			printf("Arguments -- \n");
			pmlt_print(ast, (union pml_node *)p->args, depth+1);
		}
	} break;

	case PMLTT_FUNCTION: {
		struct pml_function *p = &np->function;
		struct list *n;
		indent(depth);
		printf("%s: %s() -- %d args, %d vars, return width=%lu\n",
		       funcstr(p, estr), p->name, p->arity, (int)p->vstksz,
		       (ulong)p->width);

		indent(depth);
		printf("Parameters & Variables -- \n");
		l_for_each(n, &p->vars.list) {
			pmlt_print(ast, l_to_node(n), depth+1);
		}

		indent(depth);
		printf("Body -- \n");
		pmlt_print(ast, p->body, depth+1);
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &np->rule;
		struct list *n;
		indent(depth);
		printf("Rule: (%s)\n", rulestr(p));

		indent(depth);
		if (p->trigger == PML_RULE_PACKET) {
			if (p->pattern == NULL) {
				printf("Empty pattern\n");
			} else {
				printf("Pattern -- \n");
				pmlt_print(ast, (union pml_node *)p->pattern,
					   depth+1);
			}
		}

		indent(depth);
		printf("Action Variables -- \n");
		l_for_each(n, &p->vars.list) {
			pmlt_print(ast, l_to_node(n), depth+1);
		}

		indent(depth);
		printf("Action -- \n");
		pmlt_print(ast, (union pml_node *)p->stmts, depth+1);
	} break;

	default:
		printf("Unknown type: %d\n", np->base.type);
		break;
	}
}


void pml_ast_print(struct pml_ast *ast)
{
	struct list *n;

	printf("Printing PML Abstract Syntax Tree\n");
	printf("-----------\n");
	printf("Variables\n");
	printf("-----------\n");
	l_for_each(n, &ast->vars.list)
		pmlt_print(ast, l_to_node(n), 1);
	printf("-----------\n");
	printf("Functions\n");
	printf("-----------\n");
	l_for_each(n, &ast->funcs.list)
		pmlt_print(ast, l_to_node(n), 1);
	printf("-----------\n");
	printf("Begin Rules\n");
	printf("-----------\n");
	l_for_each(n, &ast->b_rules)
		pmlt_print(ast, l_to_node(n), 1);
	printf("-----------\n");
	printf("Packet Rules\n");
	printf("-----------\n");
	l_for_each(n, &ast->p_rules)
		pmlt_print(ast, l_to_node(n), 1);
	printf("-----------\n");
	printf("End Rules\n");
	printf("-----------\n");
	l_for_each(n, &ast->e_rules)
		pmlt_print(ast, l_to_node(n), 1);
	printf("-----------\n");
}


int pmln_walk(union pml_node *np, void *ctx, pml_walk_f pre, pml_walk_f in,
	      pml_walk_f post)
{
	int rv = 0;
	struct list *x;
	byte_t xstk[PML_WALK_XSTKLEN];

	if (np == NULL)
		return 0;
	
	if (pre != NULL) {
		rv = (*pre)(np, ctx, xstk);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	}

	switch (np->base.type) {

	case PMLTT_LIST: {
		struct pml_list *p = &np->list;
		struct list *e;
		l_for_each_safe(e, x, &p->list) {
			rv = pmln_walk(l_to_node(e), ctx, pre, in, post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &np->variable;
		if (p->init != NULL) {
			rv = pmln_walk((union pml_node *)p->init, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}
	} break;

	case PMLTT_UNOP: {
		struct pml_op *p = &np->op;
		rv = pmln_walk((union pml_node *)p->arg1, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_BINOP: {
		struct pml_op *p = &np->op;

		rv = pmln_walk((union pml_node *)p->arg1, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;

		if (in != NULL) {
			rv = (*in)((union pml_node *)p, ctx, xstk);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		rv = pmln_walk((union pml_node *)p->arg2, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_CALL: {
		struct pml_call *p = &np->call;
		rv = pmln_walk((union pml_node *)p->args, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &np->ifstmt;

		rv = pmln_walk((union pml_node *)p->test, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;

		rv = pmln_walk((union pml_node *)p->tbody, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;

		if (p->fbody != NULL) {
			rv = pmln_walk((union pml_node *)p->fbody, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &np->whilestmt;

		rv = pmln_walk((union pml_node *)p->test, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;

		rv = pmln_walk((union pml_node *)p->body, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *p = &np->locator;

		if (p->pkt != NULL) {
			rv = pmln_walk((union pml_node *)p->pkt, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		if (p->idx != NULL) {
			rv = pmln_walk((union pml_node *)p->idx, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		if (p->off != NULL) {
			rv = pmln_walk((union pml_node *)p->off, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		if (p->len != NULL) {
			rv = pmln_walk((union pml_node *)p->len, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *p = &np->assign;

		rv = pmln_walk((union pml_node *)p->loc, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;

		rv = pmln_walk((union pml_node *)p->expr, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_CFMOD: {
		struct pml_cfmod *p = &np->cfmod;

		rv = pmln_walk((union pml_node *)p->expr, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
        } break;

	case PMLTT_PRINT: {
		struct pml_print *p = &np->print;

		rv = pmln_walk((union pml_node *)p->args, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_FUNCTION: {
		struct pml_function *p = &np->function;
		struct list *n;

		l_for_each_safe(n, x, &p->vars.list) {
			rv = pmln_walk(l_to_node(n), ctx, pre, in, post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		rv = pmln_walk((union pml_node *)p->body, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &np->rule;

		if (p->pattern != NULL) {
			rv = pmln_walk((union pml_node *)p->pattern, ctx, pre,
				       in, post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		rv = pmln_walk((union pml_node *)p->stmts, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	default:
		break;
	}

	if (post != NULL) {
		rv = (*post)(np, ctx, xstk);
		if (rv < 0)
			return rv;
	}

	return 0;
}


int pml_ast_walk(struct pml_ast *ast, void *ctx, pml_walk_f pre,
		 pml_walk_f in, pml_walk_f post)
{
	struct list *n;
	int rv = 0;

	if (ast == NULL)
		return -1;

	l_for_each(n, &ast->vars.list) {
		rv = pmln_walk(l_to_node(n), ctx, pre, in, post);
		if (rv < 0)
			goto out;
	}
	l_for_each(n, &ast->funcs.list) {
		rv = pmln_walk(l_to_node(n), ctx, pre, in, post);
		if (rv < 0)
			goto out;
	}
	l_for_each(n, &ast->b_rules) {
		rv = pmln_walk(l_to_node(n), ctx, pre, in, post);
		if (rv < 0)
			goto out;
	}
	l_for_each(n, &ast->p_rules) {
		rv = pmln_walk(l_to_node(n), ctx, pre, in, post);
		if (rv < 0)
			goto out;
	}
	l_for_each(n, &ast->e_rules) {
		rv = pmln_walk(l_to_node(n), ctx, pre, in, post);
		if (rv < 0)
			goto out;
	}
out:
	return rv;
}


static int find_reserved_pktfld(const char *field)
{
	int i;
	(void)rpfstr;
	for (i = PML_RPF_FIRST; i <= PML_RPF_LAST; ++i)
		if (strcmp(field, rpfld_strs[i]) == 0)
			return i;
	return PML_RPF_NONE;
}


int pml_locator_resolve_nsref(struct pml_ast *ast, struct pml_locator *l)
{
	struct ns_elem *e;
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	struct ns_scalar *sc;
	struct ns_bytestr *nbs;
	struct ns_maskstr *ms;
	struct pml_literal *lit;
	uint64_t off, len;
	int rv;
	struct pml_retval r;
	char *name = NULL, *cp;
	int rpf = PML_RPF_NONE;

	abort_unless(l && l->name);

	name = l->name;
	if ((cp = strrchr(l->name, '.')) != NULL) {
		ulong blen = cp - l->name;
		++cp;
		if ((rpf = find_reserved_pktfld(cp)) != PML_RPF_NONE) {
			if ((name = malloc(blen + 1)) == NULL) {
				pml_ast_err(ast,
					    "out of memory duplicating "
					    "packet field name\n");
				return -1;
			}
			memcpy(name, l->name, blen);
			name[blen] = '\0';
		}
	}

	e = ns_lookup(NULL, name);
	if (rpf != PML_RPF_NONE)
		free(name);
	if (e == NULL || (rpf != PML_RPF_NONE && e->type != NST_NAMESPACE))
		return 0;

	switch (e->type) {
	case NST_NAMESPACE:
		l->u.nsref = e;
		ns = (struct ns_namespace *)e;
		l->reftype = PML_REF_PKTFLD;
		if (rpf != PML_RPF_NONE) {
			l->rpfld = rpf;
			if (PML_RPF_IS_BYTESTR(rpf)) {
				l->etype = PML_ETYPE_BYTESTR;
				l->width = 0;
				l->eflags |= PML_EFLAG_VARLEN;
			} else {
				l->etype = PML_ETYPE_SCALAR;
				l->width = 8;
			}
		} else {
			l->etype = PML_ETYPE_BYTESTR;
			if (NSF_IS_VARLEN(ns->flags)) {
				l->width = 0;
				l->eflags |= PML_EFLAG_VARLEN;
			} else {
				l->width = ns->len;
			}
		}
		break;

	case NST_PKTFLD:
		l->u.nsref = e;
		pf = (struct ns_pktfld *)e;
		l->reftype = PML_REF_PKTFLD;
		if (NSF_IS_INBITS(pf->flags)) {
			l->etype = PML_ETYPE_SCALAR;
			l->width = 8;
		} else {
			l->etype = PML_ETYPE_BYTESTR;
			if (NSF_IS_VARLEN(pf->flags)) {
				l->width = 0;
				l->eflags |= PML_EFLAG_VARLEN;
			} else {
				l->width = pf->len;
			}
		}
		break;

	case NST_SCALAR:
		/* can not have packet or index for scalars */
		if (l->pkt != NULL || l->idx != NULL || l->off != NULL ||
		    l->len != NULL)
			return -1;
		lit = (struct pml_literal *)pmln_alloc(PMLTT_SCALAR);
		if (lit == NULL)
			return -1;
		sc = (struct ns_scalar *)e;
		lit->u.scalar = sc->value & 0xFFFFFFFF;
		if (NSF_IS_SIGNED(sc->flags))
			lit->u.scalar = sxt64(lit->u.scalar, 32);
		l->u.litref = lit;
		l->reftype = PML_REF_LITERAL;
		break;

	case NST_BYTESTR:
		/* can not have packet or index for scalars */
		if (l->pkt != NULL || l->idx != NULL)
			return -1;
		nbs = (struct ns_bytestr *)e;
		off = 0;
		if (l->off != NULL) {
			rv = pml_eval(ast, NULL, (union pml_node *)l->off, &r);
			if (rv < 0)
				return -1;
			off = val64(ast, &r);
		}
		if (off >= nbs->value.len)
			return -1;
		len = nbs->value.len;
		if (l->len != NULL) {
			rv = pml_eval(ast, NULL, (union pml_node *)l->len, &r);
			if (rv < 0)
				return -1;
			len = val64(ast, &r);
		}
		if (nbs->value.len - off > len)
			return -1;

		lit = (struct pml_literal *)pmln_alloc(PMLTT_BYTESTR);
		if (lit == NULL)
			return -1;
		if (pml_bytestr_copy(ast, &lit->u.bytestr, PML_SEG_ROMEM,
				     nbs->value.data + off, len) < 0) {
			pmln_free((union pml_node *)lit);
			return -1;
		}

		if (l->off != NULL) {
			pmln_free((union pml_node *)l->off);
			l->off = NULL;
		}

		if (l->len != NULL) {
			pmln_free((union pml_node *)l->len);
			l->len = NULL;
		}

		l->u.litref = lit;
		l->reftype = PML_REF_LITERAL;
		break;

	case NST_MASKSTR:
		/* can not have packet, index, offset or length for masks */
		if (l->pkt != NULL || l->idx != NULL || l->off != NULL || 
		    l->len != NULL)
			return -1;
		ms = (struct ns_maskstr *)e;
		abort_unless(ms->value.len == ms->mask.len);

		lit = (struct pml_literal *)pmln_alloc(PMLTT_MASKVAL);
		if (lit == NULL)
			return -1;
		if ((pml_bytestr_copy(ast, &lit->u.maskval.val, PML_SEG_ROMEM,
				      ms->value.data, ms->value.len) < 0) ||
		    (pml_bytestr_copy(ast, &lit->u.maskval.mask, PML_SEG_ROMEM,
				      ms->mask.data, ms->mask.len) < 0)) {
			pmln_free((union pml_node *)lit);
			return -1;
		}

		l->u.litref = lit;
		l->reftype = PML_REF_LITERAL;
		break;
	}

	return 1;
}


struct pml_resolve_ctx {
	/* at most 2 var symbol tables to consider:  vars, global */
	struct pml_symtab *symtabs[2];
	int ntab;
	int vtidx;
	struct pml_function *livefunc;
	struct pml_while *innerloop;
	struct pml_ast *ast;
};


static struct pml_variable *rlookup(struct pml_resolve_ctx *ctx, 
				    const char *name)
{
	int i;
	union pml_node *node;

	for (i = 0; i < ctx->ntab; ++i) {
		node = symtab_lookup(ctx->symtabs[i], name);
		if (node != NULL) {
			abort_unless(node->base.type == PMLTT_VAR);
			return (struct pml_variable *)node;
		}
	}

	return NULL;
}


static int resolve_locsym(struct pml_resolve_ctx *ctx, struct pml_locator *l)
{
	struct pml_variable *v;
	int rv;
	struct pml_symtab *t;

	/* check if already resolved */
	if ((l->reftype != PML_REF_UNKNOWN) && 
	    (l->reftype != PML_REF_UNKNOWN_NS_ELEM))
		return 0;

	if ((l->reftype == PML_REF_UNKNOWN_NS_ELEM) || 
	    (l->reftype == PML_REF_UNKNOWN)) {
		rv = pml_locator_resolve_nsref(ctx->ast, l);
		if (rv < 0) {
			pml_ast_err(ctx->ast,
				    "Internal error resolving field '%s'\n", 
				    l->name);
			return -1;
		}
		if ((rv == 0) && (l->reftype == PML_REF_UNKNOWN_NS_ELEM)) {
			pml_ast_err(ctx->ast, 
				    "Unable to resolve protocol field '%s'\n",
				    l->name);
			return -1;
		}
		if (rv > 0)
			return 0;
	}

	v = rlookup(ctx, l->name);
	if (v != NULL) {
		l->reftype = PML_REF_VAR;
		l->u.varref = v;
		if (v->vtype == PML_VTYPE_CONST) {
			l->eflags |= (PML_EFLAG_CONST|PML_EFLAG_PCONST);
		} else if (v->vtype == PML_VTYPE_PARAM) {
			struct pml_function *f = ctx->livefunc;
			/* if the variable is a parameter in an inline */
			/* function, then it can be considered constant */
			if (PML_FUNC_IS_INLINE(f))
				l->eflags |= PML_EFLAG_PCONST;
		}
		l->width = v->width;
		return 0;
	}

	/* if we can't create the local variable, return an error */
	if (ctx->vtidx < 0) {
		pml_ast_err(ctx->ast, "unable to resolve variable '%s'\n",
			    l->name);
		return -1;
	}

	t = ctx->symtabs[ctx->vtidx];
	v = pml_var_alloc(l->name, 0, PML_VTYPE_LOCAL, NULL);
	if (v == NULL) {
		pml_ast_err(ctx->ast, "out of memory building ast\n");
		return -1;
	}
	v->addr = t->addr_rw2;
	t->addr_rw2 += 1;
	abort_unless(symtab_add(t, (struct pml_sym *)v) >= 0);
	l->reftype = PML_REF_VAR;
	l->u.varref = v;

	return 0;
}


static int binop_typecheck(struct pml_ast *ast, struct pml_op *op)
{
	struct pml_expr_base *a1, *a2;

	a1 = (struct pml_expr_base *)op->arg1;
	a2 = (struct pml_expr_base *)op->arg2;

	switch(op->op) {
	case PMLOP_MATCH:
	case PMLOP_NOTMATCH:
		if (a1->etype != PML_ETYPE_BYTESTR) {
			pml_ast_err(ast,
				    "%s: Left argument of a match operation "
				    "must be a byte string: %s instead\n",
				    opstr(op), ets(a1));
			return -1;
		}
		if (a1->etype != PML_ETYPE_BYTESTR &&
		    a2->etype != PML_ETYPE_MASKVAL) {
			pml_ast_err(ast, 
				    "%s: Right argument of a match operation "
				    "must be a byte string or masked "
				    "string: %s instead\n", 
				    opstr(op), ets(a2));
			return -1;
		}
		break;
	case PMLOP_REXMATCH:
	case PMLOP_NOTREXMATCH:
		if (a1->etype != PML_ETYPE_BYTESTR ||
		    a2->etype != PML_ETYPE_BYTESTR) {
			pml_ast_err(ast, "Both arguments of a regex operation "
					 "must be byte strings. Types are "
					 "'%s' and '%s'\n", ets(a1), ets(a2));
			return -1;
		}
		break;
	}

	return 0;
}


static int resolve_node_pre(union pml_node *node, void *ctxp, void *xstk)
{
	struct pml_resolve_ctx *ctx = ctxp;

	if (node->base.type == PMLTT_WHILE) {
		struct pml_while **oinner = xstk;
		*oinner = ctx->innerloop;
		ctx->innerloop = (struct pml_while *)node;
	} else if (node->base.type == PMLTT_CFMOD) {
		struct pml_cfmod *m = (struct pml_cfmod *)&node->cfmod;

		if (m->cftype == PML_CFM_RETURN) {
			if (ctx->livefunc == NULL) {
				pml_ast_err(ctx->ast, 
					    "return statement outside of "
					    " a function\n");
				return -1;
			}
		} else if (m->cftype == PML_CFM_BREAK ||
			   m->cftype == PML_CFM_CONTINUE) {
			if (ctx->innerloop == NULL) {
				pml_ast_err(ctx->ast, 
					    "'%s' statement outside of "
					    " a loop\n", cfmstr(m));
				return -1;
			}
		}
	} 

	return 0;
}


static int resolve_node_post(union pml_node *node, void *ctxp, void *xstk)
{
	struct pml_resolve_ctx *ctx = ctxp;

	switch(node->base.type) {

	case PMLTT_BINOP: {
		struct pml_op *op = (struct pml_op *)node;
		/* type checking _is_ required for certain binary operations */
		/* specifically, the MATCH and REXMATCH Operations */
		if (binop_typecheck(ctx->ast, op) < 0)
			return -1;
		if (PML_EXPR_IS_CONST(op->arg1) && 
		    PML_EXPR_IS_CONST(op->arg2)) {
			op->eflags |= PML_EFLAG_CONST | PML_EFLAG_PCONST;
			op->eflags |= PML_EFLAG_PCONST;
		} else if (PML_EXPR_IS_PCONST(op->arg1) && 
		           PML_EXPR_IS_PCONST(op->arg2)) {
			op->eflags |= PML_EFLAG_PCONST;
		}
		/* for now all binary operations return scalars */
		op->etype = PML_ETYPE_SCALAR;
	} break;

	case PMLTT_UNOP: {
		struct pml_op *op = (struct pml_op *)node;
		/* type checking not currently required for unary operations */
		/* because both byte strings and scalars are allowed for */
		/* all operations. */
		if (PML_EXPR_IS_CONST(op->arg1)) {
			op->eflags |= PML_EFLAG_CONST | PML_EFLAG_PCONST;
		} else if (PML_EXPR_IS_PCONST(op->arg1)) {
			op->eflags |= PML_EFLAG_PCONST;
		}
		/* for now all unary operations return scalars */
		op->etype = PML_ETYPE_SCALAR;
	} break;

	case PMLTT_CALL: {
		struct pml_call *c = (struct pml_call *)node;
		struct pml_function *f;
		struct list *n;
		f = c->func;
		if (PML_FUNC_IS_PCONST(f)) {
			c->eflags |= PML_EFLAG_CONST;
			l_for_each(n, &c->args->list) {
				if (!PML_EXPR_IS_PCONST(l_to_node(n))) {
					c->eflags &= ~PML_EFLAG_PCONST;
					break;
				}
			}
		}
	} break;

	case PMLTT_LOCATOR: {
		struct pml_locator *l = (struct pml_locator *)node;
		if (resolve_locsym(ctx, l) < 0)
			return -1;
		if (l->reftype == PML_REF_LITERAL) {
			l->etype = l->u.litref->etype;
		} else if (l->reftype == PML_REF_VAR) {
			struct pml_variable *v = l->u.varref;
			l->etype = v->etype;
			if (v->vtype == PML_VTYPE_CONST)
				l->eflags |= PML_EFLAG_CONST;
		} else {
			struct ns_elem *e;
			abort_unless(l->reftype == PML_REF_PKTFLD);
			e = l->u.nsref;
			if (e->type == NST_NAMESPACE)
				l->etype = PML_ETYPE_SCALAR;
			else
				l->etype = PML_ETYPE_BYTESTR;
		}
	} break;

	case PMLTT_LOCADDR: {
		struct pml_locator *l = (struct pml_locator *)node;
		if (resolve_locsym(ctx, l) < 0)
			return -1;
		if ((l->reftype == PML_REF_NS_CONST) || 
		    ((l->reftype == PML_REF_VAR) && 
		     (l->u.varref->vtype == PML_VTYPE_CONST))) {
			pml_ast_err(ctx->ast, 
				    "'%s' is not an addressable field.\n",
				    l->name);
			return -1;
		}
	} break;

	case PMLTT_WHILE: {
		struct pml_while **oinner = xstk;
		ctx->innerloop = *oinner;
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *a = (struct pml_assign *)node;
		if ((a->loc->reftype != PML_REF_VAR) && 
		    (a->loc->reftype != PML_REF_PKTFLD)) {
			pml_ast_err(ctx->ast, "locator '%s' in assignment is"
					      " not a valid lvalue\n",
				    a->loc->name);
			return -1;
		}
		if (a->loc->reftype == PML_REF_VAR) {
			struct pml_variable *v = a->loc->u.varref;
			abort_unless(v != NULL);
			abort_unless(v->vtype != PML_VTYPE_UNKNOWN);
			if (v->vtype == PML_VTYPE_CONST) {
				pml_ast_err(ctx->ast, 
					    "locator '%s' in assignment is"
					    "a constant\n", v->name);
				return -1;
			}
		}
	} break;

	}

	return 0;
}


static int resolve_node(struct pml_resolve_ctx *ctx, union pml_node *node)
{
	return pmln_walk(node, ctx, resolve_node_pre, NULL,
			 resolve_node_post);
}


int pml_resolve_refs(struct pml_ast *ast, union pml_node *node)
{
	struct pml_resolve_ctx ctx;
	int rv = 0;

	ctx.ast = ast;
	ctx.livefunc = NULL;
	ctx.innerloop = NULL;

	if (node->base.type == PMLTT_RULE) {
		struct pml_rule *rule = (struct pml_rule *)node;

		ctx.symtabs[0] = &rule->vars;
		ctx.symtabs[1] = &ast->vars;
		ctx.ntab = 2;
		ctx.vtidx = 0;
		rv = resolve_node(&ctx, (union pml_node *)rule->pattern);
		if (rv < 0)
			goto out;
		rv = resolve_node(&ctx, (union pml_node *)rule->stmts);
		if (rv < 0)
			goto out;
		rule->vstksz = rule->vars.addr_rw2 * sizeof(uint64_t);

	} else if (node->base.type == PMLTT_FUNCTION &&
		   !PML_FUNC_IS_INLINE((struct pml_function *)node)) {
		struct pml_function *func = (struct pml_function *)node;

		ctx.symtabs[0] = &func->vars;
		ctx.symtabs[1] = &ast->vars;
		ctx.ntab = 2;
		ctx.vtidx = 0;
		ctx.livefunc = func;
		rv = resolve_node(&ctx, (union pml_node *)func->body);
		if (rv < 0)
			goto out;
		func->pstksz = func->vars.addr_rw1 * sizeof(uint64_t);
		func->vstksz = func->vars.addr_rw2 * sizeof(uint64_t);

	} else if (node->base.type == PMLTT_FUNCTION) {
		struct pml_function *inln = (struct pml_function *)node;
		struct pml_expr_base *pe;

		abort_unless(PML_FUNC_IS_INLINE(inln));
		ctx.symtabs[0] = &inln->vars;
		ctx.symtabs[1] = &ast->vars;
		ctx.ntab = 2;
		ctx.vtidx = -1; /* no local variables in inlines */
		ctx.livefunc = inln;
		rv = resolve_node(&ctx, (union pml_node *)inln->body);
		if (rv < 0)
			goto out;
		inln->pstksz = inln->vars.addr_rw1 * sizeof(uint64_t);
		if (PML_EXPR_IS_PCONST(inln->body))
			inln->flags |= PML_FF_PCONST;
		pe = (struct pml_expr_base *)inln->body;
		if (pe->etype != PML_ETYPE_SCALAR) {
			pml_ast_err(ast,
				    "Non-scalar expression for inline %s "
				    "(type = %d)\n",
				    inln->name, pe->etype);
			goto out;
		}

	} else if (node->base.type == PMLTT_VAR) {
		struct pml_variable *var = (struct pml_variable *)node;

		ctx.symtabs[0] = &ast->vars;
		ctx.ntab = 1;
		ctx.vtidx = -1;
		rv = resolve_node(&ctx, (union pml_node *)var->init);
		if (rv < 0)
			goto out;

		if (var->init != NULL) {
			if (!PML_EXPR_IS_CONST(var->init)) {
				pml_ast_err(ast, 
					    "Global %s %s initialization value"
					    " is not constant.\n", 
					    (var->vtype == PML_VTYPE_GLOBAL 
						? "global"
						: "const"),
					    var->name);
				goto out;
			}
			if (var->init->expr.etype != var->etype) {
				pml_ast_err(ast,
					    "Variable '%s' %s initialization "
					    "expression does not match "
					    "variable type (init is %s)\n",
					    var->name, etype_strs[var->etype],
					    ets(var->init));
				goto out;
			}
			if (var->init->expr.width > var->width) {
				pml_ast_err(ast,
					    "Variable '%s' %s initialization "
					    "expression is larger than the "
					    "variable (expr = %u, var = %u)\n",
					    var->name, etype_strs[var->etype],
					    (uint)var->init->expr.width, 
					    (uint)var->width);
				goto out;
			}
		}

	} else {

		pml_ast_err(ast, "Invalid node type for resolution: %d\n",
			    node->base.type);
		goto out;

	}

out:
	return rv;
}


static void stkfree(struct pml_stack_frame *fr)
{
	if (fr != NULL) {
		free(fr->stack);
		memset(fr, 0, sizeof(*fr));
		free(fr);
	}
}


static struct pml_stack_frame *stkalloc(struct pml_ast *ast,
					union pml_node *node)
{
	struct pml_stack_frame *fr = NULL;

	fr = malloc(sizeof(struct pml_stack_frame));
	if (fr == NULL)
		goto oomerr;

	if (node->base.type == PMLTT_FUNCTION) {
		struct pml_function *p = (struct pml_function *)node;
		fr->psz = p->pstksz;
		fr->ssz = p->pstksz + p->vstksz;
		fr->u.func = p;
	} else if (node->base.type == PMLTT_RULE) {
		struct pml_rule *p = (struct pml_rule *)node;
		fr->psz = 0;
		fr->ssz = p->vstksz;
		fr->u.rule = p;
	} else {
		pml_ast_err(ast, "Invalid node type to allocate stack frame\n",
			    node->base.type);
		return NULL;
	}

	fr->stack = calloc(1, fr->ssz);
	if (fr->stack == NULL)
		goto oomerr;

	return fr;

oomerr:
	pml_ast_err(ast, "Out of memory in stkalloc()\n");
	stkfree(fr);
	return NULL;
}


static uint64_t val64(struct pml_ast *ast, struct pml_retval *v)
{
	byte_t *data, *mask;
	int i;
	byte_t bytes[8];

	abort_unless(v);

	switch(v->etype) {
	case PML_ETYPE_SCALAR:
		return v->val;
	case PML_ETYPE_BYTESTR:
		data = pml_bytestr_ptr(ast, &v->bytes);
		return be64val(data, v->bytes.len);
	case PML_ETYPE_MASKVAL: {
		data = pml_bytestr_ptr(ast, &v->bytes);
		mask = pml_bytestr_ptr(ast, &v->mask);
		ulong len = (v->bytes.len > v->mask.len) ? v->bytes.len :
			    v->mask.len;
		if (len > sizeof(bytes))
			len = sizeof(bytes);
		for (i = 0; i < len; ++i)
			bytes[i] = data[i] & mask[i];
		return be64val(bytes, len);
	} break;
	default:
		abort_unless(0);
		return (uint64_t)-1;
	}
}


static int unimplemented(struct pml_ast *ast, struct pml_stack_frame *fr,
			 union pml_node *node, struct pml_retval *v)
{
	abort_unless(ast && node);
	pml_ast_err(ast, "evaluation of type '%d' unimplemented\n",
		    node->base.type);
	return -1;
}


static int e_scalar(struct pml_ast *ast, struct pml_stack_frame *fr,
		    union pml_node *node, struct pml_retval *r)
{
	r->etype = PML_ETYPE_SCALAR;
	r->val = ((struct pml_literal *)node)->u.scalar;
	return 0;
}


static int e_bytestr(struct pml_ast *ast, struct pml_stack_frame *fr,
		     union pml_node *node, struct pml_retval *r)
{
	r->etype = PML_ETYPE_BYTESTR;
	r->bytes = ((struct pml_literal *)node)->u.bytestr;
	return 0;
}


static int e_maskval(struct pml_ast *ast, struct pml_stack_frame *fr,
		     union pml_node *node, struct pml_retval *r)
{
	r->etype = PML_ETYPE_MASKVAL;
	r->bytes = ((struct pml_literal*)node)->u.maskval.val;
	r->mask = ((struct pml_literal*)node)->u.maskval.mask;
	return 0;
}


static int is_match_op(int op)
{
	return (op >= PMLOP_MATCH) && (op <= PMLOP_NOTREXMATCH);

}


static int matchop(struct pml_ast *ast, struct pml_retval *l,
		   struct pml_retval *r)
{
	ulong i;
	byte_t *lb, *rb, *rm;
	abort_unless(l->etype == PML_ETYPE_BYTESTR);
	abort_unless(r->etype == PML_ETYPE_BYTESTR ||
		     r->etype == PML_ETYPE_MASKVAL);

	lb = pml_bytestr_ptr(ast, &l->bytes);
	rb = pml_bytestr_ptr(ast, &r->bytes);

	if (r->etype == PML_ETYPE_BYTESTR) {
		if (l->bytes.len != r->bytes.len)
			return 0;
		return memcmp(lb, rb, l->bytes.len);
	} else {
		if (l->bytes.len != r->bytes.len)
			return 0;
		abort_unless(r->bytes.len == r->mask.len);
		rm = pml_bytestr_ptr(ast, &r->mask);
		for (i = 0; i < l->bytes.len ; ++i)
			if ((*lb & *rm) != (*rb & *rm))
				return 0;
		return 1;
	}
}


static int e_binop(struct pml_ast *ast, struct pml_stack_frame *fr,
		   union pml_node *node, struct pml_retval *r)
{
	struct pml_op *op = (struct pml_op *)node;
	struct pml_retval lr, rr;
	uint64_t left = 0, right = 0;
	int rv;

	r->etype = PML_ETYPE_SCALAR;
	abort_unless(op->arg1 != NULL && is_expr(op->arg1));
	abort_unless(op->arg2 != NULL && is_expr(op->arg2));

	if (pml_eval(ast, fr, (union pml_node *)op->arg1, &lr) < 0)
		return -1;
	if (!is_match_op(op->op))
		left = val64(ast, &lr);

	/* implement short circuit evaluation for || and && */
	if (op->op == PMLOP_OR) {
		if (left) {
			r->val = 1;
			return 0;
		}
	} else if (op->op == PMLOP_AND) {
		if (!left) {
			r->val = 0;
			return 0;
		}
	}

	if (pml_eval(ast, fr, (union pml_node *)op->arg2, &rr) < 0)
		return -1;
	if (!is_match_op(op->op))
		right = val64(ast, &rr);

	switch(op->op) {
	case PMLOP_OR:
	case PMLOP_AND: r->val = right != 0;
		break;
	case PMLOP_MATCH:
		if ((rv = matchop(ast, &lr, &rr)) < 0)
			return -1;
		r->val = rv;
		break;
	case PMLOP_NOTMATCH:
		if ((rv = matchop(ast, &lr, &rr)) < 0)
			return -1;
		r->val = !rv;
		break;
	case PMLOP_REXMATCH:
	case PMLOP_NOTREXMATCH:
		/* TODO */
		pml_ast_err(ast, "eval: regex matching unimplemented\n");
		return -1;
		break;
	case PMLOP_EQ: r->val = left == right;
		break;
	case PMLOP_NEQ: r->val = left != right;
		break;
	case PMLOP_LT: r->val = (int64_t)left < (int64_t)right;
		break;
	case PMLOP_GT: r->val = (int64_t)left > (int64_t)right;
		break;
	case PMLOP_LEQ: r->val = (int64_t)left <= (int64_t)right;
		break;
	case PMLOP_GEQ: r->val = (int64_t)left >= (int64_t)right;
		break;
	case PMLOP_BOR: r->val = left | right;
		break;
	case PMLOP_BXOR: r->val = left ^ right;
		break;
	case PMLOP_BAND: r->val = left & right;
		break;
	case PMLOP_PLUS: r->val = left + right;
		break;
	case PMLOP_MINUS: r->val = left - right;
		break;
	case PMLOP_TIMES: r->val = left * right;
		break;
	case PMLOP_DIV: 
		if (!right) {
			pml_ast_err(ast, "eval: divide by zero error\n");
			return -1;
		}
		r->val = left / right;
		break;
	case PMLOP_MOD: 
		if (!right) {
			pml_ast_err(ast, "eval: divide by zero error\n");
			return -1;
		}
		r->val = left % right;
		break;
	case PMLOP_SHL: r->val = left << (right & 63);
		break;
	case PMLOP_SHR: r->val = left >> (right & 63);
		break;
	default:
		abort_unless(0);
	}

	return 0;
}


static int e_unop(struct pml_ast *ast, struct pml_stack_frame *fr,
		  union pml_node *node, struct pml_retval *r)
{
	struct pml_op *op = (struct pml_op *)node;
	struct pml_retval lr;
	uint64_t arg;

	abort_unless(op->etype == PML_ETYPE_SCALAR);
	abort_unless(op->arg1 != NULL && is_expr(op->arg1));

	if (pml_eval(ast, fr, (union pml_node *)op->arg1, &lr) < 0)
		return -1;
	arg = val64(ast, &lr);

	r->etype = PML_ETYPE_SCALAR;
	switch(op->op) {
	case PMLOP_NOT:
		r->val = !arg;
		break;
	case PMLOP_BINV:
		r->val = ~arg;
		break;
	case PMLOP_NEG:
		r->val = -arg;
		break;
	default:
		abort_unless(0);
	}

	return 0;
}


static int e_call(struct pml_ast *ast, struct pml_stack_frame *fr,
		  union pml_node *node, struct pml_retval *r)
{
	struct pml_call *c = (struct pml_call *)node;
	struct pml_function *f = c->func;
	struct pml_stack_frame *nfr;
	struct pml_retval lr;
	struct list *n;
	int rv = -1;
	uint64_t *pp;

	abort_unless(l_length(&c->args->list) == f->arity);
	r->etype = PML_ETYPE_SCALAR;
	nfr = stkalloc(ast, (union pml_node *)f);
	if (nfr == NULL)
		return -1;

	/* evaluation the parameters and put them in the stack frame */
	pp = (uint64_t *)nfr->stack;
	l_for_each(n, &c->args->list) {
		rv = pml_eval(ast, fr, l_to_node(n), &lr);
		if (rv < 0)
			goto out;
		*pp++ = val64(ast, &lr);
	}

	if (PML_FUNC_IS_INTRINSIC(f))
		rv = (*f->ieval)(ast, nfr, (union pml_node *)f, &lr);
	else
		rv = pml_eval(ast, nfr, f->body, &lr);
	if (rv < 0)
		goto out;
	r->val = val64(ast, &lr);
out:
	stkfree(nfr);
	return rv;
}


static int getofflen(struct pml_ast *ast, struct pml_stack_frame *fr,
		     struct pml_locator *l, uint64_t fieldlen,
		     uint64_t *off, uint64_t *len)
{
	struct pml_retval lr;

	if (l->off != NULL) {
		if (pml_eval(ast, fr, (union pml_node *)l->off, &lr) < 0)
			return -1;
		*off = val64(ast, &lr);
	}

	if (l->len != NULL) {
		if (pml_eval(ast, fr, (union pml_node *)l->len, &lr) < 0)
			return -1;
		*len = val64(ast, &lr);
	} else {
		*len = fieldlen;
	}

	return 0;
}


static int e_const(struct pml_ast *ast, struct pml_stack_frame *fr,
		   struct pml_locator *l, struct pml_retval *r)
{
	uint64_t off = 0, len = 0;
	struct pml_retval lr;
	struct pml_variable *v = l->u.varref;

	abort_unless(l->off == NULL || PML_EXPR_IS_CONST(l->off));
	abort_unless(l->len == NULL || PML_EXPR_IS_CONST(l->len));

	if (v->etype == PML_ETYPE_SCALAR) {

		abort_unless(l->off == NULL && l->len == NULL);
		if (pml_eval(ast, fr, (union pml_node*)v->init, r) < 0)
			return -1;

	} else if (v->etype == PML_ETYPE_BYTESTR ||
		   v->etype == PML_ETYPE_MASKVAL) { 

		if (pml_eval(ast, fr, (union pml_node*)v->init, &lr) < 0)
			return -1;
		if (getofflen(ast, fr, l, lr.bytes.len, &off, &len) < 0)
			return -1;
		abort_unless(v->etype == PML_ETYPE_BYTESTR ||
			     lr.mask.len == lr.bytes.len);
		if (len > lr.bytes.len || off > lr.bytes.len - len) {
			pml_ast_err(ast,
				    "field overflow locator for '%s': "
				    "[off=%lu,len=%lu,field=%lu bytes]\n",
				    l->name, (ulong)off, (ulong)len,
				    (ulong)lr.bytes.len);
			return -1;
		}
		r->etype = v->etype;
		r->bytes.segnum = lr.bytes.segnum;
		r->bytes.addr = lr.bytes.addr + off;
		r->bytes.len = len;
		if (v->etype == PML_ETYPE_MASKVAL) { 
			r->mask.segnum = lr.mask.segnum;
			r->mask.addr = lr.mask.addr + off;
			r->mask.len = len;
		}

	} else {
		abort_unless(0);
	}
	return 0;
}


static int e_locator(struct pml_ast *ast, struct pml_stack_frame *fr,
		     union pml_node *node, struct pml_retval *r)
{
	struct pml_locator *l = (struct pml_locator *)node;
	uint64_t off = 0, len = 8;

	if (l->reftype == PML_REF_VAR) {
		struct pml_variable *v = l->u.varref;

		abort_unless(l->pkt == NULL);
		abort_unless(l->idx == NULL);
		abort_unless(v->vtype == PML_VTYPE_CONST ||
			     v->vtype == PML_VTYPE_GLOBAL ||
			     v->vtype == PML_VTYPE_PARAM ||
		             v->vtype == PML_VTYPE_LOCAL);

		if (v->vtype == PML_VTYPE_CONST) {

			return e_const(ast, fr, l, r);

		} else if (v->vtype == PML_VTYPE_GLOBAL) {

			if (getofflen(ast, fr, l, v->width, &off, &len) < 0)
				return -1;
			if (off > v->width || v->width - off < len) {
				pml_ast_err(ast,
					    "eval: access to global '%s' is "
					    "out of bounds: [off=%lu,len=%lu,"
					    "varlen=%lu]\n",
					    (ulong)off, (ulong)len, 
					    (ulong)v->width);
				return -1;
			}
			if (l->etype == PML_ETYPE_SCALAR) {
				abort_unless(l->off == NULL);
				abort_unless(l->len == NULL);
				r->etype = PML_ETYPE_SCALAR;
				r->val = *(uint64_t *)(fr->stack + v->addr);
			} else {
				abort_unless(l->etype == PML_ETYPE_BYTESTR);
				r->etype = PML_ETYPE_BYTESTR;
				r->bytes.segnum = PML_SEG_RWMEM;
				r->bytes.addr = v->addr + off;
				r->bytes.len = len;
			}

		} else {
			byte_t *p;

			abort_unless(v->vtype == PML_VTYPE_PARAM ||
			             v->vtype == PML_VTYPE_LOCAL);
			abort_unless(l->etype == PML_ETYPE_SCALAR);
			abort_unless(l->off == NULL && l->len == NULL);
			abort_unless(fr);
			if (fr->ssz < 8 || fr->ssz - 8 < v->addr) {
				pml_ast_err(ast,
					    "eval: stack overflow in var '%s':"
					    " stack size=%lu, var addr=%lu\n",
					    v->name, fr->ssz, v->addr);
				return -1;
			}
			r->etype = PML_ETYPE_SCALAR;
			p = fr->stack + v->addr * sizeof(uint64_t);
			if (v->vtype == PML_VTYPE_LOCAL)
				p += fr->psz;
			r->val = *(uint64_t *)p;
		}
	} else if (l->reftype == PML_REF_PKTFLD) {

		/* TODO */
		pml_ast_err(ast, "eval: Packet fields unimplemented\n");
		return -1;

	} else if (l->reftype == PML_REF_LITERAL) {

		return pml_eval(ast, fr, (union pml_node *)l->u.litref, r);

	} else {

		abort_unless(0);

	}

	return 0;
}


static int e_locaddr(struct pml_ast *ast, struct pml_stack_frame *fr,
		     union pml_node *node, struct pml_retval *r)
{
	struct pml_locator *l = (struct pml_locator *)node;

	if (l->reftype == PML_REF_VAR) {
		abort_unless(l->u.varref->vtype == PML_VTYPE_GLOBAL ||
		             l->u.varref->vtype == PML_VTYPE_PARAM ||
		             l->u.varref->vtype == PML_VTYPE_LOCAL);
		r->etype = PML_ETYPE_SCALAR;
		r->val = l->u.varref->addr;
	} else if (l->reftype == PML_REF_PKTFLD) {
		/* TODO */
		pml_ast_err(ast, 
			    "eval: Packet field addresses unimplemented\n");
		return -1;
	} else {
		pml_ast_err(ast, "eval: Invalid reftype in locator: %d\n",
			    l->reftype);
		return -1;
	}
	return 0;
}


static pml_eval_f evaltab[] = {
	unimplemented,		/* PMLTT_LIST */
	e_scalar,		/* PMLTT_SCALAR */
	e_bytestr,		/* PMLTT_BYTESTR */
	e_maskval,		/* PMLTT_MASKVAL */
	unimplemented,		/* PMLTT_VAR */
	e_binop,		/* PMLTT_BINOP */
	e_unop,			/* PMLTT_UNOP */
	e_call,			/* PMLTT_CALL */
	unimplemented,		/* PMLTT_IF */
	unimplemented,		/* PMLTT_WHILE */
	e_locator,		/* PMLTT_LOCATOR */
	e_locaddr,		/* PMLTT_LOCADDR */
	unimplemented,		/* PMLTT_ASSIGN */
	unimplemented,		/* PMLTT_CFMOD */
	unimplemented,		/* PMLTT_PRINT */
	unimplemented,		/* PMLTT_FUNCTION */
	unimplemented,		/* PMLTT_RULE */
};


int pml_eval(struct pml_ast *ast, struct pml_stack_frame *fr, 
	     union pml_node *node, struct pml_retval *r)
{
	abort_unless(ast && r);
	if (node == NULL || node->base.type < 0 || 
	    node->base.type > PMLTT_RULE) {
		pml_ast_err(ast, "Invalid node given to pml_eval()\n");
		return -1;
	}

	return (*evaltab[node->base.type])(ast, fr, node, r);
}


void pml_ast_mem_init(struct pml_ast *ast)
{
	struct list *n;
	struct pml_retval r;
	struct pml_variable *v;
	int err;
	byte_t *vp, *cp;
	struct dynbuf *dyb;
	ulong len;
	int i;

	abort_unless(ast);

	dyb = &ast->mi_bufs[PML_SEG_RWMEM];

	memset(dyb->data, 0, dyb->len);

	l_for_each(n, &ast->vars.list) {
		v = (struct pml_variable *)l_to_node(n);
		if (v->type != PML_VTYPE_GLOBAL || v->init == NULL)
			continue;

		err = pml_eval(ast, NULL, (union pml_node *)v->init, &r);
		abort_unless(err == 0);

		vp = dyb->data + v->addr;
		if (r.etype == PML_ETYPE_SCALAR) {
			len = (v->width > 8 ? 8 : v->width);
			for (i = 0; i < len; ++i)
				*vp++ = (r.val >> (56 - i * 8)) & 0xFF;
		} else if (r.etype == PML_ETYPE_BYTESTR) {
			cp = pml_bytestr_ptr(ast, &r.bytes);
			len = (r.bytes.len > v->width ? v->width : r.bytes.len);
			memmove(vp, cp, len);
		} else {
			abort_unless(0);
		}
	}
}


static int pml_opt_cexpr(union pml_expr_u *e, void *astp, union pml_expr_u **ne)
{
	struct pml_retval r;
	struct pml_literal *lit = NULL;
	int rv;

	*ne = NULL;

	if (e != NULL && PML_EXPR_IS_CONST(e) && !PML_EXPR_IS_LITERAL(e)) {

		rv = pml_eval(astp, NULL, (union pml_node *)e, &r);
		if (rv < 0)
			return -1;

		switch(r.etype) {
		case PML_ETYPE_SCALAR:
			lit = (struct pml_literal *)pmln_alloc(PMLTT_SCALAR);
			lit->etype = PML_ETYPE_SCALAR;
			lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;
			lit->width = 8;
			lit->u.scalar = r.val;
			break;

		case PML_ETYPE_BYTESTR:
			lit = (struct pml_literal *)pmln_alloc(PMLTT_BYTESTR);
			lit->etype = PML_ETYPE_BYTESTR;
			lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;
			lit->u.bytestr = r.bytes;
			lit->width = r.bytes.len;
			break;

		case PML_ETYPE_MASKVAL:
			lit = (struct pml_literal *)pmln_alloc(PMLTT_MASKVAL);
			lit->etype = PML_ETYPE_MASKVAL;
			lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;
			lit->u.maskval.val = r.bytes;
			lit->u.maskval.mask = r.mask;
			lit->width = r.bytes.len;
			break;
		}
		*ne = (union pml_expr_u *)lit;
	}

	return 0;
}


/* optimize an expression pointed to by a (union pml_expr_u *) pointer */
static int pml_opt_e_cexpr(union pml_expr_u **e, void *astp)
{
	union pml_expr_u *ne;
	if (pml_opt_cexpr(*e, astp, &ne) < 0)
		return -1;
	if (ne != NULL) {
		pmln_free((union pml_node *)*e);
		*e = ne;
	}
	return 0;
}


/* optimize an expression pointed to by a (union pml_node *) pointer */
static int pml_opt_n_cexpr(union pml_node **e, void *astp)
{
	union pml_expr_u *ne;
	if (pml_opt_cexpr((union pml_expr_u *)*e, astp, &ne) < 0)
		return -1;
	if (ne != NULL) {
		pmln_free(*e);
		*e = (union pml_node *)ne;
	}
	return 0;
}


/* optimize an expression pointed to by a union pml_expr_u * pointer */
/* that is in an expression list. */
static int pml_opt_l_cexpr(union pml_expr_u *e, void *astp)
{
	struct list *prev;
	union pml_expr_u *ne;
	if (pml_opt_cexpr(e, astp, &ne) < 0)
		return -1;
	if (ne != NULL) {
		prev = e->expr.ln.prev;
		l_rem(&e->expr.ln);
		l_ins(prev, &ne->expr.ln);
		pmln_free((union pml_node *)e);
	}
	return 0;
}


static int pml_cexpr_walker(union pml_node *node, void *astp, void *xstk)
{
	struct list *n, *x;

	switch(node->base.type) {

	case PMLTT_VAR: {
		struct pml_variable *v = (struct pml_variable *)node;
		if (v->init != NULL) {
			if (pml_opt_e_cexpr(&v->init, astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_BINOP:
	case PMLTT_UNOP: {
		struct pml_op *op = (struct pml_op *)node;
		if (pml_opt_e_cexpr(&op->arg1, astp) < 0)
			return -1;
		if (op->type == PMLTT_BINOP) {
			if (pml_opt_e_cexpr(&op->arg2, astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_CALL: {
		struct pml_call *c = (struct pml_call *)node;
		l_for_each_safe(n, x, &c->args->list) {
			if (pml_opt_l_cexpr((union pml_expr_u *)l_to_node(n), 
					   astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_IF: {
		struct pml_if *pif = (struct pml_if *)node;
		if (pml_opt_e_cexpr(&pif->test, astp) < 0)
			return -1;
	} break;

	case PMLTT_WHILE: {
		struct pml_while *w = (struct pml_while *)node;
		if (pml_opt_e_cexpr(&w->test, astp) < 0)
			return -1;
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *l = (struct pml_locator *)node;
		if ((pml_opt_e_cexpr(&l->pkt, astp) < 0) ||
		    (pml_opt_e_cexpr(&l->idx, astp) < 0) ||
		    (pml_opt_e_cexpr(&l->off, astp) < 0) ||
		    (pml_opt_e_cexpr(&l->len, astp) < 0))
			return -1;
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *a = (struct pml_assign *)node;
		if (pml_opt_e_cexpr(&a->expr, astp) < 0)
			return -1;
	} break;

	case PMLTT_PRINT: {
		struct pml_print *p = (struct pml_print *)node;
		l_for_each_safe(n, x, &p->args->list) {
			if (pml_opt_l_cexpr((union pml_expr_u *)l_to_node(n),
					   astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_FUNCTION: {
		struct pml_function *f = (struct pml_function *)node;
		if (PML_FUNC_IS_INLINE(f)) {
			if (pml_opt_n_cexpr(&f->body, astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_RULE: {
		struct pml_rule *r = (struct pml_rule *)node;
		if (pml_opt_e_cexpr(&r->pattern, astp) < 0)
			return -1;
	} break;

	default:
		return 0;
	}
	return 0;
}


int pml_ast_optimize(struct pml_ast *ast)
{
	return pml_ast_walk(ast, ast, pml_cexpr_walker, NULL, NULL);
}


void pml_lexv_init(struct pml_lex_val *v)
{
	memset(v, 0, sizeof(*v));
}


void pml_lexv_fini(int toknum, struct pml_lex_val *v)
{
	if (v->type == PMLLV_STRING) {
		free(v->u.raw.data);
		v->u.raw.data = 0;
	}
	memset(v, 0, sizeof(*v));
}


extern void *PMLAlloc(void *(*mallocProc)(size_t));
extern void PMLFree(void *p, void (*freeProc)(void*));
extern void PML(void *parser, int tok, struct pml_lex_val xtok,
		struct pml_ast *ast);


pml_parser_t pml_alloc()
{
	return PMLAlloc(malloc);
}


int pml_parse(pml_parser_t p, struct pml_ast *ast, int tok,
	      struct pml_lex_val xtok)
{
	PML(p, tok, xtok, ast);
	if (ast->error)
		return -1;
	else
		return 0;
}


void pml_free(pml_parser_t p)
{
	PMLFree(p, free);
}


