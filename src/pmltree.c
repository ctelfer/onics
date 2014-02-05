/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * pmltree.c -- Code for managing PML abstract syntax trees.
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
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <cat/aux.h>
#include <cat/str.h>
#include <cat/bitops.h>
#include "pmltree.h"
#include "ns.h"
#include "util.h"


/* macros to simplify list management */
#define l_to_node(p) (union pml_node *)container(p, struct pml_node_base, ln)

#define sym_for_each(_n, _st) l_for_each((_n), &(_st)->list)
#define sym_for_each_safe(_n, _x, _st) l_for_each_safe((_n), (_x), &(_st)->list)

#define for_each_le(_n, _pl) l_for_each((_n), &(_pl)->list)
#define for_each_le_safe(_n, _x, _pl) \
	l_for_each_safe((_n), (_x), &(_pl)->list)

#define for_each_arg(_n, _c) for_each_le(_n, (_c)->args)
#define for_each_arg_safe(_n, _x, _c) \
	for_each_le_safe(_n, _x, (_c)->args)

#define for_each_rvar(_n, _r) sym_for_each((_n), &(_r)->vars)
#define for_each_rvar_safe(_n, _x, _r) \
	sym_for_each_safe((_n), (_x), &(_r)->vars)

#define for_each_fvar(_n, _f) sym_for_each((_n), &(_f)->vars)
#define for_each_fvar_safe(_n, _x, _f) \
	sym_for_each_safe((_n), (_x), &(_f)->vars)

#define for_each_gvar(_n, _ast) sym_for_each(_n, &(_ast)->vars)
#define for_each_gvar_safe(_n, _x, _ast) \
	sym_for_each_safe(_n, _x, &(_ast)->vars)

#define for_each_func(_n, _ast) sym_for_each(_n, &(_ast)->funcs)
#define for_each_func_safe(_n, _x, _ast) \
	sym_for_each_safe(_n, _x, &(_ast)->funcs)

#define for_each_prule(_n, _ast) l_for_each(_n, &(_ast)->p_rules)
#define for_each_prule_safe(_n, _x, _ast) \
	l_for_each_safe(_n, _x, &(_ast)->p_rules)

#define SYMTABSIZE    256


#define SCALAR_SIZE	4
#define LG2_SCALAR_SIZE	2
#define STRREF_SIZE	(SCALAR_SIZE * 2)
#define LG2_STRREF_SIZE	(LG2_SCALAR_SIZE + 1)

static ulong val32(struct pml_ast *ast, struct pml_retval *v);
static const char *nts(int type);
static struct pml_variable *pml_var_alloc_nc(struct pml_ast *ast, char *name, 
				             int vtype, int etype, int size,
				             union pml_expr_u *init);


/* return -1 if conversion from stype to dtype is invalid and 0 otherwise */
static int typecheck(int stype, int dtype)
{
	int valid;

	switch (stype) {
	case PML_ETYPE_VOID:
		valid = dtype == PML_ETYPE_VOID;
		break;

	case PML_ETYPE_SCALAR:
		valid = dtype == PML_ETYPE_VOID ||
		        dtype == PML_ETYPE_SCALAR;
		break;

	case PML_ETYPE_BYTESTR:
		valid = dtype == PML_ETYPE_VOID ||
		        dtype == PML_ETYPE_SCALAR || 
		        dtype == PML_ETYPE_BYTESTR || 
			dtype == PML_ETYPE_STRREF;
		break;

	case PML_ETYPE_MASKVAL:
		valid = dtype == PML_ETYPE_VOID ||
		        dtype == PML_ETYPE_SCALAR || 
		        dtype == PML_ETYPE_BYTESTR ||
		        dtype == PML_ETYPE_MASKVAL; 
		break;

	case PML_ETYPE_STRREF:
		valid = dtype == PML_ETYPE_VOID ||
		        dtype == PML_ETYPE_STRREF;
		break;

	default:
		abort_unless(0);
		valid = 0;
	}

	return valid ? 0 : -1;
}


static int is_expr(void *nodep)
{
	int type;
	if (nodep == NULL)
		return 0;
	type = ((union pml_node *)nodep)->base.type;
	return PML_TYPE_IS_EXPR(type);
}


static void *pml_bytestr_ptr(struct pml_ast *ast, struct pml_bytestr *bs)
{
	struct dynbuf *dyb;
	abort_unless(ast && bs);
       	abort_unless(bs->segnum >= PML_SEG_MIN && bs->segnum <= PML_SEG_MAX);
	abort_unless(bs->ispkt == 0);

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


static void symtab_rem(struct pml_sym *sym) 
{
	ht_rem(&sym->hn);
	l_rem(&sym->ln);
}


static void symtab_destroy(struct pml_symtab *t)
{
	struct list *n, *x;

	abort_unless(t);
	if (t->tab.bkts == NULL)
		return;
	sym_for_each_safe(n, x, t)
		pmln_free(l_to_node(n));
	free(t->tab.bkts);
	t->tab.bkts = NULL;
	abort_unless(l_isempty(&t->list));
}


/* A symbol table can allocate variables in two read-write blocks. */
/* For global variables, the first block is variables with explicit */
/* initializers and the second is for variables without them.  The */
/* program initializeds the latter to 0.  For functions, the first */
/* block is for parameters and the second is for local variables.  */
/* But these no adjustment */
static void symtab_adj_var_addrs(struct pml_symtab *t)
{
	struct list *n;
	struct pml_variable *v;

	abort_unless(t);
	sym_for_each(n, t) {
		v = (struct pml_variable *)l_to_node(n);
		abort_unless(v->vtype == PML_VTYPE_GLOBAL || 
			     v->vtype == PML_VTYPE_CONST);
		if ((v->vtype == PML_VTYPE_GLOBAL) && (v->init == NULL))
			v->addr += t->addr_rw1;
	}
	t->addr_rw2 += t->addr_rw1;
}


static int add_resv_var(struct pml_ast *ast, const char *name,
			int type, ulong size)
{
	char *vname = strdup(name);
	struct pml_variable *v;
	int rv;
	struct pml_symtab *t = &ast->vars;

	if (vname == NULL) {
		pml_ast_err(ast, "out of memory allocating var name '%s'\n",
			    name);
		return -1;
	}
	v = pmln_alloc(ast, PMLTT_VAR);
	if (v == NULL) {
		free(vname);
		return -1;
	}
	v->vtype = PML_VTYPE_GLOBAL;
	v->etype = type;
	v->width = size;
	v->name = vname;
	
	rv = symtab_add(t, (struct pml_sym *)v);
	abort_unless(rv >= 0);
	
	return 0;
}


int pml_ast_init(struct pml_ast *ast)
{
	int i;
	ast->error = 0;
	ast->done = 0;
	if (symtab_init(&ast->vars) < 0)
		return -1;
	if (symtab_init(&ast->funcs) < 0) {
		symtab_destroy(&ast->vars);
		return -1;
	}
	if (add_resv_var(ast, "mem", PML_ETYPE_BYTESTR, 0) < 0)
		return -1;
	ast->b_rule = NULL;
	l_init(&ast->p_rules);
	ast->t_rule = NULL;
	ast->e_rule = NULL;
	for (i = PML_SEG_MIN; i <= PML_SEG_MAX; ++i)
		dyb_init(&ast->mi_bufs[i], NULL);
	dyb_init(&ast->regexes, NULL);
	ast->livefunc = NULL;
	ast->ltab = NULL;
	str_copy(ast->errbuf, "", sizeof(ast->errbuf));
	ast->scanner = NULL;
	ast->parser = NULL;
	return 0;
}


static int _e_pop(struct pml_ast *ast, struct pml_stack_frame *fr,
		  union pml_node *node, struct pml_retval *v)
{
	uint32_t n;

	abort_unless(fr->psz >= sizeof(uint32_t));
	n = *(uint32_t *)fr->stack;
	v->etype = PML_ETYPE_SCALAR;
	v->val = pop_32(n);

	return 0;
}


static int _e_log2(struct pml_ast *ast, struct pml_stack_frame *fr,
		   union pml_node *node, struct pml_retval *v)
{
	uint32_t n;

	abort_unless(fr->psz >= sizeof(uint32_t));
	n = *(uint32_t *)fr->stack;
	v->etype = PML_ETYPE_SCALAR;
	v->val = ilog2_32(n);

	return 0;
}


static int _e_min(struct pml_ast *ast, struct pml_stack_frame *fr,
		  union pml_node *node, struct pml_retval *v)
{
	int32_t n1, n2;

	abort_unless(fr->psz >= 2 * sizeof(uint32_t));
	n1 = *(uint32_t *)fr->stack;
	n2 = *(uint32_t *)(fr->stack + sizeof(uint32_t));
	v->etype = PML_ETYPE_SCALAR;
	v->val = (n1 < n2) ? n1 : n2;

	return 0;
}


static int _e_max(struct pml_ast *ast, struct pml_stack_frame *fr,
		  union pml_node *node, struct pml_retval *v)
{
	int32_t n1, n2;

	abort_unless(fr->psz >= 2 * sizeof(uint32_t));
	n1 = *(uint32_t *)fr->stack;
	n2 = *(uint32_t *)(fr->stack + sizeof(uint32_t));
	v->etype = PML_ETYPE_SCALAR;
	v->val = (n1 > n2) ? n1 : n2;

	return 0;
}


#define _INTP(s) { #s, PML_ETYPE_SCALAR }
#define _SREFP(s) { #s, PML_ETYPE_STRREF }

static struct pml_intrinsic stdintr[] = {
	/* TODO: create eval versions of these and make them PCONST */
	{ "str_len", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _SREFP(ref) } },
	{ "str_addr", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _SREFP(ref) } },
	{ "str_ispkt", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _SREFP(ref) } },
	{ "str_seg", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _SREFP(ref) } },
	{ "str_isnull", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _SREFP(ref) } },
	{ "str_mkref", PML_ETYPE_STRREF, 4, 0, NULL,
		{ _INTP(ispkt), _INTP(seg),
	          _INTP(addr), _INTP(len) } },

	{ "pkt_new", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pnum), _INTP(len) } },
	{ "pkt_new_z", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pnum), _INTP(len) } },
	{ "pkt_swap", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pndst), _INTP(pnsrc) } },
	{ "pkt_copy", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pndst), _INTP(pnsrc) } },
	{ "pkt_ins_u", PML_ETYPE_VOID, 3, 0, NULL,
		{ _INTP(pnum), _INTP(off), _INTP(len) } },
	{ "pkt_ins_d", PML_ETYPE_VOID, 3, 0, NULL,
		{ _INTP(pnum), _INTP(off), _INTP(len) } },
	{ "pkt_cut_u", PML_ETYPE_VOID, 1, 0, NULL, { _SREFP(str) } },
	{ "pkt_cut_d", PML_ETYPE_VOID, 1, 0, NULL, { _SREFP(str) } },
	{ "pkt_parse", PML_ETYPE_VOID, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "pkt_get_off", PML_ETYPE_SCALAR, 4, 0, NULL,
		{ _INTP(pnum), _INTP(prid), _INTP(idx), _INTP(oid) } },
	{ "pkt_adj_off", PML_ETYPE_VOID, 5, 0, NULL,
		{ _INTP(pnum), _INTP(prid), _INTP(idx), _INTP(oid),
		  _INTP(amt) } },
	{ "pkt_nlists", PML_ETYPE_SCALAR, 0, 0, NULL, { } },
	{ "pkt_lempty", PML_ETYPE_SCALAR, 1, 0, NULL, { _INTP(list) } },
	{ "pkt_enq", PML_ETYPE_VOID, 2, 0, NULL, {_INTP(list), _INTP(pnum)} },
	{ "pkt_deq", PML_ETYPE_VOID, 2, 0, NULL, {_INTP(list), _INTP(pnum)} },
	{ "pkt_push", PML_ETYPE_VOID, 2, 0, NULL, {_INTP(list), _INTP(pnum)} },
	{ "pkt_pop", PML_ETYPE_VOID, 2, 0, NULL, {_INTP(list), _INTP(pnum)} },
	{ "parse_push_back", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pnum), _INTP(prid) } },
	{ "parse_pop_back", PML_ETYPE_VOID, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "parse_push_front", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pnum), _INTP(prid) } },
	{ "parse_pop_front", PML_ETYPE_VOID, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "parse_update", PML_ETYPE_VOID, 1, 0, NULL,
		{ _INTP(pdesc) } },
	{ "fix_dltype", PML_ETYPE_VOID, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "fix_len", PML_ETYPE_VOID, 1, 0, NULL,
		{ _INTP(pdesc) } },
	{ "fix_lens", PML_ETYPE_VOID, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "fix_csum", PML_ETYPE_VOID, 1, 0, NULL,
		{ _INTP(pdesc) } },
	{ "fix_csums", PML_ETYPE_VOID, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "meta_get_ts_sec", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "meta_get_ts_nsec", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "meta_set_ts", PML_ETYPE_VOID, 3, 0, NULL,
		{ _INTP(pnum), _INTP(sec), _INTP(nsec) } },
	{ "meta_get_presnap", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "meta_set_presnap", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pnum), _INTP(val) } },
	{ "meta_get_inport", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "meta_set_inport", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pnum), _INTP(val) } },
	{ "meta_get_outport", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "meta_set_outport", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pnum), _INTP(val) } },
	{ "meta_get_flowid", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "meta_set_flowid", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pnum), _INTP(val) } },
	{ "meta_get_class", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "meta_set_class", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pnum), _INTP(val) } },
	{ "meta_get_seq", PML_ETYPE_SCALAR, 1, 0, NULL,
		{ _INTP(pnum) } },
	{ "meta_set_seq", PML_ETYPE_VOID, 2, 0, NULL,
		{ _INTP(pnum), _INTP(val) } },
	{ "meta_has", PML_ETYPE_SCALAR, 2, 0, NULL, 
		{ _INTP(pnum), _INTP(type), } },
	{ "meta_add", PML_ETYPE_VOID, 2, 0, NULL, 
		{ _INTP(pnum), _INTP(type), } },
	{ "meta_add_info", PML_ETYPE_VOID, 2, 0, NULL, 
		{ _INTP(pnum), _INTP(numw), } },
	{ "meta_rem", PML_ETYPE_VOID, 2, 0, NULL, 
		{ _INTP(pnum), _INTP(type), } },
	{ "meta_rd8", PML_ETYPE_SCALAR, 3, 0, NULL, 
		{ _INTP(pnum), _INTP(type), _INTP(off) } },
	{ "meta_rd16", PML_ETYPE_SCALAR, 3, 0, NULL, 
		{ _INTP(pnum), _INTP(type), _INTP(off) } },
	{ "meta_rd32", PML_ETYPE_SCALAR, 3, 0, NULL, 
		{ _INTP(pnum), _INTP(type), _INTP(off) } },
	{ "meta_wr8", PML_ETYPE_VOID, 4, 0, NULL, 
		{ _INTP(pnum), _INTP(type), _INTP(off), _INTP(val) } },
	{ "meta_wr16", PML_ETYPE_VOID, 4, 0, NULL, 
		{ _INTP(pnum), _INTP(type), _INTP(off), _INTP(val) } },
	{ "meta_wr32", PML_ETYPE_VOID, 4, 0, NULL, 
		{ _INTP(pnum), _INTP(type), _INTP(off), _INTP(val) } },
	{ "exit", PML_ETYPE_VOID, 1, 0, NULL,
		{ _INTP(rval) } },
	{ "pop", PML_ETYPE_SCALAR, 1, PML_FF_PCONST|PML_FF_INLINE, _e_pop,
		{ _INTP(num) } },
	{ "log2", PML_ETYPE_SCALAR, 1, PML_FF_PCONST|PML_FF_INLINE, _e_log2,
		{ _INTP(num) } },
	{ "min", PML_ETYPE_SCALAR, 2, PML_FF_PCONST|PML_FF_INLINE, _e_min,
		{ _INTP(num1), _INTP(num2) } },
	{ "max", PML_ETYPE_SCALAR, 2, PML_FF_PCONST|PML_FF_INLINE, _e_max,
		{ _INTP(num1), _INTP(num2) } },
};

#undef _INTP
#undef _SREFP


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


void pml_ast_set_parser(struct pml_ast *ast, struct pmllex *scanner,
		        pml_parser_t *parser)
{
	if (ast->scanner != NULL || ast->parser != NULL)
		pml_ast_free_parser(ast);
	ast->scanner = scanner;
	ast->parser = parser;
}


void pml_ast_free_parser(struct pml_ast *ast)
{
	if (ast->scanner != NULL) {
		pmll_free(ast->scanner);
		ast->scanner = NULL;
	}
	if (ast->parser != NULL) {
		pml_free(ast->parser);
		ast->parser = NULL;
	}
}


void pml_ast_clear(struct pml_ast *ast)
{
	struct list *n, *x;
	int i;

	pml_ast_free_parser(ast);

	ast->error = 0;
	ast->done = 0;

	symtab_destroy(&ast->vars);
	symtab_destroy(&ast->funcs);

	pmln_free(ast->b_rule);
	ast->b_rule = NULL;

	for_each_prule_safe(n, x, ast)
		pmln_free(l_to_node(n));
	abort_unless(l_isempty(&ast->p_rules));

	pmln_free(ast->t_rule);
	ast->t_rule = NULL;

	pmln_free(ast->e_rule);
	ast->e_rule = NULL;

	for (i = PML_SEG_MIN; i <= PML_SEG_MAX; ++i)
		dyb_clear(&ast->mi_bufs[i]);
	dyb_clear(&ast->regexes);

	ast->livefunc = NULL;
	ast->ltab = NULL;

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


void pml_ast_clear_err(struct pml_ast *ast)
{
	ast->errbuf[0] = '\0';
	ast->error = 0;
}


struct pml_function *pml_ast_lookup_func(struct pml_ast *ast, char *name)
{
	return (struct pml_function *)symtab_lookup(&ast->funcs, name);
}


int pml_check_func_proto(struct pml_ast *ast, struct pml_function *f1,
			 struct pml_function *f2)
{
	struct list *n1, *n2;
	struct pml_variable *v1, *v2;
	int i;

	if (f1->rtype != f2->rtype || f1->arity != f2->arity ||
	    f1->flags != f2->flags) {
		pml_ast_err(ast,
			    "Function %s does not match prototype\n",
			    f1->name);
	}

	n1 = l_head(&f1->vars.list);
	n2 = l_head(&f2->vars.list);
	for (i = 0; i < f1->arity; ++i) {
		v1 = (struct pml_variable *)l_to_node(n1);
		v2 = (struct pml_variable *)l_to_node(n2);
		if (v1->etype != v2->etype || 
		    v1->width != v2->width || 
		    strcmp(v1->name, v2->name) != 0) {
			pml_ast_err(ast, "Parameter %d in function '%s' does"
					 " not match prototype declaration",
				    f1->name, i+1);
			return -1;
		}
		n1 = n1->next;
		n2 = n2->next;
	}

	return 0;
}


int pml_ast_add_func_proto(struct pml_ast *ast, struct pml_function *func)
{
	if (PML_FUNC_IS_INLINE(func)) {
		pml_ast_err(ast,
			    "Attempt to add protoype for inline function: %s\n",
			    func->name);
		return -1;
	}

	if (PML_FUNC_IS_INTRINSIC(func)) {
		pml_ast_err(ast,
			    "Attempt to add protoype for intrinsic function:"
			    " %s\n", func->name);
		return -1;
	}

	abort_unless(symtab_lookup(&ast->funcs, func->name) == NULL);
	abort_unless(func->body == NULL);
	symtab_add(&ast->funcs, (struct pml_sym *)func);

	return 0;
}


int pml_ast_add_func(struct pml_ast *ast, struct pml_function *func)
{
	symtab_add(&ast->funcs, (struct pml_sym *)func);

	if (pml_resolve_refs(ast, (union pml_node *)func) < 0)
		return -1;

	return 0;
}


int pml_ast_add_intrinsic(struct pml_ast *ast, struct pml_intrinsic *intr)
{
	struct pml_function *f = NULL;
	struct pml_variable *v;
	int i;

	abort_unless(intr && intr->name && intr->arity >= 0 && ast);
	abort_unless((intr->flags & 
			~(PML_FF_INLINE|PML_FF_INTRINSIC|PML_FF_PCONST)) == 0);
	

	if (symtab_lookup(&ast->funcs, intr->name) != NULL) {
		pml_ast_err(ast, "Duplicate function: %s\n", intr->name);
		return -1;
	}

	f = pmln_alloc(ast, PMLTT_FUNCTION);
	if (f == NULL)
		return -1;

	if ((f->name = strdup(intr->name)) == NULL)
		goto enomem;
	for (i = 0; i < intr->arity; ++i) {
		abort_unless(intr->params[i].name);
		v = pml_var_alloc_nc(ast, intr->params[i].name, PML_VTYPE_PARAM,
				     intr->params[i].etype, 0, NULL);
		if (v == NULL)
			goto enomem;
		if (pml_func_add_param(f, v) < 0) {
			pmln_free(f);
			return -1;
		}
	}
	f->rtype = intr->rtype;
	f->arity = intr->arity;
	f->ieval = intr->eval;
	f->flags = intr->flags | PML_FF_INTRINSIC;
	f->pstksz = f->arity * sizeof(uint32_t);
	f->vstksz = 0;

	abort_unless(symtab_add(&ast->funcs, (struct pml_sym *)f) >= 0);

	return 0;

enomem:
	pmln_free(f);
	return -1;
}


struct pml_variable *pml_ast_lookup_var(struct pml_ast *ast, char *name)
{
	return (struct pml_variable *)symtab_lookup(&ast->vars, name);
}


int pml_ast_add_var(struct pml_ast *ast, struct pml_variable *var)
{
	uint32_t max;

	if (symtab_add(&ast->vars, (struct pml_sym *)var) < 0) {
		pml_ast_err(ast, "Duplicate global variable: %s\n", var->name);
		return -1;
	}

	if (pml_resolve_refs(ast, (union pml_node *)var) < 0)
		return -1;

	if (var->vtype != PML_VTYPE_CONST) {
		/* NOTE: pad global vars to SCALAR_SIZE-byte sizes */
		max = (uint32_t)-1 - ast->vars.addr_rw1 - ast->vars.addr_rw2;
		if (rup2_32(var->width, LG2_SCALAR_SIZE) > max) {
			pml_ast_err(ast, 
				    "global read-write address space overflow");
			return -1;
		}
		if (var->init != NULL) {
			var->addr = ast->vars.addr_rw1;
			ast->vars.addr_rw1 += rup2_32(var->width, LG2_SCALAR_SIZE);
		} else { 
			var->addr = ast->vars.addr_rw2;
			ast->vars.addr_rw2 += rup2_32(var->width, LG2_SCALAR_SIZE);
		}
	}

	return 0;
}


int pml_ast_add_rule(struct pml_ast *ast, struct pml_rule *rule)
{
	struct pml_list *olist, *nlist;
	abort_unless(rule->trigger >= PML_RULE_BEGIN &&
		     rule->trigger <= PML_RULE_END);
	switch(rule->trigger) {
	case PML_RULE_BEGIN:
		abort_unless(rule->pattern == NULL);
		if (ast->b_rule == NULL) {
			ast->b_rule = rule;
		} else {
			olist = ast->b_rule->stmts;
			nlist = rule->stmts;
			l_append(&olist->list, &nlist->list);
			pmln_free(rule);
			rule = ast->b_rule;
		}
		break;
	case PML_RULE_PACKET:
		l_enq(&ast->p_rules, &rule->ln);
		break;
	case PML_RULE_TICK:
		if (ast->t_rule == NULL) {
			ast->t_rule = rule;
		} else {
			olist = ast->t_rule->stmts;
			nlist = rule->stmts;
			l_append(&olist->list, &nlist->list);
			pmln_free(rule);
			rule = ast->t_rule;
		}
		break;
	case PML_RULE_END:
		if (ast->e_rule == NULL) {
			ast->e_rule = rule;
		} else {
			olist = ast->e_rule->stmts;
			nlist = rule->stmts;
			l_append(&olist->list, &nlist->list);
			pmln_free(rule);
			rule = ast->e_rule;
		}
		break;
	}
	if (pml_resolve_refs(ast, (union pml_node *)rule) < 0)
		return -1;
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
	f->vars.addr_rw1 += v->width / sizeof(uint32_t);
	v->func = f;

	return 0;
}


int pml_func_add_var(struct pml_symtab *t, struct pml_function *f,
		     struct pml_variable *v)
{
	abort_unless(v && v->vtype == PML_VTYPE_LOCAL);
	if (symtab_add(t, (struct pml_sym *)v) < 0)
		return -1;
	v->addr = t->addr_rw2;
	t->addr_rw2 += (v->width + (SCALAR_SIZE - 1)) / SCALAR_SIZE;
	v->func = f;

	return 0;
}


int pml_ast_add_regex(struct pml_ast *ast, struct pml_literal *lit)
{
	if (dyb_cat_a(&ast->regexes, &lit, sizeof(lit)) < 0) {
		pml_ast_err(ast, "out of memory adding regex\n");
		return -1;
	}
	return 0;
}


void pml_ast_get_rexarr(struct pml_ast *ast, struct pml_literal ***larr,
			ulong *alen)
{
	struct dynbuf *db = &ast->regexes;
	*larr = (struct pml_literal **)db->data;
	*alen = db->len / sizeof(struct pml_literal *);
}


static void check_undefined_funcs(struct pml_ast *ast)
{
	struct list *n;
	struct pml_function *func;

	for_each_func(n, ast) {
		func = (struct pml_function *)l_to_node(n);
		if ((func->callers > 0) && PML_FUNC_IS_REGULAR(func) &&
		    (func->body == NULL)) {
			pml_ast_err(ast,
				    "Undefined function '%s' called %u times\n",
				    func->name, func->callers);
			return;
		}
	}
}


void pml_ast_finalize(struct pml_ast *ast)
{
	struct pml_variable *v;
	ulong gsz;

	if (ast->error)
		return;

	check_undefined_funcs(ast);
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
	pml_ast_mem_init(ast);

	/* adjust the size of the global memory region */
	v = (struct pml_variable *)symtab_lookup(&ast->vars, "mem");
	abort_unless(v != NULL);
	v->addr = 0;
	v->width = gsz;
}


static union pml_node *_pmln_alloc(int type)
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
	memset(&node->cgctx, 0, PML_CGCTX_SIZE);

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
			p->width = SCALAR_SIZE;
		} else if (type == PMLTT_BYTESTR) {
			p->etype = PML_ETYPE_BYTESTR;
			p->u.bytestr.ispkt = 0;
			p->u.bytestr.addr = 0;
			p->u.bytestr.len = 0;
			p->u.bytestr.segnum = PML_SEG_NONE;
		} else if (type == PMLTT_MASKVAL) {
			p->etype = PML_ETYPE_MASKVAL;
			p->u.maskval.val.ispkt = 0;
			p->u.maskval.val.addr = 0;
			p->u.maskval.val.len = 0;
			p->u.maskval.val.segnum = PML_SEG_NONE;
			p->u.maskval.mask.ispkt = 0;
			p->u.maskval.mask.addr = 0;
			p->u.maskval.mask.len = 0;
			p->u.maskval.mask.segnum = PML_SEG_NONE;
		}
	} break;

	case PMLTT_UNOP:
	case PMLTT_BINOP: {
		struct pml_op *p = &np->op;
		p->etype = PML_ETYPE_UNKNOWN;
		p->eflags = 0;
		p->width = SCALAR_SIZE;
		p->op = 0;
		p->arg1 = NULL;
		p->arg2 = NULL;
		return (union pml_node *)p;
	} break;

	case PMLTT_CALL: {
		struct pml_call *p = &np->call;
		p->etype = PML_ETYPE_SCALAR;
		p->eflags = 0;
		p->width = SCALAR_SIZE;
		p->func = NULL;
		p->args = NULL;
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *p = &np->locator;
		p->eflags = 0;
		if (type == PMLTT_LOCATOR) {
			p->etype = PML_ETYPE_UNKNOWN;
			p->width = 0;
		} else {
			p->etype = PML_ETYPE_STRREF;
			p->width = STRREF_SIZE;
		}
		p->reftype = PML_REF_UNKNOWN;
		p->rpfld = PML_RPF_NONE;
		p->name = NULL;
		p->pkt = NULL;
		p->idx = NULL;
		p->off = NULL;
		p->len = NULL;
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
		p->expr = NULL;
		p->width = 0;
		p->fmt = PML_FMT_UNKNOWN;
		p->flags = 0;
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &np->variable;
		ht_ninit(&p->hn, "", p);
		p->vtype = PML_VTYPE_UNKNOWN;
		p->etype = PML_ETYPE_UNKNOWN;
		p->width = 0;
		p->name = NULL;
		p->init = NULL;
		p->func = NULL;
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
		p->name = NULL;
		p->arity = 0;
		p->callers = 0;
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


void *pmln_alloc(struct pml_ast *ast, int type)
{
	union pml_node *n;

	abort_unless(ast != NULL);
	n = _pmln_alloc(type);
	if (n == NULL)
		pml_ast_err(ast, "Out of memory allocating '%s'-type node\n",
			    nts(type));

	return n;
}


void pmln_free(void *nodep)
{
	union pml_node *node = nodep;
	if (node == NULL)
		return;

	/* remove from whatever list it is on, if any */
	l_rem(&node->base.ln);

	switch (node->base.type) {

	case PMLTT_LIST: {
		struct pml_list *p = &node->list;
		struct list *l;
		while ((l = l_deq(&p->list)) != NULL)
			pmln_free(l_to_node(l));
	} break;

	case PMLTT_SCALAR:
	case PMLTT_BYTESTR:
	case PMLTT_MASKVAL:
		break;

	case PMLTT_BINOP: {
		struct pml_op *p = &node->op;
		pmln_free(p->arg1);
		pmln_free(p->arg2);
	} break;

	case PMLTT_UNOP: {
		struct pml_op *p = &node->op;
		pmln_free(p->arg1);
	} break;

	case PMLTT_CALL: {
		struct pml_call *p = &node->call;
		pmln_free(p->args);
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *p = &node->locator;
		free(p->name);
		pmln_free(p->pkt);
		pmln_free(p->idx);
		pmln_free(p->off);
		pmln_free(p->len);
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &node->ifstmt;
		pmln_free(p->test);
		pmln_free(p->tbody);
		pmln_free(p->fbody);
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &node->whilestmt;
		pmln_free(p->test);
		pmln_free(p->body);
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *p = &node->assign;
		pmln_free(p->loc);
		pmln_free(p->expr);
	} break;

	case PMLTT_CFMOD: {
		struct pml_cfmod *p = &node->cfmod;
		pmln_free(p->expr);
	} break;

	case PMLTT_PRINT: {
		struct pml_print *p = &node->print;
		pmln_free(p->expr);
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &node->variable;
		symtab_rem((struct pml_sym *)p);
		free(p->name);
		pmln_free(p->init);
	} break;

	case PMLTT_FUNCTION: {
		struct pml_function *p = &node->function;
		symtab_rem((struct pml_sym *)p);
		free(p->name);
		p->name = NULL;
		symtab_destroy(&p->vars);
		pmln_free(p->body);
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &node->rule;
		pmln_free(p->pattern);
		pmln_free(p->stmts);
	} break;

	default:
		abort_unless(0);
	}

	free(node);
}


union pml_expr_u *pml_binop_alloc(struct pml_ast *ast, int op, 
				  union pml_expr_u *left, 
		                  union pml_expr_u *right)
{
	struct pml_op *o = pmln_alloc(ast, PMLTT_BINOP);
	if (o != NULL) {
		o->op = op;
		o->arg1 = left;
		o->arg2 = right;
	} else {
		pmln_free(left);
		pmln_free(right);
	}
	return (union pml_expr_u *)o;
}


union pml_expr_u *pml_unop_alloc(struct pml_ast *ast, int op,
				 union pml_expr_u *ex)
{
	struct pml_op *o = pmln_alloc(ast, PMLTT_UNOP);
	if (o != NULL) {
		o->op = op;
		o->arg1 = ex;
	} else {
		pmln_free(ex);
	}
	return (union pml_expr_u *)o;
}


static int find_gstr_init_size(union pml_expr_u *init)
{
	struct pml_literal *lit;
	struct pml_locator *loc;
	struct ns_elem *e;
	struct ns_bytestr *bs;

	if (PML_EXPR_IS_SCALAR(init)) {
		return SCALAR_SIZE;
	} else if (PML_EXPR_IS_BYTESTR(init)) {
		abort_unless(init->expr.type == PMLTT_BYTESTR);
		lit = &init->literal;
		if (lit->u.bytestr.len > INT_MAX)
			return -1;
		return lit->u.bytestr.len;
	} else if (init->expr.etype == PML_ETYPE_UNKNOWN &&
	   	   init->expr.type == PMLTT_LOCATOR) {
		/* check for protocol constants: all others are errors */
		loc = &init->loc;
		/* we do not currently allow slices of protocol constants */
		if (loc->pkt != NULL || loc->idx != NULL || loc->off != NULL ||
		    loc->len != NULL)
			return -1;

		e = ns_lookup(NULL, loc->name);
		if (e == NULL)
			return -1;

		if (e->type == NST_SCALAR) {
			return SCALAR_SIZE;
		} else if (e->type == NST_BYTESTR) {
			bs = (struct ns_bytestr *)e;
			if (bs->value.len > INT_MAX)
				return -1;
			return bs->value.len;
		} else {
			return -1;
		}
	} else {
		return -1;
	}
}


struct pml_variable *pml_var_alloc(struct pml_ast *ast, char *name, 
				   int vtype, int etype, int size,
				   union pml_expr_u *init)
{
	struct pml_variable *v = pmln_alloc(ast, PMLTT_VAR);

	if (v == NULL) {
		free(name);
		pmln_free(init);
		return NULL;
	}

	v->name = name;
	v->etype = etype;
	v->vtype = vtype;
	if (etype == PML_ETYPE_SCALAR) {
		v->width = SCALAR_SIZE;
	} else if (etype == PML_ETYPE_STRREF) {
		v->width = STRREF_SIZE;
	} else {
		if (size < 0) {
			abort_unless(init != NULL);
			abort_unless(vtype == PML_VTYPE_GLOBAL);
			size = find_gstr_init_size(init);
			if (size < 0) {
				free(name);
				pmln_free(init);
				pmln_free(v);
				return NULL;
			}
		}
		v->width = size;
		v->etype = PML_ETYPE_BYTESTR;
	}
	v->init = init;

	return v;
}


static struct pml_variable *pml_var_alloc_nc(struct pml_ast *ast, char *name, 
				             int vtype, int etype, int size,
				             union pml_expr_u *init)
{
	struct pml_variable *v;
	char *nc = strdup(name);

	if (nc == NULL)
		return NULL;
	v = pml_var_alloc(ast, nc, vtype, etype, size, init);
	if (v == NULL)
		free(nc);

	return v;
}


struct pml_call *pml_call_alloc(struct pml_ast *ast, struct pml_function *func,
				struct pml_list *args)
{
	uint alen;
	struct pml_call *c;

	alen = l_length(&args->list);
	if (alen != func->arity) {
		pml_ast_err(ast, "argument length for call of '%s' does"
				 "not match function arity (%u vs %u)\n",
			    func->name, alen, func->arity);
		return NULL;
	}

	c = pmln_alloc(ast, PMLTT_CALL);
	if (c == NULL) {
		pmln_free(args);
		return NULL;
	}


	c->func = func;
	c->args = args;
	c->etype = func->rtype;
	switch (c->etype) {
	case PML_ETYPE_SCALAR:
		c->width = SCALAR_SIZE;
		break;
	case PML_ETYPE_STRREF:
		c->etype = PML_ETYPE_BYTESTR;
		c->width = STRREF_SIZE;
		break;
	case PML_ETYPE_VOID:
		c->width = 0;
		break;
	default:
		abort_unless(0);
	}
	c->eflags = 0;
	func->callers++;

	return c;
}


struct pml_print *pml_print_alloc(struct pml_ast *ast, union pml_expr_u *expr,
				  const struct pml_print_fmt *fmt)
{
	struct pml_print *p = pmln_alloc(ast, PMLTT_PRINT);

	if (p == NULL) {
		pmln_free(expr);
		return NULL;
	}

	abort_unless(expr);
	p->expr = expr;
	if (fmt != NULL) {
		p->width = fmt->width;
		p->fmt = fmt->fmt;
		p->flags = fmt->flags;
	}

	return p;
}


static const char *fmt_strs[] = {
	NULL, "b", "o", "d", "u", "x", "s", "hex", "ip", "ip6", "eth"
};
int pml_print_strtofmt(const char *s)
{
	int i;
	for (i = 1; i < PML_FMT_NUM; ++i)
		if (strcmp(fmt_strs[i], s) == 0)
			return i;
	return PML_FMT_UNKNOWN;
}


void pml_prlist_free(struct pml_print *p)
{
	union pml_node *n;
	while ((n = l_to_node(l_pop(&p->ln))) != NULL)
		pmln_free(n);
	pmln_free((union pml_node *)p);
}


int pml_bytestr_copy(struct pml_ast *ast, struct pml_bytestr *bs, int seg,
		     void *data, ulong len)
{
	int r;
	abort_unless(ast && bs && data && len > 0);

	if (seg < PML_SEG_MIN || seg > PML_SEG_MAX) {
		pml_ast_err(ast, "Invalid segment for bytestr copy: %d\n", seg);
		return -1;
	}

	bs->ispkt = 0;
	bs->segnum = seg;
	bs->addr = dyb_last(&ast->mi_bufs[seg]);
	bs->len = len;
	r = dyb_cat_a(&ast->mi_bufs[seg], data, len);
	if (r < 0)
		pml_ast_err(ast, "out of memory in bytestr copy\n");
	return r;
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


static const char *nt_strs[] = {
	"list", "scalar", "byte string", "mask string", "binary operator",
	"unary operator", "call", "locator", "location address", 
	"if statement", "while statement", "assignment",
	"control flow modifier", "print", "variable", "function", "rule"
};


static const char *nts(int type)
{
	if ((type >= PMLTT_LIST) && (type <= PMLTT_RULE))
		return nt_strs[type];
	else
		return "INVALID!";
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
	"unknown", "void", "scalar", "byte string", "masked string", 
	"string reference"
};
static const char *ets(void *p) {
	struct pml_expr_base *e = p;
	abort_unless(p);
	abort_unless(e->etype <= PML_ETYPE_LAST);
	return etype_strs[e->etype];
}


static const char *pts(struct pml_variable *v) {
	abort_unless(v);
	abort_unless(v->etype <= PML_ETYPE_LAST);
	return etype_strs[v->etype];
}


static const char *rtstr(void *p) {
	struct pml_function *f = p;
	abort_unless(p);
	abort_unless(f->rtype <= PML_ETYPE_LAST);
	return etype_strs[f->rtype];
}


static const char *vtype_strs[] = {
	"unknown", "const", "global", "param", "local"
};
static const char *vts(struct pml_variable *v)
{
	abort_unless(v && v->vtype <= PML_VTYPE_LOCAL);
	return vtype_strs[v->vtype];
}


static const char *rtype_strs[] = {
	"unknown", "unknown namespace element", "variable",
	"packet field", "proto const",
};
static const char *rts(struct pml_locator *l)
{
	abort_unless(l && l->reftype >= PML_REF_UNKNOWN &&
		     l->reftype <= PML_REF_LITERAL);
	return rtype_strs[l->reftype];
}


static const char *rule_trigger_strs[] = {
	"begin", "packet", "tick", "end"
};
const char *rulestr(struct pml_rule *r)
{
	abort_unless(r && r->trigger >= PML_RULE_BEGIN &&
		     r->trigger <= PML_RULE_END);
	return rule_trigger_strs[r->trigger];
}


static const char *fmt_names[] = {
	"unknown", "binary", "octal", "signed decimal", "unsigned",
	"hexadecimal", "string", "hex string", "IP address", "IPv6 Address",
	"802 Address"
};
const char *fmtstr(struct pml_print *p)
{
	abort_unless(p && p->fmt >= PML_FMT_UNKNOWN &&
		     p->fmt < PML_FMT_NUM);
	return fmt_names[p->fmt];
}


char *fflagstr(struct pml_print *p)
{
	static char s[16];
	str_copy(s, "[", sizeof(s));
	if (p->flags & PML_PFLAG_LJUST)
		str_cat(s, "l", sizeof(s));
	if (p->flags & PML_PFLAG_NEWLINE)
		str_cat(s, "n", sizeof(s));
	str_cat(s, "]", sizeof(s));
	return s;
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
	"unknown", "return", "break", "continue", "nextrule", "send(all)",
	"drop(all)", "send(one)", "drop(one)", "send w/o free"
};
static const char *cfmstr(struct pml_cfmod *m)
{
	abort_unless(m && m->cftype >= PML_CFM_UNKNOWN && 
		     m->cftype <= PML_CFM_SENDNOFREE);
	return cfm_strs[m->cftype];
}


static const char *rpfld_strs[] = {
	"**UNALLOWED**", "exists", 
	"hlen", "plen", "tlen", "totlen", "error", "prid",
	"index", "header", "payload", "trailer", "parse"
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
		for_each_le(e, p) {
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
		       (long)signxul(p->u.scalar, 32), 
		       (p->u.scalar & 0xFFFFFFFFul),
		       (p->u.scalar & 0xFFFFFFFFul));
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
		} else if (p->reftype == PML_REF_LITERAL) {
			indent(depth);
			printf("Constant --\n");
			pmlt_print(ast, (union pml_node *)p->u.litref, depth+1);
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
		printf("Print Statement: type: %s, width:%lu, flags:%s\n", 
		       fmtstr(p), p->width, fflagstr(p));
		if (p->expr != NULL) {
			indent(depth);
			printf("Expression -- \n");
			pmlt_print(ast, (union pml_node *)p->expr, depth+1);
		}
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

	case PMLTT_FUNCTION: {
		struct pml_function *p = &np->function;
		struct list *n;
		indent(depth);
		printf("%s: %s() -- %d args, %d-byte stack, return type=%s\n",
		       funcstr(p, estr), p->name, p->arity, (int)p->vstksz,
		       rtstr(p));

		indent(depth);
		printf("Parameters & Variables -- \n");
		for_each_fvar(n, p)
			pmlt_print(ast, l_to_node(n), depth+1);

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
		for_each_rvar(n, p)
			pmlt_print(ast, l_to_node(n), depth+1);

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
	for_each_gvar(n, ast)
		pmlt_print(ast, l_to_node(n), 1);
	printf("-----------\n");
	printf("Functions\n");
	printf("-----------\n");
	for_each_func(n, ast)
		pmlt_print(ast, l_to_node(n), 1);
	printf("-----------\n");
	printf("Begin Rule\n");
	printf("-----------\n");
	pmlt_print(ast, (union pml_node *)ast->b_rule, 1);
	printf("-----------\n");
	printf("Packet Rules\n");
	printf("-----------\n");
	for_each_prule(n, ast)
		pmlt_print(ast, l_to_node(n), 1);
	printf("-----------\n");
	printf("Tick Rule\n");
	printf("-----------\n");
	pmlt_print(ast, (union pml_node *)ast->t_rule, 1);
	printf("-----------\n");
	printf("-----------\n");
	printf("End Rule\n");
	printf("-----------\n");
	pmlt_print(ast, (union pml_node *)ast->e_rule, 1);
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
		for_each_le_safe(e, x, p) {
			rv = pmln_walk(l_to_node(e), ctx, pre, in, post);
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

	case PMLTT_IF: {
		struct pml_if *p = &np->ifstmt;

		rv = pmln_walk((union pml_node *)p->test, ctx, pre, in, post);
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

		rv = pmln_walk((union pml_node *)p->tbody, ctx, pre, in, post);
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

		if (in != NULL) {
			rv = (*in)((union pml_node *)p, ctx, xstk);
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

	case PMLTT_ASSIGN: {
		struct pml_assign *p = &np->assign;

		rv = pmln_walk((union pml_node *)p->loc, ctx, pre, in, post);
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

		rv = pmln_walk((union pml_node *)p->expr, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
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

	case PMLTT_FUNCTION: {
		struct pml_function *p = &np->function;
		struct list *n;

		for_each_fvar_safe(n, x, p) {
			rv = pmln_walk(l_to_node(n), ctx, pre, in, post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		if (in != NULL) {
			rv = (*in)((union pml_node *)p, ctx, xstk);
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

		if (in != NULL) {
			rv = (*in)((union pml_node *)p, ctx, xstk);
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

	for_each_gvar(n, ast) {
		rv = pmln_walk(l_to_node(n), ctx, pre, in, post);
		if (rv < 0)
			goto out;
	}
	for_each_func(n, ast) {
		rv = pmln_walk(l_to_node(n), ctx, pre, in, post);
		if (rv < 0)
			goto out;
	}
	rv = pmln_walk((union pml_node *)ast->b_rule, ctx, pre, in, post);
	if (rv < 0)
		goto out;
	for_each_prule(n, ast) {
		rv = pmln_walk(l_to_node(n), ctx, pre, in, post);
		if (rv < 0)
			goto out;
	}
	rv = pmln_walk((union pml_node *)ast->t_rule, ctx, pre, in, post);
	if (rv < 0)
		goto out;
	rv = pmln_walk((union pml_node *)ast->e_rule, ctx, pre, in, post);
	if (rv < 0)
		goto out;
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


struct pml_literal *pml_lookup_ns_literal(struct pml_ast *ast, 
					  struct pml_locator *l)
{
	struct pml_literal *lit = NULL;
	struct ns_elem *e;

	abort_unless(l);
	e = ns_lookup(NULL, l->name);
	if (e == NULL)
		return NULL;

	if (e->type == NST_BYTESTR) {
		struct ns_bytestr *nbs;
		lit = pmln_alloc(ast, PMLTT_BYTESTR);
		if (lit == NULL)
			return NULL;

		nbs = (struct ns_bytestr *)e;
		if (pml_bytestr_copy(ast, &lit->u.bytestr, PML_SEG_ROMEM,
				     nbs->value.data, nbs->value.len) < 0) {
			pmln_free((union pml_node *)lit);
			return NULL;
		}
	} else if (e->type == NST_MASKSTR) {
		struct ns_maskstr *ms;
		lit = pmln_alloc(ast, PMLTT_MASKVAL);
		if (lit == NULL)
			return NULL;

		ms = (struct ns_maskstr *)e;
		if ((pml_bytestr_copy(ast, &lit->u.maskval.val, PML_SEG_ROMEM,
				      ms->value.data, ms->value.len) < 0) ||
		    (pml_bytestr_copy(ast, &lit->u.maskval.mask, PML_SEG_ROMEM,
				      ms->mask.data, ms->mask.len) < 0)) {
			pmln_free((union pml_node *)lit);
			return NULL;
		}
	} else if (e->type == NST_SCALAR) {
		struct ns_scalar *sc;
		lit = pmln_alloc(ast, PMLTT_SCALAR);
		if (lit == NULL)
			return NULL;

		sc = (struct ns_scalar *)e;
		lit->u.scalar = sc->value;
	} else {
		return NULL;
	}
	lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;

	return lit;
}


static void set_nsref_locator_type(struct pml_locator *l)
{
	struct ns_elem *nse = l->u.nsref;

	if (l->rpfld != PML_RPF_NONE) {
		if (PML_RPF_IS_BYTESTR(l->rpfld)) {
			l->etype = PML_ETYPE_BYTESTR;
			l->width = 0;
			l->eflags |= PML_EFLAG_VARLEN;
		} else {
			l->etype = PML_ETYPE_SCALAR;
			l->width = SCALAR_SIZE;
		}
	} else {
		if (NSF_IS_INBITS(nse->flags)) {
			l->etype = PML_ETYPE_SCALAR;
			l->width = SCALAR_SIZE;
		} else {
			l->etype = PML_ETYPE_BYTESTR;
			if (NSF_IS_VARLEN(nse->flags)) {
				l->width = 0;
				l->eflags |= PML_EFLAG_VARLEN;
			} else {
				if (nse->type == NST_NAMESPACE) {
					struct ns_namespace *ns;
					ns = (struct ns_namespace *)nse;
					l->width = ns->len;
				} else {
					struct ns_pktfld *pf;
				       	pf = (struct ns_pktfld *)nse;
					l->width = pf->len;
				}
			}
		}
	}
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
	uint32_t off, len;
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
	if (rpf != PML_RPF_NONE) {
		free(name);
		if (e == NULL) {
			pml_ast_err(ast, "'%s' is an unknown namespace\n", l->name);
			return -1;
		}
	}

	if (e == NULL)
		return 0;

	if (rpf != PML_RPF_NONE && e->type != NST_NAMESPACE && 
	    e->type != NST_PKTFLD) {
		pml_ast_err(ast, "'%s' is an illegal field\n", l->name);
		return -1;
	}

	switch (e->type) {
	case NST_NAMESPACE:
		l->u.nsref = e;
		ns = (struct ns_namespace *)e;
		l->reftype = PML_REF_PKTFLD;
		/* Syntactic Sugar: */
		/* a namespace with no offset or length is the same as */
		/* an 'exists' reserved namespace.  The presence of an */
		/* address or length makes it refer to the parse field */
		if (rpf == PML_RPF_NONE) {
			if (l->off == NULL && l->len == NULL) {
				abort_unless(l->type == PMLTT_LOCATOR);
				rpf = PML_RPF_EXISTS;
			} else {
				rpf = PML_RPF_PARSE;
			}
		} else if (ns->prid == PRID_INVALID) {
			pml_ast_err(ast, "'%s' is not a protocol\n", ns->name);
			return -1;
		}
		l->rpfld = rpf;
		break;

	case NST_PKTFLD:
		pf = (struct ns_pktfld *)e;
		l->u.nsref = e;
		l->reftype = PML_REF_PKTFLD;
		l->rpfld = rpf;
		if (rpf != PML_RPF_NONE && 
		    (rpf != PML_RPF_EXISTS || pf->prid == PRID_INVALID)) {
			pml_ast_err(ast, "'%s' is an invalid protocol field\n",
				    l->name);
			return -1;
		}
		break;

	case NST_SCALAR:
		/* can not have packet or index for scalars */
		if (l->pkt != NULL || l->idx != NULL || l->off != NULL ||
		    l->len != NULL)
			return -1;
		lit = pmln_alloc(ast, PMLTT_SCALAR);
		if (lit == NULL)
			return -1;
		sc = (struct ns_scalar *)e;
		lit->u.scalar = sc->value;
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
			off = val32(ast, &r);
		}
		if (off >= nbs->value.len)
			return -1;
		len = nbs->value.len;
		if (l->len != NULL) {
			rv = pml_eval(ast, NULL, (union pml_node *)l->len, &r);
			if (rv < 0)
				return -1;
			len = val32(ast, &r);
		}
		if (nbs->value.len - off > len)
			return -1;

		lit = pmln_alloc(ast, PMLTT_BYTESTR);
		if (lit == NULL)
			return -1;
		lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;
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
		    l->len != NULL) {
			pml_ast_err(ast, "fields illegal for mask value\n");
			return -1;
		}
		ms = (struct ns_maskstr *)e;
		abort_unless(ms->value.len == ms->mask.len);

		lit = pmln_alloc(ast, PMLTT_MASKVAL);
		if (lit == NULL)
			return -1;
		lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;
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
		return 0;
	}

	/* if we can't create the local variable, return an error */
	if (ctx->vtidx < 0) {
		pml_ast_err(ctx->ast, "unable to resolve variable '%s'\n",
			    l->name);
		return -1;
	}

	t = ctx->symtabs[ctx->vtidx];
	v = pml_var_alloc_nc(ctx->ast, l->name, PML_VTYPE_LOCAL, 
			     PML_ETYPE_SCALAR, 0, NULL);
	if (v == NULL)
		return -1;
	v->etype = PML_ETYPE_SCALAR;
	abort_unless(pml_func_add_var(t, ctx->livefunc, v) >= 0);

	l->reftype = PML_REF_VAR;
	l->u.varref = v;

	return 0;
}


int check_nsref_assignment(struct pml_ast *ast, struct pml_assign *a)
{
	struct pml_locator *loc = a->loc;

	abort_unless(loc->reftype == PML_REF_PKTFLD);
	if (loc->u.nsref->type == NST_NAMESPACE) {
		/* can't be a reserved non-byte string */
		if (!PML_RPF_IS_BYTESTR(loc->rpfld)) {
			pml_ast_err(ast, 
				    "Protocol field '%s' can not be an lvalue",
				    loc->name);
			return -1;
		}
	} else if (loc->u.nsref->type != NST_PKTFLD) {
		/* can't be a protocol constant */
		pml_ast_err(ast, 
			    "Protocol field '%s' is a constant and cannot"
			    " be an lvalue\n",
			    loc->name);
		return -1;
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


static int typecheck_binop(struct pml_ast *ast, struct pml_op *op)
{
	struct pml_expr_base *a1, *a2;

	a1 = (struct pml_expr_base *)op->arg1;
	a2 = (struct pml_expr_base *)op->arg2;

	switch(op->op) {
	case PMLOP_MATCH:
	case PMLOP_NOTMATCH:
		if (typecheck(a1->etype, PML_ETYPE_BYTESTR) < 0) {
			pml_ast_err(ast,
				    "%s: Left argument of a match operation "
				    "must be a byte string: %s instead\n",
				    opstr(op), ets(a1));
			return -1;
		}
		if (a2->etype != PML_ETYPE_BYTESTR &&
		    a2->etype != PML_ETYPE_MASKVAL) {
			pml_ast_err(ast, 
				    "%s: Right argument of a match operation "
				    "must be a byte string blob pointer or "
				    "masked string: %s instead\n", 
				    opstr(op), ets(a2));
			return -1;
		}
		break;

	case PMLOP_REXMATCH:
	case PMLOP_NOTREXMATCH:
		if (typecheck(a1->etype, PML_ETYPE_BYTESTR) < 0 ||
		    a2->etype != PML_ETYPE_BYTESTR) {
			pml_ast_err(ast, "Both arguments of a regex operation "
					 "must be byte strings. Types are "
					 "'%s' and '%s'\n", ets(a1), ets(a2));
			return -1;
		}
		break;

	default:
		if (typecheck(a1->etype, PML_ETYPE_SCALAR) < 0) {
			pml_ast_err(ast, "Left argument of scalar operator"
					 " can not be converted to scalar");
			return -1;
		}
		if (typecheck(a2->etype, PML_ETYPE_SCALAR) < 0) {
			pml_ast_err(ast, "Right argument of scalar operator"
					 " can not be converted to scalar");
			return -1;
		}
	}

	return 0;
}


static int typecheck_call(struct pml_ast *ast, struct pml_call *c)
{
	int i;
	struct list *pn, *an;
	struct pml_variable *p;
	union pml_expr_u *a;
	struct pml_function *f = c->func;

	pn = l_head(&f->vars.list);
	an = l_head(&c->args->list);
	for (i = 0; i < f->arity; ++i) {
		p = (struct pml_variable *)l_to_node(pn);
		a = (union pml_expr_u *)l_to_node(an);
		if (typecheck(a->expr.etype, p->etype) < 0) {
			pml_ast_err(ast, "Argument '%s' to function '%s' is type"
				         " '%s' instead of '%s'",
				    p->name, f->name, ets(a), pts(p));
			return -1;
		}
		pn = pn->next;
		an = an->next;
	}

	return 0;
}


static int typecheck_locator(struct pml_ast *ast, struct pml_locator *loc)
{
	union pml_expr_u *e;
	if (loc->pkt != NULL) {
		e = loc->pkt;
		if (typecheck(e->expr.etype, PML_ETYPE_SCALAR) < 0) {
			pml_ast_err(ast, "invalid locator packet type");
			return -1;
		}
	}
	if (loc->idx != NULL) {
		e = loc->idx;
		if (typecheck(e->expr.etype, PML_ETYPE_SCALAR) < 0) {
			pml_ast_err(ast, "invalid locator index type");
			return -1;
		}
	}
	if (loc->off != NULL) {
		e = loc->off;
		if (typecheck(e->expr.etype, PML_ETYPE_SCALAR) < 0) {
			pml_ast_err(ast, "invalid locator offset type");
			return -1;
		}
	}
	if (loc->len != NULL) {
		e = loc->len;
		if (typecheck(e->expr.etype, PML_ETYPE_SCALAR) < 0) {
			pml_ast_err(ast, "invalid locator length type");
			return -1;
		}
	}
	return 0;
}


static int typecheck_node(struct pml_ast *ast, union pml_node *node,
			  struct pml_function *livefunc)
{
	union pml_expr_u *e;
	switch (node->base.type) {

	case PMLTT_LIST:
	case PMLTT_SCALAR:
	case PMLTT_BYTESTR:
	case PMLTT_MASKVAL:
	case PMLTT_LOCADDR:
	case PMLTT_VAR:
	case PMLTT_FUNCTION:
	case PMLTT_RULE:
		/* no check */
		break;

	case PMLTT_BINOP: {
		struct pml_op *op = &node->op;
		if (typecheck_binop(ast, op) < 0)
			return -1;
	} break;

	case PMLTT_UNOP: {
		struct pml_op *op = &node->op;
		e = op->arg1;
		if (typecheck(e->expr.etype, PML_ETYPE_SCALAR) < 0) {
			pml_ast_err(ast, "invalid unary operand");
			return -1;
		}
	} break;

	case PMLTT_CALL:
		if (typecheck_call(ast, &node->call) < 0)
			return -1;
		break;

	case PMLTT_LOCATOR: {
		if (typecheck_locator(ast, &node->locator) < 0)
			return -1;
	} break;

	case PMLTT_IF: {
		struct pml_if *ifstmt = &node->ifstmt;
		e = ifstmt->test;
		if (typecheck(e->expr.etype, PML_ETYPE_SCALAR) < 0) {
			pml_ast_err(ast, "invalid 'if' test");
			return -1;
		}
	} break;

	case PMLTT_WHILE: {
		struct pml_while *whilestmt = &node->whilestmt;
		e = whilestmt->test;
		if (typecheck(e->expr.etype, PML_ETYPE_SCALAR) < 0) {
			pml_ast_err(ast, "invalid 'while' condition");
			return -1;
		}
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *a = &node->assign;
		e = a->expr;
		/* scalar -> bytestr is allowed for assignments.  Note that */
		/* strref variables have a location expr type of bytestr. */
		if (a->loc->etype == PML_ETYPE_BYTESTR &&
		    e->expr.etype == PML_ETYPE_SCALAR)
			break;
		/* all others are for regular type conversion rules */
		if (typecheck(e->expr.etype, a->loc->etype) < 0) {
			pml_ast_err(ast, "incompatible assignment type: %s->%s",
				    ets(e), ets(a->loc));
			return -1;
		}
	} break;

	case PMLTT_CFMOD: {
		struct pml_cfmod *c = &node->cfmod;
		if (c->cftype == PML_CFM_RETURN) {
			e = c->expr;
			if (typecheck(e->expr.etype, livefunc->rtype) < 0) {
				pml_ast_err(ast, "'return' value does not match"
					         " function return type");
				return -1;
			}
		}
	} break;

	case PMLTT_PRINT: {
		struct pml_print *p = &node->print;
	       	e = p->expr;
		if (typecheck(e->expr.etype, PML_FMT_TO_ETYPE(p->fmt)) < 0) {
			pml_ast_err(ast, "print expr doesn't match format");
			return -1;
		}
	} break;

	default:
		abort_unless(0);
	}

	return 0;
}


static int resolve_node_post(union pml_node *node, void *ctxp, void *xstk)
{
	struct pml_resolve_ctx *ctx = ctxp;

	switch(node->base.type) {

	case PMLTT_BINOP: {
		struct pml_op *op = (struct pml_op *)node;

		/* propagate CONST & PCONST expression flags */
		if (PML_EXPR_IS_CONST(op->arg1) && 
		    PML_EXPR_IS_CONST(op->arg2)) {
			op->eflags |= PML_EFLAG_CONST | PML_EFLAG_PCONST;
			op->eflags |= PML_EFLAG_PCONST;
		} else if (PML_EXPR_IS_PCONST(op->arg1) && 
		           PML_EXPR_IS_PCONST(op->arg2)) {
			op->eflags |= PML_EFLAG_PCONST;
		}

		/*
		 * Convert "==" or "!=" operations to match/notmatch
		 * if both the left and right hand side args are string
		 * expression. 
		 */
		if ((op->op == PMLOP_EQ || op->op == PMLOP_NEQ) &&
		    PML_EXPR_IS_BYTESTR(op->arg1) && 
		    PML_EXPR_IS_BYTESTR(op->arg2)) {
			if (op->op == PMLOP_EQ)
				op->op = PMLOP_MATCH;
			else
				op->op = PMLOP_NOTMATCH;
		}

		/* for now all binary operations return scalars */
		op->etype = PML_ETYPE_SCALAR;
	} break;

	case PMLTT_UNOP: {
		struct pml_op *op = (struct pml_op *)node;
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
			for_each_arg(n, c) {
				if (!PML_EXPR_IS_PCONST(l_to_node(n))) {
					c->eflags &= ~(PML_EFLAG_PCONST|
						       PML_EFLAG_CONST);
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
			l->eflags = l->u.litref->eflags;
		} else if (l->reftype == PML_REF_VAR) {
			struct pml_variable *v = l->u.varref;

			/* string references as rvalues return type string */
			/* otherwise, the type of the expression is the type */
			/* of the variable type. */
			l->etype = v->etype;
			if (l->etype == PML_ETYPE_STRREF)
				l->etype = PML_ETYPE_BYTESTR;

			if (v->vtype == PML_VTYPE_CONST) {
				l->eflags |= (PML_EFLAG_CONST|PML_EFLAG_PCONST);
			} else if (v->vtype == PML_VTYPE_PARAM) {
				struct pml_function *f = ctx->livefunc;
				/* if the variable is a parameter in an inline */
				/* function, then it can be considered constant */
				if (PML_FUNC_IS_INLINE(f))
					l->eflags |= PML_EFLAG_PCONST;
			} else if (v->vtype == PML_VTYPE_GLOBAL) {
				if ((v->etype == PML_ETYPE_SCALAR) && 
				    ((l->off != NULL) || (l->len != NULL))) {
					pml_ast_err(ctx->ast,
						    "'%s' is a scalar global"
						    " and can not be accessed"
						    " as a byte string\n",
						    l->name);
					return -1;
				}

			}
			l->width = v->width;
		} else {
			abort_unless(l->reftype == PML_REF_PKTFLD);
			set_nsref_locator_type(l);
		}
	} break;

	case PMLTT_LOCADDR: {
		struct pml_locator *l = (struct pml_locator *)node;

		if (resolve_locsym(ctx, l) < 0)
			return -1;

		abort_unless(l->pkt == NULL && l->idx == NULL &&
			     l->off == NULL && l->len == NULL);

		if ((l->reftype != PML_REF_VAR) || 
		    (l->u.varref->etype != PML_ETYPE_STRREF)) {
			pml_ast_err(ctx->ast, 
				    "'%s' is not an addressable field.\n",
				    l->name);
			return -1;
		}

		l->eflags |= PML_EFLAG_CONST|PML_EFLAG_PCONST;

		/* redundant? */
		l->etype = PML_ETYPE_STRREF;
		l->width = STRREF_SIZE;
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
		} else {
			abort_unless(a->loc->reftype == PML_REF_PKTFLD);
			if (check_nsref_assignment(ctx->ast, a) < 0)
				return -1;
		}
	} break;

	case PMLTT_PRINT: {
		struct pml_print *p = (struct pml_print *)node;
		if (p->fmt == PML_FMT_UNKNOWN) {
			if (p->expr->expr.etype == PML_ETYPE_SCALAR)
				p->fmt = PML_FMT_DEC;
			else
				p->fmt = PML_FMT_STR;
		}
	} break;

	}

	if (typecheck_node(ctx->ast, node, ctx->livefunc) < 0)
		return -1;

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
		ctx.vtidx = -1; /* no local vars in the pattern */
		rv = resolve_node(&ctx, (union pml_node *)rule->pattern);
		if (rv < 0)
			goto out;
		ctx.vtidx = 0; /* local vars allowed in the statement */
		rv = resolve_node(&ctx, (union pml_node *)rule->stmts);
		if (rv < 0)
			goto out;
		rule->vstksz = rule->vars.addr_rw2 * sizeof(uint32_t);

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
		func->pstksz = func->vars.addr_rw1 * sizeof(uint32_t);
		func->vstksz = func->vars.addr_rw2 * sizeof(uint32_t);

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
		inln->pstksz = inln->vars.addr_rw1 * sizeof(uint32_t);
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


static ulong val32(struct pml_ast *ast, struct pml_retval *v)
{
	byte_t *data, *mask;
	int i;
	byte_t bytes[sizeof(uint32_t)];

	abort_unless(v);

	switch(v->etype) {
	case PML_ETYPE_SCALAR:
		return v->val;
	case PML_ETYPE_BYTESTR:
		data = pml_bytestr_ptr(ast, &v->bytes);
		return be32val(data, v->bytes.len);
	case PML_ETYPE_MASKVAL: {
		data = pml_bytestr_ptr(ast, &v->bytes);
		mask = pml_bytestr_ptr(ast, &v->mask);
		ulong len = (v->bytes.len > v->mask.len) ? v->bytes.len :
			    v->mask.len;
		if (len > sizeof(bytes))
			len = sizeof(bytes);
		for (i = 0; i < len; ++i)
			bytes[i] = data[i] & mask[i];
		return be32val(bytes, len);
	} break;
	default:
		abort_unless(0);
		return (ulong)-1;
	}
}


int pml_lit_val(struct pml_ast *ast, struct pml_literal *lit, ulong *val)
{
	byte_t *data, *mask;
	int i;
	ulong len;
	byte_t bytes[sizeof(uint32_t)];

	if (ast == NULL || lit == NULL || val == NULL)
		return -1;

	if (lit->type == PMLTT_SCALAR) {
		*val = lit->u.scalar;
	} else if (lit->type == PMLTT_BYTESTR) {
		data = pml_bytestr_ptr(ast, &lit->u.bytestr);
		*val = be32val(data, lit->u.bytestr.len);
	} else if (lit->type == PMLTT_MASKVAL) {
		data = pml_bytestr_ptr(ast, &lit->u.maskval.val);
		mask = pml_bytestr_ptr(ast, &lit->u.maskval.mask);
		len = lit->u.maskval.val.len;
		if (len != lit->u.maskval.mask.len)
			return -1;
		if (len > sizeof(bytes))
			len = sizeof(bytes);
		for (i = 0; i < len; ++i)
			bytes[i] = data[i] & mask[i];
		*val = be32val(bytes, len);
	} else {
		return -1;
	}
	return 0;
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
	uint32_t left = 0, right = 0;
	int rv;

	r->etype = PML_ETYPE_SCALAR;
	abort_unless(is_expr(op->arg1));
	abort_unless(is_expr(op->arg2));

	if (pml_eval(ast, fr, (union pml_node *)op->arg1, &lr) < 0)
		return -1;
	if (!is_match_op(op->op))
		left = val32(ast, &lr);

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
		right = val32(ast, &rr);

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
		pml_ast_err(ast, "eval: regex matching unimplemented\n");
		return -1;
		break;
	case PMLOP_EQ: r->val = left == right;
		break;
	case PMLOP_NEQ: r->val = left != right;
		break;
	case PMLOP_LT: r->val = (int32_t)left < (int32_t)right;
		break;
	case PMLOP_GT: r->val = (int32_t)left > (int32_t)right;
		break;
	case PMLOP_LEQ: r->val = (int32_t)left <= (int32_t)right;
		break;
	case PMLOP_GEQ: r->val = (int32_t)left >= (int32_t)right;
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
	case PMLOP_SHL: r->val = left << (right & 31);
		break;
	case PMLOP_SHR: r->val = left >> (right & 31);
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
	uint32_t arg;

	abort_unless(op->etype == PML_ETYPE_SCALAR);
	abort_unless(is_expr(op->arg1));

	if (pml_eval(ast, fr, (union pml_node *)op->arg1, &lr) < 0)
		return -1;
	arg = val32(ast, &lr);

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
	uint32_t *pp;

	abort_unless(l_length(&c->args->list) == f->arity);
	r->etype = PML_ETYPE_SCALAR;
	nfr = stkalloc(ast, (union pml_node *)f);
	if (nfr == NULL)
		return -1;

	/* evaluation the parameters and put them in the stack frame */
	pp = (uint32_t *)nfr->stack;
	for_each_arg(n, c) {
		rv = pml_eval(ast, fr, l_to_node(n), &lr);
		if (rv < 0)
			goto out;
		*pp++ = val32(ast, &lr);
	}

	if (PML_FUNC_IS_INTRINSIC(f))
		rv = (*f->ieval)(ast, nfr, (union pml_node *)f, &lr);
	else
		rv = pml_eval(ast, nfr, f->body, &lr);
	if (rv < 0)
		goto out;
	r->val = val32(ast, &lr);
out:
	stkfree(nfr);
	return rv;
}


static int getofflen(struct pml_ast *ast, struct pml_stack_frame *fr,
		     struct pml_locator *l, uint32_t fieldlen,
		     uint32_t *off, uint32_t *len)
{
	struct pml_retval lr;

	if (l->off != NULL) {
		if (pml_eval(ast, fr, (union pml_node *)l->off, &lr) < 0)
			return -1;
		*off = val32(ast, &lr);
	}

	if (l->len != NULL) {
		if (pml_eval(ast, fr, (union pml_node *)l->len, &lr) < 0)
			return -1;
		*len = val32(ast, &lr);
	} else {
		*len = fieldlen;
	}

	return 0;
}


static int e_const(struct pml_ast *ast, struct pml_stack_frame *fr,
		   struct pml_locator *l, struct pml_retval *r)
{
	uint32_t off = 0, len = 0;
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
		r->bytes.ispkt = lr.bytes.ispkt;
		r->bytes.segnum = lr.bytes.segnum;
		r->bytes.addr = lr.bytes.addr + off;
		r->bytes.len = len;
		if (v->etype == PML_ETYPE_MASKVAL) { 
			r->mask.ispkt = lr.mask.ispkt;
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
	uint32_t off = 0, len = SCALAR_SIZE;

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
				r->val = *(uint32_t *)(fr->stack + v->addr);
			} else {
				abort_unless(l->etype == PML_ETYPE_BYTESTR);
				r->etype = PML_ETYPE_BYTESTR;
				r->bytes.ispkt = 0;
				r->bytes.segnum = PML_SEG_RWMEM;
				r->bytes.addr = v->addr + off;
				r->bytes.len = len;
			}

		} else {
			byte_t *p;

			if (fr == NULL)
				return -1;

			abort_unless(v->vtype == PML_VTYPE_PARAM ||
			             v->vtype == PML_VTYPE_LOCAL);
			abort_unless(l->etype == PML_ETYPE_SCALAR);
			abort_unless(l->off == NULL && l->len == NULL);
			if (fr->ssz < SCALAR_SIZE || 
			    fr->ssz - SCALAR_SIZE < v->addr) {
				pml_ast_err(ast,
					    "eval: stack overflow in var '%s':"
					    " stack size=%lu, var addr=%lu\n",
					    v->name, fr->ssz, v->addr);
				return -1;
			}
			r->etype = PML_ETYPE_SCALAR;
			p = fr->stack + v->addr * sizeof(uint32_t);
			if (v->vtype == PML_VTYPE_LOCAL)
				p += fr->psz;
			r->val = *(uint32_t *)p;
		}
	} else if (l->reftype == PML_REF_PKTFLD) {

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
	struct pml_literal *lit;

	r->etype = PML_ETYPE_STRREF;
	if (l->reftype == PML_REF_VAR) {
		if (l->u.varref->vtype == PML_VTYPE_GLOBAL) {
			r->bytes.ispkt = 0;
			r->bytes.addr = l->u.varref->addr;
			r->bytes.len = l->u.varref->width;
			r->bytes.segnum = PML_SEG_RWMEM;
		} else {
			/* can't evaluate this, but not an error */
			return -1;
		}
	} else if (l->reftype == PML_REF_LITERAL) {
		lit = l->u.litref;
		abort_unless(lit->type == PMLTT_BYTESTR);
		r->bytes = lit->u.bytestr;
	} else if (l->reftype == PML_REF_PKTFLD) {
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
	e_binop,		/* PMLTT_BINOP */
	e_unop,			/* PMLTT_UNOP */
	e_call,			/* PMLTT_CALL */
	e_locator,		/* PMLTT_LOCATOR */
	e_locaddr,		/* PMLTT_LOCADDR */
	unimplemented,		/* PMLTT_IF */
	unimplemented,		/* PMLTT_WHILE */
	unimplemented,		/* PMLTT_ASSIGN */
	unimplemented,		/* PMLTT_CFMOD */
	unimplemented,		/* PMLTT_PRINT */
	unimplemented,		/* PMLTT_VAR */
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
	uint shift;
	int i;

	abort_unless(ast);

	dyb = &ast->mi_bufs[PML_SEG_RWMEM];

	memset(dyb->data, 0, dyb->size);

	for_each_gvar(n, ast) {
		v = (struct pml_variable *)l_to_node(n);
		if (v->vtype != PML_VTYPE_GLOBAL || v->init == NULL ||
		    v->width == 0)
			continue;

		err = pml_eval(ast, NULL, (union pml_node *)v->init, &r);
		abort_unless(err == 0);

		vp = dyb->data + v->addr;
		if (r.etype == PML_ETYPE_SCALAR) {
			len = (v->width > SCALAR_SIZE ? SCALAR_SIZE : v->width);
			for (i = 0; i < len; ++i) {
				shift = (SCALAR_SIZE - 1 - i) * 8;
				*vp++ = (r.val >> shift) & 0xFF;
			}
		} else if (r.etype == PML_ETYPE_BYTESTR) {
			cp = pml_bytestr_ptr(ast, &r.bytes);
			len = (r.bytes.len > v->width ? v->width : r.bytes.len);
			memmove(vp, cp, len);
			memset(vp + len, 0, v->width - len);
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
		if (rv < 0) {
			pml_ast_clear_err(astp);
			return 0;
		}

		switch(r.etype) {
		case PML_ETYPE_SCALAR:
			lit = pmln_alloc(astp, PMLTT_SCALAR);
			if (lit == NULL)
				return -1;
			lit->etype = PML_ETYPE_SCALAR;
			lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;
			lit->width = SCALAR_SIZE;
			lit->u.scalar = r.val;
			break;

		case PML_ETYPE_BYTESTR:
			lit = pmln_alloc(astp, PMLTT_BYTESTR);
			if (lit == NULL)
				return -1;
			lit->etype = PML_ETYPE_BYTESTR;
			lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;
			lit->u.bytestr = r.bytes;
			lit->width = r.bytes.len;
			break;

		case PML_ETYPE_MASKVAL:
			lit = pmln_alloc(astp, PMLTT_MASKVAL);
			if (lit == NULL)
				return -1;
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


static int is_literal_zero(union pml_expr_u *e)
{
	return e != NULL &&
	       PML_EXPR_IS_SCALAR(e) &&
	       e->literal.u.scalar == 0;
}


static int pml_opt_locator(struct pml_locator *l, void *astp)
{
	if ((pml_opt_e_cexpr(&l->pkt, astp) < 0) ||
	    (pml_opt_e_cexpr(&l->idx, astp) < 0) ||
	    (pml_opt_e_cexpr(&l->off, astp) < 0) ||
	    (pml_opt_e_cexpr(&l->len, astp) < 0))
		return -1;
	if (is_literal_zero(l->pkt)) {
		pmln_free((union pml_node *)l->pkt);
		l->pkt = NULL;
	}
	if (is_literal_zero(l->idx)) {
		pmln_free((union pml_node *)l->idx);
		l->idx = NULL;
	}
	if (is_literal_zero(l->off)) {
		pmln_free((union pml_node *)l->off);
		l->off= NULL;
	}
	return 0;
}


static int pml_cexpr_walker(union pml_node *node, void *astp, void *xstk)
{
	struct list *n, *x;

	switch(node->base.type) {

	case PMLTT_BINOP:
	case PMLTT_UNOP: {
		struct pml_op *op = &node->op;
		if (pml_opt_e_cexpr(&op->arg1, astp) < 0)
			return -1;
		if (op->type == PMLTT_BINOP) {
			if (pml_opt_e_cexpr(&op->arg2, astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_CALL: {
		struct pml_call *c = &node->call;
		for_each_arg_safe(n, x, c) {
			if (pml_opt_l_cexpr((union pml_expr_u *)l_to_node(n), 
					   astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		if (pml_opt_locator(&node->locator, astp) < 0)
			return -1;
	} break;

	case PMLTT_IF: {
		struct pml_if *pif = &node->ifstmt;
		if (pml_opt_e_cexpr(&pif->test, astp) < 0)
			return -1;
	} break;

	case PMLTT_WHILE: {
		struct pml_while *w = &node->whilestmt;
		if (pml_opt_e_cexpr(&w->test, astp) < 0)
			return -1;
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *a = &node->assign;
		if (pml_opt_e_cexpr(&a->expr, astp) < 0)
			return -1;
	} break;

	case PMLTT_PRINT: {
		struct pml_print *p = (struct pml_print *)node;
		if (pml_opt_e_cexpr(&p->expr, astp) < 0)
			return -1;
	} break;

	case PMLTT_VAR: {
		struct pml_variable *v = &node->variable;
		if (v->init != NULL) {
			if (pml_opt_e_cexpr(&v->init, astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_FUNCTION: {
		struct pml_function *f = &node->function;
		if (PML_FUNC_IS_INLINE(f)) {
			if (pml_opt_n_cexpr(&f->body, astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_RULE: {
		struct pml_rule *r = &node->rule;
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


extern void *PMLAlloc(void *(*mallocProc)(size_t));
extern void PMLFree(void *p, void (*freeProc)(void*));
extern void PML(void *parser, int tok, struct pmll_val xtok,
		struct pml_ast *ast);


pml_parser_t pml_alloc()
{
	return PMLAlloc(malloc);
}


int pml_parse(pml_parser_t p, struct pml_ast *ast, int tok,
	      struct pmll_val xtok)
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


