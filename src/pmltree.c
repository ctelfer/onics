/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#include "pmltree.h"
#include <cat/aux.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define l_to_node(p) container(p, struct pml_node, pmln_ln)
#define SYMTABSIZE    256


static struct hashsys symtab_sys = {
	cmp_str, ht_shash, NULL
};


static int symtab_init(struct htab *ht)
{
	struct list *bins;
	if ((bins = malloc(SYMTABSIZE * sizeof(struct list))) == NULL)
		return -1;
	ht_init(ht, bins, SYMTABSIZE, &symtab_sys);
	return 0;
}


static struct pml_function *ftab_lkup(struct htab *ht, const char *s)
{
	uint h;
	struct hnode *hn;

	abort_unless(ht && s);
	if ((hn = ht_lkup(ht, (void *)s, &h)) == NULL)
		return NULL;
	return container(hn, struct pml_function, pmlf_hn);
}


static int ftab_add(struct htab *ht, struct pml_function *func) 
{
	uint h;
	struct hnode *hn;

	if (ht_lkup(ht, func->pmlf_name, &h) != NULL)
		return -1;
	hn = &func->pmlf_hn;
	ht_ninit(hn, func->pmlf_name, func, h);
	ht_ins(ht, hn);

	return 0;
}


static struct pml_variable *vtab_lkup(struct htab *ht, const char *s)
{
	uint h;
	struct hnode *hn;

	abort_unless(ht && s);
	if ((hn = ht_lkup(ht, (void *)s, &h)) == NULL)
		return NULL;
	return container(hn, struct pml_variable, pmlvar_hn);
}


static int vtab_add(struct htab *ht, struct pml_variable *var) 
{
	uint h;
	struct hnode *hn;

	if (ht_lkup(ht, var->pmlvar_name, &h) != NULL)
		return -1;
	hn = &var->pmlvar_hn;
	ht_ninit(hn, var->pmlvar_name, var, h);
	ht_ins(ht, hn);

	return 0;
}


static void freesym(void *nodep, void *ctx)
{
	struct pml_node *node = nodep;
	if (node->pmln_type == PMLTT_VAR) {
		struct pml_variable *p = nodep;
		ht_rem(&p->pmlvar_hn);
		l_rem(&p->pmlvar_ln);
	} else if (node->pmln_type == PMLTT_FUNCTION) {
		struct pml_function *p = nodep;
		ht_rem(&p->pmlf_hn);
		l_rem(&p->pmlf_ln);
	} else {
		abort_unless(0);
	}
	pmlt_free((union pml_tree *)node);
}


static void symtab_destroy(struct htab *ht)
{
	if (ht->tab == NULL)
		return;
	ht_apply(ht, freesym, NULL);
	free(ht->tab);
	ht->tab = NULL;
}


static void freerule(void *rulep, void *ctx)
{
	struct pml_rule *r = rulep;
	l_rem(&r->pmlr_ln);
	pmlt_free((union pml_tree *)r);
}


void pml_ast_init(struct pml_ast *ast)
{
	ast->pmla_error = 0;
	ast->pmla_line = 0;
	symtab_init(&ast->pmla_gvars);
	symtab_init(&ast->pmla_funcs);
	l_init(&ast->pmla_rules);
	ast->pmla_err_fp = stderr;
}


void pml_ast_clear(struct pml_ast *ast)
{
	ast->pmla_error = 0;
	ast->pmla_line = 0;
	symtab_destroy(&ast->pmla_gvars);
	symtab_destroy(&ast->pmla_funcs);
	l_apply(&ast->pmla_rules, freerule, NULL);
	l_init(&ast->pmla_rules);
	ast->pmla_err_fp = NULL;
}


void pml_ast_err(struct pml_ast *ast, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ast->pmla_err_fp != NULL)
		vfprintf(ast->pmla_err_fp, fmt, ap);
	va_end(ap);
}


struct pml_function *pml_ast_lookup_func(struct pml_ast *ast, char *name)
{
	return ftab_lkup(&ast->pmla_funcs, name);
}


int pml_ast_add_func(struct pml_ast *ast, struct pml_function *func)
{
	return ftab_add(&ast->pmla_funcs, func);
}


struct pml_variable *pml_ast_lookup_var(struct pml_ast *ast, char *name)
{
	return vtab_lkup(&ast->pmla_gvars, name);
}


int pml_ast_add_var(struct pml_ast *ast, struct pml_variable *var)
{
	return vtab_add(&ast->pmla_gvars, var);
}


struct pml_variable *pml_func_lookup_var(struct pml_function *func, char *name)
{
	return vtab_lkup(&func->pmlf_vars, name);
}


int pml_func_add_var(struct pml_function *func, struct pml_variable *var)
{
	return vtab_add(&func->pmlf_vars, var);
}


union pml_tree *pmlt_alloc(int pmltt)
{
	switch (pmltt) {
	case PMLTT_SCALAR:
	case PMLTT_BYTESTR:
	case PMLTT_MASKVAL:
	case PMLTT_VARREF:{
		struct pml_value *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlv_type = pmltt;
		l_init(&p->pmlv_ln);
		if (pmltt == PMLTT_SCALAR) {
			p->pmlv_sval = 0;
			p->pmlv_swidth = 4;
		} else if (pmltt == PMLTT_BYTESTR) {
			pml_bytestr_set_static(&p->pmlv_byteval, NULL, 0);
		} else if (pmltt == PMLTT_MASKVAL) {
			pml_bytestr_set_static(&p->pmlv_mval, NULL, 0);
			pml_bytestr_set_static(&p->pmlv_mmask, NULL, 0);
		} else {
			p->pmlv_varref = NULL;
		}
		return (union pml_tree *)p;
	} break;

	case PMLTT_VAR:{
		struct pml_variable *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlvar_type = pmltt;
		l_init(&p->pmlvar_ln);
		p->pmlvar_name = NULL;
		p->pmlvar_init = NULL;
	} break;

	case PMLTT_UNOP:
	case PMLTT_BINOP:{
		struct pml_op *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlo_type = pmltt;
		l_init(&p->pmlo_ln);
		p->pmlo_op = 0;
		p->pmlo_arg1 = NULL;
		p->pmlo_arg2 = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_FUNCALL:{
		struct pml_funcall *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlfc_type = pmltt;
		l_init(&p->pmlfc_ln);
		p->pmlfc_func = NULL;
		p->pmlfc_args = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_IF:{
		struct pml_if *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlif_type = pmltt;
		l_init(&p->pmlif_ln);
		p->pmlif_test = NULL;
		p->pmlif_tbody = NULL;
		p->pmlif_fbody = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_WHILE:{
		struct pml_while *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlw_type = pmltt;
		l_init(&p->pmlw_ln);
		p->pmlw_test = NULL;
		p->pmlw_body = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_NAME:
	case PMLTT_OFFSETOF:
	case PMLTT_LOCATOR:{
		struct pml_locator *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlloc_type = pmltt;
		l_init(&p->pmlloc_ln);
		p->pmlloc_name = NULL;
		p->pmlloc_pkt = NULL;
		p->pmlloc_off = NULL;
		p->pmlloc_len = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_SETACT:{
		struct pml_set_action *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlsa_type = pmltt;
		l_init(&p->pmlsa_ln);
		p->pmlsa_conv = 0;
		p->pmlsa_variable = NULL;
		p->pmlsa_expr = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_RETURN:{
		struct pml_return *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlret_type = pmltt;
		l_init(&p->pmlret_ln);
		p->pmlret_expr = NULL;
		return (union pml_tree *)p;
        } break;

	case PMLTT_PRINT:{
		struct pml_print *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlp_type = pmltt;
		l_init(&p->pmlp_ln);
		p->pmlp_fmt = NULL;
		p->pmlp_args = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_LIST:{
		struct pml_list *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmll_type = pmltt;
		l_init(&p->pmll_list);
		return (union pml_tree *)p;
	} break;

	case PMLTT_FUNCTION:
	case PMLTT_PREDICATE:{
		struct pml_function *p;
		if (((p = calloc(1, sizeof(*p))) == NULL) ||
		    (symtab_init(&p->pmlf_vars) < 0))
			return NULL;
		p->pmlf_type = pmltt;
		l_init(&p->pmlf_ln);
		p->pmlf_name = NULL;
		p->pmlf_arity = 0;
		p->pmlf_prmlist = NULL;
		p->pmlf_varlist = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_RULE:{
		struct pml_rule *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlr_type = pmltt;
		l_init(&p->pmlr_ln);
		p->pmlr_pattern = NULL;
		p->pmlr_stmts = NULL;
		return (union pml_tree *)p;
	} break;

	}
	return NULL;
}


void pmlt_free(union pml_tree *tree)
{
	if (tree == NULL)
		return;

	switch (tree->node.pmln_type) {
	case PMLTT_SCALAR:
	case PMLTT_VARREF:
		break;

	case PMLTT_BYTESTR:{
		struct pml_value *p = &tree->value;
		pml_bytestr_free(&p->pmlv_byteval);
	} break;

	case PMLTT_VAR:{
		struct pml_variable *p = &tree->variable;
		free(p->pmlvar_name);
		pmlt_free((union pml_tree *)p->pmlvar_init);
	}

	case PMLTT_MASKVAL:{
		struct pml_value *p = &tree->value;
		pml_bytestr_free(&p->pmlv_mval);
		pml_bytestr_free(&p->pmlv_mmask);
	} break;

	case PMLTT_BINOP:{
		struct pml_op *p = &tree->op;
		pmlt_free((union pml_tree *)p->pmlo_arg1);
		pmlt_free((union pml_tree *)p->pmlo_arg2);
	} break;

	case PMLTT_UNOP:{
		struct pml_op *p = &tree->op;
		pmlt_free((union pml_tree *)p->pmlo_arg1);
	} break;

	case PMLTT_FUNCALL:{
		struct pml_funcall *p = &tree->funcall;
		pmlt_free((union pml_tree *)p->pmlfc_args);
	} break;

	case PMLTT_IF:{
		struct pml_if *p = &tree->ifstmt;
		pmlt_free((union pml_tree *)p->pmlif_test);
		pmlt_free((union pml_tree *)p->pmlif_tbody);
		pmlt_free((union pml_tree *)p->pmlif_fbody);
	} break;

	case PMLTT_WHILE:{
		struct pml_while *p = &tree->whilestmt;
		pmlt_free((union pml_tree *)p->pmlw_test);
		pmlt_free((union pml_tree *)p->pmlw_body);
	} break;

	case PMLTT_NAME:
	case PMLTT_OFFSETOF:
	case PMLTT_LOCATOR:{
		struct pml_locator *p = &tree->locator;
		free(p->pmlloc_name);
		pmlt_free((union pml_tree *)p->pmlloc_pkt);
		pmlt_free((union pml_tree *)p->pmlloc_off);
		pmlt_free((union pml_tree *)p->pmlloc_len);
	} break;

	case PMLTT_SETACT:{
		struct pml_set_action *p = &tree->setact;
		pmlt_free((union pml_tree *)p->pmlsa_variable);
		pmlt_free((union pml_tree *)p->pmlsa_expr);
	} break;

	case PMLTT_RETURN:{
		struct pml_return *p = &tree->retact;
		pmlt_free((union pml_tree *)p->pmlret_expr);
	} break;

	case PMLTT_PRINT:{
		struct pml_print *p = &tree->print;
		free(p->pmlp_fmt);
		pmlt_free((union pml_tree *)p->pmlp_args);
	} break;

	case PMLTT_LIST:{
		struct pml_list *p = &tree->list;
		struct list *l;
		while ((l = l_deq(&p->pmll_list)) != NULL)
			pmlt_free((union pml_tree *)l_to_node(l));
	} break;

	case PMLTT_FUNCTION:
	case PMLTT_PREDICATE:{
		struct pml_function *p = &tree->function;
		free(p->pmlf_name);
		p->pmlf_name = NULL;
		symtab_destroy(&p->pmlf_vars);
		pmlt_free((union pml_tree *)p->pmlf_prmlist);
		pmlt_free((union pml_tree *)p->pmlf_varlist);
		pmlt_free(p->pmlf_body);
	} break;

	case PMLTT_RULE:{
		struct pml_rule *p = &tree->rule;
		pmlt_free((union pml_tree *)p->pmlr_pattern);
		pmlt_free((union pml_tree *)p->pmlr_stmts);
	} break;

	default:
		abort_unless(0);
	}

	free(tree);
}


union pml_expr_u *pml_binop_alloc(int op, union pml_expr_u *left, 
		                  union pml_expr_u *right)
{
	struct pml_op *o = (struct pml_op *)pmlt_alloc(PMLTT_BINOP);
	o->pmlo_op = op;
	o->pmlo_arg1 = left;
	o->pmlo_arg2 = right;
	return (union pml_expr_u *)o;
}


union pml_expr_u *pml_unop_alloc(int op, union pml_expr_u *ex)
{
	struct pml_op *o = (struct pml_op *)pmlt_alloc(PMLTT_UNOP);
	o->pmlo_op = op;
	o->pmlo_arg1 = ex;
	return (union pml_expr_u *)o;
}


struct pml_variable *pml_var_alloc(char *name, int width, 
		                   struct pml_value *init)
{
	struct pml_variable *v = (struct pml_variable *)
		pmlt_alloc(PMLTT_VAR);
	v->pmlvar_name = name;
	v->pmlvar_init = init;
	return v;
}


void pml_bytestr_set_static(struct pml_bytestr *b, void *data, size_t len)
{
	abort_unless(b);
	abort_unless((len == 0) || (data != NULL));
	abort_unless(len <= PML_BYTESTR_MAX_STATIC);
	b->pmlbs_is_dynamic = 0;
	b->pmlbs_data = b->pmlbs_sbytes;
	b->pmlbs_len = len;
	memcpy(b->pmlbs_sbytes, data, len);
}


void pml_bytestr_set_dynamic(struct pml_bytestr *b, void *data, size_t len)
{
	abort_unless(b);
	abort_unless(len > 0);
        abort_unless(data != NULL);
	b->pmlbs_is_dynamic = 1;
	b->pmlbs_data = data;
	b->pmlbs_len = len;
}


void pml_bytestr_free(struct pml_bytestr *b)
{
	abort_unless(b);
	if (b->pmlbs_is_dynamic) {
		free(b->pmlbs_data);
		pml_bytestr_set_static(b, NULL, 0);
	}
}


int pml_locator_extend_name(struct pml_locator *l, char *name, size_t elen)
{
	size_t olen, len;
	char *newname;

	olen = len = strlen(l->pmlloc_name);
	if (len + 2 < len)
		return -1;
	len += 2;
	if (((size_t)0-1) - len < elen)
		return -1;
	len += elen;

	newname = realloc(l->pmlloc_name, len);
	if (newname == NULL)
		return -1;

	newname[olen] = '.';
	memcpy(newname + olen + 1, name, elen);
	newname[len-1] = '\0';
	l->pmlloc_name = newname;

	return 0;
}
