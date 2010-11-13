/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#include "pmltree.h"
#include <cat/aux.h>
#include <stdlib.h>
#include <string.h>

#define l_to_node(p) container(p, struct pml_node, pmln_ln)
#define SYMTABSIZE    256


static struct hashsys vartab_sys = {
	cmp_str, ht_shash, NULL
};


static int vtab_init(struct htab *ht)
{
	struct list *bins;
	if ((bins = malloc(SYMTABSIZE * sizeof(struct list))) == NULL)
		return -1;
	ht_init(ht, bins, SYMTABSIZE, &vartab_sys);
	return 0;
}


static struct pml_variable *vtab_lkup(struct htab *ht, const char *s,
				      int *create)
{
	uint h;
	struct hnode *hn;
	struct pml_variable *p = NULL;
	abort_unless(ht && s);

	if ((hn = ht_lkup(ht, (void *)s, &h)) != NULL) {
		if (create != NULL)
			*create = 0;
	} else if (create != NULL) {
		p = calloc(1, sizeof(*p));
		if (p == NULL) {
			*create = 0;
			return NULL;
		}
		hn = &p->pmlvar_hn;
		if ((p->pmlvar_name = strdup(s)) == NULL) {
			free(p);
			*create = 0;
			return NULL;
		}
		ht_ninit(hn, p->pmlvar_name, p, h);
		ht_ins(ht, hn);
	}

	return p;
}


static void freevar(void *var, void *ctx)
{
	struct pml_variable *p = var;
	ht_rem(&p->pmlvar_hn);
	free(p->pmlvar_name);
	free(p);
}


void vtab_destroy(struct htab *ht)
{
	if (ht->tab == NULL)
		return;
	ht_apply(ht, freevar, NULL);
	free(ht->tab);
	ht->tab = NULL;
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
		    (vtab_init(&p->pmlf_vars) < 0))
			return NULL;
		p->pmlf_type = pmltt;
		l_init(&p->pmlf_ln);
		p->pmlf_name = NULL;
		p->pmlf_arity = 0;
		p->pmlf_pnames = NULL;
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
		uint i;
		if (p->pmlf_pnames != NULL) {
			for (i = 0; i < p->pmlf_arity; ++i)
				free(p->pmlf_pnames[i]);
			free(p->pmlf_pnames);
		}
		vtab_destroy(&p->pmlf_vars);
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


struct pml_function *pml_ast_lookup_func(struct pml_ast *ast, char *name)
{
	/* TODO */
	return NULL;
}


int pml_locator_extend_name(struct pml_locator *l, char *name, size_t len)
{
	/* TODO */
	return 0;
}
