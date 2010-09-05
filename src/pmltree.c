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
			p->pmlv_byteval.data = NULL;
			p->pmlv_byteval.len = 0;
		} else if (pmltt == PMLTT_MASKVAL) {
			p->pmlv_mval.data = NULL;
			p->pmlv_mval.len = 0;
			p->pmlv_mmask.data = NULL;
			p->pmlv_mmask.len = 0;
		} else {
			p->pmlv_varref = NULL;
		}
		return (union pml_tree *)p;
	} break;

	case PMLTT_BINOP:{
		struct pml_binop *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlb_type = pmltt;
		p->pmlb_op = 0;
		p->pmlb_left = NULL;
		p->pmlb_right = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_UNOP:{
		struct pml_unop *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlu_type = pmltt;
		p->pmlu_op = 0;
		p->pmlu_expr = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_FUNCALL:{
		struct pml_funcall *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlfc_type = pmltt;
		p->pmlfc_func = NULL;
		p->pmlfc_args = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_IF:{
		struct pml_if *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlif_type = pmltt;
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
		p->pmlw_test = NULL;
		p->pmlw_body = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_LOCATOR:{
		struct pml_locator *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlloc_type = pmltt;
		p->pmlloc_name = NULL;
		p->pmlloc_off = 0;
		p->pmlloc_len = 0;
		return (union pml_tree *)p;
	} break;

	case PMLTT_PKTACT:{
		struct pml_pkt_action *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlpa_type = pmltt;
		p->pmlpa_action = 0;
		p->pmlpa_pkt = NULL;
		p->pmlpa_name = NULL;
		p->pmlpa_off = NULL;
		p->pmlpa_amount = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_SETACT:{
		struct pml_set_action *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlsa_type = pmltt;
		p->pmlsa_conv = 0;
		p->pmlsa_vname = NULL;
		p->pmlsa_off = NULL;
		p->pmlsa_len = NULL;
		p->pmlsa_newval = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_PRINT:{
		struct pml_print *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlp_type = pmltt;
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

	case PMLTT_FUNCTION:{
		struct pml_function *p;
		if (((p = calloc(1, sizeof(*p))) == NULL) ||
		    (vtab_init(&p->pmlf_vars) < 0))
			return NULL;
		p->pmlf_type = pmltt;
		p->pmlf_name = NULL;
		p->pmlf_nparams = 0;
		p->pmlf_pnames = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_RULE:{
		struct pml_rule *p;
		if ((p = calloc(1, sizeof(*p))) == NULL)
			return NULL;
		p->pmlr_type = pmltt;
		p->pmlr_pattern = NULL;
		p->pmlr_stmts = NULL;
		return (union pml_tree *)p;
	} break;

	default:
		return NULL;
	}
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
		free(p->pmlv_byteval.data);
	} break;

	case PMLTT_MASKVAL:{
		struct pml_value *p = &tree->value;
		free(p->pmlv_mval.data);
		free(p->pmlv_mmask.data);
	} break;

	case PMLTT_BINOP:{
		struct pml_binop *p = &tree->binop;
		pmlt_free((union pml_tree *)p->pmlb_left);
		pmlt_free((union pml_tree *)p->pmlb_right);
	} break;

	case PMLTT_UNOP:{
		struct pml_unop *p = &tree->unop;
		pmlt_free((union pml_tree *)p->pmlu_expr);
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

	case PMLTT_LOCATOR:{
		struct pml_locator *p = &tree->locator;
		free(p->pmlloc_name);
	} break;

	case PMLTT_PKTACT:{
		struct pml_pkt_action *p = &tree->pktact;
		free(p->pmlpa_name);
		pmlt_free((union pml_tree *)p->pmlpa_pkt);
		pmlt_free((union pml_tree *)p->pmlpa_off);
		pmlt_free((union pml_tree *)p->pmlpa_amount);
	} break;

	case PMLTT_SETACT:{
		struct pml_set_action *p = &tree->setact;
		free(p->pmlsa_vname);
		pmlt_free((union pml_tree *)p->pmlsa_off);
		pmlt_free((union pml_tree *)p->pmlsa_len);
		pmlt_free((union pml_tree *)p->pmlsa_newval);
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

	case PMLTT_FUNCTION:{
		struct pml_function *p = &tree->function;
		uint i;
		if (p->pmlf_pnames != NULL) {
			for (i = 0; i < p->pmlf_nparams; ++i)
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
