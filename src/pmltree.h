/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#ifndef __pmltree_h
#define __pmltree_h
#include <cat/list.h>
#include <cat/hash.h>
#include <stdio.h>

struct pml_ast {
	int pmla_error;
	unsigned long pmla_line;
	struct htab pmla_gvars;
	struct htab pmla_funcs;
	struct list pmla_rules;
	FILE *pmla_err_fp;
};


enum {
	PMLTT_SCALAR,
	PMLTT_BYTESTR,
	PMLTT_MASKVAL,
	PMLTT_VAR,
	PMLTT_VARREF,
	PMLTT_BINOP,
	PMLTT_UNOP,
	PMLTT_FUNCALL,
	PMLTT_IF,
	PMLTT_WHILE,
	PMLTT_NAME,
	PMLTT_OFFSETOF,
	PMLTT_LOCATOR,
	PMLTT_SETACT,
	PMLTT_RETURN,
	PMLTT_PRINT,
	PMLTT_LIST,
	PMLTT_FUNCTION,
	PMLTT_PREDICATE,
	PMLTT_RULE,
};


enum {
	PMLOP_OR,
	PMLOP_AND,
	PMLOP_MATCH,
	PMLOP_NOTMATCH,
	PMLOP_REXMATCH,
	PMLOP_NOTREXMATCH,
	PMLOP_EQ,
	PMLOP_NEQ,
	PMLOP_LT,
	PMLOP_GT,
	PMLOP_LEQ,
	PMLOP_GEQ,
	PMLOP_SLT,
	PMLOP_SGT,
	PMLOP_SLEQ,
	PMLOP_SGEQ,
	PMLOP_BOR,
	PMLOP_BXOR,
	PMLOP_BAND,
	PMLOP_PLUS,
	PMLOP_MINUS,
	PMLOP_TIMES,
	PMLOP_DIV,
	PMLOP_MOD,
	PMLOP_NOT,
	PMLOP_BINV,
	PMLOP_NEG,
};


struct pml_node {
	int pmln_type;
	struct list pmln_ln;
};

union pml_expr_u;

#define PML_BYTESTR_MAX_STATIC	16
struct pml_bytestr {
	int pmlbs_is_dynamic;
	struct raw pmlbs_raw;
	uchar pmlbs_sbytes[PML_BYTESTR_MAX_STATIC];
};
#define pmlbs_data pmlbs_raw.data
#define pmlbs_len pmlbs_raw.len


struct pml_maskval {
	struct pml_bytestr pmlm_val;
	struct pml_bytestr pmlm_mask;
};


struct pml_scalar {
	unsigned long pmls_val;
	int pmls_width;
};


struct pml_value {
	int pmlv_type;
	struct list pmlv_ln;
	union {
		struct pml_scalar u_scalar;
		struct pml_bytestr u_bytestr;
		struct pml_maskval u_maskval;
		struct pml_variable *u_varref;
	} pmlv_u;
};

#define pmlv_scalar     pmlv_u.u_scalar
#define pmlv_sval       pmlv_u.u_scalar.pmls_val
#define pmlv_swidth     pmlv_u.u_scalar.pmls_width
#define pmlv_byteval    pmlv_u.u_bytestr
#define pmlv_maskval    pmlv_u.u_maskval
#define pmlv_mval       pmlv_u.u_maskval.pmlm_val
#define pmlv_mmask      pmlv_u.u_maskval.pmlm_mask
#define pmlv_varref	pmlv_u.u_varref

struct pml_op {
	int pmlo_type;
	struct list pmlo_ln;
	int pmlo_op;
	union pml_expr_u *pmlo_arg1;
	union pml_expr_u *pmlo_arg2;
};


struct pml_funcall {
	int pmlfc_type;
	struct list pmlfc_ln;
	struct pml_func *pmlfc_func;
	struct pml_list *pmlfc_args;	/* expressions */
};


struct pml_if {
	int pmlif_type;
	struct list pmlif_ln;
	union pml_expr_u *pmlif_test;
	struct pml_list *pmlif_tbody;
	struct pml_list *pmlif_fbody;
};


struct pml_while {
	int pmlw_type;
	struct list pmlw_ln;
	union pml_expr_u *pmlw_test;
	struct pml_list *pmlw_body;
};


struct pml_set_action {
	int pmlsa_type;
	struct list pmlsa_ln;
	int pmlsa_conv;		/* byte order conversion */
	struct pml_locator *pmlsa_variable;
	union pml_expr_u *pmlsa_expr;
};


struct pml_return {
	int pmlret_type;
	struct list pmlret_ln;
	union pml_expr_u *pmlret_expr;
};


struct pml_print {
	int pmlp_type;
	struct list pmlp_ln;
	char *pmlp_fmt;
	struct pml_list *pmlp_args;	/* expressions */
};


struct pml_locator {
	int pmlloc_type;
	struct list pmlloc_ln;	/* unused */
	char *pmlloc_name;
	union pml_expr_u *pmlloc_pkt;
	union pml_expr_u *pmlloc_off;
	union pml_expr_u *pmlloc_len;
};


struct pml_list {
	int pmll_type;
	struct list pmll_list;
};


struct pml_variable {
	int pmlvar_type;
	struct list pmlvar_ln;
	struct hnode pmlvar_hn;
	char *pmlvar_name;
	int width;
	struct pml_value *pmlvar_init;
};


/* These are the decls in the program */


struct pml_function {
	int pmlf_type;
	struct list pmlf_ln;
	struct hnode pmlf_hn;
	char *pmlf_name;
	uint pmlf_arity;
	struct htab pmlf_vars;
	struct pml_list *pmlf_prmlist;
	struct pml_list *pmlf_varlist;
	union pml_tree *pmlf_body;  /* expr for pred, list for func */
};


struct pml_rule {
	int pmlr_type;
	struct list pmlr_ln;
	union pml_expr_u *pmlr_pattern;
	struct pml_list *pmlr_stmts;
};


union pml_expr_u {
	struct pml_node node;
	struct pml_value value;
	struct pml_op op;
	struct pml_funcall funcall;
	struct pml_locator locator;
};


union pml_tree {
	struct pml_node node;
	struct pml_value value;
	struct pml_variable variable;
	struct pml_op op;
	union pml_expr_u expr_u;
	struct pml_funcall funcall;
	struct pml_if ifstmt;
	struct pml_while whilestmt;
	struct pml_set_action setact;
	struct pml_return retact;
	struct pml_print print;
	struct pml_list list;
	struct pml_function function;
	struct pml_rule rule;
	struct pml_locator locator;
};


union pml_tree *pmlt_alloc(int pmltt);
void pmlt_free(union pml_tree *tree);

void pml_ast_init(struct pml_ast *ast);
void pml_ast_clear(struct pml_ast *ast);
void pml_ast_err(struct pml_ast *ast, const char *fmt, ...);
struct pml_function *pml_ast_lookup_func(struct pml_ast *ast, char *name);
int pml_ast_add_func(struct pml_ast *ast, struct pml_function *func);
struct pml_variable *pml_ast_lookup_var(struct pml_ast *ast, char *name);
int pml_ast_add_var(struct pml_ast *ast, struct pml_variable *var);

struct pml_variable *pml_func_lookup_var(struct pml_function *func, char *name);
int pml_func_add_var(struct pml_function *func, struct pml_variable *var);

union pml_expr_u *pml_binop_alloc(int op, union pml_expr_u *left, 
		                  union pml_expr_u *right);
union pml_expr_u *pml_unop_alloc(int op, union pml_expr_u *ex);
struct pml_variable *pml_var_alloc(char *name, int width,
				   struct pml_value *init);

void pml_bytestr_set_static(struct pml_bytestr *b, void *data, size_t len);
void pml_bytestr_set_dynamic(struct pml_bytestr *b, void *data, size_t len);
void pml_bytestr_free(struct pml_bytestr *b);


struct pml_function *pml_ast_lookup_func(struct pml_ast *ast, char *name);

int pml_locator_extend_name(struct pml_locator *l, char *name, size_t len);

#endif /* __pmtree_h */
