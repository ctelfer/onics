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
	int			error;
	unsigned long		line;
	struct htab		vartab;
	struct htab		functab;
	struct list		rules;
	FILE *			errfp;
};


enum {
	PMLTT_LIST,
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
	int			type;
	struct list		ln;
};


struct pml_list {
	int			type;
	struct list		ln;
	struct list		list;
};


union pml_expr_u;


#define PML_BYTESTR_MAX_STATIC	16
struct pml_bytestr {
	int			is_dynamic;
	struct raw		bytes;
	uchar			sbytes[PML_BYTESTR_MAX_STATIC];
};


struct pml_maskval {
	struct pml_bytestr	val;
	struct pml_bytestr	mask;
};


struct pml_scalar {
	unsigned long		val;
	int			width;
};


struct pml_value {
	int			type;
	struct list		ln;
	union {
		struct pml_scalar	scalar;
		struct pml_bytestr	bytestr;
		struct pml_maskval	maskval;
		struct pml_variable *	varref;
	} u;
};


struct pml_op {
	int			type;
	struct list		ln;
	int			op;
	union pml_expr_u *	arg1;
	union pml_expr_u *	arg2;
};


struct pml_funcall {
	int			type;
	struct list		ln;
	struct pml_func *	func;
	struct pml_list *	args;	/* expressions */
};


struct pml_if {
	int			type;
	struct list		ln;
	union pml_expr_u *	test;
	struct pml_list *	tbody;
	struct pml_list *	fbody;
};


struct pml_while {
	int			type;
	struct list		ln;
	union pml_expr_u *	test;
	struct pml_list *	body;
};


struct pml_set_action {
	int			type;
	struct list		ln;
	int			conv;	/* byte order conversion */
	struct pml_locator *	variable;
	union pml_expr_u *	expr;
};


struct pml_return {
	int			type;
	struct list		ln;
	union pml_expr_u *	expr;
};


struct pml_print {
	int			type;
	struct list		ln;
	char *			fmt;
	struct pml_list *	args;	/* expressions */
};


struct pml_locator {
	int			type;
	struct list		ln;	/* unused */
	char *			name;
	union pml_expr_u *	pkt;
	union pml_expr_u *	off;
	union pml_expr_u *	len;
};


struct pml_variable {
	int			type;
	struct list		ln;
	struct hnode		hn;
	char *			name;
	int			width;
	struct pml_value *	init;
};


struct pml_function {
	int			type;
	struct list		ln;
	struct hnode		hn;
	char *			name;
	uint			arity;
	struct htab		vars;
	struct pml_list *	prmlist;
	struct pml_list *	varlist;
	union pml_tree *	body;  /* expr for pred, list for func */
};


struct pml_rule {
	int			type;
	struct list		ln;
	union pml_expr_u *	pattern;
	struct pml_list *	stmts;
};


union pml_expr_u {
	struct pml_node		node;
	struct pml_value	value;
	struct pml_op		op;
	struct pml_funcall	funcall;
	struct pml_locator	locator;
};


union pml_tree {
	struct pml_node		node;
	struct pml_value	value;
	struct pml_variable	variable;
	struct pml_op		op;
	struct pml_funcall	funcall;
	struct pml_if		ifstmt;
	struct pml_while	whilestmt;
	struct pml_set_action	setact;
	struct pml_return	retact;
	struct pml_print	print;
	struct pml_list		list;
	struct pml_function	function;
	struct pml_rule		rule;
	struct pml_locator	locator;
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
