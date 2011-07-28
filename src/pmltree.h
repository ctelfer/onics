/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#ifndef __pmltree_h
#define __pmltree_h
#include <cat/cat.h>
#include <cat/list.h>
#include <cat/hash.h>
#include <stdio.h>
#include <stdint.h>
#include "pml.h"

struct pml_ast {
	int			error;
	int			done;
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
	PMLTT_BINOP,
	PMLTT_UNOP,
	PMLTT_FUNCALL,
	PMLTT_IF,
	PMLTT_WHILE,
	PMLTT_LOCATOR,
	PMLTT_LOCADDR,
	PMLTT_ASSIGN,
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
	PMLOP_SHL,
	PMLOP_SHR,
	PMLOP_SRA,
	PMLOP_NOT,
	PMLOP_BINV,
	PMLOP_NEG,
};


struct pml_node_base {
	int			type;
	struct list		ln;
};


struct pml_list {
	int			type;
	struct list		ln;
	struct list		list;
};


union pml_expr_u;


enum {
	PML_ETYPE_UNKNOWN,
	PML_ETYPE_SCALAR,
	PML_ETYPE_BYTESTR,
	PML_ETYPE_MASKSTR,
};
struct pml_expr_base {
	int			type;
	struct list		ln;
	ushort			etype;
	uchar			width;		/* scalar only */
	uchar			issigned;	/* scalar only */
};


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


struct pml_literal {
	int			type;
	struct list		ln;
	ushort			etype;
	uchar			width;		/* scalar only */
	uchar			issigned;	/* scalar only */
	union {
		uint64_t		scalar;
		struct pml_bytestr	bytestr;
		struct pml_maskval	maskval;
	} u;
};


struct pml_op {
	int			type;
	struct list		ln;
	ushort			etype;
	uchar			width;		/* scalar only */
	uchar			issigned;	/* scalar only */
	int			op;
	union pml_expr_u *	arg1;
	union pml_expr_u *	arg2;
};


struct pml_funcall {
	int			type;
	struct list		ln;
	ushort			etype;
	uchar			width;		/* scalar only */
	uchar			issigned;	/* scalar only */
	struct pml_function *	func;
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


struct pml_assign {
	int			type;
	struct list		ln;
	int			conv;	/* byte order conversion */
	struct pml_locator *	loc;
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


enum {
	PML_REF_UNKNOWN,
	PML_REF_VAR,
	PML_REF_NS,
};
struct pml_locator {
	int			type;
	struct list		ln;
	ushort			etype;
	uchar			width;		/* scalar only */
	uchar			issigned;	/* scalar only */
	char *			name;
	int			reftype;
	union pml_expr_u *	pkt;
	union pml_expr_u *	off;
	union pml_expr_u *	len;
	union {
		struct pml_variable *	varref;
		struct ns_elem *	nsref;
	} u;
};


struct pml_sym {
	int			type;
	struct list		ln;
	struct hnode		hn;
};


struct pml_variable {
	int			type;
	struct list		ln;
	struct hnode		hn;
	char *			name;
	int			width;
	union pml_expr_u *	init;
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
	union pml_node *	body;  /* expr for pred, list for func */
};


struct pml_rule {
	int			type;
	struct list		ln;
	union pml_expr_u *	pattern;
	struct pml_list *	stmts;
};


union pml_expr_u {
	struct pml_node_base	base;
	struct pml_expr_base	expr;
	struct pml_literal	literal;
	struct pml_locator	loc;
	struct pml_op		op;
	struct pml_funcall	funcall;
};


union pml_id_u {
	struct pml_sym		sym;
	struct pml_variable	var;
	struct pml_function	func;
};


union pml_node {
	struct pml_node_base	base;
	struct pml_literal	literal;
	struct pml_variable	variable;
	struct pml_op		op;
	struct pml_funcall	funcall;
	struct pml_if		ifstmt;
	struct pml_while	whilestmt;
	struct pml_assign	assign;
	struct pml_return	retact;
	struct pml_print	print;
	struct pml_list		list;
	struct pml_function	function;
	struct pml_rule		rule;
	struct pml_locator	locator;
};


union pml_node *pmln_alloc(int pmltt);
void pmln_free(union pml_node *node);
void pmln_print(union pml_node *node, uint depth);

void pml_ast_init(struct pml_ast *ast);
void pml_ast_clear(struct pml_ast *ast);
void pml_ast_err(struct pml_ast *ast, const char *fmt, ...);
void pml_ast_print(struct pml_ast *ast);
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
				   union pml_expr_u *init);

void pml_bytestr_set_static(struct pml_bytestr *b, void *data, size_t len);
void pml_bytestr_set_dynamic(struct pml_bytestr *b, void *data, size_t len);
void pml_bytestr_free(struct pml_bytestr *b);


struct pml_function *pml_ast_lookup_func(struct pml_ast *ast, char *name);

int pml_locator_extend_name(struct pml_locator *l, char *name, size_t len);


/* Lexical analyzer definitions */

#define PMLLV_SCALAR	0
#define PMLLV_STRING	1

struct pml_lex_val {
	int type;
	union {
		byte_t v6addr[16];
		byte_t ethaddr[6];
		unsigned long num;
		byte_t v4addr[4];
		struct raw raw;
	} u;
};

void pml_lexv_init(struct pml_lex_val *v);
void pml_lexv_fini(int toknum, struct pml_lex_val *v);

#ifndef THIS_IS_SCANNER
typedef void *pml_scanner_t;
int pmllex_init(pml_scanner_t *);
void pmlset_in(FILE *input, pml_scanner_t);
int pmllex(pml_scanner_t);
struct pml_lex_val pmlget_extra(pml_scanner_t);
void pmlset_extra(struct pml_lex_val v, pml_scanner_t);
const char *pmlget_text(pml_scanner_t);
int pmlget_lineno(pml_scanner_t);
void pmllex_destroy(pml_scanner_t);
#endif /* THIS_IS_SCANNER */


/* Parser interface */

typedef void *pml_parser_t;

pml_parser_t pml_alloc();
int pml_parse(pml_parser_t p, struct pml_ast *ast, int tok,
	      struct pml_lex_val xtok);
void pml_free(pml_parser_t p);



#endif /* __pmtree_h */
