/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * pmltree.h -- API for PML abstract syntax tree manipulation.
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
#ifndef __pmltree_h
#define __pmltree_h
#include <cat/cat.h>
#include <cat/list.h>
#include <cat/hash.h>
#include <cat/buffer.h>
#include <stdio.h>
#include <stdint.h>
#include "pmllex.h"


/* -- Data structures for the PML Abstract Syntax Tree -- */

/* forward declarations */
union  pml_node;
struct pml_ast;
struct pml_stack_frame;
struct pml_retval;

/* Tree walker */
#define PML_WALK_XSTKLEN	256
typedef int pml_walk_f(union pml_node *node, void *ctx, void *xstk);

/* subtree evaluation */
typedef int (*pml_eval_f)(struct pml_ast *ast, struct pml_stack_frame *fr,
			  union pml_node *node, struct pml_retval *v);


/* Sizes are in bytes for globals and words (8-bytes) for function */
/* parameters and local variables. For global variables, rw block 1 */
/* is for initialized globals while block 2 is for those that the */
/* code does not explicitly initialize.  (initialized to 0).  For */
/* functions, rw block 1 is for parameters and rw block 2 is for */
/* local variables. */
struct pml_symtab {
	struct list		list;
	struct htab		tab;

	ulong			addr_rw1; /* size of read-write block 1 */
	ulong			addr_rw2; /* size of read-write block 2 */
};


struct pml_ast {
	int			error;
	int			done;
	struct pml_symtab	vars;
	struct pml_symtab	funcs;
	struct pml_rule *	b_rule;
	struct list		p_rules;
	struct pml_rule *	t_rule;
	struct pml_rule *	e_rule;
	struct dynbuf		mi_bufs[2];
	struct dynbuf		regexes;
	struct pml_symtab *	ltab;
	struct pml_function *	livefunc;
	char			errbuf[256];
};

/* 
 * we keep the size of the PML_SEG_ROMEM segment in the size of the mi_buf 
 * that corresponds to that segment.  We keep the size of the RW segment in
 * the variable symbol table:  'vars.addr_rw2'.  vars.addr_rw1 is the
 * length of the explictly initialized portion.
 */



enum {
	PML_SEG_NONE = -1,

	PML_SEG_MIN = 0,
	PML_SEG_ROMEM = 0,
	PML_SEG_RWMEM = 1,

	PML_SEG_MAX = PML_SEG_RWMEM,
};


enum {
	PMLTT_LIST,
	PMLTT_SCALAR,
	PMLTT_BYTESTR,
	PMLTT_MASKVAL,
	PMLTT_BINOP,
	PMLTT_UNOP,
	PMLTT_CALL,
	PMLTT_LOCATOR,
	PMLTT_LOCADDR,
	PMLTT_IF,
	PMLTT_WHILE,
	PMLTT_ASSIGN,
	PMLTT_CFMOD,
	PMLTT_PRINT,
	PMLTT_VAR,
	PMLTT_FUNCTION,
	PMLTT_RULE,
};

#define PML_TYPE_IS_EXPR(t) ((t) >= PMLTT_SCALAR && (t) <= PMLTT_LOCADDR)
#define PML_TYPE_IS_STMT(t) ((t) >= PMLTT_IF && (t) <= PMLTT_PRINT)
#define PML_TYPE_IS_DECL(t) ((t) >= PMLTT_VAR && (t) <= PMLTT_RULE)


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
	PMLOP_NOT,
	PMLOP_BINV,
	PMLOP_NEG,
};


#define PML_CGCTX_SIZE		32
struct pml_node_base {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];
};


struct pml_list {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];
	struct list		list;
};


union pml_expr_u;


enum {
	PML_ETYPE_UNKNOWN,
	PML_ETYPE_VOID,
	PML_ETYPE_SCALAR,
	PML_ETYPE_BYTESTR,
	PML_ETYPE_MASKVAL,
	PML_ETYPE_STRREF,
	PML_ETYPE_LAST = PML_ETYPE_STRREF,
};

enum {
	/* expression is constant */
	PML_EFLAG_CONST	= 1,

	/* expression is constant if parameters are constant */
	/* for inline functions. */
	PML_EFLAG_PCONST = 2,

	PML_EFLAG_VARLEN = 4,
};
#define PML_EXPR_IS_SCALAR(ep) \
	(((union pml_expr_u *)ep)->expr.etype == PML_ETYPE_SCALAR)
#define PML_EXPR_IS_BYTESTR(ep) \
	(((union pml_expr_u *)ep)->expr.etype == PML_ETYPE_BYTESTR)
#define PML_EXPR_IS_MASKVAL(ep) \
	(((union pml_expr_u *)ep)->expr.etype == PML_ETYPE_MASKVAL)
#define PML_EXPR_IS_CONST(ep) \
	((((union pml_expr_u *)ep)->expr.eflags & PML_EFLAG_CONST) != 0)
#define PML_EXPR_IS_PCONST(ep) \
	((((union pml_expr_u *)ep)->expr.eflags & \
	  	(PML_EFLAG_CONST|PML_EFLAG_PCONST)) != 0)
#define PML_EXPR_IS_LITERAL(ep) \
	(((union pml_expr_u *)ep)->expr.type >= PMLTT_SCALAR && \
	 ((union pml_expr_u *)ep)->expr.type <= PMLTT_MASKVAL)
struct pml_expr_base {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];
	ushort			etype;
	ushort			eflags;
	ulong			width;
};


struct pml_bytestr {
	int			ispkt;
	int			segnum;
	ulong			addr;
	ulong			len;
};


struct pml_maskval {
	struct pml_bytestr	val;
	struct pml_bytestr	mask;
};


struct pml_literal {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];
	ushort			etype;
	ushort			eflags;
	ulong			width;

	union {
		ulong			scalar;
		struct pml_bytestr	bytestr;
		struct pml_maskval	maskval;
	} u;
};


struct pml_op {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];
	ushort			etype;
	ushort			eflags;
	ulong			width;

	int			op;
	union pml_expr_u *	arg1;
	union pml_expr_u *	arg2;
};


struct pml_call {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];
	ushort			etype;
	ushort			eflags;
	ulong			width;

	struct pml_function *	func;
	struct pml_list *	args;		/* expressions */
};


enum {
	PML_REF_UNKNOWN,
	PML_REF_UNKNOWN_NS_ELEM,	/* temporary */
	PML_REF_VAR,
	PML_REF_PKTFLD,
	PML_REF_LITERAL,
};
enum {
	PML_RPF_NONE,
	PML_RPF_EXISTS,
	/* From here to 'END' must match with NETVM_PRP_* */
	PML_RPF_HLEN,
	PML_RPF_PLEN,
	PML_RPF_TLEN,
	PML_RPF_LEN,
	PML_RPF_ERROR,
	PML_RPF_PRID,
	PML_RPF_INDEX,
	PML_RPF_HEADER,
	PML_RPF_PAYLOAD,
	PML_RPF_TRAILER,
	/* END NETVM_PRP_* match */
	PML_RPF_PARSE,
	PML_RPF_FIRST = PML_RPF_EXISTS,
	PML_RPF_LAST = PML_RPF_PARSE,
};
#define PML_RPF_IS_BYTESTR(f) (((f) >= PML_RPF_HEADER) && \
			       ((f) <= PML_RPF_PARSE))

/* get the corresponding netvm offset index for a given reserved field */
#define PML_RPF_TO_NVMFIELD(f)  ((f) - PML_RPF_HLEN)

/* get the netvm offset index for a given reserved byte string field */
#define PML_RPF_TO_NVMOFF(f)  (((f) == PML_RPF_PARSE) ? \
			        NETVM_PRP_SOFF : \
			        ((f) - PML_RPF_HEADER + NETVM_PRP_SOFF))

/* get the length field for a given reserved byte string field */
#define PML_RPF_TO_NVMLEN(f)  ((f) - PML_RPF_HEADER)

struct pml_locator {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];
	ushort			etype;
	ushort			eflags;
	ulong			width;

	char *			name;
	int			reftype;
	int			rpfld;	/* reserved packet field */
	union pml_expr_u *	pkt;	/* packet number */
	union pml_expr_u *	idx;	/* header index */
	union pml_expr_u *	off;	/* offset into field in bytes */
	union pml_expr_u *	len;	/* length from offset in bytes */
	union {
		struct pml_literal *	litref;
		struct pml_variable *	varref;
		struct ns_elem *	nsref;
	} u;
};


struct pml_if {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];

	union pml_expr_u *	test;
	struct pml_list *	tbody;
	struct pml_list *	fbody;
};


struct pml_while {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];

	union pml_expr_u *	test;
	struct pml_list *	body;
};


struct pml_assign {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];

	struct pml_locator *	loc;
	union pml_expr_u *	expr;
};


enum {
	PML_CFM_UNKNOWN,
	PML_CFM_RETURN,
	PML_CFM_BREAK,
	PML_CFM_CONTINUE,
	PML_CFM_NEXTRULE,
	PML_CFM_SENDALL,
	PML_CFM_DROPALL,
	PML_CFM_SENDONE,
	PML_CFM_DROPONE,
	PML_CFM_SENDNOFREE,
};
struct pml_cfmod {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];

	int			cftype;
	union pml_expr_u *	expr;
};


enum {
	PML_FMT_UNKNOWN,

	/* these take scalars */
	PML_FMT_BIN,
	PML_FMT_OCT,
	PML_FMT_DEC,
	PML_FMT_UDEC,
	PML_FMT_HEX,

	/* these take byte strings */
	PML_FMT_STR,
	PML_FMT_HEXSTR,

	/* these take byte string addresses of 4, 16 and 6 bytes */
	PML_FMT_IPA,
	PML_FMT_IP6A,
	PML_FMT_ETHA,

	PML_FMT_NUM,
};

#define PML_FMT_TO_ETYPE(f) \
	(((f) >= PML_FMT_STR) ? PML_ETYPE_BYTESTR : PML_ETYPE_SCALAR)


enum {
	PML_PFLAG_LJUST = 1,
};


struct pml_print_fmt {
	ulong			width;
	int			fmt;
	int			flags;
};


struct pml_print {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];

	union pml_expr_u *	expr;
	ulong			width;
	int			fmt;
	int			flags;
};


struct pml_sym {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];
	struct hnode		hn;
	char *			name;
};


enum {
	PML_VTYPE_UNKNOWN, 
	PML_VTYPE_CONST,
	PML_VTYPE_GLOBAL,
	PML_VTYPE_PARAM,
	PML_VTYPE_LOCAL,
};


/*
 * The address of each variable should be interpreted according to its type:
 *  - const -> offset in read-only segment
 *  - global -> offset is in the read-write segment
 *  - local -> offset (in bytes) from bottom of the stack frame.
 */
struct pml_variable {
	/* pml_sym_base fields */
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];
	struct hnode		hn;
	char *			name;

	union pml_expr_u *	init;
	struct pml_function *	func;
	ushort			vtype;
	ushort			etype;
	ulong			width;
	ulong			addr;	/* depends on type:  see above */
};


enum {
	PML_FF_INLINE = 1,	/* inline function */
	PML_FF_INTRINSIC = 2,
	PML_FF_PCONST = 4,	/* inline function is const if params are */
};
#define PML_FUNC_IS_INLINE(f)		((f)->flags & PML_FF_INLINE)
#define PML_FUNC_IS_PCONST(f)		((f)->flags & PML_FF_PCONST)
#define PML_FUNC_IS_INTRINSIC(f)	((f)->flags & PML_FF_INTRINSIC)
#define PML_FUNC_IS_REGULAR(f) \
	(((f)->flags & (PML_FF_INTRINSIC|PML_FF_INLINE)) == 0)
struct pml_function {
	/* pml_sym_base fields */
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];
	struct hnode		hn;	/* node for lookup in the AST */
	char *			name;

	ushort			rtype;	/* return type */
	uint			arity;	/* number of arguments */
	uint			callers;
	struct pml_symtab	vars;
	union pml_node *	body;	/* expr for pred, list for func */
	pml_eval_f		ieval;	/* call to eval intrinsic */

	int			flags;
	ulong			pstksz;
	ulong			vstksz;
};


enum {
	PML_RULE_BEGIN,
	PML_RULE_PACKET,
	PML_RULE_TICK,
	PML_RULE_END,
};


struct pml_rule {
	int			type;
	struct list		ln;
	byte_t			cgctx[PML_CGCTX_SIZE];

	int			trigger;
	struct pml_symtab	vars;

	union pml_expr_u *	pattern;
	struct pml_list *	stmts;
	ulong			vstksz;
};


union pml_expr_u {
	struct pml_node_base	base;
	struct pml_expr_base	expr;
	struct pml_literal	literal;
	struct pml_locator	loc;
	struct pml_op		op;
	struct pml_call		call;
};


union pml_node {
	struct pml_node_base	base;
	struct pml_expr_base	expr;
	struct pml_literal	literal;
	struct pml_variable	variable;
	struct pml_op		op;
	struct pml_call		call;
	struct pml_if		ifstmt;
	struct pml_while	whilestmt;
	struct pml_assign	assign;
	struct pml_cfmod	cfmod;
	struct pml_print	print;
	struct pml_list		list;
	struct pml_function	function;
	struct pml_rule		rule;
	struct pml_locator	locator;
};


/* PML expression (and maybe statement) evaluation */
struct pml_stack_frame {
	byte_t *	stack;
	ulong		ssz;
	ulong		psz;
	union {
		struct pml_node_base *	node;
		struct pml_rule *	rule;
		struct pml_function *	func;
	} u;
};


struct pml_retval {
	int			etype;
	struct pml_bytestr	bytes;
	struct pml_bytestr	mask;
	ulong			val;
};


/* structure definition for an intrinsic function to add */
#define PML_MAXIARGS		8
struct pml_param {
	char *			name;
	int			etype;
};
struct pml_intrinsic {
	char *			name;
	int			rtype;
	int			arity;
	int			flags;
	pml_eval_f		eval;
	struct pml_param	params[PML_MAXIARGS];
};


/* -- basic AST initialization and maintenance -- */
int  pml_ast_init(struct pml_ast *ast);
int  pml_ast_add_std_intrinsics(struct pml_ast *ast);
void pml_ast_clear(struct pml_ast *ast);
void pml_ast_err(struct pml_ast *ast, const char *fmt, ...);
void pml_ast_clear_err(struct pml_ast *ast);

/* -- PML AST node allocation -- */
/* returns type (union pml_node *) */
void *pmln_alloc(struct pml_ast *ast, int pmltt);
/* takes type (union pml_node *) */
void pmln_free(void *node);

int  pml_locator_extend_name(struct pml_locator *l, char *name, ulong len);
int  pml_bytestr_copy(struct pml_ast *ast, struct pml_bytestr *bs, int seg,
		      void *data, ulong len);

/* The following 'alloc()' calls all free their subtree arguments if */
/* there is an error creating their respective node. */
union pml_expr_u *pml_binop_alloc(struct pml_ast *ast, int op,
				  union pml_expr_u *left, 
		                  union pml_expr_u *right);
union pml_expr_u *pml_unop_alloc(struct pml_ast *ast, int op,
				 union pml_expr_u *ex);
struct pml_variable *pml_var_alloc(struct pml_ast *ast, char *name, int vtype, 
				   int etype, int size, union pml_expr_u *init);
struct pml_call *pml_call_alloc(struct pml_ast *ast, struct pml_function *func,
				struct pml_list *args);
struct pml_print *pml_print_alloc(struct pml_ast *ast, union pml_expr_u *expr,
				  const struct pml_print_fmt *fmt);
void pml_prlist_free(struct pml_print *p);
int pml_print_strtofmt(const char *s);

/* -- helper functions for symbol values PML (vars, functions, etc) -- */
int pml_func_add_param(struct pml_function *func, struct pml_variable *var);
int pml_func_add_var(struct pml_symtab *t, struct pml_function *f,
		     struct pml_variable *v);
int pml_check_func_proto(struct pml_ast *ast, struct pml_function *f1, 
			 struct pml_function *f2);
int pml_ast_add_func_proto(struct pml_ast *ast, struct pml_function *func);
int pml_ast_add_func(struct pml_ast *ast, struct pml_function *func);
int pml_ast_add_intrinsic(struct pml_ast *ast, struct pml_intrinsic *intr);
struct pml_function *pml_ast_lookup_func(struct pml_ast *ast, char *name);
struct pml_variable *pml_func_lookup_param(struct pml_function *func, 
					   char *name);
int pml_ast_add_var(struct pml_ast *ast, struct pml_variable *var);
int pml_ast_add_rule(struct pml_ast *ast, struct pml_rule *rule);
struct pml_variable *pml_ast_lookup_var(struct pml_ast *ast, char *name);
int pml_ast_add_regex(struct pml_ast *ast, struct pml_literal *lit);
void pml_ast_get_rexarr(struct pml_ast *ast, struct pml_literal ***larr,
			ulong *alen);

/* -- Functions to finalize the AST or portions of it. -- */

/* Resolve a namespace reference to a PML expression. */
/* Returns -1 if there was an internal error. */
/* Returns 0 if the locator could not be resolved. */
/* Returns 1 if the locator was resolved. */
int  pml_locator_resolve_nsref(struct pml_ast *ast, struct pml_locator *loc);
int  pml_resolve_refs(struct pml_ast *ast, union pml_node *node);
struct pml_literal *pml_lookup_ns_literal(struct pml_ast *ast, 
					  struct pml_locator *loc);

void pml_ast_finalize(struct pml_ast *ast);
int  pml_ast_optimize(struct pml_ast *ast);


/* -- Utility functions on a completed tree -- */
/* 
   Walk an abstract syntax tree.  
   Call 'pre' before processing each node, 'in' between subnodes, and 
   'post' after all subnodes are visited.  If the callbacks return < 0,
   abort processing.  If they return > 1 stop visiting the current node
   (and subnodes) but continue on the traversal.  If the return value is
   0, then continue processing.
 */
int  pmln_walk(union pml_node *np, void *ctx, pml_walk_f pre, pml_walk_f in,
	       pml_walk_f post);
int  pml_ast_walk(struct pml_ast *ast, void *ctx, pml_walk_f pre,
		  pml_walk_f in, pml_walk_f post);
void pmln_print(union pml_node *node, uint depth);
void pml_ast_print(struct pml_ast *ast);
int  pml_lit_val(struct pml_ast *ast, struct pml_literal *lit, ulong *val);


/* -- PML tree evaluation -- */
void pml_ast_mem_init(struct pml_ast *ast);
int  pml_eval(struct pml_ast *ast, struct pml_stack_frame *fr, 
	      union pml_node *node, struct pml_retval *v);


/* -- Parser interface -- */

typedef void *pml_parser_t;

pml_parser_t pml_alloc();
int pml_parse(pml_parser_t p, struct pml_ast *ast, int tok,
	      struct pmll_val xtok);
void pml_free(pml_parser_t p);



#endif /* __pmtree_h */
