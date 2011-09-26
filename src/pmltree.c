/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#include "pmltree.h"
#include "ns.h"
#include "util.h"
#include <cat/aux.h>
#include <cat/str.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define l_to_node(p) (union pml_node *)container(p, struct pml_node_base, ln)
#define SYMTABSIZE    256


static int symtab_init(struct pml_symtab *t)
{
	struct hnode **bins;

	abort_unless(t);
	if ((bins = malloc(SYMTABSIZE * sizeof(struct hnode *))) == NULL) {
		return -1;
	}
	ht_init(&t->tab, bins, SYMTABSIZE, cmp_str, ht_shash, NULL);
	l_init(&t->list);
	t->nxtaddr = 0;
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


int pml_ast_init(struct pml_ast *ast)
{
	ast->error = 0;
	ast->done = 0;
	ast->line = 0;
	if (symtab_init(&ast->vars) < 0)
		return -1;
	if (symtab_init(&ast->funcs) < 0) {
		symtab_destroy(&ast->vars);
		return -1;
	}
	l_init(&ast->rules);
	str_copy(ast->errbuf, "", sizeof(ast->errbuf));
	return 0;
}


void pml_ast_clear(struct pml_ast *ast)
{
	struct list *n, *x;
	ast->error = 0;
	ast->done = 0;
	ast->line = 0;
	symtab_destroy(&ast->vars);
	symtab_destroy(&ast->funcs);
	l_for_each_safe(n, x, &ast->rules) {
		pmln_free(l_to_node(n));
	}
	abort_unless(l_isempty(&ast->rules));
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


struct pml_variable *pml_ast_lookup_var(struct pml_ast *ast, char *name)
{
	return (struct pml_variable *)symtab_lookup(&ast->vars, name);
}


int pml_ast_add_var(struct pml_ast *ast, struct pml_variable *var)
{
	if (symtab_add(&ast->vars, (struct pml_sym *)var) < 0) {
		pml_ast_err(ast, "Duplicate global variable: %s\n", var->name);
		return -1;
	}

	if (pml_resolve_refs(ast, (union pml_node *)var) < 0)
		return -1;

	return 0;
}


int pml_ast_add_rule(struct pml_ast *ast, struct pml_rule *rule)
{
	if (pml_resolve_refs(ast, (union pml_node *)rule) < 0)
		return -1;
	l_enq(&ast->rules, &rule->ln);

	return 0;
}


struct pml_variable *pml_func_lookup_param(struct pml_function *func, char *s)
{
	return (struct pml_variable *)symtab_lookup(&func->params, s);
}


int pml_func_add_param(struct pml_function *func, struct pml_variable *var)
{
	int rv;
	rv = symtab_add(&func->params, (struct pml_sym *)var);
	if (rv < 0)
		return -1;
	var->addr = func->params.nxtaddr;
	func->params.nxtaddr += 1;

	/* XXX all parameters must be added before local addresses, so */
	/* the local variable table's next address always starts at the  */
	/* last parameter table's next address. */
	func->vars.nxtaddr = func->params.nxtaddr;

	return 0;
}


union pml_node *pmln_alloc(int pmltt)
{
	union pml_node *np;

	np = calloc(1, sizeof(*np));
	if (np == NULL)
		return NULL;

	switch (pmltt) {

	case PMLTT_LIST: {
		struct pml_list *p = &np->list;
		p->type = pmltt;
		l_init(&p->ln);
		l_init(&p->list);
	} break;

	case PMLTT_SCALAR:
	case PMLTT_BYTESTR:
	case PMLTT_MASKVAL: {
		struct pml_literal *p = &np->literal;
		p->type = pmltt;
		l_init(&p->ln);
		p->eflags = PML_EFLAG_CONST;
		if (pmltt == PMLTT_SCALAR) {
			p->etype = PML_ETYPE_SCALAR;
			p->u.scalar = 0;
			p->width = 8;
		} else if (pmltt == PMLTT_BYTESTR) {
			p->etype = PML_ETYPE_BYTESTR;
			pml_bytestr_set_static(&p->u.bytestr, NULL, 0);
		} else if (pmltt == PMLTT_MASKVAL) {
			p->etype = PML_ETYPE_MASKVAL;
			pml_bytestr_set_static(&p->u.maskval.val, NULL, 0);
			pml_bytestr_set_static(&p->u.maskval.mask, NULL, 0);
		}
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &np->variable;
		p->type = pmltt;
		l_init(&p->ln);
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
		p->type = pmltt;
		p->etype = PML_ETYPE_UNKNOWN;
		p->eflags = 0;
		p->width = 0;
		l_init(&p->ln);
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
		p->type = pmltt;
		l_init(&p->ln);
		p->func = NULL;
		p->args = NULL;
		return (union pml_node *)p;
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &np->ifstmt;
		p->type = pmltt;
		l_init(&p->ln);
		p->test = NULL;
		p->tbody = NULL;
		p->fbody = NULL;
		return (union pml_node *)p;
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &np->whilestmt;;
		p->type = pmltt;
		l_init(&p->ln);
		p->test = NULL;
		p->body = NULL;
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *p = &np->locator;
		p->eflags = 0;
		if (pmltt == PMLTT_LOCATOR) {
			p->etype = PML_ETYPE_UNKNOWN;
			p->width = 0;
		} else {
			p->etype = PML_ETYPE_SCALAR;
			p->width = 8;
		}
		p->reftype = PML_REF_UNKNOWN;
		p->type = pmltt;
		l_init(&p->ln);
		p->name = NULL;
		p->pkt = NULL;
		p->idx = NULL;
		p->off = NULL;
		p->len = NULL;
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *p = &np->assign;
		p->type = pmltt;
		l_init(&p->ln);
		p->loc = NULL;
		p->expr = NULL;
	} break;

	case PMLTT_RETURN: {
		struct pml_return *p = &np->retact;
		p->type = pmltt;
		l_init(&p->ln);
		p->expr = NULL;
        } break;

	case PMLTT_PRINT: {
		struct pml_print *p = &np->print;
		p->type = pmltt;
		l_init(&p->ln);
		p->fmt = NULL;
		p->args = NULL;
	} break;

	case PMLTT_FUNCTION:
	case PMLTT_INLINE: {
		struct pml_function *p = &np->function;
		l_init(&p->ln);
		ht_ninit(&p->hn, "", p);
		if (symtab_init(&p->params) < 0) {
			free(np);
			return NULL;
		}
		if (symtab_init(&p->vars) < 0) {
			symtab_destroy(&p->params);
			free(np);
			return NULL;
		}
		p->isconst = 0;
		p->width = 8;
		p->type = pmltt;
		p->name = NULL;
		p->arity = 0;
		p->body = NULL;
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &np->rule;
		p->type = pmltt;
		l_init(&p->ln);
		symtab_init(&p->vars);
		p->pattern = NULL;
		p->stmts = NULL;
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
		break;

	case PMLTT_BYTESTR: {
		struct pml_literal *p = &node->literal;
		pml_bytestr_free(&p->u.bytestr);
	} break;

	case PMLTT_MASKVAL: {
		struct pml_literal *p = &node->literal;
		pml_bytestr_free(&p->u.maskval.val);
		pml_bytestr_free(&p->u.maskval.mask);
	} break;

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

	case PMLTT_RETURN: {
		struct pml_return *p = &node->retact;
		pmln_free((union pml_node *)p->expr);
	} break;

	case PMLTT_PRINT: {
		struct pml_print *p = &node->print;
		free(p->fmt);
		pmln_free((union pml_node *)p->args);
	} break;

	case PMLTT_FUNCTION:
	case PMLTT_INLINE: {
		struct pml_function *p = &node->function;
		ht_rem(&p->hn);
		free(p->name);
		p->name = NULL;
		symtab_destroy(&p->params);
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
	if (func->type == PMLTT_INLINE && func->isconst) {
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


void pml_bytestr_set_static(struct pml_bytestr *b, void *data, size_t len)
{
	abort_unless(b);
	abort_unless((len == 0) || (data != NULL));
	abort_unless(len <= PML_BYTESTR_MAX_STATIC);
	b->is_dynamic = 0;
	b->bytes.data = b->sbytes;
	b->bytes.len = len;
	memcpy(b->sbytes, data, len);
}


void pml_bytestr_set_dynamic(struct pml_bytestr *b, void *data, size_t len)
{
	abort_unless(b);
	abort_unless(len > 0);
        abort_unless(data != NULL);
	b->is_dynamic = 1;
	b->bytes.data = data;
	b->bytes.len = len;
}


int pml_bytestr_copy(struct pml_bytestr *b, const void *data, size_t len)
{
	void *d;
	abort_unless(b);
	abort_unless(len > 0);
        abort_unless(data != NULL);

	if (len <= PML_BYTESTR_MAX_STATIC) {
		d = malloc(len);
		if (d == NULL)
			return -1;
		if (b->is_dynamic)
			free(b->bytes.data);
		b->bytes.data = d;
		b->is_dynamic = 1;
	} else {
		b->bytes.data = b->sbytes;
		b->is_dynamic = 0;
	}

	memcpy(b->bytes.data, data, len);
	b->bytes.len = len;

	return 0;
}


void pml_bytestr_free(struct pml_bytestr *b)
{
	abort_unless(b);
	if (b->is_dynamic) {
		free(b->bytes.data);
		pml_bytestr_set_static(b, NULL, 0);
	}
}


int pml_locator_extend_name(struct pml_locator *l, char *name, size_t elen)
{
	size_t olen, len;
	char *newname;

	olen = len = strlen(l->name);
	if (len + 2 < len)
		return -1;
	len += 2;
	if (((size_t)0-1) - len < elen)
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


static void print_bytes(struct pml_bytestr *bs, uint depth)
{
	size_t i = 0;
	for (i = 0; i < bs->bytes.len; ++i) {
		if (i % 8 == 0)
			indent(depth);
		printf("%02x", bs->bytes.data[i]);
		if ((i == bs->bytes.len - 1) || (i % 8 == 7))
			fputc('\n', stdout);
	}
}


static const char *eflag_strs[] = {
	"[]", "[c]", "[p]", "[c,p]",
	"[v]", "[cv]", "[pv]", "[cpv]"
};


static const char *efs(void *p, char s[16])
{
	struct pml_expr_base *e = p;
	abort_unless(p);
	abort_unless((e->eflags & ~(PML_EFLAG_CONST|
				    PML_EFLAG_PCONST|
				    PML_EFLAG_VARLEN)) == 0);

	snprintf(s, 16, "[%s; width=%lu]", eflag_strs[e->eflags], 
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
	"unknown", "const", "global", "local"
};
const char *vts(struct pml_variable *v)
{
	abort_unless(v && v->vtype >= PML_VTYPE_UNKNOWN &&
		     v->vtype <= PML_VTYPE_LOCAL);
	return vtype_strs[v->vtype];
}


static const char *rtype_strs[] = {
	"unknown", "variable", "packet field", "proto const",
	"unknown namespace elem"
};
const char *rts(struct pml_locator *l)
{
	abort_unless(l && l->reftype >= PML_REF_UNKNOWN &&
		     l->reftype <= PML_REF_UNKNOWN_NS_ELEM);
	return rtype_strs[l->reftype];
}


/* Basically a pre-order printing traversal of the tree */
void pmlt_print(union pml_node *np, uint depth)
{
	char estr[16];

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
			pmlt_print(l_to_node(e), depth);
			indent(depth);
			printf("-----\n");
		}
	} break;

	case PMLTT_SCALAR: {
		struct pml_literal *p = &np->literal;
		indent(depth);
		printf("Scalar %s -- width %d: %ld (%lu,0x%lx)\n",
		       efs(p, estr), (unsigned)p->width, 
		       (long)p->u.scalar, (unsigned long)p->u.scalar,
		       (long)p->u.scalar);
	} break;

	case PMLTT_BYTESTR: {
		struct pml_literal *p = &np->literal;
		indent(depth);
		printf("Byte string %s -- \n", efs(p, estr));
		print_bytes(&p->u.bytestr, depth);
	} break;

	case PMLTT_MASKVAL: {
		struct pml_literal *p = &np->literal;
		indent(depth);
		printf("Masked Pattern %s \n", efs(p, estr));
		indent(depth);
		printf("Value --\n");
		print_bytes(&p->u.maskval.val, depth);
		indent(depth);
		printf("Mask --\n");
		print_bytes(&p->u.maskval.mask, depth);
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &np->variable;
		indent(depth);
		printf("Variable: %s [%s; width=%lu, addr=%lu]\n", p->name,
		       vts(p), (unsigned long)p->width, (unsigned long)p->addr);
		if (p->init != NULL) {
			indent(depth+1);
			printf("Initialization value -- \n");
			pmlt_print((union pml_node *)p->init, depth+1);
		}
	} break;

	case PMLTT_UNOP: {
		struct pml_op *p = &np->op;
		indent(depth);
		printf("Unary Operation: %d %s\n", p->op, efs(p, estr));

		indent(depth);
		printf("Operand -- \n");
		pmlt_print((union pml_node *)p->arg1, depth+1);
	} break;

	case PMLTT_BINOP: {
		struct pml_op *p = &np->op;
		indent(depth);
		printf("Binary Operation: %d %s\n", p->op, efs(p, estr));

		indent(depth);
		printf("Left Operand -- \n");
		pmlt_print((union pml_node *)p->arg1, depth+1);

		indent(depth);
		printf("Right Operand -- \n");
		pmlt_print((union pml_node *)p->arg2, depth+1);
	} break;

	case PMLTT_CALL: {
		struct pml_call *p = &np->call;
		struct pml_function *f = p->func;
		indent(depth);
		printf("Function call to: %s %s\n", f->name, efs(p, estr));
		indent(depth);
		printf("Arguments -- \n");
		pmlt_print((union pml_node *)p->args, depth+1);
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &np->ifstmt;
		indent(depth);
		printf("If Statement\n");

		indent(depth);
		printf("Test -- \n");
		pmlt_print((union pml_node *)p->test, depth+1);

		indent(depth);
		printf("True body -- \n");
		pmlt_print((union pml_node *)p->tbody, depth+1);

		if (p->fbody != NULL) {
			indent(depth);
			printf("False body -- \n");
			pmlt_print((union pml_node *)p->fbody, depth+1);
		}
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &np->whilestmt;
		indent(depth);
		printf("While Statement\n");

		indent(depth);
		printf("Loop Test -- \n");
		pmlt_print((union pml_node *)p->test, depth+1);

		indent(depth);
		printf("Loop Body -- \n");
		pmlt_print((union pml_node *)p->body, depth+1);
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
			pmlt_print((union pml_node *)p->u.varref, depth+1);
		} else if (p->reftype == PML_REF_PKTFLD) {
			indent(depth);
			printf("Packet field --\n");
		} else if (p->reftype == PML_REF_NS_CONST) {
			indent(depth);
			printf("Protocol Constant --\n");
		}

		if (p->pkt != NULL) {
			indent(depth);
			printf("Packet -- \n");
			pmlt_print((union pml_node *)p->pkt, depth+1);
		}

		if (p->idx != NULL) {
			indent(depth);
			printf("Header Index -- \n");
			pmlt_print((union pml_node *)p->pkt, depth+1);
		}

		if (p->off != NULL) {
			indent(depth);
			printf("Offset -- \n");
			pmlt_print((union pml_node *)p->off, depth+1);
		}

		if (p->len != NULL) {
			indent(depth);
			printf("Length -- \n");
			pmlt_print((union pml_node *)p->len, depth+1);
		}
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *p = &np->assign;
		indent(depth);
		printf("Assignment to %s\n", p->loc->name);

		if (p->expr != NULL) {
			indent(depth);
			printf("Value -- \n");
			pmlt_print((union pml_node *)p->expr, depth+1);
		}
	} break;

	case PMLTT_RETURN: {
		struct pml_return *p = &np->retact;
		indent(depth);
		printf("Function return wth value --\n");
		pmlt_print((union pml_node *)p->expr, depth+1);

        } break;

	case PMLTT_PRINT: {
		struct pml_print *p = &np->print;
		indent(depth);
		printf("Print Statement: \"%s\"\n", p->fmt);
		if (p->args != NULL) {
			indent(depth);
			printf("Arguments -- \n");
			pmlt_print((union pml_node *)p->args, depth+1);
		}
	} break;

	case PMLTT_FUNCTION:
	case PMLTT_INLINE: {
		struct pml_function *p = &np->function;
		struct list *n;
		indent(depth);
		printf("%s: %s%s with %d arguments, return width %lu\n", 
		       (np->base.type == PMLTT_FUNCTION) ? 
		       		"Function" : 
				"Inline Function",
			(p->isconst) ? "(const)" : "",
			p->name, p->arity, (unsigned long)p->width);

		indent(depth);
		printf("Parameters -- \n");
		l_for_each(n, &p->params.list) {
			pmlt_print(l_to_node(n), depth+1);
		}

		indent(depth);
		printf("Variables -- \n");
		l_for_each(n, &p->vars.list) {
			pmlt_print(l_to_node(n), depth+1);
		}

		pmlt_print(p->body, depth+1);
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &np->rule;
		struct list *n;
		indent(depth);
		printf("Rule\n");

		indent(depth);
		if (p->pattern == NULL) {
			printf("Empty pattern\n");
		} else {
			printf("Pattern -- \n");
			pmlt_print((union pml_node *)p->pattern, depth+1);
		}

		indent(depth);
		printf("Action Variables -- \n");
		l_for_each(n, &p->vars.list) {
			pmlt_print(l_to_node(n), depth+1);
		}

		indent(depth);
		printf("Action -- \n");
		pmlt_print((union pml_node *)p->stmts, depth+1);
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
		pmlt_print(l_to_node(n), 1);
	printf("-----------\n");
	printf("Functions\n");
	printf("-----------\n");
	l_for_each(n, &ast->funcs.list)
		pmlt_print(l_to_node(n), 1);
	printf("-----------\n");
	printf("Rules\n");
	printf("-----------\n");
	l_for_each(n, &ast->rules)
		pmlt_print(l_to_node(n), 1);
	printf("-----------\n");
}


int pmlt_walk(union pml_node *np, void *ctx, pml_walk_f pre, pml_walk_f in,
	      pml_walk_f post)
{
	int rv = 0;
	struct list *x;

	if (np == NULL)
		return 0;
	
	if (pre != NULL) {
		rv = (*pre)(np, ctx);
		if (rv < 0)
			return rv;
	}

	switch (np->base.type) {

	case PMLTT_LIST: {
		struct pml_list *p = &np->list;
		struct list *e;
		l_for_each_safe(e, x, &p->list) {
			rv = pmlt_walk(l_to_node(e), ctx, pre, in, post);
			if (rv < 0)
				return rv;
		}
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &np->variable;
		if (p->init != NULL) {
			rv = pmlt_walk((union pml_node *)p->init, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
		}
	} break;

	case PMLTT_UNOP: {
		struct pml_op *p = &np->op;
		rv = pmlt_walk((union pml_node *)p->arg1, ctx, pre, in, post);
		if (rv < 0)
			return rv;
	} break;

	case PMLTT_BINOP: {
		struct pml_op *p = &np->op;

		rv = pmlt_walk((union pml_node *)p->arg1, ctx, pre, in, post);
		if (rv < 0)
			return rv;

		if (in != NULL) {
			rv = (*in)((union pml_node *)p, ctx);
			if (rv < 0)
				return rv;
		}

		rv = pmlt_walk((union pml_node *)p->arg2, ctx, pre, in, post);
		if (rv < 0)
			return rv;
	} break;

	case PMLTT_CALL: {
		struct pml_call *p = &np->call;
		rv = pmlt_walk((union pml_node *)p->args, ctx, pre, in, post);
		if (rv < 0)
			return rv;
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &np->ifstmt;

		rv = pmlt_walk((union pml_node *)p->test, ctx, pre, in, post);
		if (rv < 0)
			return rv;

		rv = pmlt_walk((union pml_node *)p->tbody, ctx, pre, in, post);
		if (rv < 0)
			return rv;

		if (p->fbody != NULL) {
			rv = pmlt_walk((union pml_node *)p->fbody, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
		}
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &np->whilestmt;

		rv = pmlt_walk((union pml_node *)p->test, ctx, pre, in, post);
		if (rv < 0)
			return rv;

		rv = pmlt_walk((union pml_node *)p->body, ctx, pre, in, post);
		if (rv < 0)
			return rv;
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *p = &np->locator;

		if (p->pkt != NULL) {
			rv = pmlt_walk((union pml_node *)p->pkt, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
		}

		if (p->idx != NULL) {
			rv = pmlt_walk((union pml_node *)p->idx, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
		}

		if (p->off != NULL) {
			rv = pmlt_walk((union pml_node *)p->off, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
		}

		if (p->len != NULL) {
			rv = pmlt_walk((union pml_node *)p->len, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
		}
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *p = &np->assign;

		rv = pmlt_walk((union pml_node *)p->loc, ctx, pre, in, post);
		if (rv < 0)
			return rv;

		rv = pmlt_walk((union pml_node *)p->expr, ctx, pre, in, post);
		if (rv < 0)
			return rv;
	} break;

	case PMLTT_RETURN: {
		struct pml_return *p = &np->retact;

		rv = pmlt_walk((union pml_node *)p->expr, ctx, pre, in, post);
		if (rv < 0)
			return rv;
        } break;

	case PMLTT_PRINT: {
		struct pml_print *p = &np->print;

		rv = pmlt_walk((union pml_node *)p->args, ctx, pre, in, post);
		if (rv < 0)
			return rv;
	} break;

	case PMLTT_FUNCTION:
	case PMLTT_INLINE: {
		struct pml_function *p = &np->function;
		struct list *n;

		l_for_each_safe(n, x, &p->params.list) {
			rv = pmlt_walk(l_to_node(n), ctx, pre, in, post);
			if (rv < 0)
				return rv;
		}

		l_for_each_safe(n, x, &p->vars.list) {
			rv = pmlt_walk(l_to_node(n), ctx, pre, in, post);
			if (rv < 0)
				return rv;
		}

		rv = pmlt_walk((union pml_node *)p->body, ctx, pre, in, post);
		if (rv < 0)
			return rv;
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &np->rule;

		if (p->pattern != NULL) {
			rv = pmlt_walk((union pml_node *)p->pattern, ctx, pre,
				       in, post);
			if (rv < 0)
				return rv;
		}

		rv = pmlt_walk((union pml_node *)p->stmts, ctx, pre, in, post);
		if (rv < 0)
			return rv;
	} break;

	default:
		break;
	}

	if (post != NULL) {
		rv = (*post)(np, ctx);
		if (rv < 0)
			return rv;
	}

	return 0;
}


int pml_locator_resolve_nsref(struct pml_locator *l)
{
	struct ns_elem *e;
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	struct ns_scalar *sc;
	struct ns_bytestr *bs;
	struct ns_maskstr *ms;
	struct pml_literal *lit;
	uint64_t off, len;

	abort_unless(l && l->name);

	e = ns_lookup(NULL, l->name);
	if (e == NULL)
		return 0;

	switch (e->type) {
	case NST_NAMESPACE:
		l->u.nsref = e;
		ns = (struct ns_namespace *)e;
		l->reftype = PML_REF_PKTFLD;
		if ((ns->flags & NSF_VARLEN) != 0) {
			l->width = 0;
			l->eflags |= PML_EFLAG_VARLEN;
		} else {
			l->width = ns->len;
		}
		break;

	case NST_PKTFLD:
		l->u.nsref = e;
		pf = (struct ns_pktfld *)e;
		l->reftype = PML_REF_PKTFLD;
		if ((pf->flags & NSF_VARLEN) != 0) {
			l->width = 0;
			l->eflags |= PML_EFLAG_VARLEN;
		} else {
			l->width = pf->len;
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
		bs = (struct ns_bytestr *)e;
		off = 0;
		if (l->off != NULL) {
			if (pml_const_eval(l->off, &off) < 0)
				return -1;
		}
		if (off >= bs->value.len)
			return -1;
		len = bs->value.len;
		if (l->len != NULL) {
			if (pml_const_eval(l->len, &len) < 0)
				return -1;
		}
		if (bs->value.len - off > len)
			return -1;

		lit = (struct pml_literal *)pmln_alloc(PMLTT_BYTESTR);
		if (lit == NULL)
			return -1;
		if (pml_bytestr_copy(&lit->u.bytestr, bs->value.data + off,
				     len) < 0) {
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
		if ((pml_bytestr_copy(&lit->u.maskval.val,
				      ms->value.data, ms->value.len) < 0) ||
		    (pml_bytestr_copy(&lit->u.maskval.mask,
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
	/* at most 3 var symbol tables to consider:  params, vars, global */
	struct pml_symtab *symtabs[3];
	int nst;
	int vtidx;
	struct pml_ast *ast;
};


static struct pml_variable *rlookup(struct pml_resolve_ctx *ctx, 
				    const char *name, int *ti)
{
	int i;
	union pml_node *node;

	for (i = 0; i < ctx->nst; ++i) {
		node = symtab_lookup(ctx->symtabs[i], name);
		if (node != NULL) {
			abort_unless(node->base.type == PMLTT_VAR);
			*ti = i;
			return (struct pml_variable *)node;
		}
	}

	return NULL;
}


static int resolve_locator(struct pml_resolve_ctx *ctx, struct pml_locator *l)
{
	struct pml_variable *v;
	int ti;
	int rv;
	struct pml_symtab *t;

	/* check if already resolved */
	if ((l->reftype != PML_REF_UNKNOWN) && 
	    (l->reftype != PML_REF_UNKNOWN_NS_ELEM))
		return 0;

	if ((l->reftype == PML_REF_UNKNOWN_NS_ELEM) || 
	    (l->reftype == PML_REF_UNKNOWN)) {
		rv = pml_locator_resolve_nsref(l);
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

	v = rlookup(ctx, l->name, &ti);
	if (v != NULL) {
		l->reftype = PML_REF_VAR;
		l->u.varref = v;
		if (v->vtype == PML_VTYPE_CONST)
			l->eflags |= (PML_EFLAG_CONST|PML_EFLAG_PCONST);
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
	v = pml_var_alloc(l->name, 8, PML_VTYPE_LOCAL, NULL);
	if (v == NULL) {
		pml_ast_err(ctx->ast, "out of memory building ast\n");
		return -1;
	}
	v->addr = t->nxtaddr;
	t->nxtaddr += 1;
	symtab_add(t, (struct pml_sym *)v);
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
			pml_ast_err(ast, "Left argument of a match operation "
					 "must be a byte string: %s instead\n",
				    ets(a1));
			return -1;
		}
		if (a1->etype != PML_ETYPE_BYTESTR &&
		    a2->etype != PML_ETYPE_MASKVAL) {
			pml_ast_err(ast, "Right argument of a match operation "
					 "must be a byte string or masked "
					 "string: %s instead\n", ets(a2));
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


static int resolve_node(union pml_node *node, void *ctxp)
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
		if ((f->type == PMLTT_INLINE) && f->isconst) {
			c->eflags |= PML_EFLAG_PCONST;
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
		if (resolve_locator(ctx, l) < 0)
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
		if (resolve_locator(ctx, l) < 0)
			return -1;
		if ((l->reftype == PML_REF_NS_CONST) || 
		    ((l->reftype == PML_REF_VAR) && 
		     (l->u.varref->vtype == PML_VTYPE_CONST))) {
			pml_ast_err(ctx->ast, "'%s' is not a field with"
					      "an address to take\n",
				    l->name);
			return -1;
		}
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


int pml_resolve_refs(struct pml_ast *ast, union pml_node *node)
{
	struct pml_resolve_ctx ctx;
	int rv;

	ctx.ast = ast;

	if (node->base.type == PMLTT_RULE) {
		struct pml_rule *rule = (struct pml_rule *)node;
		ctx.symtabs[0] = &rule->vars;
		ctx.symtabs[1] = &ast->vars;
		ctx.nst = 2;
		ctx.vtidx = 0;
		rv = pmlt_walk((union pml_node *)rule->pattern, &ctx, NULL,
			       NULL, resolve_node);
		if (rv < 0)
			return -1;
		return pmlt_walk((union pml_node *)rule->stmts, &ctx, NULL,
				 NULL, resolve_node);
	} else if (node->base.type == PMLTT_FUNCTION) {
		struct pml_function *func = (struct pml_function *)node;
		ctx.symtabs[0] = &func->params;
		ctx.symtabs[1] = &func->vars;
		ctx.symtabs[2] = &ast->vars;
		ctx.nst = 3;
		ctx.vtidx = 1;
		return pmlt_walk((union pml_node *)func->body, &ctx, NULL,
				 NULL, resolve_node);
	} else if (node->base.type == PMLTT_INLINE) {
		struct pml_function *inln = (struct pml_function *)node;
		struct pml_expr_base *pe;
		ctx.symtabs[0] = &inln->params;
		ctx.symtabs[1] = &ast->vars;
		ctx.nst = 2;
		ctx.vtidx = -1; /* no local variables in inlines */
		rv = pmlt_walk((union pml_node *)inln->body, &ctx, NULL, NULL,
			       resolve_node);
		if (rv < 0)
			return -1;
		inln->isconst = PML_EXPR_IS_PCONST(node);
		pe = (struct pml_expr_base *)inln->body;
		if (pe->etype != PML_ETYPE_SCALAR) {
			pml_ast_err(ast, "Non-scalar expression for inline %s "
					 "(type = %d)\n",
				    inln->name, pe->etype);
			return -1;
		}
		return 0;
	} else if (node->base.type == PMLTT_VAR) {
		struct pml_variable *var = (struct pml_variable *)node;
		ctx.symtabs[0] = &ast->vars;
		ctx.nst = 1;
		ctx.vtidx = -1;
		rv = pmlt_walk((union pml_node *)var->init, &ctx, NULL,
			       NULL, resolve_node);
		if (rv < 0)
			return -1;

		if (var->init != NULL) {
			if (!PML_EXPR_IS_CONST(var->init)) {
				pml_ast_err(ast, 
					    "Global %s %s initialization value"
					    " is not constant.\n", 
					    (var->vtype == PML_VTYPE_GLOBAL 
						? "global"
						: "const"),
					    var->name);
				return -1;
			}
			if (var->init->expr.etype != var->etype) {
				pml_ast_err(ast,
					    "Variable %s initialization "
					    "expression does not match "
					    "variable type (%s vs %s)\n",
					    etype_strs[var->etype], 
					    ets(var->init));
				return -1;
			}
		}
		return 0;
	} else {
		pml_ast_err(ast, "Invalid node type for resolution: %d\n",
			    node->base.type);
		return -1;
	}
}


int pml_const_eval(union pml_expr_u *e, uint64_t *v)
{
	return -1;
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


