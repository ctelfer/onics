/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#include "pmltree.h"
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
	return 0;
}


static union pml_node *symtab_lkup(struct pml_symtab *t, const char *s)
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
	struct list *n;

	abort_unless(t);
	if (t->tab.bkts == NULL)
		return;
	l_for_each(n, &t->list) {
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
	struct list *n;
	ast->error = 0;
	ast->done = 0;
	ast->line = 0;
	symtab_destroy(&ast->vars);
	symtab_destroy(&ast->funcs);
	l_for_each(n, &ast->rules) {
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
}


struct pml_function *pml_ast_lookup_func(struct pml_ast *ast, char *name)
{
	return (struct pml_function *)symtab_lkup(&ast->funcs, name);
}


int pml_ast_add_func(struct pml_ast *ast, struct pml_function *func)
{
	return symtab_add(&ast->funcs, (struct pml_sym *)func);
}


struct pml_variable *pml_ast_lookup_var(struct pml_ast *ast, char *name)
{
	return (struct pml_variable *)symtab_lkup(&ast->vars, name);
}


int pml_ast_add_var(struct pml_ast *ast, struct pml_variable *var)
{
	return symtab_add(&ast->vars, (struct pml_sym *)var);
}


struct pml_variable *pml_func_lookup_param(struct pml_function *func, char *s)
{
	return (struct pml_variable *)symtab_lkup(&func->params, s);
}


int pml_func_add_param(struct pml_function *func, struct pml_variable *var)
{
	return symtab_add(&func->params, (struct pml_sym *)var);
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
			p->etype = PML_ETYPE_UINT;
			p->u.scalar = 0;
			p->width = 8;
		} else if (pmltt == PMLTT_BYTESTR) {
			p->etype = PML_ETYPE_BYTESTR;
			pml_bytestr_set_static(&p->u.bytestr, NULL, 0);
		} else if (pmltt == PMLTT_MASKVAL) {
			p->etype = PML_ETYPE_MASKSTR;
			pml_bytestr_set_static(&p->u.maskval.val, NULL, 0);
			pml_bytestr_set_static(&p->u.maskval.mask, NULL, 0);
		}
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &np->variable;
		p->type = pmltt;
		l_init(&p->ln);
		ht_ninit(&p->hn, NULL, p);
		p->vtype = PML_ETYPE_UNKNOWN;
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
		p->etype = PML_ETYPE_UINT;
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
			p->etype = PML_ETYPE_UINT;
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
		p->conv = 0;
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
		ht_ninit(&p->hn, NULL, p);
		if (symtab_init(&p->params) < 0) {
			free(np);
			return NULL;
		}
		if (symtab_init(&p->vars) < 0) {
			symtab_destroy(&p->params);
			free(np);
			return NULL;
		}
		p->rtype = PML_ETYPE_UINT;
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
	if (PML_EXPR_IS_CONST(left) && PML_EXPR_IS_CONST(right))
		o->eflags = PML_EFLAG_CONST;
	return (union pml_expr_u *)o;
}


union pml_expr_u *pml_unop_alloc(int op, union pml_expr_u *ex)
{
	struct pml_op *o = (struct pml_op *)pmln_alloc(PMLTT_UNOP);
	o->op = op;
	o->arg1 = ex;
	if (PML_EXPR_IS_CONST(ex))
		o->eflags = PML_EFLAG_CONST;
	return (union pml_expr_u *)o;
}


struct pml_variable *pml_var_alloc(char *name, int width, 
		                   union pml_expr_u *init)
{
	struct pml_variable *v = (struct pml_variable *)
		pmln_alloc(PMLTT_VAR);
	v->name = name;
	v->width = width;
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
		ast->error = 1;
		return NULL;
	}

	c->func = func;
	c->args = args;
	c->width = func->width;
	/* TODO: get from rtype */
	c->etype = PML_ETYPE_UINT;
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


/* Basically a pre-order printing traversal of the tree */
void pmlt_print(union pml_node *np, uint depth)
{
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
		printf("Scalar-- width %d: %lu (0x%lx)\n", 
		       (unsigned)p->width, p->u.scalar, p->u.scalar);
	} break;

	case PMLTT_BYTESTR: {
		struct pml_literal *p = &np->literal;
		indent(depth);
		printf("Byte string -- \n");
		print_bytes(&p->u.bytestr, depth);
	} break;

	case PMLTT_MASKVAL: {
		struct pml_literal *p = &np->literal;
		indent(depth);
		printf("Masked Pattern\n");
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
		printf("Variable: %s\n", p->name);
		if (p->init != NULL) {
			indent(depth+1);
			printf("Initialization value -- \n");
			pmlt_print((union pml_node *)p->init, depth+1);
		}
	} break;

	case PMLTT_UNOP: {
		struct pml_op *p = &np->op;
		indent(depth);
		printf("Unary Operation: %d\n", p->op);

		indent(depth);
		printf("Operand -- \n");
		pmlt_print((union pml_node *)p->arg1, depth+1);
	} break;

	case PMLTT_BINOP: {
		struct pml_op *p = &np->op;
		indent(depth);
		printf("Binary Operation: %d\n", p->op);

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
		printf("Function call to: %s\n", 
		       (f == NULL) ? "UNDEFINED!" : f->name);
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
		printf("%s: %s\n", 
		       (p->type == PMLTT_LOCATOR) ? 
		           "Locator"              : 
			   "Location Address",
		       p->name);

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
		printf("%s: %s with %d arguments\n", 
		       (np->base.type == PMLTT_FUNCTION) ? 
		       		"Function" : 
				"Inline Function",
			p->name, p->arity);

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
	l_for_each(n, &ast->vars.list) {
		pmlt_print(l_to_node(n), 1);
	}
	printf("-----------\n");
	printf("Functions\n");
	printf("-----------\n");
	l_for_each(n, &ast->funcs.list) {
		pmlt_print(l_to_node(n), 1);
	}
	printf("-----------\n");
	printf("Rules\n");
	printf("-----------\n");
	l_for_each(n, &ast->rules) {
		pmlt_print(l_to_node(n), 1);
	}
	printf("-----------\n");
}


int pmlt_walk(union pml_node *np, void *ctx, pml_walk_f pre, pml_walk_f in,
	      pml_walk_f post)
{
	int rv = 0;

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
		l_for_each(e, &p->list) {
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

		l_for_each(n, &p->params.list) {
			rv = pmlt_walk(l_to_node(n), ctx, pre, in, post);
			if (rv < 0)
				return rv;
		}

		l_for_each(n, &p->vars.list) {
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


struct pml_resolv_ctx {
	struct pml_block *block;
	struct pml_ast *ast;
};


int pml_resolve_refs(struct pml_ast *ast, union pml_node *node)
{
	return 0;
}




int pml_const_eval(struct pml_ast *ast, union pml_expr_u *e, uint64_t *v)
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


