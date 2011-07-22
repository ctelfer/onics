/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#include "pmltree.h"
#include <cat/aux.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define l_to_node(p) container(p, struct pml_node_base, ln)
#define SYMTABSIZE    256


static int symtab_init(struct htab *ht)
{
	struct hnode **bins;
	if ((bins = malloc(SYMTABSIZE * sizeof(struct hnode *))) == NULL)
		return -1;
	ht_init(ht, bins, SYMTABSIZE, cmp_str, ht_shash, NULL);
	return 0;
}


static struct pml_function *ftab_lkup(struct htab *ht, const char *s)
{
	uint h;
	struct hnode *hn;

	abort_unless(ht && s);
	if ((hn = ht_lkup(ht, (void *)s, &h)) == NULL)
		return NULL;
	return container(hn, struct pml_function, hn);
}


static int ftab_add(struct htab *ht, struct pml_function *func) 
{
	uint h;
	struct hnode *hn;

	if (ht_lkup(ht, func->name, &h) != NULL)
		return -1;
	hn = &func->hn;
	ht_ninit(hn, func->name, func);
	ht_ins(ht, hn, h);

	return 0;
}


static struct pml_variable *vtab_lkup(struct htab *ht, const char *s)
{
	uint h;
	struct hnode *hn;

	abort_unless(ht && s);
	if ((hn = ht_lkup(ht, (void *)s, &h)) == NULL)
		return NULL;
	return container(hn, struct pml_variable, hn);
}


static int vtab_add(struct htab *ht, struct pml_variable *var) 
{
	uint h;
	struct hnode *hn;

	if (ht_lkup(ht, var->name, &h) != NULL)
		return -1;
	hn = &var->hn;
	ht_ninit(hn, var->name, var);
	ht_ins(ht, hn, h);

	return 0;
}


static void freesym(void *nodep, void *ctx)
{
	struct pml_node_base *node = nodep;
	if (node->type == PMLTT_VAR) {
		struct pml_variable *p = nodep;
		ht_rem(&p->hn);
		l_rem(&p->ln);
	} else if (node->type == PMLTT_FUNCTION) {
		struct pml_function *p = nodep;
		ht_rem(&p->hn);
		l_rem(&p->ln);
	} else {
		abort_unless(0);
	}
	pmln_free((union pml_node *)node);
}


static void symtab_destroy(struct htab *ht)
{
	if (ht->bkts == NULL)
		return;
	ht_apply(ht, freesym, NULL);
	free(ht->bkts);
	ht->bkts = NULL;
}


static void freerule(void *rulep, void *ctx)
{
	struct pml_rule *r = rulep;
	l_rem(&r->ln);
	pmln_free((union pml_node *)r);
}


void pml_ast_init(struct pml_ast *ast)
{
	ast->error = 0;
	ast->done = 0;
	ast->line = 0;
	symtab_init(&ast->vartab);
	symtab_init(&ast->functab);
	l_init(&ast->rules);
	ast->errfp = stderr;
}


void pml_ast_clear(struct pml_ast *ast)
{
	ast->error = 0;
	ast->done = 0;
	ast->line = 0;
	symtab_destroy(&ast->vartab);
	symtab_destroy(&ast->functab);
	l_apply(&ast->rules, freerule, NULL);
	l_init(&ast->rules);
	ast->errfp = NULL;
}


void pml_ast_err(struct pml_ast *ast, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (ast->errfp != NULL)
		vfprintf(ast->errfp, fmt, ap);
	va_end(ap);
}


struct pml_function *pml_ast_lookup_func(struct pml_ast *ast, char *name)
{
	return ftab_lkup(&ast->functab, name);
}


int pml_ast_add_func(struct pml_ast *ast, struct pml_function *func)
{
	return ftab_add(&ast->functab, func);
}


struct pml_variable *pml_ast_lookup_var(struct pml_ast *ast, char *name)
{
	return vtab_lkup(&ast->vartab, name);
}


int pml_ast_add_var(struct pml_ast *ast, struct pml_variable *var)
{
	return vtab_add(&ast->vartab, var);
}


struct pml_variable *pml_func_lookup_var(struct pml_function *func, char *name)
{
	return vtab_lkup(&func->vars, name);
}


int pml_func_add_var(struct pml_function *func, struct pml_variable *var)
{
	return vtab_add(&func->vars, var);
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
	case PMLTT_MASKVAL:
	case PMLTT_VARREF:
	case PMLTT_VARADDR: {
		struct pml_value *p = &np->value;
		p->type = pmltt;
		l_init(&p->ln);
		if (pmltt == PMLTT_SCALAR) {
			p->u.scalar.val = 0;
			p->u.scalar.width = 4;
		} else if (pmltt == PMLTT_BYTESTR) {
			pml_bytestr_set_static(&p->u.bytestr, NULL, 0);
		} else if (pmltt == PMLTT_MASKVAL) {
			pml_bytestr_set_static(&p->u.maskval.val, NULL, 0);
			pml_bytestr_set_static(&p->u.maskval.mask, NULL, 0);
		} else {
			p->u.varname = NULL;
		}
		p->varref = NULL;
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &np->variable;
		p->type = pmltt;
		l_init(&p->ln);
		p->name = NULL;
		p->init = NULL;
	} break;

	case PMLTT_UNOP:
	case PMLTT_BINOP: {
		struct pml_op *p = &np->op;
		p->type = pmltt;
		l_init(&p->ln);
		p->op = 0;
		p->arg1 = NULL;
		p->arg2 = NULL;
		return (union pml_node *)p;
	} break;

	case PMLTT_FUNCALL: {
		struct pml_funcall *p = &np->funcall;
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

	case PMLTT_LOCATOR: {
		struct pml_locator *p = &np->locator;
		p->type = pmltt;
		l_init(&p->ln);
		p->name = NULL;
		p->pkt = NULL;
		p->off = NULL;
		p->len = NULL;
	} break;

	case PMLTT_SETACT: {
		struct pml_set_action *p = &np->setact;
		p->type = pmltt;
		l_init(&p->ln);
		p->conv = 0;
		p->varname = NULL;
		p->varref = NULL;
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
	case PMLTT_PREDICATE: {
		struct pml_function *p = &np->function;
		if (symtab_init(&p->vars) < 0) {
			free(np);
			return NULL;
		}
		p->type = pmltt;
		l_init(&p->ln);
		p->name = NULL;
		p->arity = 0;
		p->prmlist = NULL;
		p->varlist = NULL;
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

	switch (node->base.type) {

	case PMLTT_LIST: {
		struct pml_list *p = &node->list;
		struct list *l;
		while ((l = l_deq(&p->list)) != NULL)
			pmln_free((union pml_node *)l_to_node(l));
	} break;

	case PMLTT_SCALAR:
		break;

	case PMLTT_VARREF: 
	case PMLTT_VARADDR: {
		struct pml_value *p = &node->value;
		pmln_free((union pml_node *)p->u.varname);
	} break;

	case PMLTT_BYTESTR: {
		struct pml_value *p = &node->value;
		pml_bytestr_free(&p->u.bytestr);
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &node->variable;
		free(p->name);
		pmln_free((union pml_node *)p->init);
	}

	case PMLTT_MASKVAL: {
		struct pml_value *p = &node->value;
		pml_bytestr_free(&p->u.maskval.val);
		pml_bytestr_free(&p->u.maskval.mask);
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

	case PMLTT_FUNCALL: {
		struct pml_funcall *p = &node->funcall;
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

	case PMLTT_LOCATOR: {
		struct pml_locator *p = &node->locator;
		free(p->name);
		pmln_free((union pml_node *)p->pkt);
		pmln_free((union pml_node *)p->off);
		pmln_free((union pml_node *)p->len);
	} break;

	case PMLTT_SETACT: {
		struct pml_set_action *p = &node->setact;
		pmln_free((union pml_node *)p->varname);
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
	case PMLTT_PREDICATE: {
		struct pml_function *p = &node->function;
		free(p->name);
		p->name = NULL;
		symtab_destroy(&p->vars);
		pmln_free((union pml_node *)p->prmlist);
		pmln_free((union pml_node *)p->varlist);
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


struct pml_variable *pml_var_alloc(char *name, int width, 
		                   struct pml_value *init)
{
	struct pml_variable *v = (struct pml_variable *)
		pmln_alloc(PMLTT_VAR);
	v->name = name;
	v->init = init;
	return v;
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
			union pml_node *en = 
				(union pml_node *)
					container(e, struct pml_node_base, ln);
			pmlt_print(en, depth);
			indent(depth);
			printf("-----\n");
		}
	} break;

	case PMLTT_SCALAR: {
		struct pml_value *p = &np->value;
		indent(depth);
		printf("Scalar-- width %d: %lu (0x%lx)\n", 
		       p->u.scalar.width, p->u.scalar.val, p->u.scalar.val);
	} break;

	case PMLTT_BYTESTR: {
		struct pml_value *p = &np->value;
		indent(depth);
		printf("Byte string -- \n");
		print_bytes(&p->u.bytestr, depth);
	} break;

	case PMLTT_MASKVAL: {
		struct pml_value *p = &np->value;
		indent(depth);
		printf("Masked Pattern\n");
		indent(depth);
		printf("Value --\n");
		print_bytes(&p->u.maskval.val, depth);
		printf("Mask --\n");
		print_bytes(&p->u.maskval.mask, depth);
	} break;

	case PMLTT_VARREF:
	case PMLTT_VARADDR: {
		struct pml_value *p = &np->value;
		struct pml_locator *l = p->u.varname;
		indent(depth);
		printf("%s: %s (%s)\n",
		       (np->base.type == PMLTT_VARREF) ? 
		       		"Variable Reference" : "Variable address",
		       (l != NULL) ? "BAD REFERENCE" : l->name,
		       (p->varref != NULL) ? "resolved" : "unresolved");
		indent(depth);
		printf("Variable -- \n");
		pmlt_print((union pml_node *)l, depth+1);
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

	case PMLTT_FUNCALL: {
		struct pml_funcall *p = &np->funcall;
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

	case PMLTT_LOCATOR: {
		struct pml_locator *p = &np->locator;
		indent(depth);
		printf("Locator: %s\n", p->name);

		if (p->pkt != NULL) {
			indent(depth);
			printf("Packet -- \n");
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

	case PMLTT_SETACT: {
		struct pml_set_action *p = &np->setact;
		indent(depth);
		printf("Assignment to %s (%s)\n", p->varname->name,
		       (p->varref != NULL) ? "resolved" : "unresolved");

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
	case PMLTT_PREDICATE: {
		struct pml_function *p = &np->function;
		indent(depth);
		printf("%s: %s with %d arguments\n", 
		       (np->base.type == PMLTT_FUNCTION) ? 
		       		"Function" : 
				"Predicate",
			p->name, p->arity);

		indent(depth);
		printf("Parameters -- \n");
		pmlt_print((union pml_node *)p->prmlist, depth+1);

		indent(depth);
		printf("Variables -- \n");
		pmlt_print((union pml_node *)p->varlist, depth+1);

		pmlt_print(p->body, depth+1);
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &np->rule;
		indent(depth);
		printf("Rule\n");

		indent(depth);
		printf("Pattern -- \n");
		pmlt_print((union pml_node *)p->pattern, depth+1);

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
	struct hnode *hn;
	struct hash_iter hi;
	struct list *ln;

	printf("Printing PML Abstract Syntax Tree\n");
	printf("-----------\n");
	printf("Variables\n");
	ht_for_each(hn, hi, ast->vartab) {
		struct pml_variable *p = container(hn, struct pml_variable, hn);
		pmlt_print((union pml_node *)p, 1);

	}
	printf("-----------\n");
	printf("Functions\n");
	ht_for_each(hn, hi, ast->functab) {
		struct pml_function *p = container(hn, struct pml_function, hn);
		pmlt_print((union pml_node *)p, 1);
	}
	printf("-----------\n");
	printf("Rules\n");
	l_for_each(ln, &ast->rules) {
		union pml_node *en = 
			(union pml_node *)
				container(ln, struct pml_node_base, ln);
		pmlt_print((union pml_node *)en, 1);
	}
	printf("-----------\n");
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


