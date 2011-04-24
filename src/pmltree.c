/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#include "pmltree.h"
#include <cat/aux.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define l_to_node(p) container(p, struct pml_node, ln)
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
	struct pml_node *node = nodep;
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
	pmlt_free((union pml_tree *)node);
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
	pmlt_free((union pml_tree *)r);
}


void pml_ast_init(struct pml_ast *ast)
{
	ast->error = 0;
	ast->line = 0;
	symtab_init(&ast->vartab);
	symtab_init(&ast->functab);
	l_init(&ast->rules);
	ast->errfp = stderr;
}


void pml_ast_clear(struct pml_ast *ast)
{
	ast->error = 0;
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


union pml_tree *pmlt_alloc(int pmltt)
{
	union pml_tree *tp;

	tp = calloc(1, sizeof(*tp));
	if (tp == NULL)
		return NULL;

	switch (pmltt) {

	case PMLTT_LIST: {
		struct pml_list *p = &tp->list;
		p->type = pmltt;
		l_init(&p->ln);
		l_init(&p->list);
	} break;

	case PMLTT_SCALAR:
	case PMLTT_BYTESTR:
	case PMLTT_MASKVAL:
	case PMLTT_VARREF:
	case PMLTT_VARADDR: {
		struct pml_value *p = &tp->value;
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
		struct pml_variable *p = &tp->variable;
		p->type = pmltt;
		l_init(&p->ln);
		p->name = NULL;
		p->init = NULL;
	} break;

	case PMLTT_UNOP:
	case PMLTT_BINOP: {
		struct pml_op *p = &tp->op;
		p->type = pmltt;
		l_init(&p->ln);
		p->op = 0;
		p->arg1 = NULL;
		p->arg2 = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_FUNCALL: {
		struct pml_funcall *p = &tp->funcall;
		p->type = pmltt;
		l_init(&p->ln);
		p->func = NULL;
		p->args = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &tp->ifstmt;
		p->type = pmltt;
		l_init(&p->ln);
		p->test = NULL;
		p->tbody = NULL;
		p->fbody = NULL;
		return (union pml_tree *)p;
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &tp->whilestmt;;
		p->type = pmltt;
		l_init(&p->ln);
		p->test = NULL;
		p->body = NULL;
	} break;

	case PMLTT_NAME:
	case PMLTT_OFFSETOF:
	case PMLTT_LOCATOR: {
		struct pml_locator *p = &tp->locator;
		p->type = pmltt;
		l_init(&p->ln);
		p->name = NULL;
		p->pkt = NULL;
		p->off = NULL;
		p->len = NULL;
	} break;

	case PMLTT_SETACT: {
		struct pml_set_action *p = &tp->setact;
		p->type = pmltt;
		l_init(&p->ln);
		p->conv = 0;
		p->varname = NULL;
		p->varref = NULL;
		p->expr = NULL;
	} break;

	case PMLTT_RETURN: {
		struct pml_return *p = &tp->retact;
		p->type = pmltt;
		l_init(&p->ln);
		p->expr = NULL;
        } break;

	case PMLTT_PRINT: {
		struct pml_print *p = &tp->print;
		p->type = pmltt;
		l_init(&p->ln);
		p->fmt = NULL;
		p->args = NULL;
	} break;

	case PMLTT_FUNCTION:
	case PMLTT_PREDICATE: {
		struct pml_function *p = &tp->function;
		if (symtab_init(&p->vars) < 0) {
			free(tp);
			return NULL;
		}
		p->type = pmltt;
		l_init(&p->ln);
		p->name = NULL;
		p->arity = 0;
		p->prmlist = NULL;
		p->varlist = NULL;
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &tp->rule;
		p->type = pmltt;
		l_init(&p->ln);
		p->pattern = NULL;
		p->stmts = NULL;
	} break;

	default: {
		free(tp);
		tp = NULL;
	} break;

	}
	return tp;
}


void pmlt_free(union pml_tree *tree)
{
	if (tree == NULL)
		return;

	switch (tree->node.type) {

	case PMLTT_LIST: {
		struct pml_list *p = &tree->list;
		struct list *l;
		while ((l = l_deq(&p->list)) != NULL)
			pmlt_free((union pml_tree *)l_to_node(l));
	} break;

	case PMLTT_SCALAR:
		break;

	case PMLTT_VARREF: 
	case PMLTT_VARADDR: {
		struct pml_value *p = &tree->value;
		pmlt_free((union pml_tree *)&p->u.varname);
	} break;

	case PMLTT_BYTESTR: {
		struct pml_value *p = &tree->value;
		pml_bytestr_free(&p->u.bytestr);
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &tree->variable;
		free(p->name);
		pmlt_free((union pml_tree *)p->init);
	}

	case PMLTT_MASKVAL: {
		struct pml_value *p = &tree->value;
		pml_bytestr_free(&p->u.maskval.val);
		pml_bytestr_free(&p->u.maskval.mask);
	} break;

	case PMLTT_BINOP: {
		struct pml_op *p = &tree->op;
		pmlt_free((union pml_tree *)p->arg1);
		pmlt_free((union pml_tree *)p->arg2);
	} break;

	case PMLTT_UNOP: {
		struct pml_op *p = &tree->op;
		pmlt_free((union pml_tree *)p->arg1);
	} break;

	case PMLTT_FUNCALL: {
		struct pml_funcall *p = &tree->funcall;
		pmlt_free((union pml_tree *)p->args);
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &tree->ifstmt;
		pmlt_free((union pml_tree *)p->test);
		pmlt_free((union pml_tree *)p->tbody);
		pmlt_free((union pml_tree *)p->fbody);
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &tree->whilestmt;
		pmlt_free((union pml_tree *)p->test);
		pmlt_free((union pml_tree *)p->body);
	} break;

	case PMLTT_NAME:
	case PMLTT_OFFSETOF:
	case PMLTT_LOCATOR: {
		struct pml_locator *p = &tree->locator;
		free(p->name);
		pmlt_free((union pml_tree *)p->pkt);
		pmlt_free((union pml_tree *)p->off);
		pmlt_free((union pml_tree *)p->len);
	} break;

	case PMLTT_SETACT: {
		struct pml_set_action *p = &tree->setact;
		pmlt_free((union pml_tree *)p->varname);
		pmlt_free((union pml_tree *)p->expr);
	} break;

	case PMLTT_RETURN: {
		struct pml_return *p = &tree->retact;
		pmlt_free((union pml_tree *)p->expr);
	} break;

	case PMLTT_PRINT: {
		struct pml_print *p = &tree->print;
		free(p->fmt);
		pmlt_free((union pml_tree *)p->args);
	} break;

	case PMLTT_FUNCTION:
	case PMLTT_PREDICATE: {
		struct pml_function *p = &tree->function;
		free(p->name);
		p->name = NULL;
		symtab_destroy(&p->vars);
		pmlt_free((union pml_tree *)p->prmlist);
		pmlt_free((union pml_tree *)p->varlist);
		pmlt_free(p->body);
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &tree->rule;
		pmlt_free((union pml_tree *)p->pattern);
		pmlt_free((union pml_tree *)p->stmts);
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
	o->op = op;
	o->arg1 = left;
	o->arg2 = right;
	return (union pml_expr_u *)o;
}


union pml_expr_u *pml_unop_alloc(int op, union pml_expr_u *ex)
{
	struct pml_op *o = (struct pml_op *)pmlt_alloc(PMLTT_UNOP);
	o->op = op;
	o->arg1 = ex;
	return (union pml_expr_u *)o;
}


struct pml_variable *pml_var_alloc(char *name, int width, 
		                   struct pml_value *init)
{
	struct pml_variable *v = (struct pml_variable *)
		pmlt_alloc(PMLTT_VAR);
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


void pml_lexv_init(struct pml_lex_val *v)
{
	memset(v, 0, sizeof(*v));
}


void pml_lexv_fini(int toknum, struct pml_lex_val *v)
{
	fprintf(stderr, "Freeing %d -- ", toknum);
	if (v->type == PMLLV_STRING) {
		fprintf(stderr, "data = %s", v->u.raw.data);
		free(v->u.raw.data);
		v->u.raw.data = 0;
	} else {
		fprintf(stderr, "no-associated data");
	}
	fprintf(stderr, "\n");
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


