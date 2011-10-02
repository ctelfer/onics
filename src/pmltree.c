/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#include "pmltree.h"
#include "ns.h"
#include "util.h"
#include <cat/aux.h>
#include <cat/str.h>
#include <cat/bitops.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#define l_to_node(p) (union pml_node *)container(p, struct pml_node_base, ln)
#define SYMTABSIZE    256


struct pml_stack_frame {
	uint8_t *	stack;
	size_t		ssz;
	size_t		psz;
	union {
		struct pml_node_base *	node;
		struct pml_rule *	rule;
		struct pml_function *	func;
	} u;
};


struct pml_global_state {
	struct pml_ast *ast;
	uint8_t *	gmem;
	size_t		gsz;
};


struct pml_retval {
	int		etype;
	struct raw	bytes;
	struct raw	mask;
	uint64_t	val;
};


typedef int (*pml_eval_f)(struct pml_global_state *gs,
			  struct pml_stack_frame *fr, union pml_node *node,
			  struct pml_retval *v);


static int init_global_state(struct pml_global_state *gs, struct pml_ast *ast,
			     size_t gsz);
static int pml_eval(struct pml_global_state *gs, struct pml_stack_frame *fr, 
		    union pml_node *node, struct pml_retval *v);
static uint64_t val64(struct pml_retval *v);


static int is_expr(void *nodep)
{
	int type;
	if (nodep == NULL)
		return 0;
	type = ((union pml_node *)nodep)->base.type;
	return (type == PMLTT_SCALAR || type == PMLTT_BYTESTR ||
		type == PMLTT_MASKVAL || type == PMLTT_BINOP ||
		type == PMLTT_UNOP || type == PMLTT_CALL ||
		type == PMLTT_LOCATOR || type == PMLTT_LOCADDR);
}


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
	l_init(&ast->b_rules);
	l_init(&ast->p_rules);
	l_init(&ast->e_rules);
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

	l_for_each_safe(n, x, &ast->b_rules) {
		pmln_free(l_to_node(n));
	}
	abort_unless(l_isempty(&ast->b_rules));

	l_for_each_safe(n, x, &ast->p_rules) {
		pmln_free(l_to_node(n));
	}
	abort_unless(l_isempty(&ast->p_rules));

	l_for_each_safe(n, x, &ast->e_rules) {
		pmln_free(l_to_node(n));
	}
	abort_unless(l_isempty(&ast->e_rules));

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

	if (var->vtype != PML_VTYPE_CONST) {
		var->addr = ast->vars.nxtaddr;
		/* pad global vars to 8-byte alignment */
		ast->vars.nxtaddr += rup2_64(var->width, 3);
	}

	return 0;
}


int pml_ast_add_rule(struct pml_ast *ast, struct pml_rule *rule)
{
	abort_unless(rule->trigger >= PML_RULE_BEGIN &&
		     rule->trigger <= PML_RULE_END);
	if (pml_resolve_refs(ast, (union pml_node *)rule) < 0)
		return -1;
	switch(rule->trigger) {
	case PML_RULE_BEGIN:
		abort_unless(rule->pattern == NULL);
		l_enq(&ast->b_rules, &rule->ln);
		break;
	case PML_RULE_PACKET:
		l_enq(&ast->p_rules, &rule->ln);
		break;
	case PML_RULE_END:
		abort_unless(rule->pattern == NULL);
		l_enq(&ast->e_rules, &rule->ln);
		break;
	}
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

	case PMLTT_CFMOD: {
		struct pml_cfmod *p = &np->cfmod;
		p->type = pmltt;
		l_init(&p->ln);
		p->cftype = PML_CFM_UNKNOWN;
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
		p->pstksz = 0;
		p->vstksz = 0;
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &np->rule;
		p->type = pmltt;
		l_init(&p->ln);
		symtab_init(&p->vars);
		p->pattern = NULL;
		p->stmts = NULL;
		p->vstksz = 0;
		p->trigger = PML_RULE_PACKET;
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

	case PMLTT_CFMOD: {
		struct pml_cfmod *p = &node->cfmod;
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


static const char *efs(void *p, char s[80])
{
	struct pml_expr_base *e = p;
	abort_unless(p);
	abort_unless((e->eflags & ~(PML_EFLAG_CONST|
				    PML_EFLAG_PCONST|
				    PML_EFLAG_VARLEN)) == 0);

	snprintf(s, 80, "[%s; width=%lu]", eflag_strs[e->eflags], 
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
static const char *vts(struct pml_variable *v)
{
	abort_unless(v && v->vtype >= PML_VTYPE_UNKNOWN &&
		     v->vtype <= PML_VTYPE_LOCAL);
	return vtype_strs[v->vtype];
}


static const char *rtype_strs[] = {
	"unknown", "variable", "packet field", "proto const",
	"unknown namespace elem"
};
static const char *rts(struct pml_locator *l)
{
	abort_unless(l && l->reftype >= PML_REF_UNKNOWN &&
		     l->reftype <= PML_REF_UNKNOWN_NS_ELEM);
	return rtype_strs[l->reftype];
}


static const char *rule_trigger_strs[] = {
	"begin", "packet", "end"
};
const char *rulestr(struct pml_rule *r)
{
	abort_unless(r && r->trigger >= PML_RULE_BEGIN &&
		     r->trigger <= PML_RULE_END);
	return rule_trigger_strs[r->trigger];
}


static const char *op_strs[] = {
	"logical OR", "logical AND", "match", "notmatch", "rex match",
	"rex not match", "equals", "not equals", "less than", "greater than",
	"less or equal to", "greater or equal to", "binary OR", "binary XOR",
	"binary AND", "add", "subtract", "multiply", "divide", "modulus",
	"shift left", "shift right", "logical NOT", "binary compliment",
	"negative"
};
static const char *opstr(struct pml_op *op)
{
	abort_unless(op && op->op >= PMLOP_OR && op->op <= PMLOP_NEG);
	return op_strs[op->op];
}


static const char *cfm_strs[] = {
	"unknown", "return", "break", "continue", "nextrule", "nextpkt",
	"drop"
};
static const char *cfmstr(struct pml_cfmod *m)
{
	abort_unless(m && m->cftype >= PML_CFM_UNKNOWN && 
		     m->cftype <= PML_CFM_DROP);
	return cfm_strs[m->cftype];
}


/* Basically a pre-order printing traversal of the tree */
void pmlt_print(union pml_node *np, uint depth)
{
	char estr[80];

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
		       (long)p->u.scalar, (ulong)p->u.scalar,
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
		       vts(p), (ulong)p->width, (ulong)p->addr);
		if (p->init != NULL) {
			indent(depth+1);
			printf("Initialization value -- \n");
			pmlt_print((union pml_node *)p->init, depth+1);
		}
	} break;

	case PMLTT_UNOP: {
		struct pml_op *p = &np->op;
		indent(depth);
		printf("Unary Operation: '%s' %s\n", opstr(p), efs(p, estr));

		indent(depth);
		printf("Operand -- \n");
		pmlt_print((union pml_node *)p->arg1, depth+1);
	} break;

	case PMLTT_BINOP: {
		struct pml_op *p = &np->op;
		indent(depth);
		printf("Binary Operation: '%s' %s\n", opstr(p), efs(p, estr));

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
			pmlt_print((union pml_node *)p->idx, depth+1);
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

	case PMLTT_CFMOD: {
		struct pml_cfmod *p = &np->cfmod;
		indent(depth);
		printf("Control Flow Modification: '%s'\n", cfmstr(p));
		if (p->expr != NULL)
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
		printf("%s%s: %s() -- %d args, %d vars, return width=%lu\n",
		       (np->base.type == PMLTT_FUNCTION) ? 
		       		"Function" : 
				"Inline Function",
			(p->isconst) ? " [const] " : "",
			p->name, p->arity, (int)p->vstksz, (ulong)p->width);

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
		printf("Rule: (%s)\n", rulestr(p));

		indent(depth);
		if (p->trigger == PML_RULE_PACKET) {
			if (p->pattern == NULL) {
				printf("Empty pattern\n");
			} else {
				printf("Pattern -- \n");
				pmlt_print((union pml_node *)p->pattern,
					   depth+1);
			}
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
	printf("Begin Rules\n");
	printf("-----------\n");
	l_for_each(n, &ast->b_rules)
		pmlt_print(l_to_node(n), 1);
	printf("-----------\n");
	printf("Packet Rules\n");
	printf("-----------\n");
	l_for_each(n, &ast->p_rules)
		pmlt_print(l_to_node(n), 1);
	printf("-----------\n");
	printf("End Rules\n");
	printf("-----------\n");
	l_for_each(n, &ast->e_rules)
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
		else if (rv > 0)
			return 0;
	}

	switch (np->base.type) {

	case PMLTT_LIST: {
		struct pml_list *p = &np->list;
		struct list *e;
		l_for_each_safe(e, x, &p->list) {
			rv = pmlt_walk(l_to_node(e), ctx, pre, in, post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}
	} break;

	case PMLTT_VAR: {
		struct pml_variable *p = &np->variable;
		if (p->init != NULL) {
			rv = pmlt_walk((union pml_node *)p->init, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}
	} break;

	case PMLTT_UNOP: {
		struct pml_op *p = &np->op;
		rv = pmlt_walk((union pml_node *)p->arg1, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_BINOP: {
		struct pml_op *p = &np->op;

		rv = pmlt_walk((union pml_node *)p->arg1, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;

		if (in != NULL) {
			rv = (*in)((union pml_node *)p, ctx);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		rv = pmlt_walk((union pml_node *)p->arg2, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_CALL: {
		struct pml_call *p = &np->call;
		rv = pmlt_walk((union pml_node *)p->args, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_IF: {
		struct pml_if *p = &np->ifstmt;

		rv = pmlt_walk((union pml_node *)p->test, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;

		rv = pmlt_walk((union pml_node *)p->tbody, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;

		if (p->fbody != NULL) {
			rv = pmlt_walk((union pml_node *)p->fbody, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}
	} break;

	case PMLTT_WHILE: {
		struct pml_while *p = &np->whilestmt;

		rv = pmlt_walk((union pml_node *)p->test, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;

		rv = pmlt_walk((union pml_node *)p->body, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *p = &np->locator;

		if (p->pkt != NULL) {
			rv = pmlt_walk((union pml_node *)p->pkt, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		if (p->idx != NULL) {
			rv = pmlt_walk((union pml_node *)p->idx, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		if (p->off != NULL) {
			rv = pmlt_walk((union pml_node *)p->off, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		if (p->len != NULL) {
			rv = pmlt_walk((union pml_node *)p->len, ctx, pre, in,
				       post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *p = &np->assign;

		rv = pmlt_walk((union pml_node *)p->loc, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;

		rv = pmlt_walk((union pml_node *)p->expr, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_CFMOD: {
		struct pml_cfmod *p = &np->cfmod;

		rv = pmlt_walk((union pml_node *)p->expr, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
        } break;

	case PMLTT_PRINT: {
		struct pml_print *p = &np->print;

		rv = pmlt_walk((union pml_node *)p->args, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_FUNCTION:
	case PMLTT_INLINE: {
		struct pml_function *p = &np->function;
		struct list *n;

		l_for_each_safe(n, x, &p->params.list) {
			rv = pmlt_walk(l_to_node(n), ctx, pre, in, post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		l_for_each_safe(n, x, &p->vars.list) {
			rv = pmlt_walk(l_to_node(n), ctx, pre, in, post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		rv = pmlt_walk((union pml_node *)p->body, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
	} break;

	case PMLTT_RULE: {
		struct pml_rule *p = &np->rule;

		if (p->pattern != NULL) {
			rv = pmlt_walk((union pml_node *)p->pattern, ctx, pre,
				       in, post);
			if (rv < 0)
				return rv;
			else if (rv > 0)
				return 0;
		}

		rv = pmlt_walk((union pml_node *)p->stmts, ctx, pre, in, post);
		if (rv < 0)
			return rv;
		else if (rv > 0)
			return 0;
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


int pml_locator_resolve_nsref(struct pml_ast *ast, struct pml_locator *l)
{
	struct ns_elem *e;
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	struct ns_scalar *sc;
	struct ns_bytestr *bs;
	struct ns_maskstr *ms;
	struct pml_literal *lit;
	uint64_t off, len;
	int rv;
	struct pml_global_state gs;
	struct pml_retval r;

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
		init_global_state(&gs, ast, 0);
		if (l->off != NULL) {
			rv = pml_eval(&gs, NULL, (union pml_node *)l->off, &r);
			if (rv < 0)
				return -1;
			off = val64(&r);
		}
		if (off >= bs->value.len)
			return -1;
		len = bs->value.len;
		if (l->len != NULL) {
			rv = pml_eval(&gs, NULL, (union pml_node *)l->len, &r);
			if (rv < 0)
				return -1;
			len = val64(&r);
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
	int ntab;
	int vtidx;
	int ptidx;
	struct pml_ast *ast;
};


static struct pml_variable *rlookup(struct pml_resolve_ctx *ctx, 
				    const char *name, int *ti)
{
	int i;
	union pml_node *node;

	for (i = 0; i < ctx->ntab; ++i) {
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
		rv = pml_locator_resolve_nsref(ctx->ast, l);
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
		else if (ti == ctx->ptidx)
			l->eflags |= PML_EFLAG_PCONST;
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
	v = pml_var_alloc(l->name, 0, PML_VTYPE_LOCAL, NULL);
	if (v == NULL) {
		pml_ast_err(ctx->ast, "out of memory building ast\n");
		return -1;
	}
	v->addr = t->nxtaddr;
	t->nxtaddr += 8;
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
			pml_ast_err(ast,
				    "%s: Left argument of a match operation "
				    "must be a byte string: %s instead\n",
				    opstr(op), ets(a1));
			return -1;
		}
		if (a1->etype != PML_ETYPE_BYTESTR &&
		    a2->etype != PML_ETYPE_MASKVAL) {
			pml_ast_err(ast, 
				    "%s: Right argument of a match operation "
				    "must be a byte string or masked "
				    "string: %s instead\n", 
				    opstr(op), ets(a2));
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
			c->eflags |= PML_EFLAG_CONST;
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
		ctx.ntab = 2;
		ctx.vtidx = 0;
		ctx.ptidx = -1;
		rv = pmlt_walk((union pml_node *)rule->pattern, &ctx, NULL,
			       NULL, resolve_node);
		if (rv < 0)
			return -1;
		rv = pmlt_walk((union pml_node *)rule->stmts, &ctx, NULL,
			       NULL, resolve_node);
		if (rv < 0)
			return -1;
		rule->vstksz = rule->vars.nxtaddr;
		return 0;
	} else if (node->base.type == PMLTT_FUNCTION) {
		struct pml_function *func = (struct pml_function *)node;
		ctx.symtabs[0] = &func->params;
		ctx.symtabs[1] = &func->vars;
		ctx.symtabs[2] = &ast->vars;
		ctx.ntab = 3;
		ctx.vtidx = 1;
		ctx.ptidx = 0;
		rv = pmlt_walk((union pml_node *)func->body, &ctx, NULL,
			       NULL, resolve_node);
		if (rv < 0)
			return -1;
		func->pstksz = func->params.nxtaddr * sizeof(uint64_t);
		func->vstksz = func->vars.nxtaddr * sizeof(uint64_t) -
			       func->pstksz;
		return 0;
	} else if (node->base.type == PMLTT_INLINE) {
		struct pml_function *inln = (struct pml_function *)node;
		struct pml_expr_base *pe;
		ctx.symtabs[0] = &inln->params;
		ctx.symtabs[1] = &ast->vars;
		ctx.ntab = 2;
		ctx.ptidx = 0;
		ctx.vtidx = -1; /* no local variables in inlines */
		rv = pmlt_walk((union pml_node *)inln->body, &ctx, NULL, NULL,
			       resolve_node);
		if (rv < 0)
			return -1;
		inln->pstksz = inln->params.nxtaddr * sizeof(uint64_t);
		inln->isconst = PML_EXPR_IS_PCONST(inln->body);
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
		ctx.ntab = 1;
		ctx.vtidx = -1;
		ctx.ptidx = -1;
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
					    "Variable '%s' %s initialization "
					    "expression does not match "
					    "variable type (init is %s)\n",
					    var->name,
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


static void stkfree(struct pml_stack_frame *fr)
{
	if (fr != NULL) {
		free(fr->stack);
		memset(fr, 0, sizeof(*fr));
		free(fr);
	}
}


static struct pml_stack_frame *stkalloc(struct pml_ast *ast,
					union pml_node *node)
{
	struct pml_stack_frame *fr = NULL;

	fr = malloc(sizeof(struct pml_stack_frame));
	if (fr == NULL)
		goto oomerr;

	if (node->base.type == PMLTT_FUNCTION || 
	    node->base.type == PMLTT_INLINE) {
		struct pml_function *p = (struct pml_function *)node;
		fr->psz = p->pstksz;
		fr->ssz = p->pstksz + p->vstksz;
		fr->u.func = p;
	} else if (node->base.type == PMLTT_RULE) {
		struct pml_rule *p = (struct pml_rule *)node;
		fr->psz = 0;
		fr->ssz = p->vstksz;
		fr->u.rule = p;
	} else {
		pml_ast_err(ast, "Invalid node type to allocate stack frame\n",
			    node->base.type);
		return NULL;
	}

	fr->stack = calloc(1, fr->ssz);
	if (fr->stack == NULL)
		goto oomerr;

	return fr;

oomerr:
	pml_ast_err(ast, "Out of memory in stkalloc()\n");
	stkfree(fr);
	return NULL;
}


static int init_global_state(struct pml_global_state *gs, struct pml_ast *ast,
			     size_t gsz)
{
	abort_unless(gs);
	if (gsz == 0) {
		gs->gmem = NULL;
	} else {
		gs->gmem = calloc(1, gsz);
		if (gs->gmem == NULL)
			return -1;
	}
	gs->gsz = gsz;
	gs->ast = ast;
	return 0;
}


static void clear_global_state(struct pml_global_state *gs)
{
	free(gs->gmem);
	gs->gmem = NULL;
	gs->gsz = 0;
}


static uint64_t val64(struct pml_retval *v)
{
	abort_unless(v);
	switch(v->etype) {
	case PML_ETYPE_SCALAR:
		return v->val;
	case PML_ETYPE_BYTESTR:
		return be64val(v->bytes.data, v->bytes.len);
	case PML_ETYPE_MASKVAL: {
		uint8_t bytes[8];
		int i;
		size_t len = (v->bytes.len > v->mask.len) ? v->bytes.len :
				v->mask.len;
		for (i = 0; i < len; ++i)
			bytes[i] = v->bytes.data[i] & v->mask.data[i];
		return be64val(bytes, len);
	} break;
	default:
		abort_unless(0);
		return (uint64_t)-1;
	}
}


static int unimplemented(struct pml_global_state *gs,
			 struct pml_stack_frame *fr, union pml_node *node,
			 struct pml_retval *v)
{
	abort_unless(gs && gs->ast && node);
	pml_ast_err(gs->ast, "evaluation of type '%d' unimplemented\n",
		    node->base.type);
	return -1;
}


static int e_scalar(struct pml_global_state *gs, struct pml_stack_frame *fr,
		    union pml_node *node, struct pml_retval *r)
{
	r->etype = PML_ETYPE_SCALAR;
	r->val = ((struct pml_literal *)node)->u.scalar;
	return 0;
}


static int e_bytestr(struct pml_global_state *gs, struct pml_stack_frame *fr,
		     union pml_node *node, struct pml_retval *r)
{
	r->etype = PML_ETYPE_BYTESTR;
	r->bytes = ((struct pml_literal *)node)->u.bytestr.bytes;
	return 0;
}


static int e_maskval(struct pml_global_state *gs, struct pml_stack_frame *fr,
		     union pml_node *node, struct pml_retval *r)
{
	r->etype = PML_ETYPE_MASKVAL;
	r->bytes = ((struct pml_literal *)node)->u.maskval.val.bytes;
	r->mask = ((struct pml_literal *)node)->u.maskval.mask.bytes;
	return 0;
}


static int is_match_op(int op)
{
	return (op >= PMLOP_MATCH) && (op <= PMLOP_NOTREXMATCH);

}


static int matchop(struct pml_retval *l, struct pml_retval *r)
{
	size_t i;
	byte_t *lb, *rb, *rm;
	abort_unless(l->etype == PML_ETYPE_BYTESTR);
	abort_unless(r->etype == PML_ETYPE_BYTESTR ||
		     r->etype == PML_ETYPE_MASKVAL);

	if (r->etype == PML_ETYPE_BYTESTR) {
		if (l->bytes.len != r->bytes.len)
			return 0;
		return memcmp(l->bytes.data, r->bytes.data, l->bytes.len);
	} else {
		if (l->bytes.len != r->bytes.len)
			return 0;
		abort_unless(r->bytes.len == r->mask.len);
		lb = l->bytes.data;
		rb = r->bytes.data;
		rm = r->mask.data;
		for (i = 0; i < l->bytes.len ; ++i)
			if ((*lb & *rm) != (*rb & *rm))
				return 0;
		return 1;
	}
}


static int e_binop(struct pml_global_state *gs, struct pml_stack_frame *fr,
		   union pml_node *node, struct pml_retval *r)
{
	struct pml_op *op = (struct pml_op *)node;
	struct pml_retval lr, rr;
	uint64_t left = 0, right = 0;
	int rv;

	r->etype = PML_ETYPE_SCALAR;
	abort_unless(op->arg1 != NULL && is_expr(op->arg1));
	abort_unless(op->arg2 != NULL && is_expr(op->arg2));

	if (pml_eval(gs, fr, (union pml_node *)op->arg1, &lr) < 0)
		return -1;
	if (!is_match_op(op->op))
		left = val64(&lr);

	/* implement short circuit evaluation for || and && */
	if (op->op == PMLOP_OR) {
		if (left) {
			r->val = 1;
			return 0;
		}
	} else if (op->op == PMLOP_AND) {
		if (!left) {
			r->val = 0;
			return 0;
		}
	}

	if (pml_eval(gs, fr, (union pml_node *)op->arg2, &rr) < 0)
		return -1;
	if (!is_match_op(op->op))
		right = val64(&rr);

	switch(op->op) {
	case PMLOP_OR:
	case PMLOP_AND: r->val = right != 0;
		break;
	case PMLOP_MATCH:
		if ((rv = matchop(&lr, &rr)) < 0)
			return -1;
		r->val = rv;
		break;
	case PMLOP_NOTMATCH:
		if ((rv = matchop(&lr, &rr)) < 0)
			return -1;
		r->val = !rv;
		break;
	case PMLOP_REXMATCH:
	case PMLOP_NOTREXMATCH:
		/* TODO */
		pml_ast_err(gs->ast, "eval: regex matching unimplemented\n");
		return -1;
		break;
	case PMLOP_EQ: r->val = left == right;
		break;
	case PMLOP_NEQ: r->val = left != right;
		break;
	case PMLOP_LT: r->val = (int64_t)left < (int64_t)right;
		break;
	case PMLOP_GT: r->val = (int64_t)left > (int64_t)right;
		break;
	case PMLOP_LEQ: r->val = (int64_t)left <= (int64_t)right;
		break;
	case PMLOP_GEQ: r->val = (int64_t)left >= (int64_t)right;
		break;
	case PMLOP_BOR: r->val = left | right;
		break;
	case PMLOP_BXOR: r->val = left ^ right;
		break;
	case PMLOP_BAND: r->val = left & right;
		break;
	case PMLOP_PLUS: r->val = left + right;
		break;
	case PMLOP_MINUS: r->val = left - right;
		break;
	case PMLOP_TIMES: r->val = left * right;
		break;
	case PMLOP_DIV: 
		if (!right) {
			pml_ast_err(gs->ast, "eval: divide by zero error\n");
			return -1;
		}
		r->val = left / right;
		break;
	case PMLOP_MOD: 
		if (!right) {
			pml_ast_err(gs->ast, "eval: divide by zero error\n");
			return -1;
		}
		r->val = left % right;
		break;
	case PMLOP_SHL: r->val = left << (right & 63);
		break;
	case PMLOP_SHR: r->val = left >> (right & 63);
		break;
	default:
		abort_unless(0);
	}

	return 0;
}


static int e_unop(struct pml_global_state *gs, struct pml_stack_frame *fr,
		  union pml_node *node, struct pml_retval *r)
{
	struct pml_op *op = (struct pml_op *)node;
	struct pml_retval lr;
	uint64_t arg;

	abort_unless(op->etype == PML_ETYPE_SCALAR);
	abort_unless(op->arg1 != NULL && is_expr(op->arg1));

	if (pml_eval(gs, fr, (union pml_node *)op->arg1, &lr) < 0)
		return -1;
	arg = val64(&lr);

	r->etype = PML_ETYPE_SCALAR;
	switch(op->op) {
	case PMLOP_NOT:
		r->val = !arg;
		break;
	case PMLOP_BINV:
		r->val = ~arg;
		break;
	case PMLOP_NEG:
		r->val = -arg;
		break;
	default:
		abort_unless(0);
	}

	return 0;
}


static int e_call(struct pml_global_state *gs, struct pml_stack_frame *fr,
		  union pml_node *node, struct pml_retval *r)
{
	struct pml_call *c = (struct pml_call *)node;
	struct pml_function *f = c->func;
	struct pml_stack_frame *nfr;
	struct pml_retval lr;
	struct list *n;
	int rv = -1;
	uint64_t *pp;

	abort_unless(l_length(&c->args->list) == f->arity);
	r->etype = PML_ETYPE_SCALAR;
	nfr = stkalloc(gs->ast, (union pml_node *)f);
	if (nfr == NULL)
		return -1;

	/* evaluation the parameters and put them in the stack frame */
	pp = (uint64_t *)nfr->stack;
	l_for_each(n, &c->args->list) {
		rv = pml_eval(gs, fr, l_to_node(n), &lr);
		if (rv < 0)
			goto out;
		*pp++ = val64(&lr);
	}

	rv = pml_eval(gs, nfr, f->body, &lr);
	if (rv < 0)
		goto out;
	r->val = val64(&lr);
out:
	stkfree(nfr);
	return rv;
}


static int getofflen(struct pml_global_state *gs, struct pml_stack_frame *fr,
		     struct pml_locator *l, uint64_t fieldlen,
		     uint64_t *off, uint64_t *len)
{
	struct pml_retval lr;

	if (l->off != NULL) {
		if (pml_eval(gs, fr, (union pml_node *)l->off, &lr) < 0)
			return -1;
		*off = val64(&lr);
	}

	if (l->len != NULL) {
		if (pml_eval(gs, fr, (union pml_node *)l->len, &lr) < 0)
			return -1;
		*len = val64(&lr);
	} else {
		*len = fieldlen;
	}

	return 0;
}


static int e_const(struct pml_global_state *gs, struct pml_stack_frame *fr,
		   struct pml_locator *l, struct pml_retval *r)
{
	uint64_t off = 0, len = 0;
	struct pml_retval lr;
	struct pml_variable *v = l->u.varref;

	abort_unless(l->off == NULL || PML_EXPR_IS_CONST(l->off));
	abort_unless(l->len == NULL || PML_EXPR_IS_CONST(l->len));

	if (v->etype == PML_ETYPE_SCALAR) {

		abort_unless(l->off == NULL && l->len == NULL);
		if (pml_eval(gs, fr, (union pml_node*)v->init, r) < 0)
			return -1;

	} else if (v->etype == PML_ETYPE_BYTESTR ||
		   v->etype == PML_ETYPE_MASKVAL) { 

		if (pml_eval(gs, fr, (union pml_node*)v->init, &lr) < 0)
			return -1;
		if (getofflen(gs, fr, l, lr.bytes.len, &off, &len) < 0)
			return -1;
		abort_unless(v->etype == PML_ETYPE_BYTESTR ||
				(lr.mask.data != NULL && 
				 lr.mask.len == lr.bytes.len));
		if (len > lr.bytes.len || off > lr.bytes.len - len) {
			pml_ast_err(gs->ast,
				    "field overflow locator for '%s': "
				    "[off=%lu,len=%lu,field=%lu bytes]\n",
				    l->name, (ulong)off, (ulong)len,
				    (ulong)lr.bytes.len);
			return -1;
		}
		r->etype = v->etype;
		r->bytes.data = lr.bytes.data + off;
		r->bytes.len = len;
		if (v->etype == PML_ETYPE_MASKVAL) { 
			r->mask.data = lr.mask.data + off;
			r->mask.len = len;
		}

	} else {
		abort_unless(0);
	}
	return 0;
}


static int e_locator(struct pml_global_state *gs, struct pml_stack_frame *fr,
		     union pml_node *node, struct pml_retval *r)
{
	struct pml_locator *l = (struct pml_locator *)node;
	uint64_t off = 0, len = 8;

	if (l->reftype == PML_REF_VAR) {
		struct pml_variable *v = l->u.varref;

		abort_unless(l->pkt == NULL);
		abort_unless(l->idx == NULL);
		abort_unless(v->vtype == PML_VTYPE_CONST ||
			     v->vtype == PML_VTYPE_GLOBAL ||
		             v->vtype == PML_VTYPE_LOCAL);

		if (v->vtype == PML_VTYPE_CONST) {

			return e_const(gs, fr, l, r);

		} else if (v->vtype == PML_VTYPE_GLOBAL) {

			if (getofflen(gs, fr, l, v->width, &off, &len) < 0)
				return -1;
			if (off > v->width || v->width - off < len) {
				pml_ast_err(gs->ast,
					    "eval: access to global '%s' is "
					    "out of bounds: [off=%lu,len=%lu,"
					    "varlen=%lu]\n",
					    (ulong)off, (ulong)len, 
					    (ulong)v->width);
				return -1;
			}
			if (l->etype == PML_ETYPE_SCALAR) {
				abort_unless(l->off == NULL);
				abort_unless(l->len == NULL);
				r->etype = PML_ETYPE_SCALAR;
				r->val = *(uint64_t *)(fr->stack + v->addr);
			} else {
				abort_unless(l->etype == PML_ETYPE_BYTESTR);
				r->etype = PML_ETYPE_BYTESTR;
				r->bytes.data = gs->gmem + v->addr + off;
				r->bytes.len = len;
			}

		} else {

			abort_unless(v->vtype == PML_VTYPE_LOCAL);
			abort_unless(l->etype == PML_ETYPE_SCALAR);
			abort_unless(l->off == NULL && l->len == NULL);
			abort_unless(fr);
			if (fr->ssz < 8 || fr->ssz - 8 < v->addr) {
				pml_ast_err(gs->ast,
					    "eval: stack overflow in var '%s':"
					    " stack size=%lu, var addr=%lu\n",
					    v->name, fr->ssz, v->addr);
				return -1;
			}
			r->etype = PML_ETYPE_SCALAR;
			r->val = *(uint64_t *)(fr->stack + 
					       v->addr * sizeof(uint64_t));
		}
	} else if (l->reftype == PML_REF_PKTFLD) {

		/* TODO */
		pml_ast_err(gs->ast, "eval: Packet fields unimplemented\n");
		return -1;

	} else if (l->reftype == PML_REF_LITERAL) {

		return pml_eval(gs, fr, (union pml_node *)l->u.litref, r);

	} else {

		abort_unless(0);

	}

	return 0;
}


static int e_locaddr(struct pml_global_state *gs, struct pml_stack_frame *fr,
		     union pml_node *node, struct pml_retval *r)
{
	struct pml_locator *l = (struct pml_locator *)node;

	if (l->reftype == PML_REF_VAR) {
		abort_unless(l->u.varref->vtype == PML_VTYPE_GLOBAL ||
		             l->u.varref->vtype == PML_VTYPE_LOCAL);
		r->etype = PML_ETYPE_SCALAR;
		r->val = l->u.varref->addr;
	} else if (l->reftype == PML_REF_PKTFLD) {
		/* TODO */
		pml_ast_err(gs->ast, "eval: Packet field addresses "
				     "unimplemented\n");
		return -1;
	} else {
		pml_ast_err(gs->ast, "eval: Invalid reftype in locator: %d\n",
			    l->reftype);
		return -1;
	}
	return 0;
}


static pml_eval_f evaltab[] = {
	unimplemented,		/* PMLTT_LIST */
	e_scalar,		/* PMLTT_SCALAR */
	e_bytestr,		/* PMLTT_BYTESTR */
	e_maskval,		/* PMLTT_MASKVAL */
	unimplemented,		/* PMLTT_VAR */
	e_binop,		/* PMLTT_BINOP */
	e_unop,			/* PMLTT_UNOP */
	e_call,			/* PMLTT_CALL */
	unimplemented,		/* PMLTT_IF */
	unimplemented,		/* PMLTT_WHILE */
	e_locator,		/* PMLTT_LOCATOR */
	e_locaddr,		/* PMLTT_LOCADDR */
	unimplemented,		/* PMLTT_ASSIGN */
	unimplemented,		/* PMLTT_CFMOD */
	unimplemented,		/* PMLTT_PRINT */
	unimplemented,		/* PMLTT_FUNCTION */
	unimplemented,		/* PMLTT_INLINE */
	unimplemented,		/* PMLTT_RULE */
};


/* TODO: make error reporting separate from AST error reporting */
static int pml_eval(struct pml_global_state *gs, struct pml_stack_frame *fr, 
		    union pml_node *node, struct pml_retval *r)
{
	abort_unless(gs && r);
	if (node == NULL || node->base.type < 0 || 
	    node->base.type > PMLTT_RULE) {
		pml_ast_err(gs->ast, "Invalid node given to pml_eval()\n");
		return -1;
	}

	return (*evaltab[node->base.type])(gs, fr, node, r);
}


static int pml_opt_cexpr(union pml_expr_u *e, void *astp, union pml_expr_u **ne)
{
	struct pml_global_state gs;
	struct pml_retval r;
	struct pml_literal *lit = NULL;
	int rv;

	*ne = NULL;

	if (e != NULL && PML_EXPR_IS_CONST(e) && !PML_EXPR_IS_LITERAL(e)) {
		init_global_state(&gs, astp, 0);
		rv = pml_eval(&gs, NULL, (union pml_node *)e, &r);
		if (rv < 0)
			return -1;
		switch(r.etype) {
		case PML_ETYPE_SCALAR:
			lit = (struct pml_literal *)pmln_alloc(PMLTT_SCALAR);
			lit->etype = PML_ETYPE_SCALAR;
			lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;
			lit->width = 8;
			lit->u.scalar = r.val;
			break;

		case PML_ETYPE_BYTESTR:
			lit = (struct pml_literal *)pmln_alloc(PMLTT_BYTESTR);
			lit->etype = PML_ETYPE_BYTESTR;
			lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;
			rv = pml_bytestr_copy(&lit->u.bytestr, r.bytes.data,
					      r.bytes.len);
			if (rv < 0)
				goto errout;
			lit->width = r.bytes.len;
			break;

		case PML_ETYPE_MASKVAL:
			lit = (struct pml_literal *)pmln_alloc(PMLTT_MASKVAL);
			lit->etype = PML_ETYPE_MASKVAL;
			lit->eflags = PML_EFLAG_CONST|PML_EFLAG_PCONST;
			rv = pml_bytestr_copy(&lit->u.maskval.val, 
					      r.bytes.data, r.bytes.len);
			if (rv < 0)
				goto errout;
			rv = pml_bytestr_copy(&lit->u.maskval.mask, 
					      r.mask.data, r.mask.len);
			if (rv < 0)
				goto errout;
			lit->width = r.bytes.len;
			break;
		}
		*ne = (union pml_expr_u *)lit;
	}

	return 0;

errout:
	pmln_free((union pml_node *)lit);
	pml_ast_err(astp, "Out of memory during constant optimization\n");
	return -1;
}


/* optimize an expression pointed to by a union pml_expr_u * pointer */
static int pml_opt_p_cexpr(union pml_expr_u **e, void *astp)
{
	union pml_expr_u *ne;
	if (pml_opt_cexpr(*e, astp, &ne) < 0)
		return -1;
	if (ne != NULL) {
		pmln_free((union pml_node *)*e);
		*e = ne;
	}
	return 0;
}


/* optimize an expression pointed to by a union pml_node * pointer */
static int pml_opt_np_cexpr(union pml_node **e, void *astp)
{
	union pml_expr_u *ne;
	if (pml_opt_cexpr((union pml_expr_u *)*e, astp, &ne) < 0)
		return -1;
	if (ne != NULL) {
		pmln_free(*e);
		*e = (union pml_node *)ne;
	}
	return 0;
}


/* optimize an expression pointed to by a union pml_expr_u * pointer */
static int pml_opt_l_cexpr(union pml_expr_u *e, void *astp)
{
	struct list *prev;
	union pml_expr_u *ne;
	if (pml_opt_cexpr(e, astp, &ne) < 0)
		return -1;
	if (ne != NULL) {
		prev = e->expr.ln.prev;
		l_rem(&e->expr.ln);
		l_ins(prev, &ne->expr.ln);
		pmln_free((union pml_node *)e);
	}
	return 0;
}


static int pml_cexpr_walker(union pml_node *node, void *astp)
{
	struct list *n, *x;

	switch(node->base.type) {

	case PMLTT_VAR: {
		struct pml_variable *v = (struct pml_variable *)node;
		if (v->init != NULL) {
			if (pml_opt_p_cexpr(&v->init, astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_BINOP:
	case PMLTT_UNOP: {
		struct pml_op *op = (struct pml_op *)node;
		if (pml_opt_p_cexpr(&op->arg1, astp) < 0)
			return -1;
		if (op->type == PMLTT_BINOP) {
			if (pml_opt_p_cexpr(&op->arg2, astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_CALL: {
		struct pml_call *c = (struct pml_call *)node;
		l_for_each_safe(n, x, &c->args->list) {
			if (pml_opt_l_cexpr((union pml_expr_u *)l_to_node(n), 
					   astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_IF: {
		struct pml_if *pif = (struct pml_if *)node;
		if (pml_opt_p_cexpr(&pif->test, astp) < 0)
			return -1;
	} break;

	case PMLTT_WHILE: {
		struct pml_while *w = (struct pml_while *)node;
		if (pml_opt_p_cexpr(&w->test, astp) < 0)
			return -1;
	} break;

	case PMLTT_LOCATOR:
	case PMLTT_LOCADDR: {
		struct pml_locator *l = (struct pml_locator *)node;
		if (pml_opt_p_cexpr(&l->pkt, astp) < 0)
			return -1;
		if (pml_opt_p_cexpr(&l->idx, astp) < 0)
			return -1;
		if (pml_opt_p_cexpr(&l->off, astp) < 0)
			return -1;
		if (pml_opt_p_cexpr(&l->len, astp) < 0)
			return -1;
	} break;

	case PMLTT_ASSIGN: {
		struct pml_assign *a = (struct pml_assign *)node;
		if (pml_opt_p_cexpr(&a->expr, astp) < 0)
			return -1;
	} break;

	case PMLTT_PRINT: {
		struct pml_print *p = (struct pml_print *)node;
		l_for_each_safe(n, x, &p->args->list) {
			if (pml_opt_l_cexpr((union pml_expr_u *)l_to_node(n),
					   astp) < 0)
				return -1;
		}
	} break;

	case PMLTT_INLINE: {
		struct pml_function *f = (struct pml_function *)node;
		if (pml_opt_np_cexpr(&f->body, astp) < 0)
			return -1;
	} break;

	case PMLTT_RULE: {
		struct pml_rule *r = (struct pml_rule *)node;
		if (pml_opt_p_cexpr(&r->pattern, astp) < 0)
			return -1;
	} break;

	default:
		return 0;
	}
	return 0;
}


int pml_ast_optimize(struct pml_ast *ast)
{
	struct list *n;
	int rv = 0;

	abort_unless(ast);
	l_for_each(n, &ast->vars.list) {
		rv = pmlt_walk(l_to_node(n), ast, pml_cexpr_walker, NULL, NULL);
		if (rv < 0)
			goto out;
	}
	l_for_each(n, &ast->funcs.list) {
		rv = pmlt_walk(l_to_node(n), ast, pml_cexpr_walker, NULL, NULL);
		if (rv < 0)
			goto out;
	}
	l_for_each(n, &ast->b_rules) {
		rv = pmlt_walk(l_to_node(n), ast, pml_cexpr_walker, NULL, NULL);
		if (rv < 0)
			goto out;
	}
	l_for_each(n, &ast->p_rules) {
		rv = pmlt_walk(l_to_node(n), ast, pml_cexpr_walker, NULL, NULL);
		if (rv < 0)
			goto out;
	}
	l_for_each(n, &ast->e_rules) {
		rv = pmlt_walk(l_to_node(n), ast, pml_cexpr_walker, NULL, NULL);
		if (rv < 0)
			goto out;
	}
out:
	return rv;
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


