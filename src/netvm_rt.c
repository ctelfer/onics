#include "netvm_rt.h"
#include <cat/stduse.h>
#include <cat/grow.h>
#include <stdlib.h>
#include <string.h>

#define MMMAXSIZE  (128 * 1024)

size_t mem_required(struct netvm_program *prog)
{
	return amm_get_fill(&prog->rwmm) + amm_get_fill(&prog->romm);
}

void nprg_init(struct netvm_program *prog, int matchonly)
{
	int i;

	abort_unless(prog);

	prog->matchonly = matchonly;
	prog->linked = 0;
	prog->inst = NULL;
	prog->ninst = 0;
	prog->isiz = 0;
	prog->labels = ht_new(&estdmm, 64, CAT_KT_STR, 0, 0);
	prog->ipatches = clist_new_list(&estdmm, sizeof(struct netvm_ipatch));
	prog->vars = ht_new(&estdmm, 64, CAT_KT_STR, 0, 0);
	prog->varlist = clist_new_list(&estdmm, sizeof(struct netvm_var *));
	amm_init(&prog->rwmm, (byte_t *) 0, MMMAXSIZE, 8, 0);
	amm_init(&prog->romm, (byte_t *) 0, MMMAXSIZE, 8, 0);
	for (i = 0; i < NETVM_MAXCOPROC; ++i) {
		prog->cpreqs[i].cpt = NETVM_CPT_NONE;
		prog->cpreqs[i].addrs = NULL;
	}
}


/* instructions and instruction symbols */
int nprg_add_code(struct netvm_program *prog, struct netvm_inst *inst,
		  uint32_t ninst, uint32_t * iaddr)
{
	abort_unless(prog && inst);

	if ((ninst == 0) || (prog->ninst >= ~(uint32_t) 0 - ninst))
		return -1;

	if (prog->ninst + ninst > prog->isiz) {
		void *p = prog->inst;
		mm_agrow(&estdmm, &p, sizeof(*inst), &prog->isiz,
			 prog->ninst + ninst);
		prog->inst = p;
	}

	abort_unless(prog->inst && prog->isiz >= prog->ninst + ninst);
	memcpy(prog->inst, inst, ninst * sizeof(*inst));
	if (iaddr)
		*iaddr = prog->ninst;
	prog->ninst += ninst;

	return 0;
}


int nprg_add_label(struct netvm_program *prog, const char *name, uint32_t iaddr)
{
	struct netvm_label *nl;

	abort_unless(prog && name);

	if (prog->linked)
		return -1;
	if (iaddr >= prog->ninst)
		return -1;
	if (ht_get_dptr(prog->labels, name))
		return -1;

	nl = emalloc(sizeof(*nl));
	nl->name = estrdup(name);
	nl->addr = iaddr;
	ht_put(prog->labels, (void *)name, nl);

	return 0;
}


int nprg_add_ipatch(struct netvm_program *prog, uint32_t iaddr, uint32_t delta,
		    const char *symname, int type)
{
	struct netvm_ipatch iptch;

	abort_unless(prog);

	if (prog->linked)
		return -1;
	if (iaddr >= prog->ninst)
		return -1;
	if ((type != NETVM_IPTYPE_LABEL) && (type != NETVM_IPTYPE_VAR))
		return -1;

	iptch.iaddr = iaddr;
	iptch.delta = delta;
	iptch.symname = estrdup(symname);
	iptch.type = type;
	clist_enqueue(prog->ipatches, &iptch);

	return 0;
}


/* variables and variable symbols */
struct netvm_var *nprg_add_var(struct netvm_program *prog, const char *name,
			       uint32_t len, int isrdonly)
{
	struct netvm_var *var;
	byte_t *p;

	abort_unless(prog && prog->vars && name);

	if (ht_get_dptr(prog->vars, (void *)name))
		return NULL;

	if (isrdonly) {
		if (!(p = mem_get(&prog->romm.mm, len)))
			return NULL;
	} else {
		if (!(p = mem_get(&prog->rwmm.mm, len)))
			return NULL;
	}

	var = emalloc(sizeof(*var));
	var->name = estrdup(name);
	var->addr = p - (byte_t *) 0;
	var->len = len;
	var->inittype = NETVM_ITYPE_NONE;
	var->isrdonly = isrdonly;
	var->datalen = 0;
	var->init_type_u.data = NULL;
	ht_put(prog->vars, var->name, var);
	clist_enqueue(prog->varlist, &var);

	return var;
}


static void freevar(void *clnp, void *realfree)
{
	struct clist_node *cln = clnp;
	struct netvm_var *var = cln_data(cln, struct netvm_var *);

	if (var->inittype == NETVM_ITYPE_DATA) {
		free(var->init_type_u.data);
	} else if ((var->inittype == NETVM_ITYPE_LABEL) ||
		   (var->inittype == NETVM_ITYPE_VADDR)) {
		free(var->init_type_u.symname);
	}

	if (realfree != NULL) {
		free(var->name);
		free(var);
	}
}


int nprg_vinit_data(struct netvm_var *var, void *data, uint32_t len)
{
	abort_unless(var && data && len <= var->len);

	freevar(var, NULL);
	var->inittype = NETVM_ITYPE_DATA;
	var->init_type_u.data = emalloc(len);
	memcpy(var->init_type_u.data, data, len);
	var->datalen = len;

	return 0;
}


int nprg_vinit_ilabel(struct netvm_var *var, const char *label, uint32_t delta)
{
	abort_unless(var && label);

	freevar(var, NULL);
	var->inittype = NETVM_ITYPE_LABEL;
	var->init_type_u.symname = estrdup(label);

	return 0;
}


int nprg_vinit_vaddr(struct netvm_var *var, const char *varname, uint32_t delta)
{
	abort_unless(var && varname);

	freevar(var, NULL);
	var->inittype = NETVM_ITYPE_VADDR;
	var->init_type_u.symname = estrdup(varname);

	return 0;
}


int nprg_vinit_fill(struct netvm_var *var, uint32_t val, int width)
{
	abort_unless(var);

	switch (width) {
	case 1:
	case 2:
	case 4:
	case 8:
		break;
	default:
		return -1;
	}

	freevar(var, NULL);
	var->inittype = NETVM_ITYPE_FILL;
	var->datalen = width;
	var->init_type_u.fill = val;

	return 0;
}


int nprg_add_cppatch(struct netvm_program *prog, uint32_t cpt, uint32_t iaddr)
{
	struct netvm_cpreq *r, *e;

	abort_unless(prog);

	if (prog->linked)
		return -1;
	if (iaddr >= prog->ninst)
		return -1;

	for (r = prog->cpreqs, e = r + NETVM_MAXCOPROC; r < e; ++r) {
		if (r->cpt == NETVM_CPT_NONE) {
			r->cpt = cpt;
			r->addrs = clist_new_list(&estdmm, sizeof(uint32_t));
			break;
		} else if (r->cpt == cpt) {
			break;
		}
	}

	if (r == e)
		return -1;

	clist_enqueue(r->addrs, &iaddr);

	return 0;
}


static void label_free_aux(void *labelp, void *unused)
{
	struct netvm_label *label = labelp;

	(void)unused;
	free(label->name);
}


static void ipatch_free_aux(void *clnp, void *unused)
{
	struct clist_node *cln = clnp;
	struct netvm_ipatch *iptch = cln_dptr(cln);

	(void)unused;
	free(iptch->symname);
}


static void linkfree(struct netvm_program *prog)
{
	int i;

	if (prog->labels) {
		ht_apply(prog->labels, label_free_aux, NULL);
		ht_free(prog->labels);
		prog->labels = NULL;
	}

	if (prog->ipatches) {
		clist_apply(prog->ipatches, ipatch_free_aux, NULL);
		clist_free_list(prog->ipatches);
		prog->ipatches = NULL;
	}

	if (prog->vars) {
		ht_free(prog->vars);
		prog->vars = NULL;
	}

	for (i = 0; i < NETVM_MAXCOPROC; ++i) {
		prog->cpreqs[i].cpt = NETVM_CPT_NONE;
		if (prog->cpreqs[i].addrs) {
			clist_free_list(prog->cpreqs[i].addrs);
			prog->cpreqs[i].addrs = NULL;
		}
	}
}


/* resolve all instruction patches in the system */
int nprg_link(struct netvm_program *prog, struct netvm *vm)
{
	struct clist_node *cln;
	struct netvm_inst *inst;
	struct netvm_ipatch *iptch;
	struct netvm_label *label;
	struct netvm_var *var, *var2;
	uint32_t val;
	int i, j;

	abort_unless(prog);

	if (!vm) {
		if (prog->cpreqs[0].cpt != NETVM_CPT_NONE)
			return -1;
	} else {
		uint32_t a;
		for (i = 0; i < NETVM_MAXCOPROC; ++i) {
			if (prog->cpreqs[i].cpt == NETVM_CPT_NONE)
				break;
			/* find the coproc in the vm */
			for (j = 0; j < NETVM_MAXCOPROC; ++j) {
				if (vm->coprocs == NULL)
					continue;
				if (vm->coprocs[j]->type == prog->cpreqs[i].cpt)
					break;
			}
			if (j == NETVM_MAXCOPROC)
				return -1;
			clist_for_each(cln, prog->cpreqs[i].addrs) {
				a = cln_data(cln, uint32_t);
				abort_unless(a < prog->ninst);
				inst = prog->inst + a;
				inst->x = j;
			}
		}
	}

	/* patch all instructions */
	clist_for_each(cln, prog->ipatches) {
		iptch = cln_dptr(cln);
		abort_unless(iptch->iaddr < prog->ninst);
		inst = prog->inst + iptch->iaddr;
		if (iptch->type == NETVM_IPTYPE_LABEL) {
			label = ht_get_dptr(prog->labels, iptch->symname);
			if (label == NULL)
				return -1;
			inst->w = label->addr;
		} else {
			abort_unless(iptch->type == NETVM_IPTYPE_VAR);
			var = ht_get_dptr(prog->vars, iptch->symname);
			if (var == NULL)
				return -1;
			inst->w = var->addr;
		}
	}

	/* patch all variables */
	clist_for_each(cln, prog->varlist) {
		var = cln_data(cln, struct netvm_var *);
		if (var->inittype == NETVM_ITYPE_LABEL) {
			label =
			    ht_get_dptr(prog->labels, var->init_type_u.symname);
			if (label == NULL)
				return -1;
			free(var->init_type_u.symname);
			val = label->addr;
			var->inittype = NETVM_ITYPE_FILL;
			var->datalen = 8;
			var->init_type_u.fill = val;
		} else if (var->inittype == NETVM_ITYPE_VADDR) {
			var2 =
			    ht_get_dptr(prog->vars, var->init_type_u.symname);
			if (var2 == NULL)
				return -1;
			free(var->init_type_u.symname);
			val = var2->addr;
			var->inittype = NETVM_ITYPE_FILL;
			var->datalen = 8;
			var->init_type_u.fill = val;
		}
	}

	clist_for_each(cln, prog->varlist) {
		ht_clr(prog->vars, cln_data(cln, struct netvm_var *)->name);
	}

	linkfree(prog);
	prog->linked = 1;

	return 0;
}


static void loadvar(byte_t * mem, struct netvm_var *var)
{
	uint32_t i;

	switch (var->inittype) {
	case NETVM_ITYPE_NONE:
		break;

	case NETVM_ITYPE_FILL:
		for (i = 0; i < var->len; i += var->datalen) {
			switch (var->datalen) {
			case 1:
				*(uint8_t *) (mem + i) = var->init_type_u.fill;
				break;
			case 2:
				*(uint16_t *) (mem + i) = var->init_type_u.fill;
				break;
			case 4:
				*(uint32_t *) (mem + i) = var->init_type_u.fill;
				break;
			default:
				abort_unless(0);
			}
		}
		break;

	case NETVM_ITYPE_DATA:
		memcpy(mem + var->addr, var->init_type_u.data, var->datalen);
		break;

	default:
		abort_unless(0);
	}
}


/* load a program onto a VM */
int nprg_load(struct netvm_program *prog, struct netvm *vm)
{
	size_t memreq;
	struct clist_node *cln;

	abort_unless(vm && prog);

	if (!prog->linked)
		return -1;
	memreq = mem_required(prog);
	if ((memreq > vm->memsz) || ((memreq > 0) && !vm->mem))
		return -1;
	if (netvm_setcode(vm, prog->inst, prog->ninst) < 0)
		return -1;

	netvm_set_matchonly(vm, prog->matchonly);
	clist_for_each(cln, prog->varlist) {
		loadvar(vm->mem, cln_data(cln, struct netvm_var *));
	}
	netvm_setrooff(vm, vm->memsz - amm_get_fill(&prog->romm));

	return 0;
}


/* release all auxilliary data */
void nprg_release(struct netvm_program *prog)
{
	int i;

	abort_unless(prog);

	linkfree(prog);

	if (prog->varlist) {
		clist_apply(prog->varlist, freevar, &i);
		clist_free_list(prog->varlist);
		prog->varlist = NULL;
	}

	free(prog->inst);
	prog->inst = NULL;
	prog->isiz = 0;
	prog->ninst = 0;
	prog->linked = 0;
}



void nvmmrt_init(struct netvm_mrt *mrt, struct netvm *vm, netvm_pktin_f inf,
		 void *inctx, netvm_pktout_f outf, void *outctx)
{
	abort_unless(mrt && vm && inf && outf);

	mrt->vm = vm;
	mrt->pktin = inf;
	mrt->inctx = inctx;
	mrt->pktout = outf;
	mrt->outctx = outctx;
	mrt->begin = NULL;
	mrt->end = NULL;
	mrt->pktprogs =
	    clist_new_list(&estdmm, sizeof(struct netvm_matchedprog));
}


int nvmmrt_set_begin(struct netvm_mrt *mrt, struct netvm_program *prog)
{
	abort_unless(mrt && prog);

	mrt->begin = prog;

	return 0;
}


int nvmmrt_set_end(struct netvm_mrt *mrt, struct netvm_program *prog)
{
	abort_unless(mrt && prog);

	mrt->end = prog;

	return 0;
}


int nvmmrt_add_pktprog(struct netvm_mrt *mrt, struct netvm_program *match,
		       struct netvm_program *action)
{
	struct netvm_matchedprog mp;

	abort_unless(mrt && mrt->pktprogs && action && match);

	match->matchonly = 1;	/* override anything in the match program */
	mp.match = match;
	mp.action = action;
	clist_enqueue(mrt->pktprogs, &mp);

	return 0;
}


int nvmmrt_execute(struct netvm_mrt *mrt)
{
	struct pktbuf *pkb;
	struct netvm_matchedprog *mprog;
	int i, rv, send;
	uint64_t rc;
	struct clist_node *cln;

	abort_unless(mrt);

	if (mrt->begin && (nprg_load(mrt->begin, mrt->vm) < 0))
		return -1;

	while ((pkb = (*mrt->pktin) (mrt->inctx))) {
		netvm_loadpkt(mrt->vm, pkb, 0);

		send = 1;
		clist_for_each(cln, mrt->pktprogs) {
			mprog = cln_dptr(cln);
			if (nprg_load(mprog->match, mrt->vm) < 0)
				return -1;
			if ((rv = netvm_run(mrt->vm, -1, &rc)) < 0)
				return -1;
			if (!rc)
				continue;
			if (nprg_load(mprog->action, mrt->vm) < 0)
				return -1;
			/* clear all packets on an error */
			if ((rv = netvm_run(mrt->vm, -1, &rc)) < 0) {
				for (i = 0; i < NETVM_MAXPKTS; ++i)
					netvm_clrpkt(mrt->vm, i, 0);
				continue;
			}
			if (rv > 0) {
				if (rv > 0)
					send = 0;
				if (rv == 2)
					break;
			}
		}
		if (send) {
			for (i = 0; i < NETVM_MAXPKTS; ++i) {
				pkb = netvm_clrpkt(mrt->vm, i, 1);
				if (pkb)
					(*mrt->pktout) (pkb, mrt->outctx);
			}
		} else {
			netvm_clrpkt(mrt->vm, 0, 0);
		}
	}

	for (i = 0; i < NETVM_MAXPKTS; ++i)
		netvm_clrpkt(mrt->vm, i, 0);

	if (mrt->end && (nprg_load(mrt->end, mrt->vm) < 0))
		return -1;

	return 0;
}


void nvmmrt_release(struct netvm_mrt *mrt, void (*progfree) (void *))
{
	struct clist_node *cln;
	struct netvm_matchedprog *mprog;

	abort_unless(mrt);

	if (progfree) {
		(*progfree) (mrt->begin);
		(*progfree) (mrt->end);
		clist_for_each(cln, mrt->pktprogs) {
			mprog = cln_dptr(cln);
			(*progfree) (mprog->match);
			(*progfree) (mprog->action);
		}
	}

	clist_free_list(mrt->pktprogs);
	mrt->vm = NULL;
}
