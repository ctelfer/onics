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
  abort_unless(prog);
  prog->matchonly = matchonly;
  prog->linked = 0;
  prog->inst = NULL;
  prog->ninst = 0;
  prog->isiz = 0;
  prog->labels = ht_new(64, CAT_DT_STR);
  prog->ipatches = clist_newlist();
  prog->vars = ht_new(64, CAT_DT_STR);
  prog->varlist = clist_newlist();;
  amm_init(&prog->rwmm, (byte_t*)0, MMMAXSIZE, 8, 0);
  amm_init(&prog->romm, (byte_t*)0, MMMAXSIZE, 8, 0);
}


/* instructions and instruction symbols */
int nprg_add_code(struct netvm_program *prog, struct netvm_inst *inst,
                  uint32_t ninst, uint32_t *iaddr)
{
  abort_unless(prog && inst);
  if ( (ninst == 0) || (prog->ninst >= ~(uint32_t)0 - ninst) )
    return -1;
  if ( prog->ninst + ninst > prog->isiz ) { 
    void *p = prog->inst;
    mem_agrow(&estdmem, &p, sizeof(*inst), &prog->isiz, prog->ninst + ninst);
    prog->inst = p;
  }
  abort_unless(prog->inst && prog->isiz >= prog->ninst + ninst);
  memcpy(prog->inst, inst, ninst * sizeof(*inst));
  if ( iaddr )
    *iaddr = prog->ninst;
  prog->ninst += ninst;
  return 0;
}


int nprg_add_label(struct netvm_program *prog, const char *name, uint32_t iaddr)
{
  struct netvm_label *nl;
  abort_unless(prog && name);
  if ( prog->linked )
    return -1;
  if ( iaddr >= prog->ninst )
    return -1;
  if ( ht_get(prog->labels, (void *)name) )
    return -1;
  nl = emalloc(sizeof(*nl));
  nl->name = estrdup(name);
  nl->addr = iaddr;
  ht_put(prog->labels, (void *)name, nl);
  return 0;
}


int nprg_add_ipatch(struct netvm_program *prog, uint32_t iaddr, uint64_t delta,
                    const char *symname, int type)
{
  struct netvm_ipatch iptch;
  abort_unless(prog);
  if ( prog->linked )
    return -1;
  if ( iaddr >= prog->ninst )
    return -1;
  if ( (type != NETVM_IPTYPE_LABEL) && (type != NETVM_IPTYPE_VAR) )
    return -1;
  iptch.iaddr = iaddr;
  iptch.delta = delta;
  iptch.symname = estrdup(symname);
  iptch.type = type;
  clist_enq(prog->ipatches, struct netvm_ipatch, iptch);
  return 0;
}


/* variables and variable symbols */
struct netvm_var *nprg_add_var(struct netvm_program *prog, const char *name,
                               uint32_t len, int isrdonly)
{
  struct netvm_var *var;
  byte_t *p;
  abort_unless(prog && prog->vars && name);
  if ( ht_get(prog->vars, (void*)name) )
    return NULL;

  if ( isrdonly ) {
    if ( !(p = mem_get(&prog->romm.mm, len)) )
      return NULL;
  } else {
    if ( !(p = mem_get(&prog->rwmm.mm, len)) )
      return NULL;
  }
  var = emalloc(sizeof(*var));
  var->name = estrdup(name);
  var->addr = p - (byte_t*)0;
  var->len = len;
  var->inittype = NETVM_ITYPE_NONE;
  var->isrdonly = isrdonly;
  var->datalen = 0;
  var->init_type_u.data = NULL;
  ht_put(prog->vars, (void *)var->name, var);
  clist_enq(prog->varlist, struct netvm_var *, var);
  return var;
}


static void freevar(void *varp, void *realfree)
{
  struct netvm_var *var = varp;
  if ( var->inittype == NETVM_ITYPE_DATA )
    free(var->init_type_u.data);
  else if ( (var->inittype == NETVM_ITYPE_LABEL) || 
            (var->inittype == NETVM_ITYPE_VADDR) )
    free(var->init_type_u.symname);
  if ( realfree != NULL ) {
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
  memcpy(var->init_type_u.data, data,len);
  var->datalen = len;
  return 0;
}


int nprg_vinit_ilabel(struct netvm_var *var, const char *label, uint64_t delta)
{
  abort_unless(var && label);
  freevar(var, NULL);
  var->inittype = NETVM_ITYPE_LABEL;
  var->init_type_u.symname = estrdup(label);
  return 0;
}

int nprg_vinit_vaddr(struct netvm_var *var, const char *varname, uint64_t delta)
{
  abort_unless(var && varname);
  freevar(var, NULL);
  var->inittype = NETVM_ITYPE_VADDR;
  var->init_type_u.symname = estrdup(varname);
  return 0;
}

int nprg_vinit_fill(struct netvm_var *var, uint64_t val, int width)
{
  abort_unless(var);
  switch(width) {
  case 1: case 2: case 4: case 8:
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


static void label_free_aux(void *labelp, void *unused)
{
  struct netvm_label *label = labelp;
  (void)unused;
  free(label->name);
}


static void ipatch_free_aux(void *iptchp, void *unused)
{
  struct netvm_ipatch *iptch = iptchp;
  (void)unused;
  free(iptch->symname);
}


static void linkfree(struct netvm_program *prog)
{
  if ( prog->labels ) {
    ht_apply(prog->labels, label_free_aux, NULL);
    ht_free(prog->labels);
    prog->labels = NULL;
  }
  if ( prog->ipatches ) {
    l_apply(prog->ipatches, ipatch_free_aux, NULL);
    clist_freelist(prog->ipatches);
    prog->ipatches = NULL;
  }
  if ( prog->vars ) {
    ht_free(prog->vars);
    prog->vars = NULL;
  }
}


/* resolve all instruction patches in the system */
int nprg_link(struct netvm_program *prog)
{
  struct list *l;
  struct netvm_inst *inst;
  struct netvm_ipatch *iptch;
  struct netvm_label *label;
  struct netvm_var *var, *var2;
  uint32_t val;
  abort_unless(prog);

  /* patch all instructions */
  for ( l = l_head(prog->ipatches); l != l_end(prog->ipatches); l = l->next ) {
    iptch = clist_dptr(l, struct netvm_ipatch);
    abort_unless(iptch->iaddr < prog->ninst);
    inst = prog->inst + iptch->iaddr;
    if ( iptch->type == NETVM_IPTYPE_LABEL ) {
      label = ht_get(prog->labels, iptch->symname);
      if ( label == NULL )
        return -1;
      inst->val = label->addr;
    } else {
      abort_unless(iptch->type == NETVM_IPTYPE_VAR);
      var = ht_get(prog->vars, iptch->symname);
      if ( var == NULL )
        return -1;
      inst->val = var->addr;
    }
  }

  /* patch all variables */
  for ( l = l_head(prog->varlist); l != l_end(prog->varlist); l = l->next ) {
    var = clist_data(l, struct netvm_var *);
    if ( var->inittype == NETVM_ITYPE_LABEL ) {
      label = ht_get(prog->labels, var->init_type_u.symname);
      if ( label == NULL )
        return -1;
      free(var->init_type_u.symname);
      val = label->addr;
      var->inittype = NETVM_ITYPE_FILL;
      var->datalen = 8;
      var->init_type_u.fill = val;
    } else if ( var->inittype == NETVM_ITYPE_VADDR ) {
      var2 = ht_get(prog->vars, var->init_type_u.symname);
      if ( var2 == NULL )
        return -1;
      free(var->init_type_u.symname);
      val = var2->addr;
      var->inittype = NETVM_ITYPE_FILL;
      var->datalen = 8;
      var->init_type_u.fill = val;
    }
  }

  for ( l = l_head(prog->varlist); l != l_end(prog->varlist); l = l->next )
    ht_clr(prog->vars, var->name);
  linkfree(prog);
  prog->linked = 1;

  return 0;
}


static void loadvar(byte_t *mem, struct netvm_var *var)
{
  uint32_t i;
  switch(var->inittype) {
  case NETVM_ITYPE_NONE:
    break;
  case NETVM_ITYPE_FILL:
    for ( i = 0; i < var->len; i += var->datalen ) {
      switch(var->datalen) {
      case 1: *(uint8_t *)(mem + i) = var->init_type_u.fill; break;
      case 2: *(uint16_t *)(mem + i) = var->init_type_u.fill; break;
      case 4: *(uint32_t *)(mem + i) = var->init_type_u.fill; break;
      case 8: *(uint64_t *)(mem + i) = var->init_type_u.fill; break;
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
int nprg_load(struct netvm *vm, struct netvm_program *prog)
{
  size_t memreq;
  struct list *l;
  struct netvm_var *var;
  abort_unless(vm && prog);
  if ( !prog->linked )
    return -1;
  memreq = mem_required(prog);
  if ( (memreq > vm->memsz) || ((memreq > 0) && !vm->mem)  )
    return -1;
  if ( netvm_setcode(vm, prog->inst, prog->ninst) < 0 )
    return -1;
  netvm_set_matchonly(vm, prog->matchonly);
  for ( l = l_head(prog->varlist); l != l_end(prog->varlist); l = l->next )
    loadvar(vm->mem, var);
  netvm_setrooff(vm, vm->memsz - amm_get_fill(&prog->romm));
  return 0;
}


/* release all auxilliary data */
void nprg_release(struct netvm_program *prog)
{
  int dummy;
  abort_unless(prog);
  linkfree(prog);
  if ( prog->varlist ) {
    l_apply(prog->varlist, freevar, &dummy);
    clist_freelist(prog->varlist);
    prog->ipatches = NULL;
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
  mrt->pktprogs = clist_newlist();
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
  match->matchonly = 1; /* override anything in the match program */
  mp.match = match;
  mp.action = action;
  clist_enq(mrt->pktprogs, struct netvm_matchedprog, mp);
  return 0;
}


int nvmmrt_execute(struct netvm_mrt *mrt)
{
  struct pktbuf *pkb;
  struct netvm_matchedprog *mprog;
  int i, rv, send;
  uint64_t rc;
  struct list *l;

  abort_unless(mrt);
  if ( mrt->begin && (nprg_load(mrt->vm, mrt->begin) < 0) )
      return -1;

  while ( (pkb = (*mrt->pktin)(mrt->inctx)) ) {
    netvm_loadpkt(mrt->vm, pkb, 0);

    send = 1;
    for ( l = l_head(mrt->pktprogs); l != l_end(mrt->pktprogs); l = l->next ) {
      mprog = clist_data(l, struct netvm_matchedprog *);
      if ( nprg_load(mrt->vm, mprog->match) < 0 )
        return -1;
      if ( (rv = netvm_run(mrt->vm, -1, &rc)) < 0 )
        return -1;
      if ( !rc )
        continue;
      if ( nprg_load(mrt->vm, mprog->action) < 0 )
        return -1;
      /* clear all packets on an error */
      if ( (rv = netvm_run(mrt->vm, -1, &rc)) < 0 ) {
        for ( i = 0; i < NETVM_MAXPKTS; ++i )
          netvm_clrpkt(mrt->vm, i, 0);
        continue;
      }
      if ( rv > 0 ) {
        if ( rv > 0 )
          send = 0;
        if ( rv == 2 )
          break;
      }
    }
    if ( send ) {
      for ( i = 0; i < NETVM_MAXPKTS; ++i ) {
        pkb = netvm_clrpkt(mrt->vm, i, 1);
        if ( pkb )
          (*mrt->pktout)(pkb, mrt->outctx);
      }
    } else {
      netvm_clrpkt(mrt->vm, 0, 0);
    }
  }

  for ( i = 0; i < NETVM_MAXPKTS; ++i )
    netvm_clrpkt(mrt->vm, i, 0);

  if ( mrt->end && (nprg_load(mrt->vm, mrt->end) < 0) )
      return -1;

  return 0;
}


void nvmmrt_release(struct netvm_mrt *mrt, void (*progfree)(void *))
{
  struct list *l;
  struct netvm_matchedprog *mprog;
  abort_unless(mrt);
  if ( progfree ) {
    (*progfree)(mrt->begin);
    (*progfree)(mrt->end);
    for ( l = l_head(mrt->pktprogs); l != l_end(mrt->pktprogs); l = l->next ) {
      mprog = clist_data(l, struct netvm_matchedprog *);
      (*progfree)(mprog->match);
      (*progfree)(mprog->action);
    }
  }
  clist_freelist(mrt->pktprogs);
  mrt->vm= NULL;
}


