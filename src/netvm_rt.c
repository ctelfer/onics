#include "netvm_rt.h"
#include <cat/stdlib.h>

#define MMMAXSIZE  (128 * 1024)

static size_t mem_required(struct netvm_program *prog)
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
  prog->isymtab = ht_new(64, CAT_DT_STR);
  prog->ipatches = clist_newlist();
  prog->msymtab = ht_new(64, CAT_DT_STR);
  prog->mpatches = clist_newlist();
  amm_init(&prog->rwmm, (byte_t*)0, MMMAXSIZE, 8, 0);
  amm_init(&prog->romm, (byte_t*)0, MMMAXSIZE, 8, 1);
}


/* instructions and instruction symbols */
struct netvm_iloc *nprg_add_code(struct netvm_program *prog, 
                                 struct netvm_inst *inst uint32_t ninst, 
                                 const char *name)
{
  struct netvm_sym *sym = NULL;
  abort_unless(prog && inst);
  if ( (ninst == 0) || (prog->ninst >= ~(uint32_t)0 - ninst) )
    return NULL;
  if ( name && ht_get(prog->isymtab) )
    return NULL;
  if ( prog->ninst + ninst > prog->isiz ) { 
    void *p = prog->inst;
    mem_agrow(&estdmem, &p, sizeof(*inst), &prog->isiz, prog->ninst + ninst);
    prog->inst = p;
  }
  abort_unless(prog->inst && prog->isiz >= prog->ninst + ninst);
  memcpy(prog->inst, inst, ninst * sizeof(*inst));
  if ( name ) {
    sym = emalloc(sizeof(*sym));
    sym ->name = estrdup(name);
    sym->addr = prog->ninst;
    sym->len = ninst;
  }
  prog->ninst += ninst;
  return sym;
}


int nprg_add_sympatch(struct netvm_program *prog, const char *symbol, 
                      uint32_t iaddr, uint64_t delta)
{
  struct netvm_sympatch symp;
  abort_unless(prog && prog->ipatches);
  symp.symbol = estrdup(symbol);
  symp.iaddr = iaddr;
  symp.delta = delta;
  clist_enq(prog->ipatches, struct netvm_sympatch, symp);
}


const struct netvm_sym *nprg_get_isym(struct netvm_program *prog, 
                                      const char *name)
{
  abort_unless(prog && prog->isymtab);
  return ht_get(prog->isymtab, name);
}


/* variables and variable symbols */
struct netvm_var *nprg_add_var(struct netvm_program *prog, const char *name,
                               uint32_t len, int isrdonly)
{
  struct netvm_var *var;
  byte_t *p;
  abort_unless(prog && prog->msymtab, && name);
  if ( ht_get(prog->msymtab, name) )
    return NULL;

  if ( isrdonly ) {
    if ( !(p = mem_get(&prog->romm, len)) )
      return NULL;
  } else {
    if ( !(p = mem_get(&prog->rwmm, len)) )
      return NULL;
  }
  var = emalloc(sizeof(*var));
  var->name = estrdup(name);
  var->addr = p - (byte_t)0;
  var->len = len;
  var->inittype = NETVM_ITYPE_NONE;
  var->isrdonly = isrdonly;
  var->datalen = 0;
  var->init_type_u.data = NULL;
  ht_put(prog->msymtab, var);
  return var;
}


int nprg_vinit_data(struct netvm_var *var, void *data, uint32_t len)
{
  abort_unless(var && data && len <= var->len);
  if ( var->type == NETVM_ITYPE_DATA )
    free(var->init_type_u.data);
  var->type = NETVM_ITYPE_DATA;
  var->init_type_u.data = emalloc(len);
  memcpy(var->init_type_u.data, data,len);
  var->datalen = len;
  return 0;
}


void nprg_vinit_fill(struct netvm_var *var, uint64_t val, int width)
{
  if ( var->type == NETVM_ITYPE_DATA )
    free(var->init_type_u.data);
  var->type = NETVM_INIT_FILL;
  var->datalen = width;
  var->init_type_u.fill = val;
}


const struct netvm_var *nprg_get_var(struct netvm_program *prog, 
                                     const char *name);
{
  abort_unless(prog && prog->msymtab);
  return ht_get(prog->msymtab, name);
}


/* resolve all instruction patches in the system */
int nprg_link(struct netvm *vm)
{
}


/* load a program onto a VM */
int nprg_load(struct netvm *vm, struct netvm_program *prog)
{
}


static void sympatch_free_aux(void *spp, void *)
{
  struct netvm_sympatch *sp = spp;
  free(sp->symbol);
}


static void sym_free_aux(void *symp, void *)
{
  struct netvm_sym *sym = symp;
  free(sym->name);
}


static void var_free_aux(void *varp, void *)
{
  struct netvm_sym *var = varp;
  free(var->name);
  if ( var->inittype == NETVM_ITYPE_DATA )
    free(var->init_type_u.data);
}


/* release all auxilliary data */
void nprg_release(struct netvm_program *prog)
{
  abort_unless(prog);

  if ( prog->isymtab ) {
    ht_apply(prog->isymtab, sym_free_aux, NULL);
    ht_free(prog->isymtab);
    prog->isymtab = NULL;
  }
  if ( prog->ipatches ) {
    l_apply(prog->ipatches, sympatch_free_aux, NULL);
    clist_freelist(prog->ipatches);
    prog->ipatches = NULL;
  }
  if ( prog->msymtab ) {
    ht_apply(prog->msymtab, var_free_aux, NULL);
    ht_free(prog->msymtab);
    prog->msymtab = NULL;
  }
  if ( prog->mpatches ) {
    l_apply(prog->mpatches, sympatch_free_aux, NULL);
    clist_freelist(prog->mpatches);
    prog->ipatches = NULL;
  }
  free(prog->inst);
  prog->inst = NULL;
  prog->isiz = 0;
  prog->ninst = 0;
  prog->linked = 0;
}



void nvmmrt_init(struct netvm_mrt *, struct netvm *vm, pktin_f inf, void *inctx,
                 pktout_f outf, void *outctx)
{
}


int nvmmrt_set_begin(struct netvm_mrt *rt, struct netvm_prog *prog)
{
}


int nvmmrt_set_end(struct netvm_mrt *rt, struct netvm_prog *prog)
{
}


int nvmmrt_add_pktprog(struct netvm_mrt *rt, struct netvm_matchedprog *prog)
{
}


int nvmmrt_execute(struct netvm_mrt *rt)
{
}


void nvmmrt_release(struct netvm_mrt *rt, free_f progfree)
{
}


