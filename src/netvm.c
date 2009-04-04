#include "netvm.h"
#include <cat/cat.h>

#define FATAL(__cond, __vm) \
  if (__cond) { __vm->error = 1; __vm->running = 0; return; }

#define NONFATAL(__cond, __vm) \
  if (__cond) { __vm->error = 1; return; }

#define S_EMPTY(__vm)           (__vm->sp == 0)
#define S_HAS(__vm, __n)        (__vm->sp >= n)
#define S_FULL(__vm)            (__vm->sp >= __vm->stksz)

#define S_TOP(__vm, __v)                                                \
  do {                                                                  \
    FATAL(S_EMPTY(__vm));                                               \
    __v = __vm->stack[__vm->sp];                                        \
  } while (0)

#define S_POP(__vm, __v)                                                \
  do {                                                                  \
    FATAL(S_EMPTY(__vm));                                               \
    __v = __vm->stack[--__vm->sp];                                      \
  } while (0)

#define S_PUSH(__vm, __v)                                               \
  do {                                                                  \
    FATAL(S_FULL(__vm));                                                \
    __vm->stack[__vm->sp++] = (__v);                                    \
  } while (0)

#define BADWIDTH(__w) (!__w || (__w & (__w - 1)) || (__w > 8))



static void unimplemented(struct netvm *vm)
{
  struct netvm_instr *inst = &vm->inst[vm->pc];
  if ( vm->outfile )
    fprintf(vm->outfile, "Instruction %d not implemented\n", inst->opcode);
  vm->error = 1;
  vm->running = 0;
}


static void ni_pop(struct netvm *vm)
{
  uint64_t v;
  S_POP(vm, v);
}


static void ni_push(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  S_PUSH(vm, inst->u.num.val);
}


static void ni_dup(struct netvm *vm)
{
  uint64_t val;
  S_TOP(vm, val);
  S_PUSH(vm, val);
}


static void ni_ldmem(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint64_t val;
  register unsigned int addr = inst->u.num.val;
  register unsigned int width = inst->u.num.width;
  FATAL(addr > vm->memsz || addr + width > vm->memsz);
  if (inst->u.num.issigned)
    width = -width;
  switch(width) {
  case -1: val = (int64_t)*(int8_t *)(vm->mem + addr) = val; break;
  case -2: val = (int64_t)*(int16_t *)(vm->mem + addr) = val; break;
  case -4: val = (int64_t)*(int32_t *)(vm->mem + addr) = val; break;
  case -8: val = (int64_t)*(int64_t *)(vm->mem + addr) = val; break;
  case 1: val = *(uint8_t *)(vm->mem + addr) = val; break;
  case 2: val = *(uint16_t *)(vm->mem + addr) = val; break;
  case 4: val = *(uint32_t *)(vm->mem + addr) = val; break;
  case 8: val = *(uint64_t *)(vm->mem + addr) = val; break;
  default:
    FATAL(0);
  }
  S_PUSH(vm, val);
}


static void ni_stmem(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  uint64_t val;
  register unsigned int addr = inst->u.num.val;
  register int width = inst->u.num.width;
  FATAL(addr > vm->memsz || addr + width > vm->memsz);
  S_POP(vm, val);
  if (inst->u.num.issigned)
    width = -width;
  switch(width) {
  case -1: *(int8_t *)(vm->mem + addr) = val; break;
  case -2: *(int16_t *)(vm->mem + addr) = val; break;
  case -4: *(int32_t *)(vm->mem + addr) = val; break;
  case -8: *(int64_t *)(vm->mem + addr) = val; break;
  case 1: *(uint8_t *)(vm->mem + addr) = val; break;
  case 2: *(uint16_t *)(vm->mem + addr) = val; break;
  case 4: *(uint32_t *)(vm->mem + addr) = val; break;
  case 8: *(uint64_t *)(vm->mem + addr) = val; break;
  default:
    FATAL(0);
  }
}


static void ni_lkpkt(struct netvm *vm)
{
  struct netvm_inst *inst = &vm->inst[vm->pc];
  struct netvm_hdr_desc *hd, hd0;
  struct hdr_parse *hdr;
  uint64_t val;

  hd = &inst->hdr;
  if ( hd->pktnum == NETVM_HDONSTACK ) {
    hd = &hd0;
    S_POP(vm, val);
    hd->pktnum = val & 0xFF;
    hd->htype = (val >> 8) & 0xFF;
    hd->idx = (val >> 16) & 0xFF;
    hd->field = (val >> 24) & 0xFF;
    S_POP(vm, val);
    hd->offset = val;
  }
  FATAL(!NETVM_HDRFLDOK(hd->field));
  hdr = find_header(hd);
  FATAL(hdr == NULL);

  if (NETVM_ISHDROFF(hd->field)) {

  }
}


struct netvm_inst g_netvm_ops[NTVM_IT_MAX+1] = { 
  ni_pop,
  ni_push,
  ni_dup,
  ni_ldmem,
  ni_stmem,
  ni_ldpkt,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented,
  unimplemented
};


void init_netvm(struct netvm *vm, struct netvm_data *stack, unsigned int ssz,
                byte_t *mem, unsigned int memsz, unsigned int roseg, 
                FILE *outfile)
{
  abort_unless(vm && stack && mem && vm->rosegoff <= vm->memsz);
  vm->stack = stack;
  vm->stksz = ssz;
  vm->mem = mem;
  vm->memsz = memsz;
  vm->rosegoff = roseg;
  vm->outfile = outfile;
  vm->inst = NULL;
  vm->ninst = 0;
  reset_netvm(vm, NULL, 0);
}


/* clear memory, set pc <= 0, discard packets */
void reset_netvm(struct netvm *vm, struct netvm_inst *inst, unsigned ni)
{
  int i;
  abort_unless(vm && stack && mem && vm->rosegoff <= vm->memsz);
  vm->pc = 0;
  vm->sp = 0;
  for ( i = 0; i < NETVM_MAXPACKETS; ++i )
    vm->packets[i] = NULL;
  memset(vm->mem, 0, vm->rosegoff);
  if ( inst != NULL ) {
    vm->inst = inst;
    vm->ninst = ni;
  }
}


/* 0 if run ok and no retval, 1 if run ok and stack not empty, -1 if err */
int run_netvm(struct netvm *vm, int maxcycles, int *rv)
{
  unsigned i, maxi;
  struct netvm_instr *inst;

  abort_unless(vm && stack && mem && vm->rosegoff <= vm->memsz);
  if ( !vm->inst )
    return -1;

  if ( vm->matchonly )
    maxi = NTVM_IT_MAX_MATCH;
  else
    maxi =  NTVM_IT_MAX;
  for ( i = 0; i < vm->ninst; i++ )
    if ( vm->inst[i].opcode > maxi )
      return -1;

  vm->error = 0;
  vm->pc = 0;
  vm->running = 0;
  vm->sp = 0;
  vm->branch = 0;

  while ( vm->running && maxcycles != 0 ) {
    inst = &vm->inst[vm->pc];
    (*g_netvm_ops[inst->opcode])(vm);

    /* if we branched: don't adjust the PC, otherwise clear the branch flag */
    if ( vm->branch )
      vm->branch = 0;
    else
      ++vm->pc;

    /* decrement cycle count if running for a limited duration */
    if ( maxcycles > 0 )
      --maxcycles;
  }

  if ( maxcycles == 0 )
    return -2;
  else if ( vm->error )
    return -1;
  if ( vm->sp == 0 )
    return 0;
  if ( rv )
    *rv = TOP(vm);
  return 1;
}

