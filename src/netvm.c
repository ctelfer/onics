#include "netvm.h"
#include <cat/cat.h>

static void unimplemented(struct netvm *vm)
{
  struct netvm_instr *inst = &vm->inst[vm->pc];
  if ( vm->outfile )
    fprintf(vm->outfile, "Instruction %d not implemented\n", inst->opcode);
  vm->error = 1;
  vm->running = 0;
}


struct netvm_inst g_netvm_ops[NTVM_IT_MAX+1] = { 
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

  vm->pc = 0;
  vm->running = 0;
  vm->sp = 0;

  while ( vm->running && maxcycles != 0 ) {
    inst = &vm->inst[vm->pc];
    (*g_netvm_ops[inst->opcode])(vm);
    if ( maxcycles > 0 )
      --maxcycles;
  }

  if ( vm->error )
    return -1;
  if ( vm->running )
    return -2;
  if ( vm->sp == 0 )
    return 0;
  if ( rv )
    *rv = (int)vm->stack[vm->sp-1];
  return 1;
}

