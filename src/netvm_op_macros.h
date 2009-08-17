#ifndef __netvm_op_macros_h
#define __netvm_op_macros_h

/* purely to set a breakpoint during debugging */
static int dbgabrt()
{
  return 1;
}

#define IMMED(inst) ((inst)->flags & NETVM_IF_IMMED)
#define CPIMMED(inst) ((inst)->flags & NETVM_IF_CPIMMED)
#define ISSIGNED(inst) ((inst)->flags & NETVM_IF_SIGNED)
#define CPOP(inst) (((inst)->flags >> 8) & 0xFF)

#define VMERR(__vm, __e) do { __vm->error = __e; dbgabrt(); return; } while (0)

#define FATAL(__vm, __e, __cond) \
  if (__cond) { __vm->error = __e; dbgabrt(); return; }

#define S_EMPTY(__vm)           (__vm->sp == __vm->bp)
#define S_HAS(__vm, __n)        (__vm->sp - __vm->bp >= __n)
#define S_FULL(__vm)            (__vm->sp >= __vm->stksz)
#define S_AVAIL(__vm)           (__vm->stksz - __vm->sp)

#define S_TOP(__vm, __v)                                                \
  do {                                                                  \
    FATAL((__vm), NETVM_ERR_STKUNDF, S_EMPTY(__vm));                    \
    __v = __vm->stack[__vm->sp-1];                                      \
  } while (0)

/* __n is a 0-based index from the top of the stack */
#define S_GET(__vm, __n)        (__vm->stack[__vm->sp - __n - 1])
#define S_SET(__vm, __n, __val) (__vm->stack[__vm->sp - __n - 1] = __val)

#define S_POP(__vm, __v)                                                \
  do {                                                                  \
    FATAL((__vm), NETVM_ERR_STKUNDF, S_EMPTY(__vm));                    \
    __v = __vm->stack[--__vm->sp];                                      \
  } while (0)

#define S_PUSH(__vm, __v)                                               \
  do {                                                                  \
    FATAL((__vm), NETVM_ERR_STKOVFL, S_FULL(__vm));                     \
    __vm->stack[__vm->sp++] = (__v);                                    \
  } while (0)


#endif /*__netvm_op_macros_h */
