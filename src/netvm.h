#ifndef __netvm_h
#define __netvm_h
#include "tcpip_hdrs.h"
#include <stdio.h>


struct netvm_data {
  uint8_t       issigned;
  uint8_t       isnet;
  uint16_t      width;          /* valid for INT and UINT: 1,2,4,8 */
  uint64_t      val;
};


enum {
  NTVM_IT_POP,
  NTVM_IT_PUSH,
  NTVM_IT_DUP,
  NTVM_IT_LDMEM,
  NTVM_IT_LDPKT,
  NTVM_IT_LDPMETA,
  NTVM_IT_ADD,
  NTVM_IT_SUB,
  NTVM_IT_MUL,
  NTVM_IT_DIV,
  NTVM_IT_MOD,
  NTVM_IT_SHL,
  NTVM_IT_SHR,
  NTVM_IT_SHRA,
  NTVM_IT_NOT,
  NTVM_IT_AND,
  NTVM_IT_OR,
  NTVM_IT_EQ,
  NTVM_IT_LT,
  NTVM_IT_LE,
  NTVM_IT_SEQ,
  NTVM_IT_SLT,
  NTVM_IT_SLE,
  NTVM_IT_MASKEQ,
  NTVM_IT_TONET,
  NTVM_IT_TOHOST,
  NTVM_IT_SETWIDTH,
  NTVM_IT_HASPROTO,
  NTVM_IT_HALT,

  NTVM_IT_MAX_MATCH = NTVM_IT_HALT,
  /* not allowed in pure match run */
  NTVM_IT_PRBIN,
  NTVM_IT_PRDEC,
  NTVM_IT_PRHEX,
  NTVM_IT_PROCT,
  NTVM_IT_PRIP,
  NTVM_IT_PRETH,
  NTVM_IT_PRIPV6,
  NTVM_IT_PRSTR,
  NTVM_IT_STMEM,
  NTVM_IT_STPKT,
  NTVM_IT_STPMETA,
  NTVM_IT_SAVEPKT,
  NTVM_IT_FIXLEN,
  NTVM_IT_FIXCKSUM,
  NTVM_IT_BR,
  NTVM_IT_BRIF,
  NTVM_IT_BROFF,

  NTVM_IT_MAX = NTVM_IT_BROFF
};


struct netvm_inst {
  byte_t                opcode;
  struct netvm_data     data;
};


#define NETVM_MAXPKTS   16
struct netvm {
  int                   matchonly;
  struct netvm_inst *   inst;
  unsigned int          ninst;
  struct netvm_data *   stack;
  unsigned int          stksz;
  byte_t *              mem;
  unsigned int          memsz;
  unsigned int          rosegoff;
  FILE *                outfile;
  struct pktbuf *       packets[NETVM_MAXPKTS];
  int                   running;
  int                   error;
  unsigned              pc;
  unsigned              sp;
};


void init_netvm(struct netvm *vm, struct netvm_data *stack, unsigned int ssz,
                byte_t *mem, unsigned int memsz, unsigned int roseg, 
                FILE *outfile);

/* clear memory, set pc <= 0, discard packets */
void reset_netvm(struct netvm *vm, struct netvm_inst *inst, unsigned ni);


/* 0 if run ok and no retval, 1 if run ok and stack not empty, -1 if err, -2 */
/* if out of cycles */
int run_netvm(struct netvm *vm, int maxcycles, int *rv);



#endif /* __netvm_h */
