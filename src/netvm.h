#ifndef __netvm_h
#define __netvm_h
#include "tcpip_hdrs.h"
#include <stdio.h>


enum {
  NETVM_UINT,
  NETVM_INT,
  NETVM_ADDR,
  NETVM_HDR,
};

enum {
  NETVM_HDR_HOFF,
  NETVM_HDR_HLEN,
  NETVM_HDR_POFF,
  NETVM_HDR_PLEN,
  NETVM_HDR_TOFF,
  NETVM_HDR_TLEN,
  NETVM_HDR_EOFF,
  NETVM_HDR_LEN
};


enum {
  NETVM_IT_POP,
  NETVM_IT_PUSH,
  NETVM_IT_DUP,
  NETVM_IT_LDMEM,
  NETVM_IT_STMEM,
  NETVM_IT_LDPKT,
  NETVM_IT_LDCLASS,
  NETVM_IT_LDTS,
  NETVM_IT_LDHDRF,
  NETVM_IT_ADD,
  NETVM_IT_SUB,
  NETVM_IT_MUL,
  NETVM_IT_DIV,
  NETVM_IT_MOD,
  NETVM_IT_SHL,
  NETVM_IT_SHR,
  NETVM_IT_SHRA,
  NETVM_IT_NOT,
  NETVM_IT_AND,
  NETVM_IT_OR,
  NETVM_IT_EQ,
  NETVM_IT_NEQ,
  NETVM_IT_LT,
  NETVM_IT_LE,
  NETVM_IT_GT,
  NETVM_IT_GE,
  NETVM_IT_SLT,
  NETVM_IT_SLE,
  NETVM_IT_SGT,
  NETVM_IT_SGE,
  NETVM_IT_MASKEQ,
  NETVM_IT_TONET,
  NETVM_IT_TOHOST,
  NETVM_IT_HASPROTO,
  NETVM_IT_HASHDR,
  NETVM_IT_HALT,

  NETVM_IT_MAX_MATCH = NETVM_IT_HALT,
  /* not allowed in pure match run */
  NETVM_IT_PRBIN,
  NETVM_IT_PRDEC,
  NETVM_IT_PRHEX,
  NETVM_IT_PROCT,
  NETVM_IT_PRIP,
  NETVM_IT_PRETH,
  NETVM_IT_PRIPV6,
  NETVM_IT_PRSTR,
  NETVM_IT_STPKT,
  NETVM_IT_STCLASS,
  NETVM_IT_STTS,
  NETVM_IT_COPYPKT,
  NETVM_IT_FIXLEN,
  NETVM_IT_FIXCKSUM,
  NETVM_IT_BR,
  NETVM_IT_BRIF,
  NETVM_IT_BROFF,

  NETVM_IT_MAX = NETVM_IT_BROFF
};


struct netvm_data {
  union {
    struct netvm_num {
      unsigned short            width; /* valid for INT and UINT: 1,2,4,8 */
      unsigned short            pad;
      unsigned long long        val;
    } num;
    struct netvm_hdr_desc {
      unsigned char             onstack;  /* read from stack instead */
      unsigned char             htype; /* PPT_*;  PPT_NONE == absolute idx */
      unsigned char             idx;   /* 0 == whole packet, 1 == 1st hdr,... */
      unsigned char             field; /* NETVM_HDR_* */
      unsigned int              offset;
    } hdr;
  }u;
};

/* 
 * if onstack is set for a hdr_desc in an instruction then the instruction 
 * expects the (field << 16 | idx << 8 | htype) to be the next entry on the 
 * stack.  If the offset is needed for the instruction, the offset must be
 * the second thing on the stack.
 */


struct netvm_inst {
  unsigned int          opcode;
  struct netvm_data     data;
};


#define NETVM_MAXPKTS   16
struct netvm {
  int                   matchonly;
  struct netvm_inst *   inst;
  unsigned int          ninst;
  unsigned long long *  stack;
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
