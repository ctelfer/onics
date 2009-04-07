#ifndef __netvm_h
#define __netvm_h
#include "tcpip_hdrs.h"
#include "packet.h"
#include "progoparse.h"
#include <cat/emit.h>

struct netvmpkt {
  struct pktbuf *       packet;
  struct hdr_parse *    headers;
};


enum {
  NETVM_HDR_HOFF,
  NETVM_HDR_POFF,
  NETVM_HDR_TOFF,
  NETVM_HDR_EOFF,
  NETVM_HDR_HLEN,
  NETVM_HDR_PLEN,
  NETVM_HDR_TLEN,
  NETVM_HDR_LEN
};

#define NETVM_HDRFLDOK(f) (((f) >= NETVM_HDR_HOFF) && ((f) <= NETVM_HDR_LEN)
#define NETVM_ISHDROFF(f) (((f) >= NETVM_HDR_HOFF) && ((f) <= NETVM_HDR_EOFF)
#define NETVM_ISHDRLEN(f) (((f) >= NETVM_HDR_HLEN) && ((f) <= NETVM_HDR_LEN)


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
  NETVM_IT_NOT,
  NETVM_IT_TONET,
  NETVM_IT_TOHOST,
  NETVM_IT_SIGNX,
  NETVM_IT_ADD,
  NETVM_IT_SUB,
  NETVM_IT_MUL,
  NETVM_IT_DIV,
  NETVM_IT_MOD,
  NETVM_IT_SHL,
  NETVM_IT_SHR,
  NETVM_IT_SHRA,
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
  NETVM_IT_HASHDR,
  NETVM_IT_HALT,
  NETVM_IT_MAX_MATCH = NETVM_IT_HALT,

  /* not allowed in pure match run */
  NETVM_IT_BR,
  NETVM_IT_BRIF,
  NETVM_IT_PRBIN,
  NETVM_IT_PROCT,
  NETVM_IT_PRDEC,
  NETVM_IT_PRHEX,
  NETVM_IT_PRIP,
  NETVM_IT_PRETH,
  NETVM_IT_PRIPV6,
  NETVM_IT_PRSTR,
  NETVM_IT_STPKT,
  NETVM_IT_STCLASS,
  NETVM_IT_STTS,
  NETVM_IT_PKTNEW,
  NETVM_IT_PKTCOPY,
  NETVM_IT_HDRCREATE,
  NETVM_IT_FIXLEN,
  NETVM_IT_FIXCKSUM,
  NETVM_IT_PKTINS,
  NETVM_IT_PKTCUT,
  NETVM_IT_HDRADJ,

  NETVM_IT_MAX = NETVM_IT_BROFF
};


enum {
  NETVM_HDF_HDONSTACK   0x1,
  NETVM_HDF_OFFONSTACK  0x2,
  NETVM_HDF_TONET       0x4,
  NETVM_HDF_TOHOST      0x8,
  NETVM_HDF_IPHLEN      0x10, /* only used on 1 byte packet load instructions */
  NETVM_HDF_TCPHLEN     0x20, /* only used on 1 byte packet load instructions */
  NETVM_HDF_MOVEUP      0x40, /* only used HDRINS and HDRCUT */
};


#define NETVM_HDONSTACK   255
struct netvm_data {
  union {
    struct netvm_num {
      uint8_t           width;
      uint8_t           issigned;
      uint8_t           immed; /* addr for load/store ops and v2 of alu ops */
      uint8_t           pad;
      uint64_t          val;
    } num;
    struct netvm_hdr_desc {
      uint8_t           width;    /* useless for load/store header field ops */
      uint8_t           issigned; /* useless for load/store header field ops */
      uint8_t           flags;    /* header desc is on the stack */
      uint8_t           pad;      /* offset is on the stack */
      uint8_t           pktnum;   /* which packet entry */
      uint8_t           htype;    /* PPT_*;  PPT_NONE == absolute idx */
      uint8_t           idx;      /* 0 == whole packet, 1 == 1st hdr,... */
      uint8_t           field;    /* NETVM_HDR_* */
      uint32_t          offset;
    } hdr;
  }u;
};

/* 
 * If onstack is set for a load/store instruction then the address to load
 * from or store to is on top of the stack.  Store operations always take their
 * values from the stack as well.  (but not PUSH operations)
 *
 * If onstack is set for a header instruction then the instruction 
 * expects the (field << 24 | idx << 16 | htype << 8 | pktnum ) to be the next 
 * entry on the stack.  If the offset is needed for the instruction, the 
 * offset must be the second thing on the stack.
 */


struct netvm_inst {
  uint32_t              opcode;
  struct netvm_data     data;
};


/* NOTE: must be less than or equal to NETVM_HDONSTACK */
#define NETVM_MAXPKTS   16
struct netvm {
  struct netvm_inst *   inst;
  uint32_t              ninst;
  uint64_t *            stack;
  uint32_t              stksz;
  byte_t *              mem;
  uint32_t              memsz;
  uint32_t              rosegoff;
  struct emitter *      outport;
  struct netvmpkt *     packets[NETVM_MAXPKTS];
  int                   matchonly;
  int                   running;
  int                   error;
  int                   branch;
  unsigned int          pc;
  unsigned int          sp;
};


void init_netvm(struct netvm *vm, struct netvm_data *stack, unsigned int ssz,
                byte_t *mem, unsigned int memsz, unsigned int roseg, 
                struct emitter *outport);

/* clear memory, set pc <= 0, discard packets */
void reset_netvm(struct netvm *vm, struct netvm_inst *inst, unsigned ni);

/* 0 if run ok and no retval, 1 if run ok and stack not empty, -1 if err, -2 */
/* if out of cycles */
int run_netvm(struct netvm *vm, int maxcycles, int *rv);

/* returns 0 if ok inputting packet and -1 otherwise */
void set_netvm_packet(struct netvm *vm, int slot, struct netvmpkt *pkt);

/* returns 0 if the packet is OK to be sent and -1 otherwise */
struct netvmpkt *release_netvm_packet(struct netvm *vm, int slot);

#endif /* __netvm_h */
