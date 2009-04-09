#ifndef __netvm_h
#define __netvm_h
#include "tcpip_hdrs.h"
#include "packet.h"
#include "protoparse.h"
#include <cat/emit.h>

struct netvmpkt {
  struct pktbuf *       packet;
  struct hdr_parse *    headers;
};

enum {
  NETVM_HDR_HOFF = 1,
  NETVM_HDR_POFF,
  NETVM_HDR_TOFF,
  NETVM_HDR_EOFF,
  NETVM_HDR_HLEN,
  NETVM_HDR_PLEN,
  NETVM_HDR_TLEN,
  NETVM_HDR_LEN
};

#define NETVM_HDRFLDOK(f) (((f) >= NETVM_HDR_HOFF) && ((f) <= NETVM_HDR_LEN))
#define NETVM_ISHDROFF(f) (((f) >= NETVM_HDR_HOFF) && ((f) <= NETVM_HDR_EOFF))

enum {
  NETVM_OC_POP,
  NETVM_OC_PUSH,
  NETVM_OC_DUP,
  NETVM_OC_LDMEM,
  NETVM_OC_STMEM,
  NETVM_OC_LDPKT,
  NETVM_OC_LDCLASS,
  NETVM_OC_LDTS,
  NETVM_OC_LDHDRF,
  NETVM_OC_NOT,
  NETVM_OC_TONET,
  NETVM_OC_TOHOST,
  NETVM_OC_SIGNX,
  NETVM_OC_ADD,
  NETVM_OC_SUB,
  NETVM_OC_MUL,
  NETVM_OC_DIV,
  NETVM_OC_MOD,
  NETVM_OC_SHL,
  NETVM_OC_SHR,
  NETVM_OC_SHRA,
  NETVM_OC_AND,
  NETVM_OC_OR,
  NETVM_OC_EQ,
  NETVM_OC_NEQ,
  NETVM_OC_LT,
  NETVM_OC_LE,
  NETVM_OC_GT,
  NETVM_OC_GE,
  NETVM_OC_SLT,
  NETVM_OC_SLE,
  NETVM_OC_SGT,
  NETVM_OC_SGE,
  NETVM_OC_HASHDR,
  NETVM_OC_HALT,
  NETVM_OC_MAX_MATCH = NETVM_OC_HALT,

  /* not allowed in pure match run */
  NETVM_OC_BR,
  NETVM_OC_BRIF,
  NETVM_OC_PRBIN,       /* special: val == min string width */
  NETVM_OC_PROCT,       /* special: val == min string width */
  NETVM_OC_PRDEC,       /* special: val == min string width */
  NETVM_OC_PRHEX,       /* special: val == min string width */
  NETVM_OC_PRIP,        /* special: no immediate operands */
  NETVM_OC_PRETH,       /* special: no immediate operands */
  NETVM_OC_PRIPV6,      /* special: no immediate operands */
  NETVM_OC_PRSTR,       /* special: if immmed, width == string length */
  NETVM_OC_STPKT,
  NETVM_OC_STCLASS,
  NETVM_OC_STTS,
  NETVM_OC_PKTNEW,
  NETVM_OC_PKTCOPY,
  NETVM_OC_HDRCREATE,
  NETVM_OC_FIXLEN,
  NETVM_OC_FIXCKSUM,
  NETVM_OC_PKTINS,
  NETVM_OC_PKTCUT,
  NETVM_OC_HDRADJ,

  NETVM_OC_MAX = NETVM_OC_HDRADJ
};

enum {
  NETVM_IF_IMMED =      0x1, /* last op is immediate rather than on stack */ 
  NETVM_IF_SIGNED =     0x2, /* number, value or all operands are signed */
  NETVM_IF_TONET =      0x4, /* for store operations */
  NETVM_IF_TOHOST =     0x8, /* for load operation s*/
  NETVM_IF_IPHLEN =    0x10, /* on 1 byte packet load instructions */
  NETVM_IF_TCPHLEN =   0x20, /* on 1 byte packet load instructions */
  NETVM_IF_MOVEUP =    0x40, /* only used HDRINS and HDRCUT */
};

/* 
 * If immed is not set for a load/store instruction then the address to load
 * from or store to is on top of the stack.  Store operations always take their
 * values from the stack as well.  (but not PUSH operations)
 *
 * If immed is not set for a header instruction then the instruction 
 * expects a struct netvm_hdr_desc to be the value on the stack packed into a
 * 64-bit word.
 */

#define NETVM_HDESC(pn, ht, idx, fld, off) \
  ((((uint64_t)(pn) & 0xFF) << 56)|\
   (((uint64_t)(ht) & 0xFF) << 48)|\
   (((uint64_t)(idx) & 0xFF) << 40)|\
   (((uint64_t)(fld) & 0xFF) << 32)|\
   ((uint64_t)(off) & 0xFFFFFFFF))


struct netvm_hdr_desc {
  uint8_t           pktnum;     /* which packet entry */
  uint8_t           htype;      /* PPT_*;  PPT_NONE == absolute idx */
  uint8_t           idx;        /* 0 == 1st hdr, 1 == 2nd hdr,... */
  uint8_t           field;      /* NETVM_HDR_* */
  uint32_t          offset;     /* offset into packet */
};

struct netvm_inst {
  uint8_t       opcode; /* NETVM_OC_* */
  uint8_t       width;  /* 1, 2, 4 or 8 for most operations */
  uint16_t      flags;  /* NETVM_IF_* */
  uint64_t      val;    /* Varies with instruction */
};

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


/* mem may be NULL and memsz 0.  roseg must be <= memsz.  stack must not be */
/* 0 and ssz is the number of stack elements.  outport may be NULL */
void init_netvm(struct netvm *vm, uint64_t *stack, unsigned int ssz,
                byte_t *mem, unsigned int memsz, unsigned int roseg, 
                struct emitter *outport);

/* clear memory, set pc <= 0, discard packets */
void reset_netvm(struct netvm *vm, struct netvm_inst *inst, unsigned ni);

/* 0 if run ok and no retval, 1 if run ok and stack not empty, -1 if err, -2 */
/* if out of cycles */
int run_netvm(struct netvm *vm, int maxcycles, int *rv);


/* takes control of the struct pktbuf and returns a netvmpkt */
struct netvmpkt *pktbuf_to_netvmpkt(struct pktbuf *pb);

/* frees the netvmpkt and the underlying pakcet */
void free_netvmpkt(struct netvmpkt *pkt);

/* returns 0 if ok inputting packet and -1 otherwise */
void set_netvm_packet(struct netvm *vm, int slot, struct netvmpkt *pkt);

/* returns 0 if the packet is OK to be sent and -1 otherwise */
struct netvmpkt *release_netvm_packet(struct netvm *vm, int slot);

#endif /* __netvm_h */
