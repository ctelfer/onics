#ifndef __netvm_h
#define __netvm_h
#include "tcpip_hdrs.h"
#include "pktbuf.h"
#include "protoparse.h"
#include <cat/emit.h>

enum {
  NETVM_HDI_LINK,       /* e.g. Ethernet */
  NETVM_HDI_TUN,        /* e.g. ESP, GRE, IP in IP */
  NETVM_HDI_NET,        /* e.g. IPv4, IPv6 */
  NETVM_HDI_XPORT,      /* e.g. TCP, UDP, RTP, ICMP */
  NETVM_HDI_MAX = NETVM_HDI_XPORT
};

struct netvmpkt {
  struct pktbuf *       packet;
  struct hdr_parse *    headers;
  struct hdr_parse *    layer[NETVM_HDI_MAX+1];
};

/* 
 * W -> uses width field to determine now many bytes to manipulate
 * I -> Immediate flag honored for last argument
 * S -> will sign extend on load if sign extention flag set
 * N -> will convert to network byte order on store if TONET flag set
 * H -> will convert to host byte order on load if TOHOST flag set
 * T -> with 1-byte load will treat as TCP offset and convert to byte length 
 * P -> with 1-byte load will treat as IP header len and convert to byte length 
 * M -> MOVEUP flag used for INS and CUT operations
 */

enum {
  NETVM_OC_NOP,         /* no operation */
  NETVM_OC_POP,         /* discards top of stack */
  NETVM_OC_PUSH,        /* implied IMMED:  pushes immediate value onto stack */
  NETVM_OC_DUP,         /* dupcliates top of stack */
  NETVM_OC_LDMEM,       /* [addr|WIS]: load from memory */
  NETVM_OC_STMEM,       /* [addr|WI]: store to memory */
  NETVM_OC_LDPKT,       /* [hdesc|WSHTP]: load bytes from packet */
  NETVM_OC_LDCLASS,     /* [pktnum|I]: load packet class */
  NETVM_OC_LDTS,        /* [pktnum|I]: load packet timestamp */
  NETVM_OC_LDHDRF,      /* [hdesc|I]: load field from header parse */
  NETVM_OC_NOT,         /* [v] logcal not (1 or 0) */
  NETVM_OC_INVERT,      /* [v] bit-wise inversion */
  NETVM_OC_TOBOOL,      /* [v] if v != 0, 1, otherwise 0 */
  NETVM_OC_TONET,       /* [v|W] convert to network byte order */
  NETVM_OC_TOHOST,      /* [v|W] convert to host byte order */
  NETVM_OC_SIGNX,       /* [v|W] sign extend based on width */
  NETVM_OC_ADD,         /* [v1,v2|I] add v1 and v2 */
  NETVM_OC_SUB,         /* [v1,v2|I] subtract v2 from v1 */
  NETVM_OC_MUL,         /* [v1,v2|I] multiply v1 from v2 */
  NETVM_OC_DIV,         /* [v1,v2|I] divide v1 by v2 */
  NETVM_OC_MOD,         /* [v1,v2|I] remainder of v1 / v2 */
  NETVM_OC_SHL,         /* [v1,v2|I] v1 left shifted by (v2 % 64) */
  NETVM_OC_SHR,         /* [v1,v2|I] v1 right shifted by (v2 % 64) */
  NETVM_OC_SHRA,        /* [v1,v2|I] v1 right arithmatic shifted by (v2 % 64) */
  NETVM_OC_AND,         /* [v1,v2|I] bitwise v1 and v2 */
  NETVM_OC_OR,          /* [v1,v2|I] bitwise v1 or v2 */
  NETVM_OC_XOR,         /* [v1,v2|I] bitwise v1 exclusive or v2 */
  NETVM_OC_EQ,          /* [v1,v2|I] v1 equals v2 */
  NETVM_OC_NEQ,         /* [v1,v2|I] v1 not equal to v2 */
  NETVM_OC_LT,          /* [v1,v2|I] v1 less than v2 */
  NETVM_OC_LE,          /* [v1,v2|I] v1 less than or equal to v2 */
  NETVM_OC_GT,          /* [v1,v2|I] v1 greater than v2 */
  NETVM_OC_GE,          /* [v1,v2|I] v1 greater than or equal to v2 */
  NETVM_OC_SLT,         /* [v1,v2|I] v1 less than v2 (signed) */
  NETVM_OC_SLE,         /* [v1,v2|I] v1 less than or equal to v2 (signed) */
  NETVM_OC_SGT,         /* [v1,v2|I] v1 greater than v2 (signed) */
  NETVM_OC_SGE,         /* [v1,v2|I] v1 greater than or equal to v2 (signed) */
  NETVM_OC_HASHDR,      /* [hdesc|I] true if has header (field in HD ignored) */
  NETVM_OC_HALT,        /* halt program */
  NETVM_OC_BR,          /* [v|I] set PC to v (must be > PC in matchonly mode */
  NETVM_OC_BRIF,        /* [c,v|I] set PC to v if c is non-zero */
                        /*         (must be > PC in matchonly mode */
  NETVM_OC_MAX_MATCH = NETVM_OC_BRIF,

  /* not allowed in pure match run */
  NETVM_OC_PRBIN,       /* [v] print v in binary --  val == min string width */
  NETVM_OC_PROCT,       /* [v] print v in octal  --  val == min string width */
  NETVM_OC_PRDEC,       /* [v|S] print v in decimal --  val == min str width */
  NETVM_OC_PRHEX,       /* [v] print v in hex --  val == min string width */
  NETVM_OC_PRIP,        /* [v] print IP address (network byte order) */
  NETVM_OC_PRETH,       /* [v] print ethernet address (network byte order) */
  NETVM_OC_PRIPV6,      /* [vhi,vlo] print IPv6 address (network byte order) */
  NETVM_OC_PRSTR,       /* [addr,len|I] print len bytes from addr in mem */
  NETVM_OC_STPKT,       /* [v,hdesc|IWH] store into packet memory */
  NETVM_OC_STCLASS,     /* [v,pktnum|I] store into packet class */
  NETVM_OC_STTS,        /* [v,pktnum|I] store into timestamp */
  NETVM_OC_PKTNEW,      /* [hdesc|I] create packet: offset==len, htype==dl */
  NETVM_OC_PKTCOPY,     /* [pktnum1,pktnum2|I] copy packet */
  NETVM_OC_HDRPUSH,     /* [hdesc|I] create header of htype in packet pktnum */
  NETVM_OC_HDRPOP,      /* [pktnum|I] pop the top header off of packet pktnum */
  NETVM_OC_FIXLEN,      /* [ptknum|I] fix length fields in the packet */
  NETVM_OC_FIXCKSUM,    /* [ptknum|I] fix checksum fields in the packet */
  NETVM_OC_PKTINS,      /* [len,hdesc|I] insert len bytes at hd.offset */
  NETVM_OC_PKTCUT,      /* [len,hdesc|I] cut len bytes at hd.offset */
  NETVM_OC_HDRADJ,      /* [amt,hdesc|I] adjust offset field by amt (signed) */

  NETVM_OC_MAX = NETVM_OC_HDRADJ
};

enum {
  NETVM_IF_IMMED =     0x01, /* last op is immediate rather than on stack */ 
  NETVM_IF_SIGNED =    0x02, /* number, value or all operands are signed */
  NETVM_IF_TONET =     0x04, /* for store operations */
  NETVM_IF_TOHOST =    0x08, /* for load operation s*/
  NETVM_IF_IPHLEN =    0x10, /* on 1 byte packet load instructions */
  NETVM_IF_TCPHLEN =   0x20, /* on 1 byte packet load instructions */
  NETVM_IF_MOVEUP =    0x40, /* only used HDRINS and HDRCUT */
};

enum {
  NETVM_HDR_HOFF,
  NETVM_HDR_POFF,
  NETVM_HDR_TOFF,
  NETVM_HDR_EOFF,
  NETVM_HDR_HLEN,
  NETVM_HDR_PLEN,
  NETVM_HDR_TLEN,
  NETVM_HDR_LEN,
  NETVM_HDR_ERR,
  NETVM_HDR_TYPE
};

#define NETVM_HDRFLDOK(f) ((f) <= NETVM_HDR_TYPE)
#define NETVM_ISHDROFF(f) ((f) <= NETVM_HDR_EOFF)

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

#define NETVM_HDLAYER   255   /* find header of type NETVM_HDI_* */
/* 
 * When htype == NETVM_HDLAYER, the header referred to is one of the layer
 * pointers stored in netvmpkt.  This allows quick access to the network, 
 * data link, transport, and tunnel headers.  It also allows them to be accessed
 * by layer. (e.g. transport).  In this case the idx field tells which layer.
 */

struct netvm_hdr_desc {
  uint8_t               pktnum;     /* which packet entry */
  uint8_t               htype;      /* PPT_*;  PPT_NONE == absolute idx */
  uint8_t               idx;        /* 0 == 1st hdr, 1 == 2nd hdr,... */
  uint8_t               field;      /* NETVM_HDR_* */
  uint32_t              offset;     /* offset into packet */
};

struct netvm_inst {
  uint8_t               opcode; /* NETVM_OC_* */
  uint8_t               width;  /* 1, 2, 4 or 8 for most operations */
  uint16_t              flags;  /* NETVM_IF_* */
  uint64_t              val;    /* Varies with instruction */
};

#define NETVM_MAXPKTS   16
struct netvm {
  struct netvm_inst *   inst;
  uint32_t              ninst;
  uint32_t              pc;

  uint64_t *            stack;
  uint32_t              stksz;
  uint32_t              sp;

  byte_t *              mem;
  uint32_t              memsz;
  uint32_t              rosegoff;

  struct emitter *      outport;
  struct netvmpkt *     packets[NETVM_MAXPKTS];
  int                   matchonly;
  int                   running;
  int                   error;
};


/* mem may be NULL and memsz 0.  roseg must be <= memsz.  stack must not be */
/* 0 and ssz is the number of stack elements.  outport may be NULL */
void netvm_init(struct netvm *vm, uint64_t *stack, uint32_t ssz,
                byte_t *mem, uint32_t memsz, uint32_t roseg, 
                struct emitter *outport);

/* set the instruction code and validate the vm: 0 on success, -1 on error */
int netvm_setcode(struct netvm *vm, struct netvm_inst *inst, uint32_t ni);

/* validate a netvm is properly set up and that all branches are correct */
/* called by set_netvm_code implicitly:  returns 0 on success, -1 on error */
int netvm_validate(struct netvm *vm);

/* clear memory, set pc <- 0, set sp <- 0, discard packets */
void netvm_reset(struct netvm *vm);

/* will free existing packets if they are slotted.  Note this gives up */
/* control of the packet.  netvm_clrpkt() or netvm_reset() or other native */
/* netvm instructions will free it.  Make a copy if this isn't desired or */
/* be careful of the program that you run and call clrpkt with the don't free */
/* flag set before calling netvm_reset() */
void netvm_loadpkt(struct netvm *vm, struct pktbuf *p, int slot);

/* free the packet in a slot:  note this destroys existin packet buffer */
/* unless keeppktbuf is set */
struct pktbuf *netvm_clrpkt(struct netvm *vm, int slot, int keeppktbuf);

/* 0 if run ok and no retval, 1 if run ok and stack not empty, -1 if err, -2 */
/* if out of cycles */
int netvm_run(struct netvm *vm, int maxcycles, uint64_t *rv);

#endif /* __netvm_h */
