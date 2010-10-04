#ifndef __netvm_h
#define __netvm_h
#include "tcpip_hdrs.h"
#include "stdpp.h"
#include "pktbuf.h"

struct netvm;			/* forward declaration */
typedef void (*netvm_op) (struct netvm * vm);


/* 
 * W -> uses width field to determine now many bytes to manipulate
 * I -> Immediate flag honored for last argument
 * S -> will sign extend on load if sign extention flag set
 * A -> byte swap multi-byte values before loading/storing
 * T -> with 1-byte load will treat as TCP offset and convert to byte length 
 * P -> with 1-byte load will treat as IP header len and convert to byte length 
 * M -> MOVEUP flag used for INS and CUT operations
 * V -> Uses the "val" field of the instruction regardless (i.e. without
 *      concern for the NETVM_IF_IMMED flag)
 * R -> Load offset from read-only segment offset
 * B -> Offsets are from base pointer upwards, not stack pointer downwards
 * -B -> Offsets are from base pointer downwards
 *
 * Field types:
 * v, v1, v2 - a generic numeric value
 * sa - a source address in memory
 * da - a destination address in memory
 * len - a length, usually of some region in memory
 * pdesc - a header descriptor (see below)
 * pkn - an index into the packet table
 * pa - a packet address
 * rxaddr - address of regular expression in memory
 * rxlen - length of regular expression in memory
 * cp - coprocessor identifier
 */

enum {
	NETVM_OC_NOP,		/* no operation */
	NETVM_OC_POP,		/* discards top of stack */
	NETVM_OC_PUSH,		/* [|V] pushes immediate value onto stack */
	NETVM_OC_DUP,		/* [|-BBV] dups slot "val" from top of stack */
	NETVM_OC_SWAP,		/* [|BWV] swap stack pos "val" and "width" */
				/* 0-based counting from the top of the stack */
	NETVM_OC_LDMEM,		/* [addr|WISR] load from memory */
	NETVM_OC_STMEM,		/* [v,addr|WI] store to memory */
	NETVM_OC_LDPKT,		/* [pdesc|IWSATP] load bytes from packet */
	NETVM_OC_LDPEXST,	/* [pkn|I] push true if pkn exists */
	NETVM_OC_LDPRPF,	/* [pdesc|I] load field from proto parse */
	NETVM_OC_BULKM2M,	/* [sa,da,len|I] move data from sa to da */
	NETVM_OC_BULKP2M,	/* [pa,da,len,pkn|I] move bytes from pa to da */
	NETVM_OC_MEMCMP,	/* [a1,a2,len|I] compare bytes in mem */
	NETVM_OC_PFXCMP,	/* [a1,a2,pfx,len|I] compare bits via prefix */
	NETVM_OC_MASKEQ,	/* [a1,a2,mka,len|I] compare bytes via mask */
	NETVM_OC_NOT,		/* [v] logcal not (1 or 0) */
	NETVM_OC_INVERT,	/* [v] bit-wise inversion */
	NETVM_OC_TOBOOL,	/* [v] if v != 0, 1, otherwise 0 */
	NETVM_OC_POPL,		/* [v|W] # of bits in v for lower W bytes */
	NETVM_OC_NLZ,		/* [v|W] # leading 0s in v for lower W bytes */
	NETVM_OC_SIGNX,		/* [v|W] sign extend based on width */
	NETVM_OC_ADD,		/* [v1,v2|I] add v1 and v2 */
	NETVM_OC_SUB,		/* [v1,v2|I] subtract v2 from v1 */
	NETVM_OC_MUL,		/* [v1,v2|I] multiply v1 from v2 */
	NETVM_OC_DIV,		/* [v1,v2|I] divide v1 by v2 */
	NETVM_OC_MOD,		/* [v1,v2|I] remainder of v1 / v2 */
	NETVM_OC_SHL,		/* [v1,v2|I] v1 left shifted by (v2 % 32) */
	NETVM_OC_SHR,		/* [v1,v2|I] v1 right shifted by (v2 % 32) */
	NETVM_OC_SHRA,		/* [v1,v2|I] v1 right arith shift by (v2 %32) */
	NETVM_OC_AND,		/* [v1,v2|I] bitwise v1 and v2 */
	NETVM_OC_OR,		/* [v1,v2|I] bitwise v1 or v2 */
	NETVM_OC_XOR,		/* [v1,v2|I] bitwise v1 exclusive or v2 */
	NETVM_OC_EQ,		/* [v1,v2|I] v1 equals v2 */
	NETVM_OC_NEQ,		/* [v1,v2|I] v1 not equal to v2 */
	NETVM_OC_LT,		/* [v1,v2|I] v1 < v2 */
	NETVM_OC_LE,		/* [v1,v2|I] v1 <= v2 */
	NETVM_OC_GT,		/* [v1,v2|I] v1 > v2 */
	NETVM_OC_GE,		/* [v1,v2|I] v1 >= v2 */
	NETVM_OC_SLT,		/* [v1,v2|I] v1 < v2 (signed) */
	NETVM_OC_SLE,		/* [v1,v2|I] v1 <= v2 (signed) */
	NETVM_OC_SGT,		/* [v1,v2|I] v1 > v2 (signed) */
	NETVM_OC_SGE,		/* [v1,v2|I] v1 >= v2 (signed) */
	NETVM_OC_HASPRP,	/* [pdesc|I] true if has prp (field ignored) */
	NETVM_OC_GETCPT,	/* [cp|I] push the type of co-processor 'cp' */
				/*    push NETVM_CPT_NONE if it doesn't exist */
	NETVM_OC_CPOP,		/* [cp params,cp|I] call a coprocessor op. */
				/*   if IMMED, the cp # is taken from 'width' */
				/*   The coprocessor op # is in 'flags' >> 8 */
				/*   A cp op may be marked matchonly. */
				/*   IMMED must be set in matchonly mode. */
	NETVM_OC_HALT,		/* [|V] halt program, store 'val' in ret code */
	NETVM_OC_BR,		/* [v|I] PC += v (must be > 0 in matchonly) */
	NETVM_OC_BNZ,		/* [c,v|I] PC += v if c is non-zero (ditto) */
	NETVM_OC_BZ,		/* [c,v|I] PC += v if c is zero (ditto) */
	NETVM_OC_MAX_MATCH = NETVM_OC_BZ,

	/* not allowed in pure match run */
	NETVM_OC_JUMP,		/* [addr|I] branch to absolute address addr */
	NETVM_OC_CALL,		/* [(args..,)v,narg|I]: branch and link to v */ 
				/*   put return address narg deep in the */
				/*   stack, pushing the rest (args) up */
	NETVM_OC_RETURN,	/* [v,(rets..,)nret|I]: branch to the addr */
				/*   nret deep in the stack.  shift the */
				/*   remaining stack values down */
	NETVM_OC_STPKT,		/* [v,pdesc|IWA] store into packet memory */
	NETVM_OC_BULKM2P,	/* [pa,sa,len,pkn|I] move bytes from pa to sa */
	NETVM_OC_PKTSWAP,	/* [p1,p2|I] swap packets, if "I" p1 in width */
	NETVM_OC_PKTNEW,	/* [pdesc|I] create packet: */
	                        /*   offset == len, ptype == dl type */
	NETVM_OC_PKTCOPY,	/* [pkn2,pkn1|I]copy packet from pkn1 to pkn2 */
	NETVM_OC_PKTDEL,	/* [pkn|I] delete packet */
	NETVM_OC_SETLAYER,	/* [pdesc|I] set prp to layer 'width' */
	NETVM_OC_CLRLAYER,	/* [pkn|I] clear layer 'width' */
	NETVM_OC_PRPPUSH,	/* [pdesc|I] "push" prp of ptype in packet pkn */
				/*   to innermost header */
	NETVM_OC_PRPPOP,	/* [pkn|I] pop the top prp off of packet pkn */
	NETVM_OC_PRPUP,		/* [pdesc|I] update the fields in the prp */
	NETVM_OC_FIXDLT,	/* [pkn|I] set dltype from PPT_ of 2nd prp */
	NETVM_OC_FIXLEN,	/* [pkn|I] fix length fields in the packet */
	NETVM_OC_FIXCKSUM,	/* [pkn|I] fix checksum fields in the packet */
	NETVM_OC_PKTINS,	/* [len,pdesc|I] insert len bytes @ pd.offset */
	NETVM_OC_PKTCUT,	/* [len,pdesc|I] cut len bytes @ pd.offset */
	NETVM_OC_PRPADJ,	/* [amt,pdesc|I] adjust offset 'field' by */
	                        /*   amt (signed) bytes in prp */

	NETVM_OC_MAX = NETVM_OC_PRPADJ
/* 
* Still to consider:
*
* REGTO - queue an instruction address on a timer list with one argument
*         and issue a CALL when the timer expires.  2 types of timers:
*         real-time and instruction tick?  Pushes a handle which one can
*         use to cancel the event.
* STOPTO - cancel a registered timer event
*
* CURTIME - get the current time (GMT?  Relative?)
*
* Instruction store modification? 
*/
};

enum {
	NETVM_IF_IMMED = 0x01,	/* last op is immediate rather than on stack */
	NETVM_IF_SIGNED = 0x02,	/* number, value or all operands are signed */
	NETVM_IF_SWAP = 0x04,	/* for load operation s */

	NETVM_IF_CPIMMED = 0x10,/* last op is immediate in coprocessor */
	NETVM_IF_IPHLEN = 0x10,	/* on 1 byte packet load instructions */
	NETVM_IF_TCPHLEN = 0x20,/* on 1 byte packet load instructions */
	NETVM_IF_MOVEUP = 0x40,	/* only used PRPINS and PRPCUT */
	NETVM_IF_RDONLY = 0x80,	/* load from read-only segment */

	NETVM_IF_BPOFF = 0x01,	/* DUP or SWAP offsets are from base pointer */
	NETVM_IF_NEGBPOFF = 0x02,/* DUP offsets are negative from base pointer */
};

enum {
	NETVM_PRP_HLEN,
	NETVM_PRP_PLEN,
	NETVM_PRP_TLEN,
	NETVM_PRP_LEN,
	NETVM_PRP_ERR,
	NETVM_PRP_TYPE,
	NETVM_PRP_OFF_BASE,

	NETVM_PRP_SOFF = NETVM_PRP_OFF_BASE,
	NETVM_PRP_POFF,
	NETVM_PRP_TOFF,
	NETVM_PRP_EOFF,
};

#define NETVM_ISPRPOFF(f)	((f) >= NETVM_PRP_OFF_BASE)

/* 
 * If immed is not set for a load/store instruction then the address to load
 * from or store to is on top of the stack.  Store operations always take their
 * values from the stack as well.  (but not PUSH operations)
 *
 * Header descriptors have 2 forms.
 * Packed:
 * 	packet number = 0;
 * 	prp index = 0
 * 	16 bits - ppt
 * 	4 bits - field
 * 	12 bits - offset 
 * 
 * Full:
 * 	(top of stack)
 * 	PPT: 16  pkt number:4  prp index:4  field:8
 * 	offset:32
 *
 * When no flags are set the pdesc comes on top of the stack and the offset 
 * follows.  When IMMED is set, the pdesc is in packed form encoded in the 
 * instruction.  Otherwise the parse descriptor is on the stack in "full" form:
 */

#define NETVM_IPD_PPT_OFF	0
#define NETVM_IPD_PPT_LEN	16
#define NETVM_IPD_PPT_MASK	0xffff
#define NETVM_IPD_FLD_OFF	16
#define NETVM_IPD_FLD_LEN	4
#define NETVM_IPD_FLD_MASK	0xf
#define NETVM_IPD_OFF_OFF	20
#define NETVM_IPD_OFF_LEN	12
#define NETVM_IPD_OFF_MASK	0xfff

#define NETVM_IPDESC(ppt, fld, off) \
  ((((uint32_t)(ppt) & NETVM_IPD_PPT_MASK) << NETVM_IPD_PPT_OFF)|\
   (((uint32_t)(fld) & NETVM_IPD_FLD_MASK) << NETVM_IPD_FLD_OFF)|\
   (((uint32_t)(off) & NETVM_IPD_OFF_MASK) << NETVM_IPD_OFF_OFF))

#define NETVM_PD_PPT_OFF	0
#define NETVM_PD_PPT_LEN	16
#define NETVM_PD_PPT_MASK	0xffff
#define NETVM_PD_PKT_OFF	16
#define NETVM_PD_PKT_LEN	4
#define NETVM_PD_PKT_MASK	0xf
#define NETVM_PD_IDX_OFF	20
#define NETVM_PD_IDX_LEN	4
#define NETVM_PD_IDX_MASK	0xf
#define NETVM_PD_FLD_OFF	24
#define NETVM_PD_FLD_LEN	8
#define NETVM_PD_FLD_MASK	0xff
#define NETVM_PDESC(pkt, ppt, idx, fld) \
  ((((uint32_t)(pkt) & NETVM_PD_PKT_MASK) << NETVM_PD_PKT_OFF)|\
   (((uint32_t)(ppt) & NETVM_PD_PPT_MASK) << NETVM_PD_PPT_OFF)|\
   (((uint32_t)(idx) & NETVM_PD_IDX_MASK) << NETVM_PD_IDX_OFF)|\
   (((uint32_t)(fld) & NETVM_PD_FLD_MASK) << NETVM_PD_FLD_OFF))

#define NETVM_PRP_LAYER   255	/* find header of type MPKT_LAYER_* */
/* 
 * When ptype == NETVM_PRP_LAYER, the header referred to is one of the layer
 * pointers stored in pktbuf.  This allows quick access to the network, 
 * data link, transport, and tunnel headers.  It also allows them to be accessed
 * by layer. (e.g. transport).  In this case the idx field tells which layer.
 */

struct netvm_prp_desc {
	uint8_t pktnum;		/* which packet entry */
	uint8_t idx;		/* 0 == 1st prp, 1 == 2nd prp,... */
	uint8_t field;		/* NETVM_PRP_* or prp field id */
	uint16_t ptype;		/* PPT_*;  PPT_NONE == absolute idx */
	uint32_t offset;	/* offset into packet for LD/STPKT */
	/* or proto field index for PRFLD */
};

struct netvm_inst {
	uint8_t opcode;		/* NETVM_OC_* */
	uint8_t width;		/* 1, 2, 4 or 8 for most operations */
	uint16_t flags;		/* NETVM_IF_* */
	uint32_t val;		/* Varies with instruction */
};

/* 
   For coprocessor instructions: 
    - width = co-processor ID
    - flags >> 8 = co-processor function ID
    - flags & NETVM_IF_CPIMMED means IMMED for coprocessor fields (val)
 */
#define NETVM_CPOP(cpop) (((uint16_t)cpop) << 8)

#define NETVM_JA(v)     ((uint32_t)(v)-1)
#define NETVM_BRF(v)    ((uint32_t)(v)-1)
#define NETVM_BRB(v)    ((uint32_t)0-(v)-1)

#ifndef NETVM_MAXPKTS
#define NETVM_MAXPKTS   16
#endif /* NETVM_MAXPKTS */


struct netvm_coproc;
/*
 * A coprocessor operation has the following characteristics.
 *  - width = co-processor ID
 *  - flags >> 8 = co-processor opcode #
 *  - flags & NETVM_IF_CPIMMED means IMMED for coprocessor fields (val)
 */
typedef void (*netvm_cpop)(struct netvm *vm, struct netvm_coproc *cpc, int cpi);

/*
 * Methods:
 *  - regi -> Operations to initialize the coprocessor when first registered
 *            with the vm.  Perform any resource allocations here 
 *  - reset -> Operations to run when the VM is resetting
 *  - validate -> Called to validate a coprocessor instruction.  Keep in mind
 *            that the VM can be queried including its 'matchonly' state,
 *            so instructions that should be matchonly should be rejected here.
 *
 */
struct netvm_coproc {
	uint32_t type;
	uint numops;
	netvm_cpop *ops;
	int (*regi)(struct netvm_coproc * coproc, struct netvm * vm, int cpi);
	void (*reset)(struct netvm_coproc * coproc);
	int (*validate)(struct netvm_inst * inst, struct netvm * vm);
};

#ifndef NETVM_MAXCOPROC
#define NETVM_MAXCOPROC 8
#endif /* NETVM_MAXCOPROC */

#define NETVM_CPT_NONE  ((uint32_t)0)

struct netvm {
	struct netvm_inst *inst;
	uint32_t ninst;
	uint32_t pc;

	uint32_t *stack;
	uint32_t stksz;
	uint32_t sp;
	uint32_t bp;

	byte_t *mem;
	uint32_t memsz;
	uint32_t rosegoff;

	struct pktbuf *packets[NETVM_MAXPKTS];

	struct netvm_coproc *coprocs[NETVM_MAXCOPROC];

	int matchonly;
	int running;
	int error;
};


enum {
	/* Validation error */
	NETVM_ERR_UNINIT = -1,
	NETVM_ERR_BADOP = -2,
	NETVM_ERR_BRADDR = -3,
	NETVM_ERR_BRMONLY = -4,
	NETVM_ERR_BADLAYER = -5,
	NETVM_ERR_BADWIDTH = -6,
	NETVM_ERR_BADCP = -7,
	NETVM_ERR_MIN = NETVM_ERR_BADCP,

	/* runtime errors */
	NETVM_ERR_UNIMPL = 1,
	NETVM_ERR_STKOVFL,
	NETVM_ERR_STKUNDF,
	NETVM_ERR_WIDTH,
	NETVM_ERR_INSTADDR,
	NETVM_ERR_MEMADDR,
	NETVM_ERR_PKTADDR,
	NETVM_ERR_MRDONLY,
	NETVM_ERR_PKTNUM,
	NETVM_ERR_NOPKT,
	NETVM_ERR_NOPRP,
	NETVM_ERR_NOPRPFLD,
	NETVM_ERR_PDESC,	/* TODO: make sure this gets used */
	NETVM_ERR_PRPIDX,
	NETVM_ERR_PRPFLD,
	NETVM_ERR_LAYER,
	NETVM_ERR_FIXLEN,
	NETVM_ERR_CKSUM,
	NETVM_ERR_PKTINS,
	NETVM_ERR_PKTCUT,
	NETVM_ERR_PRPADJ,
	NETVM_ERR_NOMEM,
	NETVM_ERR_IOVFL,
	NETVM_ERR_BADCOPROC,
	NETVM_ERR_BADCPOP,
	NETVM_ERR_MAX = NETVM_ERR_BADCPOP,
};


/* mem may be NULL and memsz 0.  roseg must be <= memsz.  stack must not be */
/* 0 and ssz is the number of stack elements.  outport may be NULL */
void netvm_init(struct netvm *vm, uint32_t * stack, uint32_t ssz,
		byte_t * mem, uint32_t memsz);

/* set the instruction code and validate the vm: 0 on success, -1 on error */
int netvm_setcode(struct netvm *vm, struct netvm_inst *inst, uint32_t ni);

/* set the offset of the read-only segment for the VM */
int netvm_setrooff(struct netvm *vm, uint32_t rooff);

/* set a coprocessor: return the cpi or -1 if initialization error */
int netvm_set_coproc(struct netvm *vm, int cpi, struct netvm_coproc *coproc);

/* validate a netvm is properly set up and that all branches are correct */
/* called by set_netvm_code implicitly:  returns 0 on success, -1 on error */
int netvm_validate(struct netvm *vm);

/* zero out non-read-only memory */
void netvm_clrmem(struct netvm *vm);

/* free all packets */
void netvm_clrpkts(struct netvm *vm);

/* reset co-processors */
void netvm_reset_coprocs(struct netvm *vm);

/* pc <- 0, sp <- 0 */
void netvm_restart(struct netvm *vm);

/* clear memory, set pc <- 0, set sp <- 0, discard packets */
void netvm_reset(struct netvm *vm);

/* set matchonly */
void netvm_set_matchonly(struct netvm *vm, int matchonly);

/* will free existing packets if they are slotted.  Note this gives up */
/* control of the packet.  netvm_clrpkt() or netvm_reset() or other native */
/* netvm instructions will free it.  Make a copy if this isn't desired or */
/* be careful of the program that you run and call clrpkt with the don't free */
/* flag set before calling netvm_reset() */
int netvm_loadpkt(struct netvm *vm, struct pktbuf *p, int slot);

/* free the packet in a slot:  note this destroys existin packet buffer */
/* unless keeppktbuf is set */
struct pktbuf *netvm_clrpkt(struct netvm *vm, int slot, int keeppktbuf);

/* 0 if run ok and no retval, 1 if run ok and stack not empty, -1 if err, -2 */
/* if out of cycles */
int netvm_run(struct netvm *vm, int maxcycles, uint32_t * rv);

/* returns the error string corresponding to the netvm error */
const char *netvm_estr(int error);


#endif /* __netvm_h */
