#ifndef __netvm_h
#define __netvm_h
#include "tcpip_hdrs.h"
#include "stdproto.h"
#include "pktbuf.h"

struct netvm;			/* forward declaration */
typedef void (*netvm_op) (struct netvm * vm);


struct netvm_inst {
	uint8_t			op;	/* NETVM_OC_* */
	uint8_t			x;
	uint8_t			y;
	uint8_t			z;
	uint32_t		w;	/* Varies with instruction */
};

/* 
   For coprocessor instructions: 
    - x = co-processor ID
    - y = co-processor function ID
 */
#define NETVM_JA(v)     ((uint32_t)(v)-1)
#define NETVM_BRF(v)    ((uint32_t)(v)-1)
#define NETVM_BRB(v)    ((uint32_t)0-(v)-1)

/* 
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

#define	NETVM_SEG_RWMEM		0
#define	NETVM_SEG_ROMEM		1
#define	NETVM_SEG_PKT0		128

enum {
	NETVM_OC_NOP,		/* no operation */
	NETVM_OC_POP,		/* discards top of stack */
	NETVM_OC_PUSH,		/* pushes 'w' onto stack */
	NETVM_OC_DUP,		/* dups 'w' from the top of the stack */
	NETVM_OC_DUPBP,		/* dups 'w' from above the BP if x == 0 */
				/* dups 'w' from below the BP if x != 0 */
	NETVM_OC_SWAP,		/* swap stack pos 'x' and 'w' from SP down */
	NETVM_OC_SWAPBP,	/* swap stack pos 'x' and 'w' from BP up */
	NETVM_OC_LDM,		/* [addr] load abs(x) bytes from mem seg y */
	NETVM_OC_LDMI,		/* load abs(x) bytes from mem seg y @ addr w */
	NETVM_OC_LDP,		/* [pdesc] load from packet (pdesc on stack) */
	NETVM_OC_LDPI,		/* load from packet (use packed pdesc format) */
	NETVM_OC_PFE,		/* [pdesc] push 1 if field exists 0 otherwise */
	NETVM_OC_PFEI		/* same as PFE but use packed pdesc */
	NETVM_OC_LDPF,		/* [pdesc] load field from proto parse */
	NETVM_OC_LDPFI,		/* load field from proto parse (packed pdesc) */

				/* For the following 3 operations, and for */
				/* MOVE below:  x = a1 seg, y = a2 seg, */
				/* and z = mask seg (MSKCMP only) */
	NETVM_OC_CMP,		/* [a1,a2,len] compare bytes in mem */
	NETVM_OC_PCMP,		/* [a1,a2,pfx,len] compare bits via prefix */
	NETVM_OC_MSKCMP,	/* [a1,a2,mka,len] compare bytes via mask */

	NETVM_OC_NOT,		/* [v] logcal not (1 or 0) */
	NETVM_OC_INVERT,	/* [v] bit-wise inversion */
	NETVM_OC_TOBOOL,	/* [v] if v != 0, 1, otherwise 0 */
	NETVM_OC_POPL,		/* [v|W] # of bits in v for lower W bytes */
	NETVM_OC_NLZ,		/* [v|W] # leading 0s in v for lower W bytes */
	NETVM_OC_SIGNX,		/* [v|W] sign extend based on width */

	NETVM_OC_ADD,		/* [v1,v2] add v1 and v2 */
	NETVM_OC_ADDI,		/* [v] add v1 and w */
	NETVM_OC_SUB,		/* [v1,v2] subtract v2 from v1 */
	NETVM_OC_SUBI,		/* [v] subtract w from v */
	NETVM_OC_MUL,		/* [v1,v2] multiply v1 by v2 */
	NETVM_OC_MULI,		/* [v] multiply v by w */
	NETVM_OC_DIV,		/* [v1,v2] divide v1 by v2 */
	NETVM_OC_DIVI,		/* [v] divide v by w */
	NETVM_OC_MOD,		/* [v1,v2] remainder of v1 / v2 */
	NETVM_OC_MODI,		/* [v] remainder of v / w */
	NETVM_OC_SHL,		/* [v1,v2] v1 left shifted by (v2 % 32) */
	NETVM_OC_SHLI,		/* [v] v left shifted by (w % 32) */
	NETVM_OC_SHR,		/* [v1,v2] v1 right shifted by (v2 % 32) */
	NETVM_OC_SHRI,		/* [v] v1 right shifted by (w % 32) */
	NETVM_OC_SHRA,		/* [v1,v2] v1 right arith shift by (v2 % 32) */
	NETVM_OC_SHRAI,		/* [v] v1 right arith shift by (w % 32) */
	NETVM_OC_AND,		/* [v1,v2] bitwise v1 and v2 */
	NETVM_OC_ANDI,		/* [v] bitwise v and w */
	NETVM_OC_OR,		/* [v1,v2] bitwise v1 or v2 */
	NETVM_OC_ORI,		/* [v] bitwise v1 or v2 */
	NETVM_OC_XOR,		/* [v1,v2] bitwise v1 exclusive or v2 */
	NETVM_OC_XORI,		/* [v] bitwise v1 exclusive or w */
	NETVM_OC_EQ,		/* [v1,v2] v1 equals v2 */
	NETVM_OC_EQI,		/* [v] v1 equals w */
	NETVM_OC_NEQ,		/* [v1,v2] v1 not equal to v2 */
	NETVM_OC_NEQI,		/* [v] v1 not equal to w */
	NETVM_OC_LT,		/* [v1,v2] v1 less than v2 */
	NETVM_OC_LTI,		/* [v] v1 less than w */
	NETVM_OC_LE,		/* [v1,v2] v1 less than or equal to v2 */
	NETVM_OC_LEI,		/* [v] v1 less than or equal to w */
	NETVM_OC_GT,		/* [v1,v2] v1 greater than v2 */
	NETVM_OC_GTI,		/* [v] v1 greater than w */
	NETVM_OC_GE,		/* [v1,v2] v1 greater than or equal to v2 */
	NETVM_OC_GEI,		/* [v] v1 greater than or equal to w */
	NETVM_OC_SLT,		/* [v1,v2] v1 signed less than v2 */
	NETVM_OC_SLTI,		/* [v] v1 signed less than w */
	NETVM_OC_SLE,		/* [v1,v2] v1 signed less than or equal to v2 */
	NETVM_OC_SLEI,		/* [v] v1 signed less than or equal to w */
	NETVM_OC_SGT,		/* [v1,v2] v1 signed greater than v2 */
	NETVM_OC_SGTI,		/* [v] v1 signed greater than w */
	NETVM_OC_SGE,		/* [v1,v2] v1 signed greater than|equal to v2 */
	NETVM_OC_SGEI,		/* [v] v1 signed greater than or equal to w */

	NETVM_OC_GETCPT,	/* [cp] push the type of co-processor 'cp' */
				/*    push NETVM_CPT_NONE if it doesn't exist */
	NETVM_OC_CPOPI,		/* [cp params] call coprocessor x w/op y. */

	NETVM_OC_HALT,		/* halt program, store 'w' in ret code */
	NETVM_OC_BRI,		/* PC += w (must be > 0 in matchonly) */
	NETVM_OC_BNZI,		/* [c] PC += v if c is non-zero (ditto) */
	NETVM_OC_BZI,		/* [c] PC += v if c is zero (ditto) */
	NETVM_OC_JMPI,		/* branch to absolute address w */
	NETVM_OC_MAX_MATCH = NETVM_OC_JMPI,

	/* 
	 * The following instructions are not allowed in pure match run.
	 * There are possible 3 reasons for this:
	 *  1) We cannot validate that the program will terminate in 
	 *     # cycles <= # of instructions with these operations.
	 *  2) These operations could modify memory or the packets. 
	 *  3) We cannot verify the coprocessor operation statically as
	 *     the operation gets selected at runtime.
	 */

	NETVM_OC_CPOP,		/* [cp params, cpop, cpi] call coprocessor */
				/*   'cpi' with operation 'cpop'. */
	NETVM_OC_BR,		/* [v] PC += v */
	NETVM_OC_BNZ,		/* [c,v] PC += v if c is non-zero */
	NETVM_OC_BZ,		/* [c,v] PC += v if c is zero */
	NETVM_OC_JMP,		/* [addr] branch to absolute address addr */

	NETVM_OC_CALL,		/* [(args..,)v]: branch and link to v */ 
				/*   put return address 'w' deep in the */
				/*   stack, pushing the rest (args) up */
	NETVM_OC_RET,		/* [v,(rets..,)]: branch to the addr */
				/*   'w' deep in the stack.  shift the */
				/*   remaining stack values down */

	NETVM_OC_STM,		/* [v,addr] store x bytes of v to addr seg y */
	NETVM_OC_STMI,		/* [v] store x bytes of v to w seg y */
	NETVM_OC_STP,		/* [v,pdesc] store x bytes of v to pdesc */
	NETVM_OC_STPI,		/* [v] store x bytes of v into pdesc */

	NETVM_OC_MOVE,		/* [sa,da,len] move len bytes from sa to da */

	NETVM_OC_PKSWAP,	/* [p1,p2] swap packets p1 and p2  */
	NETVM_OC_PKNEW,		/* [pdesc] create packet: */
	                        /*   offset == len, ptype == dl type */
	NETVM_OC_PKCOPY,	/* [pkn2,pkn1] copy packet from pkn1 to pkn2 */
	NETVM_OC_PKSLA,		/* [pdesc] set layer 'x' to prp in pdesc */
	NETVM_OC_PKCLA,		/* [pkn] clear layer 'x' */
	NETVM_OC_PKPPSH,	/* [pdesc] "push" prp of ptype in packet pkn */
				/*   to inner header if !x or outer if x */
	NETVM_OC_PKPPOP,	/* [pkn] pop the top prp off of packet pkn */

	NETVM_OC_PKDEL,		/* [pkn] delete packet */
	NETVM_OC_PKDELI,	/* delete packet 'x' */
	NETVM_OC_PKFXD,		/* [pkn] set dltype from PPT_ of 2nd prp */
	NETVM_OC_PKFXDI,	/* set dltype of pkt 'x' from PPT_ of 2nd prp */
	NETVM_OC_PKPUP,		/* [pdesc] update parse fields (packed pdesc) */
	NETVM_OC_PKPUPI,	/* update the parse fields (stack pdesc) */
	NETVM_OC_PKFL,		/* [pdesc] fix length fields in the packet */
				/*   If pdesc refers to the base parse, fix */
				/*   all lengths that are in a layer */
	NETVM_OC_PKFLI,		/* fix length fields in packet (packed pdesc) */
	NETVM_OC_PKFC,		/* [pdesc] fix checksum fields in the packet */
				/*   If pdesc refers to the base parse, fix */
				/*   all checksums that are in a layer */
	NETVM_OC_PKFCI,		/* fix checksums in the packet (packed pdesc) */

	NETVM_OC_PKINS,		/* [len,pdesc] insert len bytes @ pd.offset */
				/*   move new bytes down if x or up if !x */
	NETVM_OC_PKCUT,		/* [len,pdesc] cut len bytes @ pd.offset */
				/*   move new bytes down if x or up if !x */
	NETVM_OC_PKADJ,		/* [amt,pdesc] adjust offset 'field' by */
	                        /*   amt (signed) bytes in parse */

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


/* 
 * Protocol descirptors take two forms
 * Packed (in the instruction):
 *      x = packet number
 * 	y = prp index
 * 	z = prp field
 *	w = (ppt * 65536) + offset; (offset <= 65535)
 * 
 * Full (on the stack):
 *      offset:32
 *      PPT: 16  pkt number:4  prp index:4  field:8
 *
 * When no flags are set the pdesc comes on top of the stack and the offset 
 * follows.  When IMMED is set, the pdesc is in packed form encoded in the 
 * instruction.  Otherwise the parse descriptor is on the stack in "full" form:
 */

#define NETVM_STK_PDESC(pkt, ppt, idx, fld, off) \
	(pkt), (idx), (fld), (((ppt) << 16) | ((off) & 0xFFFF))

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
	uint8_t			pktnum;	/* which packet entry */
	uint8_t			idx;	/* 0 == 1st prp, 1 == 2nd prp,... */
	uint8_t			field;	/* NETVM_PRP_* or prp field id */
	uint16_t		ptype;	/* PPT_*;  PPT_NONE == absolute idx */
	uint32_t		offset;	/* offset into packet for LD/STPKT */
					/* or proto field index for PRFLD */
};


/* Packet parse field indices */
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


struct netvm_coproc;
/*
 * A coprocessor operation has the following characteristics.
 *  - x = co-processor ID
 *  - y = co-processor opcode #
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
	uint32_t		type;
	uint			numops;
	netvm_cpop *		ops;

	int			(*regi)(struct netvm_coproc * coproc, 
			        	struct netvm * vm, int cpi);

	void			(*reset)(struct netvm_coproc * coproc);

	int			(*validate)(struct netvm_inst * inst,
					    struct netvm * vm);
};


#define NETVM_CPT_NONE		((uint32_t)0)
#define NETVM_MAXCOPROC		8
#define NETVM_MAXPKTS   	16

struct netvm {
	struct netvm_inst *	inst;
	uint32_t		ninst;
	uint32_t		pc;

	uint32_t *		stack;
	uint32_t		stksz;
	uint32_t		sp;
	uint32_t		bp;

	byte_t *		mem;
	uint32_t		memsz;
	uint32_t		rosegoff;

	struct pktbuf *		packets[NETVM_MAXPKTS];

	struct netvm_coproc *	coprocs[NETVM_MAXCOPROC];

	int			matchonly;
	int			running;
	int			error;
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
