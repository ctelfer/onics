/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * netvm.h -- NetVM external API and core data structures.
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __netvm_h
#define __netvm_h
#include "tcpip_hdrs.h"
#include "prid.h"
#include "pktbuf.h"

struct netvm;			/* forward declaration */
typedef void (*netvm_op)(struct netvm * vm);


struct netvm_inst {
	uchar			op;	/* NETVM_OC_* */
	uchar			x;
	uchar			y;
	uchar			z;
	ulong			w;	/* Varies with instruction */
};


/*
 * Segments
 *
 * The Netvm uses separate memory segments and regards packets as
 * being a special type of memory segment.  A memory segment is denoted
 * by an 8-bit number where the high order bit determines whether the
 * lower 7 bits index a regular memory segment or packet.  (0 means memory,
 * and 1 means packet).  NETVM_SEG_ISPKT is the bitmask to apply to
 * a segment number to test this.
 */
#define	NETVM_SEG_ISPKT		0x08
#define	NETVM_SEG_SEGMASK	0x07

/*
 * Most memory operations accept addresses in a unified address space format.
 * This format is a single 32-bit address that can refer to any memory 
 * segment or packet buffer.  The format is:
 *
 * MSB                      LSB
 *  [seg desc: 4  address: 28]
 * 
 * The segment descriptor is a memory segment index with the NETVM_SEG_ISPKT
 * bit (bit 3 in the 4-bit address) cleared or a packet number with the
 * NETVM_SEG_ISPKT bit set.
 */

#define NETVM_UA_ISPKT_OFF	31
#define NETVM_UA_SEG_OFF	28
#define NETVM_UA_OFF_MASK	(0x0FFFFFFFul)
#define NETVM_UA_SEG_MASK	(0xFul)
#define NETVM_UA_ISPKT(addr)	(((addr) & 0x80000000ul) != 0)
#define NETVM_UADDR(ispkt, idx, addr) \
	(((ulong)(ispkt) & 1) << 31 | ((ulong)(idx) & 0x7) << 28 | \
	 ((addr) & 0x0FFFFFFF))


/* 
 * Some instructions require metadata about a packet and/or it's
 * parse fields.  Such instructions take a protocol descriptor either
 * from the stack or from the instruction itself.  Instructions
 * specify which form they expect.
 *
 * Instruction protocol descriptor form:
 *      y = packet number
 * 	z = prp index:4 prp field:4
 *	w = (prid * 65536) + offset
 *
 * Offset is unsigned and < 2**16.  Also, only the lower 3 bits of the
 * packet number are considered as the NETVM_SEG_ISPKT bit may be set
 * when the 'y' field is used to differentiate between packet and memory
 * segments for LD/ST operations.  (see below)
 * 
 * Stack protocol descriptor form.  It takes two words:
 *
 * Top of stack:
 *     MSB                                        LSB
 *      PRID: 16      prp index:8           field:8  
 *      pkt/seg:4                         offset:28
 * Bottom of stack:
 *
 * Stack offset is 32-bit 2s compliment signed integer.
 */

#define NETVM_PPD_PKT_MASK	0xF
#define NETVM_PPD_IDX_OFF	4
#define NETVM_PPD_IDX_MASK	0xF
#define NETVM_PPD_FLD_OFF	0
#define NETVM_PPD_FLD_MASK	0xF
#define NETVM_PPD_PRID_OFF	16
#define NETVM_PPD_PRID_MASK	0xFFFF
#define NETVM_PPD_OFF_OFF	0
#define NETVM_PPD_OFF_MASK	0xFFFF

#define NETVM_OP_PDESC(pkt, prid, idx, fld, off)  \
	(((pkt) & 0x7) | NETVM_SEG_ISPKT), \
	(((idx)& 0xF)<< 4) | ((fld) & 0xF), \
	((((prid) & 0xFFFF) << 16) | ((off) & 0xFFFF))

#define NETVM_PD_OFF_OFF	0
#define NETVM_PD_OFF_LEN	28
#define NETVM_PD_OFF_MASK	0x0FFFFFFFul
#define NETVM_PD_PKT_OFF	28
#define NETVM_PD_PKT_LEN	3
#define NETVM_PD_PKT_MASK	0x7

#define NETVM_PD_PRID_OFF	16
#define NETVM_PD_PRID_LEN	16
#define NETVM_PD_PRID_MASK	0xffff
#define NETVM_PD_IDX_OFF	8
#define NETVM_PD_IDX_LEN	8
#define NETVM_PD_IDX_MASK	0xff
#define NETVM_PD_FLD_OFF	0
#define NETVM_PD_FLD_LEN	8
#define NETVM_PD_FLD_MASK	0xff

#define NETVM_PDESC_W0(prid, idx, fld) \
  ((((ulong)(prid) & NETVM_PD_PRID_MASK) << (NETVM_PD_PRID_OFF))|\
   (((ulong)(idx) & NETVM_PD_IDX_MASK) << (NETVM_PD_IDX_OFF))   |\
   (((ulong)(fld) & NETVM_PD_FLD_MASK) << (NETVM_PD_FLD_OFF)))

#define NETVM_PDESC_W1(pkt, off) \
	(((((pkt) & NETVM_PD_PKT_MASK) | NETVM_SEG_ISPKT) << NETVM_PD_PKT_OFF)\
	 ((ulong)(off) & NETVM_PD_OFF_MASK))

struct netvm_prp_desc {
	uchar			pktnum;	/* which packet entry */
	uchar			idx;	/* 0 == 1st prp, 1 == 2nd prp,... */
	uchar			field;	/* NETVM_PRP_* or prp field id */
	uchar			pad;
	uint			prid;	/* PRID_*;  PRID_NONE == absolute idx */
	ulong			offset;	/* offset into packet for LD/STPKT */
					/* or proto field index for PRFLD */
};

#define NETVM_PRP_LAYER   255	/* find header of type MPKT_LAYER_* */
/* 
 * When ptype == NETVM_PRP_LAYER, the header referred to is one of the layer
 * pointers stored in pktbuf.  This allows quick access to the network, 
 * data link, transport, and tunnel headers.  It also allows them to be accessed
 * by layer. (e.g. transport).  In this case the idx field tells which layer.
 */

/* Packet parse field indices */
enum {
	NETVM_PRP_HLEN,		/* header length */
	NETVM_PRP_PLEN,		/* payload length */
	NETVM_PRP_TLEN,		/* trailer length */
	NETVM_PRP_LEN,		/* total length */
	NETVM_PRP_ERR,		/* error mask */
	NETVM_PRP_PRID,		/* protocol ID: usually used with pclasses */
	NETVM_PRP_PIDX,		/* protocol parse index (0 == none) */
	NETVM_PRP_OFF_BASE,

	NETVM_PRP_SOFF = NETVM_PRP_OFF_BASE,	/* parse start offset */
	NETVM_PRP_POFF,				/* parse payload offset */
	NETVM_PRP_TOFF,				/* parse trailer offset */
	NETVM_PRP_EOFF,				/* parse end offset */
};

#define NETVM_ISPRPOFF(f)	((f) >= NETVM_PRP_OFF_BASE)
#define NETVM_PF_INVALID	0xFFFFFFFF


/* 
 * NetVM co-processors extend the base instruction set with additional
 * operations.  Each coprocessor fits in a "slot" of the VM each with
 * a unique co-processor ID (CPI) starting from 0.  Each CP has up to
 * 255 operations (CPOs).  The CPI and CPO can be specified in the x,y 
 * fields of the CPOPI instruction or from the top two arguments on the
 * stack for the CPOP instruction.  Only CPOPI may be used in
 * 'matchonly' in order to ensure that only 'safe' CPOs are called.  The
 * CP's 'validate' method should ensure that CPOPI calls are 'safe' and
 * return an error if this can not be guaranteed.
 *
 * Each co-processor also has a co-processor type (CPT) which is a 64-bit ID
 * denoting function, version, etc of the co-processor.  The GETCPT
 * instruction lets the VM query the CPTs of the current VM.  So, a
 * non-matchonly VM can have dynamically discoverable operations. 
 * NETVM_CPT_NONE (i.e. 0) is a reserved value which indicates the absence
 * of a co-processor in a given CPI.
 *
 * CPOs should generally conform to the conventions of NetVM instructions.
 */
struct netvm_coproc;
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
	ulong			type;
	uint			numops;
	netvm_cpop *		ops;

	int			(*regi)(struct netvm_coproc *coproc, 
			        	struct netvm *vm, int cpi);

	void			(*reset)(struct netvm_coproc *coproc);

	int			(*validate)(struct netvm_inst *inst,
					    struct netvm *vm);
};

#define NETVM_CPT_NONE		((ulong)0)



/* NetVM definition */
#define NETVM_MAXMSEGS		4
#define NETVM_MAXPKTS   	16
#define NETVM_MAXCOPROC		8

#define NETVM_SEG_RD		1
#define NETVM_SEG_WR		2
#define NETVM_SEG_RDWR		3
#define NETVM_SEG_MO		4	/* useable in matchonly mode */
#define NETVM_SEG_PMASK		7


struct netvm_mseg {
	byte_t *		base;
	uint			len;
	uint			perms;
};


struct netvm {
	struct netvm_inst *	inst;
	uint			ninst;
	uint			pc;
	uint			nxtpc;

	ulong *			stack;
	uint			stksz;
	uint			sp;
	uint			bp;

	struct netvm_mseg	msegs[NETVM_MAXMSEGS];

	struct pktbuf *		packets[NETVM_MAXPKTS];

	struct netvm_coproc *	coprocs[NETVM_MAXCOPROC];

	int			matchonly;
	int			status;
};



/* 
 * NetVM Instruction Set
 *
 * Field types:
 * v, v1, v2 - a generic numeric value
 * len - a length, usually of some region in memory
 * pdesc - a header descriptor (see below)
 * pkn - an index into the packet table
 * rxaddr - address of regular expression in memory
 * rxlen - length of regular expression in memory
 * cp - coprocessor identifier
 * addr - an address (see above).  May refer to a packet or memory segment.
 *        (also, a1, a2, a3, amk... )
 */

/* maximum number of values for a multi-return */
#define NETVM_MAXRET	8

enum {
	NETVM_OC_POP,		/* discards top 'w' entries of stack */
	NETVM_OC_POPTO,		/* discard all but last 'w' in stack frame */
	NETVM_OC_PUSH,		/* pushes 'w' onto stack */
	NETVM_OC_ZPUSH,		/* pushes 'w' 0s onto the stack */
	NETVM_OC_DUP,		/* dups 'w' from the top of the stack */
	NETVM_OC_SWAP,		/* swap stack pos 'x' and 'w' from SP down */
	NETVM_OC_LDBP,		/* [i] load value 'i' above(below if 'x') BP */
	NETVM_OC_LDBPI,		/* as BPLD but position is taken from 'w' */
	NETVM_OC_STBP,		/* [v, i] pop top of stack and store the value */
				/*   i positions above (below if x) the BP; */
				/*   must be in the adjusted stack frame. */
	NETVM_OC_STBPI,		/* [v] as BPST but position is taken from 'w' */
	NETVM_OC_PUSHFR,	/* push current BP onto stack and set the BP */
				/*     to the new stack pointer. */
	NETVM_OC_POPFR,		/* pop the stack to the BP-1. If 'x' > 0 then */
				/*     save the top 'x' values to a max of */
				/*     NETVM_MAXRET.  If 'w' > 0, also pop */
				/*     the 'w' values below the stack frame. */

	/* 
	 * For LDPF and LDPFI, if 'x' is set then generate a unified address 
	 * by setting the packet number and ISPKT bit in the high byte.  
	 * (note: not all fields are offsets from the packet start.  use
	 * accordingly). 
	 */
	NETVM_OC_LDPF,		/* [pdesc] load field from proto parse */
	NETVM_OC_LDPFI,		/* load field from proto parse (packed pdesc) */

	/*
	 * For these 5 load operations, x must be in [1,8] or [129,136]
	 * If x is in [129,136], the result will be sign extended to 64 bits 
	 * for a value of x-128 bytes.   The same address conventions are
	 * followed on the ST, STI, STU, STPD, STPDI, instructions.
	 */
	NETVM_OC_LD,		/* [addr,len] load len(max 8) bytes from addr */
	NETVM_OC_LDLI,		/* [addr] load 'x' (max 8) bytes from addr */
	NETVM_OC_LDI,		/* load x bytes from mem seg y @ addr w */
	NETVM_OC_LDPD,		/* [pdesc] x bytes from the pkt desc location */
	NETVM_OC_LDPDI,		/* x bytes from the (packed) desc location */

	NETVM_OC_CMP,		/* [a1,a2,len] compare bytes in mem */
	NETVM_OC_PCMP,		/* [a1,a2,len] compare bits via prefix */
	NETVM_OC_MSKCMP,	/* [a1,a2,amk,len] compare bytes via mask */

	/* Arithmatic operations */
	NETVM_OC_NOT,		/* [v] logcal not (1 or 0) */
	NETVM_OC_INVERT,	/* [v] bit-wise inversion */
	NETVM_OC_POPL,		/* [v] # of bits in v for lower x bytes */
	NETVM_OC_NLZ,		/* [v] # leading 0s in v for lower x bytes */

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
	NETVM_OC_SHL,		/* [v1,v2] v1 left shifted by (v2 % 64) */
	NETVM_OC_SHLI,		/* [v] v left shifted by (w % 64) */
	NETVM_OC_SHR,		/* [v1,v2] v1 right shifted by (v2 % 64) */
	NETVM_OC_SHRI,		/* [v] v1 right shifted by (w % 64) */
	NETVM_OC_SHRA,		/* [v1,v2] v1 right arith shift by (v2 % 64) */
	NETVM_OC_SHRAI,		/* [v] v1 right arith shift by (w % 64) */
	NETVM_OC_AND,		/* [v1,v2] bitwise v1 and v2 */
	NETVM_OC_ANDI,		/* [v] bitwise v and w */
	NETVM_OC_OR,		/* [v1,v2] bitwise v1 or v2 */
	NETVM_OC_ORI,		/* [v] bitwise v1 or w */
	NETVM_OC_XOR,		/* [v1,v2] bitwise v1 exclusive or v2 */
	NETVM_OC_XORI,		/* [v] bitwise v1 exclusive or w */
	NETVM_OC_EQ,		/* [v1,v2] v1 equals v2 */
	NETVM_OC_EQI,		/* [v] v1 equals w */
	NETVM_OC_NEQ,		/* [v1,v2] v1 not equal to v2 */
	NETVM_OC_NEQI,		/* [v] v1 not equal to w */
	NETVM_OC_LT,		/* [v1,v2] v1 < v2 (signed) */
	NETVM_OC_LTI,		/* [v] v1 < w (signed) */
	NETVM_OC_LE,		/* [v1,v2] v1 <= v2 (signed) */
	NETVM_OC_LEI,		/* [v] v1 <= w (signed) */
	NETVM_OC_GT,		/* [v1,v2] v1 > v2 (signed) */
	NETVM_OC_GTI,		/* [v] v1 > w (signed) */
	NETVM_OC_GE,		/* [v1,v2] v1 >= v2 (signed) */
	NETVM_OC_GEI,		/* [v] v1 >= w (signed) */
	NETVM_OC_ULT,		/* [v1,v2] v1 < v2 (unsigned) */
	NETVM_OC_ULTI,		/* [v] v1 < w (unsigned) */
	NETVM_OC_ULE,		/* [v1,v2] v1 <= v2 (unsigned) */
	NETVM_OC_ULEI,		/* [v] v1 <= w (unsigned) */
	NETVM_OC_UGT,		/* [v1,v2] v1 > v2 (unsigned) */
	NETVM_OC_UGTI,		/* [v] v1 > w (unsigned) */
	NETVM_OC_UGE,		/* [v1,v2] v1 >= v2 (unsigned) */
	NETVM_OC_UGEI,		/* [v] v1 >= w (unsigned) */
	NETVM_OC_MIN,		/* [v1,v2] signed min(v1,v2) */
	NETVM_OC_MINI,		/* [v] signed min(v,'w') */
	NETVM_OC_MAX,		/* [v1,v2] signed max(v1,v2) */
	NETVM_OC_MAXI,		/* [v] signed max(v,'w') */
	NETVM_OC_UMIN,		/* [v1,v2] unsigned min(v1,v2) */
	NETVM_OC_UMINI,		/* [v] unsigned min(v,'w') */
	NETVM_OC_UMAX,		/* [v1,v2] unsigned max(v1,v2) */
	NETVM_OC_UMAXI,		/* [v] unsigned max(v,'w') */

	NETVM_OC_GETCPT,	/* [cp] push the type of co-processor 'cp' */
				/*    push NETVM_CPT_NONE if it doesn't exist */
	NETVM_OC_CPOPI,		/* [cp params] call coprocessor x w/op y. */

	NETVM_OC_BRI,		/* PC += (signed)w (must be > 0 in matchonly) */
	NETVM_OC_BNZI,		/* [c] PC += w if c is non-zero (ditto) */
	NETVM_OC_BZI,		/* [c] PC += w if c is zero (ditto) */
	NETVM_OC_JMPI,		/* branch to absolute address w */
	NETVM_OC_HALT,		/* halt program and put 'w' in 'status' */
	NETVM_OC_MAX_MATCH = NETVM_OC_HALT,

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
	NETVM_OC_PUSHPC,	/* pushes the pc + 'w' - 1 onto the stack */
				/* this is the value one would jump to */
				/* to start 'w' instructions after the puship */
				/* instruction. */
	NETVM_OC_JMP,		/* [addr] branch to absolute address addr */

	NETVM_OC_CALL,		/* [(args..,)v]: branch and link to v */ 
				/*   Store next PC on stack, then push */
				/*   current BP to SP, set BP to new SP */
	NETVM_OC_RET,		/* [(rets..,)]: return from call */
				/*   branch back to bp-2 addr, restoring */
				/*   bp to bp-1 value.  save the top 'x' */
				/*   vals from the stack.  pop to bp-1-'w'. */
				/*   push the saved values onto the stack. */

	NETVM_OC_ST,		/* [v,addr,len] store len(max 8) bytes of */
				/*  v to addr */
	NETVM_OC_STLI,		/* [v,addr] store x(max 8) bytes of v to addr */
	NETVM_OC_STI,		/* [v] store x bytes of v to w in seg y */
	NETVM_OC_STPD,		/* [v,pdesc] store x bytes of v at pdesc */
	NETVM_OC_STPDI,		/* [v] store x bytes of v at (packed) pdesc */

	NETVM_OC_MOVE,		/* [a1,a2,len] move len bytes from */
				/*    a1 to a2.  (note unified addresses) */

	/* packet specific operations */
	NETVM_OC_PKNEW,		/* [pkn,len] create packet of length 'len' */
				/* + 256 bytes of pad.  if 'x' then len = 0 */
				/* else, len = 'len' */
	NETVM_OC_PKSWAP,	/* [pkn1,pkn2] swap packets pkn1 and pkn2  */
	NETVM_OC_PKCOPY,	/* [pkn2,pkn1] copy packet from pkn1 to pkn2 */
	NETVM_OC_PKDEL,		/* [pkn] delete packet */

	NETVM_OC_PKSLA,		/* [pdesc] set layer 'x' to prp in pdesc */
	NETVM_OC_PKCLA,		/* [pkn] clear layer 'x' */
	NETVM_OC_PKPPSH,	/* [pkn,prid] "push" prp of prid in packet */
				/*   pkn to inner header if !x or outer if x */
	NETVM_OC_PKPPOP,	/* [pkn] pop the top prp off of packet pkn */
	                        /*   if x then pop from front else innermost */

	NETVM_OC_PKPRS,		/* [pkn] delete parse and if 'x' == 0 reparse */
	NETVM_OC_PKFXD,		/* [pkn] set dltype to PRID_ of 2nd prp */
	NETVM_OC_PKPUP,		/* [pdesc] update parse fields (stack pdesc) */

	NETVM_OC_PKFXL,		/* [pdesc] fix length fields in the packet */
				/*   If pdesc refers to the base parse, fix */
				/*   all lengths that are in a layer */
	NETVM_OC_PKFXLI,	/* fix length fields in packet (packed pdesc) */
	NETVM_OC_PKFXC,		/* [pdesc] fix checksum fields in the packet */
				/*   If pdesc refers to the base parse, fix */
				/*   all checksums that are in a layer */
	NETVM_OC_PKFXCI,	/* fix checksums in the packet (packed pdesc) */

				/* for these 3 operations, it is an error */
				/* if the address doesn't refer to a packet */
	NETVM_OC_PKINS,		/* [addr,len] insert len bytes @ pd.offset */
				/*   move new bytes down if x or up if !x */
	NETVM_OC_PKCUT,		/* [addr,len] cut len bytes @ pd.offset */
				/*   move new bytes down if x or up if !x */
	NETVM_OC_PKADJ,		/* [pdesc,amt] adjust offset 'field' by */
	                        /*   amt (signed) bytes in parse */

	NETVM_OC_MAXOP = NETVM_OC_PKADJ
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


#define NETVM_OP_CANSWAP(_oc) \
	(((_oc) >= NETVM_OC_ADD) && ((_oc) <= NETVM_OC_UMAXI))


#define NETVM_IADDR(w)  ((ulong)(w))
#define NETVM_BRF(w)    ((ulong)(w))
#define NETVM_BRB(w)    (-(ulong)(w))

#define NETVM_OP(OPCODE, x, y, z, w)\
	{ NETVM_OC_##OPCODE, (x), (y), (z), (w) }
#define NETVM_PDIOP(OPCODE, x, pkt, prid, idx, fld, off) \
	{ NETVM_OC_##OPCODE, (x), NETVM_OP_PDESC(pkt, prid, idx, fld, off) }

#define NETVM_BR_F(amt) NETVM_OP(BRI, 0, 0, 0, NETVM_BRF(amt))
#define NETVM_BR_B(amt) NETVM_OP(BRI, 0, 0, 0, NETVM_BRB(amt))
#define NETVM_BRIF_F(amt) NETVM_OP(BNZI, 0, 0, 0, NETVM_BRF(amt))
#define NETVM_BRIF_B(amt) NETVM_OP(BNZI, 0, 0, 0, NETVM_BRB(amt))
#define NETVM_BRIFNOT_F(amt) NETVM_OP(BZI, 0, 0, 0, NETVM_BRF(amt))
#define NETVM_BRIFNOT_B(amt) NETVM_OP(BZI, 0, 0, 0, NETVM_BRB(amt))

enum {
	/* standard status */
	NETVM_STATUS_RUNNING = 0,
	NETVM_STATUS_STOPPED = 1,
	NETVM_STATUS_OOCYCLES = 2,
	NETVM_STATUS_BPT = 3,

	/* defined by the runtime */
	NETVM_STATUS_RTDEF0 = 16,
	NETVM_STATUS_RTDEF1 = 17,
	NETVM_STATUS_RTDEF2 = 18,
	NETVM_STATUS_RTDEF3 = 19,
	NETVM_STATUS_RTDEF4 = 20,
	NETVM_STATUS_RTDEF5 = 21,
	NETVM_STATUS_RTDEF6 = 22,
	NETVM_STATUS_RTDEF7 = 23,

	/* runtime errors */
	NETVM_ERR_MIN = 64,
	NETVM_ERR_UNIMPL = NETVM_ERR_MIN,
	NETVM_ERR_STKOVFL,
	NETVM_ERR_STKUNDF,
	NETVM_ERR_WIDTH,
	NETVM_ERR_INSTADDR,
	NETVM_ERR_MEMADDR,
	NETVM_ERR_PKTADDR,
	NETVM_ERR_MPERM,
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
	NETVM_ERR_PARSE,
	NETVM_ERR_NOMEM,
	NETVM_ERR_IOVFL,
	NETVM_ERR_BADCOPROC,
	NETVM_ERR_BADCPOP,
	NETVM_ERR_MAX = NETVM_ERR_BADCPOP,

	/* Validation error */
	/* these should not appear in vm->status */
	NETVM_VERR_UNINIT = -1,
	NETVM_VERR_BADOP = -2,
	NETVM_VERR_BRADDR = -3,
	NETVM_VERR_BRMONLY = -4,
	NETVM_VERR_BADLAYER = -5,
	NETVM_VERR_BADWIDTH = -6,
	NETVM_VERR_BADNUMRET = -7,
	NETVM_VERR_BADCP = -8,
	NETVM_VERR_CPERR = -9,
	NETVM_VERR_CPREQ = -10,
	NETVM_VERR_PROG = -11,
	NETVM_VERR_MIN = NETVM_VERR_PROG,

};

#define NETVM_STATUS_ISERR(x) ((x) >= NETVM_ERR_MIN && (x) <= NETVM_ERR_MAX)


/* mem may be NULL and memsz 0.  roseg must be <= memsz.  stack must not be */
/* 0 and ssz is the number of stack elements.  outport may be NULL */
void netvm_init(struct netvm *vm, ulong *stack, uint ssz);

/* set the instruction code */
void netvm_set_code(struct netvm *vm, struct netvm_inst *inst, uint ni);

/* Set up one of the memory segments in the VM */
void netvm_set_mseg(struct netvm *vm, int seg, byte_t *base, uint len,
		    int perms);

/* set a coprocessor: return the cpi or -1 if initialization error */
int netvm_set_coproc(struct netvm *vm, int cpi, struct netvm_coproc *coproc);

/* set matchonly flag */
void netvm_set_matchonly(struct netvm *vm, int matchonly);

/* validate a netvm is properly set up and that all branches are correct */
/* called by set_netvm_code implicitly:  returns 0 on success, -1 on error */
int netvm_validate(struct netvm *vm);

/* zero out non-read-only memory */
void netvm_clr_mem(struct netvm *vm);

/* free all packets */
void netvm_clr_pkts(struct netvm *vm);

/* reset co-processors */
void netvm_reset_coprocs(struct netvm *vm);

/* pc <- 0, sp <- 0 */
void netvm_restart(struct netvm *vm);

/* clear memory, set pc <- 0, set sp <- 0, discard packets */
void netvm_reset(struct netvm *vm);

/* set the program counter in the vm to pc */
void netvm_set_pc(struct netvm *vm, uint pc);

/* returns 1 if the given slot holds a valid packet and 0 otherwise */
int netvm_pkt_isvalid(struct netvm *vm, int slot);

/* will free existing packets if they are slotted.  Note this gives up */
/* control of the packet.  netvm_clrpkt() or netvm_reset() or other native */
/* netvm instructions will free it.  Make a copy if this isn't desired or */
/* be careful of the program that you run and call clrpkt with the don't free */
/* flag set before calling netvm_reset() */
void netvm_load_pkt(struct netvm *vm, struct pktbuf *p, int slot);

/* free the packet in a slot:  note this destroys existin packet buffer */
/* unless keeppktbuf is set */
struct pktbuf *netvm_clr_pkt(struct netvm *vm, int slot, int keeppktbuf);

/* 0 if run ok and no retval, 1 if run ok and stack not empty, -1 if err, -2 */
/* if out of cycles */
int netvm_run(struct netvm *vm, int maxcycles, ulong *rv);

/* returns the error string corresponding to the netvm error */
const char *netvm_estr(int error);


#endif /* __netvm_h */
