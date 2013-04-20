/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * netvm_std_coproc.h -- Standard NetVM coprocessor definitions.
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
#ifndef __netvm_std_coproc_h
#define __netvm_std_coproc_h

#include "netvm.h"
#include <cat/emit.h>
#include <cat/match.h>


/* --------- Global Coprocessor Definitions --------- */
#define NETVM_CPT_XPKT      1
#define NETVM_CPT_OUTPORT   2
#define NETVM_CPT_PKTQ      3
#define NETVM_CPT_REX       4


/* --------- Xpkt Coprocessor --------- */


/* 
 * Tag descriptor value format: 
 *  | idx(16) | tag type(8) | pkt(8) |
 */

struct netvm_xpktcp_tagdesc {
	ushort			index;
	uchar			type;
	uchar			pktnum;
};

enum {
	NETVM_CPOC_HASTAG,	/* [td]/'w' == td */
	NETVM_CPOC_RDTAG,	/* [td]/'w' == td -- read tag into buf */
	NETVM_CPOC_ADDTAG,	/* [td]/'w' == td -- add tag in buf to packet */
	NETVM_CPOC_DELTAG,	/* [td]/'w' == td -- delete tag from packet */

	/* NOTE: with these two, if the high order bit is set for width */
	/* then the bytes will get swapped before storing.  This is only */
	/* valid for widths 2, 4, 8. */
	NETVM_CPOC_LDTAG,	/* [addr]/'w', z == width -- load from tag */
				/*     buf onto stack  */
	NETVM_CPOC_STTAG,	/* [v,addr]/[v](addr == 'w') z == width, */
				/*     store 'v' into tag buffer */

	NETVM_CPOC_NUMXPKT,
};


struct netvm_xpkt_cp {
	struct netvm_coproc 	coproc;
	netvm_cpop		ops[NETVM_CPOC_NUMXPKT];
	byte_t			tag[XPKT_TAG_MAXW * 4];
};


int init_xpkt_cp(struct netvm_xpkt_cp *cp);
void fini_xpkt_cp(struct netvm_xpkt_cp *cp);


/* --------- Output Port Coprocessor --------- */

enum {
	/* For all operations except PRSTRI, w is the pad width.  */
	/* pad to the left if z and right otherwise. Numbers get */
	/* padded with spaces and other types get padded with spaces. */
	NETVM_CPOC_PRBIN,/* [v] print v in binary */
	NETVM_CPOC_PROCT,/* [v] print v in octal */
	NETVM_CPOC_PRDEC,/* [v] print v in signed decimal */
	NETVM_CPOC_PRUDEC,/* [v] print v in unsigned decimal */
	NETVM_CPOC_PRHEX,/* [v] print v in hex */

	NETVM_CPOC_PRIP, /* [addr] print IP address (network byte order) */
	NETVM_CPOC_PRETH,/* [addr] print ethernet addr (network byte order) */
	                 /*     vhi has only 2 MSB of address */
	NETVM_CPOC_PRIPV6,/* [addr] print IPv6 addr (network byte order) */
	NETVM_CPOC_PRSTR,/* [addr,len] print len bytes from addr */
	NETVM_CPOC_PRSTRI,/* as PRSTR except w holds |len(8)|addr(24)| */
			  /* and 'z' holds the segment to print from */
	NETVM_CPOC_PRXSTR,/* [addr,len] print len bytes from addr */

	NETVM_CPOC_NUMPR
};

#define NETVM_CPOP_PRSTRI(seg, addr, len) \
	NETVM_OP(CPOPI, NETVM_CPI_OUTPORT, NETVM_CPOC_PRSTRI, seg, \
		 ((((len) & 0xFF) << 24) | (addr & 0xFFFFFF)))
	


struct netvm_outport_cp {
	struct netvm_coproc	coproc;
	netvm_cpop		ops[NETVM_CPOC_NUMPR];
	struct emitter *	outport;
};

void init_outport_cp(struct netvm_outport_cp *cp, struct emitter *em);
void set_outport_emitter(struct netvm_outport_cp *cp, struct emitter *em);
void fini_outport_cp(struct netvm_outport_cp *cp);



/* --------- Packet Queue Coprocessor --------- */

enum {
	NETVM_CPOC_QEMPTY,	/* [qnum] return whether a queue is empty */
	NETVM_CPOC_ENQ,		/* [qnum, pktnum] enqueue onto queue qnum */
	NETVM_CPOC_DEQ,		/* [qnum, pktnum] dequeue from queue qnum */

	NETVM_CPOC_NUMPQ,
};


struct netvm_pktq_cp {
	struct netvm_coproc	coproc;
	netvm_cpop		ops[NETVM_CPOC_NUMPQ];
	struct list *		queues;
	uint			nqueues;
};

int init_pktq_cp(struct netvm_pktq_cp *cp, uint nqueues);
int set_pktq_num(struct netvm_pktq_cp *cp, uint nqueues);
void fini_pktq_cp(struct netvm_pktq_cp *cp);


/* --------- Regular Expression Coprocessor --------- */

/* for *REX, width == # of submatches to push */
enum {
	NETVM_CPOC_REX_INIT,	/* [addr,len,rxidx]: init pattern 'rxidx' */
				/* on the string given in (addr/len) */
	NETVM_CPOC_REX_CLEAR,
	NETVM_CPOC_REX_MATCH,	/* [addr,len,rxidx]: return 0 or 1 on match */
	NETVM_CPOC_REX_MATCHX,	/* [addr,len,nm,rxidx]: Return a set of nm */
				/* offsets or 0xFFFFFFFF on no match with */
				/* a match offset for the whole pattern at */
				/* the top of the stack.  */
	NETVM_CPOC_NUMREX,
};

#define NETVM_MAXREXMATCH	16
#define NETVM_MAXREXPAT		128

struct netvm_rex_cp {
	struct netvm_coproc	coproc;
	netvm_cpop		ops[NETVM_CPOC_NUMREX];
	struct rex_pat		rexes[NETVM_MAXREXPAT];
	char			rinit[NETVM_MAXREXPAT];
	struct memmgr *		rexmm;
};

int init_rex_cp(struct netvm_rex_cp *cp, struct memmgr *rexmm, uint nrex);
void set_rexmm_cp(struct netvm_rex_cp *cp, struct memmgr *rexmm);
int add_rex_cp(struct netvm_rex_cp *cp, struct rex_pat *rex);
void fini_rex_cp(struct netvm_rex_cp *cp);

/*
  NETVM_ERR_QNUM, "bad queue index",
  NETVM_ERR_REXNUM, "bad regular expression index",
  NETVM_ERR_REX, "regex match error",
*/

/*
 * TODO:
 * RESOLVE - resolve names to addresses or visa versa (mem to mem)
 *
 * If we do this, should it be synchronous or asynchronous?  See below.
 *
 */


/* --------- Install / Finalize Standard Coprocessors as a Bundle --------- */

enum {
	NETVM_CPI_XPKT = 0,
	NETVM_CPI_OUTPORT = 1,
	NETVM_CPI_PKTQ = 2,
	NETVM_CPI_REX = 3,
};

struct netvm_std_coproc {
	struct netvm_xpkt_cp	xpkt;
	struct netvm_outport_cp	outport;
	struct netvm_pktq_cp	pktq;
	struct netvm_rex_cp	rex;
};

int init_netvm_std_coproc(struct netvm *vm, struct netvm_std_coproc *cps);
void fini_netvm_std_coproc(struct netvm_std_coproc *cps);

#endif /* __netvm_std_coproc_h */
