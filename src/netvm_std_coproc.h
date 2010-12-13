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
	uint16_t		index;
	uint8_t			type;
	uint8_t			pktnum;
};

enum {
	NETVM_CPOC_HASTAG,	/* (MO) val == tagdesc */
	NETVM_CPOC_RDTAG,	/* (MO) val == tagdesc */
	NETVM_CPOC_ADDTAG,	/* val == tagdesc */
	NETVM_CPOC_DELTAG,	/* val == tagdesc */
	NETVM_CPOC_LDTAG,	/* (MO) [addr] z == width, w = swap bytes */
	NETVM_CPOC_STTAG,	/* [addr,v] z == width, w = swap bytes */

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
			 /* For PRBIN, PROCT, PRDEC, PRHEX, z == byte width */
	NETVM_CPOC_PRBIN,/* [v] print v in binary: w == min string width */
	NETVM_CPOC_PROCT,/* [v] print v in octal: w == min string width */
	NETVM_CPOC_PRDEC,/* [v] print v in decimal: w == min str width */
			 /*     signed if z. */
	NETVM_CPOC_PRHEX,/* [v] print v in hex: w == min string width */
	NETVM_CPOC_PRIP, /* [v] print IP address (network byte order) */
	NETVM_CPOC_PRETH,/* [vhi, vlo] print ethernet addr (network byte order) */
	                 /*     vhi has only 2 MSB of address */
	NETVM_CPOC_PRIPV6,/* [v0,v1,v2,v3] print IPv6 addr (network byte order) */
	NETVM_CPOC_PRSTR,/* [addr,len] print len bytes from addr in mem */
	NETVM_CPOC_PRSTRI,/* print 'z' bytes from address 'w' in mem */

	NETVM_CPOC_NUMPR
};


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
	NETVM_CPOC_REX,		/* [addr,len,rxidx]: z is the memory seg */
				/* w is the number of matches to push */
	NETVM_CPOC_NUMREX,
};

#define NETVM_MAXREXMATCH 16

struct netvm_rex_cp {
	struct netvm_coproc	coproc;
	netvm_cpop		ops[NETVM_CPOC_NUMREX];
	struct rex_pat **	rexes;
	uint			nrexes;
	uint			ralen;
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
