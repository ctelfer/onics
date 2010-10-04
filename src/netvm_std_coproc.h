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
	uint16_t	index;
	uint8_t		type;
	uint8_t		pktnum;
};

enum {
	NETVM_CPOC_HASTAG,	/* mo, val == tagdesc */
	NETVM_CPOC_RDTAG,	/* mo, val == tagdesc */
	NETVM_CPOC_ADDTAG,	/* val == tagdesc */
	NETVM_CPOC_DELTAG,	/* val == tagdesc */
	NETVM_CPOC_LDTAG,	/* [addr] mo, val == width */
	NETVM_CPOC_STTAG,	/* [vaddr,v] val == width */

	NETVM_CPOC_NUMXPKT,
};


struct netvm_xpkt_cp {
	struct netvm_coproc coproc;
	netvm_cpop ops[NETVM_CPOC_NUMXPKT];
	byte_t tag[XPKT_TAG_MAXW * 4];
};


int init_xpkt_cp(struct netvm_xpkt_cp *cp);
void fini_xpkt_cp(struct netvm_xpkt_cp *cp);


/* --------- Output Port Coprocessor --------- */

enum {
	NETVM_CPOC_PRBIN,/* [v|V] print v in binary: val == min string width */
	NETVM_CPOC_PROCT,/* [v|V] print v in octal: val == min string width */
	NETVM_CPOC_PRDEC,/* [v|VS] print v in decimal: val == min str width */
	NETVM_CPOC_PRHEX,/* [v|V] print v in hex: val == min string width */
	NETVM_CPOC_PRIP, /* [v] print IP address (network byte order) */
	NETVM_CPOC_PRETH,/* [v] print ethernet address (network byte order) */
	NETVM_CPOC_PRIPV6,/* [vhi,vlo] print IPv6 addr (network byte order) */
	NETVM_CPOC_PRSTR,/* [addr,len|I] print len bytes from addr in mem */

	NETVM_CPOC_NUMPR
};

#define NETVM_OPNUMV(strw, numw)  ((uint32_t)((strw)<<16|(numw)))

struct netvm_outport_cp {
	struct netvm_coproc coproc;
	netvm_cpop ops[NETVM_CPOC_NUMPR];
	struct emitter *outport;
};

void init_outport_cp(struct netvm_outport_cp *cp, struct emitter *em);
void set_outport_emitter(struct netvm_outport_cp *cp, struct emitter *em);
void fini_outport_cp(struct netvm_outport_cp *cp);



/* --------- Packet Queue Coprocessor --------- */

enum {
	NETVM_CPOC_QEMPTY,	/* [qnum|I] return whether a queue is empty */
	NETVM_CPOC_ENQ,		/* [qnum,pktnum|I] enqueue onto queue qnum */
	NETVM_CPOC_DEQ,		/* [qnum,pktnum|I] dequeue from queue qnum */

	NETVM_CPOC_NUMPQ,
};


struct netvm_pktq_cp {
	struct netvm_coproc coproc;
	netvm_cpop ops[NETVM_CPOC_NUMPQ];
	struct list *queues;
	uint32_t nqueues;
};

int init_pktq_cp(struct netvm_pktq_cp *cp, uint32_t nqueues);
int set_pktq_num(struct netvm_pktq_cp *cp, uint32_t nqueues);
void fini_pktq_cp(struct netvm_pktq_cp *cp);


/* --------- Regular Expression Coprocessor --------- */

/* for *REX, width == # of submatches to push */
enum {
	NETVM_CPOC_REXP,	/* [pa,len,rxidx,(pktnum,nmatch)|I]:regex */
				/*      on packet data */
	NETVM_CPOC_REXM,	/* [addr,len,rxidx, nmatch|I]: regex on */
				/*      memory data */
	NETVM_CPOC_NUMREX,
};

#define NETVM_MAXREXMATCH 16
#define NETVM_REXPV(nmatch, pktnum)  ((uint32_t)((nmatch)<<16|(pktnum)))

struct netvm_rex_cp {
	struct netvm_coproc coproc;
	netvm_cpop ops[NETVM_CPOC_NUMREX];
	struct rex_pat **rexes;
	uint32_t nrexes;
	uint32_t ralen;
	struct memmgr *rexmm;
};

int init_rex_cp(struct netvm_rex_cp *cp, struct memmgr *rexmm);
void set_rexmm_cp(struct netvm_rex_cp *cp, struct memmgr *rexmm);
int add_rex_cp(struct netvm_rex_cp *cp, struct rex_pat *rex);
void fini_rex_cp(struct netvm_rex_cp *cp);

/*
  NETVM_ERR_QNUM, "bad queue index",
  NETVM_ERR_REXNUM, "bad regular expression index",
  NETVM_ERR_REX, "regex match error",
*/

/*
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
	struct netvm_xpkt_cp xpkt;
	struct netvm_outport_cp outport;
	struct netvm_pktq_cp pktq;
	struct netvm_rex_cp rex;
};

int init_netvm_std_coproc(struct netvm *vm, struct netvm_std_coproc *cps);
void fini_netvm_std_coproc(struct netvm_std_coproc *cps);

#endif /* __netvm_std_coproc_h */
