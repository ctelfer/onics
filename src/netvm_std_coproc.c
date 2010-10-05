#include <stdlib.h>
#include <string.h>
#include <cat/mem.h>
#include <cat/emit_format.h>
#include "netvm.h"
#include "netvm_std_coproc.h"
#include "netvm_op_macros.h"
#include "pktbuf.h"

#define swap16(v) ( (((uint16_t)(v) << 8) & 0xFF00) | \
		    (((uint16_t)(v) >> 8) & 0xFF) )
#define swap32(v) ( (((uint32_t)(v) << 24) & 0xFF000000ul) | \
		    (((uint32_t)(v) << 8) & 0xFF0000ul)    | \
		    (((uint32_t)(v) >> 8) & 0xFF00ul)      | \
		    (((uint32_t)(v) >> 24) & 0xFFul) )


/* --------- Xpkt Coprocessor --------- */

static int xpktcp_register(struct netvm_coproc *cp, struct netvm *vm, int cpid)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	memset(xcp->tag, 0, sizeof(xcp->tag));
	return 0;
}


static void xpktcp_reset(struct netvm_coproc *cp)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	memset(xcp->tag, 0, sizeof(xcp->tag));
}


static int xpktcp_validate(struct netvm_inst *inst, struct netvm *vm)
{
	if ((IMMED(inst) &&
	     (CPOP(inst) < NETVM_CPOC_HASTAG || CPOP(inst) > NETVM_CPOC_STTAG))
	     || (CPOP(inst) >= NETVM_CPOC_LDTAG && 
		 CPOP(inst) <= NETVM_CPOC_STTAG && 
		 inst->val != 1 && inst->val != 2 && inst->val != 4))
	{
		return -1;
	}

	/* Write and store operations not permitted in matchonly mode */
	if (vm->matchonly) {
	       if ((CPOP(inst) == NETVM_CPOC_STTAG)  || 
	           (CPOP(inst) == NETVM_CPOC_ADDTAG) ||
	           (CPOP(inst) == NETVM_CPOC_DELTAG))
		return -1;
	}
	return 0;
}


static void xtagdesc(struct netvm_xpktcp_tagdesc *td, uint32_t val)
{
	td->index = val >> 16;
	td->type = (val >> 8) & 0xFF;
	td->pktnum = val & 0xFF;
}


void xpktcp_hastag(struct netvm *vm, struct netvm_coproc *cp, int cpi)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	uint32_t n;

	if (CPIMMED(inst)) {
		n = inst->val;
	} else {
		S_POP(vm, n);
	}
	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));

	n = pkb_find_tag(pkb, td.type, td.index) != NULL;
	S_PUSH(vm, n);
}


void xpktcp_rdtag(struct netvm *vm, struct netvm_coproc *cp, int cpi)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	struct xpkt_tag_hdr *xth;
	uint32_t n;

	if (CPIMMED(inst)) {
		n = inst->val;
	} else {
		S_POP(vm, n);
	}
	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));
	xth = pkb_find_tag(pkb, td.type, td.index);
	FATAL(vm, NETVM_ERR_BADCPOP, (xth == NULL));
	memcpy(xcp->tag, xth, xth->xth_nwords * 4);
	/* The tag must be in packed form for the VM */
	xpkt_pack_tags((uint32_t *)xcp->tag, xth->xth_nwords * 4);
}


void xpktcp_addtag(struct netvm *vm, struct netvm_coproc *cp, int cpi)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	uint32_t n;
	int rv;

	if (CPIMMED(inst)) {
		n = inst->val;
	} else {
		S_POP(vm, n);
	}
	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));

	/* Extract the length of the option we are trying to write */
	/* it is an error to try to add an empty tag. */
	n = xcp->tag[1] * 4;
	FATAL(vm, NETVM_ERR_BADCPOP, n == 0);
	rv = xpkt_unpack_tags((uint32_t *)xcp->tag, xcp->tag[1] * 4);
	FATAL(vm, NETVM_ERR_BADCPOP, (rv < 0));
	rv = pkb_add_tag(pkb, (struct xpkt_tag_hdr *)xcp->tag);
	FATAL(vm, NETVM_ERR_BADCPOP, (rv < 0));
}


void xpktcp_deltag(struct netvm *vm, struct netvm_coproc *cp, int cpi)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	uint32_t n;
	int rv;

	if (CPIMMED(inst)) {
		n = inst->val;
	} else {
		S_POP(vm, n);
	}
	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));
	rv = pkb_del_tag(pkb, td.type, td.index);
	FATAL(vm, NETVM_ERR_BADCPOP, (rv < 0));
}


void xpktcp_ldtag(struct netvm *vm, struct netvm_coproc *cp, int cpi)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint32_t addr;
	uint32_t val;
	byte_t *p;

	S_POP(vm, addr);

	switch (inst->val) {
	case 1:
		FATAL(vm, NETVM_ERR_MEMADDR, addr >= XPKT_TAG_MAXW * 4);
		val = *(byte_t *)(xcp->tag + addr);
		if (ISSIGNED(inst))
			val |= -(val & 0x80);
		break;
	case 2:
		FATAL(vm, NETVM_ERR_MEMADDR, addr > XPKT_TAG_MAXW * 4 - 2);
		p = xcp->tag + addr;
		val = *p++ << 8;
		val |= *p;
		if (inst->flags & NETVM_IF_SWAP)
			val = swap16(val);
		if (ISSIGNED(inst))
			val |= -(val & 0x8000);
		break;
	case 4:
		FATAL(vm, NETVM_ERR_MEMADDR, addr > XPKT_TAG_MAXW * 4 - 4);
		p = xcp->tag + addr;
		val = *p++ << 24;
		val |= *p++ << 16;
		val |= *p++ << 8;
		val |= *p;
		if (inst->flags & NETVM_IF_SWAP)
			val = swap32(val);
		if (ISSIGNED(inst))
			val |= -(val & 0x80000000);
		break;
	default:
		abort_unless(0);	/* should be checked at validation */
		VMERR(vm, NETVM_ERR_WIDTH);
	}
	S_PUSH(vm, val);
}


void xpktcp_sttag(struct netvm *vm, struct netvm_coproc *cp, int cpi)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint32_t addr;
	uint32_t val;
	byte_t *p;

	S_POP(vm, addr);
	S_POP(vm, val);

	switch (inst->val) {
	case 1:
		FATAL(vm, NETVM_ERR_MEMADDR, addr >= XPKT_TAG_MAXW * 4);
		*(byte_t *)(vm->mem + addr) = val;
		break;
	case 2:
		FATAL(vm, NETVM_ERR_MEMADDR, addr > XPKT_TAG_MAXW * 4 - 2);
		p = vm->mem + addr;
		*p++ = (val >> 8) & 0xFF;
		*p = val & 0xFF;
		break;
	case 4:
		FATAL(vm, NETVM_ERR_MEMADDR, addr > XPKT_TAG_MAXW * 4 - 4);
		p = vm->mem + addr;
		*p++ = (val >> 24) & 0xFF;
		*p++ = (val >> 16) & 0xFF;
		*p++ = (val >> 8) & 0xFF;
		*p = val & 0xFF;
		break;
	default:
		abort_unless(0);	/* should be checked at validation */
		VMERR(vm, NETVM_ERR_WIDTH);
	}

}


int init_xpkt_cp(struct netvm_xpkt_cp *cp)
{
	netvm_cpop *opp;
	abort_unless(cp);
	cp->coproc.type = NETVM_CPT_XPKT;
	cp->coproc.numops = NETVM_CPOC_NUMXPKT;
	cp->coproc.ops = cp->ops;
	cp->coproc.regi = &xpktcp_register;
	cp->coproc.reset = &xpktcp_reset;
	cp->coproc.validate = &xpktcp_validate;
	opp = cp->ops;
	opp[NETVM_CPOC_HASTAG] = xpktcp_hastag;
	opp[NETVM_CPOC_RDTAG] = xpktcp_rdtag;
	opp[NETVM_CPOC_ADDTAG] = xpktcp_addtag;
	opp[NETVM_CPOC_DELTAG] = xpktcp_deltag;
	opp[NETVM_CPOC_LDTAG] = xpktcp_ldtag;
	opp[NETVM_CPOC_STTAG] = xpktcp_sttag;
	return 0;
}


void fini_xpkt_cp(struct netvm_xpkt_cp *cp)
{
	abort_unless(cp);
}


/* --------- Outport Coprocessor --------- */

static int outport_register(struct netvm_coproc *cp, struct netvm *vm, int cpi)
{
	return 0;
}


static void outport_reset(struct netvm_coproc *cp)
{
}


#define SWIDTH(inst) ((inst->val >> 16) & 0xFFFF)
#define NWIDTH(inst) (inst->val & 0xFFFF)
static int outport_validate(struct netvm_inst *inst, struct netvm *vm)
{
	int swidth = SWIDTH(inst);
	int nwidth = NWIDTH(inst);
	if ((IMMED(inst) &&
	     (CPOP(inst) < NETVM_CPOC_PRBIN || CPOP(inst) > NETVM_CPOC_PRSTR))
	    || (swidth < 0 || swidth > 64) || (CPOP(inst) >= NETVM_CPOC_PRBIN
					       && CPOP(inst) <= NETVM_CPOC_PRHEX
					       && nwidth != 1 && nwidth != 2
					       && nwidth != 4))
		return -1;
	return 0;
}


static void nci_prnum(struct netvm *vm, struct netvm_coproc *ncp, int cpi)
{
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	char fmtbuf[12];
	int swidth = SWIDTH(inst);
	int nwidth = NWIDTH(inst);
	uint32_t val;

	abort_unless(cp->outport);	/* guaranteed by netvm_init() */
	abort_unless(swidth <= 64 && swidth >= 0);

	switch (CPOP(inst)) {
	case NETVM_CPOC_PRBIN:
		if (swidth)
			sprintf(fmtbuf, "%%0%d" FMT32 "b", swidth);
		else
			sprintf(fmtbuf, "%%" FMT32 "b");
		break;
	case NETVM_CPOC_PROCT:
		if (swidth)
			sprintf(fmtbuf, "%%0%d" FMT32 "o", swidth);
		else
			sprintf(fmtbuf, "%%" FMT32 "o");
		break;
	case NETVM_CPOC_PRDEC:
		if (swidth) {
			if (ISSIGNED(inst))
				sprintf(fmtbuf, "%%0%d" FMT32 "d", swidth);
			else
				sprintf(fmtbuf, "%%0%d" FMT32 "u", swidth);
		} else {
			if (ISSIGNED(inst))
				sprintf(fmtbuf, "%%" FMT32 "d");
			else
				sprintf(fmtbuf, "%%" FMT32 "u");
		}
		break;
	case NETVM_CPOC_PRHEX:
		if (swidth)
			sprintf(fmtbuf, "%%0%d" FMT32 "x", swidth);
		else
			sprintf(fmtbuf, "%%" FMT32 "x");
		break;
	default:
		abort_unless(0);
	}

	S_POP(vm, val);
	/* mask out all irrelevant bits */
	if (nwidth < 4)
		val &= ~((1 << (nwidth * 8)) - 1);
	/* sign extend the result if we are printing a signed decimal */
	if (ISSIGNED(inst) && (CPOP(inst) == NETVM_CPOC_PRDEC))
		val |= -(val & (1 << (nwidth * 8 - 1)));
	emit_format(cp->outport, fmtbuf, val);
}


static void nci_prip(struct netvm *vm, struct netvm_coproc *ncp, int cpi)
{
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	uint32_t val;
	byte_t *bp = (byte_t *) & val;
	abort_unless(cp->outport);
	S_POP(vm, val);
	/* Assumes network byte order */
	emit_format(cp->outport, "%u.%u.%u.%u", bp[0], bp[1], bp[2], bp[3]);
}


static void nci_preth(struct netvm *vm, struct netvm_coproc *ncp, int cpi)
{
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	uint32_t val1, val2;
	byte_t *bp1 = (byte_t *) & val1;
	byte_t *bp2 = (byte_t *) & val2;
	abort_unless(cp->outport);
	S_POP(vm, val1);
	S_POP(vm, val2);
	/* Assumes network byte order */
	emit_format(cp->outport, "%02x:%02x:%02x:%02x:%02x:%02x",
		    bp1[0], bp1[1], bp1[2], bp1[3], bp2[0], bp2[1]);
}


static void nci_pripv6(struct netvm *vm, struct netvm_coproc *ncp, int cpi)
{
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	uint32_t v1, v2, v3, v4;
	byte_t *b1 = (byte_t *) & v1;
	byte_t *b2 = (byte_t *) & v2;
	byte_t *b3 = (byte_t *) & v3;
	byte_t *b4 = (byte_t *) & v4;
	abort_unless(cp->outport);
	S_POP(vm, v1);
	S_POP(vm, v2);
	S_POP(vm, v3);
	S_POP(vm, v4);
	emit_format(cp->outport,
		    "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		    b1[0], b1[1], b1[2], b1[3], b2[0], b2[1], b2[2], b2[3],
		    b3[0], b3[1], b3[2], b3[3], b4[0], b4[1], b4[2], b4[3]);
}


static void nci_prstr(struct netvm *vm, struct netvm_coproc *ncp, int cpi)
{
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint32_t addr, len;
	abort_unless(cp->outport);
	if (CPIMMED(inst)) {
		len = inst->val;
	} else {
		S_POP(vm, len);
	}
	S_POP(vm, addr);
	FATAL(vm, NETVM_ERR_IOVFL, addr + len < addr);
	FATAL(vm, NETVM_ERR_MEMADDR, !vm->mem || !vm->memsz || addr >= vm->memsz
	      || addr + len > vm->memsz);
	emit_raw(cp->outport, vm->mem + addr, len);
}


void init_outport_cp(struct netvm_outport_cp *cp, struct emitter *em)
{
	netvm_cpop *opp;
	abort_unless(cp);
	cp->coproc.type = NETVM_CPT_OUTPORT;
	cp->coproc.numops = NETVM_CPOC_NUMPR;
	cp->coproc.ops = cp->ops;
	cp->coproc.regi = &outport_register;
	cp->coproc.reset = &outport_reset;
	cp->coproc.validate = &outport_validate;
	set_outport_emitter(cp, em);
	opp = cp->ops;
	opp[NETVM_CPOC_PRBIN] = opp[NETVM_CPOC_PROCT] = opp[NETVM_CPOC_PRDEC] =
	    opp[NETVM_CPOC_PRHEX] = &nci_prnum;
	opp[NETVM_CPOC_PRIP] = nci_prip;
	opp[NETVM_CPOC_PRETH] = nci_preth;
	opp[NETVM_CPOC_PRIPV6] = nci_pripv6;
	opp[NETVM_CPOC_PRSTR] = nci_prstr;
}


void set_outport_emitter(struct netvm_outport_cp *cp, struct emitter *em)
{
	abort_unless(cp);
	if (em == NULL)
		cp->outport = &null_emitter;
	else
		cp->outport = em;
}


void fini_outport_cp(struct netvm_outport_cp *cp)
{
	abort_unless(cp);
}


/* --------- Packet Queue Coprocessor --------- */

static int pktq_register(struct netvm_coproc *ncp, struct netvm *vm, int cpi)
{
	return 0;
}


static void pktq_reset(struct netvm_coproc *ncp)
{
	struct netvm_pktq_cp *cp = container(ncp, struct netvm_pktq_cp, coproc);
	int i;

	abort_unless(ncp);

	for (i = 0; i < cp->nqueues; ++i) {
		struct list *l;
		while ((l = l_deq(&cp->queues[i])))
			pkb_free(container(l, struct pktbuf, pkb_entry));
	}
}


static int pktq_validate(struct netvm_inst *inst, struct netvm *vm)
{
	if ((IMMED(inst) &&
	     (CPOP(inst) < NETVM_CPOC_QEMPTY || CPOP(inst) > NETVM_CPOC_DEQ)))
		return -1;
	return 0;
}


static void nci_qempty(struct netvm *vm, struct netvm_coproc *ncp, int cpi)
{
	struct netvm_pktq_cp *cp = container(ncp, struct netvm_pktq_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint32_t qnum;
	if (CPIMMED(inst)) {
		qnum = inst->val;
	} else {
		S_POP(vm, qnum);
	}
	FATAL(vm, NETVM_ERR_BADCPOP, qnum >= cp->nqueues);
	S_PUSH(vm, l_isempty(&cp->queues[qnum]));
}


static void nci_qop(struct netvm *vm, struct netvm_coproc *ncp, int cpi)
{
	struct netvm_pktq_cp *cp = container(ncp, struct netvm_pktq_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	uint32_t pktnum, qnum;
	struct pktbuf *pkb;
	struct list *l;
	if (CPIMMED(inst)) {
		pktnum = inst->val;
	} else {
		S_POP(vm, pktnum);
	}
	S_POP(vm, qnum);
	FATAL(vm, NETVM_ERR_PKTNUM, pktnum >= NETVM_MAXPKTS);
	FATAL(vm, NETVM_ERR_BADCPOP, qnum >= cp->nqueues);

	if (CPOP(inst) == NETVM_CPOC_ENQ) {
		FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pktnum]));
		l_enq(&cp->queues[qnum], &pkb->pkb_entry);
		vm->packets[pktnum] = NULL;
	} else {
		if ((l = l_deq(&cp->queues[qnum]))) {
			pkb_free(vm->packets[pktnum]);
			vm->packets[pktnum] =
			    container(l, struct pktbuf, pkb_entry);
		}
	}
}


int init_pktq_cp(struct netvm_pktq_cp *cp, uint32_t nqueues)
{
	netvm_cpop *opp;
	abort_unless(cp);

	cp->queues = NULL;
	if (set_pktq_num(cp, nqueues) < 0)
		return -1;

	cp->coproc.type = NETVM_CPT_PKTQ;
	cp->coproc.numops = NETVM_CPOC_NUMPQ;
	cp->coproc.ops = cp->ops;
	cp->coproc.regi = &pktq_register;
	cp->coproc.reset = &pktq_reset;
	cp->coproc.validate = &pktq_validate;
	opp = cp->ops;
	opp[NETVM_CPOC_QEMPTY] = &nci_qempty;
	opp[NETVM_CPOC_ENQ] = &nci_qop;
	opp[NETVM_CPOC_DEQ] = &nci_qop;

	return 0;
}


int set_pktq_num(struct netvm_pktq_cp *cp, uint32_t nqueues)
{
	struct list *queues = NULL;
	uint32_t i;
	abort_unless(cp);

	if (nqueues > 0) {
		/* overflow check */
		abort_unless(SIZE_MAX / sizeof(struct list) >= nqueues);
		if ((queues = malloc(sizeof(struct list) * nqueues)) == NULL)
			return -1;
		for (i = 0; i < nqueues; ++i)
			l_init(&queues[i]);
	}

	if (cp->queues != NULL) {
		pktq_reset(&cp->coproc);
		free(cp->queues);
	}

	cp->queues = queues;
	cp->nqueues = nqueues;

	return 0;
}


void fini_pktq_cp(struct netvm_pktq_cp *cp)
{
	abort_unless(cp);
	pktq_reset(&cp->coproc);
	if (cp->queues != NULL) {
		free(cp->queues);
		cp->queues = NULL;
	}
}



/* --------- Regular Expression Coprocessor --------- */

static int rex_register(struct netvm_coproc *ncp, struct netvm *vm, int cpi)
{
	return 0;
}


static void rex_reset(struct netvm_coproc *ncp)
{
}


static int rex_validate(struct netvm_inst *inst, struct netvm *vm)
{
	if ((IMMED(inst) &&
	     (CPOP(inst) < NETVM_CPOC_REXP || CPOP(inst) > NETVM_CPOC_REXM)))
		return -1;
	return 0;
}


static void rexmatch(struct netvm *vm, struct rex_pat *pat, struct raw *loc,
		     int32_t nm)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct rex_match_loc m[NETVM_MAXREXMATCH];
	int rv, i;
	FATAL(vm, NETVM_ERR_BADCPOP, (inst->width > NETVM_MAXREXMATCH));
	rv = rex_match(pat, loc, m, nm);
	FATAL(vm, NETVM_ERR_BADCPOP, (rv == REX_ERROR));
	if (rv == REX_MATCH) {
		for (i = nm - 1; i >= 0; --i) {
			S_PUSH(vm, m[i].valid);
			if (!m[i].valid) {
				S_PUSH(vm, (uint32_t) - 1);
				S_PUSH(vm, (uint32_t) - 1);
			} else {
				S_PUSH(vm, (uint32_t) m[i].start);
				S_PUSH(vm, (uint32_t) m[i].len);
			}
		}
	}
	S_PUSH(vm, rv == REX_MATCH);
}


static void nci_rexp(struct netvm *vm, struct netvm_coproc *ncp, int cpi)
{
	struct netvm_rex_cp *cp = container(ncp, struct netvm_rex_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	int32_t nm;
	uint32_t pktnum, poff, len, ridx;
	struct pktbuf *pkb;
	struct prparse *prp;
	struct raw r;

	if (CPIMMED(inst)) {
		pktnum = (inst->val >> 16) & 0xFFFF;
		nm = inst->val & 0xFFFF;
	} else {
		S_POP(vm, pktnum);
		S_POP(vm, nm);
	}

	FATAL(vm, NETVM_ERR_BADCPOP, (nm < 0));
	FATAL(vm, NETVM_ERR_PKTNUM, (pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pktnum]));
	S_POP(vm, ridx);
	FATAL(vm, NETVM_ERR_BADCPOP, (ridx >= cp->nrexes));
	S_POP(vm, len);
	S_POP(vm, poff);
	FATAL(vm, NETVM_ERR_IOVFL, (len + poff < len));
	prp = &pkb->pkb_prp;
	FATAL(vm, NETVM_ERR_PKTADDR,
	      (poff < prp_soff(prp)) || (poff + len > prp_totlen(prp)));
	r.data = prp->data + poff;
	r.len = len;
	rexmatch(vm, cp->rexes[ridx], &r, nm);
}


static void nci_rexm(struct netvm *vm, struct netvm_coproc *ncp, int cpi)
{
	struct netvm_rex_cp *cp = container(ncp, struct netvm_rex_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	int32_t nm;
	uint32_t addr, len, ridx;
	struct raw r;

	if (CPIMMED(inst)) {
		nm = inst->val & 0xFFFF;
	} else {
		S_POP(vm, nm);
	}

	FATAL(vm, NETVM_ERR_BADCPOP, (nm < 0));
	S_POP(vm, ridx);
	FATAL(vm, NETVM_ERR_BADCPOP, (ridx >= cp->nrexes));
	S_POP(vm, len);
	S_POP(vm, addr);
	FATAL(vm, NETVM_ERR_IOVFL, (addr + len < len));
	FATAL(vm, NETVM_ERR_NOMEM, vm->mem == NULL);
	FATAL(vm, NETVM_ERR_MEMADDR, (addr + len > vm->memsz));
	r.data = vm->mem + addr;
	r.len = len;
	rexmatch(vm, cp->rexes[ridx], &r, nm);
}


#define DEFAULT_REXRALEN  16

int init_rex_cp(struct netvm_rex_cp *cp, struct memmgr *rexmm)
{
	struct rex_pat **ra;
	netvm_cpop *opp;
	abort_unless(cp);

	if ((ra = malloc(sizeof(struct rex_pat *) * DEFAULT_REXRALEN)) == NULL)
		return -1;
	cp->coproc.type = NETVM_CPT_REX;
	cp->coproc.numops = NETVM_CPOC_NUMREX;
	cp->coproc.ops = cp->ops;
	cp->coproc.regi = &rex_register;
	cp->coproc.reset = &rex_reset;
	cp->coproc.validate = &rex_validate;
	opp = cp->ops;
	opp[NETVM_CPOC_REXP] = nci_rexp;
	opp[NETVM_CPOC_REXM] = nci_rexm;
	cp->rexes = ra;
	memset(ra, 0, sizeof(struct rex_pat *) * DEFAULT_REXRALEN);
	cp->nrexes = 0;
	cp->ralen = DEFAULT_REXRALEN;
	cp->rexmm = rexmm;
	return 0;
}


void set_rexmm_cp(struct netvm_rex_cp *cp, struct memmgr *rexmm)
{
	abort_unless(cp);
	cp->rexmm = rexmm;
}


int add_rex_cp(struct netvm_rex_cp *cp, struct rex_pat *rex)
{
	abort_unless(cp && rex);

	if (cp->nrexes == cp->ralen) {
		struct rex_pat **ra;
		uint32_t nralen = cp->ralen << 1;
		if (nralen < cp->ralen)
			return -1;
		ra = realloc(cp->rexes, nralen * sizeof(struct rex_pat *));
		if (ra == NULL)
			return -1;
		cp->rexes = ra;
		cp->ralen = nralen;
	}

	cp->rexes[cp->nrexes++] = rex;

	return 0;
}


void fini_rex_cp(struct netvm_rex_cp *cp)
{
	uint32_t i;
	struct memmgr *mm;
	if ((mm = cp->rexmm) != NULL)
		for (i = 0; i < cp->nrexes; ++i)
			mem_free(mm, cp->rexes[i]);
	free(cp->rexes);
}


/* --------- Install / Finalize Standard Coprocessors as a Bundle --------- */

#define DEFAULT_NPKTQS    16

int init_netvm_std_coproc(struct netvm *vm, struct netvm_std_coproc *cps)
{
	abort_unless(vm && cps);

	init_xpkt_cp(&cps->xpkt);
	init_outport_cp(&cps->outport, NULL);
	if (init_rex_cp(&cps->rex, &stdmm) < 0)
		return -1;
	if (init_pktq_cp(&cps->pktq, DEFAULT_NPKTQS) < 0) {
		fini_rex_cp(&cps->rex);
		return -1;
	}

	if (netvm_set_coproc(vm, NETVM_CPI_XPKT, &cps->xpkt.coproc) < 0)
		goto err;
	if (netvm_set_coproc(vm, NETVM_CPI_OUTPORT, &cps->outport.coproc) < 0)
		goto err;
	if (netvm_set_coproc(vm, NETVM_CPI_PKTQ, &cps->pktq.coproc) < 0)
		goto err;
	if (netvm_set_coproc(vm, NETVM_CPI_REX, &cps->rex.coproc) < 0)
		goto err;

	return 0;

err:
	fini_netvm_std_coproc(cps);
	return -1;
}


void fini_netvm_std_coproc(struct netvm_std_coproc *cps)
{
	abort_unless(cps);
	fini_xpkt_cp(&cps->xpkt);
	fini_outport_cp(&cps->outport);
	fini_pktq_cp(&cps->pktq);
	fini_rex_cp(&cps->rex);
}
