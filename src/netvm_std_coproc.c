/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * netvm_std_coproc.c -- Standard NetVM coprocessors especially for
 *   use with PML.
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
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <cat/mem.h>
#include <cat/emit_format.h>
#include "netvm.h"
#include "netvm_std_coproc.h"
#include "netvm_op_macros.h"
#include "pktbuf.h"
#include "util.h"

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
	int width;

	if ((inst->y == NETVM_CPOC_LDTB) || (inst->y == NETVM_CPOC_STTB) ||
	    (inst->y == NETVM_CPOC_RDTAG) || (inst->y == NETVM_CPOC_WRTAG)) {
		if (!netvm_valid_width(inst->z))
			return -1;
		width = inst->z & 0x7F;
		if (width != 1 && width != 2 && width != 4)
			return -1;
	}

	/* Write and store operations not permitted in matchonly mode */
	if (vm->matchonly) {
	       if ((inst->y == NETVM_CPOC_STTB)  || 
	           (inst->y == NETVM_CPOC_ADDTAG) ||
	           (inst->y == NETVM_CPOC_DELTAG) ||
	           (inst->y == NETVM_CPOC_ADDXTAG) ||
	           (inst->y == NETVM_CPOC_WRTAG))
		return -1;
	}
	return 0;
}


static void xtagdesc(struct netvm_xpktcp_tagdesc *td, ulong val)
{
	td->index = (val >> 16) & 0xFFFF;
	td->type = (val >> 8) & 0xFF;
	td->pktnum = val & 0xFF;
}


static void xpktcp_hastag(struct netvm *vm, struct netvm_coproc *cp, int cpi,
			  int cpop)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	ulong n;

	if (inst->op == NETVM_OC_CPOPI) {
		n = inst->w;
	} else {
		S_POP(vm, n);
	}
	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));

	n = pkb_find_tag(pkb, td.type, td.index) != NULL;
	S_PUSH(vm, n);
}


static void xpktcp_ldtag(struct netvm *vm, struct netvm_coproc *cp, int cpi,
			 int cpop)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	struct xpkt_tag_hdr *xth;
	ulong n;

	if (inst->op == NETVM_OC_CPOPI) {
		n = inst->w;
	} else {
		S_POP(vm, n);
	}
	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));
	xth = pkb_find_tag(pkb, td.type, td.index);
	FATAL(vm, NETVM_ERR_BADCPOP, (xth == NULL));
	memcpy(xcp->tag, xth, xpkt_tag_size(xth));
	/* The tag must be in packed form for the VM */
	xpkt_pack_tags((void *)xcp->tag, xth->nwords + 1);
}


static void xpktcp_addtag(struct netvm *vm, struct netvm_coproc *cp, int cpi,
			  int cpop)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	ulong n;
	int rv;

	if (inst->op == NETVM_OC_CPOPI) {
		n = inst->w;
	} else {
		S_POP(vm, n);
	}
	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));

	/* Extract the length of the option we are trying to write */
	n = xcp->tag[1] + 1;
	rv = xpkt_unpack_tags((void *)xcp->tag, n);
	FATAL(vm, NETVM_ERR_BADCPOP, (rv < 0));
	rv = pkb_add_tag(pkb, (struct xpkt_tag_hdr *)xcp->tag);
	FATAL(vm, NETVM_ERR_BADCPOP, (rv < 0));
}


static void xpktcp_deltag(struct netvm *vm, struct netvm_coproc *cp, int cpi,
			  int cpop)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	ulong n;
	int rv;

	if (inst->op == NETVM_OC_CPOPI) {
		n = inst->w;
	} else {
		S_POP(vm, n);
	}
	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));
	rv = pkb_del_tag(pkb, td.type, td.index);
	FATAL(vm, NETVM_ERR_BADCPOP, (rv < 0));
}


static void xpktcp_ldtb(struct netvm *vm, struct netvm_coproc *cp, int cpi,
			int cpop)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	ulong addr;
	int width;

	S_POP(vm, addr);

	width = inst->z;
	FATAL(vm, NETVM_ERR_MEMADDR, addr > XPKT_TAG_MAXW * 4 - (width & 0x7F));
	netvm_p2stk(vm, (byte_t *)(xcp->tag + addr), width);
}


static void xpktcp_sttb(struct netvm *vm, struct netvm_coproc *cp, int cpi,
			int cpop)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	ulong addr;
	ulong val;
	int width = inst->z;
	byte_t *p;

	S_POP(vm, addr);
	S_POP(vm, val);
	p = xcp->tag + addr;
	FATAL(vm, NETVM_ERR_MEMADDR, addr > XPKT_TAG_MAXW * 4 - (width & 0x7F));
	netvm_stk2p(vm, p, val, width);
}


static void xpktcp_clrtbuf(struct netvm *vm, struct netvm_coproc *cp, int cpi,
			   int cpop)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	memset(xcp->tag, 0, sizeof(xcp->tag));
}


static void xpktcp_addxtag(struct netvm *vm, struct netvm_coproc *cp, int cpi,
			   int cpop)
{
	struct netvm_xpkt_cp *xcp = container(cp, struct netvm_xpkt_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	ulong n;
	ulong nw;
	int rv;

	if (inst->op == NETVM_OC_CPOPI) {
		n = inst->w;
	} else {
		S_POP(vm, n);
	}
	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));

	switch (td.type) {
	case XPKT_TAG_TIMESTAMP:
		xpkt_tag_ts_init((struct xpkt_tag_ts *)xcp->tag, 0, 0);
		break;
	case XPKT_TAG_SNAPINFO:
		xpkt_tag_si_init((struct xpkt_tag_snapinfo *)xcp->tag, 0);
		break;
	case XPKT_TAG_INIFACE:
		xpkt_tag_iif_init((struct xpkt_tag_iface *)xcp->tag, 0);
		break;
	case XPKT_TAG_OUTIFACE:	
		xpkt_tag_oif_init((struct xpkt_tag_iface *)xcp->tag, 0);
		break;
	case XPKT_TAG_FLOW:
		xpkt_tag_flowid_init((struct xpkt_tag_flowid *)xcp->tag, 0);
		break;
	case XPKT_TAG_CLASS:
		xpkt_tag_class_init((struct xpkt_tag_class *)xcp->tag, 0);
		break;
	case XPKT_TAG_SEQ:
		xpkt_tag_seq_init((struct xpkt_tag_seq *)xcp->tag, 0);
		break;
	case XPKT_TAG_PARSEINFO:
		xpkt_tag_pi_init((struct xpkt_tag_parseinfo *)xcp->tag, 
				 PRID_NONE, 0, 0);
		break;
	case XPKT_TAG_APPINFO:
		if (inst->op == NETVM_OC_CPOPI) {
			nw = inst->z;
		} else {
			S_POP(vm, nw);
			FATAL(vm, NETVM_ERR_BADCPOP, nw > 255);
		}
		xpkt_tag_ai_init((struct xpkt_tag_appinfo *)xcp->tag, 0, NULL,
				 nw);
		break;
	default:
		VMERR(vm, NETVM_ERR_BADCPOP);

	}
	rv = pkb_add_tag(pkb, (struct xpkt_tag_hdr *)xcp->tag);
	FATAL(vm, NETVM_ERR_BADCPOP, (rv < 0));
}


static void xpktcp_rdtag(struct netvm *vm, struct netvm_coproc *cp, int cpi,
			 int cpop)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	struct xpkt_tag_hdr *xth;
	ulong n;
	ulong addr;
	int width;

	if (inst->op == NETVM_OC_CPOPI) {
		n = inst->w;
	} else {
		S_POP(vm, n);
	}
	S_POP(vm, addr);
	width = inst->z;

	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));
	xth = pkb_find_tag(pkb, td.type, td.index);
	FATAL(vm, NETVM_ERR_BADCPOP, (xth == NULL));
	FATAL(vm, NETVM_ERR_MEMADDR, 
	      (addr >= 1024 || (addr + (width & 0x7F) > xpkt_tag_size(xth))));
	xpkt_pack_tag(xth);
	netvm_p2stk(vm, (byte_t *)xth + addr, width);
	xpkt_unpack_tag(xth);
}


static void xpktcp_wrtag(struct netvm *vm, struct netvm_coproc *cp, int cpi,
			 int cpop)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_xpktcp_tagdesc td;
	struct pktbuf *pkb;
	struct xpkt_tag_hdr *xth;
	ulong n;
	ulong val;
	ulong addr;
	int width;

	if (inst->op == NETVM_OC_CPOPI) {
		n = inst->w;
	} else {
		S_POP(vm, n);
	}
	S_POP(vm, val);
	S_POP(vm, addr);
	width = inst->z;

	xtagdesc(&td, n);
	FATAL(vm, NETVM_ERR_PKTNUM, (td.pktnum >= NETVM_MAXPKTS));
	FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[td.pktnum]));
	xth = pkb_find_tag(pkb, td.type, td.index);
	FATAL(vm, NETVM_ERR_BADCPOP, (xth == NULL));
	FATAL(vm, NETVM_ERR_MEMADDR, 
	      (addr < 2 || addr >= 1024 ||
	       (addr + (width & 0x7F) > xpkt_tag_size(xth))));
	xpkt_pack_tag(xth);
	netvm_stk2p(vm, (byte_t *)xth + addr, val, width);
	xpkt_unpack_tag(xth);
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
	opp[NETVM_CPOC_LDTAG] = xpktcp_ldtag;
	opp[NETVM_CPOC_ADDTAG] = xpktcp_addtag;
	opp[NETVM_CPOC_DELTAG] = xpktcp_deltag;
	opp[NETVM_CPOC_LDTB] = xpktcp_ldtb;
	opp[NETVM_CPOC_STTB] = xpktcp_sttb;
	opp[NETVM_CPOC_CLRTBUF] = xpktcp_clrtbuf;
	opp[NETVM_CPOC_ADDXTAG] = xpktcp_addxtag;
	opp[NETVM_CPOC_RDTAG] = xpktcp_rdtag;
	opp[NETVM_CPOC_WRTAG] = xpktcp_wrtag;
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


static int outport_validate(struct netvm_inst *inst, struct netvm *vm)
{
	if ((inst->y == NETVM_CPOC_PRBIN) || (inst->y == NETVM_CPOC_PROCT) || 
	    (inst->y == NETVM_CPOC_PRDEC) || (inst->y == NETVM_CPOC_PRHEX)) {
		if (inst->w > 64)
			return NETVM_VERR_CPERR;
	}
	return 0;
}


static void nci_prnum(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		      int cpop)
{
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	char fmtbuf[32];
	ulong val;
	int i;

	abort_unless(cp->outport);	/* guaranteed by netvm_init() */

	S_POP(vm, val);

	fmtbuf[0] = '%';
	i = 1;
	if (inst->w > 0) {
		if (inst->z & NETVM_CPOC_LJUST) 
			fmtbuf[i++] = '-';
		i += snprintf(&fmtbuf[i], sizeof(fmtbuf)-i, "0%lul", 
			      (ulong)inst->w);
	} else {
		i += snprintf(&fmtbuf[i], sizeof(fmtbuf)-i, "l");
	}

	switch (cpop) {
	case NETVM_CPOC_PRBIN:
		fmtbuf[i++] = 'b';
		break;
	case NETVM_CPOC_PROCT:
		fmtbuf[i++] = 'o';
		break;
	case NETVM_CPOC_PRDEC:
		val = signxul(val, 32);
		fmtbuf[i++] = 'd';
		break;
	case NETVM_CPOC_PRUDEC:
		fmtbuf[i++] = 'u';
		break;
	case NETVM_CPOC_PRHEX:
		fmtbuf[i++] = 'x';
		break;
	default:
		abort_unless(0);
	}
	if (inst->z & NETVM_CPOC_NEWLINE)
		fmtbuf[i++] = '\n';
	fmtbuf[i++] = '\0';

	/* sign extend the result if we are printing a signed decimal */
	emit_format(cp->outport, fmtbuf, (ulong)val);
}


static void padspc(struct emitter *e, uint len)
{
	const static char spaces[17] = "                ";
	while (len > 16) {
		emit_raw(e, spaces, 16);
		len -= 16;
	}
	emit_raw(e, spaces, len);
}


static void outstr(struct emitter *e, char *s, ulong len, ulong pad, int flags)
{
	/* if we aren't left-justifying the value, add */
	/* the space padding to push it to the right. */
	if ((flags & NETVM_CPOC_LJUST) == 0 && (len < pad))
		padspc(e, pad - len);

	emit_raw(e, s, len);

	/* if we are left-justifying the value, add space padding */
	/* to fill out the width to the right. */
	if ((flags & NETVM_CPOC_LJUST) != 0 && (len < pad))
		padspc(e, pad - len);

	if (flags & NETVM_CPOC_NEWLINE)
		emit_char(e, '\n');
}


static void nci_prip(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		     int cpop)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	ulong addr;
	byte_t *p;
	char str[64];
	uint len;

	abort_unless(cp->outport);
	S_POP(vm, addr);
	netvm_get_uaddr_ptr(vm, addr, 0, 4, &p);
	VMCKRET(vm);
	len = iptostr(str, p, sizeof(str));
	outstr(cp->outport, str, len, inst->w, inst->z);
}


static void nci_preth(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		      int cpop)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	ulong addr;
	byte_t *p;
	char str[64];
	uint len;

	abort_unless(cp->outport);
	S_POP(vm, addr);
	netvm_get_uaddr_ptr(vm, addr, 0, 6, &p);
	VMCKRET(vm);
	len = ethtostr(str, p, sizeof(str));
	outstr(cp->outport, str, len, inst->w, inst->z);
}


static void nci_pripv6(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		       int cpop)
{
	struct netvm_inst *inst = &vm->inst[vm->pc];
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	ulong addr;
	byte_t *p;
	char str[64];
	uint len;

	abort_unless(cp->outport);
	S_POP(vm, addr);
	netvm_get_uaddr_ptr(vm, addr, 0, 16, &p);
	VMCKRET(vm);
	len = ip6tostr(str, p, sizeof(str));
	outstr(cp->outport, str, len, inst->w, inst->z);
}


static void nci_prstr(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		      int cpop)
{
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	ulong addr, len;
	byte_t *p;

	S_POP(vm, len);
	S_POP(vm, addr);
	netvm_get_uaddr_ptr(vm, addr, 0, len, &p);
	VMCKRET(vm);
	outstr(cp->outport, p, len, inst->w, inst->z);
}


static void nci_prstri(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		       int cpop)
{
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	ulong addr, len;
	byte_t *p;
	uchar seg;

	abort_unless(cp->outport);
	len = (inst->w >> 24) & 0xFF;
	addr = inst->w & 0xFFFFFF;
	seg = inst->z;
	netvm_get_seg_ptr(vm, seg, addr, 0, len, &p);

	VMCKRET(vm);

	emit_raw(cp->outport, p, len);
}


static void nci_prxstr(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		       int cpop)
{
	struct netvm_outport_cp *cp =
	    container(ncp, struct netvm_outport_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	ulong addr, len;
	ulong plen = 0;
	byte_t *p;
	char xd[2];
	int i;

	abort_unless(cp->outport);
	S_POP(vm, len);
	S_POP(vm, addr);
	netvm_get_uaddr_ptr(vm, addr, 0, len, &p);
	VMCKRET(vm);

	if (2*len < inst->w)
		plen = inst->w - 2 * len;

	if (plen > 0 && (inst->z & NETVM_CPOC_LJUST) == 0)
		padspc(cp->outport, plen);

	while (len > 0) {
		i = *p >> 4;
		xd[0] = (i > 10) ? ('A' + i - 10) : ('0' + i);
		i = *p & 0xF;
		xd[1] = (i > 10) ? ('A' + i - 10) : ('0' + i);
		emit_raw(cp->outport, xd, 2);
		++p;
		--len;
	}

	if (plen > 0 && (inst->z & NETVM_CPOC_LJUST) != 0)
		padspc(cp->outport, plen);
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
	    opp[NETVM_CPOC_PRUDEC] = opp[NETVM_CPOC_PRHEX] = &nci_prnum;
	opp[NETVM_CPOC_PRIP] = nci_prip;
	opp[NETVM_CPOC_PRETH] = nci_preth;
	opp[NETVM_CPOC_PRIPV6] = nci_pripv6;
	opp[NETVM_CPOC_PRSTR] = nci_prstr;
	opp[NETVM_CPOC_PRSTRI] = nci_prstri;
	opp[NETVM_CPOC_PRXSTR] = nci_prxstr;
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
	uint i;

	abort_unless(ncp);

	if (cp->npkts == 0)
		return;

	for (i = 0; i < cp->nqueues; ++i) {
		struct list *l;
		while ((l = l_deq(&cp->queues[i])))
			pkb_free(container(l, struct pktbuf, entry));
	}
	cp->npkts = 0;
}


static int pktq_validate(struct netvm_inst *inst, struct netvm *vm)
{
	return 0;
}


static void nci_numq(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		     int cpop)
{
	struct netvm_pktq_cp *cp = container(ncp, struct netvm_pktq_cp, coproc);
	S_PUSH(vm, cp->nqueues);
}


static void nci_qempty(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		       int cpop)
{
	struct netvm_pktq_cp *cp = container(ncp, struct netvm_pktq_cp, coproc);
	ulong qnum;

	S_POP(vm, qnum);
	FATAL(vm, NETVM_ERR_BADCPOP, qnum >= cp->nqueues);
	S_PUSH(vm, l_isempty(&cp->queues[qnum]));
}


static void nci_qop(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		    int cpop)
{
	struct netvm_pktq_cp *cp = container(ncp, struct netvm_pktq_cp, coproc);
	ulong pktnum, qnum;
	struct pktbuf *pkb;
	struct list *l;

	S_POP(vm, pktnum);
	S_POP(vm, qnum);
	FATAL(vm, NETVM_ERR_PKTNUM, pktnum >= NETVM_MAXPKTS);
	FATAL(vm, NETVM_ERR_BADCPOP, qnum >= cp->nqueues);

	if (cpop == NETVM_CPOC_ENQ) {
		FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pktnum]));
		l_enq(&cp->queues[qnum], &pkb->entry);
		vm->packets[pktnum] = NULL;
		++cp->npkts;
	} else if (cpop == NETVM_CPOC_PUSH) {
		FATAL(vm, NETVM_ERR_NOPKT, !(pkb = vm->packets[pktnum]));
		l_push(&cp->queues[qnum], &pkb->entry);
		vm->packets[pktnum] = NULL;
		++cp->npkts;
	} else {
		abort_unless(cpop == NETVM_CPOC_DEQ);
		if ((l = l_deq(&cp->queues[qnum]))) {
			pkb_free(vm->packets[pktnum]);
			vm->packets[pktnum] = container(l,struct pktbuf,entry);
			--cp->npkts;
		}
	}
}


int init_pktq_cp(struct netvm_pktq_cp *cp, uint nqueues)
{
	uint i;
	netvm_cpop *opp;
	abort_unless(cp);

	cp->queues = NULL;
	cp->nqueues = 0;
	cp->npkts = 0;
	if (nqueues > 0) {
		if ((cp->queues = calloc(sizeof(struct list), nqueues)) == NULL)
			return -1;
		for (i = 0; i < nqueues; ++i)
			l_init(&cp->queues[i]);
	}
	cp->nqueues = nqueues;

	cp->coproc.type = NETVM_CPT_PKTQ;
	cp->coproc.numops = NETVM_CPOC_NUMPQ;
	cp->coproc.ops = cp->ops;
	cp->coproc.regi = &pktq_register;
	cp->coproc.reset = &pktq_reset;
	cp->coproc.validate = &pktq_validate;
	opp = cp->ops;
	opp[NETVM_CPOC_NUMQ] = &nci_numq;
	opp[NETVM_CPOC_QEMPTY] = &nci_qempty;
	opp[NETVM_CPOC_ENQ] = &nci_qop;
	opp[NETVM_CPOC_PUSH] = &nci_qop;
	opp[NETVM_CPOC_DEQ] = &nci_qop;

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
	return 0;
}


static void nci_rex_init(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		         int cpop)
{
	struct netvm_rex_cp *cp = container(ncp, struct netvm_rex_cp, coproc);
	ulong addr, len, ridx;
	struct raw r;
	int rv;
	struct rex_pat *pat;
	byte_t *p;

	S_POP(vm, ridx);
	S_POP(vm, len);
	S_POP(vm, addr);

	FATAL(vm, NETVM_ERR_BADCPOP, (ridx >= NETVM_MAXREXPAT));
	netvm_get_uaddr_ptr(vm, addr, 0, len, &p);
	VMCKRET(vm);

	pat = &cp->rexes[ridx];
	if (cp->rinit[ridx]) {
		rex_free(pat);
		cp->rinit[ridx] = 0;
	}

	r.data = p;
	r.len = len;
	rv = rex_init(pat, &r, cp->rexmm, NULL);
	FATAL(vm, NETVM_ERR_BADCPOP, (rv < 0));
	cp->rinit[ridx] = 1;
}


static void nci_rex_clear(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		          int cpop)
{
	struct netvm_rex_cp *cp = container(ncp, struct netvm_rex_cp, coproc);
	ulong ridx;

	S_POP(vm, ridx);
	FATAL(vm, NETVM_ERR_BADCPOP, (ridx >= NETVM_MAXREXPAT));
	if (cp->rinit[ridx]) {
		rex_free(&cp->rexes[ridx]);
		cp->rinit[ridx] = 0;
	}
}


static void rexmatch(struct netvm *vm, struct rex_pat *pat, struct raw *loc,
		     long nm, ulong seg)
{
	struct rex_match_loc m[NETVM_MAXREXMATCH];
	int rv, i;

	rv = rex_match(pat, loc, m, nm);
	FATAL(vm, NETVM_ERR_BADCPOP, (rv == REX_ERROR));
	if (rv == REX_MATCH) {
		for (i = nm - 1; i >= 0; --i) {
			S_PUSH(vm, m[i].valid);
			if (!m[i].valid) {
				S_PUSH(vm, NETVM_PF_INVALID);
				S_PUSH(vm, NETVM_PF_INVALID);
			} else {
				S_PUSH(vm, (ulong)m[i].start + seg);
				S_PUSH(vm, (ulong)m[i].len);
			}
		}
	}
	S_PUSH(vm, rv == REX_MATCH);
}


static void _rex_match(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
		       int domatch)
{
	struct netvm_rex_cp *cp = container(ncp, struct netvm_rex_cp, coproc);
	struct netvm_inst *inst = &vm->inst[vm->pc];
	ulong addr, len, nmatch, ridx;
	byte_t *p;
	struct raw r;

	S_POP(vm, ridx);
	if (domatch)
		S_POP(vm, nmatch);
	else
		nmatch = 0;
	S_POP(vm, len);
	S_POP(vm, addr);

	FATAL(vm, NETVM_ERR_BADCPOP, (ridx >= NETVM_MAXREXPAT));
	FATAL(vm, NETVM_ERR_BADCPOP, (cp->rinit[ridx] == 0));
	FATAL(vm, NETVM_ERR_BADCPOP, (nmatch > NETVM_MAXREXMATCH));
	netvm_get_uaddr_ptr(vm, addr, 0, len, &p);
	VMCKRET(vm);

	/* regular expression matches reside within the lower 32 bits of */
	/* address space. */
	FATAL(vm, NETVM_ERR_MEMADDR, 
	     (addr & NETVM_UA_OFF_MASK) + len >= NETVM_PF_INVALID);

	if (!inst->z)
		addr = 0;
	r.data = p;
	r.len = len;
	rexmatch(vm, &cp->rexes[ridx], &r, nmatch, addr);
}


static void nci_rex_match(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
			  int cpop)
{
	return _rex_match(vm, ncp, cpi, 0);
}


static void nci_rex_matchx(struct netvm *vm, struct netvm_coproc *ncp, int cpi,
			   int cpop)
{
	return _rex_match(vm, ncp, cpi, 1);
}


int init_rex_cp(struct netvm_rex_cp *cp, struct memmgr *rexmm)
{
	netvm_cpop *opp;
	abort_unless(cp);

	cp->coproc.type = NETVM_CPT_REX;
	cp->coproc.numops = NETVM_CPOC_NUMREX;
	cp->coproc.ops = cp->ops;
	cp->coproc.regi = &rex_register;
	cp->coproc.reset = &rex_reset;
	cp->coproc.validate = &rex_validate;
	opp = cp->ops;
	opp[NETVM_CPOC_REX_INIT] = nci_rex_init;
	opp[NETVM_CPOC_REX_CLEAR] = nci_rex_clear;
	opp[NETVM_CPOC_REX_MATCH] = nci_rex_match;
	opp[NETVM_CPOC_REX_MATCHX] = nci_rex_matchx;
	memset(cp->rinit, 0, sizeof(cp->rinit));
	cp->rexmm = rexmm;

	return 0;
}


void fini_rex_cp(struct netvm_rex_cp *cp)
{
	uint i;
	for (i = 0; i < NETVM_MAXREXPAT; ++i)
		if (cp->rinit[i]) {
			rex_free(&cp->rexes[i]);
			cp->rinit[i] = 0;
		}
}


/* --------- Install / Finalize Standard Coprocessors as a Bundle --------- */

#define DEFAULT_NPKTQS    256


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
