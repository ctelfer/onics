/*
 * ONICS
 * Copyright 2012-2022
 * Christopher Adam Telfer
 *
 * protoparse.c -- Framework to parse network protocols.
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
#include "protoparse.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>

static struct proto_parser *_pp_lookup(uint prid);

/* helper functions for the default parsers */
static void root_init(struct pdu *pdu, ulong off, ulong hlen, ulong plen,
		      ulong tlen);
static struct pdu *new_pdu(struct pduspec *ps, struct pdu_ops *ops);
static int mkspec(struct pdu *pdu, int enclose, uint prid, struct pduspec *ps);

static int nxtcld_fail(struct pdu *reg, byte_t *buf, struct pdu *cld,
		       uint *prid, ulong *off, ulong *maxlen);


/* parse callbacks for PRID_NONE */
static struct pdu *none_parse(struct pdu *reg, byte_t *buf, ulong off,
			       ulong maxlen);
static int none_getspec(struct pdu *pdu, int enclose, struct pduspec *ps);
static int none_add(struct pdu *reg, byte_t *buf, struct pduspec *ps,
		    int enclose);
				
static struct proto_parser_ops none_proto_parser_ops = {
	none_parse,
	nxtcld_fail,
	none_getspec,
	none_add,
};


/* parse callbacks for PRID_DATA and PRID_RAWPKT */
static struct pdu *data_parse(struct pdu *reg, byte_t *buf, ulong off,
			      ulong maxlen);
static int data_getspec(struct pdu *pdu, int enclose, struct pduspec *ps);
static int data_add(struct pdu *reg, byte_t *buf, struct pduspec *ps,
		    int enclose);

static struct proto_parser_ops data_proto_parser_ops = {
	data_parse,
	nxtcld_fail,
	data_getspec,
	data_add,
};


/* -- global protocol parser tables -- */
struct proto_parser inet_proto_parsers[PRID_PER_PF];
struct proto_parser net_proto_parsers[PRID_PER_PF];
struct proto_parser dlt_proto_parsers[PRID_PER_PF] = {
	{PRID_RAWPKT, 1, &data_proto_parser_ops},
};
struct proto_parser pver_proto_parsers[PRID_PER_PF];
struct proto_parser pp_proto_parsers[PRID_PER_PF] = {
	{PRID_NONE, 1, &none_proto_parser_ops},
	{PRID_DATA, 1, &data_proto_parser_ops},
};


static struct proto_parser *proto_families[PRID_NUM_PF] = {
	&inet_proto_parsers[0], &net_proto_parsers[0], &dlt_proto_parsers[0],
	&pver_proto_parsers[0], NULL, NULL, NULL, NULL,  /* 0 - 7 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 8-15 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 16-23 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 24-31 */

	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 32-39 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 40-47 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 48-55 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 56-63 */

	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 64-71 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 72-79 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 80-87 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 88-95 */

	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 96-103 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 104-111 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 112-119 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 120-127 */

	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 128-135 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 136-143 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 144-151 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 152-159 */

	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 160-167 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 168-175 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 176-183 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 184-191 */

	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 192-199 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 200-207 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 208-215 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 216-223 */

	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 224-231 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 232-239 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, /* 240-247 */
	NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	&pp_proto_parsers[0], /* 248-255 */
};


/* -- Protocol parser API -- */
int pp_register(unsigned prid, struct proto_parser_ops *ppo)
{
	struct proto_parser *pp;
	uint family = PRID_FAMILY(prid);
	uint proto = PRID_PROTO(prid);

	if ((ppo == NULL) || (ppo->parse == NULL) || (ppo->add == NULL) ||
	    (family == PRID_PF_RES)) {
		errno = EINVAL;
		return -1;
	}

	if (proto_families[family] == NULL) {
		proto_families[family] =
			calloc(sizeof(struct proto_parser), PRID_PER_PF);
		if (proto_families[family] == NULL)
			return -1;
	}
	pp = &proto_families[family][proto];

	if (pp->valid) {
		errno = EACCES;
		return -1;
	}

	pp->prid = prid;
	pp->ops = ppo;
	pp->valid = 1;

	return 0;
}


static struct proto_parser *_pp_lookup(uint prid)
{
	if (proto_families[PRID_FAMILY(prid)] != NULL)
		return &proto_families[PRID_FAMILY(prid)][PRID_PROTO(prid)];
	else
		return NULL;
}


const struct proto_parser *pp_lookup(uint prid)
{
	const struct proto_parser *pp = _pp_lookup(prid);
	if (pp && !pp->valid)
		pp = NULL;
	return pp;
}


int pp_unregister(uint prid)
{
	struct proto_parser *pp;

	pp = _pp_lookup(prid);
	if (!pp) {
		errno = EINVAL;
		return -1;
	}

	if (!pp->valid) {
		errno = EACCES;
		return -1;
	}

	pp->valid = 0;
	pp->ops = NULL;
	return 0;
}


/* -- ops for "NONE", "NONE root" and "DATA" and "RAWPKT" protocol type -- */

static struct pdu *default_copy(struct pdu *opdu);
static void default_free(struct pdu *pdu);
static struct pdu *root_copy(struct pdu *opdu);
static void root_free(struct pdu *pdu);

static struct pdu_ops none_pdu_ops = {
	pdu_nop_update,
	pdu_nop_fixnxt,
	pdu_nop_fixlen,
	pdu_nop_fixcksum,
	default_copy,
	default_free
};


static struct pdu_ops data_pdu_ops = {
	pdu_nop_update,
	pdu_nop_fixnxt,
	pdu_nop_fixlen,
	pdu_nop_fixcksum,
	default_copy,
	default_free
};


static struct pdu_ops root_pdu_ops = {
	pdu_nop_update,
	pdu_nop_fixnxt,
	pdu_nop_fixlen,
	pdu_nop_fixcksum,
	root_copy,
	root_free
};

/* -- Various helper functions -- */
static void root_init(struct pdu *pdu, ulong off, ulong hlen, ulong plen,
		      ulong tlen)
{
	pdu->prid = PRID_NONE;
	pdu->error = 0;
	pdu->ops = &root_pdu_ops;
	l_init(&pdu->node);
	pdu->region = NULL;
	pdu->noff = PDU_OI_MIN_NUM;
	pdu_soff(pdu) = off;
	pdu_poff(pdu) = pdu_soff(pdu) + hlen;
	pdu_toff(pdu) = pdu_poff(pdu) + plen;
	pdu_eoff(pdu) = pdu_toff(pdu) + tlen;
	abort_unless(pdu_soff(pdu) <= pdu_poff(pdu));
	abort_unless(pdu_poff(pdu) <= pdu_toff(pdu));
	abort_unless(pdu_toff(pdu) <= pdu_eoff(pdu));
}


static struct pdu *new_pdu(struct pduspec *ps, struct pdu_ops *ops)
{
	struct pdu *pdu;

	pdu = malloc(sizeof(*pdu));
	if (!pdu)
		return NULL;

	pdu->prid = ps->prid;
	pdu->error = 0;
	pdu->ops = ops;
	l_init(&pdu->node);
	pdu->region = NULL;
	pdu->noff = PDU_OI_MIN_NUM;
	pdu_soff(pdu) = ps->off;
	pdu_poff(pdu) = pdu_soff(pdu) + ps->hlen;
	pdu_toff(pdu) = pdu_poff(pdu) + ps->plen;
	pdu_eoff(pdu) = pdu_toff(pdu) + ps->tlen;
	abort_unless(pdu_soff(pdu) <= pdu_poff(pdu));
	abort_unless(pdu_poff(pdu) <= pdu_toff(pdu));
	abort_unless(pdu_toff(pdu) <= pdu_eoff(pdu));

	return pdu;
}


static int nxtcld_fail(struct pdu *reg, byte_t *buf, struct pdu *cld,
		       uint *prid, ulong *off, ulong *maxlen)
{
	(void)reg;
	(void)buf;
	(void)cld;
	(void)prid;
	(void)off;
	(void)maxlen;
	return 0;
}


static int mkspec(struct pdu *pdu, int enclose, uint prid, struct pduspec *ps)
{
	ps->prid = prid;
	if (enclose) {
		ps->off = pdu_soff(pdu);
		ps->hlen = 0;
		ps->plen = pdu_totlen(pdu);
		ps->tlen = 0;
	} else {
		ps->off = pdu_poff(pdu);
		ps->hlen = 0;
		ps->plen = pdu_plen(pdu);
		ps->tlen = 0;
	}

	return 0;
}


/* -- NONE and NONE root parser functions -- */
static struct pdu *none_parse(struct pdu *reg, byte_t *buf, ulong off,
			      ulong maxlen)
{
	struct pdu *pdu;
	struct pduspec ps;

	abort_unless(reg);
	(void)buf;

	ps.prid = PRID_NONE;
	ps.off = off;
	ps.hlen = 0;
	ps.plen = maxlen;
	ps.tlen = 0;
	pdu = new_pdu(&ps, &none_pdu_ops);
	if (pdu != NULL)
		pdu->region = reg;
	return pdu;
}


static int none_getspec(struct pdu *pdu, int enclose, struct pduspec *ps)
{
	return mkspec(pdu, enclose, PRID_NONE, ps);
}


static int none_add(struct pdu *reg, byte_t *buf, struct pduspec *ps,
		    int enclose)
{
	struct pdu *pdu;
	(void)buf;
	abort_unless(ps);
	ps->prid = PRID_NONE;
	pdu = new_pdu(ps, &none_pdu_ops);
	if (!pdu)
		return -1;
	pdu_add_insert(reg, pdu, enclose);
	return 0;
}


/* -- DATA and RAWPKT parser functions -- */
static struct pdu *data_parse(struct pdu *reg, byte_t *buf, ulong off,
			      ulong maxlen)
{
	struct pdu *pdu;
	struct pduspec ps;

	abort_unless(reg);
	(void)buf;

	ps.prid = PRID_DATA;
	ps.off = off;
	ps.hlen = 0;
	ps.plen = maxlen;
	ps.tlen = 0;
	pdu = new_pdu(&ps, &none_pdu_ops);
	if (pdu != NULL)
		pdu->region = reg;
	return pdu;
}


static int data_getspec(struct pdu *pdu, int enclose, struct pduspec *ps)
{
	return mkspec(pdu, enclose, PRID_DATA, ps);
}


static int data_add(struct pdu *reg, byte_t *buf, struct pduspec *ps,
		    int enclose)
{
	struct pdu *pdu;
	(void)buf;
	abort_unless(ps);
	ps->prid = PRID_DATA;
	pdu = new_pdu(ps, &data_pdu_ops);
	if (!pdu)
		return -1;
	pdu_add_insert(reg, pdu, enclose);
	return 0;
}


/* -- default pdu handlers -- */
static struct pdu *default_copy(struct pdu *opdu)
{
	struct pduspec ps;
	ps.prid = opdu->prid;
	ps.off = pdu_soff(opdu);
	ps.hlen = pdu_hlen(opdu);
	ps.plen = pdu_plen(opdu);
	ps.tlen = pdu_tlen(opdu);
	return new_pdu(&ps, opdu->ops);
			
}


static void default_free(struct pdu *pdu)
{
	free(pdu);
}


static struct pdu *root_copy(struct pdu *opdu)
{
	return NULL;
}


static void root_free(struct pdu *pdu)
{
	abort_unless(0);
}


/* -- Protocol Parse Functions -- */
struct pdu *pdu_get_root(struct pdu *pdu)
{
	while (pdu->region != NULL)
		pdu = pdu->region;
	return pdu;
}


struct pdu *pdu_next_in_region(struct pdu *from, struct pdu *reg)
{
	struct pdu *pdu;
	abort_unless(from && reg);
	for (pdu = pdu_next(from);
	     !pdu_list_end(pdu) && (pdu_soff(pdu) <= pdu_eoff(reg));
	     pdu = pdu_next(pdu)) {
		if (pdu->region == reg)
			return pdu;
	}
	return NULL;
}


int pdu_region_empty(struct pdu *reg)
{
	abort_unless(reg);
	return (pdu_next_in_region(reg, reg) == NULL);
}


void pdu_init_root(struct pdu *root, ulong len)
{
	abort_unless(root && (len >= 0));
	root_init(root, 0, 0, len, 0);
}


void pdu_insert(struct pdu *from, struct pdu *toins)
{
	struct pdu *last = from, *next;
	/* search for first node in list with a starting offset */
	/* greater than or equal to the offset of this pdu */
	for (next = pdu_next(last);
	     !pdu_list_end(next) && pdu_soff(next) < pdu_soff(toins);
	     last = next, next = pdu_next(next)) ;
	l_ins(&last->node, &toins->node);
}


int pdu_parse_packet(struct pdu *root, byte_t *buf, uint nprid)
{
	struct pdu *pdu, *last, *reg;
	const struct proto_parser *pp;
	int errval, rv;
	ulong off, maxlen, noff;

	pp = pp_lookup(nprid);
	if (!root || root->prid != PRID_NONE || !pp) {
		errno = EINVAL;
		return -1;
	}

	off = pdu_poff(root);
	maxlen = pdu_plen(root);
	pdu = root;

	do {
		last = pdu;
		if (!(pdu = (*pp->ops->parse)(last, buf, off, maxlen))) {
			errval = errno;
			goto err;
		}
		pdu_insert(last, pdu);

		/* don't continue parsing if the lengths are screwed up */
		if ((pdu->error & PDU_ERR_HLENMASK) || !pdu_plen(pdu))
			break;

		reg = NULL;
		rv = (*pp->ops->nxtcld)(pdu, buf, NULL, &nprid, &noff, &maxlen);
		if (!rv) {
			/* if the new parse does not have a child, then */
			/* start going up the enclosing regions testing */
			/* for a new child in each region passing the */
			/* new parse to provide the position information */
			/* for determining the presence of a new child. */
			reg = pdu->region;
			while (reg != NULL) {
				pp = pp_lookup(reg->prid);
				abort_unless(pp);
				rv = (*pp->ops->nxtcld)(reg, buf, pdu, &nprid,
							&noff, &maxlen);
				if (rv)
					break;
				reg = reg->region;
			}
		}

		if (rv) {
			/* sanity check to ensure termination */
			/* sibling parses may not start at the same offset */
			/* TODO: determine similar restrictions for child */
			/* regions to ensure termination. */
			abort_unless(reg == NULL || noff > off);
			off = noff;
			pp = pp_lookup(nprid);
		} else {
			pp = NULL;
		}
	} while (pp);

	return 0;

err:
	pdu_clear(root);
	errno = errval;
	return -1;
}


int pdu_get_spec(uint prid, struct pdu *pdu, int flags, struct pduspec *ps)
{
	const struct proto_parser *pp;
	struct pdu dummy;
	int rv;

	if (!pdu || !ps) {
		errno = EINVAL;
		return -1;
	}

	pp = pp_lookup(prid);
	if (!pp) {
		errno = ENOTSUP;
		return -1;
	}

	/* If we are wrapping an empty data block, treat the payload */
	/* as an embedded none-type parse to wrap around and pop afterwards. */
	if (((flags == PDU_GSF_WRAPPDU) && pdu_empty(pdu)) ||
	    (flags == PDU_GSF_WRAPPLD)) {
		root_init(&dummy, pdu_poff(pdu), 0, pdu_plen(pdu), 0);
		dummy.region = pdu;
		pdu_insert(pdu, &dummy);
		pdu = &dummy;
	}

	rv = (*pp->ops->getspec)(pdu, flags != PDU_GSF_APPEND, ps);

	if (pdu == &dummy)
		pdu_remove(&dummy);

	return rv;
}


int pdu_add(struct pdu *reg, byte_t *buf, struct pduspec *ps, int enclose)
{
	const struct proto_parser *pp;
	ulong len;

	if (!reg || !ps || (ps->off == PDU_OFF_INVALID) ||
	    (pp = pp_lookup(ps->prid)) == NULL)
		goto errout;

	/* carefully bounds check the offset and length fields */
	abort_unless(ps->off <= PDU_OFF_MAX);
	if (ps->hlen > PDU_OFF_MAX - ps->off)
		goto errout;
	len = ps->off + ps->hlen;
	if (ps->plen > PDU_OFF_MAX - len)
		goto errout;
	len += ps->plen;
	if (ps->tlen > PDU_OFF_MAX - len)
		goto errout;

	/* TODO: check that new parse fits within the given region? */
	if ((*pp->ops->add)(reg, buf, ps, enclose) < 0)
		goto errout;

	return 0;

errout:
	errno = EINVAL;
	return -1;

}


/* clear from back to front */
void pdu_clear(struct pdu *pdu)
{
	struct pdu *next, *prev;
	abort_unless(pdu && pdu->region == NULL);
	for (next = pdu_prev(pdu); next != pdu; next = prev) {
		abort_unless(next->ops && next->ops->free);
		prev = pdu_prev(next);
		l_rem(&next->node);
		(*next->ops->free)(next);
	}
}


void pdu_remove(struct pdu *pdu)
{
	struct pdu *next;
	if (!pdu)
		return;
	abort_unless(pdu->region != NULL);
	for (next = pdu_next_in_region(pdu, pdu); next != NULL;
	     next = pdu_next_in_region(next, pdu))
		next->region = pdu->region;
	l_rem(&pdu->node);
}


void pdu_free_parse(struct pdu *pdu)
{
	struct pdu *next;
	if (!pdu)
		return;
	abort_unless(pdu->region != NULL);
	abort_unless(pdu->ops && pdu->ops->free);
	for (next = pdu_next_in_region(pdu, pdu); next != NULL;
	     next = pdu_next_in_region(next, pdu))
		next->region = pdu->region;
	l_rem(&pdu->node);
	(*pdu->ops->free)(pdu);
}


static int parse_in_region(struct pdu *pdu, struct pdu *reg)
{
	struct pdu *t = pdu->region;
	while (t != NULL) {
		if (t == reg)
			return 1;
		t = t->region;
	}
	return 0;
}


/* This can be more elegantly coded with a recursive solution.  */
/* However, the hope is that this library could be used in a stack- */
/* constrained environment.  So, for now we prefer to do it */
/* iteratively.  */
void pdu_free_region(struct pdu *pdu)
{
	struct pdu *trav, *hold;

	if (pdu == NULL)
		return;
	if (pdu->region == NULL) {
		pdu_clear(pdu);
		return;
	}

	/* find the last node potentially in the region */
	hold = NULL;
	trav = pdu_next(pdu);
	while (!pdu_list_end(trav) && (pdu_soff(trav) <= pdu_eoff(pdu))) {
		hold = trav;
		trav = pdu_next(trav);
	}
	if (hold == NULL)
		trav = pdu;
	else
		trav = hold;

	/* work backwards from last node potentially in the region */
	/* This is because working backwards we cannot delete a node */
	/* that might have a dangling region reference. */
	while (trav != pdu) {
		hold = pdu_prev(trav);
		if (parse_in_region(trav, pdu)) {
			abort_unless(trav->ops && trav->ops->free);
			l_rem(&trav->node);
			(*trav->ops->free)(trav);
		}
		trav = hold;
	}

	abort_unless(pdu->ops && pdu->ops->free);
	l_rem(&pdu->node);
	(*pdu->ops->free)(pdu);
}


int pdu_copy(struct pdu *npdu, struct pdu *opdu)
{
	struct pdu *trav, *last, *apdu, *oreg, *nreg;
	int errval;

	if (!npdu || !opdu || opdu->region != NULL) {
		errno = EINVAL;
		return -1;
	}

	*npdu = *opdu;
	l_init(&npdu->node);

	for (last = npdu, trav = pdu_next(opdu); !pdu_list_end(trav);
	     last = apdu, trav = pdu_next(trav)) {
		abort_unless(opdu->ops && opdu->ops->copy);
		if (!(apdu = (*trav->ops->copy)(trav))) {
			errval = errno;
			goto err;
		}
		l_ins(&last->node, &apdu->node);
	}

	/* patch up regions: recall that each parse (except the root parse) */
	/* MUST have a region that comes before it in the list. */
	for (apdu = pdu_next(npdu), trav = pdu_next(opdu);
	     !pdu_list_end(trav);
	     apdu = pdu_next(apdu), trav = pdu_next(trav)) {
		oreg = pdu_prev(trav);
		nreg = pdu_prev(apdu);
		abort_unless(trav->region != NULL);
		while (oreg != trav->region) {
			abort_unless(oreg != NULL);
			oreg = pdu_prev(oreg);
			nreg = pdu_prev(nreg);
		}
		apdu->region = nreg;
	}

	return 0;

err:
	pdu_clear(apdu);
	errno = errval;
	return -1;
}


uint pdu_update(struct pdu *pdu, byte_t *buf)
{
	abort_unless(pdu && pdu->ops && pdu->ops->update);
	(*pdu->ops->update)(pdu, buf);
	return pdu->error;
}


int pdu_fix_nxthdr(struct pdu *pdu, byte_t *buf)
{
	abort_unless(pdu && pdu->ops && pdu->ops->fixcksum);
	return (*pdu->ops->fixnxt)(pdu, buf);
}


int pdu_fix_len(struct pdu *pdu, byte_t *buf)
{
	abort_unless(pdu && pdu->ops && pdu->ops->fixlen);
	return (*pdu->ops->fixlen)(pdu, buf);
}


int pdu_fix_cksum(struct pdu *pdu, byte_t *buf)
{
	abort_unless(pdu && pdu->ops && pdu->ops->fixcksum);
	return (*pdu->ops->fixcksum)(pdu, buf);
}


/*
 * Find the lowest lower bound in the contained region and the
 * highest upper bound contained in the region.  If there are
 * no contained region it returns high = region starting offset
 * and low = region ending offset.  So one can test for this
 * condition by checking on return whether low >= high.
 */
static void ubounds(struct pdu *reg, ulong *low, ulong *high)
{
	ulong uend = 0;
	struct pdu *pdu;

	abort_unless(reg && low && high);

	pdu = pdu_next_in_region(reg, reg);
	if (pdu == NULL) {
		/* zero parses in region */
		*low = pdu_eoff(reg);
		*high = pdu_soff(reg);
	} else {
		/* at least one parse in the region */
		*low = pdu_soff(pdu);
		for (; pdu != NULL; pdu = pdu_next_in_region(pdu, reg))
			if (pdu_eoff(pdu) > uend)
				uend = pdu_eoff(pdu);
		abort_unless(*low <= uend);
		*high = uend;
	}
}


int pdu_inject(struct pdu *pdu, byte_t *buf, ulong off, ulong len, int moveup)
{
	byte_t *op, *np;
	ulong mlen;
	uint i;

	if (pdu == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (off > pdu_totlen(pdu)) {
		errno = EINVAL;
		return -1;
	}
	off += pdu_soff(pdu); /* make offset relative to parse header */

	/* get the root region */
	while (pdu->region != NULL)
		pdu = pdu->region;

	if (moveup) {
		if ((off > pdu_toff(pdu)) || (len > pdu_tlen(pdu))) {
			errno = EINVAL;
			return -1;
		}

		if (buf != NULL) {
			op = buf + off;
			np = op + len;
			mlen = pdu_toff(pdu) - off;
			memmove(np, op, mlen);
			memset(op, 'U', len);
		}

		pdu_toff(pdu) += len;

		for (pdu = pdu_next(pdu);
		     !pdu_list_end(pdu);
		     pdu = pdu_next(pdu)) {
			if (pdu_eoff(pdu) < off)
				continue;
			for (i = 0; i < pdu->noff; ++i) {
				if ((pdu->offs[i] != PDU_OFF_INVALID) &&
				    (pdu->offs[i] >= off))
					pdu->offs[i] += len;
			}
		}
	} else {
		if ((off < pdu_poff(pdu)) || (len > pdu_hlen(pdu))) {
			errno = EINVAL;
			return -1;
		}

		if (buf != NULL) {
			op = buf + pdu_poff(pdu);
			np = op - len;
			mlen = off - pdu_poff(pdu);
			memmove(np, op, mlen);
			memset(buf + off - len, 'D', len);
		}

		pdu_poff(pdu) -= len;
		for (pdu = pdu_next(pdu);
		     !pdu_list_end(pdu);
		     pdu = pdu_next(pdu)) {
			if (pdu_soff(pdu) >= off)
				continue;
			for (i = 0; i < pdu->noff; ++i) {
				if ((pdu->offs[i] != PDU_OFF_INVALID) &&
				    (pdu->offs[i] < off))
					pdu->offs[i] -= len;
			}
		}
	}

	return 0;
}


int pdu_cut(struct pdu *pdu, byte_t *buf, ulong off, ulong len, int moveup)
{
	byte_t *op, *np;
	ulong mlen;
	uint i;

	if (pdu == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (off > pdu_totlen(pdu)) {
		errno = EINVAL;
		return -1;
	}
	off += pdu_soff(pdu);	/* make offset relative to parse */

	/* get the root region */
	while (pdu->region != NULL)
		pdu = pdu->region;

	if ((off < pdu_poff(pdu)) || (off >= pdu_toff(pdu)) ||
	    (len > pdu_toff(pdu) - off)) {
		errno = EINVAL;
		return -1;
	}

	if (moveup) {
		if (buf != NULL) {
			op = buf + pdu_poff(pdu);
			mlen = off - pdu_poff(pdu);
			np = buf + off + len - mlen;
			memmove(np, op, mlen);
			memset(op, 0x3C, len);
		}

		pdu_poff(pdu) += len;
		for (pdu = pdu_next(pdu);
		     !pdu_list_end(pdu);
		     pdu = pdu_next(pdu)) {
			for (i = 0; i < pdu->noff; ++i) {
				if ((pdu->offs[i] != PDU_OFF_INVALID)
				    && (pdu->offs[i] < off + len)) {
					if (pdu->offs[i] < off)
						pdu->offs[i] += len;
					else
						pdu->offs[i] = off + len;
				}
			}
		}
	} else {
		if (buf != NULL) {
			np = buf + off;
			op = np + len;
			mlen = pdu_toff(pdu) - off - len;
			memmove(np, op, mlen);
			memset(np + mlen, 0x2D, len);
		}

		pdu_toff(pdu) -= len;
		for (pdu = pdu_next(pdu);
		     !pdu_list_end(pdu);
		     pdu = pdu_next(pdu)) {
			for (i = 0; i < pdu->noff; ++i) {
				if ((pdu->offs[i] != PDU_OFF_INVALID)
				    && (pdu->offs[i] >= off)) {
					if (pdu->offs[i] >= off + len)
						pdu->offs[i] -= len;
					else
						pdu->offs[i] = off;
				}
			}
		}
	}

	return 0;
}


int pdu_adj_off(struct pdu *pdu, uint oid, long amt)
{
	struct pdu *reg;
	struct pdu *trav;
	long newoff, blo, bhi;


	if (!pdu || (oid >= pdu->noff)) {
		errno = EINVAL;
		return -1;
	}

	reg = pdu->region;

	newoff = pdu->offs[oid] + (ulong)amt;

	switch (oid) {
	case PDU_OI_SOFF:
		if (reg == NULL)
			blo = 0;
		else
			blo = pdu_soff(reg);
		bhi = pdu_poff(pdu);
		break;
	case PDU_OI_POFF:
		blo = pdu_soff(pdu);
		bhi = pdu_toff(pdu);
		break;
	case PDU_OI_TOFF:
		blo = pdu_poff(pdu);
		bhi = pdu_eoff(pdu);
		break;
	case PDU_OI_EOFF:
		blo = pdu_toff(pdu);
		if (reg == NULL)
			bhi = LONG_MAX;
		else
			bhi = pdu_eoff(reg);
		break;
	default:
		blo = pdu_soff(pdu);
		bhi = pdu_eoff(pdu);
	}

	abort_unless(blo >= 0 && bhi >= 0);
	if ((newoff < blo) || (newoff > bhi))
		return -2;

	pdu->offs[oid] = newoff;

	/* may need to adjust list placement */
	if ((oid == PDU_OI_SOFF) && (reg != NULL)) {
		trav = pdu_prev(pdu);
		if (pdu_soff(pdu) < pdu_soff(trav)) {
			l_rem(&pdu->node);
			do {
				trav = pdu_prev(trav);
			} while (pdu_soff(pdu) < pdu_soff(trav));
			l_ins(&trav->node, &pdu->node);
		} else {
			trav = pdu_next(pdu);
			if (!pdu_list_end(trav)
			    && (pdu_soff(pdu) > pdu_soff(trav))) {
				l_rem(&pdu->node);
				do {
					trav = pdu_next(trav);
				} while (!pdu_list_end(trav)
					 && (pdu_soff(pdu) > pdu_soff(trav)));
				l_ins(trav->node.prev, &pdu->node);
			}
		}
	}

	return 0;
}


int pdu_adj_plen(struct pdu *pdu, long amt)
{
	int rv;

	/* Note: if we move the trailer offset down successfully there should */
	/* be no reason we can't move the end offset down as well. This works */
	/* in reverse for moving the end and trailer offsets forward.  */
	if (amt < 0) {
		if (pdu_adj_off(pdu, PDU_OI_TOFF, amt) < 0)
			return -2;
		rv = pdu_adj_off(pdu, PDU_OI_EOFF, amt);
		abort_unless(rv >= 0);
	} else {
		if (pdu_adj_off(pdu, PDU_OI_EOFF, amt) < 0)
			return -2;
		rv = pdu_adj_off(pdu, PDU_OI_TOFF, amt);
		abort_unless(rv >= 0);
	}

	return 0;
}


int pdu_adj_unused(struct pdu *reg)
{
	ulong ustart, uend;

	if (!reg) {
		errno = EINVAL;
		return -1;
	}

	ubounds(reg, &ustart, &uend);
	if (ustart >= uend) {
		pdu_poff(reg) = pdu_soff(reg);
		pdu_toff(reg) = pdu_eoff(reg);
	} else {
		pdu_poff(reg) = ustart;
		pdu_toff(reg) = uend;
	}

	return 0;
}


void pdu_add_insert(struct pdu *reg, struct pdu *pdu, int enclose)
{
	struct pdu *trav;
	pdu->region = reg;

	/* inserts at earliest possition in list for its offset */
	/* within the region */
	pdu_insert(reg, pdu);

	if (enclose) {
		/* for all parses in the region that are enclosed in the */
		/* new parse (offset/length-wise), make them point to */
		/* the new parse as their region.  */
		for (trav = pdu_next_in_region(pdu, reg);
		     trav != NULL;
		     trav = pdu_next_in_region(trav, reg)) {
			if (pdu_eoff(trav) <= pdu_eoff(pdu))
				trav->region = pdu;
		}
	}
}



void pdu_init(struct pdu *pdu, uint prid, ulong off, ulong hlen, ulong plen,
	      ulong tlen, struct pdu_ops *ops, struct pdu *reg,
	      uint nxfields)
{
	pdu->prid = prid;
	pdu->error = 0;
	pdu_soff(pdu) = off;
	pdu_poff(pdu) = off + hlen;
	pdu_toff(pdu) = off + hlen + plen;
	pdu_eoff(pdu) = off + hlen + plen + tlen;
	abort_unless(pdu_soff(pdu) >= 0 && pdu_poff(pdu) >= pdu_soff(pdu) &&
		     pdu_toff(pdu) >= pdu_poff(pdu) &&
		     pdu_eoff(pdu) >= pdu_toff(pdu));
	pdu->ops = ops;
	l_init(&pdu->node);
	pdu->region = reg;
	pdu->noff = PDU_OI_MIN_NUM + nxfields;
	pdu_reset_xfields(pdu);
}


void pdu_reset_xfields(struct pdu *pdu)
{
	uint i;
	for (i = PDU_OI_EXTRA; i < pdu->noff; ++i)
		pdu->offs[i] = PDU_OFF_INVALID;
}


int pduspec_init(struct pduspec *ps, struct pdu *pdu, uint prid, uint hlen,
		 uint tlen, int enclose)
{
	ps->prid = prid;
	ps->hlen = hlen;
	ps->tlen = tlen;
	if (enclose) {
		if (pdu_soff(pdu) < hlen) {
			errno = ENOSPC;
			return -1;
		}
		ps->off = pdu_soff(pdu) - hlen;
		ps->plen = pdu_totlen(pdu);
	} else {
		if (pdu_plen(pdu) < hlen + tlen) {
			errno = ENOSPC;
			return -1;
		}
		ps->off = pdu_poff(pdu);
		ps->plen = pdu_plen(pdu) - hlen - tlen;
	}
	return 0;
}


void pdu_nop_update(struct pdu *pdu, byte_t *buf)
{
	/* do nothing */
}


int pdu_nop_fixnxt(struct pdu *pdu, byte_t *buf)
{
	return 0; /* return success */
}


int pdu_nop_fixlen(struct pdu *pdu, byte_t *buf)
{
	return 0; /* return success */
}


int pdu_nop_fixcksum(struct pdu *pdu, byte_t *buf)
{
	return 0; /* return success */
}


struct pdu *pdu_nop_copy(struct pdu *opdu)
{
	return NULL;  /* this we can't do without help */
}


void pdu_nop_free(struct pdu *pdu)
{
	/* do nothing */
}
