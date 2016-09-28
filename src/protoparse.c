/*
 * ONICS
 * Copyright 2012-2016
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
static void base_init(struct prparse *prp, ulong off, ulong hlen, ulong plen, 
		      ulong tlen);
static struct prparse *new_prp(struct prpspec *ps, struct prparse_ops *ops);
static int mkspec(struct prparse *prp, int enclose, uint prid,
		  struct prpspec *ps);

static int nxtcld_fail(struct prparse *reg, byte_t *buf, struct prparse *cld,
		       uint *prid, ulong *off, ulong *maxlen);


/* parse callbacks for PRID_NONE */
static struct prparse *none_parse(struct prparse *reg, byte_t *buf, ulong off,
				  ulong maxlen);
static int none_getspec(struct prparse *prp, int enclose, struct prpspec *ps);
static int none_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		    int enclose);
				
static struct proto_parser_ops none_proto_parser_ops = {
	none_parse,
	nxtcld_fail,
	none_getspec,
	none_add,
};


/* parse callbacks for PRID_DATA and PRID_RAWPKT */
static struct prparse *data_parse(struct prparse *reg, byte_t *buf, ulong off,
				  ulong maxlen);
static int data_getspec(struct prparse *prp, int enclose, struct prpspec *ps);
static int data_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
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


/* -- ops for "NONE", "NONE base" and "DATA" and "RAWPKT" protocol type -- */

static struct prparse *default_copy(struct prparse *oprp);
static void default_free(struct prparse *prp);
static struct prparse *base_copy(struct prparse *oprp);
static void base_free(struct prparse *prp);

static struct prparse_ops none_prparse_ops = {
	prp_nop_update,
	prp_nop_fixnxt,
	prp_nop_fixlen,
	prp_nop_fixcksum,
	default_copy,
	default_free
};


static struct prparse_ops data_prparse_ops = {
	prp_nop_update,
	prp_nop_fixnxt,
	prp_nop_fixlen,
	prp_nop_fixcksum,
	default_copy,
	default_free
};


static struct prparse_ops base_prparse_ops = {
	prp_nop_update,
	prp_nop_fixnxt,
	prp_nop_fixlen,
	prp_nop_fixcksum,
	base_copy,
	base_free
};

/* -- Various helper functions -- */
static void base_init(struct prparse *prp, ulong off, ulong hlen, ulong plen, 
		      ulong tlen)
{
	prp->prid = PRID_NONE;
	prp->error = 0;
	prp->ops = &base_prparse_ops;
	l_init(&prp->node);
	prp->region = NULL;
	prp->noff = PRP_OI_MIN_NUM;
	prp_soff(prp) = off;
	prp_poff(prp) = prp_soff(prp) + hlen;
	prp_toff(prp) = prp_poff(prp) + plen;
	prp_eoff(prp) = prp_toff(prp) + tlen;
	abort_unless(prp_soff(prp) <= prp_poff(prp));
	abort_unless(prp_poff(prp) <= prp_toff(prp));
	abort_unless(prp_toff(prp) <= prp_eoff(prp));
}


static struct prparse *new_prp(struct prpspec *ps, struct prparse_ops *ops)
{
	struct prparse *prp;

	prp = malloc(sizeof(*prp));
	if (!prp)
		return NULL;

	prp->prid = ps->prid;
	prp->error = 0;
	prp->ops = ops;
	l_init(&prp->node);
	prp->region = NULL;
	prp->noff = PRP_OI_MIN_NUM;
	prp_soff(prp) = ps->off;
	prp_poff(prp) = prp_soff(prp) + ps->hlen;
	prp_toff(prp) = prp_poff(prp) + ps->plen;
	prp_eoff(prp) = prp_toff(prp) + ps->tlen;
	abort_unless(prp_soff(prp) <= prp_poff(prp));
	abort_unless(prp_poff(prp) <= prp_toff(prp));
	abort_unless(prp_toff(prp) <= prp_eoff(prp));

	return prp;
}


static int nxtcld_fail(struct prparse *reg, byte_t *buf, struct prparse *cld,
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


static int mkspec(struct prparse *prp, int enclose, uint prid,
		  struct prpspec *ps)
{
	ps->prid = prid;
	if (enclose) {
		ps->off = prp_soff(prp);
		ps->hlen = 0;
		ps->plen = prp_totlen(prp);
		ps->tlen = 0;
	} else {
		ps->off = prp_poff(prp);
		ps->hlen = 0;
		ps->plen = prp_plen(prp);
		ps->tlen = 0;
	}

	return 0;
}


/* -- NONE and NONE base parser functions -- */
static struct prparse *none_parse(struct prparse *reg, byte_t *buf,
				  ulong off, ulong maxlen)
{
	struct prparse *prp;
	struct prpspec ps;

	abort_unless(reg);
	(void)buf;

	ps.prid = PRID_NONE;
	ps.off = off;
	ps.hlen = 0;
	ps.plen = maxlen;
	ps.tlen = 0;
	prp = new_prp(&ps, &none_prparse_ops);
	if (prp != NULL)
		prp->region = reg;
	return prp;
}


static int none_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return mkspec(prp, enclose, PRID_NONE, ps);
}


static int none_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		    int enclose)
{
	struct prparse *prp;
	(void)buf;
	abort_unless(ps);
	ps->prid = PRID_NONE;
	prp = new_prp(ps, &none_prparse_ops);
	if (!prp)
		return -1;
	prp_add_insert(reg, prp, enclose);
	return 0;
}


/* -- DATA and RAWPKT parser functions -- */
static struct prparse *data_parse(struct prparse *reg, byte_t *buf, ulong off,
				  ulong maxlen)
{
	struct prparse *prp;
	struct prpspec ps;

	abort_unless(reg);
	(void)buf;

	ps.prid = PRID_DATA;
	ps.off = off;
	ps.hlen = 0;
	ps.plen = maxlen;
	ps.tlen = 0;
	prp = new_prp(&ps, &none_prparse_ops);
	if (prp != NULL)
		prp->region = reg;
	return prp;
}


static int data_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return mkspec(prp, enclose, PRID_DATA, ps);
}


static int data_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		    int enclose)
{
	struct prparse *prp;
	(void)buf;
	abort_unless(ps);
	ps->prid = PRID_DATA;
	prp = new_prp(ps, &data_prparse_ops);
	if (!prp)
		return -1;
	prp_add_insert(reg, prp, enclose);
	return 0;
}


/* -- default prparse handlers -- */
static struct prparse *default_copy(struct prparse *oprp)
{
	struct prpspec ps;
	ps.prid = oprp->prid;
	ps.off = prp_soff(oprp);
	ps.hlen = prp_hlen(oprp);
	ps.plen = prp_plen(oprp);
	ps.tlen = prp_tlen(oprp);
	return new_prp(&ps, oprp->ops);
			
}


static void default_free(struct prparse *prp)
{
	free(prp);
}


static struct prparse *base_copy(struct prparse *oprp)
{
	return NULL;
}


static void base_free(struct prparse *prp)
{
	abort_unless(0);
}


/* -- Protocol Parse Functions -- */
struct prparse *prp_get_base(struct prparse *prp)
{
	while (prp->region != NULL)
		prp = prp->region;
	return prp;
}


struct prparse *prp_next_in_region(struct prparse *from, struct prparse *reg)
{
	struct prparse *prp;
	abort_unless(from && reg);
	for (prp = prp_next(from);
	     !prp_list_end(prp) && (prp_soff(prp) <= prp_eoff(reg));
	     prp = prp_next(prp)) {
		if (prp->region == reg)
			return prp;
	}
	return NULL;
}


int prp_region_empty(struct prparse *reg)
{
	abort_unless(reg);
	return (prp_next_in_region(reg, reg) == NULL);
}


void prp_init_parse_base(struct prparse *base, ulong len)
{
	abort_unless(base && (len >= 0));
	base_init(base, 0, 0, len, 0);
}


void prp_insert_parse(struct prparse *from, struct prparse *toins)
{
	struct prparse *last = from, *next;
	/* search for first node in list with a starting offset */
	/* greater than or equal to the offset of this prparse */
	for (next = prp_next(last);
	     !prp_list_end(next) && prp_soff(next) < prp_soff(toins);
	     last = next, next = prp_next(next)) ;
	l_ins(&last->node, &toins->node);
}


int prp_parse_packet(struct prparse *base, byte_t *buf, uint nprid)
{
	struct prparse *prp, *last, *reg;
	const struct proto_parser *pp;
	int errval, rv;
	ulong off, maxlen, noff;

	pp = pp_lookup(nprid);
	if (!base || base->prid != PRID_NONE || !pp) {
		errno = EINVAL;
		return -1;
	}

	off = prp_poff(base);
	maxlen = prp_plen(base);
	prp = base;

	do {
		last = prp;
		if (!(prp = (*pp->ops->parse)(last, buf, off, maxlen))) {
			errval = errno;
			goto err;
		}
		prp_insert_parse(last, prp);

		/* don't continue parsing if the lengths are screwed up */
		if ((prp->error & PRP_ERR_HLENMASK) || !prp_plen(prp))
			break;

		reg = NULL;
		rv = (*pp->ops->nxtcld)(prp, buf, NULL, &nprid, &noff, &maxlen);
		if (!rv) {
			/* if the new parse does not have a child, then */
			/* start going up the enclosing regions testing */
			/* for a new child in each region passing the */
			/* new parse to provide the position information */
			/* for determining the presence of a new child. */
			reg = prp->region;
			while (reg != NULL) {
				pp = pp_lookup(reg->prid);
				abort_unless(pp);
				rv = (*pp->ops->nxtcld)(reg, buf, prp, &nprid,
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
	prp_clear(base);
	errno = errval;
	return -1;
}


int prp_get_spec(uint prid, struct prparse *prp, int flags, struct prpspec *ps)
{
	const struct proto_parser *pp;
	struct prparse dummy;
	int rv;

	if (!prp || !ps) {
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
	if (((flags == PRP_GSF_WRAPPRP) && prp_empty(prp)) ||
	    (flags == PRP_GSF_WRAPPLD)) {
		base_init(&dummy, prp_poff(prp), 0, prp_plen(prp), 0);
		dummy.region = prp;
		prp_insert_parse(prp, &dummy);
		prp = &dummy;
	}

	rv = (*pp->ops->getspec)(prp, flags != PRP_GSF_APPEND, ps);

	if (prp == &dummy)
		prp_remove_parse(&dummy);

	return rv;
}


int prp_add(struct prparse *reg, byte_t *buf, struct prpspec *ps, int enclose)
{
	const struct proto_parser *pp;
	ulong len;

	if (!reg || !ps || (ps->off == PRP_OFF_INVALID) ||
	    (pp = pp_lookup(ps->prid)) == NULL)
		goto errout;

	/* carefully bounds check the offset and length fields */
	abort_unless(ps->off <= PRP_OFF_MAX);
	if (ps->hlen > PRP_OFF_MAX - ps->off)
		goto errout;
	len = ps->off + ps->hlen;
	if (ps->plen > PRP_OFF_MAX - len)
		goto errout;
	len += ps->plen;
	if (ps->tlen > PRP_OFF_MAX - len)
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
void prp_clear(struct prparse *prp)
{
	struct prparse *next, *prev;
	abort_unless(prp && prp->region == NULL);
	for (next = prp_prev(prp); next != prp; next = prev) {
		abort_unless(next->ops && next->ops->free);
		prev = prp_prev(next);
		l_rem(&next->node);
		(*next->ops->free)(next);
	}
}


void prp_remove_parse(struct prparse *prp)
{
	struct prparse *next;
	if (!prp)
		return;
	abort_unless(prp->region != NULL);
	for (next = prp_next_in_region(prp, prp); next != NULL;
	     next = prp_next_in_region(next, prp))
		next->region = prp->region;
	l_rem(&prp->node);
}


void prp_free_parse(struct prparse *prp)
{
	struct prparse *next;
	if (!prp)
		return;
	abort_unless(prp->region != NULL);
	abort_unless(prp->ops && prp->ops->free);
	for (next = prp_next_in_region(prp, prp); next != NULL;
	     next = prp_next_in_region(next, prp))
		next->region = prp->region;
	l_rem(&prp->node);
	(*prp->ops->free)(prp);
}


static int parse_in_region(struct prparse *prp, struct prparse *reg)
{
	struct prparse *t = prp->region;
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
void prp_free_region(struct prparse *prp)
{
	struct prparse *trav, *hold;

	if (prp == NULL)
		return;
	if (prp->region == NULL) {
		prp_clear(prp);
		return;
	}

	/* find the last node potentially in the region */
	hold = NULL;
	trav = prp_next(prp);
	while (!prp_list_end(trav) && (prp_soff(trav) <= prp_eoff(prp))) {
		hold = trav;
		trav = prp_next(trav);
	}
	if (hold == NULL)
		trav = prp;
	else
		trav = hold;

	/* work backwards from last node potentially in the region */
	/* This is because working backwards we cannot delete a node */
	/* that might have a dangling region reference. */
	while (trav != prp) {
		hold = prp_prev(trav);
		if (parse_in_region(trav, prp)) {
			abort_unless(trav->ops && trav->ops->free);
			l_rem(&trav->node);
			(*trav->ops->free)(trav);
		}
		trav = hold;
	}

	abort_unless(prp->ops && prp->ops->free);
	l_rem(&prp->node);
	(*prp->ops->free)(prp);
}


int prp_copy(struct prparse *nprp, struct prparse *oprp)
{
	struct prparse *trav, *last, *aprp, *oreg, *nreg;
	int errval;

	if (!nprp || !oprp || oprp->region != NULL) {
		errno = EINVAL;
		return -1;
	}

	*nprp = *oprp;
	l_init(&nprp->node);

	for (last = nprp, trav = prp_next(oprp); !prp_list_end(trav);
	     last = aprp, trav = prp_next(trav)) {
		abort_unless(oprp->ops && oprp->ops->copy);
		if (!(aprp = (*trav->ops->copy)(trav))) {
			errval = errno;
			goto err;
		}
		l_ins(&last->node, &aprp->node);
	}

	/* patch up regions: recall that each parse (except the root parse) */
	/* MUST have a region that comes before it in the list. */
	for (aprp = prp_next(nprp), trav = prp_next(oprp);
	     !prp_list_end(trav);
	     aprp = prp_next(aprp), trav = prp_next(trav)) {
		oreg = prp_prev(trav);
		nreg = prp_prev(aprp);
		abort_unless(trav->region != NULL);
		while (oreg != trav->region) {
			abort_unless(oreg != NULL);
			oreg = prp_prev(oreg);
			nreg = prp_prev(nreg);
		}
		aprp->region = nreg;
	}

	return 0;

err:
	prp_clear(aprp);
	errno = errval;
	return -1;
}


uint prp_update(struct prparse *prp, byte_t *buf)
{
	abort_unless(prp && prp->ops && prp->ops->update);
	(*prp->ops->update)(prp, buf);
	return prp->error;
}


int prp_fix_nxthdr(struct prparse *prp, byte_t *buf)
{
	abort_unless(prp && prp->ops && prp->ops->fixcksum);
	return (*prp->ops->fixnxt)(prp, buf);
}


int prp_fix_len(struct prparse *prp, byte_t *buf)
{
	abort_unless(prp && prp->ops && prp->ops->fixlen);
	return (*prp->ops->fixlen)(prp, buf);
}


int prp_fix_cksum(struct prparse *prp, byte_t *buf)
{
	abort_unless(prp && prp->ops && prp->ops->fixcksum);
	return (*prp->ops->fixcksum)(prp, buf);
}


/* 
 * Find the lowest lower bound in the contained region and the 
 * highest upper bound contained in the region.  If there are
 * no contained region it returns high = region starting offset
 * and low = region ending offset.  So one can test for this
 * condition by checking on return whether low >= high.
 */
static void ubounds(struct prparse *reg, ulong *low, ulong *high)
{
	ulong uend = 0;
	struct prparse *prp;

	abort_unless(reg && low && high);

	prp = prp_next_in_region(reg, reg);
	if (prp == NULL) {
		/* zero parses in region */
		*low = prp_eoff(reg);
		*high = prp_soff(reg);
	} else {
		/* at least one parse in the region */
		*low = prp_soff(prp);
		for (; prp != NULL; prp = prp_next_in_region(prp, reg))
			if (prp_eoff(prp) > uend)
				uend = prp_eoff(prp);
		abort_unless(*low <= uend);
		*high = uend;
	}
}


int prp_insert(struct prparse *prp, byte_t *buf, ulong off, ulong len,
	       int moveup)
{
	byte_t *op, *np;
	ulong mlen;
	uint i;

	if (prp == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (off > prp_totlen(prp)) {
		errno = EINVAL;
		return -1;
	}
	off += prp_soff(prp); /* make offset relative to parse header */

	/* get the root region */
	while (prp->region != NULL)
		prp = prp->region;

	if (moveup) {
		if ((off > prp_toff(prp)) || (len > prp_tlen(prp))) {
			errno = EINVAL;
			return -1;
		}

		if (buf != NULL) {
			op = buf + off;
			np = op + len;
			mlen = prp_toff(prp) - off;
			memmove(np, op, mlen);
			memset(op, 'U', len);
		}

		prp_toff(prp) += len;

		for (prp = prp_next(prp); 
		     !prp_list_end(prp); 
		     prp = prp_next(prp)) {
			if (prp_eoff(prp) < off)
				continue;
			for (i = 0; i < prp->noff; ++i) {
				if ((prp->offs[i] != PRP_OFF_INVALID) &&
				    (prp->offs[i] >= off))
					prp->offs[i] += len;
			}
		}
	} else {
		if ((off < prp_poff(prp)) || (len > prp_hlen(prp))) {
			errno = EINVAL;
			return -1;
		}

		if (buf != NULL) {
			op = buf + prp_poff(prp);
			np = op - len;
			mlen = off - prp_poff(prp);
			memmove(np, op, mlen);
			memset(buf + off - len, 'D', len);
		}

		prp_poff(prp) -= len;
		for (prp = prp_next(prp); 
		     !prp_list_end(prp); 
		     prp = prp_next(prp)) {
			if (prp_soff(prp) >= off)
				continue;
			for (i = 0; i < prp->noff; ++i) {
				if ((prp->offs[i] != PRP_OFF_INVALID) &&
				    (prp->offs[i] < off))
					prp->offs[i] -= len;
			}
		}
	}

	return 0;
}


int prp_cut(struct prparse *prp, byte_t *buf, ulong off, ulong len, int moveup)
{
	byte_t *op, *np;
	ulong mlen;
	uint i;

	if (prp == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (off > prp_totlen(prp)) {
		errno = EINVAL;
		return -1;
	}
	off += prp_soff(prp);	/* make offset relative to parse */

	/* get the root region */
	while (prp->region != NULL)
		prp = prp->region;

	if ((off < prp_poff(prp)) || (off >= prp_toff(prp)) ||
	    (len > prp_toff(prp) - off)) {
		errno = EINVAL;
		return -1;
	}

	if (moveup) {
		if (buf != NULL) {
			op = buf + prp_poff(prp);
			mlen = off - prp_poff(prp);
			np = buf + off + len - mlen;
			memmove(np, op, mlen);
			memset(op, 0x3C, len);
		}

		prp_poff(prp) += len;
		for (prp = prp_next(prp);
		     !prp_list_end(prp); 
		     prp = prp_next(prp)) {
			for (i = 0; i < prp->noff; ++i) {
				if ((prp->offs[i] != PRP_OFF_INVALID)
				    && (prp->offs[i] < off + len)) {
					if (prp->offs[i] < off)
						prp->offs[i] += len;
					else
						prp->offs[i] = off + len;
				}
			}
		}
	} else {
		if (buf != NULL) {
			np = buf + off;
			op = np + len;
			mlen = prp_toff(prp) - off - len;
			memmove(np, op, mlen);
			memset(np + mlen, 0x2D, len);
		}

		prp_toff(prp) -= len;
		for (prp = prp_next(prp);
		     !prp_list_end(prp); 
		     prp = prp_next(prp)) {
			for (i = 0; i < prp->noff; ++i) {
				if ((prp->offs[i] != PRP_OFF_INVALID)
				    && (prp->offs[i] >= off)) {
					if (prp->offs[i] >= off + len)
						prp->offs[i] -= len;
					else
						prp->offs[i] = off;
				}
			}
		}
	}

	return 0;
}


int prp_adj_off(struct prparse *prp, uint oid, long amt)
{
	struct prparse *reg;
	struct prparse *trav;
	long newoff, blo, bhi;


	if (!prp || (oid >= prp->noff)) {
		errno = EINVAL;
		return -1;
	}

	reg = prp->region;

	newoff = prp->offs[oid] + (ulong)amt;

	switch (oid) {
	case PRP_OI_SOFF:
		if (reg == NULL)
			blo = 0;
		else
			blo = prp_soff(reg);
		bhi = prp_poff(prp);
		break;
	case PRP_OI_POFF:
		blo = prp_soff(prp);
		bhi = prp_toff(prp);
		break;
	case PRP_OI_TOFF:
		blo = prp_poff(prp);
		bhi = prp_eoff(prp);
		break;
	case PRP_OI_EOFF:
		blo = prp_toff(prp);
		if (reg == NULL)
			bhi = LONG_MAX;
		else
			bhi = prp_eoff(reg);
		break;
	default:
		blo = prp_soff(prp);
		bhi = prp_eoff(prp);
	}

	abort_unless(blo >= 0 && bhi >= 0);
	if ((newoff < blo) || (newoff > bhi))
		return -2;

	prp->offs[oid] = newoff;

	/* may need to adjust list placement */
	if ((oid == PRP_OI_SOFF) && (reg != NULL)) {
		trav = prp_prev(prp);
		if (prp_soff(prp) < prp_soff(trav)) {
			l_rem(&prp->node);
			do {
				trav = prp_prev(trav);
			} while (prp_soff(prp) < prp_soff(trav));
			l_ins(&trav->node, &prp->node);
		} else {
			trav = prp_next(prp);
			if (!prp_list_end(trav)
			    && (prp_soff(prp) > prp_soff(trav))) {
				l_rem(&prp->node);
				do {
					trav = prp_next(trav);
				} while (!prp_list_end(trav)
					 && (prp_soff(prp) > prp_soff(trav)));
				l_ins(trav->node.prev, &prp->node);
			}
		}
	}

	return 0;
}


int prp_adj_plen(struct prparse *prp, long amt)
{
	int rv;

	/* Note: if we move the trailer offset down successfully there should */
	/* be no reason we can't move the end offset down as well. This works */
	/* in reverse for moving the end and trailer offsets forward.  */
	if (amt < 0) {
		if (prp_adj_off(prp, PRP_OI_TOFF, amt) < 0)
			return -2;
		rv = prp_adj_off(prp, PRP_OI_EOFF, amt);
		abort_unless(rv >= 0);
	} else {
		if (prp_adj_off(prp, PRP_OI_EOFF, amt) < 0)
			return -2;
		rv = prp_adj_off(prp, PRP_OI_TOFF, amt);
		abort_unless(rv >= 0);
	}

	return 0;
}


int prp_adj_unused(struct prparse *reg)
{
	ulong ustart, uend;

	if (!reg) {
		errno = EINVAL;
		return -1;
	}

	ubounds(reg, &ustart, &uend);
	if (ustart >= uend) {
		prp_poff(reg) = prp_soff(reg);
		prp_toff(reg) = prp_eoff(reg);
	} else {
		prp_poff(reg) = ustart;
		prp_toff(reg) = uend;
	}

	return 0;
}


void prp_add_insert(struct prparse *reg, struct prparse *prp, int enclose)
{
	struct prparse *trav;
	prp->region = reg;

	/* inserts at earliest possition in list for its offset */
	/* within the region */
	prp_insert_parse(reg, prp);

	if (enclose) {
		/* for all parses in the region that are enclosed in the */
		/* new parse (offset/length-wise), make them point to */
		/* the new parse as their region.  */
		for (trav = prp_next_in_region(prp, reg);
		     trav != NULL;
		     trav = prp_next_in_region(trav, reg)) {
			if (prp_eoff(trav) <= prp_eoff(prp))
				trav->region = prp;
		}
	}
}



void prp_init_parse(struct prparse *prp, uint prid, ulong off, ulong hlen,
		    ulong plen, ulong tlen, struct prparse_ops *ops,
		    struct prparse *reg, uint nxfields)
{
	prp->prid = prid;
	prp->error = 0;
	prp_soff(prp) = off;
	prp_poff(prp) = off + hlen;
	prp_toff(prp) = off + hlen + plen;
	prp_eoff(prp) = off + hlen + plen + tlen;
	abort_unless(prp_soff(prp) >= 0 && prp_poff(prp) >= prp_soff(prp) &&
		     prp_toff(prp) >= prp_poff(prp) &&
		     prp_eoff(prp) >= prp_toff(prp));
	prp->ops = ops;
	l_init(&prp->node);
	prp->region = reg;
	prp->noff = PRP_OI_MIN_NUM + nxfields;
	prp_reset_xfields(prp);
}


void prp_reset_xfields(struct prparse *prp)
{
	uint i;
	for (i = PRP_OI_EXTRA; i < prp->noff; ++i)
		prp->offs[i] = PRP_OFF_INVALID;
}


int prpspec_init(struct prpspec *ps, struct prparse *prp, uint prid, uint hlen,
		 uint tlen, int enclose)
{
	ps->prid = prid;
	ps->hlen = hlen;
	ps->tlen = tlen;
	if (enclose) {
		if (prp_soff(prp) < hlen) {
			errno = ENOSPC;
			return -1;
		}
		ps->off = prp_soff(prp) - hlen;
		ps->plen = prp_totlen(prp);
	} else {
		if (prp_plen(prp) < hlen + tlen) {
			errno = ENOSPC;
			return -1;
		}
		ps->off = prp_poff(prp);
		ps->plen = prp_plen(prp) - hlen - tlen;
	}
	return 0;
}


void prp_nop_update(struct prparse *prp, byte_t *buf)
{
	/* do nothing */
}


int prp_nop_fixnxt(struct prparse *prp, byte_t *buf)
{
	return 0; /* return success */
}


int prp_nop_fixlen(struct prparse *prp, byte_t *buf)
{
	return 0; /* return success */
}


int prp_nop_fixcksum(struct prparse *prp, byte_t *buf)
{
	return 0; /* return success */
}


struct prparse *prp_nop_copy(struct prparse *oprp)
{
	return NULL;  /* this we can't do without help */
}


void prp_nop_free(struct prparse *prp)
{
	/* do nothing */
}
