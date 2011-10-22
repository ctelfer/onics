#include "protoparse.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>


static struct proto_parser *_pp_lookup(uint type);
static struct prparse *none_parse(struct prparse *pprp, byte_t *buf, 
				  uint *nextppt);
static struct prparse *none_add(ulong off, ulong len, ulong hlen, ulong plen,
				byte_t *buf, int mode);

static struct proto_parser_ops none_proto_parser_ops = {
	none_parse,
	none_add,
};

struct proto_parser dlt_proto_parsers[PPT_PER_PF];
struct proto_parser net_proto_parsers[PPT_PER_PF];
struct proto_parser inet_proto_parsers[PPT_PER_PF];
struct proto_parser pp_proto_parsers[PPT_PER_PF] = {
	{PPT_NONE, 1, &none_proto_parser_ops},
};



int pp_register(unsigned type, struct proto_parser_ops *ppo)
{
	struct proto_parser *pp;

	if ((ppo == NULL) || (ppo->parse == NULL) || (ppo->add == NULL)) {
		errno = EINVAL;
		return -1;
	}

	pp = _pp_lookup(type);
	if (!pp) {
		errno = EINVAL;
		return -1;
	}

	if (pp->valid) {
		errno = EACCES;
		return -1;
	}

	pp->type = type;
	pp->ops = ppo;
	pp->valid = 1;

	return 0;
}


static struct proto_parser *_pp_lookup(uint type)
{
	switch (PPT_FAMILY(type)) {
	case PPT_PF_INET:
		return &inet_proto_parsers[PPT_PROTO(type)];
	case PPT_PF_NET:
		return &net_proto_parsers[PPT_PROTO(type)];
	case PPT_PF_DLT:
		return &dlt_proto_parsers[PPT_PROTO(type)];
	case PPT_PF_PP:
		if (PPT_PROTO(type) >= PPT_PF_PP_RESERVED)
			return NULL;
		else
			return &pp_proto_parsers[PPT_PROTO(type)];
	default:
		return NULL;
	}
}


const struct proto_parser *pp_lookup(uint ppt)
{
	const struct proto_parser *pp = _pp_lookup(ppt);
	if (pp && !pp->valid)
		pp = NULL;
	return pp;
}


int pp_unregister(uint type)
{
	struct proto_parser *pp;

	pp = _pp_lookup(type);
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


/* -- ops for the "NONE" protocol type -- */

static void none_update(struct prparse *prp, byte_t *buf);
static int none_fixlen(struct prparse *prp, byte_t *buf);
static int none_fixcksum(struct prparse *prp, byte_t *buf);
static struct prparse *none_copy(struct prparse *oprp);
static void none_free(struct prparse *prp);

static struct prparse_ops none_prparse_ops = {
	none_update,
	none_fixlen,
	none_fixcksum,
	none_copy,
	none_free
};


static struct prparse *none_parse(struct prparse *pprp, byte_t *buf,
				  uint *nextppt)
{
	struct prparse *prp;

	abort_unless(pprp);
	abort_unless(nextppt);

	*nextppt = PPT_INVALID;
	prp = none_add(prp_poff(pprp), prp_plen(pprp), 0, prp_plen(pprp), 
		       buf, PRP_ADD_FILL);
	if (prp != NULL) {
		prp->region = pprp;
		l_ins(&pprp->node, &prp->node);
	}
	return prp;
}


static void none_init(struct prparse *prp, ulong off, ulong len, ulong hlen, 
		      ulong plen)
{
	prp->type = PPT_NONE;
	prp->error = 0;
	prp->ops = &none_prparse_ops;
	l_init(&prp->node);
	prp->region = NULL;
	prp->noff = PRP_OI_MIN_NUM;
	prp_soff(prp) = off;
	prp_eoff(prp) = prp_soff(prp) + len;
	prp_poff(prp) = prp_soff(prp) + hlen;
	prp_toff(prp) = prp_poff(prp) + plen;

	abort_unless(prp_soff(prp) <= prp_poff(prp));
	abort_unless(prp_poff(prp) <= prp_toff(prp));
	abort_unless(prp_toff(prp) <= prp_eoff(prp));
}


static struct prparse *none_add(ulong off, ulong len, ulong hlen, ulong plen,
				byte_t *buf, int mode)
{
	struct prparse *prp;

	if (mode != PRP_ADD_FILL)
		return NULL;

	prp = malloc(sizeof(*prp));
	if (!prp)
		return NULL;

	none_init(prp, off, len, hlen, plen);

	return prp;
}


static void none_update(struct prparse *prp, byte_t *buf)
{
}


static int none_fixlen(struct prparse *prp, byte_t *buf)
{
	return 0;
}


static int none_fixcksum(struct prparse *prp, byte_t *buf)
{
	return 0;
}


static struct prparse *none_copy(struct prparse *oprp)
{
	return none_add(prp_soff(oprp), prp_totlen(oprp), prp_hlen(oprp),
			prp_plen(oprp), NULL, PRP_ADD_FILL);
}


static void none_free(struct prparse *prp)
{
	free(prp);
}



/* -- Protocol Parse Functions -- */
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


void prp_init_parse(struct prparse *base, ulong len)
{
	abort_unless(base && (len >= 0));
	none_init(base, 0, len, 0, 0);
}


int prp_parse_packet(struct prparse *base, byte_t *buf, uint ippt)
{
	struct prparse *prp;
	const struct proto_parser *pp;
	uint nextppt;
	int errval;

	abort_unless(base && base->type == PPT_NONE);
	pp = pp_lookup(ippt);
	if (!pp) {
		errno = EINVAL;
		return -1;
	}

	prp = base;
	do {
		nextppt = PPT_INVALID;
		if (!(prp = (*pp->ops->parse)(prp, buf, &nextppt))) {
			errval = errno;
			goto err;
		}
		/* don't continue parsing if the lengths are screwed up */
		if ((prp->error & PRP_ERR_HLENMASK) || !prp_plen(prp))
			break;
		pp = pp_lookup(nextppt);
	} while (pp);

	return 0;

 err:
	prp_clear(base);
	errno = errval;
	return -1;
}


int prp_add(unsigned ppt, struct prparse *pprp, byte_t *buf, int mode)
{
	const struct proto_parser *pp;
	ulong off, len, plen, hlen;
	struct prparse *prp, *next = NULL;

	pp = pp_lookup(ppt);
	if (!pp || !pprp) {
		errno = EINVAL;
		return -1;
	}

	off = prp_poff(pprp);
	len = prp_plen(pprp);
	if (mode == PRP_ADD_FILL) {
		hlen = 0;
		plen = 0;
	} else if (mode == PRP_ADD_WRAP) {
		ulong t;
		if (prp_region_empty(pprp)) {
			errno = EINVAL;
			return -1;
		}
		next = prp_next(pprp);
		t = prp_soff(next);
		hlen = t - off;
		off = t;
		plen = prp_totlen(next);
	} else if (mode == PRP_ADD_WRAPFILL) {
		next = prp_next(pprp);
		/* ensure list is non-empty and both prev and next are in the */
		/* same region.  The prev parse must enclose the next parse */
		if ((next == pprp) || (next->region != pprp)) {
			errno = EINVAL;
			return -1;
		}
		hlen = prp_soff(next) - off;
		plen = prp_totlen(next);
	} else {
		errno = EINVAL;
		return -1;
	}

	prp = (*pp->ops->add)(off, len, hlen, plen, buf, mode);
	if (prp == NULL)
		return -1;
	prp->region = pprp;
	if (next != NULL)
		next->region = prp;

	l_ins(&pprp->node, &prp->node);
	return 0;
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


int prp_fix_cksum(struct prparse *prp, byte_t *buf)
{
	abort_unless(prp && prp->ops && prp->ops->fixcksum);
	return (*prp->ops->fixcksum)(prp, buf);
}


int prp_fix_len(struct prparse *prp, byte_t *buf)
{
	abort_unless(prp && prp->ops && prp->ops->fixlen);
	return (*prp->ops->fixlen)(prp, buf);
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
		if (off > prp_toff(prp))
			return 0;
		if (len > prp_tlen(prp)) {
			errno = EINVAL;
			return -1;
		}

		if (buf != NULL) {
			op = buf + off;
			np = op + len;
			mlen = prp_toff(prp) - off;
			memmove(np, op, mlen);
			memset(op, 0x5A, len);
		}

		prp_toff(prp) += len;

		for (prp = prp_next(prp); 
		     !prp_list_end(prp); 
		     prp = prp_next(prp)) {
			for (i = 0; i < prp->noff; ++i) {
				if ((prp->offs[i] != PRP_OFF_INVALID) &&
				    (prp->offs[i] >= off))
					prp->offs[i] += len;
			}
		}
	} else {
		if (off <= prp_poff(prp))
			return 0;
		if (len > prp_hlen(prp)) {
			errno = EINVAL;
			return -1;
		}

		if (buf != NULL) {
			op = buf + prp_poff(prp);
			np = op - len;
			mlen = off - prp_poff(prp);
			memmove(np, op, mlen);
			memset(op, 0x4B, len);
		}

		prp_poff(prp) -= len;
		for (prp = prp_next(prp); 
		     !prp_list_end(prp); 
		     prp = prp_next(prp)) {
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

	if ((off < prp_soff(prp)) || (off >= prp_eoff(prp)) ||
	    (len > prp_eoff(prp) - off)) {
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
	if (ustart > uend) {
		prp_poff(reg) = prp_soff(reg);
		prp_toff(reg) = prp_eoff(reg);
	} else {
		prp_poff(reg) = ustart;
		prp_toff(reg) = uend;
	}

	return 0;
}
