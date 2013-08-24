/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * xpkt.c -- Code for manipulating data in the eXternal PacKeT format.
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
#include <string.h>
#include <limits.h>
#include <cat/pack.h>
#include "xpkt.h"


/* generic (un)pack operation when there is nothing to do */
static void packop_none(struct xpkt_tag_hdr *xth)
{
}

static int tvalid_zeroxh(struct xpkt_tag_hdr *xth)
{
	return (xth->xhword == 0);
}


static int tvalid_always(struct xpkt_tag_hdr *xth)
{
	return 1;
}


/* Timestamp */
static int ts_validate(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_ts *ts = (struct xpkt_tag_ts *)xth;
	return (ts->zero == 0) && (ts->nsec < 1000000000);
}


static void ts_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_ts *ts = (struct xpkt_tag_ts *)xth;
	ts->sec = ntoh32(ts->sec);
	ts->nsec = ntoh32(ts->nsec);
}


static void ts_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_ts *ts = (struct xpkt_tag_ts *)xth;
	ts->sec = hton32(ts->sec);
	ts->nsec = hton32(ts->nsec);
}


/* Snapinfo */
static void si_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_snapinfo *si = (struct xpkt_tag_snapinfo *)xth;
	si->wirelen = ntoh32(si->wirelen);
}


static void si_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_snapinfo *si = (struct xpkt_tag_snapinfo *)xth;
	si->wirelen = hton32(si->wirelen);
}


/* flowid */
static void flowid_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_flowid *xtf = (struct xpkt_tag_flowid *)xth;
	xtf->flowid = ntoh64(xtf->flowid);
}


static void flowid_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_flowid *xtf = (struct xpkt_tag_flowid *)xth;
	xtf->flowid = hton64(xtf->flowid);
}


/* classification tag */
static void class_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_class *xtc = (struct xpkt_tag_class *)xth;
	xtc->tag = ntoh64(xtc->tag);
}


static void class_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_class *xtc = (struct xpkt_tag_class *)xth;
	xtc->tag = hton64(xtc->tag);
}


/* sequence tag */
static void seq_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_seq *xts = (struct xpkt_tag_seq *)xth;
	xts->seq = ntoh64(xts->seq);
}


static void seq_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_seq *xts = (struct xpkt_tag_seq *)xth;
	xts->seq = hton64(xts->seq);
}


/* Parse info */
static void pi_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_parseinfo *pi = (struct xpkt_tag_parseinfo *)xth;
	pi->off = ntoh32(pi->off);
	pi->len = ntoh32(pi->len);
}


static void pi_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_parseinfo *pi = (struct xpkt_tag_parseinfo *)xth;
	pi->off = hton32(pi->off);
	pi->len = hton32(pi->len);
}


struct xpkt_tag_ops {
	int nwords;
	int maydup;
	int (*validate)(struct xpkt_tag_hdr *xth);
	void (*unpack)(struct xpkt_tag_hdr *xth);
	void (*pack)(struct xpkt_tag_hdr *xth);

} tagops[XPKT_TAG_NUM_TYPES] = {
	{XPKT_TAG_NOP_NWORDS,      1, tvalid_zeroxh, packop_none, packop_none},
	{XPKT_TAG_TIMESTAMP_NWORDS,0, ts_validate, ts_pack, ts_unpack},
	{XPKT_TAG_SNAPINFO_NWORDS, 0, tvalid_zeroxh, si_pack, si_unpack},
	{XPKT_TAG_INIFACE_NWORDS,  0, tvalid_always, packop_none, packop_none},
	{XPKT_TAG_OUTIFACE_NWORDS, 0, tvalid_always, packop_none, packop_none},
	{XPKT_TAG_FLOW_NWORDS,     0, tvalid_zeroxh, flowid_unpack,flowid_pack},
	{XPKT_TAG_CLASS_NWORDS,    0, tvalid_zeroxh, class_unpack, class_pack},
	{XPKT_TAG_SEQ_NWORDS,      0, tvalid_zeroxh, seq_unpack, seq_pack},
	{XPKT_TAG_PARSEINFO_NWORDS,1, tvalid_always, pi_unpack, pi_pack},
};


void xpkt_unpack_hdr(struct xpkthdr *xh)
{
	xh->len = ntoh32(xh->len);
	xh->tlen = ntoh16(xh->tlen);
	xh->dltype = ntoh16(xh->dltype);
}


int xpkt_validate_hdr(struct xpkthdr *xh)
{
	abort_unless(xh);

	if (xh->len < XPKT_HLEN)
		return -1;
	if (xh->tlen * 4 > (xh->len - XPKT_HLEN))
		return -2;
	return 0;
}


void xpkt_pack_hdr(struct xpkthdr *xh)
{
	xh->len = hton32(xh->len);
	xh->tlen = hton16(xh->tlen);
	xh->dltype = hton16(xh->dltype);
}


int xpkt_unpack_tags(uint32_t *tags, uint16_t tlen)
{
	struct xpkt_tag_hdr *xth;
	uint32_t *tend;

	abort_unless(tags);

	tend = tags + tlen;
	while (tags < tend) {
		xth = (struct xpkt_tag_hdr *)tags;
		if (xth->nwords + 1 > tend - tags)
			return -1;
		if (xth->type == XPKT_TAG_INVALID)
			return -2;
		if (xth->type < XPKT_TAG_NUM_TYPES) {
			/* check for proper length for tag */
			if (xth->nwords != tagops[xth->type].nwords)
				return -3;
		}
		xth->xhword = ntoh16(xth->xhword);
		if (xth->type < XPKT_TAG_NUM_TYPES)
			(*tagops[xth->type].unpack)(xth);
		tags += xth->nwords + 1;
	}

	return 0;
}


int xpkt_validate_tags(uint32_t *tags, uint16_t tlen)
{
	int rv;
	struct xpkt_tag_hdr *xth;
	uint32_t *tend;
	uchar seen[XPKT_TAG_NUM_TYPES] = { 0 };
	ptrdiff_t s;

	abort_unless(tags);

	tend = tags + tlen;
	while (tags < tend) {
		s = tend - tags;

		xth = (struct xpkt_tag_hdr *)tags;

		if (s < xth->nwords + 1)
			return -1;

		if (xth->type == XPKT_TAG_INVALID)
			return -1;

		if (xth->type < XPKT_TAG_NUM_TYPES) {
			if (xth->nwords != tagops[xth->type].nwords)
				return -1;

			/* check whether the tag is duped but shouldn't be */
			if (!tagops[xth->type].maydup) {
				if (seen[xth->type])
					return -1;
				seen[xth->type] = 1;
			}

			/* call the tag-specific validation function */
			rv = (*tagops[xth->type].validate)(xth);
			if (rv < 0)
				return -1;
		}
		tags += xth->nwords + 1;
	}

	return 0;
}


void xpkt_pack_tags(uint32_t *tags, uint16_t tlen)
{
	struct xpkt_tag_hdr *xth;
	uint32_t *tend;

	abort_unless(tags);

	tend = tags + tlen;
	while (tags < tend) {
		xth = (struct xpkt_tag_hdr *)tags;
		xth->xhword = hton16(xth->xhword);
		abort_unless(xth->nwords + 1 <= tend - tags);
		if (xth->type < XPKT_TAG_NUM_TYPES)
			(*tagops[xth->type].pack)(xth);
		tags += xth->nwords + 1;
	}
}


struct xpkt_tag_hdr *xpkt_next_tag(struct xpkt *x, struct xpkt_tag_hdr *cur)
{
	ptrdiff_t toff;

	abort_unless(x);
	/* XXX return NULL for all the aborts below? */

	if (cur == NULL) {
		if (x->hdr.tlen > 0) {
		        cur = (struct xpkt_tag_hdr *)x->tags;
			abort_unless(x->hdr.tlen >= cur->nwords + 1);
			return cur;
		}
		return NULL;
	}

	toff = (uint32_t*)cur - x->tags;
	abort_unless(toff < x->hdr.tlen);
	if (cur->nwords + 1 >= x->hdr.tlen - toff) {
		abort_unless(cur->nwords + 1 == x->hdr.tlen - toff);
		return NULL;
	}

	cur = (struct xpkt_tag_hdr *)((uint32_t *)cur + cur->nwords + 1);
	abort_unless(x->hdr.tlen - ((uint32_t *)cur - x->tags) >= 
		     cur->nwords + 1);
	return cur;
}


struct xpkt_tag_hdr *xpkt_find_tag(struct xpkt *x, byte_t type, int idx)
{
	struct xpkt_tag_hdr *xth;

	abort_unless(x && idx >= 0);

	xth = xpkt_next_tag(x, NULL);
	while ((xth != NULL) && ((idx > 0) || (type != xth->type))) {
		if (type == xth->type)
			--idx;
		xth = xpkt_next_tag(x, xth);
	}
	return xth;
}


int xpkt_find_tag_idx(struct xpkt *x, struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_hdr *trav;
	int idx = 0;

	abort_unless(x && xth);

	trav = xpkt_next_tag(x, NULL);
	while (trav && (trav != xth)) {
		if (trav->type == xth->type)
			++idx;
		xth = xpkt_next_tag(x, xth);
	}
	if (!trav)
		return -1;
	else
		return idx;
}


int xpkt_add_tag(struct xpkt *x, struct xpkt_tag_hdr *xth, int moveup)
{
	int rv;
	int flen = 0;
	byte_t *lo, *hi;
	uint16_t tl;
	struct xpkt_tag_hdr *trav;

	abort_unless(x && xth);


	if (xth->type == XPKT_TAG_INVALID)
		return -1;

	if (xth->type < XPKT_TAG_NUM_TYPES) {
		rv = (*tagops[xth->type].validate)(xth);
		if (rv < 0)
			return -1;
		if (!tagops[xth->type].maydup && xpkt_find_tag(x, xth->type, 0))
			return -1;
	}

	/* check for overflow of packet or tag length fields */
	if ((x->hdr.len + xpkt_tag_size(xth) < x->hdr.len) || 
	    (x->hdr.tlen + xth->nwords + 1 < x->hdr.tlen))
		return -1;

	if (moveup) {
		tl = xpkt_tag_size(xth);
		lo = (byte_t *)x + XPKT_HLEN + x->hdr.tlen * 4;
		hi = lo + tl;
		memmove(hi, lo, xpkt_data_len(x));
		memcpy(lo, xth, tl);
		x->hdr.tlen += xth->nwords + 1;
		x->hdr.len += tl;

	} else {
		/* first fit search for a sequence of nops big enough for */
		/* the new tag */
		tl = xth->nwords + 1;
		for (trav = xpkt_next_tag(x, NULL)  ;
                     (trav != NULL)                 ;
		     trav = xpkt_next_tag(x, trav)) {
			if (trav->type == XPKT_TAG_NOP)
				++flen;
			else
				flen = 0;
			if (flen >= tl)
				break;
		}
		if (flen >= tl) {
			memcpy((uint32_t *)trav - (tl - 1), xth, tl * 4);
		} else {
			return -1;
		}
	}

	return 0;
}


int xpkt_del_tag(struct xpkt *x, byte_t type, int idx, int pulldown)
{
	uint n;
	uint ntw;
	struct xpkt_tag_hdr *xth;

	abort_unless(x);

	/* Assume that an added tag has been validated */
	if (!(xth = xpkt_find_tag(x, type, idx)))
		return -1;

	if (pulldown) {
		n = xpkt_tag_size(xth);
		ntw = xth->nwords + 1;
		memmove(xth, (byte_t *)xth + n,
			x->hdr.len - ((byte_t*)xth - (byte_t *)x + n));
		x->hdr.tlen -= ntw;
		x->hdr.len -= n;
	} else {
		n = xth->nwords + 1;
		while (n > 0) {
			xth->type = XPKT_TAG_NOP;
			xth->nwords = 0;
			xth->xhword = 0;
			xth++;
			--n;
		}
	}

	return 0;
}


void xpkt_tag_nop_init(struct xpkt_tag_nop *t)
{
	abort_unless(t);
	t->type =  XPKT_TAG_NOP;
	t->nwords = XPKT_TAG_NOP_NWORDS;
	t->zero = 0;
}


void xpkt_tag_ts_init(struct xpkt_tag_ts *t, uint32_t sec, uint32_t nsec)
{
	abort_unless(t);
	t->type =  XPKT_TAG_TIMESTAMP;
	t->nwords = XPKT_TAG_TIMESTAMP_NWORDS;
	t->zero = 0;
	t->sec = sec;
	t->nsec = nsec;
}


void xpkt_tag_si_init(struct xpkt_tag_snapinfo *t, uint32_t wirelen)
{
	abort_unless(t);
	t->type =  XPKT_TAG_SNAPINFO;
	t->nwords = XPKT_TAG_SNAPINFO_NWORDS;
	t->zero = 0;
	t->wirelen = wirelen;
}


void xpkt_tag_iif_init(struct xpkt_tag_iface *t, uint16_t iface)
{
	abort_unless(t);
	t->type =  XPKT_TAG_INIFACE;
	t->nwords = XPKT_TAG_INIFACE_NWORDS;
	t->iface = iface;
}


void xpkt_tag_oif_init(struct xpkt_tag_iface *t, uint16_t iface)
{
	abort_unless(t);
	t->type =  XPKT_TAG_OUTIFACE;
	t->nwords = XPKT_TAG_OUTIFACE_NWORDS;
	t->iface = iface;
}


void xpkt_tag_flowid_init(struct xpkt_tag_flowid *t, uint64_t id)
{
	abort_unless(t);
	t->type =  XPKT_TAG_FLOW;
	t->nwords = XPKT_TAG_FLOW_NWORDS;
	t->zero = 0;
	t->flowid = id;
}


void xpkt_tag_class_init(struct xpkt_tag_class *t, uint64_t tag)
{
	abort_unless(t);
	t->type =  XPKT_TAG_CLASS;
	t->nwords = XPKT_TAG_CLASS_NWORDS;
	t->zero = 0;
	t->tag = tag;
}


void xpkt_tag_seq_init(struct xpkt_tag_seq *t, uint64_t seq)
{
	abort_unless(t);
	t->type =  XPKT_TAG_SEQ;
	t->nwords = XPKT_TAG_SEQ_NWORDS;
	t->zero = 0;
	t->seq = seq;
}


void xpkt_tag_pi_init(struct xpkt_tag_parseinfo *t, uint16_t proto,
		      uint32_t off, uint32_t len)
{
	abort_unless(t);
	t->type =  XPKT_TAG_PARSEINFO;
	t->nwords = XPKT_TAG_PARSEINFO_NWORDS;
	t->proto = proto;
	t->off = off;
	t->len = len;
}


void xpkt_tag_ai_init(struct xpkt_tag_appinfo *t, uint16_t subtype, uint32_t *p,
		      uint nw)
{
	abort_unless(t);
	if (nw > 0) {
		abort_unless(nw < 255);
		abort_unless(p);
		memcpy(t->data, p, nw * 4);
	}

	t->type = XPKT_TAG_APPINFO;
	t->nwords = nw;
	t->subtype = subtype;
}
