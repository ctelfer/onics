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
	return (xth->xth_xhword == 0);
}


static int tvalid_always(struct xpkt_tag_hdr *xth)
{
	return 1;
}


/* Timestamp */
static int ts_validate(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_ts *ts = (struct xpkt_tag_ts *)xth;
	return (xth->xth_xhword == 0) && (ts->xpt_ts_nsec < 1000000000);
}


static void ts_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_ts *ts = (struct xpkt_tag_ts *)xth;
	ts->xpt_ts_sec = ntoh32(ts->xpt_ts_sec);
	ts->xpt_ts_nsec = ntoh32(ts->xpt_ts_nsec);
}


static void ts_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_ts *ts = (struct xpkt_tag_ts *)xth;
	ts->xpt_ts_sec = hton32(ts->xpt_ts_sec);
	ts->xpt_ts_nsec = hton32(ts->xpt_ts_nsec);
}


/* Snapinfo */
static void si_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_snapinfo *si = (struct xpkt_tag_snapinfo *)xth;
	si->xpt_si_wire_len = ntoh32(si->xpt_si_wire_len);
}


static void si_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_snapinfo *si = (struct xpkt_tag_snapinfo *)xth;
	si->xpt_si_wire_len = hton32(si->xpt_si_wire_len);
}


/* flowid */
static void flowid_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_flowid *xtf = (struct xpkt_tag_flowid *)xth;
	xtf->xpt_fl_id = ntoh64(xtf->xpt_fl_id);
}


static void flowid_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_flowid *xtf = (struct xpkt_tag_flowid *)xth;
	xtf->xpt_fl_id = hton64(xtf->xpt_fl_id);
}


/* classification tag */
static void class_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_class *xtc = (struct xpkt_tag_class *)xth;
	xtc->xpt_cl_tag = ntoh64(xtc->xpt_cl_tag);
}


static void class_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_class *xtc = (struct xpkt_tag_class *)xth;
	xtc->xpt_cl_tag = hton64(xtc->xpt_cl_tag);
}


/* Parse info */
static void pi_unpack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_parseinfo *pi = (struct xpkt_tag_parseinfo *)xth;
	pi->xpt_pi_off = ntoh32(pi->xpt_pi_off);
	pi->xpt_pi_len = ntoh32(pi->xpt_pi_len);
}


static void pi_pack(struct xpkt_tag_hdr *xth)
{
	struct xpkt_tag_parseinfo *pi = (struct xpkt_tag_parseinfo *)xth;
	pi->xpt_pi_off = hton32(pi->xpt_pi_off);
	pi->xpt_pi_len = hton32(pi->xpt_pi_len);
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
	{XPKT_TAG_PARSEINFO_NWORDS,1, tvalid_always, pi_unpack, pi_pack},
};


void xpkt_unpack_hdr(struct xpkthdr *xh)
{
	xh->xh_len = ntoh32(xh->xh_len);
	xh->xh_tlen = ntoh16(xh->xh_tlen);
	xh->xh_dltype = ntoh16(xh->xh_dltype);
}


int xpkt_validate_hdr(struct xpkthdr *xh)
{
	abort_unless(xh);

	if (xh->xh_len < XPKT_HLEN)
		return -1;
	if (((xh->xh_tlen & 3) != 0) || 
	    (xh->xh_tlen > (xh->xh_len - XPKT_HLEN)))
		return -2;
	return 0;
}


void xpkt_pack_hdr(struct xpkthdr *xh)
{
	xh->xh_len = hton32(xh->xh_len);
	xh->xh_tlen = hton16(xh->xh_tlen);
	xh->xh_dltype = hton16(xh->xh_dltype);
}


int xpkt_unpack_tags(uint32_t *tags, uint tlen)
{
	struct xpkt_tag_hdr *xth;
	uint32_t *tend;

	abort_unless(tags);

	tend = tags + tlen;
	while (tags < tend) {
		xth = (struct xpkt_tag_hdr *)tags;
		if (tags + xth->xth_nwords > tend)
			return -1;
		if (xth->xth_type == XPKT_TAG_INVALID)
			return -2;
		if (xth->xth_type < XPKT_TAG_NUM_TYPES) {
			/* check for proper length for tag */
			if (xth->xth_nwords != tagops[xth->xth_type].nwords)
				return -3;
		} else {
			if (xth->xth_nwords == 0)
				return -3;
		}
		xth->xth_xhword = ntoh16(xth->xth_xhword);
		if (xth->xth_type < XPKT_TAG_NUM_TYPES)
			(*tagops[xth->xth_type].unpack)(xth);
		tags += xth->xth_nwords;
	}

	return 0;
}


int xpkt_validate_tags(uint32_t *tags, uint tlen)
{
	int rv;
	struct xpkt_tag_hdr *xth;
	uint32_t *tend;
	uchar seen[XPKT_TAG_NUM_TYPES] = { 0 };

	abort_unless(tags);

	tend = tags + tlen;
	while (tags < tend) {
		xth = (struct xpkt_tag_hdr *)tags;
		abort_unless(tags + xth->xth_nwords <= tend);
		abort_unless(xth->xth_type != XPKT_TAG_INVALID);
		if (xth->xth_type < XPKT_TAG_NUM_TYPES) {
			abort_unless(xth->xth_nwords == 
			             tagops[xth->xth_type].nwords);

			/* check whether the tag is duped but shouldn't be */
			if (!tagops[xth->xth_type].maydup) {
				if (seen[xth->xth_type])
					return -1;
				seen[xth->xth_type] = 1;
			}

			/* call the tag-specific validation function */
			rv = (*tagops[xth->xth_type].validate)(xth);
			if (rv < 0)
				return -2;
		} else {
			abort_unless(xth->xth_nwords != 0);
		}
		tags += xth->xth_nwords;
	}

	return 0;
}


void xpkt_pack_tags(uint32_t *tags, uint tlen)
{
	struct xpkt_tag_hdr *xth;
	uint32_t *tend;

	abort_unless(tags);

	tend = tags + tlen;
	while (tags < tend) {
		xth = (struct xpkt_tag_hdr *)tags;
		xth->xth_xhword = hton16(xth->xth_xhword);
		abort_unless(tags + xth->xth_nwords <= tend);
		if (xth->xth_type < XPKT_TAG_NUM_TYPES)
			(*tagops[xth->xth_type].pack)(xth);
		tags += xth->xth_nwords;
	}
}


static void compress(struct xpkt **xp, uint32_t *len, uint16_t *tlen,
		     int movedown)
{
	byte_t *bound, *p;
	struct xpkt *x;
	uint run = 0;
	uint skip;
	uint otlen;
	uint ndel = 0;
	uint rlen;

	abort_unless(xp && *xp && len && tlen);

	x = *xp;
	if (movedown)
		bound = (byte_t *)x + *len;
	else
		bound = (byte_t *)x;

	p = (byte_t *)x->xpkt_tags;
	otlen = *tlen;
	while (otlen > 0) {
		if (*p == 0) {
			++run;
			continue;
		}

		if (run > 0) {
			rlen = 4 * run;
			if (movedown) {
				memmove(p - rlen, p, bound - p);
				p -= rlen;
			} else {
				memmove(bound + rlen, bound, p - rlen - bound);
				bound += rlen;
			}
			ndel += run;
			run = 0;
		}
		skip = *(p + 1) * 4;
		p += skip;
		otlen -= skip;
	}

	*len -= ndel * 4;
	*tlen -= ndel * 4;
	if (!movedown)
		*xp = (struct xpkt *)bound;
}


void xpkt_compress(struct xpkt **x, int method)
{
	abort_unless(x && *x);
	compress(x, &(*x)->xpkt_len, &(*x)->xpkt_tlen, method);
}


struct xpkt_tag_hdr *xpkt_next_tag(struct xpkt *x, struct xpkt_tag_hdr *cur)
{
	uint toff;

	abort_unless(x);

	if (cur == NULL)
		return x->xpkt_tlen ? 
		         (struct xpkt_tag_hdr *)x->xpkt_tags :
		         NULL;

	abort_unless(cur->xth_nwords > 0);

	toff = (byte_t *)cur - (byte_t *)x->xpkt_tags;
	if (cur->xth_nwords >= x->xpkt_tlen - toff)
		return NULL;
	return (struct xpkt_tag_hdr *)((byte_t *)cur + (cur->xth_nwords * 4));
}


struct xpkt_tag_hdr *xpkt_find_tag(struct xpkt *x, byte_t type, int idx)
{
	struct xpkt_tag_hdr *xth;

	abort_unless(x && idx >= 0);

	xth = xpkt_next_tag(x, NULL);
	while ((xth != NULL) && ((idx > 0) || (type != xth->xth_type))) {
		if (type == xth->xth_type)
			--idx;
		xth = xpkt_next_tag(x, xth);
	}
	return xth;
}


int xpkt_add_tag(struct xpkt **xp, struct xpkt_tag_hdr *xth, int method)
{
	struct xpkt *x;
	int rv;
	int flen = 0;
	byte_t *lo, *hi;
	uint16_t ntl;
	struct xpkt_tag_hdr *trav;

	abort_unless(xp && *xp && xth);

	x = *xp;
	ntl = xth->xth_nwords * 4;

	if (xth->xth_type == XPKT_TAG_INVALID)
		return -1;
	if (xth->xth_type < XPKT_TAG_NUM_TYPES) {
		rv = (*tagops[xth->xth_type].validate)(xth);
		if (rv < 0)
			return -1;
		if (!tagops[xth->xth_type].maydup && 
		    xpkt_find_tag(x, xth->xth_type, 0))
			return -2;
	} else {
		if (ntl == 0)
			return -1;
	}
	if (0xFFFF - x->xpkt_tlen < ntl)
		return -3;


	switch(method) {
	case XPKT_ADDTAG_NOPCLOB:
		for (trav = xpkt_next_tag(x, NULL)  ;
                     (trav != NULL)                 ;
		     trav = xpkt_next_tag(x, trav)) {
			if (trav->xth_type == XPKT_TAG_NOP)
				flen += 4;
			else
				flen = 0;
			if (flen >= ntl)
				break;
		}
		if (trav == NULL)
			return -3;
		memcpy((byte_t *)trav - (ntl - 4), xth, ntl);
		break;
	case XPKT_ADDTAG_PUSHUP:
		lo = (byte_t *)x + XPKT_HLEN + x->xpkt_tlen;
		hi = lo + ntl;
		memmove(hi, lo, xpkt_data_len(x));
		memcpy(lo, xth, ntl);
		x->xpkt_tlen += ntl;
		break;
	case XPKT_ADDTAG_PUSHDOWN:
		lo = (byte_t *)x - ntl;
		hi = (byte_t *)x;
		x->xpkt_tlen += ntl;
		memcpy(lo, hi, XPKT_HLEN + x->xpkt_tlen);
		memcpy((byte_t *)x->xpkt_tags + x->xpkt_tlen, xth, ntl);
		*xp = (struct xpkt *)lo;
		break;
	default:
		abort_unless(0);
	}

	return 0;
}


int xpkt_del_tag(struct xpkt **xp, struct xpkt_tag_hdr *xth, int method)
{
	struct xpkt *x;
	byte_t *lo, *hi;
	int ntl;
	struct xpkt_tag_hdr *trav;

	abort_unless(xp && *xp && xth);

	x = *xp;

	if (xth->xth_type < XPKT_TAG_NUM_TYPES) {
		if (tagops[xth->xth_type].nwords != xth->xth_nwords)
			return -1;
	} else {
		if (xth->xth_nwords == 0)
			return -1;
	}
	ntl = xth->xth_nwords * 4;

	/* Check for proper location */
	for (trav = xpkt_next_tag(x, NULL)   ;
	     (trav != NULL) && (trav != xth) ;
	     trav = xpkt_next_tag(x, trav))
		;
	if (trav == NULL)
		return -1;

	switch(method) {
	case XPKT_DELTAG_NOPFILL:
		while (ntl > 0) {
			xth->xth_type = XPKT_TAG_NOP;
			xth->xth_nwords = 1;
			xth->xth_xhword = 0;
			xth++;
			ntl -= 4;
		}
		break;

	case XPKT_DELTAG_PULLUP:
		lo = (byte_t *)x;
		hi = lo + ntl;
		memmove(hi, lo, ((byte_t*)xth - (byte_t *)x));
		*xp = (struct xpkt *)hi;
		break;

	case XPKT_DELTAG_PULLDOWN:
		memmove((byte_t *)xth, (byte_t *)xth + ntl,
			x->xpkt_len - ((byte_t*)xth - (byte_t *)x + ntl));
		break;
	}

	return 0;
}
