/*
 * ONICS
 * Copyright 2012-2022
 * Christopher Adam Telfer
 *
 * fld.c -- convenience get/set operations on packet fields
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
#include "fld.h"
#include "util.h"


ulong fld_get_off(struct pdu *pdu, struct ns_elem *elem)
{
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	ulong off = PDU_OFF_INVALID;

	if (elem == NULL || pdu == NULL)
		return PDU_OFF_INVALID;

	if (elem->type == NST_NAMESPACE) {
		ns = (struct ns_namespace *)elem;

		if (!pdu_off_valid(pdu, ns->oidx))
			return PDU_OFF_INVALID;

		off = pdu->offs[ns->oidx] * 8;

	} else if (elem->type == NST_PKTFLD) {
		pf = (struct ns_pktfld *)elem;

		if (!pdu_off_valid(pdu, pf->oidx))
			return PDU_OFF_INVALID;

		off = (pdu->offs[pf->oidx] + pf->off) * 8;
		if (NSF_IS_INBITS(pf->flags))
			off += NSF_BITOFF(pf->flags);
	}

	return off;
}


long fld_get_len(struct pdu *pdu, struct ns_elem *elem)
{
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	long len = -1;

	if (elem->type == NST_NAMESPACE) {
		ns = (struct ns_namespace *)elem;

		if (!pdu_off_valid(pdu, ns->oidx))
			return -1;

		if (NSF_IS_VARLEN(ns->flags)) {
			if (!pdu_off_valid(pdu, ns->len))
				return -1;

			len = (pdu->offs[ns->len] - pdu->offs[ns->oidx]) * 8;
		} else {
			len = ns->len * 8;
		}


	} else {
		pf = (struct ns_pktfld *)elem;

		if (!pdu_off_valid(pdu, pf->oidx))
			return -1;

		if (NSF_IS_VARLEN(pf->flags)) {
			if (!pdu_off_valid(pdu, pf->len))
				return -1;
			len = (pdu->offs[pf->len] - pdu->offs[pf->oidx]) * 8;
		} else if (NSF_IS_INBITS(pf->flags)) {
			return pf->len;
		} else {
			len = pf->len * 8;
		}
	}

	return len;
}

static struct pdu *findpdu(struct pdu *plist, uint prid, uint idx)
{
	struct pdu *pdu;
	if (plist == NULL)
		return NULL;
	pdu_for_each(pdu, plist) {
		if ((pdu->prid == prid) && (idx-- == 0))
			return pdu;
	}
	return NULL;
}


static int pfofflen(struct pdu *pdu, struct ns_pktfld *pf,
		    ulong *offp, ulong *lenp)
{
	ulong off, len;
	off = pdu->offs[pf->oidx] + pf->off;
#if SANITY
	if (off > pdu_totlen(pdu))
		return -1;
#endif
	if (NSF_IS_INBITS(pf->flags)) {
		len = (pf->len + NSF_BITOFF(pf->flags) + 7) / 8;
#if SANITY
		if (pdu_totlen(pdu) - off > len)
			return -1;
#endif
	} else {
		if (NSF_IS_VARLEN(pf->flags)) {
#if SANITY
			if (!pdu_off_valid(pdu, pf->len) ||
			    (pdu->offs[pf->len] < off))
				return -1;
#endif
			len = pdu->offs[pf->len] - off;
		} else {
#if SANITY
			if (pdu_totlen(pdu) - off > pf->len)
				return -1;
#endif
			len = pf->len;
		}
	}

	if (offp != NULL)
		*offp = off;

	if (lenp != NULL)
		*lenp = len;

	return 0;
}


static int getinfo(struct pdu *plist, struct ns_pktfld *pf, uint idx,
		   struct pdu **ppdu, ulong *offp, ulong *lenp)
{
	struct pdu *pdu;
	if (pf == NULL)
		return -1;

	pdu = findpdu(plist, pf->prid, idx);
	if (pdu == NULL)
		return -1;

	if (!pdu_off_valid(pdu, pf->oidx))
		return -1;

	if (pfofflen(pdu, pf, offp, lenp) < 0)
		return -1;

	if (ppdu != NULL)
		*ppdu = pdu;

	return 0;
}


static ulong bitoff(ulong byteoff, struct ns_pktfld *pf)
{
	return byteoff * 8 + NSF_BITOFF(pf->flags);
}


int fld_exists(struct pdu *plist, struct ns_pktfld *pf, uint idx)
{
	struct pdu *pdu;

	if (pf == NULL)
		return 0;

	pdu = findpdu(plist, pf->prid, idx);
	if (pdu == NULL)
		return 0;

	return pdu_off_valid(pdu, pf->oidx);
}


struct pdu *fld_get_pdui(struct pdu *plist, struct ns_namespace *ns, uint idx)
{
	if (ns == NULL)
		return NULL;
	return findpdu(plist, ns->prid, idx);
}


struct pdu *fld_get_pduni(struct pdu *plist, const char *s, uint idx)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return findpdu(plist, ((struct ns_namespace *)e)->prid, idx);
}


struct pdu *fld_get_pdu(struct pdu *plist, struct ns_namespace *ns)
{
	return fld_get_pdui(plist, ns, 0);
}


struct pdu *fld_get_pdun(struct pdu *plist, const char *s)
{
	return fld_get_pduni(plist, s, 0);
}


void *fld_get_hdri(byte_t *p, struct pdu *plist, struct ns_namespace *ns,
		   uint idx, ulong *len)
{
	struct pdu *pdu;

	if (ns == NULL)
		return NULL;

	pdu = findpdu(plist, ns->prid, idx);
	if (pdu == NULL)
		return NULL;

	if (len != NULL)
		*len = pdu_hlen(pdu);

	return pdu_header(pdu, p, void);
}


void *fld_get_pldi(byte_t *p, struct pdu *plist, struct ns_namespace *ns,
		   uint idx, ulong *len)
{
	struct pdu *pdu;

	if (ns == NULL)
		return NULL;

	pdu = findpdu(plist, ns->prid, idx);
	if (pdu == NULL)
		return NULL;

	if (len != NULL)
		*len = pdu_plen(pdu);

	return pdu_payload(pdu, p);
}


void *fld_get_trli(byte_t *p, struct pdu *plist, struct ns_namespace *ns,
		   uint idx, ulong *len)
{
	struct pdu *pdu;

	if (ns == NULL)
		return NULL;

	pdu = findpdu(plist, ns->prid, idx);
	if (pdu == NULL)
		return NULL;

	if (len != NULL)
		*len = pdu_tlen(pdu);

	return pdu_trailer(pdu, p, void);
}


void *fld_get_hdrni(byte_t *p, struct pdu *plist, const char *s,
		    uint idx, ulong *len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return fld_get_hdri(p, plist, (struct ns_namespace *)e, idx, len);
}


void *fld_get_pldni(byte_t *p, struct pdu *plist, const char *s,
		    uint idx, ulong *len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return fld_get_pldi(p, plist, (struct ns_namespace *)e, idx, len);
}


void *fld_get_trlni(byte_t *p, struct pdu *plist, const char *s,
		    uint idx, ulong *len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return fld_get_trli(p, plist, (struct ns_namespace *)e, idx, len);
}


void *fld_get_hdr(byte_t *p, struct pdu *plist, struct ns_namespace *ns,
		  ulong *len)
{
	return fld_get_hdri(p, plist, ns, 0, len);
}


void *fld_get_pld(byte_t *p, struct pdu *plist, struct ns_namespace *ns,
		  ulong *len)
{
	return fld_get_pldi(p, plist, ns, 0, len);
}


void *fld_get_trl(byte_t *p, struct pdu *plist, struct ns_namespace *ns,
		  ulong *len)
{
	return fld_get_trli(p, plist, ns, 0, len);
}


void *fld_get_hdrn(byte_t *p, struct pdu *plist, const char *s, ulong *len)
{
	return fld_get_hdrni(p, plist, s, 0, len);
}


void *fld_get_pldn(byte_t *p, struct pdu *plist, const char *s, ulong *len)
{
	return fld_get_pldni(p, plist, s, 0, len);
}


void *fld_get_trln(byte_t *p, struct pdu *plist, const char *s, ulong *len)
{
	return fld_get_trlni(p, plist, s, 0, len);
}


void *fld_get_pi(byte_t *p, struct pdu *plist, struct ns_pktfld *pf, uint idx,
		 ulong *len)
{
	ulong off;

	if (getinfo(plist, pf, idx, NULL, &off, len) < 0)
		return NULL;

	return p + off;
}


void *fld_get_p(byte_t *p, struct pdu *plist, struct ns_pktfld *pf, ulong *len)
{
	return fld_get_pi(p, plist, pf, 0, len);
}


int fld_get_vi(byte_t *p, struct pdu *plist, struct ns_pktfld *pf, uint idx,
	       ulong *v)
{
	struct pdu *pdu;
	ulong off;
	ulong len;

	if (getinfo(plist, pf, idx, &pdu, &off, &len) < 0)
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		*v = getbits(p, bitoff(off, pf), pf->len);
	} else {
		*v = be32val(p + off, len);
	}

	return 0;
}


int fld_get_bi(byte_t *sp, struct pdu *plist, struct ns_pktfld *pf, uint idx,
	       void *dp, size_t len)
{
	struct pdu *pdu;
	ulong flen;
	ulong off;
	ulong v;

	if (getinfo(plist, pf, idx, &pdu, &off, &flen) < 0)
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		v = getbits(sp, bitoff(off, pf), pf->len);
		wrbe32(dp, len, v);
	} else {
		if (len > flen)
			len = flen;
		memmove(dp, sp + off, len);
	}	

	return 0;
}


int fld_set_vi(byte_t *dp, struct pdu *plist, struct ns_pktfld *pf, uint idx,
	       ulong v)
{
	struct pdu *pdu;
	ulong off;
	ulong len;

	if (getinfo(plist, pf, idx, &pdu, &off, &len) < 0)
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		setbits(dp, bitoff(off, pf), pf->len, v);
	} else {
		wrbe32(dp + off, len, v);
	}

	return 0;
}


int fld_set_bi(byte_t *dp, struct pdu *plist, struct ns_pktfld *pf, uint idx,
	       void *sp, size_t len)
{
	struct pdu *pdu;
	ulong off;
	ulong flen;
	ulong v;

	if (getinfo(plist, pf, idx, &pdu, &off, &flen) < 0)
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		v = be32val(sp, len);
		setbits(dp, bitoff(off, pf), pf->len, v);
	} else {
		if (flen < len)
			len = flen;
		memmove(dp + off, sp, len);
	}

	return 0;
}


int fld_get_v(byte_t *p, struct pdu *plist, struct ns_pktfld *pf, ulong *v)
{
	return fld_get_vi(p, plist, pf, 0, v);
}


int fld_get_b(byte_t *sp, struct pdu *plist, struct ns_pktfld *pf, void *dp,
	      size_t len)
{
	return fld_get_bi(sp, plist, pf, 0, dp, len);
}


int fld_set_v(byte_t *p, struct pdu *plist, struct ns_pktfld *pf, ulong v)
{
	return fld_set_vi(p, plist, pf, 0, v);
}


int fld_set_b(byte_t *dp, struct pdu *plist, struct ns_pktfld *pf, void *sp,
	      size_t len)
{
	return fld_set_bi(dp, plist, pf, 0, sp, len);
}


int fld_get_vni(byte_t *p, struct pdu *pdu, const char *s, uint idx, ulong *v)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_get_vi(p, pdu, (struct ns_pktfld *)e, idx, v);
}


int fld_get_bni(byte_t *sp, struct pdu *pdu, const char *s, uint idx, void *dp,
		size_t len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_get_bi(sp, pdu, (struct ns_pktfld *)e, idx, dp, len);
}


int fld_set_vni(byte_t *p, struct pdu *pdu, const char *s, uint idx, ulong v)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_set_vi(p, pdu, (struct ns_pktfld *)e, idx, v);
}


int fld_set_bni(byte_t *dp, struct pdu *pdu, const char *s, uint idx, void *sp,
		size_t len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_set_bi(dp, pdu, (struct ns_pktfld *)e, idx, sp, len);
}


int fld_get_vn(byte_t *p, struct pdu *pdu, const char *s, ulong *v)
{
	return fld_get_vni(p, pdu, s, 0, v);
}


int fld_get_bn(byte_t *sp, struct pdu *pdu, const char *s, void *dp, size_t len)
{
	return fld_get_bni(sp, pdu, s, 0, dp, len);
}


int fld_set_vn(byte_t *p, struct pdu *pdu, const char *s, ulong v)
{
	return fld_set_vni(p, pdu, s, 0, v);
}


int fld_set_bn(byte_t *dp, struct pdu *pdu, const char *s, void *sp, size_t len)
{
	return fld_set_bni(dp, pdu, s, 0, sp, len);
}


static struct list npf_cache;
static int npf_is_initialized;


static void _npf_init(void)
{
	l_init(&npf_cache);
	npf_is_initialized = 1;
}


static struct npfield *npf_new(struct pdu *pdu, byte_t *buf,
			       struct ns_elem *nse)
{
	struct npfield *npf;
	long len;

	if (l_isempty(&npf_cache)) {
		npf = calloc(sizeof(struct npfield), 1);
		if (npf == NULL)
			return NULL;
	} else {
		npf = l_to_npf(l_pop(&npf_cache));
	}

	npf->pdu = pdu;
	npf->buf = buf;
	npf->nse = nse;
	if (nse != NULL) {
		npf->off = fld_get_off(pdu, nse);
		len = fld_get_len(pdu, nse);
		if (len < 0)
			len = 0;
		npf->len = len;
	} else {
		/* gaps only: should be filled in immediately afterwards */
		npf->off = PDU_OFF_INVALID;
		npf->len = 0;
	}

	return npf;
}


static void npf_free(struct npfield *npf)
{
	memset(npf, 0, sizeof(struct npfield));
	free(npf);
}


static void npf_cache_node(struct npfield *npf)
{
	l_rem(&npf->le);
	memset(npf, 0, sizeof(struct npfield));
	l_enq(&npf_cache, &npf->le);
}


static void npfl_reset(struct npf_list *npfl)
{
	memset(npfl, 0, sizeof(struct npf_list));
	l_init(&npfl->list.le);
	npfl->list.len = (ulong)-1l;
}


static void insert_field(struct npf_list *npfl, struct npfield *npf)
{
	struct npfield *trav;

	trav = npfl_last(npfl);
	while (!npf_is_end(trav)) {
		if (trav->off <= npf->off)
			break;
		trav = npf_prev(trav);
	}
	l_ins(&trav->le, &npf->le);
	++npfl->nfields;
}


static int add_fields(struct npf_list *npfl, struct pdu *pdu,
		      struct ns_namespace *ns, npfl_filter_f filter)
{
	int i;
	int rv;
	ulong off;
	struct npfield *npf;
	struct ns_elem *nse;
	struct ns_namespace *subns;

	if (ns == NULL) {
		ns = ns_lookup_by_prid(pdu->prid);

		/* if we can't find the namespace we can't */
		/* claim to have all the fields in the list. */
		if (ns == NULL)
			return 0;

		if (filter == NULL || !filter((struct ns_elem *)ns)) {
			npf = npf_new(pdu, npfl->buf, (struct ns_elem *)ns);
			if (npf == NULL)
				return -1;
		
			insert_field(npfl, npf);
		}
	}

	for (i = 0; i < ns->nelem; ++i) {
		nse = ns->elems[i];

		/* NULL terminates the array early */
		if (nse == NULL)
			break;

		off = fld_get_off(pdu, nse);
		if (off == PDU_OFF_INVALID)
			continue;

		if (filter == NULL || !filter(nse)) {
			npf = npf_new(pdu, npfl->buf, nse);
			if (npf == NULL)
				return -1;
			insert_field(npfl, npf);
		}

		if (nse->type == NST_NAMESPACE) {
			subns = (struct ns_namespace *)nse;
			rv = add_fields(npfl, pdu, subns, filter);
			if (rv < 0)
				return rv;
		}
	}

	return 0;
}


void npfl_init(struct npf_list *npfl, struct pdu *plist, byte_t *buf)
{
	if (!npf_is_initialized)
		_npf_init();
	npfl_reset(npfl);
	npfl->plist = pdu_get_root(plist);
	npfl->buf = buf;
	npfl->nfields = 0;
	npfl->ngaps = 0;
}
		      

static void clear_nonflds(struct npf_list *npfl, ulong soff, ulong eoff,
			  int pduonly)
{
	struct list *le, *xtra;
	struct npfield *npf;
	ulong nr = 0;

	l_for_each_safe(le, xtra, &npfl->list.le) {
		npf = l_to_npf(le);
		if (npf_is_nonfld(npf) && npf->off >= soff && npf->off < eoff) {
			if (!pduonly || npf_is_pdu(npf)) {
				npf_cache_node(npf);
				++nr;
			}
		}
	}
	npfl->nfields -= nr;
	if (!pduonly)
		npfl->ngaps = 0;
}


static int add_gap(struct npf_list *npfl, ulong soff, ulong eoff,
		   struct pdu *pdu, struct npfield *prev)
{
	struct npfield *gap;

	gap = npf_new(pdu, npfl->buf, NULL);
	if (gap == NULL)
		return -1;
	gap->off = soff;
	gap->len = eoff - soff;
	gap->pdu = pdu;
	gap->buf = npfl->buf;
	l_ins(&prev->le, &gap->le);
	++npfl->nfields;
	++npfl->ngaps;

	return 0;
}


static int add_pdu_npf(struct npf_list *npfl, struct pdu *pdu)
{
	struct npfield *pdunpf;

	pdunpf = npf_new(pdu, NULL, NULL);
	if (pdunpf == NULL)
		return -1;
	pdunpf->off = pdu_soff(pdu) * 8;
	pdunpf->len = pdu_totlen(pdu) * 8;
	pdunpf->pdu = pdu;
	insert_field(npfl, pdunpf);

	return 0;
}


static struct npfield *find_first_npf(struct npf_list *npfl, struct pdu *pdu)
{
	struct npfield *prev, *trav;

	prev = &npfl->list;
	for (trav = npfl_first(npfl); trav->off < pdu_soff(pdu) * 8;
	     prev = trav, trav = npf_next(prev))
			;
	return prev;
}


static struct npfield *next_npf_or_null(struct npfield *npf)
{
	if (npf == NULL)
		return NULL;
	npf = npf_next(npf);
	if (npf_is_end(npf))
		return NULL;
	return npf;
}


static int fill_gaps(struct npf_list *npfl, struct pdu *opdu)
{
	struct npfield *before = NULL, *after;
	struct pdu *ipdu = NULL;
	int rv;
	ulong soff;
	ulong ohi;
	ulong onext;
	ulong eoff;

	if (pdu_is_root(opdu)) {
		soff = pdu_poff(opdu) * 8;
		eoff = pdu_toff(opdu) * 8;
	} else {
		soff = pdu_soff(opdu) * 8;
		eoff = pdu_eoff(opdu) * 8;
	}
	ohi = soff;

	/*
	 * check for nice case: inner parse goes all the way to the end of the
	 * outer parse.  If so, stop at the start of the inner parse.
	 * Otherwise, there may be gaps between inner parses.
	 */
	ipdu = pdu_next_in_region(opdu, opdu);
	if (ipdu != NULL && pdu_eoff(ipdu) * 8 >= eoff) {
		eoff = pdu_soff(ipdu) * 8;
	} else {
		/* 
		 * add parse NPFs as placeholders to simplify gap 
		 * insertion. We only insert gaps that are in the 
		 * outer pdu, but not enclosed in any of the inner pdus.
		 */
		for ( ; ipdu != NULL; ipdu = pdu_next_in_region(ipdu, opdu)) {
			if (add_pdu_npf(npfl, ipdu) < 0) {
				rv = -1;
				goto err;
			}
		}
	}

	before = find_first_npf(npfl, opdu);
	after = next_npf_or_null(before);
	while (ohi < eoff) {
		onext = (after == NULL) ? eoff : after->off;
		if (onext > ohi) {
			rv = add_gap(npfl, ohi, onext, opdu, before);
			if (rv < 0)
				goto err;
		}

		/* Do NOT skip field offsets for namespace elements */
		if (after != NULL && 
		    (after->nse == NULL || after->nse->type == NST_PKTFLD)) {
			onext = after->off + after->len;
			if (onext > ohi)
				ohi = onext;
		} else {
			ohi = onext;
		}
		before = after;
		after = next_npf_or_null(after);
	}

	/* remove all the parse NPFs */
	clear_nonflds(npfl, soff, eoff, 1);
	return 0;

err:
	/* remove all gap and parse NPFs */
	clear_nonflds(npfl, soff, eoff, 0);
	return rv;

}


int npfl_load(struct npf_list *npfl, struct pdu *pdu, int fill,
	      npfl_filter_f filter)
{
	int rv;

	if (!npf_is_initialized)
		_npf_init();

	if (npfl == NULL || pdu == NULL)
		return -1;

	rv = add_fields(npfl, pdu, NULL, filter);
	if (rv < 0) {
		npfl_cache(npfl);
		return rv;
	}

	if (fill) {
		rv = fill_gaps(npfl, pdu);
		if (rv < 0) {
			npfl_cache(npfl);
			return rv;
		}
	}

	return 0;
}


void npfl_clear(struct npf_list *npfl)
{
	struct list *le, *xtra;

	l_for_each_safe(le, xtra, &npfl->list.le) {
		l_rem(le);
		npf_free(l_to_npf(le));
	}
	npfl_reset(npfl);
}


void npfl_cache(struct npf_list *npfl)
{
	if (!npf_is_initialized)
		_npf_init();

	l_append(&npf_cache, &npfl->list.le);
	npfl_reset(npfl);
}


void npfl_clear_cache(void)
{
	struct list *le, *extra;

	if (!npf_is_initialized)
		_npf_init();

	l_for_each_safe(le, extra, &npf_cache) {
		l_rem(le);
		npf_free(l_to_npf(le));
	}
}


int npf_eq(struct npfield *npf1, struct npfield *npf2)
{
	ulong len;
	ulong off1;
	ulong off2;

	if (!npf_type_eq(npf1, npf2))
		return 0;

	len = npf1->len;
	if (len != npf2->len)
		return 0;

	if ((npf1->off % 8 == 0) && (npf2->off % 8 == 0) &&
	    (len % 8 == 0))  {

		/* not need to test npf2 length: we know its equal */
		return memcmp(npf1->buf + npf1->off/8,
			      npf2->buf + npf2->off/8,
			      len / 8) == 0;

	} else if (npf1->len < 32) {

		return getbits(npf1->buf, npf1->off, len) == 
		       getbits(npf2->buf, npf2->off, len);

	} else {
		/* really?  skewed bit fields longer than 32 bits? sigh... */
		/* fine, we'll go bit by bit */
		off1 = npf1->off;
		off2 = npf2->off;
		while (len > 0) {
			if (getbit(npf1->buf, off1) != getbit(npf2->buf, off2))
				return 0;
			++off1;
			++off2;
			--len;
		}

		return 1;
	}
}
