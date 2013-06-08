/*
 * ONICS
 * Copyright 2012 
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


ulong fld_get_off(struct prparse *prp, struct ns_elem *elem)
{
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	ulong off = PRP_OFF_INVALID;

	if (elem == NULL || prp == NULL)
		return PRP_OFF_INVALID;

	if (elem->type == NST_NAMESPACE) {
		ns = (struct ns_namespace *)elem;

		if (!prp_off_valid(prp, ns->oidx))
			return PRP_OFF_INVALID;

		off = prp->offs[ns->oidx] * 8;

	} else if (elem->type == NST_PKTFLD) {
		pf = (struct ns_pktfld *)elem;

		if (!prp_off_valid(prp, pf->oidx))
			return PRP_OFF_INVALID;

		off = (prp->offs[pf->oidx] + pf->off) * 8;
		if (NSF_IS_INBITS(pf->flags))
			off += NSF_BITOFF(pf->flags);
	}

	return off;
}


long fld_get_len(struct prparse *prp, struct ns_elem *elem)
{
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	long len = -1;

	if (elem->type == NST_NAMESPACE) {
		ns = (struct ns_namespace *)elem;

		if (!prp_off_valid(prp, ns->oidx))
			return -1;

		if (NSF_IS_VARLEN(ns->flags)) {
			if (!prp_off_valid(prp, ns->len))
				return -1;

			len = (prp->offs[ns->len] - prp->offs[ns->oidx]) * 8;
		} else {
			len = ns->len * 8;
		}


	} else {
		pf = (struct ns_pktfld *)elem;

		if (!prp_off_valid(prp, pf->oidx))
			return -1;

		if (NSF_IS_VARLEN(pf->flags)) {
			if (!prp_off_valid(prp, pf->len))
				return -1;
			len = (prp->offs[pf->len] - prp->offs[pf->oidx]) * 8;
		} else if (NSF_IS_INBITS(pf->flags)) {
			return pf->len;
		} else {
			len = pf->len * 8;
		}
	}

	return len;
}

static struct prparse *findprp(struct prparse *plist, uint prid, uint idx)
{
	struct prparse *prp;
	if (plist == NULL)
		return NULL;
	prp_for_each(prp, plist) {
		if ((prp->prid == prid) && (idx-- == 0))
			return prp;
	}
	return NULL;
}


static int pfofflen(struct prparse *prp, struct ns_pktfld *pf,
		    ulong *offp, ulong *lenp)
{
	ulong off, len;
	off = prp->offs[pf->oidx] + pf->off;
#if SANITY
	if (off > prp_totlen(prp))
		return -1;
#endif
	if (NSF_IS_INBITS(pf->flags)) {
		len = (off + pf->len + NSF_BITOFF(pf->flags) + 7) / 8;
#if SANITY
		if (prp_totlen(prp) - off > len)
			return -1;
#endif
	} else {
		if (NSF_IS_VARLEN(pf->flags)) {
#if SANITY
			if (!prp_off_valid(prp, pf->len) ||
			    (prp->offs[pf->len] < off))
				return -1;
#endif
			len = prp->offs[pf->len] - off;
		} else {
#if SANITY
			if (prp_totlen(prp) - off > pf->len)
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


static int getinfo(struct prparse *plist, struct ns_pktfld *pf, uint idx,
		   struct prparse **pprp, ulong *offp, ulong *lenp)
{
	struct prparse *prp;
	if (pf == NULL)
		return -1;

	prp = findprp(plist, pf->prid, idx);
	if (prp == NULL)
		return -1;

	if (!prp_off_valid(prp, pf->oidx))
		return -1;

	if (pfofflen(prp, pf, offp, lenp) < 0)
		return -1;

	if (pprp != NULL)
		*pprp = prp;

	return 0;
}


static ulong bitoff(ulong byteoff, struct ns_pktfld *pf)
{
	return byteoff * 8 + NSF_BITOFF(pf->flags);
}


int fld_exists(struct prparse *plist, struct ns_pktfld *pf, uint idx)
{
	struct prparse *prp;

	if (pf == NULL)
		return 0;

	prp = findprp(plist, pf->prid, idx);
	if (prp == NULL)
		return 0;

	return prp_off_valid(prp, pf->oidx);
}


struct prparse *fld_get_prpi(struct prparse *plist, struct ns_namespace *ns,
			     uint idx)
{
	if (ns == NULL)
		return NULL;
	return findprp(plist, ns->prid, idx);
}


struct prparse *fld_get_prpni(struct prparse *plist, const char *s, uint idx)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return findprp(plist, ((struct ns_namespace *)e)->prid, idx);
}


struct prparse *fld_get_prp(struct prparse *plist, struct ns_namespace *ns)
{
	return fld_get_prpi(plist, ns, 0);
}


struct prparse *fld_get_prpn(struct prparse *plist, const char *s)
{
	return fld_get_prpni(plist, s, 0);
}


void *fld_get_hdri(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		   uint idx, ulong *len)
{
	struct prparse *prp;

	if (ns == NULL)
		return NULL;

	prp = findprp(plist, ns->prid, idx);
	if (prp == NULL)
		return NULL;

	if (len != NULL)
		*len = prp_hlen(prp);

	return prp_header(prp, p, void);
}


void *fld_get_pldi(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		   uint idx, ulong *len)
{
	struct prparse *prp;

	if (ns == NULL)
		return NULL;

	prp = findprp(plist, ns->prid, idx);
	if (prp == NULL)
		return NULL;

	if (len != NULL)
		*len = prp_plen(prp);

	return prp_payload(prp, p);
}


void *fld_get_trli(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		   uint idx, ulong *len)
{
	struct prparse *prp;

	if (ns == NULL)
		return NULL;

	prp = findprp(plist, ns->prid, idx);
	if (prp == NULL)
		return NULL;

	if (len != NULL)
		*len = prp_tlen(prp);

	return prp_trailer(prp, p, void);
}


void *fld_get_hdrni(byte_t *p, struct prparse *plist, const char *s,
		    uint idx, ulong *len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return fld_get_hdri(p, plist, (struct ns_namespace *)e, idx, len);
}


void *fld_get_pldni(byte_t *p, struct prparse *plist, const char *s,
		    uint idx, ulong *len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return fld_get_pldi(p, plist, (struct ns_namespace *)e, idx, len);
}


void *fld_get_trlni(byte_t *p, struct prparse *plist, const char *s,
		    uint idx, ulong *len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return fld_get_trli(p, plist, (struct ns_namespace *)e, idx, len);
}


void *fld_get_hdr(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		  ulong *len)
{
	return fld_get_hdri(p, plist, ns, 0, len);
}


void *fld_get_pld(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		  ulong *len)
{
	return fld_get_pldi(p, plist, ns, 0, len);
}


void *fld_get_trl(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		  ulong *len)
{
	return fld_get_trli(p, plist, ns, 0, len);
}


void *fld_get_hdrn(byte_t *p, struct prparse *plist, const char *s,
		   ulong *len)
{
	return fld_get_hdrni(p, plist, s, 0, len);
}


void *fld_get_pldn(byte_t *p, struct prparse *plist, const char *s,
		   ulong *len)
{
	return fld_get_pldni(p, plist, s, 0, len);
}


void *fld_get_trln(byte_t *p, struct prparse *plist, const char *s,
		  ulong *len)
{
	return fld_get_trlni(p, plist, s, 0, len);
}


void *fld_get_pi(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
		uint idx, ulong *len)
{
	ulong off;

	if (getinfo(plist, pf, idx, NULL, &off, len) < 0)
		return NULL;

	return p + off;
}


int fld_get_vi(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	       uint idx, ulong *v)
{
	struct prparse *prp;
	ulong off;
	ulong len;

	if (getinfo(plist, pf, idx, &prp, &off, &len) < 0)
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		*v = getbits(p, bitoff(off, pf), pf->len);
	} else {
		*v = be32val(p + off, len);
	}

	return 0;
}


int fld_get_bi(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
	       uint idx, void *dp, size_t len)
{
	struct prparse *prp;
	ulong flen;
	ulong off;
	ulong v;

	if (getinfo(plist, pf, idx, &prp, &off, &flen) < 0)
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


int fld_set_vi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	       uint idx, ulong v)
{
	struct prparse *prp;
	ulong off;
	ulong len;

	if (getinfo(plist, pf, idx, &prp, &off, &len) < 0)
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		setbits(dp, bitoff(off, pf), pf->len, v);
	} else {
		wrbe32(dp + off, len, v);
	}

	return 0;
}


int fld_set_bi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	       uint idx, void *sp, size_t len)
{
	struct prparse *prp;
	ulong off;
	ulong flen;
	ulong v;

	if (getinfo(plist, pf, idx, &prp, &off, &flen) < 0)
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


int fld_get_v(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	      ulong *v)
{
	return fld_get_vi(p, plist, pf, 0, v);
}


int fld_get_b(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
	      void *dp, size_t len)
{
	return fld_get_bi(sp, plist, pf, 0, dp, len);
}


int fld_set_v(byte_t *p, struct prparse *plist, struct ns_pktfld *pf, ulong v)
{
	return fld_set_vi(p, plist, pf, 0, v);
}


int fld_set_b(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	      void *sp, size_t len)
{
	return fld_set_bi(dp, plist, pf, 0, sp, len);
}


int fld_get_vni(byte_t *p, struct prparse *prp, const char *s, uint idx,
	        ulong *v)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_get_vi(p, prp, (struct ns_pktfld *)e, idx, v);
}


int fld_get_bni(byte_t *sp, struct prparse *prp, const char *s, uint idx,
	        void *dp, size_t len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_get_bi(sp, prp, (struct ns_pktfld *)e, idx, dp, len);
}


int fld_set_vni(byte_t *p, struct prparse *prp, const char *s, uint idx,
	        ulong v)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_set_vi(p, prp, (struct ns_pktfld *)e, idx, v);
}


int fld_set_bni(byte_t *dp, struct prparse *prp, const char *s, uint idx,
	        void *sp, size_t len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_set_bi(dp, prp, (struct ns_pktfld *)e, idx, sp, len);
}


int fld_get_vn(byte_t *p, struct prparse *prp, const char *s, ulong *v)
{
	return fld_get_vni(p, prp, s, 0, v);
}


int fld_get_bn(byte_t *sp, struct prparse *prp, const char *s,
	       void *dp, size_t len)
{
	return fld_get_bni(sp, prp, s, 0, dp, len);
}


int fld_set_vn(byte_t *p, struct prparse *prp, const char *s, ulong v)
{
	return fld_set_vni(p, prp, s, 0, v);
}


int fld_set_bn(byte_t *dp, struct prparse *prp, const char *s,
	       void *sp, size_t len)
{
	return fld_set_bni(dp, prp, s, 0, sp, len);
}

