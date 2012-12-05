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


struct prparse *fld_getprpi(struct prparse *plist, struct ns_namespace *ns,
			    uint idx)
{
	if (ns == NULL)
		return NULL;
	return findprp(plist, ns->prid, idx);
}


struct prparse *fld_getprpni(struct prparse *plist, const char *s, uint idx)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return findprp(plist, ((struct ns_namespace *)e)->prid, idx);
}


struct prparse *fld_getprp(struct prparse *plist, struct ns_namespace *ns)
{
	return fld_getprpi(plist, ns, 0);
}


struct prparse *fld_getprpn(struct prparse *plist, const char *s)
{
	return fld_getprpni(plist, s, 0);
}


void *fld_gethdri(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
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


void *fld_getpldi(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
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


void *fld_gettrli(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
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


void *fld_gethdrni(byte_t *p, struct prparse *plist, const char *s,
		   uint idx, ulong *len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return fld_gethdri(p, plist, (struct ns_namespace *)e, idx, len);
}


void *fld_getpldni(byte_t *p, struct prparse *plist, const char *s,
		   uint idx, ulong *len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return fld_getpldi(p, plist, (struct ns_namespace *)e, idx, len);
}


void *fld_gettrlni(byte_t *p, struct prparse *plist, const char *s,
		   uint idx, ulong *len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_NAMESPACE)
		return NULL;
	return fld_gettrli(p, plist, (struct ns_namespace *)e, idx, len);
}


void *fld_gethdr(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		 ulong *len)
{
	return fld_gethdri(p, plist, ns, 0, len);
}


void *fld_getpld(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		 ulong *len)
{
	return fld_getpldi(p, plist, ns, 0, len);
}


void *fld_gettrl(byte_t *p, struct prparse *plist, struct ns_namespace *ns,
		 ulong *len)
{
	return fld_gettrli(p, plist, ns, 0, len);
}


void *fld_gethdrn(byte_t *p, struct prparse *plist, const char *s,
		  ulong *len)
{
	return fld_gethdrni(p, plist, s, 0, len);
}


void *fld_getpldn(byte_t *p, struct prparse *plist, const char *s,
		  ulong *len)
{
	return fld_getpldni(p, plist, s, 0, len);
}


void *fld_gettrln(byte_t *p, struct prparse *plist, const char *s,
		  ulong *len)
{
	return fld_gettrlni(p, plist, s, 0, len);
}


void *fld_getpi(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
		uint idx, ulong *len)
{
	ulong off;

	if (getinfo(plist, pf, idx, NULL, &off, len) < 0)
		return NULL;

	return p + off;
}


int fld_getvi(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
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


int fld_getbi(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
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


int fld_setvi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
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


int fld_setbi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
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


int fld_getv(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	     ulong *v)
{
	return fld_getvi(p, plist, pf, 0, v);
}


int fld_getb(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
	     void *dp, size_t len)
{
	return fld_getbi(sp, plist, pf, 0, dp, len);
}


int fld_setv(byte_t *p, struct prparse *plist, struct ns_pktfld *pf, ulong v)
{
	return fld_setvi(p, plist, pf, 0, v);
}


int fld_setb(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	     void *sp, size_t len)
{
	return fld_setbi(dp, plist, pf, 0, sp, len);
}


int fld_getvni(byte_t *p, struct prparse *prp, const char *s, uint idx,
	       ulong *v)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_getvi(p, prp, (struct ns_pktfld *)e, idx, v);
}


int fld_getbni(byte_t *sp, struct prparse *prp, const char *s, uint idx,
	       void *dp, size_t len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_getbi(sp, prp, (struct ns_pktfld *)e, idx, dp, len);
}


int fld_setvni(byte_t *p, struct prparse *prp, const char *s, uint idx,
	       ulong v)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_setvi(p, prp, (struct ns_pktfld *)e, idx, v);
}


int fld_setbni(byte_t *dp, struct prparse *prp, const char *s, uint idx,
	       void *sp, size_t len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_setbi(dp, prp, (struct ns_pktfld *)e, idx, sp, len);
}


int fld_getvn(byte_t *p, struct prparse *prp, const char *s, ulong *v)
{
	return fld_getvni(p, prp, s, 0, v);
}


int fld_getbn(byte_t *sp, struct prparse *prp, const char *s,
	      void *dp, size_t len)
{
	return fld_getbni(sp, prp, s, 0, dp, len);
}


int fld_setvn(byte_t *p, struct prparse *prp, const char *s, ulong v)
{
	return fld_setvni(p, prp, s, 0, v);
}


int fld_setbn(byte_t *dp, struct prparse *prp, const char *s,
	      void *sp, size_t len)
{
	return fld_setbni(dp, prp, s, 0, sp, len);
}

