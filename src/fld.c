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


static uint pflen(struct prparse *prp, struct ns_pktfld *pf)
{
	ulong off;
	ulong len;

	off = prp->offs[pf->oidx] + pf->off;
#if SANITY
	if (off > prp_totlen(prp))
		return 0;
#endif
	if (NSF_IS_INBITS(pf->flags)) {
		len = (off + pf->len + NSF_BITOFF(pf->flags) + 7) / 8;
#if SANITY
		if (prp_totlen(prp) - off > len)
			return 0;
#endif
		return len;
	} else {
		if (NSF_IS_VARLEN(pf->flags)) {
#if SANITY
			if (!prp_off_valid(prp, pf->len))
				return 0;
#endif
			return prp->offs[pf->len] - prp->offs[pf->oidx];
		} else {
#if SANITY
			if (prp_totlen(prp) - off > pf->len)
				return 0
#endif
			return pf->len;
		}
	}
}


static int getparselen(struct prparse *plist, struct ns_pktfld *pf, uint idx,
		       struct prparse **pprp, ulong *lenp)
{
	struct prparse *prp;
	ulong len;
	if (pf == NULL)
		return -1;

	prp = findprp(plist, pf->prid, idx);
	if (prp == NULL)
		return -1;

	if (!prp_off_valid(prp, pf->oidx))
		return -1;

	len = pflen(prp, pf);
	if (len == 0)
		return -1;

	*pprp = prp;
	*lenp = len;

	return 0;
}


static ulong bitoff(struct prparse *prp, struct ns_pktfld *pf)
{
	return (prp->offs[pf->oidx] + pf->off) * 8 + NSF_BITOFF(pf->flags);
}


int fld_exists(struct prparse *plist, struct ns_pktfld *pf, uint idx)
{
	struct prparse *prp;

	prp = findprp(plist, pf->prid, idx);
	if (prp == NULL)
		return 0;

	return prp_off_valid(prp, pf->oidx);
}


int fld_getvi(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	       uint idx, uint64_t *v)
{
	struct prparse *prp;
	ulong len;

	if (getparselen(plist, pf, idx, &prp, &len) < 0)
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		*v = getbits(p, bitoff(prp, pf), pf->len);
	} else {
		*v = be64val(p + prp->offs[pf->oidx] + pf->off, len);
	}

	return 0;
}


int fld_getbi(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
	      uint idx, void *dp, size_t len)
{
	struct prparse *prp;
	ulong flen;
	ulong v;

	if (getparselen(plist, pf, idx, &prp, &flen) < 0)
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		v = getbits(sp, bitoff(prp, pf), pf->len);
		wrbe64(dp, len, v);
	} else {
		if (len > flen)
			memset((byte_t *)dp + flen, 0, flen - len);
		memmove(dp, sp + prp->offs[pf->oidx] + pf->off, len);
	}	

	return 0;
}


int fld_setvi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	      uint idx, uint64_t v)
{
	struct prparse *prp;
	ulong len;

	if (getparselen(plist, pf, idx, &prp, &len) < 0)
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		setbits(dp, bitoff(prp, pf), pf->len, v);
	} else {
		wrbe64(dp + prp->offs[pf->oidx] + pf->off, len, v);
	}

	return 0;
}


int fld_setbi(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	      uint idx, void *sp, size_t len)
{
	struct prparse *prp;
	ulong flen;
	uint64_t v;

	if (getparselen(plist, pf, idx, &prp, &flen) < 0)
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		v = be64val(sp, len);
		setbits(dp, bitoff(prp, pf), pf->len, v);
	} else {
		if (flen < len)
			len = flen;
		memmove(dp + prp->offs[pf->oidx] + pf->off, sp, len);
	}

	return 0;
}


int fld_getv(byte_t *p, struct prparse *plist, struct ns_pktfld *pf,
	     uint64_t *v)
{
	return fld_getvi(p, plist, pf, 0, v);
}


int fld_getb(byte_t *sp, struct prparse *plist, struct ns_pktfld *pf,
	     void *dp, size_t len)
{
	return fld_getbi(sp, plist, pf, 0, dp, len);
}


int fld_setv(byte_t *p, struct prparse *plist, struct ns_pktfld *pf, uint64_t v)
{
	return fld_setvi(p, plist, pf, 0, v);
}


int fld_setb(byte_t *dp, struct prparse *plist, struct ns_pktfld *pf,
	     void *sp, size_t len)
{
	return fld_setbi(dp, plist, pf, 0, sp, len);
}


int fld_getnvi(byte_t *p, struct prparse *prp, const char *s, uint idx,
	       uint64_t *v)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_getvi(p, prp, (struct ns_pktfld *)e, idx, v);
}


int fld_getnbi(byte_t *sp, struct prparse *prp, const char *s, uint idx,
	       void *dp, size_t len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_getbi(sp, prp, (struct ns_pktfld *)e, idx, dp, len);
}


int fld_setnvi(byte_t *p, struct prparse *prp, const char *s, uint idx,
	       uint64_t v)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_setvi(p, prp, (struct ns_pktfld *)e, idx, v);
}


int fld_setnbi(byte_t *dp, struct prparse *prp, const char *s, uint idx,
	       void *sp, size_t len)
{
	struct ns_elem *e;
	e = ns_lookup(NULL, s);
	if (e == NULL || e->type != NST_PKTFLD)
		return -1;
	return fld_setbi(dp, prp, (struct ns_pktfld *)e, idx, sp, len);
}


int fld_getnv(byte_t *p, struct prparse *prp, const char *s, uint64_t *v)
{
	return fld_getnvi(p, prp, s, 0, v);
}


int fld_getnb(byte_t *sp, struct prparse *prp, const char *s,
	      void *dp, size_t len)
{
	return fld_getnbi(sp, prp, s, 0, dp, len);
}


int fld_setnv(byte_t *p, struct prparse *prp, const char *s, uint64_t v)
{
	return fld_setnvi(p, prp, s, 0, v);
}


int fld_setnb(byte_t *dp, struct prparse *prp, const char *s,
	      void *sp, size_t len)
{
	return fld_setnbi(dp, prp, s, 0, sp, len);
}

