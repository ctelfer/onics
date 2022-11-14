/*
 * ONICS
 * Copyright 2012-2022
 * Christopher Adam Telfer
 *
 * ns.c -- Library for managing protocol namespaces.
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
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>

#include <cat/str.h>

#include "ns.h"
#include "util.h"

static struct ns_namespace *pridtab[PRID_MAX+1];
static struct ns_elem *rootelem[256] = { 0 };
static struct ns_namespace rootns =
	NS_NAMESPACE_ROOT(rootelem, array_length(rootelem));

#define TYPEOK(t) ((t) <= NST_MASKSTR)

const struct ns_namespace *ns_get_root()
{
	return &rootns;
}


int ns_add_elem(struct ns_namespace *ns, struct ns_elem *e)
{
	int id;
	int freeid = -1;
	struct ns_elem *e2;
	struct ns_namespace *ns2;

	abort_unless(e && TYPEOK(e->type));

	if (ns == NULL)
		ns = &rootns;

	if (ns->prid > PRID_MAX)
		return -1;

	freeid = -1;
	for (id = 0; id < ns->nelem; ++id) {
		e2 = ns->elems[id];
		if (e2 == NULL) {
			if (freeid < 0)
				freeid = id;
			continue;
		}
		if (e2->name == NULL)
			continue;
		if (strcmp(e2->name, e->name) == 0)
			return -1;
	}

	if (freeid == -1)
		return -1;

	e->parent = ns;
	ns->elems[freeid] = e;
	if (e->type == NST_NAMESPACE) {
		ns2 = (struct ns_namespace *)e;
		if (pridtab[ns2->prid] == NULL)
			pridtab[ns2->prid] = ns2;
	}

	return 0;
}


void ns_rem_elem(struct ns_elem *e)
{
	struct ns_namespace *ns, *ns2;
	int id;

	abort_unless(e && TYPEOK(e->type));

	ns = e->parent;
	if (ns != NULL) {
		abort_unless(ns->type == NST_NAMESPACE);
		abort_unless(ns->elems != NULL);

		for (id = 0; id < ns->nelem; ++id)
			if (ns->elems[id] == e)
				break;

		abort_unless(id < ns->nelem);
		ns->elems[id] = NULL;
		e->parent = NULL;

		if (e->type == NST_NAMESPACE) {
			ns2 = (struct ns_namespace *)e;
			if (pridtab[ns2->prid] == ns2)
				pridtab[ns2->prid] = NULL;
		}
	}
}


struct ns_elem *ns_lookup(struct ns_namespace *ns, const char *name)
{
	struct ns_elem *elem = NULL;
	const char *p, *e;
	int i;

	abort_unless(name);

	p = name;
	if (!ns)
		ns = &rootns;

	while (*p != '\0') {
		for (e = p; *e != '\0' && *e != '.'; ++e) ;

		for (i = 0; i < ns->nelem; ++i) {
			elem = ns->elems[i];
			if (elem == NULL || elem->name == NULL)
				continue;
			if ((strncmp(elem->name, p, e - p) == 0) && 
			    (*(elem->name + (e - p)) == '\0'))
				break;
		}

		if (i == ns->nelem)
			return NULL;

		if (*e != '\0') {
			if (elem->type != NST_NAMESPACE)
				return NULL;
			ns = (struct ns_namespace *)elem;
			p = e + 1;
		}
		else {
			p = e;
		}
	}


	return elem;
}


struct ns_namespace *ns_lookup_by_prid(uint prid)
{
	if (prid > PRID_MAX)
		return NULL;
	return pridtab[prid];
}


static int pf_get_offlen(struct ns_pktfld *pf, struct pdu *pdu, ulong *off,
			 ulong *len)
{
	ulong nb;

	if (!pdu_off_valid(pdu, pf->oidx))
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		nb = (NSF_BITOFF(pf->flags) + pf->len + 7) / 8;
		abort_unless(pf->len <= sizeof(ulong) * 8);
		*len = pf->len;
	} else {
		if (NSF_IS_VARLEN(pf->flags)) {
			if (!pdu_off_valid(pdu, pf->len))
				return -1;
			/* sanity */
			if (pdu->offs[pf->len] <= pdu->offs[pf->oidx] + pf->off)
				return -1;
			nb = pdu->offs[pf->len] - (pdu->offs[pf->oidx] + pf->off);
			*len = nb;
		} else {
			nb = pf->len;
			*len = pf->len;
		} 
	}

	abort_unless(nb <= pdu_totlen(pdu));

	if (pf->off > pdu_totlen(pdu) - nb)
		return -1;

	*off = pdu->offs[pf->oidx] + pf->off;

	return 0;
}


static int ns_get_offlen(struct ns_namespace *ns, struct pdu *pdu, ulong *off,
			 ulong *len)
{
	if (!pdu_off_valid(pdu, ns->oidx))
		return -1;

	if (NSF_IS_VARLEN(ns->flags)) {
		if (!pdu_off_valid(pdu, ns->len))
			return -1;
		/* sanity */
		if (pdu->offs[ns->len] <= pdu->offs[ns->oidx])
			return -1;
		*len = pdu->offs[ns->len] - pdu->offs[ns->oidx];
	} else {
		*len = ns->len;
	} 

	*off = pdu->offs[ns->oidx];

	return 0;
}


int ns_fmt_summary(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
		   char *s, size_t ssize, const char *pfx)
{
	int r;
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	size_t nlen;
	ulong off, len;
	size_t soff;
	struct pdu *head;

	abort_unless(elem != NULL && pkt != NULL && pdu != NULL && s != NULL &&
	    	     ssize != 0);

	soff = 0;
	if (pfx != NULL) {
		soff = str_copy(s, pfx, ssize);
		if (soff >= ssize)
			return -1;
		s += soff;
		ssize -= soff;
	}

	if (elem->type == NST_NAMESPACE) {
		ns = (struct ns_namespace *)elem;
		r = ns_get_offlen(ns, pdu, &off, &len);
		if (r < 0)
			return r;
		nlen = str_copy(s, ns->fullname, ssize);
	} else if (elem->type == NST_PKTFLD) {
		pf = (struct ns_pktfld *)elem;
		r = pf_get_offlen(pf, pdu, &off, &len);
		if (r < 0)
			return r;
		nlen = str_copy(s, pf->fullname, ssize);
	} else {
		nlen = 0;
		abort_unless(0);
	}

	if (nlen >= ssize)
		return -1;
	s += nlen;
	ssize -= nlen;

	head = pdu_get_root(pdu);
	off -= pdu_poff(head);

	r = str_fmt(s, ssize, " -- [%lu:%lu]\n", off, len);
	if (r < 0)
		return -1;

	return 0;
}


int ns_fmt_raw(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	       char *s, size_t ssize, const char *pfx)
{
	int r;
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	size_t nlen;
	ulong off, len;
	size_t soff;
	struct pdu *head;

	abort_unless(elem != NULL && pkt != NULL && pdu != NULL && s != NULL &&
	    	     ssize != 0);

	soff = 0;
	if (pfx != NULL) {
		soff = str_copy(s, pfx, ssize);
		if (soff >= ssize)
			return -1;
		s += soff;
		ssize -= soff;
	}

	if (elem->type == NST_NAMESPACE) {
		ns = (struct ns_namespace *)elem;
		r = ns_get_offlen(ns, pdu, &off, &len);
		if (r < 0)
			return r;
		nlen = str_copy(s, ns->fullname, ssize);
	} else if (elem->type == NST_PKTFLD) {
		pf = (struct ns_pktfld *)elem;
		r = pf_get_offlen(pf, pdu, &off, &len);
		if (r < 0)
			return r;
		nlen = str_copy(s, pf->fullname, ssize);
	} else {
		nlen = 0;
		abort_unless(0);
	}

	if (nlen >= ssize)
		return -1;
	s += nlen;
	ssize -= nlen;

	head = pdu_get_root(pdu);
	off -= pdu_poff(head);
	r = 0;

	r = str_fmt(s, ssize, " -- [%lu:%lu]\n", off, len);
	if (r < 0)
		return -1;

	/* TODO add hex dump */

	return 0;
}



/* 
 * pad the string out to a specified width (sizeof(padding)) with
 * ":    .....   ".    return the number of non-null bytes
 * added or -1 if an error.  If the offset is already greater
 * than the padding length just add ": ".
 */
static int align(char *s, size_t ssize, size_t soff)
{
	static char padding[] = "                              ";

	/* must at least have space for ": " (including null terminator) */
	if (ssize < 3)
		return -1;

	if (soff >= sizeof(padding) - 2) {
		*s++ = ':';
		*s++ = ' ';
		return 2;
	} else {
		if (sizeof(padding) - soff + 1 >= ssize)
			return -1;
		*s++ = ':';
		str_copy(s, padding + soff, ssize-1);
		return sizeof(padding) - soff;
	}
}


static int getnum(struct ns_pktfld *pf, byte_t *pkt, struct pdu *pdu,
		  ulong *v)
{
	ulong off, len, val;

	abort_unless(pf != NULL && pkt != NULL && pdu != NULL && v != NULL);

	abort_unless(pdu->prid == pf->prid);

	if (pf_get_offlen(pf, pdu, &off, &len) < 0)
		return -1;
	pkt += off;

	if (NSF_IS_INBITS(pf->flags)) {
		*v = getbits(pkt, NSF_BITOFF(pf->flags), len);
	} else {
		if (len > sizeof(ulong))
			return -1;
		val = 0;
		do {
			val = (val << 8) | *pkt++;
		} while (--len > 0);
		*v = val;
	}

	return 0;
}


static int fmt_name(char *s, size_t ssize, const char *pfx,
		    const char *name)
{
	size_t soff;
	size_t noff;
	int r;

	soff = 0;
	if (pfx != NULL) {
		soff = str_copy(s, pfx, ssize);
		if (soff >= ssize)
			return -1;
		s += soff;
		ssize -= soff;
	}

	noff = str_copy(s, name, ssize);
	if (noff >= ssize)
		return -1;
	s += noff;
	ssize -= noff;
	soff += noff;

	r = align(s, ssize, soff);
	if (r < 0)
		return -1;
	soff += r;

	if (soff > INT_MAX)
		return -1;

	return (int)soff;
}


int ns_fmt_num(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	       char *s, size_t ssize, const char *pfx, int base)
{
	ulong v;
	struct ns_pktfld *pf;
	int r;
	size_t soff;
	ulong poff, plen;
	char fmt[16];

	abort_unless(elem != NULL && pkt != NULL && pdu != NULL && s != NULL &&
	    	     ssize != 0);

	if (elem->type != NST_PKTFLD)
		return -1;
	pf = (struct ns_pktfld *)elem;
	if (getnum(pf, pkt, pdu, &v) < 0)
		return -1;

	r = fmt_name(s, ssize, pfx, pf->fullname);
	if (r < 0)
		return -1;
	soff = r;

	if (base == 10) {
		r = str_fmt(s + soff, ssize - soff, "%lu\n", v);
	} else if (base == 16) {
		if (pf_get_offlen(pf, pdu, &poff, &plen) < 0)
			return -1;
		if (!NSF_IS_INBITS(pf->flags))
			plen *= 8;
		str_fmt(fmt, sizeof(fmt), "0x%%0%ux\n", (plen + 3) / 4);
		r = str_fmt(s + soff, ssize - soff, fmt, v);
	}
	if (r < 0)
		return -1;

	return 0;
}


int ns_fmt_dec(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	       char *s, size_t ssize, const char *pfx)
{
	return ns_fmt_num(elem, pkt, pdu, s, ssize, pfx, 10);
}



int ns_fmt_hex(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	       char *s, size_t ssize, const char *pfx)
{
	return ns_fmt_num(elem, pkt, pdu, s, ssize, pfx, 16);
}



int ns_fmt_nwlen(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	         char *s, size_t ssize, const char *pfx, int nw)
{
	ulong v;
	struct ns_pktfld *pf;
	size_t off;
	int r;
	int mul;

	abort_unless(elem != NULL && pkt != NULL && pdu != NULL && s != NULL &&
	    	     ssize != 0);

	if (elem->type != NST_PKTFLD)
		return -1;
	pf = (struct ns_pktfld *)elem;
	if (getnum(pf, pkt, pdu, &v) < 0)
		return -1;

	r = fmt_name(s, ssize, pfx, pf->fullname);
	if (r < 0)
		return -1;
	off = r;

	mul = 4 * nw;

	r = str_fmt(s + off, ssize - off, "%lu (%lu bytes)\n", v, v*mul);
	if (r < 0)
		return -1;

	return 0;
}


int ns_fmt_wlen(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	        char *s, size_t ssize, const char *pfx)
{
	return ns_fmt_nwlen(elem, pkt, pdu, s, ssize, pfx, 1);
}


int ns_fmt_qlen(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	        char *s, size_t ssize, const char *pfx)
{
	return ns_fmt_nwlen(elem, pkt, pdu, s, ssize, pfx, 2);
}


int ns_fmt_fbf(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	       char *s, size_t ssize, const char *pfx)
{
	ulong v;
	struct ns_pktfld *pf;
	size_t soff;
	int r;
	int foff;
	int fwidth;
	char fmt[16];

	abort_unless(elem != NULL && pkt != NULL && pdu != NULL && s != NULL &&
	    	     ssize != 0);

	if (elem->type != NST_PKTFLD)
		return -1;
	pf = (struct ns_pktfld *)elem;
	if (!NSPF_IS_FBF(pf))
		return -1;
	if (getnum(pf, pkt, pdu, &v) < 0)
		return -1;

	r = fmt_name(s, ssize, pfx, pf->fullname);
	if (r < 0)
		return -1;
	soff = r;

	foff = NSPF_FBF_FOFF(pf);
	fwidth = NSPF_FBF_FWIDTH(pf);

	/* account for \n\0 */
	if (ssize - soff < fwidth + 2)
		return -1;

	for (r = 0; r < foff; ++r)
		s[soff + r] = '.';
	soff += foff;
	str_fmt(fmt, sizeof(fmt), "%%0%db", pf->len);

	r = str_fmt(s + soff, ssize - soff, fmt, v);
	if (r < 0)
		return -1;
	while (r + foff < fwidth) {
		abort_unless(ssize - soff > r);
		s[soff + r] = '.';
		++r;
	}
	soff += r;
	abort_unless(ssize - soff >= 2);
	s[soff] = '\n';
	s[soff+1] = '\0';

	return 0;
}


static int buildstr(char *s, size_t ssize, const char *pfx, const char *name,
		    const char *data)
{
	size_t soff;
	size_t noff;
	int r;

	soff = 0;
	if (pfx != NULL) {
		soff = str_copy(s, pfx, ssize);
		if (soff >= ssize)
			return -1;
		s += soff;
		ssize -= soff;
	}

	noff = str_copy(s, name, ssize);
	if (noff >= ssize)
		return -1;
	s += noff;
	ssize -= noff;
	soff += noff;

	r = align(s, ssize, soff);
	if (r < 0)
		return -1;
	s += r;
	ssize -= r;

	r = str_fmt(s, ssize, "%s\n", data);
	if (r < 0)
		return -1;

	return 0;
}


int ns_fmt_ipv4a(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	         char *s, size_t ssize, const char *pfx)
{
	struct ns_pktfld *pf;
	ulong off, len, val;
	char buf[20];
	byte_t ipa[4];

	abort_unless(elem != NULL && pkt != NULL && pdu != NULL && s != NULL &&
	    	     ssize != 0);

	if (elem->type != NST_PKTFLD)
		return -1;
	pf = (struct ns_pktfld *)elem;

	abort_unless(pdu->prid == pf->prid);

	if (pf_get_offlen(pf, pdu, &off, &len) < 0)
		return -1;
	pkt += off;

	if (NSF_IS_INBITS(pf->flags)) {
		if (len != 32)
			return -1;
		val = getbits(pkt, NSF_BITOFF(pf->flags), 32);
		ipa[0] = (uint)(val >> 24) & 0xFF;
		ipa[1] = (uint)(val >> 16) & 0xFF;
		ipa[2] = (uint)(val >> 8)  & 0xFF;
		ipa[3] = (uint)(val >> 0)  & 0xFF;
		iptostr(buf, ipa, sizeof(buf));
	} else {
		if (len != 4)
			return -1;
		iptostr(buf, pkt, sizeof(buf));
	}

	return buildstr(s, ssize, pfx, pf->fullname, buf);
}


int ns_fmt_ipv6a(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	         char *s, size_t ssize, const char *pfx)
{
	struct ns_pktfld *pf;
	ulong off, len;
	char buf[52];

	abort_unless(elem != NULL && pkt != NULL && pdu != NULL && s != NULL &&
	    	     ssize != 0);

	if (elem->type != NST_PKTFLD)
		return -1;

	pf = (struct ns_pktfld *)elem;

	abort_unless(pdu->prid == pf->prid);

	if (pf_get_offlen(pf, pdu, &off, &len) < 0)
		return -1;
	pkt += off;

	if (len != 16)
		return -1;

	ip6tostr(buf, pkt, sizeof(buf));

	return buildstr(s, ssize, pfx,pf->fullname, buf);
}


int ns_fmt_etha(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	        char *s, size_t ssize, const char *pfx)
{
	struct ns_pktfld *pf;
	ulong off, len;
	char buf[20];

	abort_unless(elem != NULL && pkt != NULL && pdu != NULL && s != NULL &&
	    	     ssize != 0);

	if (elem->type != NST_PKTFLD)
		return -1;

	pf = (struct ns_pktfld *)elem;

	abort_unless(pdu->prid == pf->prid);

	if (pf_get_offlen(pf, pdu, &off, &len) < 0)
		return -1;
	pkt += off;

	if (len != 6)
		return -1;

	ethtostr(buf, pkt, sizeof(buf));

	return buildstr(s, ssize, pfx, pf->fullname, buf);
}


int ns_tostr(struct ns_elem *elem, byte_t *pkt, struct pdu *pdu,
	     char *s, size_t ssize, const char *pfx)
{
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	ns_format_f fmt;

	if (elem == NULL || pkt == NULL || pdu == NULL || s == NULL ||
	    ssize == 0)
		return -1;

	if (elem->type == NST_NAMESPACE) {
		ns = (struct ns_namespace *)elem;
		fmt = ns->fmt;
		if (fmt == NULL)
			fmt = ns_fmt_summary;
	} else if (elem->type == NST_PKTFLD) {
		pf = (struct ns_pktfld *)elem;
		fmt = pf->fmt;
		if (fmt == NULL)
			fmt = ns_fmt_dec;
	} else {
		return -1;
	}

	return (*fmt)(elem, pkt, pdu, s, ssize, pfx);
}


