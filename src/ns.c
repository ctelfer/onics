/*
 * ONICS
 * Copyright 2012 
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

#include <cat/str.h>

#include "ns.h"
#include "util.h"

static struct ns_namespace *pridtab[PRID_MAX+1];
static struct ns_elem *rootelem[256] = { 0 };
static struct ns_namespace rootns =
	NS_NAMESPACE_ROOT(rootelem, array_length(rootelem));

#define TYPEOK(t) ((t) <= NST_MASKSTR)


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


static int pf_get_offlen(struct ns_pktfld *pf, struct prparse *prp, 
		       ulong *off, ulong *len)
{
	ulong nb;

	if (!prp_off_valid(prp, pf->oidx))
		return -1;

	if (NSF_IS_INBITS(pf->flags)) {
		nb = (NSF_BITOFF(pf->flags) + pf->len + 7) / 8;
		abort_unless(pf->len <= sizeof(ulong) * 8);
		*len = pf->len;
	} else {
		if (NSF_IS_VARLEN(pf->flags)) {
			if (!prp_off_valid(prp, pf->len))
				return -1;
			/* sanity */
			if (prp->offs[pf->len] <= prp->offs[pf->oidx] + pf->off)
				return -1;
			nb = prp->offs[pf->len] - (prp->offs[pf->oidx] + pf->off);
			*len = nb;
		} else {
			nb = pf->len;
			*len = pf->len;
		} 
	}

	abort_unless(nb <= prp_totlen(prp));

	if (pf->off > prp_totlen(prp) - nb)
		return -1;

	*off = prp->offs[pf->oidx] + pf->off;

	return 0;
}


static int ns_get_offlen(struct ns_namespace *ns, struct prparse *prp, 
		       ulong *off, ulong *len)
{
	if (!prp_off_valid(prp, ns->oidx))
		return -1;

	if (NSF_IS_VARLEN(ns->flags)) {
		if (!prp_off_valid(prp, ns->len))
			return -1;
		/* sanity */
		if (prp->offs[ns->len] <= prp->offs[ns->oidx])
			return -1;
		*len = prp->offs[ns->len] - prp->offs[ns->oidx];
	} else {
		*len = ns->len;
	} 

	*off = prp->offs[ns->oidx];

	return 0;
}


int ns_fmt_raw(struct ns_elem *elem, byte_t *pkt, struct prparse *prp,
	       struct raw *out)
{
	int r;
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	size_t nlen;
	ulong off, len;

	abort_unless(elem != NULL && pkt != NULL && prp != NULL && out != NULL);

	if (out->len == 0)
		return 0;

	abort_unless(out->data != NULL);

	if (elem->type == NST_NAMESPACE) {
		ns = (struct ns_namespace *)elem;
		r = ns_get_offlen(ns, prp, &off, &len);
		if (r < 0)
			return r;
		nlen = str_copy(out->data, ns->fullname, out->len);
	} else if (elem->type == NST_PKTFLD) {
		pf = (struct ns_pktfld *)elem;
		r = pf_get_offlen(pf, prp, &off, &len);
		if (r < 0)
			return r;
		nlen = str_copy(out->data, pf->fmtstr, out->len);
	} else {
		abort_unless(0);
	}

	r = 0;
	if (nlen < out->len)
		r = snprintf(out->data + nlen - 1, out->len - nlen + 1,
			     " -- Offset %lu, Length %lu", off, len);

	return r;
}


static int getnum(struct ns_pktfld *pf, byte_t *pkt, struct prparse *prp,
		  ulong *v)
{
	ulong off, len, val;

	abort_unless(pf != NULL && pkt != NULL && prp != NULL && v != NULL);

	abort_unless(prp->prid == pf->prid);

	if (pf_get_offlen(pf, prp, &off, &len) < 0)
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


int ns_fmt_num(struct ns_elem *elem, byte_t *pkt, struct prparse *prp,
	       struct raw *out)
{
	ulong v;
	struct ns_pktfld *pf;

	if (elem->type != NST_PKTFLD)
		return -1;
	pf = (struct ns_pktfld *)elem;
	if (getnum(pf, pkt, prp, &v) < 0)
		return -1;

	return snprintf(out->data, out->len, pf->fmtstr, v);
}


int ns_fmt_wlen(struct ns_elem *elem, byte_t *pkt, struct prparse *prp,
	        struct raw *out)
{
	ulong v;
	struct ns_pktfld *pf;

	if (elem->type != NST_PKTFLD)
		return -1;
	pf = (struct ns_pktfld *)elem;
	if (getnum(pf, pkt, prp, &v) < 0)
		return -1;

	return snprintf(out->data, out->len, pf->fmtstr, v, v*4);
}


int ns_fmt_ipv4a(struct ns_elem *elem, byte_t *pkt, struct prparse *prp,
	         struct raw *out)
{
	struct ns_pktfld *pf;
	ulong off, len, val;
	char buf[20];

	abort_unless(elem != NULL && pkt != NULL && prp != NULL && out != NULL);

	if (elem->type != NST_PKTFLD)
		return -1;
	pf = (struct ns_pktfld *)elem;

	abort_unless(prp->prid == pf->prid);

	if (pf_get_offlen(pf, prp, &off, &len) < 0)
		return -1;
	pkt += off;

	if (NSF_IS_INBITS(pf->flags)) {
		if (len != 32)
			return -1;
		val = getbits(pkt, NSF_BITOFF(pf->flags), 32);
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u", 
			 (uint)(val >> 24) & 0xFF, (uint)(val >> 16) & 0xFF, 
			 (uint)(val >> 8) & 0xFF, (uint)val & 0xFF);

	} else {
		if (len != 4)
			return -1;
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
			 pkt[0], pkt[1], pkt[2], pkt[3]);
	}

	/* TODO: check format string for single %s */
	return snprintf(out->data, out->len, pf->fmtstr, buf);
}


int ns_fmt_ipv6a(struct ns_elem *elem, byte_t *pkt, struct prparse *prp,
	         struct raw *out)
{
	struct ns_pktfld *pf;
	ulong off, len;
	char buf[52];

	abort_unless(elem != NULL && pkt != NULL && prp != NULL && out != NULL);

	if (elem->type != NST_PKTFLD)
		return -1;

	pf = (struct ns_pktfld *)elem;

	abort_unless(prp->prid == pf->prid);

	if (pf_get_offlen(pf, prp, &off, &len) < 0)
		return -1;
	pkt += off;

	if (len != 16)
		return -1;

	snprintf(buf, sizeof(buf), 
		 "%x:%x:%x:%x:%x:%x:%x:%x",
		 pkt[0] << 8 | pkt[1], 
		 pkt[2] << 8 | pkt[3], 
		 pkt[4] << 8 | pkt[5], 
		 pkt[6] << 8 | pkt[7], 
		 pkt[8] << 8 | pkt[9], 
		 pkt[10] << 8 | pkt[11], 
		 pkt[12] << 8 | pkt[13], 
		 pkt[14] << 8 | pkt[15]);

	/* TODO: check format string for single %s */
	return snprintf(out->data, out->len, pf->fmtstr, buf);
}


int ns_fmt_etha(struct ns_elem *elem, byte_t *pkt, struct prparse *prp,
	        struct raw *out)
{
	struct ns_pktfld *pf;
	ulong off, len;
	char buf[20];

	abort_unless(elem != NULL && pkt != NULL && prp != NULL && out != NULL);

	if (elem->type != NST_PKTFLD)
		return -1;

	pf = (struct ns_pktfld *)elem;

	abort_unless(prp->prid == pf->prid);

	if (pf_get_offlen(pf, prp, &off, &len) < 0)
		return -1;
	pkt += off;

	if (len != 6)
		return -1;

	snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
		 pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);

	/* TODO: check format string for single %s */
	return snprintf(out->data, out->len, pf->fmtstr, buf);
}


int ns_tostr(struct ns_elem *elem, byte_t *pkt, struct prparse *prp,
	     struct raw *out)
{
	struct ns_namespace *ns;
	struct ns_pktfld *pf;
	ns_format_f fmt;

	if (elem == NULL || pkt == NULL || prp == NULL || out == NULL ||
	    out->data == NULL)
		return -1;

	if (elem->type == NST_NAMESPACE) {
		ns = (struct ns_namespace *)elem;
		fmt = ns->fmt;
		if (fmt == NULL)
			fmt = ns_fmt_raw;
	} else if (elem->type == NST_PKTFLD) {
		pf = (struct ns_pktfld *)elem;
		fmt = pf->fmt;
		if (fmt == NULL)
			fmt = ns_fmt_num;
	} else {
		return -1;
	}

	return (*fmt)(elem, pkt, prp, out);
}


