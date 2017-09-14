/*
 * ONICS
 * Copyright 2013-2015
 * Christopher Adam Telfer
 *
 * enum_proto.c -- Enumerate the protocol fields in the standard protocols.
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
#include <stdio.h>
#include <string.h>
#include <cat/str.h>
#include "ns.h"
#include "stdproto.h"
#include "util.h"

static void build_name(struct ns_elem *elem, const char *pfx,
		       char *name, size_t nsize)
{
	if (pfx != NULL) {
		str_copy(name, pfx, nsize);
		str_cat(name, ".", nsize);
		str_cat(name, elem->name, nsize);
	} else {
		str_copy(name, elem->name, nsize);
	}
}


static void dump_elem(struct ns_elem *elem, FILE *out, const char *pfx)
{
	char name[256];
	struct ns_pktfld *pf;
	struct ns_scalar *sc;
	struct ns_bytestr *bs;
	struct ns_maskstr *ms;

	build_name(elem, pfx, name, sizeof(name));

	if (elem->type == NST_PKTFLD) {
		pf = (struct ns_pktfld *)elem;
		fprintf(out, "\t%s: field - %s\n", name, pf->fullname);
	} else if (elem->type == NST_SCALAR) {
		sc = (struct ns_scalar *)elem;
		fprintf(out, "\t%s: scalar - %lu (%lx)\n", name, sc->value,
			sc->value);
	} else if (elem->type == NST_BYTESTR) {
		bs = (struct ns_bytestr *)elem;
		fprintf(out, "\t%s: byte string -\n", name);
		fhexdump(out, "\t\t", 0, bs->value.data, bs->value.len);
	} else if (elem->type == NST_MASKSTR) {
		ms = (struct ns_maskstr *)elem;
		fprintf(out, "\t%s: masked string -\n", name);
		fprintf(out, "\t\tValue:\n");
		fhexdump(out, "\t\t", 0, ms->value.data, ms->value.len);
		fprintf(out, "\t\tMask:\n");
		fhexdump(out, "\t\t", 0, ms->mask.data, ms->mask.len);
	} else {
		abort_unless(0);
	}
}


struct pmlfld { 
	const char *name;
	const char *desc;
} pml_fields[] = { 
	{ "hlen", "header length" }, 
	{ "plen", "payload length" }, 
	{ "tlen", "trailer length" },
	{ "totlen", "total PDU length" },
	{ "error", "error bitmap for PDU" },
	{ "prid", "protocol ID" }, 
	{ "index", "index of parse in list" }, 
	{ "header", "PDU header portion" }, 
	{ "payload", "PDU payload portion" },
	{ "trailer", "PDU trailer portion" },
	{ "parse", "entire PDU (as byte string)" },
};


static void print_pml_fields(FILE *out, const char *pfx)
{
	int i;
	for (i = 0; i < array_length(pml_fields); ++i)
		fprintf(out, "\t%s.%s: PML field - %s\n", pfx,
			pml_fields[i].name, pml_fields[i].desc);
}


void ns_dump(const struct ns_namespace *ns, FILE *out, const char *pfx, int lvl)
{
	uint i;
	char name[256];

	if (strcmp(ns->name, "") != 0) {
		build_name((struct ns_elem *)ns, pfx, name, sizeof(name));
		if (lvl == 1) {
			fprintf(out, "%s: protocol - PRID=0x%04x\n", name,
				ns->prid);
			print_pml_fields(out, name);
		} else {
			fprintf(out, "%s: protocol sub-namespace\n", name);
		}
		pfx = name;
	}

	for (i = 0; i < ns->nelem; ++i) {
		if (ns->elems[i] == NULL ||
		    ns->elems[i]->type == NST_NAMESPACE)
			continue;
		dump_elem(ns->elems[i], out, pfx);
	}
	for (i = 0; i < ns->nelem; ++i) {
		if (ns->elems[i] == NULL ||
		    ns->elems[i]->type != NST_NAMESPACE)
			continue;
		ns_dump((struct ns_namespace *)ns->elems[i], out, pfx, lvl+1);
	}
	if (lvl == 1)
		fprintf(out, "\n");
}


int main(int argc, char *argv[])
{
	register_std_proto();
	ns_dump(ns_get_root(), stdout, NULL, 0);
	return 0;
}
