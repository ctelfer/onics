/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * x2hpkt.c -- Program to convert from xkpt format to hexpkt format.
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
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <cat/optparse.h>
#include <cat/err.h>
#include <string.h>
#include "prid.h"
#include "util.h"
#include "pktbuf.h"
#include "ns.h"
#include "stdproto.h"

FILE *g_file = NULL;
int g_keep_xhdr = 0;
ulong g_pktnum;
ulong g_ioff;
ulong g_pbase;
ulong g_len;
byte_t *g_p;
int g_do_flush = 0;

struct field {
	struct list		le;
	struct ns_elem *	elem;
	struct prparse *	prp;
	struct ns_namespace *	ns;
	ulong			off;	/* in bits */
	ulong			len;	/* in bits */
	int			depth;
	int			ishdr;
};


struct list free_fields;
struct list packet_fields;
struct list *next_field = NULL;

#define l_to_field(_le) container((_le), struct field, le)


struct clopt g_optarr[] = {
	CLOPT_INIT(CLOPT_NOARG, 'x', "--keep-xhdr", "keep xpkt hdr in dump"),
	CLOPT_INIT(CLOPT_NOARG, 'f', "--flush-out", "Flush output per packet"),
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help")
};

struct clopt_parser g_oparser =
	CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));



void usage(const char *estr)
{
	char ubuf[4096];
	if (estr != NULL)
		fprintf(stderr, "Error -- %s\n", estr);
	optparse_print(&g_oparser, ubuf, sizeof(ubuf));
	err("usage: %s [options]\n%s\n", g_oparser.argv[0], ubuf);
}


void parse_options()
{
	int rv;
	struct clopt *opt;
	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'x':
			g_keep_xhdr = 1;
			break;
		case 'f':
			g_do_flush = 1;
			break;
		case 'h':
			usage(NULL);
		}
	}
	if (rv < 0)
		usage(g_oparser.errbuf);
	if (rv < g_oparser.argc) {
		if ((g_file = fopen(g_oparser.argv[rv], "r")) == NULL)
			errsys("fopen: ");
	} else {
		g_file = stdin;
	}
}


void printsep()
{
	printf("#####\n");
}


void hexdump_at(ulong soff, ulong eoff)
{
	/* effective address == soff - (packet base + xpkt hdr off) */
	/* pointer offset = g_p + soff */
	/* length = end - start */
	hexdump(stdout, soff - g_pbase + g_ioff, g_p + soff, eoff - soff);
}


int getpfx(char *pfx, const char *in, uint plen)
{
	char const *end = in + plen - 3;
	char *pp = pfx;
	*pp++ = '#'; *pp++ = ' ';
	while ((*in != '\0') && (in < end))
		*pp++ = toupper(*in++);
	*pp++ = ':';
	*pp++ = ' ';
	*pp = '\0';
	return pp - pfx;
}


static int off_is_valid(struct prparse *prp, uint oi)
{
	return (oi < prp->noff) && (prp->offs[oi] != PRP_OFF_INVALID);
}


ulong get_pf_offset(struct ns_pktfld *pf, struct prparse *prp)
{
	if (!off_is_valid(prp, pf->oidx))
		return PRP_OFF_INVALID;
	return (prp->offs[pf->oidx] + pf->off) * 8;
}


ulong get_ns_offset(struct ns_namespace *ns, struct prparse *prp)
{
	if (!off_is_valid(prp, ns->oidx))
		return PRP_OFF_INVALID;
	return prp->offs[ns->oidx] * 8;
}


ulong get_offset(struct ns_elem *e, struct prparse *prp)
{
	if (e->type == NST_NAMESPACE)
		return get_ns_offset((struct ns_namespace *)e, prp);
	else if (e->type == NST_PKTFLD)
		return get_pf_offset((struct ns_pktfld *)e, prp);
	else
		return PRP_OFF_INVALID;
}


ulong get_pf_len(struct ns_pktfld *pf, struct prparse *prp)
{
	ulong soff, eoff;

	abort_unless(pf->oidx < prp->noff);

	soff = prp->offs[pf->oidx];
	abort_unless(soff != PRP_OFF_INVALID);

	if (NSF_IS_VARLEN(pf->flags)) {
		abort_unless(pf->len < prp->noff);
		abort_unless(prp->offs[pf->len] != PRP_OFF_INVALID);
		eoff = prp->offs[pf->len];
		abort_unless(eoff >= soff);
		return (eoff - soff) * 8;
	} else if (NSF_IS_INBITS(pf->flags)) {
		abort_unless(pf->len <= 32);
		return NSF_BITOFF(pf->flags) + pf->len * 8;
	} else {
		return pf->len * 8;
	}
}


ulong get_ns_len(struct ns_namespace *ns, struct prparse *prp)
{
	abort_unless(off_is_valid(prp, ns->oidx));

	if (NSF_IS_VARLEN(ns->flags)) {
		abort_unless(off_is_valid(prp, ns->len));
		return (prp->offs[ns->len] - prp->offs[ns->oidx]) * 8;
	} else {
		return ns->len * 8;
	}
}


ulong get_len(struct ns_elem *e, struct prparse *prp)
{
	if (e->type == NST_NAMESPACE)
		return get_ns_len((struct ns_namespace *)e, prp);
	else if (e->type == NST_PKTFLD)
		return get_pf_len((struct ns_pktfld *)e, prp);
	else
		abort_unless(0);
}


static const char *errstrs[7] = {
	"runt", 
	"header length", 
	"length field",
	"checksum",
	"option length",
	"option field",
	"protocol field"
};
void printerr(uint err)
{
	int first = 1;
	int i;
	if (err) {
		printf("#    Errors [0x%0x]: ", err);
		for (i = 0; i <= PRP_ERR_MAXBIT; ++i) {
			if (err & (1 << i)) {
				if (!first)
					fputs(", ", stdout);
				else
					first = 0;
				fputs(errstrs[i], stdout);
			}
		}
		fputc('\n', stdout);
	}
}


int get_depth(struct prparse *prp)
{
	int i;
	for (i = 0; prp != NULL; prp = prp->region, ++i)
		;
	return i;
}


void init_fields()
{
	l_init(&free_fields);
	l_init(&packet_fields);
}


struct field *alloc_field()
{
	struct list *l;
	struct field *f;

	if (l = l_deq(&free_fields)) {
		f = l_to_field(l);
		memset(f, 0, sizeof(*f));
	} else {
		f = (struct field *)calloc(sizeof(*f), 1);
	}

	return f;
}


int field_cmp(struct field *f1, struct field *f2)
{
	if (f1->off > f2->off)
		return 1;
	if (f1->off == f2->off)
		return f2->depth - f1->depth;
	return -1;
}


void insert_field(struct field *f)
{
	struct list *trav;

	l_for_each_rev(trav, &packet_fields)
		if (field_cmp(l_to_field(trav), f) <= 0)
			break;

	l_ins(trav, &f->le);
}


void release_fields()
{
	l_move(&packet_fields, &free_fields);
}


int add_fields(struct prparse *prp, struct ns_namespace *ns)
{
	ulong off;
	int i, j;
	struct ns_elem *e;
	struct field *f;
	struct ns_namespace *subns;
	int depth;

	depth = get_depth(prp);

	if (ns == NULL) {
		ns = ns_lookup_by_prid(prp->prid);
		if (ns == NULL)
			return 0; 
		
		if ((f = alloc_field()) == NULL)
			return -1;

		f->elem = (struct ns_elem *)ns;
		f->prp = prp;
		f->ns = ns;
		f->off = prp_soff(prp) * 8;
		f->len = prp_totlen(prp) * 8;
		f->depth = depth;
		f->ishdr = 1;

		insert_field(f);
	}
			
	for (i = 0; i < ns->nelem; ++i) {
		e = ns->elems[i];

		if (e == NULL)
			break;

		off = get_offset(e, prp);
		if (off == PRP_OFF_INVALID)
			continue;

		if ((f = alloc_field()) == NULL)
			return -1;

		f->elem = e;
		f->prp = prp;
		f->ns = ns;
		f->off = off;
		f->len = get_len(e, prp);
		f->depth = depth;

		insert_field(f);
			
		if (e->type == NST_NAMESPACE) {
			subns = (struct ns_namespace *)e;
			if (add_fields(prp, subns) < 0)
				return -1;
		}
	}

	return 0;
}


#define MAXLINE		256
#define MAXPFX		16
/* print all the fields in the array up through eoff */
void print_fields(ulong eoff)
{
	char line[MAXLINE];
	struct raw r;
	struct ns_elem *e;
	struct ns_namespace *ns, *lastns = NULL;
	struct ns_pktfld *pf;
	struct field *f;
	int rv;
	int i;


	while (next_field != l_end(&packet_fields)) {

		f = l_to_field(next_field);

		if (f->off >= eoff)
			return;

		e = f->elem;
		/* check for change of prefix */
		if (f->ns != lastns) {
			i = getpfx(line, f->ns->name, MAXPFX);
			r.data = line + i;
			r.len = MAXLINE - i;
		}

		if (e->type == NST_NAMESPACE) {
			ns = (struct ns_namespace *)e;
			printsep();
			rv = (*ns->fmt)(e, g_p, f->prp, &r);
			if (rv >= 0) {
				fputs(line, stdout);
				fputc('\n', stdout);
			}
			if (f->ishdr)
				printerr(f->prp->error);
			printsep();
		} else {
			pf = (struct ns_pktfld *)e;
			rv = (*pf->fmt)(e, g_p, f->prp, &r);
			if (rv >= 0) {
				fputs(line, stdout);
				fputc('\n', stdout);
			}
		}

		next_field = l_next(next_field);
	}
}



/* 
 * Print fields and data between soff and eoff.
 */
void dump_data(struct prparse *prp, ulong soff, ulong eoff, int prhdr)
{
	char pfx[MAXPFX];
	struct ns_namespace *ns;
	int rv = 0;
	ulong sbyte, ebyte;

	if (soff >= eoff)
		return;

	sbyte = (soff + 7) / 8;
	ebyte = (eoff + 7) / 8;

	ns = ns_lookup_by_prid(prp->prid);

	if (ns != NULL)
		getpfx(pfx, ns->name, MAXPFX);
	else if (prp->prid == PRID_NONE)
		snprintf(pfx, MAXPFX, "# DATA: ");
	else
		snprintf(pfx, MAXPFX, "# PRID-%u: ", prp->prid);

	if (prhdr)
		printf("%s Data -- %lu bytes [%lu, %lu]\n", pfx, 
		       ebyte - sbyte, sbyte - g_pbase + g_ioff, 
		       ebyte - g_pbase + g_ioff);

	hexdump_at(sbyte, ebyte);
}



ulong walk_and_print_parse(struct prparse *from, struct prparse *region,
			   ulong off)
{
	struct prparse *next;
	ulong soff, eoff;

	if ((next = prp_next_in_region(from, region)) == NULL) {
		eoff = (prp_list_head(region) ? prp_toff(region) :
		        prp_eoff(region)) * 8;
		if (off < eoff) {
			print_fields(eoff);
			dump_data(region, off, eoff, 1);
		}
		return eoff;
	}

	soff = prp_soff(next) * 8;
	eoff = prp_poff(next) * 8;

	if (off < soff) {
		print_fields(eoff);
		dump_data(region, off, soff, from != region);
	}

	print_fields(eoff);
	dump_data(next, soff, eoff, 0);

	off = walk_and_print_parse(next, next, eoff);

	eoff = prp_eoff(next) * 8;
	if (off < eoff) {
		print_fields(eoff);
		dump_data(next, off, eoff, 1);
		off = eoff;
	}

	return walk_and_print_parse(next, region, off);
}


void gather_fields(struct prparse *pktp)
{
	struct prparse *prp;
	for (prp = prp_next(pktp) ; !prp_list_end(prp) ; prp = prp_next(prp))
		if (add_fields(prp, NULL) < 0)
			err("Out of memory for packet %lu\n", g_pktnum);
}


void reset_field_pointer()
{
	next_field = l_head(&packet_fields);
}


void dump_to_hex_packet(struct pktbuf *pkb)
{
	struct prparse *prp;
	int rv;

	g_len = pkb_get_len(pkb);
	g_p = pkb->buf;
	prp = &pkb->prp;
	g_pbase = prp_poff(prp);

	if (g_keep_xhdr) {
		struct xpkt *xp = pkb_get_xpkt(pkb);
		g_ioff = xpkt_doff(xp);
		abort_unless(prp_toff(prp) + g_ioff > g_ioff);
		printsep();
		printf("# Packet %lu -- %lu bytes\n", g_pktnum, g_len + g_ioff);
		printsep();
		printf("# eX-Packet Header %lu bytes\n", g_ioff);
		printsep();

		/* TODO: write up parsing for tags */

		if ((rv = pkb_pack(pkb)) < 0)
			err("Error packing packet %lu: %d\n", g_pktnum, rv);
		hexdump(stdout, 0, (byte_t *)xp, g_ioff);
		pkb_unpack(pkb);
	} else {
		g_ioff = 0;
		printsep();
		printf("# Packet %lu -- %lu bytes\n", g_pktnum, g_len);
		printsep();
	}

	gather_fields(prp);
	reset_field_pointer();

	walk_and_print_parse(prp, prp, prp_poff(prp) * 8);

	printf("\n\n");
	if (g_do_flush)
		fflush(stdout);

	release_fields();
}


int main(int argc, char *argv[])
{
	int rv;
	struct pktbuf *pkb;

	optparse_reset(&g_oparser, argc, argv);
	parse_options();

	register_std_proto();

	init_fields();

	pkb_init(1);

	while ((rv = pkb_file_read(&pkb, g_file)) > 0) {
		++g_pktnum;
		pkb_parse(pkb);
		dump_to_hex_packet(pkb);
		pkb_free(pkb);
	}

	return 0;
}
