/*
 * ONICS
 * Copyright 2012-2015
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
#include "prload.h"
#include "util.h"
#include "pktbuf.h"
#include "ns.h"
#include "stdproto.h"
#include "fld.h"

int g_keep_xhdr = 0;
ulong g_pktnum;
ulong g_ioff;
ulong g_pbase;
ulong g_len;
byte_t *g_p;
int g_do_flush = 0;
FILE *infile;
FILE *outfile;

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
	CLOPT_I_NOARG('x', NULL, "keep xpkt hdr in dump"),
	CLOPT_I_NOARG('f', NULL, "Flush output per packet"),
	CLOPT_I_NOARG('h', NULL, "print help")
};

struct clopt_parser g_oparser =
	CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));



void usage(const char *estr)
{
	char ubuf[4096];
	if (estr != NULL)
		fprintf(stderr, "Error -- %s\n", estr);
	optparse_print(&g_oparser, ubuf, sizeof(ubuf));
	fprintf(stderr, "usage: %s [options] [INFILE [OUTFILE]]\n", g_oparser.argv[0]);
	fprintf(stderr, "%s\n", ubuf);
	exit(1);
}


void parse_options()
{
	int rv;
	struct clopt *opt;
	infile = stdin;
	outfile = stdout;
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
	if (rv < g_oparser.argc - 2)
		usage(NULL);

	if (rv < g_oparser.argc) {
		if ((infile = fopen(g_oparser.argv[rv], "r")) == NULL)
			errsys("fopen: ");
	}
	if (rv < g_oparser.argc-1) {
		if ((outfile = fopen(g_oparser.argv[rv+1], "w")) == NULL)
			errsys("fopen: ");
	}
}


void printsep()
{
	fprintf(outfile, "#####\n");
}


void hexdump_at(ulong soff, ulong eoff)
{
	/* effective address == soff - (packet base + xpkt hdr off) */
	/* pointer offset = g_p + soff */
	/* length = end - start */
	fhexdump(outfile, NULL, soff - g_pbase + g_ioff, g_p + soff,
		 eoff - soff);
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


static const char *errstrs[7] = {
	"runt", 
	"header length", 
	"truncated",
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
		fprintf(outfile, "#    Errors [0x%0x]: ", err);
		for (i = 0; i <= PRP_ERR_MAXBIT; ++i) {
			if (err & (1 << i)) {
				if (!first)
					fputs(", ", outfile);
				else
					first = 0;
				fputs(errstrs[i], outfile);
			}
		}
		fputc('\n', outfile);
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

	if ((l = l_deq(&free_fields)) != NULL) {
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
	int i;
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

		off = fld_get_off(prp, e);
		if (off == PRP_OFF_INVALID)
			continue;

		if ((f = alloc_field()) == NULL)
			return -1;

		f->elem = e;
		f->prp = prp;
		f->ns = ns;
		f->off = off;
		f->len = fld_get_len(prp, e);
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
	char pfx[MAXPFX];
	char line[MAXLINE];
	struct ns_elem *e;
	struct ns_namespace *lastns = NULL;
	struct field *f;
	int rv;


	while (next_field != l_end(&packet_fields)) {

		f = l_to_field(next_field);

		if (f->off >= eoff)
			return;

		e = f->elem;
		/* check for change of prefix */
		if (f->ns != lastns) {
			getpfx(pfx, f->ns->name, MAXPFX);
			lastns = f->ns;
		}


		if (e->type == NST_NAMESPACE) {
			printsep();
			rv = ns_tostr(e, g_p, f->prp, line, sizeof(line), pfx);
			if (rv >= 0)
				fputs(line, outfile);
			if (f->ishdr)
				printerr(f->prp->error);
			printsep();
		} else {
			rv = ns_tostr(e, g_p, f->prp, line, sizeof(line), pfx);
			if (rv >= 0)
				fputs(line, outfile);
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
	ulong sbyte, ebyte;
	ulong len;
	ulong sboff;

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

	if (prhdr) {
		len = ebyte - sbyte;
		sboff = sbyte - g_pbase + g_ioff;
		fprintf(outfile, "%sData -- [%lu:%lu]\n", pfx, sboff, len);
	}

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
	prp_for_each(prp, pktp)
		if (add_fields(prp, NULL) < 0)
			err("Out of memory for packet %lu\n", g_pktnum);
}


void reset_field_pointer()
{
	next_field = l_head(&packet_fields);
}


void dump_xpkt_meta(struct pktbuf *pkb)
{
	struct xpkt_tag_hdr *t;
	struct xpkt_tag_ts *ts;
	struct xpkt_tag_snapinfo *si;
	struct xpkt_tag_iface *ifa;
	struct xpkt_tag_flowid *f;
	struct xpkt_tag_class *c;
	struct xpkt_tag_seq *seq;
	struct xpkt_tag_parseinfo *pi;
	struct xpkt_tag_appinfo *ai;
	int i;

	for (t = pkb_next_tag(pkb, NULL); t != NULL; t = pkb_next_tag(pkb, t)) {
		switch (t->type) {
		case XPKT_TAG_NOP: break;

		case XPKT_TAG_TIMESTAMP: 
			ts = (struct xpkt_tag_ts *)t;
			fprintf(outfile,
			       "# XPKT: Timestamp = %lu sec and %lu nsec\n",
			       (ulong)ts->sec, (ulong)ts->nsec);
			break;

		case XPKT_TAG_SNAPINFO: 
			si = (struct xpkt_tag_snapinfo *)t;
			fprintf(outfile,
				"# XPKT: Packet snapped: wire length = %lu\n",
			       (ulong)si->wirelen);
			break;

		case XPKT_TAG_INIFACE:
			ifa = (struct xpkt_tag_iface *)t;
			fprintf(outfile,
				"# XPKT: Incoming interface = %u\n",
			       (uint)ifa->iface);
			break;

		case XPKT_TAG_OUTIFACE:
			ifa = (struct xpkt_tag_iface *)t;
			fprintf(outfile,
				"# XPKT: Outgoing interface = %u\n",
			       (uint)ifa->iface);
			break;

		case XPKT_TAG_FLOW:
			f = (struct xpkt_tag_flowid *)t;
			fprintf(outfile, "# XPKT: Flow id = %llu\n",
				(ullong)f->flowid);
			break;

		case XPKT_TAG_CLASS:
			c = (struct xpkt_tag_class *)t;
			fprintf(outfile, "# XPKT: Packet class = %llu\n",
				(ullong)c->tag);
			break;

		case XPKT_TAG_SEQ:
			seq = (struct xpkt_tag_seq *)t;
			fprintf(outfile,
				"# XPKT: Packet sequence number = %llu\n",
			       (ullong)seq->seq);
			break;

		case XPKT_TAG_PARSEINFO:
			pi = (struct xpkt_tag_parseinfo *)t;
			fprintf(outfile,
				"# XPKT: Parse info for proto %04x: "
			       "off = %llu, length = %llu\n",
			       (uint)pi->proto, (ullong)pi->off,
			       (ullong)pi->len);
			break;

		case XPKT_TAG_APPINFO:
			ai = (struct xpkt_tag_appinfo *)t;
			fprintf(outfile,
				"# XPKT: App-specific info: subtype = %u",
				(uint)ai->subtype);
			for (i = 0; i < ai->nwords * 4; ++i) {
				if (i % 16 == 0)
					fprintf(outfile, "\n# XPKT:\t");
				fprintf(outfile, "%02x", ai->data[i]);
			}
			fprintf(outfile, "\n");
			break;
		}
	}
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
		fprintf(outfile, "# Packet %lu -- %lu bytes\n", g_pktnum,
			g_len + g_ioff);
		printsep();
		fprintf(outfile, "# XPKT: eX-PacKeT Header %lu bytes\n",
			g_ioff);
		printsep();
		dump_xpkt_meta(pkb);

		if ((rv = pkb_pack(pkb)) < 0)
			err("Error packing packet %lu: %d\n", g_pktnum, rv);
		fhexdump(outfile, NULL, 0, (byte_t *)xp, g_ioff);
		pkb_unpack(pkb);
	} else {
		g_ioff = 0;
		printsep();
		fprintf(outfile, "# Packet %lu -- %lu bytes\n", g_pktnum,
			g_len);
		printsep();
	}

	gather_fields(prp);
	reset_field_pointer();

	walk_and_print_parse(prp, prp, prp_poff(prp) * 8);

	fprintf(outfile, "\n\n");
	if (g_do_flush)
		fflush(outfile);

	release_fields();
}


int main(int argc, char *argv[])
{
	int rv;
	struct pktbuf *pkb;

	optparse_reset(&g_oparser, argc, argv);
	parse_options();

	register_std_proto();
	load_external_protocols();

	init_fields();

	pkb_init_pools(1);

	while ((rv = pkb_file_read_a(&pkb, infile, NULL, NULL)) > 0) {
		++g_pktnum;
		pkb_parse(pkb);
		dump_to_hex_packet(pkb);
		pkb_free(pkb);
	}

	return 0;
}
