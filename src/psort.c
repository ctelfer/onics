/*
 * ONICS
 * Copyright 2013 
 * Christopher Adam Telfer
 *
 * psort.c -- Sort a set of packets according to a user specified key.
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
#include <stdlib.h>
#include <string.h>
#include <cat/list.h>
#include <cat/optparse.h>
#include <cat/err.h>
#include <cat/pack.h>
#include "pktbuf.h"

FILE *g_infile;
FILE *g_outfile;
int g_ktype = XPKT_TAG_TIMESTAMP;
int g_ai_include_subtype = 0;
const char *g_progname;
int g_reverse = 0;

struct clopt g_options[] = {
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help"),
	CLOPT_INIT(CLOPT_NOARG, 'r', "--reverse",
		   "reverse the direction of the sort"),
	CLOPT_I_STRING('k', "--key-type", "KEYTYPE",
		       "Set the key type to sort on"),
};
struct clopt_parser g_oparse =
CLOPTPARSER_INIT(g_options, array_length(g_options));


void usage(const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&g_oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] IFACE [OUTFILE]\n%s\n", g_progname,
		str);
	fprintf(stderr, "\nKEYTYPE can be one of:\n");
	fprintf(stderr, "\t'timestamp', 'flowid', 'class', 'seq', "
			"'[+]appinfo'\n");
	fprintf(stderr, "\tThe default keytype is 'timestamp'\n");
	fprintf(stderr, "\t'+appinfo' includes the subtype, "
			"'appinfo' does not\n");
	exit(1);
}


static void set_key_type(const char *kts)
{
	if (strcmp(kts, "timestamp") == 0)
		g_ktype = XPKT_TAG_TIMESTAMP;
	else if (strcmp(kts, "flowid") == 0)
		g_ktype = XPKT_TAG_FLOW;
	else if (strcmp(kts, "class") == 0)
		g_ktype = XPKT_TAG_CLASS;
	else if (strcmp(kts, "seq") == 0)
		g_ktype = XPKT_TAG_SEQ;
	else if (strcmp(kts, "appinfo") == 0)
		g_ktype = XPKT_TAG_APPINFO;
	else if (strcmp(kts, "*appinfo") == 0) {
		g_ktype = XPKT_TAG_APPINFO;
		g_ai_include_subtype = 1;
	} else
		usage("Unknown key type");
}


void parse_args(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;
	const char *fn;

	g_infile = stdin;
	g_outfile = stdout;
	g_progname = argv[0];

	optparse_reset(&g_oparse, argc, argv);
	while (!(rv = optparse_next(&g_oparse, &opt))) {
		switch (opt->ch) {
		case 'h':
			usage(NULL);
			break;
		case 'k':
			set_key_type(opt->val.str_val);
			break;
		case 'r':
			g_reverse = 1;
			break;
		}
	}
	if (rv < 0)
		usage(g_oparse.errbuf);

	if (rv < argc) {
		fn = argv[rv++];
		g_infile = fopen(fn, "r");
		if (g_infile == NULL)
			errsys("Error opening file %s: ", fn);
	}

	if (rv < argc) {
		fn = argv[rv++];
		g_outfile = fopen(fn, "w");
		if (g_outfile == NULL)
			errsys("Error opening file %s: ", fn);
	}

}


void read_packets(struct list *pl)
{
	int rv;
	struct pktbuf *p;

	l_init(pl);
	while ((rv = pkb_file_read(&p, g_infile)) > 0)
		l_enq(pl, &p->entry);
	if (rv < 0)
		errsys("pkb_file_read(): ");
}


void set_key(struct pktbuf *p)
{
	struct xpkt_tag_hdr *xh;
	struct xpkt_tag_ts *xts;
	struct xpkt_tag_flowid *xf;
	struct xpkt_tag_class *xc;
	struct xpkt_tag_seq *xseq;
	struct xpkt_tag_appinfo *xai;
	int nb;
	int nbmax;

	memset(p->cb, 0xFF, sizeof(p->cb));
	xh = pkb_find_tag(p, g_ktype, 0);
	if (xh == NULL)
		return;

	switch (g_ktype) {
	case XPKT_TAG_TIMESTAMP:
		xts = (struct xpkt_tag_ts *)xh;
		pack(p->cb, sizeof(p->cb), "ww", xts->sec, xts->nsec);
		break;
	case XPKT_TAG_FLOW:
		xf = (struct xpkt_tag_flowid *)xh;
		pack(p->cb, sizeof(p->cb), "ww", (ulong)(xf->flowid >> 32), 
		     (ulong)(xf->flowid & 0xFFFFFFFFul));
		break;
	case XPKT_TAG_CLASS:
		xc = (struct xpkt_tag_class *)xh;
		pack(p->cb, sizeof(p->cb), "ww", (ulong)(xc->tag >> 32), 
		     (ulong)(xc->tag & 0xFFFFFFFFul));
		break;
	case XPKT_TAG_SEQ:
		xseq = (struct xpkt_tag_seq *)xh;
		pack(p->cb, sizeof(p->cb), "ww", (ulong)(xseq->seq >> 32), 
		     (ulong)(xseq->seq & 0xFFFFFFFFul));
		break;
	case XPKT_TAG_APPINFO:
		xai = (struct xpkt_tag_appinfo *)xh;
		if (g_ai_include_subtype) {
			pack(p->cb, sizeof(p->cb), "h", xai->subtype);
			nbmax = sizeof(p->cb) - 2;
		} else {
			nbmax = sizeof(p->cb);
		}
		nb = xai->nwords * 4;
		if (nb > nbmax)
			nb = nbmax;
		memcpy(p->cb, xai->data, nb);
		break;
	default:
		abort_unless(0);
	}
}


void load_keys(struct list *pl)
{
	struct list *l;
	l_for_each(l, pl)
		set_key(container(l, struct pktbuf, entry));
}


static int pkb_cmp(const void *le1, const void *le2)
{
	register const struct pktbuf *p1, *p2;
	int rv;
	p1 = container(le1, struct pktbuf, entry);
	p2 = container(le2, struct pktbuf, entry);
	rv = memcmp(p1->cb, p2->cb, sizeof(p1->cb));
	if (g_reverse)
		rv = rv < 0 ? 1 : ((rv > 0) ? -1 : 0);
	return rv;
}


void sort_packets(struct list *pl)
{
	l_sort(pl, pkb_cmp);
}


void write_packets(struct list *pl)
{
	struct list *l;
	struct pktbuf *p;

	while ((l = l_deq(pl)) != NULL) {
		p = container(l, struct pktbuf, entry);
		pkb_pack(p);
		if (pkb_file_write(p, g_outfile) < 0)
			errsys("pkb_file_write(): ");
	}
}


int main(int argc, char *argv[])
{
	struct list pl;

	pkb_init_pools(128);
	parse_args(argc, argv);
	read_packets(&pl);
	load_keys(&pl);
	sort_packets(&pl);
	write_packets(&pl);

	return 0;
}
