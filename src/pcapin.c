/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * pcapin.c -- Read pcap files or interfaces and output the packets in
 *   xpkt format.
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
#include "pktbuf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <cat/pack.h>
#include <cat/err.h>
#include <cat/optparse.h>

#define PKTMAX  (1024 * 64 + 64)

pcap_t *g_pcap;
uint g_ifnum = 0;
struct pktbuf *g_pkb;
struct xpkt_tag_ts *g_ts;
const char *progname;
FILE *infile;
FILE *outfile;

struct clopt g_options[] = {
	CLOPT_I_STRING('i', NULL, "IFNAME", "interface to sniff from"),
	CLOPT_I_UINT('n', NULL, "IFNUM",
		     "interface number to tag packets with"),
	CLOPT_I_NOARG('p', "--promisc",
		      "set interface in promiscuous mode"),
	CLOPT_I_NOARG('h', NULL, "print help")
};

struct clopt_parser g_oparse =
CLOPTPARSER_INIT(g_options, array_length(g_options));


void usage(const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	fprintf(stderr, "usage: %s [options] [INFILE [OUTFILE]]\n", progname);
	fprintf(stderr, "       %s -i IFACE [options] [OUTFILE]\n", progname);
	optparse_print(&g_oparse, str, sizeof(str));
	fprintf(stderr, "%s\n", str);
	exit(1);
}


void parse_args(int argc, char *argv[])
{
	char ebuf[PCAP_ERRBUF_SIZE];
	int rv, usefile = 1, promisc = 0;
	const char *pktsrc = NULL;
	struct clopt *opt;

	infile = stdin;
	outfile = stdout;
	progname = argv[0];
	optparse_reset(&g_oparse, argc, argv);
	while (!(rv = optparse_next(&g_oparse, &opt))) {
		switch (opt->ch) {
		case 'i':
			pktsrc = opt->val.str_val;
			usefile = 0;
			break;
		case 'n':
			g_ifnum = opt->val.uint_val;
			break;
		case 'p':
			promisc = 1;
			break;
		case 'h':
			usage(NULL);
			break;
		}
	}
	if (rv < 0)
		usage(g_oparse.errbuf);

	if (usefile) {
		if (rv < argc) {
			if ((infile = fopen(argv[rv], "r")) == NULL)
				errsys("fopen: ");
		}
		if ((g_pcap = pcap_fopen_offline(infile, ebuf)) == NULL)
			err("Error opening pcap: %s\n", ebuf);

		if (rv < argc-1)
			if ((outfile = fopen(argv[rv+1], "w")) == NULL)
				errsys("fopen: ");

	} else {
		g_pcap = pcap_open_live(pktsrc, 65535, promisc, 0, ebuf);
		if (g_pcap == NULL)
			err("Error opening interface %s: %s\n", pktsrc, ebuf);
		if (rv < argc)
			if ((outfile = fopen(argv[rv], "w")) == NULL)
				errsys("fopen: ");
	}
}


static void init_tags(struct pktbuf *p)
{
	struct xpkt_tag_iface ti;
	struct xpkt_tag_ts ts;
	int rv;

	xpkt_tag_iif_init(&ti, g_ifnum);
	rv = pkb_add_tag(p, (struct xpkt_tag_hdr *)&ti);
	abort_unless(rv == 0);

	xpkt_tag_ts_init(&ts, 0, 0);
	rv = pkb_add_tag(p, (struct xpkt_tag_hdr *)&ts);
	abort_unless(rv == 0);
}


void get_packet(uchar *unused, const struct pcap_pkthdr *ph, const uchar *buf)
{
	struct xpkt_tag_snapinfo si;
	int rv;

	g_ts->sec = ph->ts.tv_sec;
	g_ts->nsec = ph->ts.tv_usec * 1000;

	pkb_set_len(g_pkb, ph->caplen);

	if (ph->len != ph->caplen) {
		xpkt_tag_si_init(&si, ph->len);
		rv = pkb_add_tag(g_pkb, (struct xpkt_tag_hdr *)&si);
		abort_unless(rv == 0);
	}

	memcpy(g_pkb->buf, buf, ph->caplen);
	rv = pkb_pack(g_pkb);
	abort_unless(rv == 0);
	if (pkb_file_write(g_pkb, outfile) < 0)
		errsys("pkb_file_write: ");
	pkb_unpack(g_pkb);

	if (ph->len != ph->caplen)
		pkb_del_tag(g_pkb, XPKT_TAG_SNAPINFO, 0);
}


int main(int argc, char *argv[])
{
	int dlt;
	uint16_t dltype;

	parse_args(argc, argv);
	switch ((dlt = pcap_datalink(g_pcap))) {
	case DLT_EN10MB:
		dltype = PRID_ETHERNET2;
		break;
	default:
		err("unsupported datalink type: %d", dlt);
	}

	pkb_init_pools(1);

	if (!(g_pkb = pkb_create(PKTMAX)))
		errsys("pkb_create: ");
	pkb_set_dltype(g_pkb, dltype);
	init_tags(g_pkb);
	g_ts = (struct xpkt_tag_ts *)pkb_find_tag(g_pkb, XPKT_TAG_TIMESTAMP, 0);
	abort_unless(g_ts);

	if (pcap_loop(g_pcap, -1, &get_packet, NULL) < 0)
		errsys("pcap_loop: %s", pcap_geterr(g_pcap));

	pkb_free(g_pkb);
	pcap_close(g_pcap);

	return 0;
}
