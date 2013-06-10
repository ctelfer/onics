/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * opcin.c -- Read pcap files and output the packets in xpkt format.
 *            This implementation does not use libpcap.
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
#include "opcap.h"
#include "prid.h"

#include <cat/err.h>
#include <cat/optparse.h>

#include <stdio.h>
#include <stdlib.h>

#define PKTMAX  (1024 * 64 + 64)

struct clopt g_options[] = {
	CLOPT_INIT(CLOPT_STRING, 'i', "--iface", 
		"interface to sniff from (UNSUPPORTED)"),
	CLOPT_INIT(CLOPT_STRING, 'f', "--file", "file to read from"),
	CLOPT_INIT(CLOPT_UINT,   'n', "--iface-num",
		   "interface number to tag packets with"),
	CLOPT_INIT(CLOPT_NOARG,  'p', "--promisc",
		   "set interface in promiscuous mode (UNSUPPORTED)"),
	CLOPT_INIT(CLOPT_STRING, 'h', "--help", "print help")
};

struct clopt_parser g_oparser =
CLOPTPARSER_INIT(g_options, array_length(g_options));

void usage(const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&g_oparser, str, sizeof(str));
	fprintf(stderr, "usage: %s [options]\n%s\n", g_oparser.argv[0], str);
	exit(1);
}


int main(int argc, char *argv[])
{
	struct clopt *opt;
	ulong pcdlt;
	uint dltype;
	int rv;
	uint ifnum = 0;
	opc_h pch;
	struct pktbuf *pkb;
	struct xpkt_tag_iface ti;
	struct xpkt_tag_ts ts, *tsp;
	struct xpkt_tag_snapinfo si;
	struct opc_phdr ph;
	const char *pktsrc = NULL;

	optparse_reset(&g_oparser, argc, argv);
	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'i':
			usage("option '-i' is unsupported");
			break;
		case 'f':
			pktsrc = opt->val.str_val;
			break;
		case 'n':
			ifnum = opt->val.uint_val;
			break;
		case 'p':
			usage("option '-p' is unsupported");
			break;
		case 'h':
			usage(NULL);
			break;
		}
	}

	if (rv < argc)
		usage((rv < 0) ? g_oparser.errbuf : NULL);

	if (pktsrc != NULL) {
		if (opc_open_file_rd(pktsrc, &pch) < 0)
			errsys("Error opening file %s: ", argv[1]);
	} else {
		if (opc_open_stream_rd(stdin, &pch) < 0)
			errsys("Error reading pcap form standard input");
	}

	pcdlt = opc_get_dltype(pch);
	switch (pcdlt) {
	case OPC_DLT_EN10MB:
		dltype = PRID_ETHERNET2;
		break;
	default:
		err("unsupported datalink type: %lu", pcdlt);
	}

	pkb_init(1);
	if ((pkb = pkb_create(PKTMAX)) == NULL)
		errsys("pkb_create: ");
	xpkt_tag_iif_init(&ti, ifnum);
	pkb_add_tag(pkb, (struct xpkt_tag_hdr *)&ti);
	xpkt_tag_ts_init(&ts, 0, 0);
	pkb_add_tag(pkb, (struct xpkt_tag_hdr *)&ts);
	tsp = (struct xpkt_tag_ts *)pkb_find_tag(pkb, XPKT_TAG_TIMESTAMP, 0);
	pkb_set_dltype(pkb, dltype);

	while ((rv = opc_read(pch, pkb_data(pkb), PKTMAX, &ph)) > 0) {
		tsp->sec = ph.tssec;
		tsp->nsec = ph.tsusec * 1000;
		pkb_set_len(pkb, ph.caplen);
		if (ph.len != ph.caplen) {
			xpkt_tag_si_init(&si, ph.len);
			pkb_add_tag(pkb, (struct xpkt_tag_hdr *)&si);
		}
		pkb_pack(pkb);
		if (pkb_file_write(pkb, stdout) < 0)
			errsys("pkb_file_write: ");
		pkb_unpack(pkb);
		if (ph.len != ph.caplen)
			pkb_del_tag(pkb, XPKT_TAG_SNAPINFO, 0);
	}

	if (rv < 0)
		errsys("opc_read: ");

	pkb_free(pkb);
	opc_close(pch);

	return 0;
}
