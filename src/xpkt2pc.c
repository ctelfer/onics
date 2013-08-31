/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * xpkt2pc.c -- Write an xpkt stream of packets to a pcap file.
 *              This program does not use libpcap.
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

#include "pktbuf.h"
#include "opcap.h"

#include <cat/err.h>
#include <cat/optparse.h>

struct clopt g_optarr[] = {
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
	err("usage: %s [options] [INFILE [OUTFILE]]\n%s\n", g_oparser.argv[0],
	    ubuf);
}


int main(int argc, char *argv[])
{
	int rv;
	opc_h pch;
	struct pktbuf *pkb;
	uint dltype;
	uint32_t pcdlt;
	ulong pktnum = 1;
	struct opc_phdr ph;
	struct xpkt_tag_ts *ts;
	struct xpkt_tag_snapinfo *si;
	struct clopt *opt;
	FILE *infile = stdin;
	FILE *outfile = stdout;

	optparse_reset(&g_oparser, argc, argv);
	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'h':
			usage(NULL);
		}
	}
	if (rv < 0)
		usage(g_oparser.errbuf);
	if (rv < argc - 2)
		usage(NULL);

	if (rv < argc) {
		infile = fopen(argv[rv], "r");
		if (infile == NULL)
			errsys("error opening file '%s' for reading", argv[rv]);
	}

	if (rv < argc - 1) {
		outfile = fopen(argv[rv+1], "w");
		if (outfile == NULL)
			errsys("error opening file '%s' for writing",
			       argv[rv+1]);
	}

	pkb_init_pools(1);

	if ((rv = pkb_file_read(&pkb, infile)) <= 0) {
		if (rv == 0)
			return 0;
		if (rv < 0)
			errsys("error reading the first packet: ");
	}

	dltype = pkb_get_dltype(pkb);
	switch (dltype) {
	case PRID_ETHERNET2:
		pcdlt = OPC_DLT_EN10MB;
		break;
	default:
		err("Data link type not supported");
	}

	if (opc_open_stream_wr(outfile, 65535, pcdlt, &pch) < 0)
		errsys("opc_open_writer :");

	do {
		if (dltype != pkb_get_dltype(pkb))
			err("Datalink type mismatch: pkt 1: %u, pkt %lu: %u\n",
			    dltype, pktnum, pkb_get_dltype(pkb));

		ph.caplen = pkb_get_len(pkb);
		ts = (struct xpkt_tag_ts *)
			pkb_find_tag(pkb, XPKT_TAG_TIMESTAMP, 0);
		if (ts != NULL) {
			ph.tssec = ts->sec;
			ph.tsusec = ts->nsec / 1000;
		} else {
			ph.tssec = 0;
			ph.tsusec = 0;
		}

		si = (struct xpkt_tag_snapinfo *)
			pkb_find_tag(pkb, XPKT_TAG_SNAPINFO, 0);
		if (si != NULL) {
			ph.len = si->wirelen;
		} else {
			ph.len = ph.caplen;
		}

		if (opc_write(pch, pkb_data(pkb), &ph) < 0)
			errsys("opc_write: ");

		pkb_free(pkb);
		++pktnum;
	} while ((rv = pkb_file_read(&pkb, infile)) > 0);

	if (rv < 0)
		errsys("pkb_file_read: ");

	opc_close(pch);

	return 0;
}
