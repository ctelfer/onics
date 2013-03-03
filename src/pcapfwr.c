/*
 * ONICS
 * Copyright 2013
 * Christopher Adam Telfer
 *
 * pcapfwr.c -- Write an xpkt stream of packets to a pcap file.
 *   This program does not use libpcap.
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

void usage(const char *prog)
{
	fprintf(stderr, "usage: %s [-f INFILE] OUTFILE\n", prog);
	exit(-1);
}

int main(int argc, char *argv[])
{
	int rv;
	opcap_h pch;
	struct pktbuf *pkb;
	FILE *infile = stdin;
	uint dltype;
	uint32_t pcdlt;
	int ofi = 1;
	ulong pktnum = 1;
	struct opcap_phdr ph;
	struct xpkt_tag_ts *ts;
	struct xpkt_tag_snapinfo *si;

	if (argc < 2) 
		usage(argv[0]);

	if (strcmp(argv[1], "-f") == 0) {
		if (argc != 4)
			usage(argv[0]);
		infile = fopen(argv[2], "r");
		if (infile == NULL)
			errsys("opening input file %s: ");
		ofi = 3;
	}

	pkb_init(1);

	if ((rv = pkb_file_read(&pkb, infile)) <= 0) {
		if (rv == 0)
			return 0;
		if (rv < 0)
			errsys("error reading the first packet: ");
	}

	dltype = pkb_get_dltype(pkb);
	switch (dltype) {
	case PRID_ETHERNET2:
		pcdlt = OPCAP_DLT_EN10MB;
		break;
	default:
		err("Data link type not supported");
	}

	if (opcap_open_writer(argv[ofi], 65535, pcdlt, &pch) < 0)
		errsys("opcap_open_writer :");

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

		if (opcap_write(pch, pkb_data(pkb), &ph) < 0)
			errsys("opcap_write: ");

		pkb_free(pkb);
		++pktnum;
	} while ((rv = pkb_file_read(&pkb, infile)) > 0);

	if (rv < 0)
		errsys("pkb_file_read: ");

	opcap_close(pch);

	return 0;
}
