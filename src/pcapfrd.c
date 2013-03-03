/*
 * ONICS
 * Copyright 2012 
 * Christopher Adam Telfer
 *
 * pcapfrd.c -- Read pcap files and output the packets in xpkt format.
 *              This implementation does not use libpcap.
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

#include <stdio.h>
#include <stdlib.h>

#define PKTMAX  (1024 * 64 + 64)


void usage(const char *prog)
{
	fprintf(stderr, "usage: %s FILENAME\n", prog);
	exit(-1);
}


int main(int argc, char *argv[])
{
	ulong pcdlt;
	uint dltype;
	int rv;
	opcap_h pch;
	struct pktbuf *pkb;
	struct xpkt_tag_ts ts, *tsp;
	struct xpkt_tag_snapinfo si;
	struct opcap_phdr ph;

	if (argc < 2)
		usage(argv[0]);

	if (opcap_open_reader(argv[1], &pch) < 0)
		errsys("Error opening file %s: ", argv[1]);

	pcdlt = opcap_get_dltype(pch);
	switch (pcdlt) {
	case OPCAP_DLT_EN10MB:
		dltype = PRID_ETHERNET2;
		break;
	default:
		err("unsupported datalink type: %lu", pcdlt);
	}

	pkb_init(1);
	if ((pkb = pkb_create(PKTMAX)) == NULL)
		errsys("pkb_create: ");
	xpkt_tag_ts_init(&ts, 0, 0);
	pkb_add_tag(pkb, (struct xpkt_tag_hdr *)&ts);
	tsp = (struct xpkt_tag_ts *)pkb_find_tag(pkb, XPKT_TAG_TIMESTAMP, 0);
	pkb_set_dltype(pkb, dltype);

	while ((rv = opcap_read(pch, pkb_data(pkb), PKTMAX, &ph)) > 0) {
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
		errsys("opcap_read: ");

	pkb_free(pkb);
	opcap_close(pch);

	return 0;
}
