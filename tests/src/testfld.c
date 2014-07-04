/*
 * ONICS
 * Copyright 2013
 *
 * testfld.c -- Test field API.
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

#include <cat/err.h>

#include "pktbuf.h"
#include "protoparse.h"
#include "ns.h"
#include "stdproto.h"
#include "util.h"
#include "fld.h"
#include <string.h>

int main(int argc, char *argv[])
{
	struct pktbuf *p;
	ulong osyn;
	uchar oeth[6];
	uchar oip[6];
	uchar neth[6] = "\x10\x22\x33\x44\x55\x66";
	uchar nip[4] = "\x0b\x0c\x0d\x0e";
	ulong len;
	void *pld;
	
	register_std_proto();
	pkb_init_pools(1);

	while (pkb_file_read_a(&p, stdin, NULL, NULL) > 0) {
		if (pkb_parse(p) < 0)
			errsys("Error parsing packet\n");

		if (fld_get_bn(p->buf, &p->prp, "eth.src", oeth, 6) < 0)
			fprintf(stderr, "unable to read eth.src\n");
		fprintf(stderr, "old eth src addr\n");
		fhexdump(stderr, NULL, 0, oeth, 6);

		if (fld_get_bn(p->buf, &p->prp, "ip.daddr", oip, 4) < 0)
			fprintf(stderr, "unable to read ip.daddr\n");
		fprintf(stderr, "old ip dest addr\n");
		fhexdump(stderr, NULL, 0, oip, 4);

		if (fld_get_vn(p->buf, &p->prp, "tcp.ack", &osyn) < 0)
			fprintf(stderr, "unable to read tcp.ack\n");
		fprintf(stderr, "old tcp ack flag: %lu\n", (ulong)osyn);
		if (fld_get_vn(p->buf, &p->prp, "tcp.syn", &osyn) < 0)
			fprintf(stderr, "unable to read tcp.syn\n");
		fprintf(stderr, "old tcp syn flag: %lu\n", (ulong)osyn);

		if (fld_set_bn(p->buf, &p->prp, "eth.src", neth, 6) < 0)
			fprintf(stderr, "unable to set eth.src\n");
		if (fld_set_bn(p->buf, &p->prp, "ip.daddr", nip, 4) < 0)
			fprintf(stderr, "unable to set ip.daddr\n");
		if (fld_set_vn(p->buf, &p->prp, "tcp.syn", osyn^1) < 0)
			fprintf(stderr, "unable to toggle tcp.syn\n");


		pld = fld_get_pldn(p->buf, &p->prp, "tcp", &len);
		if (pld == NULL)
			fprintf(stderr, "unable to get 'tcp' payload\n");
		memmove(pld, "Hello World", (len < 11) ? len : 11);

		/* fixup the network layer to make parse dumping cleaner */
		prp_fix_cksum(p->layers[PKB_LAYER_NET], p->buf);

		pkb_pack(p);
		pkb_file_write(p, stdout);
	}

	return 0;
}
