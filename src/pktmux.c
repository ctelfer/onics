/*
 * ONICS
 * Copyright 2012-2022
 * Christopher Adam Telfer
 *
 * pktmux.c -- Multiplex packets from multiple input sources and mark
 *   them with metadata appropriately.
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
#include <fcntl.h>
#include <cat/err.h>
#include <cat/optparse.h>
#include <cat/uevent.h>
#include <cat/stduse.h>

#define MAX_FDS      256

int g_nfd = 0;
ulong g_npkts = 0;

struct clopt g_optarr[] = {
	CLOPT_I_NOARG('h', "--help", "print help")
};

struct clopt_parser g_oparser =
CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));


void usage(const char *estr)
{
	char ubuf[4096];
	if (estr != NULL)
		fprintf(stderr, "Error -- %s\n", estr);
	optparse_print(&g_oparser, ubuf, sizeof(ubuf));
	err("usage: %s [options] <nstreams>\n"
	    "\t<nstreams> must be between 1 and %d\n"
	    "%s", g_oparser.argv[0], MAX_FDS, ubuf);
}


void parse_options(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;

	optparse_reset(&g_oparser, argc, argv);
	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'h':
			usage(NULL);
		}
	}
	if (rv < 0)
		usage(g_oparser.errbuf);

	if (g_oparser.argc - rv == 0)
		usage("No number of streams");
	if (g_oparser.argc - rv != 1)
		usage("Extra arguments present");
	g_nfd = atoi(g_oparser.argv[rv]);
	if (g_nfd <= 0)
		usage("Must have at least one input stream");
	if (g_nfd > MAX_FDS)
		usage("Too many streams");
}


/* determine if an FD is open for reading or not and if not quit */
void testfd(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags == -1)
		err("%d is not a valid file descriptor", fd);
	if ((flags & O_ACCMODE) != O_RDONLY && (flags & O_ACCMODE) != O_RDWR)
		err("File descriptor %d is not writable", fd);
}


int readpkt(void *arg, struct callback *cb)
{
	int rv;
	struct pktbuf *p;
	struct ue_ioevent *ioe = container(cb, struct ue_ioevent, cb);
	struct xpkt_tag_iface *xifp;
	struct xpkt_tag_iface xif;
	int n;

	if ((rv = pkb_fd_read_a(&p, ioe->fd, NULL, NULL)) <= 0) {
		if (rv < 0)
			logsys(1, "Error reading from fd %d\n", ioe->fd);
		ue_io_del(ioe);
		return 0;
	}
	++g_npkts;
	xifp = (struct xpkt_tag_iface *)pkb_find_tag(p, XPKT_TAG_INIFACE, 0);
	if (xifp) {
		/* there's an existing tag:  so modify it */
		if (ioe->fd >= 3) {
			xifp->iface = ioe->fd - 3;
		} else {
			/* these should always succeed */
			n = pkb_find_tag_idx(p, (struct xpkt_tag_hdr *)xifp);
			abort_unless(n >= 0);
			rv = pkb_del_tag(p, xifp->type, n);
			abort_unless(rv == 0);
		}
	} else {
		if (ioe->fd >= 3) {
			xpkt_tag_oif_init(&xif, ioe->fd - 3);
			rv = pkb_add_tag(p, (struct xpkt_tag_hdr *)&xif);
			if (rv < 0) {
				pkb_free(p);
				return 0;
			}
		}
	}

	rv = pkb_pack(p);
	abort_unless(rv == 0);
	if (pkb_fd_write(p, 1) < 0)
		errsys("Error writing packet %lu\n", g_npkts);
	pkb_free(p);

	return 0;
}


int main(int argc, char *argv[])
{
	int i;
	struct uemux mux;

	parse_options(argc, argv);
	fclose(stdin);

	pkb_init_pools(1);

	ue_init(&mux, &estdmm);
	for (i = 3; i < 3 + g_nfd; ++i) {
		testfd(i);
		ue_io_new(&mux, UE_RD, i, readpkt, NULL);
	}

	ue_run(&mux);
	ue_fini(&mux);

	return 0;
}
