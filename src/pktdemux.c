/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * pktdemux.c -- Demultiplex packets according to their output
 *   port metadata among different streams.
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
#include <cat/bitset.h>


/*
 * This program demultiplexes xpkts out of multiple file descriptors.
 * For any given packet that comes in, if the outgoing interface is specified
 * then the program tries to send the packet out fd 3+outif.  Otherwise
 * it sends the packet out fd 1 (stdout).
 */

#define MAX_FDS      256

int g_nfd = 0;
ulong g_npkts = 0;
DECLARE_BITSET(g_fdseen, MAX_FDS);
DECLARE_BITSET(g_fdok, MAX_FDS);

struct clopt g_optarr[] = {
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
	err("usage: %s [options]\n" "%s", g_oparser.argv[0], ubuf);
}


void parse_options(int argc, char *argv[], int *infd)
{
	int rv;
	const char *fn;
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

	if (rv < argc) {
		fn = argv[rv++];
		*infd = open(fn, O_RDONLY);
		if (*infd < 0)
			errsys("Error opening file %s for reading: ", fn);
	}

	if (rv < argc)
		usage("Extra arguments present");
}


/* determine if an FD is open for writing */
int fdok(int fd)
{
	int flags = fcntl(fd, F_GETFL);
	return (flags != -1) &&
	    ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR);
}


int main(int argc, char *argv[])
{
	int rv, fd, infd = 0;
	struct pktbuf *p;
	struct xpkt_tag_iface *xif;

	parse_options(argc, argv, &infd);

	bset_set(g_fdseen, 0);
	bset_set(g_fdseen, 1);
	bset_set_to(g_fdok, 1, 1);
	bset_set(g_fdseen, 2);

	pkb_init_pools(1);

	while ((rv = pkb_fd_read_a(&p, infd, NULL, NULL)) > 0) {
		++g_npkts;
		fd = 1;
		xif = (struct xpkt_tag_iface *)
			pkb_find_tag(p, XPKT_TAG_OUTIFACE, 0);
		if ((xif != NULL) && (xif->iface + 3 < MAX_FDS))
			fd = xif->iface + 3;

		if (!bset_test(g_fdseen, fd)) {
			bset_set(g_fdseen, fd);
			bset_set_to(g_fdok, fd, fdok(fd));
		}

		if (bset_test(g_fdok, fd)) {
			rv = pkb_pack(p);
			abort_unless(rv == 0);
			if (pkb_fd_write(p, fd) < 0)
				errsys("Error writing packet %lu to %u\n",
				       g_npkts, fd);
		}
		pkb_free(p);
	}

	if (rv < 0)
		errsys("Error reading from fd 0\n");

	return 0;
}
