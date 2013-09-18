/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * pktrel.c -- Release packets according to a given traffic description.
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
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cat/err.h>
#include <cat/optparse.h>
#include <cat/time.h>

ulong g_npkts = 0;
double g_start_delay = 0.0;
double g_interval = 0.0;

struct clopt g_optarr[] = {
	CLOPT_I_NOARG('h', NULL, "print help"),
	CLOPT_I_DOUBLE('d', NULL, "NSEC", "delay start by <x> seconds"),
	CLOPT_I_DOUBLE('i', NULL, "NSEC", "delay <x> seconds ")
};

struct clopt_parser g_oparser =
CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));


void usage(const char *estr)
{
	char ubuf[4096];
	if (estr != NULL)
		fprintf(stderr, "Error -- %s\n", estr);
	optparse_print(&g_oparser, ubuf, sizeof(ubuf));
	fprintf(stderr, "usage: %s [options] [INFILE [OUTFILE]]\n%s\n", 
	        g_oparser.argv[0], ubuf);
	exit(1);
}


void parse_args(int argc, char *argv[], int *ifd, int *ofd)
{
	int rv;
	struct clopt *opt;
	const char *fn;

	optparse_reset(&g_oparser, argc, argv);
	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'd':
			g_start_delay = opt->val.dbl_val;
			break;
		case 'i':
			g_interval = opt->val.dbl_val;
			break;
		case 'h':
			usage(NULL);
		}
	}
	if (rv < 0)
		usage(g_oparser.errbuf);

	if (rv < argc) {
		fn = argv[rv++];
		*ifd = open(fn, O_RDONLY);
		if (*ifd < 0)
			errsys("unable to open file '%s'", fn);
	}

	if (rv < argc) {
		fn = argv[rv++];
		*ofd = open(fn, O_RDONLY);
		if (*ofd < 0)
			errsys("unable to open file '%s'", fn);
	}

	if (rv < argc)
		usage(NULL);
}


void sleepfor(cat_time_t amt, cat_time_t start)
{
	cat_time_t elapsed;

	if (tm_gtz(amt)) {
		while (tm_sec(amt) > 0) {
			sleep(tm_sec(amt));
			elapsed = tm_sub(tm_uget(), start);
			amt = tm_sub(amt, elapsed);
		} 

		if (tm_gtz(amt))
			usleep(tm_nsec(amt) / 1000);
	}
}


int main(int argc, char *argv[])
{
	int rv;
	struct pktbuf *p;
	cat_time_t pkts, now, base_now, base_pkts, dp, dn;
	struct xpkt_tag_ts *ts;
	int infd = 0;
	int outfd = 1;

	pkb_init_pools(1);

	parse_args(argc, argv, &infd, &outfd);

	if (g_start_delay > 0)
		sleepfor(tm_dset(g_start_delay), tm_uget());

	while ((rv = pkb_fd_read(&p, infd)) > 0) {
		now = tm_uget();

		ts = (struct xpkt_tag_ts *)pkb_find_tag(p, XPKT_TAG_TIMESTAMP, 0);

		++g_npkts;

		if (g_interval > 0.0) {
			sleepfor(tm_dset(g_interval), now);
		} else if (ts) {
			pkts = tm_lset(ts->sec, ts->nsec);

			if (tm_ltz(pkts)) {
				fprintf(stderr,
					"Invalid timestamp on packet %lu "
					"(%ld,%ld)\n",
					g_npkts, tm_sec(pkts), tm_nsec(pkts));
				pkb_free(p);
				continue;
			}

			if (g_npkts == 1) {
				base_now = now;
				base_pkts = pkts;
			}

			dn = tm_sub(now, base_now);
			dp = tm_sub(pkts, base_pkts);
			if (tm_cmp(dp, dn) > 0)
				sleepfor(tm_sub(dp, dn), now);
		} else {
			fprintf(stderr, "no timestamp on packet %lu: sending\n",
				g_npkts);
		}

		rv = pkb_pack(p);
		abort_unless(rv == 0);
		if (pkb_fd_write(p, outfd) < 0)
			errsys("Error writing packet %lu", g_npkts);
		pkb_free(p);
	}
	if (rv < 0)
		errsys("Error reading packet %lu: ", g_npkts + 1);

	return 0;
}
