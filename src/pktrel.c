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
double g_bps = 0.0;

struct clopt g_optarr[] = {
	CLOPT_I_NOARG('h', NULL, "print help"),
	CLOPT_I_DOUBLE('d', NULL, "NSEC", "delay start by <x> seconds"),
	CLOPT_I_DOUBLE('i', NULL, "NSEC", "delay <x> seconds "),
	CLOPT_I_UINT('p', NULL, "PPS",  "send <x> packets per second"),
	CLOPT_I_DOUBLE('r', NULL, "BPS",  "send <x> bits per second")
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
	fprintf(stderr,
		"\tOnly the last of the -i, -p, or -r options will be used\n");
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
		case 'h':
			usage(NULL);
			break;
		case 'i':
			g_interval = opt->val.dbl_val;
			g_bps = 0.0;
			break;
		case 'p':
			g_interval = 1.0 / (double)opt->val.uint_val;
			g_bps = 0.0;
			break;
		case 'r':
			g_bps = opt->val.dbl_val;
			if (g_bps < 1.0)
				err("Can not have a rate less than 1 bps\n");
			g_interval = 0;
			break;
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


void sleep_until(cat_time_t *when, cat_time_t *now)
{
	cat_time_t diff;

	diff = tm_sub(*when, *now);
	while (tm_gtz(diff)) {
		if (tm_sec(diff) > 0)
			sleep(tm_sec(diff));
		else
			usleep(tm_nsec(diff) / 1000);
		*now = tm_uget();
		diff = tm_sub(*when, *now);
	}
}


int main(int argc, char *argv[])
{
	int rv;
	struct pktbuf *p;
	cat_time_t pts, now, next, nnext, start_time, start_ts;
	struct xpkt_tag_ts *ts;
	int infd = 0;
	int outfd = 1;
	ulong bits;

	pkb_init_pools(1);

	parse_args(argc, argv, &infd, &outfd);

	now = tm_uget();
	if (g_start_delay > 0) {
		next = tm_add(now, tm_dset(g_start_delay));
		sleep_until(&next, &now);
	}
	start_time = now;
	next = now;


	while ((rv = pkb_fd_read_a(&p, infd, NULL, NULL)) > 0) {
		now = tm_uget();
		++g_npkts;

		if (g_interval > 0.0) {
			nnext = tm_add(next, tm_dset(g_interval));
			sleep_until(&next, &now);
			next = nnext;
		} else if (g_bps > 1.0) {
			bits = pkb_get_len(p) * 8;
			nnext = tm_add(next, tm_dset(bits / g_bps));
			sleep_until(&next, &now);
			next = nnext;
		} else if (ts) {
			ts = (struct xpkt_tag_ts *)pkb_find_tag(p, XPKT_TAG_TIMESTAMP, 0);
			pts = tm_lset(ts->sec, ts->nsec);

			if (tm_ltz(pts)) {
				fprintf(stderr,
					"Invalid timestamp on packet %lu "
					"(%ld,%ld)\n",
					g_npkts, tm_sec(pts), tm_nsec(pts));
				pkb_free(p);
				continue;
			}

			if (g_npkts == 1)
				start_ts = pts;

			next = tm_add(tm_sub(pts, start_ts), start_time);
			sleep_until(&next, &now);
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
