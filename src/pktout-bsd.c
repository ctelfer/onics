/*
 * ONICS
 * Copyright 2013
 * Christopher Adam Telfer
 *
 * pktout-linux.c -- Write packets out to an interface.
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
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <cat/err.h>
#include <cat/optparse.h>
#include <cat/str.h>

#define PKTMAX  (1024 * 64 + 64)

int g_ifsock = -1;
const char *g_oifn;
const char *g_ifn;
FILE *g_infile;

struct clopt g_options[] = {
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help")
};

struct clopt_parser g_oparse =
CLOPTPARSER_INIT(g_options, array_length(g_options));


void usage(const char *prog, const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&g_oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] [INFILE] IFNAME\n%s\n", prog, str);
	exit(1);
}


void parse_args(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;

	g_infile = stdin;

	optparse_reset(&g_oparse, argc, argv);
	while (!(rv = optparse_next(&g_oparse, &opt))) {
		switch (opt->ch) {
		case 'h':
			usage(argv[0], NULL);
			break;
		}
	}
	if (rv < 0 || rv >= argc)
		usage(argv[0], NULL);

	if (rv < argc - 1) {
		g_ifn = argv[rv++];
		g_infile = fopen(g_ifn, "r");
		if (g_infile == NULL)
			errsys("fopen(\"%s\"): ", g_ifn);
	}
	g_oifn = argv[rv];
}


void init_ifsock()
{
	int n = 0;
	char devname[64];
	struct ifreq ifr;

	do {
		snprintf(devname, sizeof(devname), "/dev/bpf%d", n++);
		g_ifsock = open(devname, O_RDWR);
	} while (g_ifsock < 0 && errno == EBUSY);

	if (g_ifsock < 0)
		errsys("opening BPF device: ");

	str_copy(ifr.ifr_name, g_oifn, sizeof(ifr.ifr_name));
	if (ioctl(g_ifsock, BIOCSETIF, &ifr) < 0)
		errsys("ioctl() BIOCSETIF: ");
}


void packet_loop()
{
	int rv;
	struct pktbuf *p;
	unsigned pktnum = 1;

	while ((rv = pkb_file_read(&p, g_infile)) > 0) {
		do {
			rv = write(g_ifsock, pkb_data(p), pkb_get_len(p));
		} while (rv < 0 && errno == EINTR);

		if (rv < 0)
			errsys("sending packet %u: ", pktnum);

		pktnum += 1;
		pkb_free(p);
	}

	if (rv < 0)
		errsys("error reading packet %u: ", pktnum);

}


int main(int argc, char *argv[])
{
	parse_args(argc, argv);
	pkb_init_pools(1);
	init_ifsock();
	packet_loop();
	fclose(g_infile);
	close(g_ifsock);

	return 0;
}
