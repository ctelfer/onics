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
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cat/err.h>
#include <cat/optparse.h>
#include <cat/str.h>

#define PKTMAX  (1024 * 64 + 64)

int g_ifsock = -1;
const char *g_oifn;
const char *g_ifn;
FILE *g_infile;

struct clopt g_options[] = {
	CLOPT_INIT(CLOPT_STRING, 'f', "--infile", "input file to read from"),
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
	fprintf(stderr, "usage: %s [options] IFNAME\n%s\n", prog, str);
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
		case 'f':
			g_ifn = opt->val.str_val;
			g_infile = fopen(g_ifn, "r");
			if (g_infile == NULL)
				errsys("error opening input file %s: ", g_ifn);
			break;
		case 'h':
			usage(argv[0], NULL);
			break;
		}
	}

	if (rv < 0 || rv > argc - 1)
		usage(argv[0], NULL);

	g_oifn = argv[rv];
}


void init_ifsock()
{
	struct ifreq ifr;
	struct sockaddr_ll sll; 

	g_ifsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (g_ifsock < 0)
		errsys("Error opening packet socket: ");

	str_copy(ifr.ifr_name, g_oifn, IFNAMSIZ);
	if (ioctl(g_ifsock, SIOCGIFINDEX, &ifr) < 0)
		errsys("Error retrieving socket index for %s: ",
		       ifr.ifr_name);

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htonl(ETH_P_ALL);
	sll.sll_ifindex = ifr.ifr_ifindex;
	if (bind(g_ifsock, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		errsys("Error binding to socket %s: ", ifr.ifr_name);

}


void packet_loop()
{
	int rv;
	ssize_t ns;
	struct pktbuf *p;
	unsigned pktnum = 1;

	while ((rv = pkb_file_read(&p, g_infile)) > 0) {
		do {
			ns = send(g_ifsock, pkb_data(p), pkb_get_len(p), 0);
		} while (ns < pkb_get_len(p) && errno == EINTR);

		if (ns < 0)
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
