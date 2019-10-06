/*
 * ONICS
 * Copyright 2013-2015
 * Christopher Adam Telfer
 *
 * pktin-linux.c -- Read packets from interfaces and output the packets in
 *   xpkt format.
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
#include "pktbuf.h"

#define PKTMAX  (1024 * 64 + 64)

const char *g_iifname = NULL;
const char *g_ofname = NULL;
uint g_ifnum = (uint)-1;
FILE *g_outfile;
int g_ifsock;
int g_promisc = 1;
int g_inonly = 0;
struct pktbuf *g_pkb;
struct xpkt_tag_ts *g_ts;
struct xpkt_tag_iface *g_tiif;

struct clopt g_options[] = {
	CLOPT_I_NOARG('h', NULL, "print help"),
	CLOPT_I_UINT('n', NULL, "IFNUM",
		     "interface number to tag packets with"),
	CLOPT_I_NOARG('I', NULL, "Capture incoming packets only"),
	CLOPT_I_NOARG('p', NULL, "don't enable promiscuous mode"),
};

struct clopt_parser g_oparse =
CLOPTPARSER_INIT(g_options, array_length(g_options));


void usage(const char *prog, const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&g_oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options] IFACE [OUTFILE]\n%s\n", prog, str);
	exit(1);
}


void parse_args(int argc, char *argv[])
{
	int rv;
	struct clopt *opt;

	g_outfile = stdout;

	optparse_reset(&g_oparse, argc, argv);
	while (!(rv = optparse_next(&g_oparse, &opt))) {
		switch (opt->ch) {
		case 'n':
			g_ifnum = opt->val.uint_val;
			break;
		case 'I':
			g_inonly = 1;
			break;
		case 'p':
			g_promisc = 0;
			break;
		case 'h':
			usage(argv[0], NULL);
			break;
		}
	}
	if (rv < 0 || rv >= argc)
		usage(argv[0], g_oparse.errbuf);

	g_iifname = argv[rv++];

	if (rv < argc) {
		g_ofname = argv[rv++];
		g_outfile = fopen(g_ofname, "w");
		if (g_outfile == NULL)
			errsys("Error opening file %s: ", g_ofname);
	}
}


/*
 * XXX
 * Linux 5.2 removed SIOGCSTAMP and created SIOGCSTAMP_OLD and SIOGCSTAMP_NEW
 * Here's for backard compatibility.  :( ... For now don't provide a timestamp
 * when this ioctl() isn't available.  Later fix this to check for the new API.
 */
#if SIOCGSTAMP

static void init_ts_tag()
{
	int rv;
	struct xpkt_tag_ts ts;

	xpkt_tag_ts_init(&ts, 0, 0);
	rv = pkb_add_tag(g_pkb, (struct xpkt_tag_hdr *)&ts);
	abort_unless(rv == 0);
	g_ts = (struct xpkt_tag_ts *)pkb_find_tag(g_pkb, XPKT_TAG_TIMESTAMP, 0);
	abort_unless(g_ts);
}

static void set_ts()
{
	struct timeval tv;

	if (ioctl(g_ifsock, SIOCGSTAMP, &tv) < 0)
		errsys("getting packet timestamp: ");
	g_ts->sec = tv.tv_sec;
	g_ts->nsec = tv.tv_usec * 1000;
}

#else /* SIOCGSTAMP */

static void init_ts_tag()
{
	g_ts = NULL;
}

static void set_ts()
{
}

#endif /* SIOCGSTAMP */


static void init_pkb()
{
	struct xpkt_tag_iface ti;
	int rv;

	pkb_init_pools(1);

	if (!(g_pkb = pkb_create(PKTMAX)))
		errsys("ptk_create: ");

	xpkt_tag_iif_init(&ti, g_ifnum);
	rv = pkb_add_tag(g_pkb, (struct xpkt_tag_hdr *)&ti);
	abort_unless(rv == 0);
	g_tiif = (struct xpkt_tag_iface*)pkb_find_tag(g_pkb,XPKT_TAG_INIFACE,0);
	abort_unless(g_tiif);

	init_ts_tag();
}


void init_ifsock()
{
	int rv;
	struct ifreq ifr;
	struct sockaddr_ll sll; 
	struct packet_mreq mr;

	g_ifsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (g_ifsock < 0)
		errsys("Error opening packet socket: ");

	if (g_iifname != NULL) {
		str_copy(ifr.ifr_name, g_iifname, IFNAMSIZ);
		if (ioctl(g_ifsock, SIOCGIFINDEX, &ifr) < 0)
			errsys("Error retrieving socket index for %s: ",
			       ifr.ifr_name);

		memset(&sll, 0, sizeof(sll));
		sll.sll_family = PF_PACKET;
		sll.sll_protocol = htonl(ETH_P_ALL);
		sll.sll_ifindex = ifr.ifr_ifindex;
		if (bind(g_ifsock, (struct sockaddr *)&sll, sizeof(sll)) < 0)
			errsys("Error binding to socket %s: ", ifr.ifr_name);

		if (g_ifnum != (uint)-1)
			g_ifnum = ifr.ifr_ifindex;
	}
	if (g_promisc) {
		memset(&mr, 0, sizeof(mr));
		mr.mr_ifindex = ifr.ifr_ifindex;
		mr.mr_type = PACKET_MR_PROMISC;
		rv = setsockopt(g_ifsock, SOL_SOCKET, PACKET_ADD_MEMBERSHIP,
				&mr, sizeof(mr));
		if (rv < 0)
			errsys("enabling promiscuous mode: ");
	}
}


void packet_loop()
{
	int rv;
	struct sockaddr_ll sll;
	socklen_t len = 1;
	socklen_t salen;
	ulong buflen;
	struct xpkt_tag_snapinfo si;
	int snapped;

	pkb_set_len(g_pkb, 0);
	pkb_set_off(g_pkb, 2);
	buflen = pkb_get_bufsize(g_pkb) - pkb_get_off(g_pkb);

	while (len > 0) {

		snapped = 0;
		salen = sizeof(sll);
		len = recvfrom(g_ifsock, pkb_data(g_pkb), buflen, MSG_TRUNC,
			       (struct sockaddr *)&sll, &salen);

		if (len < 0) {
			errsys("error receiving packet: ");
		} else if (len > 0) {
			/*
			 * Check whether we only want incoming packets
			 * Unfortunately, linux doesn't have PACKET_INCOMING
			 * that we can set as a parameter to bind(2).
			 */
			if (g_inonly && sll.sll_pkttype == PACKET_OUTGOING)
				continue;

			/* add snaplen */
			if (len > buflen) {
				xpkt_tag_si_init(&si, len);
				rv = pkb_add_tag(g_pkb,
						 (struct xpkt_tag_hdr *)&si);
				abort_unless(rv == 0);
				len = buflen;
			}

			set_ts();

			pkb_set_len(g_pkb, len);
			pkb_set_dltype(g_pkb, PRID_ETHERNET2);

			if (g_ifnum == (uint)-1)
				g_tiif->iface = sll.sll_ifindex;

			rv = pkb_pack(g_pkb);
			abort_unless(rv == 0);

			if (pkb_file_write(g_pkb, g_outfile) < 0)
				errsys("pkb_file_write: ");

			pkb_unpack(g_pkb);

			if (snapped)
				pkb_del_tag(g_pkb, XPKT_TAG_SNAPINFO, 0);

		}
	}
}


int main(int argc, char *argv[])
{
	parse_args(argc, argv);
	init_pkb();
	init_ifsock();
	packet_loop();
	pkb_free(g_pkb);
	fclose(g_outfile);
	close(g_ifsock);

	return 0;
}
