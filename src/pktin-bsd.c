/*
 * ONICS
 * Copyright 2013-2015
 * Christopher Adam Telfer
 *
 * pktin-bsd.c -- Read packets from interfaces and output the packets in
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
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <cat/err.h>
#include <cat/optparse.h>
#include <cat/str.h>
#include <cat/emalloc.h>

#include "pktbuf.h"

#define PKTMAX  (1024 * 64 + 64)
#define PKTOFF	2

const char *g_iifname = NULL;
uint g_ifnum = (uint)-1;
FILE *g_outfile;
int g_ifsock;
int g_promisc = 1;
int g_inonly = 0;
uint g_prid;
uint g_buflen;
byte_t g_xbuf[1024];

struct clopt g_options[] = {
	CLOPT_I_NOARG('h', NULL, "print help"),
	CLOPT_I_UINT('n', NULL, "IFNUM",
		     "interface number to tag packets with"),
	CLOPT_I_NOARG('I', NULL, "capture incoming packets only"),
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
	const char *ofname;

	optparse_reset(&g_oparse, argc, argv);
	while (!(rv = optparse_next(&g_oparse, &opt))) {
		switch (opt->ch) {
		case 'h':
			usage(argv[0], NULL);
			break;
		case 'n':
			g_ifnum = opt->val.uint_val;
			break;
		case 'I':
			g_inonly = 1;
			break;
		case 'p':
			g_promisc = 0;
			break;
		}
	}

	if (rv < 0 || rv >= argc)
		usage(argv[0], g_oparse.errbuf);

	g_iifname = argv[rv++];
	if (rv < argc) {
		ofname = argv[rv++];
		g_outfile = fopen(ofname, "w");
		if (g_outfile == NULL)
			errsys("Error opening file %s: ", ofname);

	}
	if (rv < argc)
		usage(argv[0], NULL);
}


static void setup_pkb(struct pktbuf *pkb, void *p, 
		      struct bpf_hdr *bh)
{
	struct xpkt_tag_iface ti;
	struct xpkt_tag_snapinfo si;
	struct xpkt_tag_ts ts;
	int rv;

	pkb_init(pkb, p, bh->bh_caplen, g_xbuf, sizeof(g_xbuf));

	if (g_ifnum != (uint)-1) {
		xpkt_tag_iif_init(&ti, g_ifnum);
		rv = pkb_add_tag(pkb, (struct xpkt_tag_hdr *)&ti);
		abort_unless(rv == 0);
	}

	/* add snaplen */
	if (bh->bh_caplen < bh->bh_datalen) {
		xpkt_tag_si_init(&si, bh->bh_datalen);
		rv = pkb_add_tag(pkb, (struct xpkt_tag_hdr *)&si);
		abort_unless(rv == 0);
	}


	xpkt_tag_ts_init(&ts, bh->bh_tstamp.tv_sec, 
			 bh->bh_tstamp.tv_usec * 1000);
	rv = pkb_add_tag(pkb, (struct xpkt_tag_hdr *)&ts);
	abort_unless(rv == 0);

	pkb_set_len(pkb, bh->bh_caplen);

	pkb_set_dltype(pkb, g_prid);
}


int bpfdev_open()
{
	int fd;
	int n = 0;
	char devname[64];

	do {
		snprintf(devname, sizeof(devname), "/dev/bpf%d", n++);
		fd = open(devname, O_RDONLY);
	} while (fd < 0 && errno == EBUSY);

	return fd;
}


void init_ifsock()
{
	struct ifreq ifr;
	uint arg;

	g_ifsock = bpfdev_open();
	if (g_ifsock < 0)
		errsys("opening BPF device: ");

	str_copy(ifr.ifr_name, g_iifname, sizeof(ifr.ifr_name));
	if (ioctl(g_ifsock, BIOCSETIF, &ifr) < 0)
		errsys("ioctl() BIOCSETIF: ");

	if (ioctl(g_ifsock, BIOCGDLT, &arg) < 0)
		errsys("ioctl() BIOCGDLT: ");

	if (arg == DLT_EN10MB) {
		g_prid = PRID_ETHERNET2;
	} else {
		err("unknown datalink type: %u", arg);
	}

	if (g_promisc)
		ioctl(g_ifsock, BIOCPROMISC, NULL);

	if (ioctl(g_ifsock, BIOCGBLEN, &g_buflen) < 0)
		errsys("ioctl(BIOCGBLEN...): ");

	if (g_inonly) {
#ifdef BIOCSDIRFILT /* OpenBSD */
		arg = BPF_DIRECTION_OUT;
		if (ioctl(g_ifsock, BIOCSDIRFILT, &arg) < 0)
			errsys("ioctl(BIOCSDIRFILT, OUT)...");
#elif defined(BIOCSSEESENT) /* osX */
		arg = 0;
		if (ioctl(g_ifsock, BIOCSSEESENT, &arg) < 0)
			errsys("ioctl(BIOCSSEESENT, 0)...");
#else
		err("Option -I not supported on this platform\n");
#endif
	}

}


void packet_loop()
{
	int rv;
	int rlen = 0;
	struct pktbuf pkb;
	struct bpf_hdr *bh;
	byte_t *bpfbuf = emalloc(g_buflen);
	byte_t *bp;

	while (1) {
		if (rlen <= 0) {
			rlen = read(g_ifsock, bpfbuf, g_buflen);
			if (rlen <= 0) {
				if (rlen < 0) {
					rlen = 0;
					if (errno == EINTR)
						continue;
					errsys("error receiving packet: ");
				}
				break;
			}

			bp = bpfbuf;
		}

		bh = (struct bpf_hdr *)bp;
		setup_pkb(&pkb, bp + bh->bh_hdrlen, bh);

		rv = pkb_pack(&pkb);
		abort_unless(rv == 0);

		if (pkb_file_write(&pkb, g_outfile) < 0)
			errsys("pkb_file_write: ");

		bp += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
		rlen -= BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
	}
}


int main(int argc, char *argv[])
{
	g_outfile = stdout;
	parse_args(argc, argv);
	init_ifsock();
	packet_loop();
	fclose(g_outfile);
	close(g_ifsock);
	return 0;
}
