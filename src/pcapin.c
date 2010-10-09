#include "pktbuf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <cat/pack.h>
#include <cat/err.h>
#include <cat/optparse.h>

#define PKTMAX  (1024 * 10)

pcap_t *g_pcap;
FILE *g_infile = NULL;
uint g_ifnum = 0;

struct clopt g_options[] = {
	CLOPT_INIT(CLOPT_STRING, 'i', "--iface", "interfact to sniff from"),
	CLOPT_INIT(CLOPT_STRING, 'f', "--file", "file to read from"),
	CLOPT_INIT(CLOPT_UINT,   'n', "--iface-num",
		   "interface number to tag packets with"),
	CLOPT_INIT(CLOPT_NOARG,  'p', "--promisc",
		   "set interface in promiscuous mode"),
	CLOPT_INIT(CLOPT_STRING, 'h', "--help", "print help")
};

struct clopt_parser g_oparse =
CLOPTPARSER_INIT(g_options, array_length(g_options));


void usage(const char *prog, const char *estr)
{
	char str[4096];
	if (estr)
		fprintf(stderr, "%s\n", estr);
	optparse_print(&g_oparse, str, sizeof(str));
	fprintf(stderr, "usage: %s [options]\n%s\n", prog, str);
	exit(1);
}


void parse_args(int argc, char *argv[])
{
	char ebuf[PCAP_ERRBUF_SIZE];
	int rv, usefile = 1, promisc = 0;
	const char *pktsrc;
	struct clopt *opt;

	optparse_reset(&g_oparse, argc, argv);
	while (!(rv = optparse_next(&g_oparse, &opt))) {
		switch (opt->ch) {
		case 'i':
			pktsrc = opt->val.str_val;
			usefile = 0;
			break;
		case 'f':
			pktsrc = opt->val.str_val;
			usefile = 1;
			break;
		case 'n':
			g_ifnum = opt->val.uint_val;
			break;
		case 'p':
			promisc = 1;
			break;
		case 'h':
			usage(argv[0], NULL);
			break;
		}
	}
	if (rv < argc)
		usage(argv[0], g_oparse.errbuf);

	if (usefile) {
		if (pktsrc != NULL) {
			if ((g_infile = fopen(pktsrc, "r")) == NULL)
				errsys("fopen: ");
		} else {
			g_infile = stdin;
		}
		if ((g_pcap = pcap_fopen_offline(g_infile, ebuf)) == NULL)
			err("Error opening pcap: %s\n", ebuf);
	} else {
		g_pcap = pcap_open_live(pktsrc, 65535, promisc, 0, ebuf);
		if (g_pcap == NULL)
			err("Error opening interface %s: %s\n", pktsrc, ebuf);
	}
}


static void init_tags(struct pktbuf *p)
{
	struct xpkt_tag_iface ti;
	struct xpkt_tag_ts ts;
	int rv;

	xpkt_tag_iif_init(&ti, g_ifnum);
	rv = pkb_add_tag(p, (struct xpkt_tag_hdr *)&ti);
	abort_unless(rv == 0);

	xpkt_tag_ts_init(&ts, 0, 0);
	rv = pkb_add_tag(p, (struct xpkt_tag_hdr *)&ts);
	abort_unless(rv == 0);
}


int main(int argc, char *argv[])
{
	int dlt;
	uint16_t dltype;
	struct pcap_pkthdr pcapph;
	const byte_t *packet;
	struct pktbuf *p;
	struct xpkt_tag_ts *ts;
	struct xpkt_tag_snapinfo si;
	int rv;

	parse_args(argc, argv);
	switch ((dlt = pcap_datalink(g_pcap))) {
	case DLT_EN10MB:
		dltype = DLT_ETHERNET2;
		break;
	default:
		err("unsupported datalink type: %d", dlt);
	}

	pkb_init(1);

	if (!(p = pkb_create(PKTMAX)))
		errsys("ptk_create: ");
	pkb_set_dltype(p, dltype);
	init_tags(p);
	ts = (struct xpkt_tag_ts *)pkb_find_tag(p, XPKT_TAG_TIMESTAMP, 0);
	abort_unless(ts);

	while ((packet = (byte_t *) pcap_next(g_pcap, &pcapph)) != NULL) {
		ts->xpt_ts_sec = pcapph.ts.tv_sec;
		ts->xpt_ts_nsec = pcapph.ts.tv_usec * 1000;

		pkb_set_len(p, pcapph.caplen);

		if (pcapph.len != pcapph.caplen) {
			xpkt_tag_si_init(&si, pcapph.len);
			rv = pkb_add_tag(p, &si.xpt_si_hdr);
			abort_unless(rv == 0);
		}

		memcpy(p->pkb_buf, packet, pcapph.caplen);
		rv = pkb_pack(p);
		abort_unless(rv == 0);
		if (pkb_fd_write(1, p) < 0)
			errsys("pkb_fd_write: ");
		pkb_unpack(p);

		if (pcapph.len != pcapph.caplen)
			pkb_del_tag(p, XPKT_TAG_SNAPINFO, 0);
	}
	pkb_free(p);
	pcap_close(g_pcap);

	return 0;
}
