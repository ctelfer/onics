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

struct clopt g_options[] = {
	CLOPT_INIT(CLOPT_STRING, 'i', "--iface", "interfact to sniff from"),
	CLOPT_INIT(CLOPT_STRING, 'f', "--file", "file to read from"),
	CLOPT_INIT(CLOPT_NOARG, 'p', "--promisc",
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


int main(int argc, char *argv[])
{
	int dlt;
	uint16_t dltype;
	struct pcap_pkthdr pcapph;
	const byte_t *packet;
	struct pktbuf *p;

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

	while ((packet = (byte_t *) pcap_next(g_pcap, &pcapph)) != NULL) {
		/* 
		TODO META
		p->pkb_tssec = pcapph.ts.tv_sec;
		p->pkb_tsnsec = pcapph.ts.tv_usec * 1000;
		p->pkb_caplen = pcapph.len;
	        */
		pkb_set_len(p, pcapph.caplen);
		memcpy(p->pkb_buf, packet, pcapph.caplen);
		abort_unless(pkb_pack(p) == 0);
		if (pkb_fd_write(0, p) < 0)
			errsys("pkb_file_write: ");
		pkb_unpack(p);
	}
	pkb_free(p);
	pcap_close(g_pcap);

	return 0;
}
