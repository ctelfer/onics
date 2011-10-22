#include "pktbuf.h"
#include <stdio.h>
#include <limits.h>
#include <pcap.h>
#include <cat/err.h>
#include <cat/pack.h>
#include <cat/optparse.h>

FILE *g_file = NULL;
struct pcap *g_pcap = NULL;
pcap_dumper_t *g_dumper = NULL;
const char *g_outiface = NULL;

struct clopt g_optarr[] = {
	CLOPT_INIT(CLOPT_STRING, 'i', "--iface", "interface to send out on"),
	CLOPT_INIT(CLOPT_STRING, 'f', "--file", "file to read from"),
	CLOPT_INIT(CLOPT_NOARG, 'h', "--help", "print help")
};

struct clopt_parser g_oparser =
CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));


void usage(const char *estr)
{
	char ubuf[4096];
	if (estr != NULL)
		fprintf(stderr, "Error -- %s\n", estr);
	optparse_print(&g_oparser, ubuf, sizeof(ubuf));
	err("usage: %s [options]\n%s\n", g_oparser.argv[0], ubuf);
}


void parse_options()
{
	int rv;
	struct clopt *opt;
	const char *pktfile = NULL;
	while (!(rv = optparse_next(&g_oparser, &opt))) {
		switch (opt->ch) {
		case 'i':
			g_outiface = opt->val.str_val;
			break;
		case 'f':
			pktfile = opt->val.str_val;
			break;
		case 'h':
			usage(NULL);
		}
	}
	if (rv < 0)
		usage(g_oparser.errbuf);
	if (rv < g_oparser.argc)
		usage("Extra arguments present");
	if (pktfile != NULL) {
		if ((g_file = fopen(pktfile, "r")) == NULL)
			errsys("fopen: ");
	} else {
		g_file = stdin;
	}
}


void setmeta(struct pcap_pkthdr *ph, struct pktbuf *p)
{
	struct xpkt_tag_ts *ts;
	struct xpkt_tag_snapinfo *si;

	ts = (struct xpkt_tag_ts *)pkb_find_tag(p, XPKT_TAG_TIMESTAMP, 0);
	if (ts) {
		ph->ts.tv_sec = ts->sec;
		ph->ts.tv_usec = ts->nsec / 1000;
	} else {
		ph->ts.tv_sec = 0;
		ph->ts.tv_usec = 0;
	}

	si = (struct xpkt_tag_snapinfo *)pkb_find_tag(p, XPKT_TAG_SNAPINFO, 0);
	if (si)
		ph->len = si->wirelen;
	else
		ph->len = pkb_get_len(p);
}


int main(int argc, char *argv[])
{
	int rv;
	uint32_t pcap_dlt;
	struct pcap_pkthdr pcapph;
	struct pktbuf *p;
	int first_dltype;
	unsigned pktnum = 1;

	optparse_reset(&g_oparser, argc, argv);
	parse_options();

	pkb_init(1);

	if ((rv = pkb_file_read(&p, g_file)) <= 0) {
		if (rv == 0)
			return 0;
		if (rv < 0)
			errsys("Reading first packet: ");
	}
	first_dltype = pkb_get_dltype(p);
	switch (first_dltype) {
	case PRID_ETHERNET2:
		pcap_dlt = DLT_EN10MB;
		break;
	default:
		err("Data link type not supported in pcap");
	}

	if (g_outiface == NULL) {
		if ((g_pcap = pcap_open_dead(pcap_dlt, INT_MAX)) == NULL)
			errsys("Error opening pcap: ");
		if ((g_dumper = pcap_dump_fopen(g_pcap, stdout)) == NULL)
			errsys("Error opening dumper to standard output: ");
	} else {
		char errbuf[PCAP_ERRBUF_SIZE];
		g_pcap = pcap_open_live(g_outiface, INT_MAX, 0, 0, errbuf);
		if (g_pcap == NULL)
			err("pcap_open_live: %s\n", errbuf);
		if (pcap_datalink(g_pcap) != pcap_dlt)
			err("Datalink type for %s is of the wrong type (%d)\n",
			    g_outiface, pcap_datalink(g_pcap));
	}

	do {
		if (first_dltype != pkb_get_dltype(p))
			err("Datalink type mismatch.  Pkt 1 type = %d "
			    "Pkt %u type = %d", 
			    first_dltype, pktnum, pkb_get_dltype(p));
		if (g_dumper != NULL) {
			pcapph.caplen = pkb_get_len(p);

			setmeta(&pcapph, p);

			pcap_dump((u_char *) g_dumper, &pcapph, pkb_data(p));
		} else {
			if (pcap_inject(g_pcap, pkb_data(p), pkb_get_len(p))< 0)
				err("pcap_inject: %s\n", pcap_geterr(g_pcap));
		}
		pkb_free(p);
		++pktnum;
	} while ((rv = pkb_file_read(&p, g_file)) > 0);

	if (rv < 0)
		errsys("pkb_file_read: ");

	if (g_dumper != NULL)
		pcap_dump_close(g_dumper);
	pcap_close(g_pcap);
	return 0;
}
