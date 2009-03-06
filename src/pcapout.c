#include "packet.h"
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
	CLOPT_INIT(CLOPT_NOARG,  'h', "--help", "print help")
};
struct clopt_parser g_oparser =
	CLOPTPARSER_INIT(g_optarr, array_length(g_optarr));


void usage(const char *estr)
{
	char ubuf[4096];
	if ( estr != NULL )
		fprintf(stderr, "Error -- %s\n", estr);
	optparse_print(&g_oparser, ubuf, sizeof(ubuf));
	err("usage: %s [options]\n%s\n", g_oparser.argv[0], ubuf);
}


void parse_options()
{
	int rv;
	struct clopt *opt;
	const char *pktfile = NULL;
	while ( !(rv = optparse_next(&g_oparser, &opt)) ) {
		switch(opt->ch) {
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
	if ( rv < 0 )
		usage(g_oparser.errbuf);
	if ( rv > 0 )
		usage("Extra arguments present");
	if ( pktfile != NULL ) {
		if ( (g_file = fopen(pktfile, "r")) == NULL )
			errsys("fopen: ");
	} else {
		g_file = stdin;
	}
}


int main(int argc, char *argv[])
{
	int rv;
	uint32_t pcap_dlt;
	struct pcap_pkthdr pcapph;
	struct pktt_packet *p;
	int first_dltype;
	unsigned pktnum = 1;

	optparse_reset(&g_oparser, argc, argv);
	parse_options();

	if ( (rv = pkt_file_read(g_file, &p)) <= 0 ) {
		if ( rv == 0 )
			return 0;
		if ( rv < 0 )
			errsys("Reading first packet");
	}
	first_dltype = p->pkt_dltype;
	switch(first_dltype) {
	case PTDL_ETHERNET2:
		pcap_dlt = DLT_EN10MB;
		break;
	default:
		err("Data link type not supported in pcap");
	}

	if ( g_outiface == NULL ) {
		if ( (g_pcap = pcap_open_dead(pcap_dlt, SIZE_MAX)) == NULL )
			errsys("Error opening pcap: ");
		if ( (g_dumper = pcap_dump_fopen(g_pcap, stdout)) == NULL )
			errsys("Error opening dumper to standard output: ");
	} else { 
		char errbuf[PCAP_ERRBUF_SIZE];
		g_pcap = pcap_open_live(g_outiface, SIZE_MAX, 0, 0, errbuf);
		if ( g_pcap == NULL )
			err("pcap_open_live: %s\n", errbuf);
		if ( pcap_datalink(g_pcap) != pcap_dlt )
			err("Datalink type for %s is of the wrong type (%d)\n",
			    g_outiface, pcap_datalink(g_pcap));
	}

	do {
		if ( first_dltype != p->pkt_dltype )
			err("Datalink type mismatch.  Pkt 1 type = %d"
			    "Pkt %u type = %d", first_dltype, pktnum, 
			    p->pkt_dltype);
		if ( g_dumper != NULL ) {
			pcapph.len = p->pkt_len;
			pcapph.caplen = p->pkt_len;
			pcapph.ts.tv_sec = p->pkt_timestamp / 1000000000;
			pcapph.ts.tv_usec = p->pkt_timestamp % 1000000000;
			pcap_dump((u_char *)g_dumper, &pcapph, p->pkt_buffer);
		} else {
			/* TODO: create an option for intervals between sends */
			if ( pcap_inject(g_pcap,p->pkt_buffer,p->pkt_len) < 0 )
				err("pcap_inject: %s\n", pcap_geterr(g_pcap));
		}
		pkt_free(p);
		++pktnum;
	} while ( (rv = pkt_file_read(stdin, &p)) > 0 );
	if ( rv < 0 )
		errsys("pkt_file_read: ");

	pcap_close(g_pcap);
	if ( g_dumper != NULL )
		pcap_dump_close(g_dumper);
	if ( g_file != NULL )
		fclose(g_file);
	return 0;
}
