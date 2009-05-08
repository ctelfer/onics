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
  if ( rv < g_oparser.argc )
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
  struct pktbuf *p;
  int first_dltype;
  unsigned pktnum = 1;

  optparse_reset(&g_oparser, argc, argv);
  parse_options();

  if ( (rv = pkb_file_read(g_file, &p)) <= 0 ) {
    if ( rv == 0 )
      return 0;
    if ( rv < 0 )
      errsys("Reading first packet: ");
  }
  first_dltype = p->pkb_dltype;
  switch(first_dltype) {
  case PKTDL_ETHERNET2:
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
    if ( first_dltype != p->pkb_dltype )
      err("Datalink type mismatch.  Pkt 1 type = %d Pkt %u type = %d", 
          first_dltype, pktnum, p->pkb_dltype);
    if ( g_dumper != NULL ) {
      pcapph.len = p->pkb_len;
      pcapph.caplen = p->pkb_len;
      pcapph.ts.tv_sec = p->pkb_tssec; 
      pcapph.ts.tv_usec = p->pkb_tsnsec / 1000;
      pcap_dump((u_char *)g_dumper, &pcapph, pkb_data(p));
    } else {
      if ( pcap_inject(g_pcap, pkb_data(p), p->pkb_len) < 0 )
        err("pcap_inject: %s\n", pcap_geterr(g_pcap));
    }
    pkb_free(p);
    ++pktnum;
  } while ( (rv = pkb_file_read(g_file, &p)) > 0 );

  if ( rv < 0 )
     errsys("pkb_file_read: ");

  if ( g_dumper != NULL )
    pcap_dump_close(g_dumper);
  pcap_close(g_pcap);
  return 0;
}
