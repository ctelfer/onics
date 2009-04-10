#include <stdio.h>
#include "packet.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"

int main(int argc, char *argv[])
{
  struct pktbuf *p;
  struct hdr_parse *hdr, *t;
  unsigned npkt = 0;
  unsigned nhdr = 0;

  install_default_proto_parsers();

  while ( pkt_file_read(stdin, &p) > 0 ) {
    ++npkt;
    if ( p->pkt_dltype != PKTDL_ETHERNET2 ) {
      printf("Unknown data type for packet %u\n", npkt);
      continue;
    }
    hdr = hdr_parse_packet(PPT_ETHERNET, p->pkt_buffer, p->pkt_offset, 
                           p->pkt_len, p->pkt_buflen);
    if ( hdr == NULL ) {
      printf("Could not parse ethernet packet %u\n", npkt);
      continue;
    }

    for ( nhdr = 1, t = hdr_child(hdr); t != hdr; t = hdr_child(t), ++nhdr ) {
      printf("%4u:\tHeader %u -- Type %u\n", npkt, nhdr, t->type);
      if ( t->error == 0 ) {
        printf("\t\tNo errors\n");
      } else {
        if ( (t->error & PPERR_TOOSMALL) ) {
          printf("\t\tPacket too small\n");
          continue;
        }
        if ( (t->error & PPERR_HLEN) ) {
          printf("\t\tHeader length error\n");
          continue;
        }
        if ( (t->error & PPERR_LENGTH) ) {
          printf("\t\tLength field error\n");
          continue;
        }
        if ( (t->error & PPERR_CKSUM) )
          printf("\t\tChecksum error\n");
        if ( (t->error & PPERR_OPTLEN) )
          printf("\t\tOption length error\n");
        if ( (t->error & PPERR_INVALID) )
          printf("\t\tInvalid field combination error\n");
      }

      printf("\t\tOffset: %8u\tLength: %8u\n", (unsigned)t->hoff,
             (unsigned)hdr_totlen(t));
      printf("\t\tHeader length: %8u\n", (unsigned)hdr_hlen(t));
      printf("\t\tPayload length:%8u\n", (unsigned)hdr_plen(t));
      printf("\t\tTrailer length:%8u\n", (unsigned)hdr_tlen(t));
    } 
    printf("\n");
    pkt_free(p);
  }

  return 0;
}
