#include <stdio.h>
#include "pktbuf.h"
#include "protoparse.h"
#include "stdpp.h"
#include "tcpip_hdrs.h"

const char *pnames(uint ppt)
{
	switch (ppt) {
	case PPT_NONE:
		return "Packet";
	case PPT_INVALID:
		return "Invalid Header";
	case PPT_ETHERNET2:
		return "Ethernet2";
	case PPT_ARP:
		return "ARP";
	case PPT_IPV4:
		return "IP";
	case PPT_IPV6:
		return "IPv6";
	case PPT_ICMP:
		return "ICMP";
	case PPT_ICMP6:
		return "ICMPv6";
	case PPT_UDP:
		return "UDP";
	case PPT_TCP:
		return "TCP";
	default:
		return "unknown";
	}
}

int main(int argc, char *argv[])
{
	struct pktbuf *p;
	struct prparse *prp, *t;
	unsigned npkt = 0;
	unsigned nprp = 0;

	register_std_proto_parsers();
	pkb_init(1);

	while (pkb_file_read(stdin, &p) > 0) {
		if (pkb_parse(p) < 0)
			errsys("Error parsing packet");
		++npkt;
		if (pkb_get_dltype(p) != DLT_ETHERNET2) {
			printf("Unknown data type for packet %u\n", npkt);
			continue;
		}
		prp = &p->pkb_prp;
		for (nprp = 1, t = prp_next(prp); !prp_list_end(t);
		     t = prp_next(t), ++nprp) {
			printf("%4u:\tHeader %u -- %s\n", npkt, nprp,
			       pnames(t->type));
			if (t->error == 0) {
				printf("\t\tNo errors\n");
			} else {
				if ((t->error & PPERR_TOOSMALL)) {
					printf("\t\tPacket too small\n");
					continue;
				}
				if ((t->error & PPERR_HLEN)) {
					printf("\t\tHeader length error\n");
					continue;
				}
				if ((t->error & PPERR_LENGTH)) {
					printf("\t\tLength field error\n");
					continue;
				}
				if ((t->error & PPERR_CKSUM))
					printf("\t\tChecksum error\n");
				if ((t->error & PPERR_OPTLEN))
					printf("\t\tOption length error\n");
				if ((t->error & PPERR_INVALID))
					printf("\t\tInvalid field combination error\n");
			}

			printf("\t\tOffset: %8u\tLength: %8u\n",
			       (unsigned)prp_soff(t), (unsigned)prp_totlen(t));
			printf("\t\tHeader length: %8u\n",
			       (unsigned)prp_hlen(t));
			printf("\t\tPayload length:%8u\n",
			       (unsigned)prp_plen(t));
			printf("\t\tTrailer length:%8u\n",
			       (unsigned)prp_tlen(t));
		}
		printf("\n");
		pkb_free(p);
	}

	return 0;
}
