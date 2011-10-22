#include <stdio.h>
#include "prid.h"
#include "pktbuf.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"

const char *pnames(uint prid)
{
	switch (prid) {
	case PRID_NONE:
		return "Packet";
	case PRID_INVALID:
		return "Invalid Header";
	case PRID_ETHERNET2:
		return "Ethernet2";
	case PRID_ARP:
		return "ARP";
	case PRID_IPV4:
		return "IP";
	case PRID_IPV6:
		return "IPv6";
	case PRID_ICMP:
		return "ICMP";
	case PRID_ICMP6:
		return "ICMPv6";
	case PRID_UDP:
		return "UDP";
	case PRID_TCP:
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

	register_std_proto();
	pkb_init(1);

	while (pkb_file_read(&p, stdin) > 0) {
		if (pkb_parse(p) < 0)
			errsys("Error parsing packet");
		++npkt;
		if (pkb_get_dltype(p) != PRID_ETHERNET2) {
			printf("Unknown data type for packet %u\n", npkt);
			continue;
		}
		prp = &p->prp;
		for (nprp = 1, t = prp_next(prp); !prp_list_end(t);
		     t = prp_next(t), ++nprp) {
			printf("%4u:\tHeader %u -- %s\n", npkt, nprp,
			       pnames(t->prid));
			if (t->error == 0) {
				printf("\t\tNo errors\n");
			} else {
				if ((t->error & PRP_ERR_TOOSMALL)) {
					printf("\t\tPacket too small\n");
					continue;
				}
				if ((t->error & PRP_ERR_HLEN)) {
					printf("\t\tHeader length error\n");
					continue;
				}
				if ((t->error & PRP_ERR_LENGTH)) {
					printf("\t\tLength field error\n");
					continue;
				}
				if ((t->error & PRP_ERR_CKSUM))
					printf("\t\tChecksum error\n");
				if ((t->error & PRP_ERR_OPTLEN))
					printf("\t\tOption length error\n");
				if ((t->error & PRP_ERR_INVALID))
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
