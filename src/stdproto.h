#ifndef __stdproto_h
#define __stdproto_h
#include "prid.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"


/* Register all the standard protocol parsers. */
int register_std_proto();
void unregister_std_proto();

#define PRP_ETH_NXFIELDS	3
#define PRP_ETHFLD_ETYPE	(PRP_OI_EXTRA + 0)
#define PRP_ETHFLD_VLAN0	(PRP_OI_EXTRA + 1)
#define PRP_ETHFLD_VLAN1	(PRP_OI_EXTRA + 2)

#define PRP_ARP_NXFIELDS	1
#define PRP_ARPFLD_ETHARP	(PRP_OI_EXTRA + 0)

#define PRP_IP_NXFIELDS		5
#define PRP_IPFLD_LSR		(PRP_OI_EXTRA + 0)
#define PRP_IPFLD_TS		(PRP_OI_EXTRA + 1)
#define PRP_IPFLD_RR		(PRP_OI_EXTRA + 2)
#define PRP_IPFLD_SRR		(PRP_OI_EXTRA + 3)
#define PRP_IPFLD_RA		(PRP_OI_EXTRA + 4)

#define PRP_TCP_NXFIELDS	6
#define PRP_TCPFLD_MSS		(PRP_OI_EXTRA + 0)
#define PRP_TCPFLD_WSCALE	(PRP_OI_EXTRA + 1)
#define PRP_TCPFLD_SACKOK	(PRP_OI_EXTRA + 2)
#define PRP_TCPFLD_SACK		(PRP_OI_EXTRA + 3)
#define PRP_TCPFLD_SACK_END	(PRP_OI_EXTRA + 4)
#define PRP_TCPFLD_TSTAMP	(PRP_OI_EXTRA + 5)
#define PRP_TCPFLD_MD5		(PRP_OI_EXTRA + 6)

#endif /* __stdproto_h */
