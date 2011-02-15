#ifndef __stdproto_h
#define __stdproto_h
#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "dltypes.h"


/* Register all the standard protocol parsers. */
int register_std_proto();
void unregister_std_proto();

#define PPT_RAWDATA		PPT_BUILD(PPT_PF_DLT, DLT_NONE)
#define PPT_ETHERNET2		PPT_BUILD(PPT_PF_DLT, DLT_ETHERNET2)

#define PPT_IPV4		PPT_BUILD(PPT_PF_NET, 0)
#define PPT_IPV6		PPT_BUILD(PPT_PF_NET, 1)
#define PPT_ARP			PPT_BUILD(PPT_PF_NET, 2)

#define PPT_ICMP		PPT_BUILD(PPT_PF_INET, IPPROT_ICMP)
#define PPT_ICMP6		PPT_BUILD(PPT_PF_INET, IPPROT_ICMPV6)
#define PPT_TCP			PPT_BUILD(PPT_PF_INET, IPPROT_TCP)
#define PPT_UDP			PPT_BUILD(PPT_PF_INET, IPPROT_UDP)


#define PRP_ARP_NXFIELDS	1
#define PRP_ARPFLD_ETHARP	(PRP_OI_EXTRA + 0)

#define PRP_IP_NXFIELDS		4
#define PRP_IPFLD_LSR		(PRP_OI_EXTRA + 0)
#define PRP_IPFLD_TS		(PRP_OI_EXTRA + 1)
#define PRP_IPFLD_RR		(PRP_OI_EXTRA + 2)
#define PRP_IPFLD_SRR		(PRP_OI_EXTRA + 3)

#define PRP_TCP_NXFIELDS	6
#define PRP_TCPFLD_MSS		(PRP_OI_EXTRA + 0)
#define PRP_TCPFLD_WSCALE	(PRP_OI_EXTRA + 1)
#define PRP_TCPFLD_SACKOK	(PRP_OI_EXTRA + 2)
#define PRP_TCPFLD_SACK		(PRP_OI_EXTRA + 3)
#define PRP_TCPFLD_SACK_END	(PRP_OI_EXTRA + 4)
#define PRP_TCPFLD_TSTAMP	(PRP_OI_EXTRA + 5)
#define PRP_TCPFLD_MD5		(PRP_OI_EXTRA + 6)

#endif /* __stdproto_h */
