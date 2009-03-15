#ifndef __pptcpip_h
#define __pptcpip_h

extern struct pparse_ops none_pparse_ops;
extern struct pparse_ops eth_pparse_ops;
extern struct pparse_ops arp_pparse_ops;
extern struct pparse_ops ipv4_pparse_ops;
extern struct pparse_ops ipv6_pparse_ops;
extern struct pparse_ops icmp_pparse_ops;
extern struct pparse_ops icmpv6_pparse_ops;
extern struct pparse_ops udp_pparse_ops;
extern struct pparse_ops tcp_pparse_ops;

#define ARPFLD_ETHARP   0

#define IPFLD_LSR       0
#define IPFLD_TS        1
#define IPFLD_RR        2
#define IPFLD_SRR       3

#define TCPFLD_MSS      0
#define TCPFLD_WSCALE   1
#define TCPFLD_SACKOK   2
#define TCPFLD_SACK     3
#define TCPFLD_TSTAMP   4
#define TCPFLD_MD5      5


#endif /* __pptcpip_h */
