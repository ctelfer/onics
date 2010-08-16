#ifndef __pptcpip_h
#define __pptcpip_h

extern struct proto_parser_ops none_proto_parser_ops;
extern struct proto_parser_ops eth_proto_parser_ops;
extern struct proto_parser_ops arp_proto_parser_ops;
extern struct proto_parser_ops ipv4_proto_parser_ops;
extern struct proto_parser_ops ipv6_proto_parser_ops;
extern struct proto_parser_ops icmp_proto_parser_ops;
extern struct proto_parser_ops icmpv6_proto_parser_ops;
extern struct proto_parser_ops udp_proto_parser_ops;
extern struct proto_parser_ops tcp_proto_parser_ops;

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
