/*
 * ONICS
 * Copyright 2012-2015
 * Christopher Adam Telfer
 *
 * tcpip_hdrs.h -- Standard TCP/IP headers and definitions.
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __tcpip_hdrs_h
#define __tcpip_hdrs_h
#include <cat/cat.h>

/* -- Address Type Structures -- */
struct ethaddr {
	uint8_t			bytes[6];
};

struct ipv6addr {
	uint8_t			bytes[16];
};


/* -- Ethernet definitions -- */
struct eth2h {
	struct ethaddr		dst;
	struct ethaddr		src;
	uint16_t		ethtype;
};
#define ETHTYPE_IP              0x0800
#define ETHTYPE_IPV6            0x86DD
#define ETHTYPE_ARP             0x0806
#define ETHTYPE_TEB             0x6558	/* Transparent Ethernet Bridging */
#define ETHTYPE_C_VLAN          0x8100
#define ETHTYPE_S_VLAN          0x88a8
#define ETHTYPE_MPLS            0x8847
#define ETHTYPE_MPLSMC          0x8848
#define ETHHLEN                 14


/* -- ARP definitions -- */
struct arph {
	uint16_t		hwfmt;		/* ARPT_* */
	uint16_t		prfmt;		/* ETHTYPE_IP */
	uint8_t			hwlen;
	uint8_t			prlen;		/* 4 */
	uint16_t		op;		/* ARPOP_* */
};
#define ARPOP_REQUEST           1	/* RFC 826 */
#define ARPOP_REPLY             2	/* RFC 826,1868 */
#define ARPOP_RREQUEST          3	/* RFC 903 */
#define ARPOP_RREPLY            4	/* RFC 903 */
#define ARPOP_DARP_REQUEST      5	/* RFC 1931 */
#define ARPOP_DARP_RREPLY       6	/* RFC 1931 */
#define ARPOP_DARP_RERROR       7	/* RFC 1931 */
#define ARPOP_INARP_REQUEST     8	/* RFC 1293 */
#define ARPOP_INARP_REPLY       9	/* RFC 1293 */
#define ARPOP_NAK               10	/* RFC 1577 */

#define ARPT_ETHERNET           1
#define ARPT_EXETHERNET         2
#define ARPT_AX25               3
#define ARPT_PROTONET_TOKRING   4
#define ARPT_CHAOS              5
#define ARPT_IEEE802            6
#define ARPT_ARCNET             7
#define ARPT_HYPERCHANNEL       8
#define ARPT_LANSTAR            9
#define ARPT_AUTONET_SHORT      10
#define ARPT_LOCALTALK          11
#define ARPT_LOCALNET           12
#define ARPT_PCNET              ARPT_LOCALENET
#define ARPT_ULTRALINK          13
#define ARPT_SMDS               14
#define ARPT_FRAME_RELAY        15
#define ARPT_ATM1               16
#define ARPT_HDLC               17
#define ARPT_FIBRE_CHANNEL      18
#define ARPT_ATM2               19
#define ARPT_SERIAL_LINE        20
#define ARPT_ATM3               21
#define ARPT_MILSTD188220       22
#define ARPT_METRICOM           23
#define ARPT_IEEE1394           24
#define ARPT_MAPOS              25
#define ARPT_TWINAXIAL          26
#define ARPT_EUI64              27
#define ARPT_HIPARP             28
#define ARPT_ISO7816_3          29
#define ARPT_ARPSEC             30
#define ARPT_IPSEC_TUNNEL       31
#define ARPT_INFINIBAND         32
#define ARPT_CAI                33
#define ARPT_WEIGAND            34
#define ARPT_PUREIP             35

struct eth_arph {
	struct arph		header;	/* { 1, 0x800, 6, 4, (1|2) } */
	uint8_t			sndhwaddr[6];
	uint8_t			sndpraddr[4];
	uint8_t			trghwaddr[6];
	uint8_t			trgpraddr[4];
};


/* -- IP (v4) definitions -- */
struct ipv4h {
	uint8_t			vhl;
	uint8_t			diffsrv;
	uint16_t		len;
	uint16_t		id;
	uint16_t		fragoff;
	uint8_t			ttl;
	uint8_t			proto;
	uint16_t		cksum;
	uint32_t		saddr;
	uint32_t		daddr;
};
#define IPH_VERSION(iph)        ((iph).vhl >> 4)
#define IPH_HLEN(iph)           (((iph).vhl & 0xf) << 2)
#define IPH_ECN(iph)            ((iph).diffsrv & 0x3)
/* Note:  must first convert to host byte order */
#define IPH_RFMASK              0x8000
#define IPH_DFMASK              0x4000
#define IPH_MFMASK              0x2000
#define IPH_FRAGOFFMASK         0x1FFF
#define IPH_FRAGOFF(fragoff)    (((fragoff) & IPH_FRAGOFFMASK) << 3)
#define IPH_MINLEN		20
#define IPH_MAXLEN		60

#define IPPROT_V6_HOPOPT        0
#define IPPROT_ICMP             1
#define IPPROT_IGMP             2
#define IPPROT_GGP              3
#define IPPROT_IPIP             4
#define IPPROT_ST               5
#define IPPROT_TCP              6
#define IPPROT_CBT              7
#define IPPROT_EGP              8
#define IPPROT_IGRP             9
#define IPPROT_BBNRCC           10
#define IPPROT_NVP              11
#define IPPROT_PUP              12
#define IPPROT_ARGUS            13
#define IPPROT_EMCON            14
#define IPPROT_XNET             15
#define IPPROT_CHAOS            16
#define IPPROT_UDP              17
#define IPPROT_TMUX             18
#define IPPROT_DCN              19
#define IPPROT_HMP              20
#define IPPROT_PKTRADIO         21
#define IPPROT_XEROXNSIDP       22
#define IPPROT_TRUNK1           23
#define IPPROT_TRUNK2           24
#define IPPROT_LEAF1            25
#define IPPROT_LEAF2            26
#define IPPROT_RDP              27
#define IPPROT_IRTP             28
#define IPPROT_ISOTRANS4        29
#define IPPROT_NETBLT           30
#define IPPROT_MFE              31
#define IPPROT_MERIT            32
#define IPPROT_DCCP             33
#define IPPROT_3RDPCP           34
#define IPPROT_IDPR             35
#define IPPROT_XTP              36
#define IPPROT_DDP              37
#define IPPROT_IDPR_CTL         38
#define IPPROT_TPPP             39
#define IPPROT_ILTP             40
#define IPPROT_V6V4             41
#define IPPROT_SDRP             42
#define IPPROT_V6_ROUTE_HDR     43
#define IPPROT_V6_FRAG_HDR      44
#define IPPROT_IDRP             45
#define IPPROT_RSVP             46
#define IPPROT_GRE              47
#define IPPROT_DSR              48
#define IPPROT_BNA              49
#define IPPROT_ESP              50
#define IPPROT_AH               51
#define IPPROT_INLSP            52
#define IPPROT_SWIPE            53
#define IPPROT_NARP             54
#define IPPROT_MEP              55
#define IPPROT_TLSP             56
#define IPPROT_SKIP             57
#define IPPROT_ICMPV6           58
#define IPPROT_MLD              IPPROT_ICMPV6
#define IPPROT_V6_NONE          59
#define IPPROT_V6_DSTOPS        60
#define IPPROT_ANY_HOSTNET      61
#define IPPROT_CFTP             62
#define IPPROT_ANY_LOCNET       63
#define IPPROT_SATNET           64
#define IPPROT_KRYPTOLAN        65
#define IPPROT_MITVRD           66
#define IPPROT_IPPC             67
#define IPPROT_ANY_DISTFS       68
#define IPPROT_SATNET_MON       69
#define IPPROT_VISA             70
#define IPPROT_IPCU             71
#define IPPROT_CPNE             72
#define IPPROT_CPHB             73
#define IPPROT_WANGSPAN         74
#define IPPROT_PVP              75
#define IPPROT_BACK_SETNET_MON  76
#define IPPROT_SUNND            77
#define IPPROT_WIDEBAND_MON     78
#define IPPROT_WIDEBAND_EXPAK   79
#define IPPROT_ISOIP            80
#define IPPROT_VMTP             81
#define IPPROT_SVMTP            82
#define IPPROT_VINES            83
#define IPPROT_TTP              84
#define IPPROT_NSFNET_IGP       85
#define IPPROT_DGP              86
#define IPPROT_TCF              87
#define IPPROT_EIGRP            88
#define IPPROT_OSPF             89
#define IPPROT_MOSPF            IPPROT_OSPF
#define IPPROT_SPRITERPC        90
#define IPPROT_LARP             91
#define IPPROT_MTP              92
#define IPPROT_AX25             93
#define IPPROT_IPIP_OLD         94
#define IPPROT_MICP             95
#define IPPROT_SCCP             96
#define IPPROT_ETHERIP          97
#define IPPROT_ENCAP_HDR        98
#define IPPROT_ANY_ENCRYPT      99
#define IPPROT_GMTP             100
#define IPPROT_IFMP             101
#define IPPROT_PNNI             102
#define IPPROT_PIM              103
#define IPPROT_ARIS             104
#define IPPROT_SCPS             105
#define IPPROT_QNX              106
#define IPPROT_ACTIVENET        107
#define IPPROT_IPPCP            108
#define IPPROT_SNP              109
#define IPPROT_CCP              110
#define IPPROT_IPX              111
#define IPPROT_VRRP             112
#define IPPROT_PGM              113
#define IPPROT_ANY_0HOP         114
#define IPPROT_L2TP             115
#define IPPROT_DDX              116
#define IPPROT_IATP             117
#define IPPROT_SCHEDXFER        118
#define IPPROT_SRP              119
#define IPPROT_UTI              120
#define IPPROT_SMP              121
#define IPPROT_SM               122
#define IPPROT_PTP              123
#define IPPROT_ISIS             124
#define IPPROT_FIRE             125
#define IPPROT_CRTP             126
#define IPPROT_CRUDP            127
#define IPPROT_SSCOPMCE         128
#define IPPROT_IPLT             129
#define IPPROT_SPS              130
#define IPPROT_PIPE             131
#define IPPROT_SCTP             132
#define IPPROT_FIBRE_CHANNEL    133
#define IPPROT_RSVP_E2E_IGN     134
#define IPPROT_MOBILITY         135
#define IPPROT_UDPLITE          136
#define IPPROT_MPLS             137
#define IPPROT_MANET            138
#define IPPROT_HIP              139
#define IPPROT_EXP1             253
#define IPPROT_EXP2             254
#define IPPROT_RESERVED         255


#define IPOPT_COPY(ipoptp)      ((*(byte_t*)ipoptp) >> 7)
#define IPOPT_CLASS(ipoptp)     (((*(byte_t*)ipoptp) & 0x60) >> 5)
#define IPOPTC_CTL              0x0
#define IPOPTC_RES1             0x1
#define IPOPTC_DBG              0x2
#define IPOPTC_RES2             0x3

#define IPOPT_CODE(ipoptp)	((*(byte_t*)ipoptp) & 0x1F)
#define IPOPT_EOP               0	/* end of options */
#define IPOPT_NOP               1	/* no op */
#define IPOPT_SEC               130	/* security tag */
#define IPOPT_LSR               131	/* loose source route */
#define IPOPT_TS                68	/* timestamp */
#define IPOPT_RR                7	/* record route */
#define IPOPT_SID               136	/* stream ID */
#define IPOPT_SSR               137	/* strict source route */
#define IPOPT_RA		148	/* router alert */

#define IP_CLASSA(addrp)        ((*(byte_t*) & 0x80) == 0x0)
#define IP_CLASSB(addrp)        ((*(byte_t*) & 0xC0) == 0x80)
#define IP_CLASSC(addrp)        ((*(byte_t*) & 0xE0) == 0xC0)
#define IP_CLASSD(addrp)        ((*(byte_t*) & 0xF0) == 0xE0)
#define IP_CLASSE(addrp)        ((*(byte_t*) & 0xF8) == 0xF0)


/* -- TCP definitions -- */
struct tcph {
	uint16_t		sport;
	uint16_t		dport;
	uint32_t		seqn;
	uint32_t		ackn;
	uint8_t			doff;
	uint8_t			flags;
	uint16_t		win;
	uint16_t		cksum;
	uint16_t		urgp;
};
#define TCPH_HLEN(tcph)         (((tcph).doff >> 2) & ~3)
#define TCPH_ECNN(tcph)         ((tcph).doff & 1)
#define TCPH_MINLEN		20
#define TCPH_MAXLEN		60
#define TCPF_FIN                0x01
#define TCPF_SYN                0x02
#define TCPF_RST                0x04
#define TCPF_PSH                0x08
#define TCPF_ACK                0x10
#define TCPF_URG                0x20
#define TCPF_CWR                0x40
#define TCPF_ECE                0x80


struct tcpopth {
	uint8_t			kind;
	uint8_t			len;
};
#define TCPOPT_EOP              0	/* length == 1 */
#define TCPOPT_NOP              1	/* length == 1 */
#define TCPOPT_MSS              2	/* length == 4 */
#define TCPOPT_WSCALE           3	/* length == 3 */
#define TCPOPT_SACKOK           4	/* length == 2 */
#define TCPOPT_SACK             5	/* length == variable */
#define TCPOPT_TSTAMP           8	/* length == 10 */
#define TCPOPT_ALTCSUM_REQ      14	/* length == 3 */
#define TCPOPT_ALTCSUM_DATA     15	/* length == variable */
#define TCPOPT_MD5              19	/* length == 18 */




/* -- UDP definitions -- */
struct udph {
	uint16_t		sport;
	uint16_t		dport;
	uint16_t		len;
	uint16_t		cksum;
};
#define UDPH_LEN		8



/* -- pseudo headers for TCP and UDP -- */
struct pseudoh {
	uint32_t		saddr;
	uint32_t		daddr;
	uint8_t			zero;
	uint8_t			proto;
	uint16_t		totlen;	/* length starting with transport header */
};


struct pseudo6h {
	struct ipv6addr		saddr;
	struct ipv6addr		daddr;
	uint32_t		totlen;
	uint16_t		zero1;
	uint8_t			zero2;
	uint8_t			proto;
};


/* -- ICMP definitions -- */
struct icmph {
	uint8_t			type;
	uint8_t			code;
	uint16_t		cksum;
	union {
		/* ICMPT_ECHO_* */
		struct {
			uint16_t id;
			uint16_t seq;
		} echo;

		/* ICMPT_DEST_UNREACH:4 */
		struct {
			uint16_t unused;
			uint16_t mtu;
		} pmtu;

		/* ICMPT_PARAM_PROB */
		struct {
			uint8_t ptr;
			uint8_t unused1;
			uint16_t unused2;
		} pprob;

		/* ICMPT_TS_* */
		struct {
			uint16_t id;
			uint16_t seq;
			uint32_t ots;
			uint32_t rts;
			uint32_t tts;
		} ts;

		/*  ICMPT_INFO_* */
		struct {
			uint16_t id;
			uint16_t seq;
		} info;

		/* ICMPT_REDIRECT */
		uint32_t gateway;

		/* Many */
		uint32_t unused;
	} u;
};
#define ICMPH_LEN		8

/* ICMP type values */
#define ICMPT_ECHO_REPLY        0
#define ICMPT_DEST_UNREACH      3
#define ICMPT_SRC_QUENCH        4
#define ICMPT_REDIRECT          5
#define ICMPT_ECHO_REQUEST      8
#define ICMPT_TIME_EXCEEDED     11
#define ICMPT_PARAM_PROB        12
#define ICMPT_TS_REQ            13
#define ICMPT_TS_REP            14
#define ICMPT_INFO_REQ          15
#define ICMPT_INFO_REP          16
#define ICMPT_TRACEROUTE        30

#define ICMPT_IS_ERR(_t)			\
	(((_t) == ICMPT_DEST_UNREACH)  ||	\
	 ((_t) == ICMPT_TIME_EXCEEDED) ||	\
	 ((_t) == ICMPT_PARAM_PROB))

#define ICMPT_HAS_OPKT(_t)			\
	(((_t) == ICMPT_DEST_UNREACH)  ||	\
	 ((_t) == ICMPT_TIME_EXCEEDED) ||	\
	 ((_t) == ICMPT_PARAM_PROB)    ||	\
	 ((_t) == ICMPT_SRC_QUENCH)    ||	\
	 ((_t) == ICMPT_REDIRECT))

#define ICMPT_IS_ECHO(_t)			\
	(((_t) == ICMPT_ECHO_REPLY)  ||		\
	 ((_t) == ICMPT_ECHO_REQUEST))

#define ICMPT_IS_TSTAMP(_t)			\
	(((_t) == ICMPT_TS_REQ)  ||		\
	 ((_t) == ICMPT_TS_REP))

#define ICMPT_IS_INFO(_t)			\
	(((_t) == ICMPT_INFO_REQ)  ||		\
	 ((_t) == ICMPT_INFO_REP))

#define ICMPT_IS_QUERY(_t)			\
	(ICMPT_IS_ECHO(_t) || ICMPT_IS_TSTAMP(_t) || ICMPT_IS_INFO(_t))

/* ICMP_DEST_UNREACH codes */
#define ICMPC_NET_UNREACH       0
#define ICMPC_HOST_UNREACH      1
#define ICMPC_PROTO_UNREACH     2
#define ICMPC_PORT_UNREACH      3
#define ICMPC_FRAG_NEEDED       4
#define ICMPC_SRCRT_FAILED      5

/* ICMP_TIME_EXCEEDED codes */
#define ICMPC_TTL_EXCEEDED      0
#define ICMPC_FRAG_TIMEOUT      1

/* ICMP_REDIRECT codes */
#define ICMPC_NET_REDIR         0
#define ICMPC_HOST_REDIR        1
#define ICMPC_TOS_NET_REDIR     2
#define ICMPC_TOS_HOST_REDIR    3


/* -- IPv6 definitions -- */
struct ipv6h {
	uint32_t		prtcfl;
	uint16_t		len;
	uint8_t			nxthdr;
	uint8_t			hoplim;
	struct ipv6addr		saddr;
	struct ipv6addr		daddr;
};
/* Assumes network byte order */
#define IPV6H_LEN		40
#define IPV6H_PVERSION(ipv6hp)  (*(byte_t *)(ipv6hp) >> 4)
#define IPV6H_VERSION(prtcfl)   ((prtcfl) >> 28)
#define IPV6H_TCLASS(prtcfl)    (((prtcfl) >> 20) & 0xFF)
#define IPV6H_FLOWID(prtcfl)    ((prtcfl) & 0xFFFFF)


struct ipv6_fragh {
	uint8_t			nxthdr;
	uint8_t			resv;
	uint16_t		fragoff;
	uint32_t		id;
};

#define IPV6_FRAGH_MFMASK	0x1
#define IPV6_FRAGH_FOMASK	0xFFF8

/* -- ICMPv6 definitions -- */
struct icmp6h {
	uint8_t			type;
	uint8_t			code;
	uint16_t		cksum;
	uint32_t		xtra;
};

#define ICMP6H_LEN		8	/* minimum */

#define ICMP6T_DEST_UNREACH     1
#define ICMP6T_PKT_TOO_BIG      2
#define ICMP6T_TIME_EXCEEDED    3
#define ICMP6T_PARAM_PROB       4
#define ICMP6T_ECHO_REQUEST     128
#define ICMP6T_ECHO_REPLY       129
#define ICMP6T_LQUERY           130
#define ICMP6T_LRESPONSE        131
#define ICMP6T_LREDUCTION       132
#define ICMP6T_RSOLICIT         133
#define ICMP6T_RADVERT          134
#define ICMP6T_NSOLICIT         135
#define ICMP6T_NADVERT          136
#define ICMP6T_NREDIR           137

#define ICMP6T_IS_ERR(_t)	(((_t) & 0x80) == 0)
#define ICMP6T_IS_ECHO(_t)	\
	(((_t) == ICMP6T_ECHO_REQUEST) || ((_t) == ICMP6T_ECHO_REPLY))
#define ICMP6T_IS_NDP(_t)	\
	(((_t) >= ICMP6T_RSOLICIT) && ((_t) <= ICMP6T_NREDIR))
#define ICMP6T_IS_NEIGH(_t)	\
	(((_t) == ICMP6T_NSOLICIT) || ((_t) == ICMP6T_NADVERT))



struct icmp6_echo {
	uint8_t		type;
	uint8_t		code;
	uint16_t	cksum;
	uint16_t	id;
	uint16_t	seq;
};
#define ICMP6_ND_ECHO_HLEN	8


struct icmp6_nd_rsol {
	uint8_t		type;
	uint8_t		code;
	uint16_t	cksum;
	uint32_t	resv;
};
#define ICMP6_ND_RSOL_HLEN	8


struct icmp6_nd_radv {
	uint8_t		type;
	uint8_t		code;
	uint16_t	cksum;
	uint8_t		hoplim;
	uint8_t		flags;
	uint16_t	tlife;
	uint32_t	treach;
	uint32_t	tretry;
};
#define ICMP6_ND_RADV_HLEN	16
#define ICMP6_RADV_MACFG	0x80
#define ICMP6_RADV_OCFG		0x40


struct icmp6_nd_neigh {
	uint8_t		type;
	uint8_t		code;
	uint16_t	cksum;
	uint32_t	flags;
	struct ipv6addr	ip6a;
};

#define ICMP6_ND_NEIGH_HLEN	24
#define ICMP6_NADV_RTR		0x80000000
#define ICMP6_NADV_SOL		0x40000000
#define ICMP6_NADV_OVD		0x20000000


struct icmp6_nd_rdr {
	uint8_t		type;
	uint8_t		code;
	uint16_t	cksum;
	struct ipv6addr	tgtaddr;
	struct ipv6addr	dstaddr;
};
#define ICMP6_ND_RDR_HLEN	40


struct icmp6_nd_opt {
	uint8_t			type;
	uint8_t			len;
	uint8_t			data[6];	/* may be longer */
};
#define ICMP6_ND_OPT_MINLEN	8

#define ICMP6_ND_OPT_SRCLLA	1
#define ICMP6_ND_OPT_TGTLLA	2
#define ICMP6_ND_OPT_PFXINFO	3
#define ICMP6_ND_OPT_RDRHDR	4
#define ICMP6_ND_OPT_MTU	5
#define ICMP6_ND_OPT_RADVIVL	7
#define ICMP6_ND_OPT_AGTINFO	8

struct icmp6_nd_opt_lla {
	uint8_t			type;
	uint8_t			len;
	uint8_t			lla[6];
};
#define ICMP6_ND_LLA_OLEN	8	/* min */

struct icmp6_nd_opt_pfxinfo {
	uint8_t			type;
	uint8_t			len;		/* must be 4 */
	uint8_t			pfxlen;
	uint8_t			flags;
	uint32_t		valid_life;
	uint32_t		pref_life;
	uint32_t		reserved;
	struct ipv6addr		prefix;
};

#define ICMP6_ND_PFXINFO_OLEN	32
#define ICMP6_NF_PFXINFO_ONLINK 0x80
#define ICMP6_NF_PFXINFO_AUTO	0x40


/* followed by the original header */
struct icmp6_nd_opt_rdrhdr {
	uint8_t			type;
	uint8_t			len;
	uint16_t		rsv1;
	uint32_t		rsv2;
};
#define ICMP6_ND_RDRHDR_OLEN	8	/* minimum */


struct icmp6_nd_opt_mtu {
	uint8_t			type;
	uint8_t			len;
	uint16_t		reserved;
	uint32_t		mtu;
};
#define ICMP6_ND_MTU_OLEN	8


struct icmp6_nd_opt_radvivl {
	uint8_t			type;
	uint8_t			len;
	uint16_t		reserved;
	uint32_t		interval;
};
#define ICMP6_ND_RADVIVL_OLEN	8

struct icmp6_nd_opt_agtinfo {
	uint8_t			type;
	uint8_t			len;
	uint16_t		reserved;
	uint16_t		hapref;
	uint16_t		halife;
};
#define ICMP6_ND_AGTINFO_OLEN	8


struct greh {
	uint8_t			flags;
	uint8_t			version;
	uint16_t		proto;
};
#define GRE_BASE_HLEN		4
#define GRE_HLEN(_gre) \
	(GRE_BASE_HLEN + \
	 (!!((_gre)->flags & GRE_FLAG_CKSUM)) * 4 + \
	 (!!((_gre)->flags & GRE_FLAG_KEY)) * 4 + \
	 (!!((_gre)->flags & GRE_FLAG_SEQ)) * 4)
#define GRE_FLAG_MSK		0xB0
#define GRE_FLAGS(_gre)		((_gre)->flags & GRE_FLAG_MSK)
#define GRE_FLAG_CKSUM		0x80
#define GRE_FLAG_KEY		0x20
#define GRE_FLAG_SEQ		0x10
#define GRE_VERS_MSK		0x7
#define GRE_VERSION(_gre)	((_gre)->version & GRE_VERS_MSK)

#define GRE_CKSUM_OFF(_flags)	GRE_HLEN
#define GRE_KEY_OFF(_flags)	\
	(GRE_BASE_HLEN + (!!((_flags) & GRE_FLAG_CKSUM)) * 4)
#define GRE_SEQ_OFF(_flags)	\
	(GRE_BASE_HLEN + (!!((_flags) & GRE_FLAG_CKSUM)) * 4 + \
			 (!!((_flags) & GRE_FLAG_KEY)) * 4)

struct nvgreh {
	uint8_t			flags;
	uint8_t			version;
	uint16_t		proto;
	uint32_t		vsidflow;
};

#define NVGRE_HLEN		8
#define NVGRE_FLAG_MSK		0xB0
#define NVGRE_FLAGS(_gre)	((_gre)->flags & NVGRE_FLAG_MSK)
#define NVGRE_VERS_MSK		0x7
#define NVGRE_VERSION(_gre)	((_gre)->version & NVGRE_VERS_MSK)
#define NVGRE_FLOW_SHF		0
#define NVGRE_FLOW_MSK		0xFF
#define NVGRE_VSID_SHF		8
#define NVGRE_VSID_MSK		0xFFFFFF
#define NVGRE_FLOW(_nvgre) \
	(((_nvgre)->vsidflow >> NVGRE_FLOW_SHF) & NVGRE_FLOW_MSK)
#define NVGRE_VSID(_nvgre) \
	(((_nvgre)->vsidflow >> NVGRE_VSID_SHF) & NVGRE_VSID_MSK)


struct vxlanh {
	uint32_t		flags;
	uint32_t		vni;
};

#define VXLAN_HLEN		8
#define VXLAN_FLAG_MSK		0x08000000
#define VXLAN_FLAG_VNI		0x08000000
#define VXLAN_VNI_MSK		0x00FFFFFF
#define VXLAN_VNI_SHF		8
#define VXLAN_VNI(_vxh)		(((_vxh)->vni >> VXLAN_VNI_SHF) & VXLAN_VNI_MSK)
#define VXLAN_PORT		4789

struct mpls_label {
	uint32_t		label;
};

#define MPLS_HLEN		4
#define MPLS_LABEL_SHF		12
#define MPLS_LABEL_MSK		0xFFFFF
#define MPLS_TC_SHF		9
#define MPLS_TC_MSK		0x7
#define MPLS_BOS_SHF		8
#define MPLS_BOS_MSK		0x1
#define MPLS_TTL_SHF		0
#define MPLS_TTL_MSK		0xFF

#define MPLS_LABEL(_lbl) \
	(((_lbl) >> MPLS_LABEL_SHF) & MPLS_LABEL_MSK)
#define MPLS_TC(_lbl) \
	(((_lbl) >> MPLS_TC_SHF) & MPLS_TC_MSK)
#define MPLS_BOS(_lbl)	\
	(((_lbl) >> MPLS_BOS_SHF) & MPLS_BOS_MSK)
#define MPLS_TTL(_lbl) \
	(((_lbl) >> MPLS_TTL_SHF) & MPLS_TTL_MSK)

#define MPLS_PORT		6635


#endif /* __tcpip_hdrs_h */
