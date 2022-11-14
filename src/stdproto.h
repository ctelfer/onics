/*
 * ONICS
 * Copyright 2012-2022
 * Christopher Adam Telfer
 *
 * stdproto.h -- Header for standard Internet protocol parse libraries.
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
#ifndef __stdproto_h
#define __stdproto_h
#include "prid.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"


/* Register all the standard protocol parsers. */
int register_std_proto();
void unregister_std_proto();

#define PDU_ETH_NXFIELDS	3
#define PDU_ETHFLD_ETYPE	(PDU_OI_EXTRA + 0)
#define PDU_ETHFLD_VLAN0	(PDU_OI_EXTRA + 1)
#define PDU_ETHFLD_VLAN1	(PDU_OI_EXTRA + 2)

#define PDU_ARP_NXFIELDS	1
#define PDU_ARPFLD_ETHARP	(PDU_OI_EXTRA + 0)

#define PDU_IP_NXFIELDS		6
#define PDU_IPFLD_OPT		(PDU_OI_EXTRA + 0)
#define PDU_IPFLD_LSR		(PDU_OI_EXTRA + 1)
#define PDU_IPFLD_TS		(PDU_OI_EXTRA + 2)
#define PDU_IPFLD_RR		(PDU_OI_EXTRA + 3)
#define PDU_IPFLD_SRR		(PDU_OI_EXTRA + 4)
#define PDU_IPFLD_RA		(PDU_OI_EXTRA + 5)

#define PDU_ICMP_NXFIELDS	6
#define PDU_ICMPFLD_QUERY	(PDU_OI_EXTRA + 0)	/* ID, timestamp */
#define PDU_ICMPFLD_PPTR	(PDU_OI_EXTRA + 1)	/* Param prob ptr */
#define PDU_ICMPFLD_MTU		(PDU_OI_EXTRA + 2)	/* Unreach code 4 */
#define PDU_ICMPFLD_TS		(PDU_OI_EXTRA + 3)	/* Timestamp fields */
#define PDU_ICMPFLD_GW		(PDU_OI_EXTRA + 4)	/* Redirect */
#define PDU_ICMPFLD_RESERVED	(PDU_OI_EXTRA + 5)	/* Various */

#define PDU_IPV6_NXFIELDS	11
#define PDU_IPV6FLD_NXTHDR	(PDU_OI_EXTRA + 0)
#define PDU_IPV6FLD_HOPOPT	(PDU_OI_EXTRA + 1)
#define PDU_IPV6FLD_RTOPT	(PDU_OI_EXTRA + 2)
#define PDU_IPV6FLD_JLEN	(PDU_OI_EXTRA + 3)
#define PDU_IPV6FLD_FRAGH	(PDU_OI_EXTRA + 4)
#define PDU_IPV6FLD_AHH		(PDU_OI_EXTRA + 5)
#define PDU_IPV6FLD_ESPH	(PDU_OI_EXTRA + 6)
#define PDU_IPV6FLD_DSTOPT1	(PDU_OI_EXTRA + 7)
#define PDU_IPV6FLD_DSTOPT2	(PDU_OI_EXTRA + 8)
#define PDU_IPV6FLD_UNKOPT	(PDU_OI_EXTRA + 9)
#define PDU_IPV6FLD_EXTOPT	(PDU_OI_EXTRA + 10)
#define PDU_IPV6_NXDHDR(_ip6pdu, _buf) \
	(*(((byte_t *)_buf) + (_ip6pdu)->offs[PDU_IPV6FLD_NXTHDR]))

#define PDU_TCP_NXFIELDS	8
#define PDU_TCPFLD_OPT		(PDU_OI_EXTRA + 0)
#define PDU_TCPFLD_MSS		(PDU_OI_EXTRA + 1)
#define PDU_TCPFLD_WSCALE	(PDU_OI_EXTRA + 2)
#define PDU_TCPFLD_SACKOK	(PDU_OI_EXTRA + 3)
#define PDU_TCPFLD_SACK		(PDU_OI_EXTRA + 4)
#define PDU_TCPFLD_SACK_END	(PDU_OI_EXTRA + 5)
#define PDU_TCPFLD_TSTAMP	(PDU_OI_EXTRA + 6)
#define PDU_TCPFLD_MD5		(PDU_OI_EXTRA + 7)

#define PDU_ICMP6_NXFIELDS	18
#define PDU_ICMP6FLD_ERESV	(PDU_OI_EXTRA + 0)
#define PDU_ICMP6FLD_PPTR	(PDU_OI_EXTRA + 1)
#define PDU_ICMP6FLD_ECHO	(PDU_OI_EXTRA + 2)	/* ID, SEQ */
#define PDU_ICMP6FLD_RSOL	(PDU_OI_EXTRA + 3)	/* router solicit */
#define PDU_ICMP6FLD_RADV	(PDU_OI_EXTRA + 4)	/* router advert */
#define PDU_ICMP6FLD_NEIGH	(PDU_OI_EXTRA + 5)	/* neigh sol/adv */
#define PDU_ICMP6FLD_REDIR	(PDU_OI_EXTRA + 6)	/* neighbor redirect */
#define PDU_ICMP6FLD_NDPOPT	(PDU_OI_EXTRA + 7)
#define PDU_ICMP6FLD_SRCLLA	(PDU_OI_EXTRA + 8)
#define PDU_ICMP6FLD_SRCLLA_EOFF	(PDU_OI_EXTRA + 9)
#define PDU_ICMP6FLD_TGTLLA	(PDU_OI_EXTRA + 10)
#define PDU_ICMP6FLD_TGTLLA_EOFF	(PDU_OI_EXTRA + 11)
#define PDU_ICMP6FLD_PFXINFO	(PDU_OI_EXTRA + 12)
#define PDU_ICMP6FLD_RDRHDR	(PDU_OI_EXTRA + 13)
#define PDU_ICMP6FLD_RDRHDR_EOFF	(PDU_OI_EXTRA + 14)
#define PDU_ICMP6FLD_MTU	(PDU_OI_EXTRA + 15)
#define PDU_ICMP6FLD_RADVIVL	(PDU_OI_EXTRA + 16)
#define PDU_ICMP6FLD_AGTINFO	(PDU_OI_EXTRA + 17)

#define PDU_GRE_NXFIELDS	3
#define PDU_GREFLD_CKSUM	(PDU_OI_EXTRA + 0)
#define PDU_GREFLD_KEY		(PDU_OI_EXTRA + 1)
#define PDU_GREFLD_SEQ		(PDU_OI_EXTRA + 2)

#define PDU_MPLS_NXFIELDS	3
#define PDU_MPLSFLD_LBL1	(PDU_OI_EXTRA + 0)
#define PDU_MPLSFLD_LBL2	(PDU_OI_EXTRA + 1)
#define PDU_MPLSFLD_LBL3	(PDU_OI_EXTRA + 2)

#endif /* __stdproto_h */
