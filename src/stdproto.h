/*
 * ONICS
 * Copyright 2012-2015
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

#define PRP_ETH_NXFIELDS	3
#define PRP_ETHFLD_ETYPE	(PRP_OI_EXTRA + 0)
#define PRP_ETHFLD_VLAN0	(PRP_OI_EXTRA + 1)
#define PRP_ETHFLD_VLAN1	(PRP_OI_EXTRA + 2)

#define PRP_ARP_NXFIELDS	1
#define PRP_ARPFLD_ETHARP	(PRP_OI_EXTRA + 0)

#define PRP_IP_NXFIELDS		6
#define PRP_IPFLD_OPT		(PRP_OI_EXTRA + 0)
#define PRP_IPFLD_LSR		(PRP_OI_EXTRA + 1)
#define PRP_IPFLD_TS		(PRP_OI_EXTRA + 2)
#define PRP_IPFLD_RR		(PRP_OI_EXTRA + 3)
#define PRP_IPFLD_SRR		(PRP_OI_EXTRA + 4)
#define PRP_IPFLD_RA		(PRP_OI_EXTRA + 5)

#define PRP_ICMP_NXFIELDS	6
#define PRP_ICMPFLD_QUERY	(PRP_OI_EXTRA + 0)	/* ID, timestamp */
#define PRP_ICMPFLD_PPTR	(PRP_OI_EXTRA + 1)	/* Param prob ptr */
#define PRP_ICMPFLD_MTU		(PRP_OI_EXTRA + 2)	/* Unreach code 4 */
#define PRP_ICMPFLD_TS		(PRP_OI_EXTRA + 3)	/* Timestamp fields */
#define PRP_ICMPFLD_GW		(PRP_OI_EXTRA + 4)	/* Redirect */
#define PRP_ICMPFLD_RESERVED	(PRP_OI_EXTRA + 5)	/* Various */

#define PRP_IPV6_NXFIELDS	11
#define PRP_IPV6FLD_NXTHDR	(PRP_OI_EXTRA + 0)
#define PRP_IPV6FLD_HOPOPT	(PRP_OI_EXTRA + 1)
#define PRP_IPV6FLD_RTOPT	(PRP_OI_EXTRA + 2)
#define PRP_IPV6FLD_JLEN	(PRP_OI_EXTRA + 3)
#define PRP_IPV6FLD_FRAGH	(PRP_OI_EXTRA + 4)
#define PRP_IPV6FLD_AHH		(PRP_OI_EXTRA + 5)
#define PRP_IPV6FLD_ESPH	(PRP_OI_EXTRA + 6)
#define PRP_IPV6FLD_DSTOPT1	(PRP_OI_EXTRA + 7)
#define PRP_IPV6FLD_DSTOPT2	(PRP_OI_EXTRA + 8)
#define PRP_IPV6FLD_UNKOPT	(PRP_OI_EXTRA + 9)
#define PRP_IPV6FLD_EXTOPT	(PRP_OI_EXTRA + 10)
#define PRP_IPV6_NXDHDR(_ip6prp, _buf) \
	(*(((byte_t *)_buf) + (_ip6prp)->offs[PRP_IPV6FLD_NXTHDR]))

#define PRP_TCP_NXFIELDS	8
#define PRP_TCPFLD_OPT		(PRP_OI_EXTRA + 0)
#define PRP_TCPFLD_MSS		(PRP_OI_EXTRA + 1)
#define PRP_TCPFLD_WSCALE	(PRP_OI_EXTRA + 2)
#define PRP_TCPFLD_SACKOK	(PRP_OI_EXTRA + 3)
#define PRP_TCPFLD_SACK		(PRP_OI_EXTRA + 4)
#define PRP_TCPFLD_SACK_END	(PRP_OI_EXTRA + 5)
#define PRP_TCPFLD_TSTAMP	(PRP_OI_EXTRA + 6)
#define PRP_TCPFLD_MD5		(PRP_OI_EXTRA + 7)

#define PRP_ICMP6_NXFIELDS	18
#define PRP_ICMP6FLD_ERESV	(PRP_OI_EXTRA + 0)
#define PRP_ICMP6FLD_PPTR	(PRP_OI_EXTRA + 1)
#define PRP_ICMP6FLD_ECHO	(PRP_OI_EXTRA + 2)	/* ID, SEQ */
#define PRP_ICMP6FLD_RSOL	(PRP_OI_EXTRA + 3)	/* router solicit */
#define PRP_ICMP6FLD_RADV	(PRP_OI_EXTRA + 4)	/* router advert */
#define PRP_ICMP6FLD_NEIGH	(PRP_OI_EXTRA + 5)	/* neigh sol/adv */
#define PRP_ICMP6FLD_REDIR	(PRP_OI_EXTRA + 6)	/* neighbor redirect */
#define PRP_ICMP6FLD_NDPOPT	(PRP_OI_EXTRA + 7)
#define PRP_ICMP6FLD_SRCLLA	(PRP_OI_EXTRA + 8)
#define PRP_ICMP6FLD_SRCLLA_EOFF	(PRP_OI_EXTRA + 9)
#define PRP_ICMP6FLD_TGTLLA	(PRP_OI_EXTRA + 10)
#define PRP_ICMP6FLD_TGTLLA_EOFF	(PRP_OI_EXTRA + 11)
#define PRP_ICMP6FLD_PFXINFO	(PRP_OI_EXTRA + 12)
#define PRP_ICMP6FLD_RDRHDR	(PRP_OI_EXTRA + 13)
#define PRP_ICMP6FLD_RDRHDR_EOFF	(PRP_OI_EXTRA + 14)
#define PRP_ICMP6FLD_MTU	(PRP_OI_EXTRA + 15)
#define PRP_ICMP6FLD_RADVIVL	(PRP_OI_EXTRA + 16)
#define PRP_ICMP6FLD_AGTINFO	(PRP_OI_EXTRA + 17)

#define PRP_GRE_NXFIELDS	3
#define PRP_GREFLD_CKSUM	(PRP_OI_EXTRA + 0)
#define PRP_GREFLD_KEY		(PRP_OI_EXTRA + 1)
#define PRP_GREFLD_SEQ		(PRP_OI_EXTRA + 2)

#endif /* __stdproto_h */
