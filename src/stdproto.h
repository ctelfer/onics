/*
 * ONICS
 * Copyright 2013 
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

#define PRP_IPV6_NXFIELDS	4
#define PRP_IPV6FLD_NXTHDR	(PRP_OI_EXTRA + 0)
#define PRP_IPV6FLD_JLEN	(PRP_OI_EXTRA + 1)
#define PRP_IPV6FLD_AHH		(PRP_OI_EXTRA + 2)
#define PRP_IPV6FLD_FRAGH	(PRP_OI_EXTRA + 3)
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

#endif /* __stdproto_h */
