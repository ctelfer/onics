/*
 * ONICS
 * Copyright 2013 
 * Christopher Adam Telfer
 *
 * opcap.h -- Interface to local libpcap implementation
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
#ifndef __opcap_h
#define __opcap_h

#include <cat/cattypes.h>
#include "config.h"

#define OPCAP_MAGIC		0xa1b2c3d4
#define OPCAP_MAGIC_SWAP	0xd4c3b2a1

#define OPCAP_FHSIZE		24
#define OPCAP_PHSIZE		16

#define OPCAP_DLT_NULL		0       /* BSD loopback encapsulation */
#define OPCAP_DLT_EN10MB	1       /* Ethernet (10Mb) */
#define OPCAP_DLT_EN3MB		2       /* Experimental Ethernet (3Mb) */
#define OPCAP_DLT_AX25		3       /* Amateur Radio AX.25 */
#define OPCAP_DLT_PRONET	4       /* Proteon ProNET Token Ring */
#define OPCAP_DLT_CHAOS		5       /* Chaos */
#define OPCAP_DLT_IEEE802	6       /* 802.5 Token Ring */
#define OPCAP_DLT_ARCNET	7       /* ARCNET, with BSD-style header */
#define OPCAP_DLT_SLIP		8       /* Serial Line IP */
#define OPCAP_DLT_PPP		9       /* Point-to-point Protocol */
#define OPCAP_DLT_FDDI		10      /* FDDI */


ONICS_PACK_DECL(
struct opcap_fhdr {
	uint32_t	magic;
	uint16_t	major;
	uint16_t	minor;
	int32_t		tz;
	uint32_t	tssig;
	uint32_t	snaplen;
	uint32_t	dltype;
}
);


ONICS_PACK_DECL(
struct opcap_phdr {
	uint32_t	tssec;
	uint32_t	tsusec;
	uint32_t	len;
	uint32_t	caplen;
}
);


typedef void *opcap_h;


/* The following return -1 on error and 0 on success except for opcap_read() */
/* They also all set errno on an error. */

/* open a pcap file for reading and return the handle. */
int opcap_open_reader(const char *fname, opcap_h *h);

/* read the next packet from a pcap reader into a buffer at 'bp' with */
/* max size of 'maxlen'.  Store the packet header contents in 'ph' */
/* returns: -1 on error, 0 on EOF and 1 when there was a successful read. */
int opcap_read(opcap_h h, void *bp, size_t maxlen, struct opcap_phdr *ph);

/* open a pcap file for writing and return the handle. */
int opcap_open_writer(const char *fname, uint32_t snaplen, uint32_t dltype,
		      opcap_h *h);

/* write a packet out to a file */
int opcap_write(opcap_h h, void *bp, struct opcap_phdr *ph);

/* return the snaplen for an open packet capture */
int opcap_is_reader(opcap_h h);

/* return the snaplen for an open packet capture */
uint32_t opcap_get_snaplen(opcap_h h);

/* return the dltype for an open packet capture */
uint32_t opcap_get_dltype(opcap_h h);

/* close a pcap file reader */
void opcap_close(opcap_h h);

#endif /* __opcap_h */
