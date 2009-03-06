#ifndef __common_pkttools_h
#define __common_pkttools_h
#include <cat/cat.h>
#include <cat/cattypes.h>
#include <stdio.h>
#include "config.h"

enum pktt_dltype_e {
	PTDL_MIN =		0x1,
	PTDL_ETHERNET2 =	0x1,
	PTDL_MAX =		0x1
};

struct pktt_packet_hdr {
	uint32_t		pkth_dltype;
	uint32_t		pkth_len;
	uint64_t		pkth_timestamp;
};

struct pktt_packet {
	struct pktt_packet_hdr  pkt_header;
	uint32_t		pkt_buflen;
	uint32_t		pkt_offset;
	byte_t			pkt_buffer[1];
};
#define pkt_dltype	pkt_header.pkth_dltype
#define pkt_len		pkt_header.pkth_len
#define pkt_timestamp	pkt_header.pkth_timestamp
#define pkt_data(p)	((p)->pkt_buffer + (p)->pkt_offset)

int  pkt_create(struct pktt_packet **p, size_t plen, enum pktt_dltype_e dltype);
int  pkt_copy(const struct pktt_packet *orig, struct pktt_packet **newp);
int  pkt_resize(struct pktt_packet **p, size_t newsize);
int  pkt_file_read(FILE *fp, struct pktt_packet **p);
int  pkt_fd_read(int fd, struct pktt_packet **p);
int  pkt_file_write(FILE *fp, struct pktt_packet *p);
int  pkt_fd_write(int fd, struct pktt_packet *p);
void pkt_free(struct pktt_packet *p);

#endif /* __common_pkttools_h */
