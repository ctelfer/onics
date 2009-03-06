#include "packet.h"
#include <cat/emalloc.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#if CAT_USE_INLINE
#define INLINE inline
#else
#define INLINE
#endif

#define PHLEN offsetof(struct pktt_packet, pkt_buffer)

static INLINE int 
dltype_is_valid(uint32_t dlt)
{
	return (dlt >= PTDL_MIN && dlt <= PTDL_MAX);
}

static INLINE size_t
offset_by_dltype(enum pktt_dltype_e dlt)
{
	switch(dlt) { 
		case PTDL_ETHERNET2:
			return 2;
		default:
			return 0;
	}
}


static INLINE struct pktt_packet *
new_packet(const struct pktt_packet_hdr *ph)
{
	size_t off = offset_by_dltype(ph->pkth_dltype);
	size_t dlen = ph->pkth_len + off;
	struct pktt_packet *p = emalloc(PHLEN + dlen);

	p->pkt_header = *ph;
	p->pkt_buflen = dlen;
	p->pkt_offset = off;

	return p;
}


int 
pkt_create(struct pktt_packet **p, size_t plen, enum pktt_dltype_e dltype)
{
	struct pktt_packet_hdr ph;

	if ( p == NULL ) { 
		errno = EINVAL;
		return -1;
	}
	ph.pkth_dltype = dltype;
	ph.pkth_len = plen;
	ph.pkth_timestamp = 0;
	*p = new_packet(&ph);

	return 0;
}


int
pkt_copy(const struct pktt_packet *orig, struct pktt_packet **newp)
{
	struct pktt_packet *p;
	size_t dlen;

	if (!orig || !newp) {
		errno = EINTR;
		return -1;
	}
	p = new_packet(&orig->pkt_header);
	memset(p->pkt_buffer, 0, p->pkt_offset);
	memcpy(pkt_data(p), pkt_data(orig), p->pkt_len);
	*newp = p;

	return 0;
}


int
pkt_resize(struct pktt_packet **p, size_t plen)
{
	size_t tlen;
	struct pktt_packet *newp;

	if (!p || !*p) {
		errno = EINTR;
		return -1;
	}
	if ( plen <= (*p)->pkt_buflen - (*p)->pkt_offset ) {
		(*p)->pkt_len = plen;
		return 0;
	}
	tlen = PHLEN + (*p)->pkt_offset + plen;
	*p = erealloc(*p, tlen);
	(*p)->pkt_buflen = tlen - PHLEN;

	return 0;
}


int
pkt_file_read(FILE *fp, struct pktt_packet **p)
{
	struct pktt_packet_hdr ph, ph2;
	size_t nr;

	if ( fp == NULL || p == NULL ) {
		errno = EINVAL;
		return -1;
	}
	if ( (nr = fread(&ph, 1, sizeof(ph), fp)) < sizeof(ph) ) {
		if ( ferror(fp) || nr > 0 ) {
			errno = EIO;
			return -1;
		} else {
			return 0;
		}
	}
	unpack(&ph, sizeof(ph), "wwj", &ph2.pkth_dltype, &ph2.pkth_len,
	       &ph2.pkth_timestamp);
	if ( !dltype_is_valid(ph2.pkth_dltype) ) {
		errno = EIO;
		return -1;
	}
	if ( (ssize_t)ph2.pkth_len < 0 ) {
		errno = EIO;
		return -1;
	}
	*p = new_packet(&ph2);
	if ( fread(pkt_data(*p), 1, (*p)->pkt_len, fp) < (*p)->pkt_len ) {
		errno = EIO;
		return -1;
	}

	return 1;
}


int
pkt_fd_read(int fd, struct pktt_packet **p)
{
	struct pktt_packet_hdr ph, ph2;
	ssize_t nr;

	if ( p == NULL ) {
		errno = EINVAL;
		return -1;
	}
	if ( (nr = io_read(fd, &ph, sizeof(ph))) < sizeof(ph) ) {
		if ( nr != 0 ) {
			errno = EIO;
			return -1;
		} else {
			return 0;
		}
	}
	unpack(&ph, sizeof(ph), "wwj", &ph2.pkth_dltype, &ph2.pkth_len,
	       &ph2.pkth_timestamp);
	if ( !dltype_is_valid(ph2.pkth_dltype) ) {
		errno = EIO;
		return -1;
	}
	if ( (ssize_t)ph2.pkth_len < 0 ) {
		errno = EIO;
		return -1;
	}
	*p = new_packet(&ph2);
	if ( io_read(fd, pkt_data(*p), (*p)->pkt_len) < (*p)->pkt_len ) {
		errno = EIO;
		return -1;
	}

	return 1;
}


int
pkt_file_write(FILE *fp, struct pktt_packet *p)
{
	struct pktt_packet_hdr ph;
	size_t nr;

	if ( fp == NULL || p == NULL || (ssize_t)p->pkt_len < 0 ) {
		errno = EINVAL;
		return -1;
	}
	pack(&ph, sizeof(ph), "wwj", &p->pkt_dltype, &p->pkt_len,
	     &p->pkt_timestamp);
	if ( (nr = fwrite(&ph, 1, sizeof(ph), fp)) < sizeof(ph) ) {
		errno = EIO;
		return -1;
	}
	if ( (nr = fwrite(pkt_data(p), 1, p->pkt_len, fp)) < p->pkt_len ) {
		errno = EIO;
		return -1;
	}

	return 0;
}


int
pkt_fd_write(int fd, struct pktt_packet *p)
{
	struct pktt_packet_hdr ph;
	size_t nr;

	if ( p == NULL || (ssize_t)p->pkt_len < 0 ) {
		errno = EINVAL;
		return -1;
	}
	pack(&ph, sizeof(ph), "wwj", &p->pkt_dltype, &p->pkt_len,
	     &p->pkt_timestamp);
	if ( (nr = io_write(fd, &ph, sizeof(ph))) < sizeof(ph) ) {
		errno = EIO;
		return -1;
	}
	if ( (nr = io_write(fd, pkt_data(p), p->pkt_len)) < p->pkt_len ) {
		errno = EIO;
		return -1;
	}

	return 0;
}


void
pkt_free(struct pktt_packet *p)
{
	free(p);
}

