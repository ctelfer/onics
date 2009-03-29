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

#define PHLEN offsetof(struct pktbuf, pkt_buffer)


static INLINE int dltype_is_valid(uint32_t dlt)
{
  return (dlt >= PKTDL_MIN && dlt <= PKTDL_MAX);
}


static INLINE size_t offset_by_dltype(enum pktdltype_e dlt)
{
  switch(dlt) { 
    case PKTDL_ETHERNET2:
      return 2;
    default:
      return 0;
  }
}


static INLINE struct pktbuf * new_packet(const struct pktprehdr *pph)
{
  size_t off = offset_by_dltype(pph->pph_dltype);
  size_t dlen = pph->pph_len + off;
  struct pktbuf *p = emalloc(PHLEN + dlen);

  p->pkt_header = *pph;
  p->pkt_buflen = dlen;
  p->pkt_offset = off;

  return p;
}


int pkt_create(struct pktbuf **p, size_t plen, enum pktdltype_e dltype)
{
  struct pktprehdr pph;

  if ( p == NULL ) { 
    errno = EINVAL;
    return -1;
  }
  pph.pph_dltype = dltype;
  pph.pph_len = plen;
  pph.pph_timestamp = 0;
  *p = new_packet(&pph);

  return 0;
}


int pkt_copy(const struct pktbuf *orig, struct pktbuf **newp)
{
  struct pktbuf *p;
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


int pkt_resize(struct pktbuf **p, size_t plen)
{
  size_t tlen;
  struct pktbuf *newp;

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


int pkt_file_read(FILE *fp, struct pktbuf **p)
{
  struct pktprehdr pph, pph2;
  size_t nr;

  if ( fp == NULL || p == NULL ) {
    errno = EINVAL;
    return -1;
  }
  if ( (nr = fread(&pph, 1, sizeof(pph), fp)) < sizeof(pph) ) {
    if ( ferror(fp) || nr > 0 ) {
      errno = EIO;
      return -1;
    } else {
      return 0;
    }
  }
  unpack(&pph, sizeof(pph), "wwj", &pph2.pph_dltype, &pph2.pph_len,
         &pph2.pph_timestamp);
  if ( !dltype_is_valid(pph2.pph_dltype) ) {
    errno = EIO;
    return -1;
  }
  if ( (ssize_t)pph2.pph_len < 0 ) {
    errno = EIO;
    return -1;
  }
  *p = new_packet(&pph2);
  if ( fread(pkt_data(*p), 1, (*p)->pkt_len, fp) < (*p)->pkt_len ) {
    errno = EIO;
    return -1;
  }

  return 1;
}


int pkt_fd_read(int fd, struct pktbuf **p)
{
  struct pktprehdr pph, pph2;
  ssize_t nr;

  if ( p == NULL ) {
    errno = EINVAL;
    return -1;
  }
  if ( (nr = io_read(fd, &pph, sizeof(pph))) < sizeof(pph) ) {
    if ( nr != 0 ) {
      errno = EIO;
      return -1;
    } else {
      return 0;
    }
  }
  unpack(&pph, sizeof(pph), "wwj", &pph2.pph_dltype, &pph2.pph_len,
         &pph2.pph_timestamp);
  if ( !dltype_is_valid(pph2.pph_dltype) ) {
    errno = EIO;
    return -1;
  }
  if ( (ssize_t)pph2.pph_len < 0 ) {
    errno = EIO;
    return -1;
  }
  *p = new_packet(&pph2);
  if ( io_read(fd, pkt_data(*p), (*p)->pkt_len) < (*p)->pkt_len ) {
    errno = EIO;
    return -1;
  }

  return 1;
}


int pkt_file_write(FILE *fp, struct pktbuf *p)
{
  struct pktprehdr pph;
  size_t nr;

  if ( fp == NULL || p == NULL || (ssize_t)p->pkt_len < 0 ) {
    errno = EINVAL;
    return -1;
  }
  pack(&pph, sizeof(pph), "wwj", p->pkt_dltype, p->pkt_len, p->pkt_timestamp);
  if ( (nr = fwrite(&pph, 1, sizeof(pph), fp)) < sizeof(pph) ) {
    errno = EIO;
    return -1;
  }
  if ( (nr = fwrite(pkt_data(p), 1, p->pkt_len, fp)) < p->pkt_len ) {
    errno = EIO;
    return -1;
  }

  return 0;
}


int pkt_fd_write(int fd, struct pktbuf *p)
{
  struct pktprehdr pph;
  size_t nr;

  if ( p == NULL || (ssize_t)p->pkt_len < 0 ) {
    errno = EINVAL;
    return -1;
  }
  pack(&pph, sizeof(pph), "wwj", p->pkt_dltype, p->pkt_len, p->pkt_timestamp);
  if ( (nr = io_write(fd, &pph, sizeof(pph))) < sizeof(pph) ) {
    errno = EIO;
    return -1;
  }
  if ( (nr = io_write(fd, pkt_data(p), p->pkt_len)) < p->pkt_len ) {
    errno = EIO;
    return -1;
  }

  return 0;
}


void pkt_free(struct pktbuf *p)
{
  free(p);
}

