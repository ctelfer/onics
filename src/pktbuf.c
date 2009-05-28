#include "pktbuf.h"
#include <cat/pack.h>
#include <cat/io.h>
#include <cat/emalloc.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define PHLEN offsetof(struct pktbuf, pkb_buffer)
#define DEFAULT_HPAD 256


static NETTOOLS_INLINE int dltype_is_valid(uint32_t dlt)
{
  return (dlt >= PKTDL_MIN && dlt <= PKTDL_MAX);
}


static NETTOOLS_INLINE size_t offset_by_dltype(enum pktdltype_e dlt)
{
  switch(dlt) { 
    case PKTDL_ETHERNET2:
      return 2 + DEFAULT_HPAD;
    case PKTDL_NONE:
      return 0 + DEFAULT_HPAD;
    default:
      return DEFAULT_HPAD;
  }
}


/* NB:  In the future I may change the allocation model for this part of */
/* the library to a list of packet buffers, etc.... */
static NETTOOLS_INLINE struct pktbuf * new_packet(const struct pktprehdr *pph)
{
  size_t off = offset_by_dltype(pph->pph_dltype);
  size_t dlen = pph->pph_len + off;
  struct pktbuf *p = emalloc(PHLEN + dlen);

  if ( !p )
    return NULL;

  p->pkb_header = *pph;
  p->pkb_buflen = dlen;
  p->pkb_offset = off;

  return p;
}


/* NB:  In the future I may change the allocation model for this part of */
/* the library to a list of packet buffers, etc.... */
static NETTOOLS_INLINE struct pktbuf * resize_packet(struct pktbuf *p, 
                                                     size_t newlen)
{
  return erealloc(p, newlen);
}


int pkb_create(struct pktbuf **p, size_t plen, enum pktdltype_e dltype)
{
  struct pktprehdr pph;

  if ( p == NULL ) { 
    errno = EINVAL;
    return -1;
  }
  pph.pph_dltype = dltype;
  pph.pph_len = plen;
  pph.pph_class = 0;
  pph.pph_tssec = 0;
  pph.pph_tsnsec = 0;
  if ( !(*p = new_packet(&pph)) ) {
    errno = ENOMEM;
    return -1;
  }

  return 0;
}


int pkb_copy(const struct pktbuf *orig, struct pktbuf **newp)
{
  struct pktbuf *p;

  if (!orig || !newp) {
    errno = EINVAL;
    return -1;
  }
  if ( !(p = new_packet(&orig->pkb_header)) ) {
    errno = ENOMEM;
    return -1;
  }
  memset(p->pkb_buffer, 0, p->pkb_offset);
  memcpy(pkb_data(p), pkb_data(orig), p->pkb_len);
  *newp = p;

  return 0;
}


int pkb_resize(struct pktbuf **p, size_t plen)
{
  size_t tlen;
  struct pktbuf *npb;

  if (!p || !*p) {
    errno = EINTR;
    return -1;
  }
  if ( plen <= (*p)->pkb_buflen - (*p)->pkb_offset ) {
    (*p)->pkb_len = plen;
    return 0;
  }
  tlen = PHLEN + (*p)->pkb_offset + plen;
  if ( !(npb = resize_packet(*p, tlen)) )
    return -1;
  *p = npb;
  (*p)->pkb_buflen = tlen - PHLEN;

  return 0;
}


int pkb_file_read(FILE *fp, struct pktbuf **p)
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
  unpack(&pph, sizeof(pph), "wwww", &pph2.pph_dltype, &pph2.pph_len,
         &pph2.pph_tssec, &pph2.pph_tsnsec);
  if ( !dltype_is_valid(pph2.pph_dltype) ) {
    errno = EIO;
    return -1;
  }
  if ( !(*p = new_packet(&pph2)) ) {
    errno = ENOMEM;
    return -1;
  }
  if ( fread(pkb_data(*p), 1, (*p)->pkb_len, fp) < (*p)->pkb_len ) {
    errno = EIO;
    return -1;
  }

  return 1;
}


int pkb_fd_read(int fd, struct pktbuf **p)
{
  struct pktprehdr pph, pph2;
  ssize_t nr;
  size_t rem, off = 0;

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
  unpack(&pph, sizeof(pph), "wwww", &pph2.pph_dltype, &pph2.pph_len,
         &pph2.pph_tssec, &pph2.pph_tsnsec);
  if ( !dltype_is_valid(pph2.pph_dltype) ) {
    errno = EIO;
    return -1;
  }

  if ( !(*p = new_packet(&pph2)) ) {
    errno = ENOMEM;
    return -1;
  }

  while ( (rem = (*p)->pkb_len) > SSIZE_MAX ) {
    if ( io_read(fd, pkb_data(*p) + off, SSIZE_MAX) < SSIZE_MAX ) {
      errno = EIO;
      return -1;
    }
    rem -= SSIZE_MAX;
    off += SSIZE_MAX;
  }
  if ( io_read(fd, pkb_data(*p) + off, rem) < rem ) {
    errno = EIO;
    return -1;
  }

  return 1;
}


int pkb_file_write(FILE *fp, struct pktbuf *p)
{
  struct pktprehdr pph;
  size_t nr;

  if ( fp == NULL || p == NULL ) {
    errno = EINVAL;
    return -1;
  }
  pack(&pph, sizeof(pph), "wwww", p->pkb_dltype, p->pkb_len, p->pkb_tssec,
       p->pkb_tsnsec);
  if ( (nr = fwrite(&pph, 1, sizeof(pph), fp)) < sizeof(pph) ) {
    errno = EIO;
    return -1;
  }
  if ( (nr = fwrite(pkb_data(p), 1, p->pkb_len, fp)) < p->pkb_len ) {
    errno = EIO;
    return -1;
  }

  return 0;
}


int pkb_fd_write(int fd, struct pktbuf *p)
{
  struct pktprehdr pph;
  size_t rem, off = 0;

  if ( p == NULL ) {
    errno = EINVAL;
    return -1;
  }
  pack(&pph, sizeof(pph), "wwww", p->pkb_dltype, p->pkb_len, p->pkb_tssec,
       p->pkb_tsnsec);
  if ( io_write(fd, &pph, sizeof(pph)) < sizeof(pph) ) {
    errno = EIO;
    return -1;
  }
  rem = p->pkb_len;
  while ( rem > SSIZE_MAX ) {
    if ( io_write(fd, pkb_data(p) + off, SSIZE_MAX) < SSIZE_MAX ) {
      errno = EIO;
      return -1;
    }
    rem -= SSIZE_MAX;
    off += SSIZE_MAX;
  }
  if ( io_write(fd, pkb_data(p) + off, rem) < rem ) {
    errno = EIO;
    return -1;
  }

  return 0;
}


/* NB:  In the future, if I change the allocation format in new_packet() */
/* then this will also have to change.  */
void pkb_free(struct pktbuf *p)
{
  free(p);
}

