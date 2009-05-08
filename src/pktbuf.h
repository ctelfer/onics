/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#ifndef __pktbuf_h
#define __pktbuf_h
#include <cat/cat.h>
#include <cat/cattypes.h>
#include <stdio.h>
#include "config.h"

struct pktprehdr {
  uint32_t  pph_dltype;
  uint32_t  pph_len;
  uint32_t  pph_class;
  uint32_t  pph_tssec;
  uint32_t  pph_tsnsec;
};

struct pktbuf {
  struct pktprehdr      pkb_header;
  uint32_t		pkb_buflen;
  uint32_t		pkb_offset;
  byte_t		pkb_buffer[1];
};
#define pkb_dltype    pkb_header.pph_dltype
#define pkb_len       pkb_header.pph_len
#define pkb_class     pkb_header.pph_class
#define pkb_tssec     pkb_header.pph_tssec
#define pkb_tsnsec    pkb_header.pph_tsnsec
#define pkb_data(p)   ((p)->pkb_buffer + (p)->pkb_offset)

enum pktdltype_e {
  PKTDL_MIN =       0x1,

  PKTDL_NONE =      0x1,        /* starts with network layer header */
  PKTDL_ETHERNET2 = 0x2,        /* starts with 14-byte ethernet 2 header */

  PKTDL_MAX =       0x2,
  PKTDL_INVALID =   PKTDL_MAX+1 /* not valid in packet, but used internally */
};

int  pkb_create(struct pktbuf **p, size_t plen, enum pktdltype_e dltype);
int  pkb_copy(const struct pktbuf *orig, struct pktbuf **newp);
int  pkb_resize(struct pktbuf **p, size_t newsize);
int  pkb_file_read(FILE *fp, struct pktbuf **p);
int  pkb_fd_read(int fd, struct pktbuf **p);
int  pkb_file_write(FILE *fp, struct pktbuf *p);
int  pkb_fd_write(int fd, struct pktbuf *p);
void pkb_free(struct pktbuf *p);

#endif /* __pktbuf_h */
