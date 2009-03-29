#ifndef __common_pkttools_h
#define __common_pkttools_h
#include <cat/cat.h>
#include <cat/cattypes.h>
#include <stdio.h>
#include "config.h"

enum pktdltype_e {
  PKTDL_MIN =       0x1,
  PKTDL_ETHERNET2 = 0x1,
  PKTDL_MAX =       0x1
};

struct pktprehdr {
  uint32_t  pph_dltype;
  uint32_t  pph_len;
  uint32_t  pph_class;
  uint64_t  pph_timestamp;
};

struct pktbuf {
  struct pktprehdr      pkt_header;
  uint32_t		pkt_buflen;
  uint32_t		pkt_offset;
  byte_t		pkt_buffer[1];
};
#define pkt_dltype    pkt_header.pph_dltype
#define pkt_len       pkt_header.pph_len
#define pkt_class     pkt_header.pph_class
#define pkt_timestamp pkt_header.pph_timestamp
#define pkt_data(p)   ((p)->pkt_buffer + (p)->pkt_offset)

int  pkt_create(struct pktbuf **p, size_t plen, enum pktdltype_e dltype);
int  pkt_copy(const struct pktbuf *orig, struct pktbuf **newp);
int  pkt_resize(struct pktbuf **p, size_t newsize);
int  pkt_file_read(FILE *fp, struct pktbuf **p);
int  pkt_fd_read(int fd, struct pktbuf **p);
int  pkt_file_write(FILE *fp, struct pktbuf *p);
int  pkt_fd_write(int fd, struct pktbuf *p);
void pkt_free(struct pktbuf *p);

#endif /* __common_pkttools_h */
