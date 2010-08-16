/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#ifndef __metapkt_h
#define __metapkt_h
#include <cat/cat.h>
#include <cat/cattypes.h>
#include <cat/list.h>
#include "pktbuf.h"
#include "protoparse.h"

enum {
  MPKT_LAYER_LINK,       /* e.g. Ethernet */
  MPKT_LAYER_NET,        /* e.g. IPv4, IPv6 */
  MPKT_LAYER_XPORT,      /* e.g. TCP, UDP, RTP, ICMP */
  MPKT_LAYER_MAX = MPKT_LAYER_XPORT
};

/* we probably want to move this out of here and call it something else */
/* parsed packets are useful to lots of applications.  We also should */
/* consider adding a list entry to this structure for easy queuing. */

struct metapkt {
  struct list           entry;
  struct pktbuf *       pkb;
  struct prparse *      headers;
  struct prparse *      layer[MPKT_LAYER_MAX+1];
};


struct metapkt *metapkt_new(size_t plen, int ppt);
struct metapkt *pktbuf_to_metapkt(struct pktbuf *pb);
struct metapkt *metapkt_copy(struct metapkt *pkt);
void metapkt_free(struct metapkt *pkt, int freebuf);
/* layer == -1 for auto */
void metapkt_set_layer(struct metapkt *pkt, struct prparse *h, int layer);
void metapkt_clr_layer(struct metapkt *pkt, int layer);
int metapkt_pushhdr(struct metapkt *pkt, int htype);
int metapkt_wraphdr(struct metapkt *pkt, int htype);
void metapkt_pophdr(struct metapkt *pkt, int fromfront);
void metapkt_fixdlt(struct metapkt *pkt);


#endif /* __metapkt_h */
