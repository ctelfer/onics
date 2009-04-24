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
  NETVM_HDI_LINK,       /* e.g. Ethernet */
  NETVM_HDI_NET,        /* e.g. IPv4, IPv6 */
  NETVM_HDI_XPORT,      /* e.g. TCP, UDP, RTP, ICMP */
  NETVM_HDI_MAX = NETVM_HDI_XPORT
};

/* we probably want to move this out of here and call it something else */
/* parsed packets are useful to lots of applications.  We also should */
/* consider adding a list entry to this structure for easy queuing. */

struct metapkt {
  struct list           entry;
  struct pktbuf *       pkb;
  struct hdr_parse *    headers;
  struct hdr_parse *    layer[NETVM_HDI_MAX+1];
};


struct metapkt *metapkt_new(size_t plen, int ppt);
struct metapkt *pktbuf_to_metapkt(struct pktbuf *pb);
struct metapkt *metapkt_copy(struct metapkt *pkt);
void metapkt_free(struct metapkt *pkt, int freebuf);
void metapkt_set_layer(struct metapkt *pkt, struct hdr_parse *h);
void metapkt_clr_layer(struct metapkt *pkt, int layer);
int metapkt_pushhdr(struct metapkt *pkt, int htype);
void metapkt_pophdr(struct metapkt *pkt);
void metapkt_fixdlt(struct metapkt *pkt);


#endif /* __metapkt_h */
