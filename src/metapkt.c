#include "config.h"
#include "metapkt.h"
#include <cat/emalloc.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>


/* NB: we pull these out because I'm thinking of changing the allocation */
/* scheme for metapackets in the future.  If so, I need  to change newpmeta() */
/* and freepmeta() */
static NETTOOLS_INLINE struct metapkt *newpmeta() 
{
  struct metapkt *pkt = ecalloc(1, sizeof(struct metapkt));
  if ( pkt )
    l_init(&pkt->entry);
  return pkt;
}


static NETTOOLS_INLINE void freepmeta(struct metapkt *pkt)
{
  free(pkt);
}


static unsigned dltype_to_ppt(uint32_t dltype)
{
  switch(dltype) {
  case PKTDL_ETHERNET2:
    return PPT_ETHERNET;
  case PKTDL_NONE:
    return PPT_NONE;
  default:
    return PPT_INVALID;
  }
}


static uint32_t ppt_to_dltype(int ppt)
{
  switch(ppt) {
  case PPT_ETHERNET:
    return PKTDL_ETHERNET2;
  case PPT_NONE:
    return PKTDL_NONE;
  default:
    return PKTDL_INVALID;
  }
}


struct metapkt *metapkt_new(size_t plen, int ppt)
{
  struct metapkt *pkt;
  uint32_t dltype = ppt_to_dltype(ppt);
  if ( dltype == PKTDL_INVALID ) {
    errno = EINVAL;
    return NULL;
  }
  if ( !(pkt = newpmeta()) )
    return NULL;
  if ( pkt_create(&pkt->pkb, plen, dltype) < 0 ) {
    free(pkt);
    return NULL;
  }
  pkt->headers = hdr_create_parse(pkt->pkb->pkt_buffer, pkt->pkb->pkt_offset,
                                  pkt->pkb->pkt_buflen);
  if ( !pkt->headers ) {
    pkt_free(pkt->pkb);
    freepmeta(pkt);
    return NULL;
  }
  return pkt;
}


struct metapkt *pktbuf_to_metapkt(struct pktbuf *pkb)
{
  struct metapkt *pkt;
  struct hdr_parse *hdr;
  unsigned ppt;

  abort_unless(pkb);
  ppt = dltype_to_ppt(pkb->pkt_dltype);
  if ( !(pkt = newpmeta()) )
    return NULL;
  pkt->pkb = pkb;
  if ( ppt != PPT_INVALID )
    pkt->headers = hdr_parse_packet(ppt,pkb->pkt_buffer, pkb->pkt_offset, 
                                    pkb->pkt_len, pkb->pkt_buflen);
  else
    pkt->headers = hdr_create_parse(pkt->pkb->pkt_buffer, pkt->pkb->pkt_offset,
                                    pkt->pkb->pkt_buflen);
  if ( !pkt->headers ) {
    freepmeta(pkt);
    return NULL;
  }
  for ( hdr=hdr_child(pkt->headers); hdr->type != PPT_NONE; hdr=hdr_child(hdr) )
    metapkt_set_layer(pkt, hdr);
  return pkt;
}


static int get_hdr_index(struct metapkt *pkt, struct hdr_parse *hdr)
{
  int i = 0;
  struct hdr_parse *t;
  for ( t = hdr_child(pkt->headers); t->type != PPT_NONE; t= hdr_child(t) ) {
    ++i;
    if ( t == hdr )
      break;
  }
  abort_unless(t == hdr && i > 0);
  return i;
}


static struct hdr_parse *get_hdr_byindex(struct metapkt *pkt, int i)
{
  struct hdr_parse *t;
  abort_unless(i > 0);
  for ( t = hdr_child(pkt->headers); --i > 0; t = hdr_child(t) ) {
    abort_unless(t->type != PPT_NONE);
  }
  return t;
}


struct metapkt *metapkt_copy(struct metapkt *pkt)
{
  struct metapkt *pnew;
  int l;
  abort_unless(pkt && pkt->pkb && pkt->headers);
  if ( !(pnew = newpmeta()) )
    return NULL;
  if ( pkt_copy(pkt->pkb, &pnew->pkb) < 0 ) {
    freepmeta(pnew);
    return NULL;
  }
  if ( !(pnew->headers = hdr_copy(pkt->headers, pnew->pkb->pkt_buffer)) ) {
    pkt_free(pnew->pkb);
    freepmeta(pnew);
    return NULL;
  }
  for ( l = NETVM_HDI_LINK; l <= NETVM_HDI_MAX; ++l )
    if ( pkt->layer[l] )
      pnew->layer[l] = get_hdr_byindex(pnew, get_hdr_index(pkt, pkt->layer[l]));
  return pnew;
}


void metapkt_free(struct metapkt *pkt, int keepbuf)
{
  if ( pkt ) {
    l_rem(&pkt->entry);
    if ( pkt->headers ) {
      hdr_free(pkt->headers, 1);
      pkt->headers = NULL;
    }
    if ( pkt->pkb && !keepbuf )
      pkt_free(pkt->pkb);
    pkt->pkb = NULL;
    freepmeta(pkt);
  }
}


static int islink(int ppt)
{
  return ppt == PPT_ETHERNET;
}


static int isnet(int ppt)
{
  switch(ppt) {
  case PPT_IPV4:
  case PPT_IPV6:
  case PPT_ARP:
    return 1;
  default:
    return 0;
  }
  return (ppt == PPT_IPV4) || (ppt == PPT_IPV6) || (ppt == PPT_ARP); 
}


static int isxport(int ppt)
{
  switch(ppt) {
  case PPT_ICMP:
  case PPT_ICMP6:
  case PPT_UDP:
  case PPT_TCP:
    return 1;
  default:
    return 0;
  }
}


void metapkt_set_layer(struct metapkt *pkt, struct hdr_parse *h)
{
  if ( islink(h->type) ) {
    if ( !pkt->layer[NETVM_HDI_LINK] )
      pkt->layer[NETVM_HDI_LINK] = h;
  } else if ( isnet(h->type) ) {
    if ( !pkt->layer[NETVM_HDI_NET] )
      pkt->layer[NETVM_HDI_NET] = h;
  } else if ( isxport(h->type) ) {
    if ( !pkt->layer[NETVM_HDI_XPORT] )
      pkt->layer[NETVM_HDI_XPORT] = h;
  }
}


void metapkt_clr_layer(struct metapkt *pkt, int layer)
{
  abort_unless(layer >= 0 && layer <= NETVM_HDI_MAX);
  pkt->layer[layer] = NULL;
}


int metapkt_pushhdr(struct metapkt *pkt, int htype)
{
  if ( hdr_add(htype, hdr_parent(pkt->headers)) < 0 )
    return -1;
  metapkt_set_layer(pkt, hdr_parent(pkt->headers));
  return 0;
}


void metapkt_pophdr(struct metapkt *pkt)
{
  struct hdr_parse *last;
  int i;
  last = hdr_parent(pkt->headers);
  if ( last->type != PPT_NONE ) {
    for ( i = 0; i <= NETVM_HDI_MAX; ++i ) {
      if ( pkt->layer[i] == last ) {
        pkt->layer[i] = NULL;
        break;
      }
    }
    hdr_free(last, 0);
  }
}


void metapkt_fixdlt(struct metapkt *pkt)
{
  uint32_t dltype = PKTDL_NONE;
  if ( pkt->layer[NETVM_HDI_LINK] != NULL ) {
    dltype = ppt_to_dltype(pkt->layer[NETVM_HDI_LINK]->type);
    abort_unless(dltype != PKTDL_INVALID);
  }
  pkt->pkb->pkt_dltype = dltype;
}

