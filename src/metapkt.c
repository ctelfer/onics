#include "metapkt.h"
#include <cat/emalloc.h>
#include <string.h>
#include <stdlib.h>


static unsigned pktdltype_to_ppt(uint32_t dltype)
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


static uint32_t ppt_to_pktdltype(int ppt)
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
  uint32_t dltype = ppt_to_pktdltype(ppt);
  if ( dltype == PKTDL_INVALID )
    return NULL;
  pkt = emalloc(sizeof(*pkt));
  memset(pkt, 0, sizeof(pkt));
  pkt_create(&pkt->pkb, plen, dltype);
  pkt->headers = hdr_create_parse(pkt->pkb->pkt_buffer, pkt->pkb->pkt_offset,
                                  pkt->pkb->pkt_buflen);
  return pkt;
}


struct metapkt *pktbuf_to_metapkt(struct pktbuf *pkb)
{
  struct metapkt *pkt;
  struct hdr_parse *hdr;
  unsigned ppt;

  abort_unless(pkb);
  ppt = pktdltype_to_ppt(pkb->pkt_dltype);
  pkt = emalloc(sizeof(*pkt));
  memset(pkt, 0, sizeof(*pkt));
  pkt->pkb = pkb;
  if ( ppt != PPT_INVALID )
    pkt->headers = hdr_parse_packet(ppt,pkb->pkt_buffer, pkb->pkt_offset, 
                                     pkb->pkt_len, pkb->pkt_buflen);
  else
    pkt->headers = hdr_create_parse(pkt->pkb->pkt_buffer, pkt->pkb->pkt_offset,
                                    pkt->pkb->pkt_buflen);
  abort_unless(pkt->headers);
  for ( hdr=hdr_child(pkt->headers); hdr->type != PPT_NONE; hdr=hdr_child(hdr) )
    metapkt_set_layer(pkt, hdr);
  return pkt;
}


struct metapkt *metapkt_copy(struct metapkt *pkt)
{
  struct metapkt *pnew;
  abort_unless(pkt && pkt->pkb && pkt->headers);
  pnew = emalloc(sizeof(*pnew));
  pkt_copy(pkt->pkb, &pnew->pkb);
  if ( !(pnew->headers = hdr_copy(pkt->headers, pnew->pkb->pkt_buffer)) ) {
    pkt_free(pnew->pkb);
    free(pnew);
    return NULL;
  }
  /* TODO: fix layers */
  return pnew;
}


void metapkt_free(struct metapkt *pkt, int keepbuf)
{
  if ( pkt ) {
    if ( pkt->headers ) {
      hdr_free(pkt->headers, 1);
      pkt->headers = NULL;
    }
    if ( pkt->pkb && !keepbuf )
      pkt_free(pkt->pkb);
    pkt->pkb = NULL;
    free(pkt);
  }
}


static int islink(int ppt)
{
  return ppt == PPT_ETHERNET;
}


static int istun(int ppt)
{
  return 0;
}


static int isnet(int ppt)
{
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
  } else if ( istun(h->type) ) {
    if ( !pkt->layer[NETVM_HDI_TUN] )
      pkt->layer[NETVM_HDI_TUN] = h;
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
  if ( hdr_parent(pkt->headers)->type != PPT_NONE ) {
    /* TODO: fix linklayer offset? */
  }
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


