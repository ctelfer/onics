#include "config.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "pptcpip.h"
#include "util.h"
#include <cat/emalloc.h>
#include <cat/pack.h>
#include <string.h>
#include <stdlib.h>


extern struct prparse_ops none_prparse_ops;
extern struct prparse_ops eth_prparse_ops;
extern struct prparse_ops arp_prparse_ops;
extern struct prparse_ops ipv4_prparse_ops;
extern struct prparse_ops ipv6_prparse_ops;
extern struct prparse_ops icmp_prparse_ops;
extern struct prparse_ops icmpv6_prparse_ops;
extern struct prparse_ops udp_prparse_ops;
extern struct prparse_ops tcp_prparse_ops;


struct ipv6_parse {
  struct prparse        prp;
  uint8_t               nexth;
  size_t                jlenoff;
};


/* NB:  right now we are using emalloc() fpr header allocation, but we */
/* may not do that in the future.  When that happens, we need to change */
/* newprp, crtprp, and freeprp */
static struct prparse *newprp(size_t sz, unsigned type, 
                              struct prparse *pprp, struct prparse_ops *ops)
{
  struct prparse *prp;
  abort_unless(sz >= sizeof(struct prparse));
  prp = emalloc(sz);
  prp->size = sz;
  prp->type = type;
  prp->data = pprp->data;
  prp->error = 0;
  prp->hoff = pprp->poff;
  prp->poff = pprp->toff;
  prp->toff = prp->poff;
  prp->eoff = prp->poff;
  prp->ops = ops;
  /* all of the default protocol parsers nest layers within layers  */
  /* this won't be true for all protocol parsers */
  prp->region = pprp;
  l_ins(&pprp->node, &prp->node);
  return prp;
}

static struct prparse *crtprp(size_t sz, unsigned type, byte_t *buf,
                              size_t off, size_t hlen, size_t plen, 
                              size_t tlen, struct prparse_ops *ops)
{
  struct prparse *prp;
  abort_unless(sz >= sizeof(struct prparse));
  prp = emalloc(sz);
  prp->size = sz;
  prp->type = type;
  prp->data = buf;
  prp->error = 0;
  prp->hoff = off;
  prp->poff = off + hlen;
  prp->toff = prp->poff + plen;
  prp->eoff = prp->toff + tlen;
  prp->ops = ops;
  l_init(&prp->node);
  return prp;
}


static NETTOOLS_INLINE void freeprp(struct prparse *prp)
{
  free(prp);
}


static int default_follows(struct prparse *pprp) 
{
  return 0;
}


static struct prparse *default_parse(struct prparse *pprp)
{
  return NULL;
}


static struct prparse *default_create(byte_t *start, size_t off, size_t len,
                                        size_t poff, size_t plen, int mode)
{
  return NULL;
}


static void default_update(struct prparse *prp)
{
}


static size_t default_getfield(struct prparse *prp, unsigned fid, 
                               unsigned num, size_t *len)
{
  if ( len != NULL )
    *len = 0;
  return 0;
}


static int default_fixlen(struct prparse *prp)
{
  return 0;
}


static int default_fixcksum(struct prparse *prp)
{
  return 0;
}


static struct prparse *default_copy(struct prparse *oprp, byte_t *buffer)
{
  return NULL;
}


static void default_free(struct prparse *prp)
{
  /* presently unused */
  (void)default_create;
  (void)default_parse;
  (void)default_follows;
  (void)default_copy;
  freeprp(prp);
}


static struct prparse *simple_copy(struct prparse *oprp, byte_t *buffer)
{
  struct prparse *prp;
  if ( oprp == NULL )
    return NULL;
  prp = emalloc(oprp->size);
  memcpy(prp, oprp, oprp->size);
  prp->data = buffer;
  return prp;
}


/* -- ops for the "NONE" protocol type -- */
static int none_follows(struct prparse *pprp) 
{
  return 0;
}


static struct prparse *none_parse(struct prparse *pprp)
{
  struct prparse *prp;
  abort_unless(none_follows(pprp));
  return newprp(sizeof(*prp), PPT_NONE, pprp, &none_prparse_ops);
}


static struct prparse *none_create(byte_t *start, size_t off, size_t len,
                                   size_t hlen, size_t plen, int mode)
{
  struct prparse *prp;
  if ( mode != PPCF_FILL )
    return NULL;
  prp = crtprp(sizeof(struct prparse), PPT_NONE, start, off, 0,
               len, 0, &none_prparse_ops);
  return prp;
}

/* -- ops for Ethernet type -- */
static int eth_follows(struct prparse *pprp) 
{
  return 0;
}


static struct prparse *eth_parse(struct prparse *pprp)
{
  struct prparse *prp;

  switch(pprp->type) {
  case PPT_NONE:
    break;
  default:
    return NULL;
  }
  prp = newprp(sizeof(*prp), PPT_ETHERNET, pprp, &eth_prparse_ops);
  if ( !prp )
    return NULL;
  if ( prp_hlen(prp) < ETHHLEN ) { 
    prp->error = PPERR_TOOSMALL;
    prp->poff = prp->toff = prp->eoff = prp->hoff;
  } else {
    prp->poff = prp->hoff + ETHHLEN;
  }
  return prp;
}


static struct prparse *eth_create(byte_t *start, size_t off, size_t len,
                                  size_t hlen, size_t plen, int mode)
{
  struct prparse *prp;

  abort_unless(plen <= len && start);

  if ( mode == PPCF_FILL ) { 
    if ( len < ETHHLEN )
      return NULL;
    plen = len - ETHHLEN;
    hlen = ETHHLEN;
  } else if ( mode == PPCF_WRAP ) { 
    if ( hlen < ETHHLEN )
      return NULL;
    hlen = ETHHLEN;
    off -= ETHHLEN;
    len = plen + hlen;
  } else { 
    abort_unless(len - plen >= hlen);
    abort_unless(mode == PPCF_WRAPFILL);
    if ( hlen < ETHHLEN )
      return NULL;
  }
  prp = crtprp(sizeof(struct prparse), PPT_ETHERNET, start, off, hlen, 
               plen, 0, &eth_prparse_ops);
  if ( prp )
    memset(start + off, 0, ETHHLEN);

  return prp;
}


static void eth_update(struct prparse *prp)
{
  if ( prp_totlen(prp) < ETHHLEN ) {
    prp->error |= PPERR_TOOSMALL;
    return;
  }
  if ( prp_hlen(prp) != ETHHLEN )
    prp->error |= PPERR_HLEN;
}


/* -- ops for ARP type -- */
static int arp_follows(struct prparse *pprp) 
{
  ushort etype;
  if ( pprp->type != PPT_ETHERNET )
    return 0;
  unpack(&prp_header(pprp, struct eth2h)->ethtype, 2, "h", &etype);
  return etype == ETHTYPE_ARP;
}


static byte_t ethiparpstr[6] = { 0, 1, 8, 0, 6, 4 };

static struct prparse *arp_parse(struct prparse *pprp)
{
  struct prparse *prp;
  abort_unless(arp_follows(pprp));
  switch(pprp->type) {
  case PPT_ETHERNET:
    break;
  default:
    return NULL;
  }
  prp = newprp(sizeof(*prp), PPT_ARP, pprp, &arp_prparse_ops);
  if ( !prp )
    return NULL;
  if ( prp_hlen(prp) < 8 ) {
    prp->error = PPERR_TOOSMALL;
    prp->poff = prp->toff = prp->eoff = prp->hoff;
  } else { 
    prp->poff = prp->hoff + 8;
    /* check for short ether-ip ARP packet */
    if ( !(memcmp(ethiparpstr, prp_header(prp,void), sizeof(ethiparpstr)) ) &&
         (prp_plen(prp) < 20) )
      prp->error = PPERR_INVALID;
  }
  return prp;
}


static void arp_update(struct prparse *prp)
{
  if ( prp_totlen(prp) < 8 ) {
    prp->error |= PPERR_TOOSMALL;
    return;
  }
  prp->poff = prp->hoff + 8;
  if ( !(memcmp(ethiparpstr, prp_header(prp,void), sizeof(ethiparpstr)) ) &&
       (prp_plen(prp) < 20) )
    prp->error = PPERR_INVALID;
}


static size_t arp_getfield(struct prparse *prp, unsigned fid, 
                           unsigned num, size_t *len)
{
  if ( prp == NULL || fid != ARPFLD_ETHARP || num != 0 || prp_hlen(prp) == 0 ||
       prp_plen(prp) < 20 || 
       memcmp(prp_header(prp,void), ethiparpstr, 6) != 0 ) {
    if ( len != NULL )
      *len = 0;
    return 0;
  }
  if ( len != NULL )
    *len = 20;
  return prp->hoff;
}


static int arp_fixlen(struct prparse *prp)
{
  if ( prp_hlen(prp) < 8 )
    return -1;
  return 0;
}


static struct prparse *arp_create(byte_t *start, size_t off, size_t len,
                                  size_t hlen, size_t plen, int mode)
{
  struct prparse *prp;
  struct arph *arp;
  abort_unless(plen <= len && start);
  if ( (mode != PPCF_FILL) || (len < 8) )
    return NULL;
  prp = crtprp(sizeof(struct prparse), PPT_ARP, start, off, 8, len - 8, 0, 
               &arp_prparse_ops);
  if ( prp ) {
    memset(start + off, 0, prp_totlen(prp));
    if ( prp_plen(prp) >= 20 ) {
      prp->toff = prp->eoff = prp->poff + 28;
      arp = prp_header(prp, struct arph);
      pack(&arp, 8, "hhbbh", ARPT_ETHERNET, ETHTYPE_IP, 6, 4, ARPOP_REQUEST);
    }
  }
  return prp;
}


/* -- ops for IPV4 type -- */
static int ipv4_follows(struct prparse *pprp)
{
  ushort etype;
  if ( pprp->type == PPT_ETHERNET ) {
    unpack(&prp_header(pprp, struct eth2h)->ethtype, 2, "h", &etype);
    return (etype == ETHTYPE_IP) && (prp_plen(pprp) > 0);
  }
  if ( pprp->type == PPT_ICMP ) {
    struct icmph *icmp = prp_header(pprp, struct icmph);
    /* types which can have a returned IP header in them */
    return (icmp->type == ICMPT_DEST_UNREACH) ||
           (icmp->type == ICMPT_TIME_EXCEEDED) ||
           (icmp->type == ICMPT_PARAM_PROB) ||
           (icmp->type == ICMPT_SRC_QUENCH) ||
           (icmp->type == ICMPT_REDIRECT);
  }
  return 0;
}


static struct prparse *ipv4_parse(struct prparse *pprp)
{
  struct prparse *prp;
  struct ipv4h *ip;
  int hlen, tlen;
  ushort iplen;
  uint16_t sum;

  abort_unless(ipv4_follows(pprp));
  /* TODO: change size when we add provisions for option parsing */
  prp = newprp(sizeof(*prp), PPT_IPV4, pprp, &ipv4_prparse_ops);
  if ( !prp )
    return NULL;
  ip = prp_header(prp, struct ipv4h);
  hlen = IPH_HLEN(*ip);
  tlen = prp_totlen(prp);
  if ( tlen < 20 ) {
    prp->error |= PPERR_TOOSMALL;
    prp->poff = prp->toff = prp->eoff = prp->hoff;
  } else if ( hlen > tlen )  {
    prp->error |= PPERR_HLEN;
    prp->poff = prp->toff = prp->eoff = prp->hoff;
  } else {
    if ( (ip->vhl & 0xf0) != 0x40 )
      prp->error |= PPERR_INVALID;
    prp->poff = prp->hoff + hlen;
    unpack(&ip->len, 2, "h", &iplen);
    if ( iplen > prp_totlen(prp) )
      prp->error |= PPERR_LENGTH;
    else if ( iplen < prp_totlen(prp) )
      prp->toff = prp->hoff + iplen;
    sum = ~ones_sum(ip, hlen, 0);
    if ( sum != 0 ) {
        prp->error |= PPERR_CKSUM;
        return prp;
    }
    if ( ip->fragoff != 0 ) {
      uint16_t fragoff = ntoh32(ip->fragoff);
      if ( (uint32_t)IPH_FRAGOFF(fragoff) + iplen > 65535 )
        prp->error |= PPERR_INVALID;
      if ( (IPH_RFMASK & fragoff) )
        prp->error |= PPERR_INVALID;
    }
    if ( hlen > 20 ) { 
      /* TODO: parse IP options */
    }
  }
  return prp;
}


static struct prparse *ipv4_create(byte_t *start, size_t off, size_t len,
                                   size_t hlen, size_t plen, int mode)
{
  struct prparse *prp;
  struct ipv4h *ip;

  abort_unless(plen <= len && start);

  if ( mode == PPCF_FILL ) {
    if ( (len < 20) || (len > 65535) )
      return NULL;
    hlen = 20;
    plen = len - 20;
  } else if ( mode == PPCF_WRAP ) { 
    if ( hlen < 20 )
      return NULL;
    if ( plen > 65515 )
      plen = 65515;
    hlen = 20;
    off -= 20;
  } else { 
    abort_unless(mode == PPCF_WRAPFILL);
    if ( (hlen < 20) || (hlen > 60) || ((hlen & 0x3) != 0) || 
         (len != plen + hlen) || (len > 65535) )
      return NULL;
  }
  prp = crtprp(sizeof(struct prparse), PPT_IPV4, start, off, hlen, plen, 0, 
               &ipv4_prparse_ops);
  if ( prp ) {
    ip = prp_header(prp, struct ipv4h);
    memset(ip, 0, prp_hlen(prp));
    ip->vhl = 0x40 | (hlen >> 2);
    ip->len = hton16(prp_totlen(prp));
    /* TODO: fill options with noops if header > 20? */
  }
  return prp;
}


static void ipv4_update(struct prparse *prp)
{
  if ( prp_totlen(prp) < 20 ) {
    prp->error |= PPERR_TOOSMALL;
    return;
  }
  if ( prp_hlen(prp) < 20 ) {
    prp->error |= PPERR_HLEN;
    return;
  }
  /* TODO: parse options */
}


static size_t ipv4_getfield(struct prparse *prp, unsigned fid, 
                            unsigned num, size_t *len)
{
  if ( len != NULL )
    *len = 0;
  /* TODO: parse options */
  return 0;
}


static int ipv4_fixlen(struct prparse *prp)
{
  struct ipv4h *ip;
  size_t hlen;
  ushort tlen;
  abort_unless(prp && prp->data);
  ip = prp_header(prp, struct ipv4h);
  hlen = prp_hlen(prp);
  if ( (hlen < 20) || (hlen > 60) || (hlen > prp_totlen(prp)) )
    return -1;
  ip->vhl = 0x40 | (hlen >> 2);
  if ( prp->toff - prp->hoff > 65535 )
    return -1;
  tlen = prp->toff - prp->hoff;
  pack(&ip->len, 2, "h", tlen);
  return 0;
}


static int ipv4_fixcksum(struct prparse *prp)
{
  size_t hlen;
  struct ipv4h *ip;
  abort_unless(prp && prp->data);
  ip = prp_header(prp, struct ipv4h);
  hlen = IPH_HLEN(*ip);
  if ( hlen < 20 )
    return -1;
  ip->cksum = 0;
  ip->cksum = ~ones_sum(ip, IPH_HLEN(*ip), 0);
  return 0;
}


static struct prparse *ipv4_copy(struct prparse *oprp, byte_t *buffer)
{
  /* TODO; initialize option parsing */
  return simple_copy(oprp, buffer);
}


static void ipv4_free(struct prparse *prp)
{
  /* TODO: fix when option parsing is complete */
  freeprp(prp);
}


static uint16_t pseudo_cksum(struct prparse *prp, uint8_t proto)
{
  struct prparse *pprp = prp_prev(prp);
  uint16_t sum = 0;
  if ( pprp->type == PPT_IPV4 ) {
    struct pseudoh ph;
    struct ipv4h *ip = prp_header(pprp, struct ipv4h);
    memset(&ph, 0, sizeof(ph));
    ph.saddr = ip->saddr;
    ph.daddr = ip->daddr;
    ph.proto = proto;
    ph.totlen = ntoh16(prp_totlen(prp));
    sum = ones_sum(&ph, 12, 0);
  } else {
    struct pseudo6h ph;
    struct ipv6h *ip6 = prp_header(pprp, struct ipv6h);
    abort_unless(pprp->type == PPT_IPV6);
    memset(&ph, 0, sizeof(ph));
    ph.saddr = ip6->saddr;
    ph.daddr = ip6->daddr;
    ph.proto = proto;
    ph.totlen = ntoh32(prp_totlen(prp));
    sum = ones_sum(&ph, 40, 0);
  }
  return ~ones_sum(prp_header(prp, void), prp_totlen(prp), sum);
}


/* -- parse options for UDP protocol -- */
static int udp_follows(struct prparse *pprp) 
{
  if ( pprp->type == PPT_IPV4 ) {
    struct ipv4h *ip = prp_header(pprp, struct ipv4h);
    return ip->proto == IPPROT_UDP;
  } else if ( pprp->type == PPT_IPV6 ) {
    struct ipv6_parse *ip6prp = (struct ipv6_parse *)pprp;
    return ip6prp->nexth == IPPROT_UDP;
  } else {
    return 0;
  }
}


static struct prparse *udp_parse(struct prparse *pprp)
{
  struct prparse *prp;
  struct udph *udp;

  abort_unless(udp_follows(pprp));
  switch(pprp->type) {
  case PPT_IPV4:
  case PPT_IPV6:
    break;
  default:
    return NULL;
  }
  prp = newprp(sizeof(*prp), PPT_UDP, pprp, &udp_prparse_ops);
  if ( !prp )
    return NULL;
  if ( prp_hlen(prp) < 8 ) {
    prp->error |= PPERR_TOOSMALL;
    prp->poff = prp->toff = prp->eoff = prp->hoff;
  } else if ( (pprp->error & PPERR_LENGTH) ) {
    prp->poff = prp->hoff + 8;
    prp->error |= PPERR_LENGTH;
    prp->error |= PPERR_CKSUM;
  } else {
    prp->poff = prp->hoff + 8;
    udp = prp_header(prp, struct udph);
    if ( (udp->cksum != 0) && (pseudo_cksum(prp, IPPROT_UDP) != 0) )
      prp->error |= PPERR_CKSUM;
  }
  return prp;
}


static struct prparse *udp_create(byte_t *start, size_t off, size_t len,
                                    size_t hlen, size_t plen, int mode)
{
  struct prparse *prp;
  struct udph *udp;

  abort_unless(plen <= len && start);

  if ( mode == PPCF_FILL ) {
    if ( len < 8 )
      return NULL;
    hlen = 8;
    plen = len - 8;
    if ( plen > 65527 )
      return NULL;
  } else if ( mode == PPCF_WRAP ) { 
    if ( hlen < 8 )
      return NULL;
    hlen = 8;
    off -= 8;
    if ( plen > 65527 )
      plen = 65527;
  } else {
    abort_unless(mode == PPCF_WRAPFILL);
    if ( (hlen != 8) || (plen > 65527) || (len != hlen + plen) )
      return NULL;
  }
  prp = crtprp(sizeof(struct prparse), PPT_UDP, start, off, hlen, plen, 0,
               &udp_prparse_ops);
  if ( prp ) {
    udp = prp_header(prp, struct udph);
    memset(udp, 0, sizeof(*udp));
    pack(&udp->len, 2, "h", (ushort)prp_totlen(prp));
  }
  return prp;
}


static void udp_update(struct prparse *prp)
{
  if ( prp_totlen(prp) < 8 ) {
    prp->error = PPERR_TOOSMALL;
    return;
  }
  if ( prp_hlen(prp) < 8 ) {
    prp->error = PPERR_HLEN;
    return;
  }
}


static int udp_fixlen(struct prparse *prp)
{
  if ( prp_hlen(prp) != 8 )
    return -1;
  if ( prp_plen(prp) > 65527 )
    return -1;
  pack(&prp_header(prp, struct udph)->len, 2, "h", (ushort)prp_totlen(prp));
  return 0;
}


static int udp_fixcksum(struct prparse *prp)
{
  struct udph *udp = prp_header(prp, struct udph);
  if ( (prp_hlen(prp) != 8) || 
       ((prp_prev(prp)->type != PPT_IPV4) && 
        (prp_prev(prp)->type != PPT_IPV6)) )
    return -1;
  udp->cksum = 0;
  udp->cksum = pseudo_cksum(prp, IPPROT_UDP);
  return 0;
}


/* -- TCP functions -- */
static int tcp_follows(struct prparse *pprp)
{
  if ( (pprp->type != PPT_IPV4) && (pprp->type != PPT_IPV6) )
    return 0;

  switch(pprp->type) {
  case PPT_IPV4: {
    struct ipv4h *ip = prp_header(pprp, struct ipv4h);
    return ip->proto == IPPROT_TCP;
  } break;
  case PPT_IPV6: {
    struct ipv6_parse *ip6prp = (struct ipv6_parse *)pprp;
    return ip6prp->nexth == IPPROT_TCP;
  } break;
  }
  return 0;
}


static struct prparse *tcp_parse(struct prparse *pprp)
{
  struct prparse *prp;
  struct tcph *tcp;
  int hlen, tlen;

  abort_unless(tcp_follows(pprp));
  switch(pprp->type) {
  case PPT_IPV4:
  case PPT_IPV6:
    break;
  default:
    return NULL;
  }

  /* TODO: change size when we add provisions for option parsing */
  prp = newprp(sizeof(*prp), PPT_TCP, pprp, &tcp_prparse_ops);
  if ( !prp )
    return NULL;
  tcp = prp_header(prp, struct tcph);
  hlen = TCPH_HLEN(*tcp);
  tlen = prp_totlen(prp);
  if ( tlen < 20 ) {
    prp->error |= PPERR_TOOSMALL;
    prp->poff = prp->toff = prp->eoff = prp->hoff;
  } else if ( hlen > tlen )  {
    prp->error |= PPERR_HLEN;
    prp->poff = prp->toff = prp->eoff = prp->hoff;
  } else if ( (pprp->error & PPERR_LENGTH) ) {
    prp->poff = prp->hoff + hlen;
    prp->error |= PPERR_LENGTH;
    prp->error |= PPERR_CKSUM;
  } else {
    prp->poff = prp->hoff + hlen;
    if ( pseudo_cksum(prp, IPPROT_TCP) != 0 )
      prp->error |= PPERR_CKSUM;
    if ( hlen > 20 ) { 
      /* TODO: parse TCP options */
    }
  }
  return prp;
}


static struct prparse *tcp_create(byte_t *start, size_t off, size_t len,
                                    size_t hlen, size_t plen, int mode)
{
  struct prparse *prp;
  struct tcph *tcp;

  abort_unless(plen <= len && start);

  if ( mode == PPCF_FILL ) {
    if ( len < 20 )
      return NULL;
    hlen = 20;
    plen = len - 20;
  } else if ( mode == PPCF_WRAP ) { 
    if ( hlen < 20 )
      return NULL;
    hlen = 20;
    off -= 20;
    len = plen + hlen;
  } else { 
    abort_unless(mode == PPCF_WRAPFILL);
    if ( (hlen < 20) || (hlen > 60) || ((hlen & 3) != 0) ||
         (len != hlen + plen) )
      return NULL;
  }
  prp = crtprp(sizeof(struct prparse), PPT_TCP, start, off, hlen, plen, 0,
               &tcp_prparse_ops);
  if ( prp ) {
    memset(prp_header(prp, void), 0, prp_hlen(prp));
    tcp = prp_header(prp, struct tcph);
    tcp->doff = hlen << 2;
  }
  return prp;
}


static void tcp_update(struct prparse *prp)
{
  if ( prp_totlen(prp) < 20 ) {
    prp->error = PPERR_TOOSMALL;
    return;
  }
  if ( prp_hlen(prp) < 20 ) {
    prp->error = PPERR_HLEN;
    return;
  }
  /* TODO: parse options */
}


static size_t tcp_getfield(struct prparse *prp, unsigned fid, 
                           unsigned num, size_t *len)
{
  if ( len != NULL )
    *len = 0;
  /* TODO: parse options */
  return 0;
}


static int tcp_fixlen(struct prparse *prp)
{
  struct tcph *tcp;
  size_t hlen;
  abort_unless(prp && prp->data);
  tcp = prp_header(prp, struct tcph);
  hlen = prp_hlen(prp);
  if ( (hlen < 20) || (hlen > 60) || (hlen > prp_totlen(prp)) )
    return -1;
  tcp->doff = hlen << 2;
  return 0;
}


static int tcp_fixcksum(struct prparse *prp)
{
  struct tcph *tcp = prp_header(prp, struct tcph);
  if ( (prp_prev(prp)->type != PPT_IPV4) && 
       (prp_prev(prp)->type != PPT_IPV6) )
    return -1;
  tcp->cksum = 0;
  tcp->cksum = pseudo_cksum(prp, IPPROT_TCP);
  return 0;
}


static struct prparse *tcp_copy(struct prparse *oprp, byte_t *buffer)
{
  /* TODO; initialize option parsing */
  return simple_copy(oprp, buffer);
}


static void tcp_free(struct prparse *prp)
{
  /* TODO: fix when option parsing is complete */
  freeprp(prp);
}


/* -- ICMP Protocol functions -- */
static int icmp_follows(struct prparse *pprp) 
{
  return (pprp->type == PPT_IPV4) &&
         (prp_header(pprp, struct ipv4h)->proto == IPPROT_ICMP);
}


static struct prparse *icmp_parse(struct prparse *pprp)
{
  struct prparse *prp;
  struct icmph *icmp;

  abort_unless(icmp_follows(pprp));
  prp = newprp(sizeof(*prp), PPT_ICMP, pprp, &icmp_prparse_ops);
  if ( !prp )
    return NULL;
  if ( prp_totlen(prp) < 8 ) {
    prp->error |= PPERR_TOOSMALL;
    prp->poff = prp->toff = prp->eoff = prp->hoff;
  } else if ( (pprp->error & PPERR_LENGTH) ) {
    prp->poff = prp->hoff + 8;
    prp->error |= PPERR_LENGTH;
    prp->error |= PPERR_CKSUM;
  } else {
    prp->poff = prp->hoff + 8;
    icmp = prp_header(prp, struct icmph);
    if ( ~ones_sum(icmp, prp_totlen(prp), 0) )
      prp->error |= PPERR_CKSUM;
  }
  return prp;
}


static struct prparse *icmp_create(byte_t *start, size_t off, size_t len,
                                     size_t hlen, size_t plen, int mode)
{
  struct prparse *prp;
  struct icmph *icmp;

  abort_unless(plen <= len && start);

  if ( mode == PPCF_FILL ) {
    if ( len < 8 )
      return NULL;
    hlen = 8;
    plen = len - 8;
  } else if ( mode == PPCF_WRAP ) { 
    if ( hlen < 8 )
      return NULL;
    hlen = 8;
    off -= 8;
  } else { 
    abort_unless(mode == PPCF_WRAPFILL);
    if ( (hlen != 8) || (len != hlen + plen) )
      return NULL;
  }
  prp = crtprp(sizeof(struct prparse), PPT_ICMP, start, off, hlen, plen, 0,
               &icmp_prparse_ops);
  if ( prp ) {
    icmp = prp_header(prp, struct icmph);
    memset(icmp, 0, sizeof(*icmp));
  }
  return prp;
}


static void icmp_update(struct prparse *prp)
{
  if ( prp_totlen(prp) < 8 ) {
    prp->error = PPERR_TOOSMALL;
    return;
  }
  if ( prp_hlen(prp) < 8 ) {
    prp->error = PPERR_HLEN;
    return;
  }
  /* TODO: check by type? */
}


static int icmp_fixcksum(struct prparse *prp)
{
  struct icmph *icmp = prp_header(prp, struct icmph);
  if ( (prp_hlen(prp) != 8) || (prp_prev(prp)->type != PPT_IPV4) )
    return -1;
  icmp->cksum = 0;
  icmp->cksum = ~ones_sum(prp, prp_totlen(prp), 0);
  return 0;
}


/* -- IPv6 functions -- */

static int ipv6_follows(struct prparse *pprp)
{
  ushort etype;
  if ( pprp->type == PPT_ETHERNET ) {
    unpack(&prp_header(pprp, struct eth2h)->ethtype, 2, "h", &etype);
    return (etype == ETHTYPE_IPV6) && (prp_plen(pprp) > 0);
  }
  if ( pprp->type == PPT_ICMP6 ) {
    struct icmp6h *icmp6 = prp_header(pprp, struct icmp6h);
    return (icmp6->type == ICMP6T_DEST_UNREACH) ||
           (icmp6->type == ICMP6T_PKT_TOO_BIG) ||
           (icmp6->type == ICMP6T_TIME_EXCEEDED) ||
           (icmp6->type == ICMP6T_PARAM_PROB);
  }
  return 0;
}


static int isv6ext(uint8_t proto)
{
  /* we consider IPsec protocols their own protocol */
  return (proto == IPPROT_V6_HOPOPT) ||
         (proto == IPPROT_V6_ROUTE_HDR) || 
         (proto == IPPROT_V6_FRAG_HDR) || 
         (proto == IPPROT_V6_DSTOPS) || 
         (proto == IPPROT_AH);
}


/* search for jumbogram options */
static int parse_ipv6_hopopt(struct ipv6_parse *ip6prp, struct ipv6h *ip6,
                             byte_t *p, size_t olen)
{
  byte_t *end = p + olen;
  p += 2;
  while ( p < end ) { 
    if ( *p == 0 ) { /* pad1 option */
      ++p;
      continue;
    } 
    if ( p + p[1] + 2 > end ) { /* padn + all other options */
      ip6prp->prp.error |= PPERR_OPTLEN;
      return -1;
    }
    if ( *p == 0xC2 ) { /* jumbogram option */
      if ( (p[1] != 4) || (ip6->len != 0) || (ip6prp->jlenoff > 0) ||
           (((p - (byte_t *)ip6) & 3) != 2) ) {
        ip6prp->prp.error |= PPERR_OPTERR;
        return -1;
      }
      ip6prp->jlenoff = p - (byte_t *)ip6;
    }
    p += p[1] + 2;
  }
  return 0;
}


static int parse_ipv6_opt(struct ipv6_parse *ip6prp, struct ipv6h *ip6, 
                          size_t len)
{
  size_t xlen = 0;
  uint8_t nexth;
  uint olen;
  byte_t *p;

  nexth = ip6->nxthdr;
  p = (byte_t *)ip6 + 40;

  while ( isv6ext(nexth) ) {
    if ( (xlen + 8 < xlen) || (xlen + 8 > len) ) {
      ip6prp->prp.error |= PPERR_OPTLEN;
      return -1;
    }
    if ( nexth == IPPROT_AH ) /* AH is idiotic and useless */
      olen = (p[1] << 2) + 8;
    else
      olen = (p[1] << 3) + 8;
    if ( (xlen + olen < xlen) || (xlen + olen > len) ) {
      ip6prp->prp.error |= PPERR_OPTLEN;
      return -1;
    }
    /* hop-by-hop options can only come first */
    if ( nexth == IPPROT_V6_HOPOPT ) {
      if ( p != (byte_t *)ip6 + 40 ) {
        ip6prp->prp.error |= PPERR_OPTERR;
      } else {
        if ( parse_ipv6_hopopt(ip6prp, ip6, p, olen) < 0 )
          return -1;
      }
    }

    nexth = p[0];
    xlen += olen;
    p += olen;
  }

  ip6prp->prp.poff = ip6prp->prp.hoff + 40 + xlen;
  ip6prp->nexth = nexth;

  return 0;
}


static struct prparse *ipv6_parse(struct prparse *pprp)
{
  struct prparse *prp;
  struct ipv6_parse *ip6prp;
  struct ipv6h *ip6;
  ushort paylen;
  size_t tlen;

  abort_unless(ipv6_follows(pprp));
  prp = newprp(sizeof(struct ipv6_parse), PPT_IPV6, pprp, &ipv6_prparse_ops);
  ip6prp = (struct ipv6_parse *)prp;
  if ( !prp )
    return NULL;
  ip6prp->nexth = 0;
  ip6prp->jlenoff = 0;
  ip6 = prp_header(prp, struct ipv6h);

  if ( IPV6H_PVERSION(ip6) != 6 ) {
    prp->error |= PPERR_INVALID;
    goto done;
  }

  tlen = prp_totlen(prp);
  if ( tlen < 40 ) {
    prp->error |= PPERR_TOOSMALL;
    prp->poff = prp->toff = prp->eoff = prp->hoff;
    goto done;
  }

  unpack(&ip6->len, 2, "h", &paylen);
  if ( tlen < (uint32_t)paylen + 40 ) {
    prp->error |= PPERR_LENGTH;
  } 

  /* sets hlen */
  if ( parse_ipv6_opt(ip6prp, ip6, tlen - 40) < 0 )
    goto done;

  if ( (paylen == 0) && (ip6prp->jlenoff > 0) ) {
    unsigned long jlen;
    unpack(prp_payload(prp) + ip6prp->jlenoff, 4, "w", &jlen);
    if ( (jlen != prp_totlen(prp) - 40) || (jlen < 65536) )
      prp->error |= PPERR_LENGTH;
  } else if ( tlen > (uint32_t)paylen + 40 ) {
    prp->toff = prp->hoff + 40 + paylen;
  }

done:
  return prp;
}


static struct prparse *ipv6_create(byte_t *start, size_t off, size_t len,
                                     size_t hlen, size_t plen, int mode)
{
  struct prparse *prp;

  abort_unless(plen <= len && start);

  if ( mode == PPCF_FILL ) {
    /* TODO support jumbo frames ? */
    if ( (len < 40) || (len > 65575) )
      return NULL;
    hlen = 40;
    plen = len - 40;
  } else if ( mode == PPCF_WRAP ) { 
    if ( hlen < 40 )
      return NULL;
    if ( plen > 65535 )
      len = 65535;
    hlen = 40;
    off -= 40;
  } else { 
    abort_unless(mode == PPCF_WRAPFILL);
    if ( (hlen != 40) || (plen > 65535) || (hlen + plen != len) )
      return NULL;
  }
  prp = crtprp(sizeof(struct ipv6_parse), PPT_IPV6, start, off, hlen, plen, 0, 
               &ipv6_prparse_ops);
  if ( prp ) {
    struct ipv6_parse *ip6prp = (struct ipv6_parse *)prp;
    struct ipv6h *ip6 = prp_header(prp, struct ipv6h);
    ip6prp->nexth = 0;
    ip6prp->jlenoff = 0;
    memset(ip6, 0, prp_hlen(prp));
    *(byte_t*)ip6 = 0x60;
    ip6->len = hton16(prp_totlen(prp));
  }
  return prp;
}


static void ipv6_update(struct prparse *prp)
{
  if ( prp_totlen(prp) < 40 ) {
    prp->error = PPERR_TOOSMALL;
    return;
  }
  if ( prp_hlen(prp) < 40 ) {
    prp->error = PPERR_HLEN;
    return;
  }
  /* TODO: parse options */
}


static size_t ipv6_getfield(struct prparse *prp, unsigned fid, 
                            unsigned num, size_t *len)
{
  if ( len != NULL )
    *len = 0;
  /* TODO: options here */
  return 0;
}


static int ipv6_fixlen(struct prparse *prp)
{
  struct ipv6h *ip6;
  ushort plen;
  abort_unless(prp && prp->data);
  ip6 = prp_header(prp, struct ipv6h);
  if ( prp_plen(prp) > 65535 )
    return -1;
  plen = prp_plen(prp);
  pack(&ip6->len, 2, "h", plen);
  return 0;
}


static struct prparse *ipv6_copy(struct prparse *oprp, byte_t *buffer)
{
  /* TODO; initialize option parsing */
  return simple_copy(oprp, buffer);
}


static void ipv6_free(struct prparse *prp)
{
  /* TODO: fix when option parsing is complete */
  freeprp(prp);
}


/* -- ICMPv6 Functions -- */
static int icmp6_follows(struct prparse *pprp) 
{
  return (pprp->type == PPT_IPV6) &&
         (((struct ipv6_parse *)pprp)->nexth == IPPROT_ICMPV6);
}


static struct prparse *icmp6_parse(struct prparse *pprp)
{
  struct prparse *prp;

  prp = newprp(sizeof(*prp), PPT_ICMP6, pprp, &icmpv6_prparse_ops);
  if ( !prp )
    return NULL;
  if ( prp_totlen(prp) < 8 ) {
    prp->error |= PPERR_TOOSMALL;
    prp->poff = prp->toff = prp->eoff = prp->hoff;
  } else if ( (pprp->error & PPERR_LENGTH) ) {
    prp->poff = prp->hoff + 8;
    prp->error |= PPERR_LENGTH;
    prp->error |= PPERR_CKSUM;
  } else {
    abort_unless(pprp->type == PPT_IPV6);
    prp->poff = prp->hoff + 8;
    if ( pseudo_cksum(prp, IPPROT_ICMPV6) != 0 )
      prp->error |= PPERR_CKSUM;
  }
  return prp;
}


static struct prparse *icmp6_create(byte_t *start, size_t off, size_t len,
                                      size_t hlen, size_t plen, int mode)
{
  struct prparse *prp;
  struct icmp6h *icmp6;

  abort_unless(plen <= len && start);

  if ( mode == PPCF_FILL ) {
    if ( len < 8 )
      return NULL;
    hlen = 8;
    plen = len - 8;
  } else if ( mode == PPCF_WRAP ) { 
    if ( hlen < 8 )
      return NULL;
    hlen = 8;
    off -= 8;
  } else { 
    abort_unless(mode == PPCF_WRAPFILL);
    if ( (hlen != 8) || (len != hlen + plen) )
      return NULL;
  }
  prp = crtprp(sizeof(struct prparse), PPT_ICMP6, start, off, hlen, plen, 0,
               &icmpv6_prparse_ops);
  if ( prp ) {
    icmp6 = prp_header(prp, struct icmp6h);
    memset(icmp6, 0, sizeof(*icmp6));
  }
  return prp;
}


static void icmp6_update(struct prparse *prp)
{
  if ( prp_totlen(prp) < 8 ) {
    prp->error = PPERR_TOOSMALL;
    return;
  }
  if ( prp_hlen(prp) < 8 ) {
    prp->error = PPERR_HLEN;
    return;
  }
  /* TODO: check by type? */
}


static int icmp6_fixcksum(struct prparse *prp)
{
  struct icmp6h *icmp6 = prp_header(prp, struct icmp6h);
  if ( (prp_hlen(prp) != 8) || (prp_prev(prp)->type != PPT_IPV6) )
    return -1;
  icmp6->cksum = 0;
  icmp6->cksum = pseudo_cksum(prp, IPPROT_ICMPV6);
  return 0;
}


/* -- op structures for default initialization -- */
struct proto_parser_ops none_proto_parser_ops = {
  none_follows, 
  none_parse, 
  none_create
};
struct prparse_ops none_prparse_ops = {
  default_update,
  default_getfield,
  default_fixlen,
  default_fixcksum,
  simple_copy,
  default_free
};
struct proto_parser_ops eth_proto_parser_ops = {
  eth_follows,
  eth_parse,
  eth_create
};
struct prparse_ops eth_prparse_ops = {
  eth_update,
  default_getfield,
  default_fixlen,
  default_fixcksum,
  simple_copy,
  default_free
};
struct proto_parser_ops arp_proto_parser_ops = { 
  arp_follows,
  arp_parse,
  arp_create
};
struct prparse_ops arp_prparse_ops = {
  arp_update,
  arp_getfield,
  arp_fixlen,
  default_fixcksum,
  simple_copy,
  default_free
};
struct proto_parser_ops ipv4_proto_parser_ops = { 
  ipv4_follows,
  ipv4_parse,
  ipv4_create
};
struct prparse_ops ipv4_prparse_ops = {
  ipv4_update,
  ipv4_getfield,
  ipv4_fixlen,
  ipv4_fixcksum,
  ipv4_copy,
  ipv4_free
};
struct proto_parser_ops ipv6_proto_parser_ops = { 
  ipv6_follows,
  ipv6_parse,
  ipv6_create
};
struct prparse_ops ipv6_prparse_ops = {
  ipv6_update,
  ipv6_getfield,
  ipv6_fixlen,
  default_fixcksum,
  ipv6_copy,
  ipv6_free
};
struct proto_parser_ops icmp_proto_parser_ops = { 
  icmp_follows,
  icmp_parse,
  icmp_create
};
struct prparse_ops icmp_prparse_ops = {
  icmp_update,
  default_getfield,
  default_fixlen,
  icmp_fixcksum,
  simple_copy,
  default_free
};
struct proto_parser_ops icmpv6_proto_parser_ops = { 
  icmp6_follows,
  icmp6_parse,
  icmp6_create
};
struct prparse_ops icmpv6_prparse_ops = {
  icmp6_update,
  default_getfield,
  default_fixlen,
  icmp6_fixcksum,
  simple_copy,
  default_free
};
struct proto_parser_ops udp_proto_parser_ops = {
  udp_follows,
  udp_parse,
  udp_create
};
struct prparse_ops udp_prparse_ops = {
  udp_update,
  default_getfield,
  udp_fixlen,
  udp_fixcksum,
  simple_copy,
  default_free
};
struct proto_parser_ops tcp_proto_parser_ops = { 
  tcp_follows,
  tcp_parse,
  tcp_create
};
struct prparse_ops tcp_prparse_ops = {
  tcp_update,
  tcp_getfield,
  tcp_fixlen,
  tcp_fixcksum,
  tcp_copy,
  tcp_free
};
