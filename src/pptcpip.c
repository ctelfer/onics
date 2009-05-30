#include "config.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "pptcpip.h"
#include "util.h"
#include <cat/emalloc.h>
#include <cat/pack.h>
#include <string.h>
#include <stdlib.h>

extern struct hparse_ops none_hparse_ops;
extern struct hparse_ops eth_hparse_ops;
extern struct hparse_ops arp_hparse_ops;
extern struct hparse_ops ipv4_hparse_ops;
extern struct hparse_ops ipv6_hparse_ops;
extern struct hparse_ops icmp_hparse_ops;
extern struct hparse_ops icmpv6_hparse_ops;
extern struct hparse_ops udp_hparse_ops;
extern struct hparse_ops tcp_hparse_ops;


struct ipv6_parse {
  struct hdr_parse      hdr;
  uint8_t               nexth;
  size_t                jlenoff;
};


/* NB:  right now we are using emalloc() fpr header allocation, but we */
/* may not do that in the future.  When that happens, we need to change */
/* newhdr, crthdr, and freehdr */

static struct hdr_parse *newhdr(size_t sz, unsigned type, 
                                struct hdr_parse *phdr, struct hparse_ops *ops)
{
  struct hdr_parse *hdr;
  abort_unless(sz >= sizeof(struct hdr_parse));
  hdr = emalloc(sz);
  hdr->size = sz;
  hdr->type = type;
  hdr->data = phdr->data;
  hdr->error = 0;
  hdr->hoff = phdr->poff;
  hdr->poff = phdr->toff;
  hdr->toff = hdr->poff;
  hdr->eoff = hdr->poff;
  hdr->ops = ops;
  l_ins(&phdr->node, &hdr->node);
  return hdr;
}

static struct hdr_parse *crthdr(size_t sz, unsigned type, byte_t *buf,
                                size_t off, size_t hlen, size_t plen, 
                                size_t tlen, struct hparse_ops *ops)
{
  struct hdr_parse *hdr;
  abort_unless(sz >= sizeof(struct hdr_parse));
  hdr = emalloc(sz);
  hdr->size = sz;
  hdr->type = type;
  hdr->data = buf;
  hdr->error = 0;
  hdr->hoff = off;
  hdr->poff = off + hlen;
  hdr->toff = hdr->poff + plen;
  hdr->eoff = hdr->toff + tlen;
  hdr->ops = ops;
  l_init(&hdr->node);
  return hdr;
}


static NETTOOLS_INLINE void freehdr(struct hdr_parse *hdr)
{
  free(hdr);
}


static int default_follows(struct hdr_parse *phdr) 
{
  return 0;
}


static struct hdr_parse *default_parse(struct hdr_parse *phdr)
{
  return NULL;
}


static struct hdr_parse *default_create(byte_t *start, size_t off, size_t len,
                                        size_t poff, size_t plen, int mode)
{
  return NULL;
}


static void default_update(struct hdr_parse *hdr)
{
}


static size_t default_getfield(struct hdr_parse *hdr, unsigned fid, 
                               unsigned num, size_t *len)
{
  if ( len != NULL )
    *len = 0;
  return 0;
}


static int default_fixlen(struct hdr_parse *hdr)
{
  return 0;
}


static int default_fixcksum(struct hdr_parse *hdr)
{
  return 0;
}


static struct hdr_parse *default_copy(struct hdr_parse *ohdr, byte_t *buffer)
{
  return NULL;
}


static void default_free(struct hdr_parse *hdr)
{
  freehdr(hdr);
}


static struct hdr_parse *simple_copy(struct hdr_parse *ohdr, byte_t *buffer)
{
  struct hdr_parse *hdr;
  if ( ohdr == NULL )
    return NULL;
  hdr = emalloc(ohdr->size);
  memcpy(hdr, ohdr, ohdr->size);
  hdr->data = buffer;
  return hdr;
}


/* -- ops for the "NONE" protocol type -- */
static int none_follows(struct hdr_parse *phdr) 
{
  return (phdr->type == PPT_NONE) && (hdr_plen(phdr) > 0);
}


static struct hdr_parse *none_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  abort_unless(none_follows(phdr));
  return newhdr(sizeof(*hdr), PPT_NONE, phdr, &none_hparse_ops);
}


static struct hdr_parse *none_create(byte_t *start, size_t off, size_t len,
                                     size_t poff, size_t plen, int mode)
{
  struct hdr_parse *hdr;
  size_t hlen;
  abort_unless(poff >= off && plen <= len && poff + plen >= poff && off <= len 
               && start);
  if ( mode != PPCF_FILL )
    return NULL;
  hlen = poff - off;
  hdr = crthdr(sizeof(struct hdr_parse), PPT_NONE, start + off, 0, hlen,
               plen, len - plen - hlen, &none_hparse_ops);
  return hdr;
}

/* -- ops for Ethernet type -- */
static int eth_follows(struct hdr_parse *phdr) 
{
  return (phdr->type == PPT_NONE);
}


static struct hdr_parse *eth_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  abort_unless(eth_follows(phdr));
  switch(phdr->type) {
  case PPT_NONE:
    break;
  default:
    return NULL;
  }
  hdr = newhdr(sizeof(*hdr), PPT_ETHERNET, phdr, &eth_hparse_ops);
  if ( !hdr )
    return NULL;
  if ( hdr_hlen(hdr) < ETHHLEN ) { 
    hdr->error = PPERR_TOOSMALL;
    hdr->poff = hdr->toff = hdr->eoff = hdr->hoff;
  } else {
    hdr->poff = hdr->hoff + ETHHLEN;
  }
  return hdr;
}


static struct hdr_parse *eth_create(byte_t *start, size_t off, size_t len,
                                    size_t poff, size_t plen, int mode)
{
  struct hdr_parse *hdr;
  abort_unless(poff >= off && plen <= len && poff + plen >= poff && off <= len 
               && start);
  if ( mode == PPCF_FILL ) { 
    if ( len - off < ETHHLEN )
      return NULL;
    plen = len - off - ETHHLEN;
  } else if ( mode == PPCF_WRAP ) { 
    if ( poff - off < ETHHLEN )
      return NULL;
    off = poff - ETHHLEN;
  } else { 
    abort_unless(mode == PPCF_SET);
    if ( poff - off != ETHHLEN )
      return NULL;
  }
  hdr = crthdr(sizeof(struct hdr_parse), PPT_ETHERNET, start, off, ETHHLEN, 
               plen, 0, &eth_hparse_ops);
  if ( hdr ) {
    memset(start + off, 0, ETHHLEN);
  }
  return hdr;
}


static void eth_update(struct hdr_parse *hdr)
{
  if ( hdr_totlen(hdr) < ETHHLEN ) {
    hdr->error |= PPERR_TOOSMALL;
    return;
  }
  if ( hdr_hlen(hdr) != ETHHLEN )
    hdr->error |= PPERR_HLEN;
}


/* -- ops for ARP type -- */
static int arp_follows(struct hdr_parse *phdr) 
{
  ushort etype;
  if ( phdr->type != PPT_ETHERNET )
    return 0;
  unpack(&hdr_header(phdr, struct eth2h)->ethtype, 2, "h", &etype);
  return etype == ETHTYPE_ARP;
}


static byte_t ethiparpstr[6] = { 0, 1, 8, 0, 6, 4 };

static struct hdr_parse *arp_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  abort_unless(arp_follows(phdr));
  switch(phdr->type) {
  case PPT_ETHERNET:
    break;
  default:
    return NULL;
  }
  hdr = newhdr(sizeof(*hdr), PPT_ARP, phdr, &arp_hparse_ops);
  if ( !hdr )
    return NULL;
  if ( hdr_hlen(hdr) < 8 ) {
    hdr->error = PPERR_TOOSMALL;
    hdr->poff = hdr->toff = hdr->eoff = hdr->hoff;
  } else { 
    hdr->poff = hdr->hoff + 8;
    /* check for short ether-ip ARP packet */
    if ( !(memcmp(ethiparpstr, hdr_header(hdr,void), sizeof(ethiparpstr)) ) &&
         (hdr_plen(hdr) < 20) )
      hdr->error = PPERR_INVALID;
  }
  return hdr;
}


static void arp_update(struct hdr_parse *hdr)
{
  if ( hdr_totlen(hdr) < 8 ) {
    hdr->error |= PPERR_TOOSMALL;
    return;
  }
  hdr->poff = hdr->hoff + 8;
  if ( !(memcmp(ethiparpstr, hdr_header(hdr,void), sizeof(ethiparpstr)) ) &&
       (hdr_plen(hdr) < 20) )
    hdr->error = PPERR_INVALID;
}


static size_t arp_getfield(struct hdr_parse *hdr, unsigned fid, 
                           unsigned num, size_t *len)
{
  if ( hdr == NULL || fid != ARPFLD_ETHARP || num != 0 || hdr_hlen(hdr) == 0 ||
       hdr_plen(hdr) < 20 || 
       memcmp(hdr_header(hdr,void), ethiparpstr, 6) != 0 ) {
    if ( len != NULL )
      *len = 0;
    return 0;
  }
  if ( len != NULL )
    *len = 20;
  return hdr->hoff;
}


static int arp_fixlen(struct hdr_parse *hdr)
{
  if ( hdr_hlen(hdr) < 8 )
    return -1;
  return 0;
}


static struct hdr_parse *arp_create(byte_t *start, size_t off, size_t len,
                                    size_t poff, size_t plen, int mode)
{
  struct hdr_parse *hdr;
  struct arph *arp;
  abort_unless(poff >= off && plen <= len && poff + plen >= poff && off <= len 
               && start);
  if ( (mode != PPCF_FILL) || (len < 8) )
    return NULL;
  hdr = crthdr(sizeof(struct hdr_parse), PPT_ARP, start, off, 8, len - 8, 0, 
               &arp_hparse_ops);
  if ( hdr ) {
    memset(start + off, 0, hdr_totlen(hdr));
    if ( hdr_plen(hdr) >= 20 ) {
      hdr->toff = hdr->eoff = hdr->poff + 28;
      arp = hdr_header(hdr, struct arph);
      pack(&arp, 8, "hhbbh", ARPT_ETHERNET, ETHTYPE_IP, 6, 4, ARPOP_REQUEST);
    }
  }
  return hdr;
}


/* -- ops for IPV4 type -- */
static int ipv4_follows(struct hdr_parse *phdr)
{
  ushort etype;
  if ( phdr->type == PPT_ETHERNET ) {
    unpack(&hdr_header(phdr, struct eth2h)->ethtype, 2, "h", &etype);
    return (etype == ETHTYPE_IP) && (hdr_plen(phdr) > 0);
  }
  if ( phdr->type == PPT_ICMP ) {
    struct icmph *icmp = hdr_header(phdr, struct icmph);
    /* types which can have a returned IP header in them */
    return (icmp->type == ICMPT_DEST_UNREACH) ||
           (icmp->type == ICMPT_TIME_EXCEEDED) ||
           (icmp->type == ICMPT_PARAM_PROB) ||
           (icmp->type == ICMPT_SRC_QUENCH) ||
           (icmp->type == ICMPT_REDIRECT);
  }
  return 0;
}


static struct hdr_parse *ipv4_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  struct ipv4h *ip;
  int hlen, tlen;
  ushort iplen;
  uint16_t sum;

  abort_unless(ipv4_follows(phdr));
  /* TODO: change size when we add provisions for option parsing */
  hdr = newhdr(sizeof(*hdr), PPT_IPV4, phdr, &ipv4_hparse_ops);
  if ( !hdr )
    return NULL;
  ip = hdr_header(hdr, struct ipv4h);
  hlen = IPH_HLEN(*ip);
  tlen = hdr_totlen(hdr);
  if ( tlen < 20 ) {
    hdr->error |= PPERR_TOOSMALL;
    hdr->poff = hdr->toff = hdr->eoff = hdr->hoff;
  } else if ( hlen > tlen )  {
    hdr->error |= PPERR_HLEN;
    hdr->poff = hdr->toff = hdr->eoff = hdr->hoff;
  } else {
    if ( (ip->vhl & 0xf0) != 0x40 )
      hdr->error |= PPERR_INVALID;
    hdr->poff = hdr->hoff + hlen;
    unpack(&ip->len, 2, "h", &iplen);
    if ( iplen > hdr_totlen(hdr) )
      hdr->error |= PPERR_LENGTH;
    else if ( iplen < hdr_totlen(hdr) )
      hdr->toff = hdr->hoff + iplen;
    sum = ~ones_sum(ip, hlen, 0);
    if ( sum != 0 ) {
        hdr->error |= PPERR_CKSUM;
        return hdr;
    }
    if ( ip->fragoff != 0 ) {
      uint16_t fragoff = ntoh32(ip->fragoff);
      if ( (uint32_t)IPH_FRAGOFF(fragoff) + iplen > 65535 )
        hdr->error |= PPERR_INVALID;
      if ( (IPH_RFMASK & fragoff) )
        hdr->error |= PPERR_INVALID;
    }
    if ( hlen > 20 ) { 
      /* TODO: parse IP options */
    }
  }
  return hdr;
}


static struct hdr_parse *ipv4_create(byte_t *start, size_t off, size_t len,
                                     size_t poff, size_t plen, int mode)
{
  struct hdr_parse *hdr;
  struct ipv4h *ip;
  size_t hlen;
  abort_unless(poff >= off && plen <= len && poff + plen >= poff && off <= len 
               && start);
  if ( mode == PPCF_FILL ) {
    if ( (len - off < 20) || (len - off > 65535) )
      return NULL;
    hlen = 20;
    poff = off + hlen;
    plen = len - 20;
  } else if ( mode == PPCF_WRAP ) { 
    if ( poff - off < 20 )
      return NULL;
    if ( len - off > 65535 ) 
      len = off + 65535;
    hlen = 20;
    off = poff - 20;
  } else { 
    abort_unless(mode == PPCF_SET);
    hlen = poff - off;
    if ( (hlen < 20) || (hlen > 60) || (len - off > 65535) || 
         (poff + plen < len) )
      return NULL;
  }
  hdr = crthdr(sizeof(struct hdr_parse), PPT_IPV4, start, off, hlen, plen, 0, 
               &ipv4_hparse_ops);
  if ( hdr ) {
    ip = hdr_header(hdr, struct ipv4h);
    memset(ip, 0, hdr_hlen(hdr));
    ip->vhl = 0x40 | (hlen >> 2);
    ip->len = hton16(hdr_totlen(hdr));
    /* TODO: fill options with noops if header > 20? */
  }
  return hdr;
}


static void ipv4_update(struct hdr_parse *hdr)
{
  if ( hdr_totlen(hdr) < 20 ) {
    hdr->error |= PPERR_TOOSMALL;
    return;
  }
  if ( hdr_hlen(hdr) < 20 ) {
    hdr->error |= PPERR_HLEN;
    return;
  }
  /* TODO: parse options */
}


static size_t ipv4_getfield(struct hdr_parse *hdr, unsigned fid, 
                            unsigned num, size_t *len)
{
  if ( len != NULL )
    *len = 0;
  /* TODO: parse options */
  return 0;
}


static int ipv4_fixlen(struct hdr_parse *hdr)
{
  struct ipv4h *ip;
  size_t hlen;
  ushort tlen;
  abort_unless(hdr && hdr->data);
  ip = hdr_header(hdr, struct ipv4h);
  hlen = hdr_hlen(hdr);
  if ( (hlen < 20) || (hlen > 60) || (hlen > hdr_totlen(hdr)) )
    return -1;
  ip->vhl = 0x40 | (hlen >> 2);
  if ( hdr->toff - hdr->hoff > 65535 )
    return -1;
  tlen = hdr->toff - hdr->hoff;
  pack(&ip->len, 2, "h", tlen);
  return 0;
}


static int ipv4_fixcksum(struct hdr_parse *hdr)
{
  size_t hlen;
  struct ipv4h *ip;
  abort_unless(hdr && hdr->data);
  ip = hdr_header(hdr, struct ipv4h);
  hlen = IPH_HLEN(*ip);
  if ( hlen < 20 )
    return -1;
  ip->cksum = 0;
  ip->cksum = ~ones_sum(ip, IPH_HLEN(*ip), 0);
  return 0;
}


static struct hdr_parse *ipv4_copy(struct hdr_parse *ohdr, byte_t *buffer)
{
  /* TODO; initialize option parsing */
  return simple_copy(ohdr, buffer);
}


static void ipv4_free(struct hdr_parse *hdr)
{
  /* TODO: fix when option parsing is complete */
  freehdr(hdr);
}


static uint16_t tcpudp_cksum(struct hdr_parse *hdr, uint8_t proto)
{
  struct hdr_parse *phdr = hdr_parent(hdr);
  uint16_t sum = 0;
  if ( phdr->type == PPT_IPV4 ) {
    struct pseudoh ph;
    struct ipv4h *ip = hdr_header(phdr, struct ipv4h);
    memset(&ph, 0, sizeof(ph));
    ph.saddr = ip->saddr;
    ph.daddr = ip->daddr;
    ph.proto = proto;
    ph.totlen = ntoh16(hdr_totlen(hdr));
    sum = ones_sum(&ph, 12, 0);
  } else {
    abort_unless(phdr->type == PPT_IPV6);
    struct pseudo6h ph;
    struct ipv6h *ip6 = hdr_header(hdr, struct ipv6h);
    memset(&ph, 0, sizeof(ph));
    ph.saddr = ip6->saddr;
    ph.daddr = ip6->daddr;
    ph.proto = proto;
    ph.totlen = ntoh16(hdr_totlen(hdr));
    sum = ones_sum(&ph, 40, 0);
  }
  return ~ones_sum(hdr_header(hdr, void), hdr_totlen(hdr), sum);
}


/* -- parse options for UDP protocol -- */
static int udp_follows(struct hdr_parse *phdr) 
{
  if ( phdr->type == PPT_IPV4 ) {
    struct ipv4h *ip = hdr_header(phdr, struct ipv4h);
    return ip->proto == IPPROT_UDP;
  } else if ( phdr->type == PPT_IPV6 ) {
    struct ipv6_parse *ip6hdr = (struct ipv6_parse *)phdr;
    return ip6hdr->nexth == IPPROT_UDP;
  } else {
    return 0;
  }
}


static struct hdr_parse *udp_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  struct udph *udp;

  abort_unless(udp_follows(phdr));
  switch(phdr->type) {
  case PPT_IPV4:
  case PPT_IPV6:
    break;
  default:
    return NULL;
  }
  hdr = newhdr(sizeof(*hdr), PPT_UDP, phdr, &udp_hparse_ops);
  if ( !hdr )
    return NULL;
  if ( hdr_hlen(hdr) < 8 ) {
    hdr->error |= PPERR_TOOSMALL;
    hdr->poff = hdr->toff = hdr->eoff = hdr->hoff;
  } else if ( (phdr->error & PPERR_LENGTH) ) {
    hdr->poff = hdr->hoff + 8;
    hdr->error |= PPERR_LENGTH;
    hdr->error |= PPERR_CKSUM;
  } else {
    hdr->poff = hdr->hoff + 8;
    udp = hdr_header(hdr, struct udph);
    if ( (udp->cksum != 0) && (tcpudp_cksum(hdr, IPPROT_UDP) != 0) )
      hdr->error |= PPERR_CKSUM;
  }
  return hdr;
}


static struct hdr_parse *udp_create(byte_t *start, size_t off, size_t len,
                                    size_t poff, size_t plen, int mode)
{
  struct hdr_parse *hdr;
  struct udph *udp;
  abort_unless(poff >= off && plen <= len && poff + plen >= poff && off <= len 
               && start);
  if ( mode == PPCF_FILL ) {
    if ( len - off < 8 )
      return NULL;
    plen = len - off - 8;
    if ( plen > 65527 )
      return NULL;
  } else if ( mode == PPCF_WRAP ) { 
    if ( poff - off < 8 )
      return NULL;
    off = poff - 8;
    if ( plen > 65527 )
      plen = 65527;
  } else { 
    abort_unless(mode == PPCF_SET);
    if ( (poff - off != 8) || ( plen > 65527) )
      return NULL;
  }
  hdr = crthdr(sizeof(struct hdr_parse), PPT_UDP, start, off, 8, len - 8, 0,
               &udp_hparse_ops);
  if ( hdr ) {
    udp = hdr_header(hdr, struct udph);
    memset(udp, 0, sizeof(*udp));
    pack(&udp->len, 2, "h", (ushort)hdr_totlen(hdr));
  }
  return hdr;
}


static void udp_update(struct hdr_parse *hdr)
{
  if ( hdr_totlen(hdr) < 8 ) {
    hdr->error = PPERR_TOOSMALL;
    return;
  }
  if ( hdr_hlen(hdr) < 8 ) {
    hdr->error = PPERR_HLEN;
    return;
  }
}


static int udp_fixlen(struct hdr_parse *hdr)
{
  if ( hdr_hlen(hdr) != 8 )
    return -1;
  if ( hdr_plen(hdr) > 65527 )
    return -1;
  pack(&hdr_header(hdr, struct udph)->len, 2, "h", (ushort)hdr_totlen(hdr));
  return 0;
}


static int udp_fixcksum(struct hdr_parse *hdr)
{
  struct udph *udp = hdr_header(hdr, struct udph);
  if ( (hdr_hlen(hdr) != 8) || 
       ((hdr_parent(hdr)->type != PPT_IPV4) && 
        (hdr_parent(hdr)->type != PPT_IPV6)) )
    return -1;
  udp->cksum = 0;
  udp->cksum = tcpudp_cksum(hdr, IPPROT_UDP);
  return 0;
}


/* -- TCP functions -- */
static int tcp_follows(struct hdr_parse *phdr)
{
  if ( (phdr->type != PPT_IPV4) && (phdr->type != PPT_IPV6) )
    return 0;

  switch(phdr->type) {
  case PPT_IPV4: {
    struct ipv4h *ip = hdr_header(phdr, struct ipv4h);
    return ip->proto == IPPROT_TCP;
  } break;
  case PPT_IPV6: {
    struct ipv6_parse *ip6hdr = (struct ipv6_parse *)phdr;
    return ip6hdr->nexth == IPPROT_TCP;
  } break;
  }
  return 0;
}


static struct hdr_parse *tcp_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  struct tcph *tcp;
  int hlen, tlen;

  abort_unless(tcp_follows(phdr));
  switch(phdr->type) {
  case PPT_IPV4:
  case PPT_IPV6:
    break;
  default:
    return NULL;
  }

  /* TODO: change size when we add provisions for option parsing */
  hdr = newhdr(sizeof(*hdr), PPT_TCP, phdr, &tcp_hparse_ops);
  if ( !hdr )
    return NULL;
  tcp = hdr_header(hdr, struct tcph);
  hlen = TCPH_HLEN(*tcp);
  tlen = hdr_totlen(hdr);
  if ( tlen < 20 ) {
    hdr->error |= PPERR_TOOSMALL;
    hdr->poff = hdr->toff = hdr->eoff = hdr->hoff;
  } else if ( hlen > tlen )  {
    hdr->error |= PPERR_HLEN;
    hdr->poff = hdr->toff = hdr->eoff = hdr->hoff;
  } else if ( (phdr->error & PPERR_LENGTH) ) {
    hdr->poff = hdr->hoff + hlen;
    hdr->error |= PPERR_LENGTH;
    hdr->error |= PPERR_CKSUM;
  } else {
    hdr->poff = hdr->hoff + hlen;
    if ( tcpudp_cksum(hdr, IPPROT_TCP) != 0 )
      hdr->error |= PPERR_CKSUM;
    if ( hlen > 20 ) { 
      /* TODO: parse TCP options */
    }
  }
  return hdr;
}


static struct hdr_parse *tcp_create(byte_t *start, size_t off, size_t len,
                                    size_t poff, size_t plen, int mode)
{
  struct hdr_parse *hdr;
  struct tcph *tcp;
  size_t hlen;
  abort_unless(poff >= off && plen <= len && poff + plen >= poff && off <= len 
               && start);
  if ( mode == PPCF_FILL ) {
    if ( len - off < 20 )
      return NULL;
    hlen = 20;
    poff = off + hlen;
    plen = len - 20;
  } else if ( mode == PPCF_WRAP ) { 
    if ( poff - off < 20 )
      return NULL;
    hlen = 20;
    off = poff - 20;
  } else { 
    abort_unless(mode == PPCF_SET);
    hlen = poff - off;
    if ( (hlen < 20) || (hlen > 60) || (poff + plen < len) )
      return NULL;
  }
  hdr = crthdr(sizeof(struct hdr_parse), PPT_TCP, start, off, hlen, plen, 0,
               &tcp_hparse_ops);
  if ( hdr ) {
    memset(hdr_header(hdr, void), 0, hdr_hlen(hdr));
    tcp = hdr_header(hdr, struct tcph);
    tcp->doff = hlen << 2;
  }
  return hdr;
}


static void tcp_update(struct hdr_parse *hdr)
{
  if ( hdr_totlen(hdr) < 20 ) {
    hdr->error = PPERR_TOOSMALL;
    return;
  }
  if ( hdr_hlen(hdr) < 20 ) {
    hdr->error = PPERR_HLEN;
    return;
  }
  /* TODO: parse options */
}


static size_t tcp_getfield(struct hdr_parse *hdr, unsigned fid, 
                           unsigned num, size_t *len)
{
  if ( len != NULL )
    *len = 0;
  /* TODO: parse options */
  return 0;
}


static int tcp_fixlen(struct hdr_parse *hdr)
{
  struct tcph *tcp;
  size_t hlen;
  abort_unless(hdr && hdr->data);
  tcp = hdr_header(hdr, struct tcph);
  hlen = hdr_hlen(hdr);
  if ( (hlen < 20) || (hlen > 60) || (hlen > hdr_totlen(hdr)) )
    return -1;
  tcp->doff = hlen << 2;
  return 0;
}


static int tcp_fixcksum(struct hdr_parse *hdr)
{
  struct tcph *tcp = hdr_header(hdr, struct tcph);
  if ( (hdr_parent(hdr)->type != PPT_IPV4) && 
       (hdr_parent(hdr)->type != PPT_IPV6) )
    return -1;
  tcp->cksum = 0;
  tcp->cksum = tcpudp_cksum(hdr, IPPROT_TCP);
  return 0;
}


static struct hdr_parse *tcp_copy(struct hdr_parse *ohdr, byte_t *buffer)
{
  /* TODO; initialize option parsing */
  return simple_copy(ohdr, buffer);
}


static void tcp_free(struct hdr_parse *hdr)
{
  /* TODO: fix when option parsing is complete */
  freehdr(hdr);
}


/* -- ICMP Protocol functions -- */
static int icmp_follows(struct hdr_parse *phdr) 
{
  return (phdr->type == PPT_IPV4) &&
         (hdr_header(phdr, struct ipv4h)->proto == IPPROT_ICMP);
}


static struct hdr_parse *icmp_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  struct icmph *icmp;

  abort_unless(icmp_follows(phdr));
  switch(phdr->type) {
  case PPT_IPV4:
    break;
  default:
    return NULL;
  }
  hdr = newhdr(sizeof(*hdr), PPT_ICMP, phdr, &icmp_hparse_ops);
  if ( !hdr )
    return NULL;
  if ( hdr_hlen(hdr) < 8 ) {
    hdr->error |= PPERR_TOOSMALL;
    hdr->poff = hdr->toff = hdr->eoff = hdr->hoff;
  } else if ( (phdr->error & PPERR_LENGTH) ) {
    hdr->poff = hdr->hoff + 8;
    hdr->error |= PPERR_LENGTH;
    hdr->error |= PPERR_CKSUM;
  } else {
    hdr->poff = hdr->hoff + 8;
    icmp = hdr_header(hdr, struct icmph);
    if ( ~ones_sum(icmp, hdr_totlen(hdr), 0) )
      hdr->error |= PPERR_CKSUM;
  }
  return hdr;
}


static struct hdr_parse *icmp_create(byte_t *start, size_t off, size_t len,
                                     size_t poff, size_t plen, int mode)
{
  struct hdr_parse *hdr;
  struct icmph *icmp;
  abort_unless(poff >= off && plen <= len && poff + plen >= poff && off <= len 
               && start);
  if ( mode == PPCF_FILL ) {
    if ( len - off < 8 )
      return NULL;
    plen = len - off - 8;
  } else if ( mode == PPCF_WRAP ) { 
    if ( poff - off < 8 )
      return NULL;
    off = poff - 8;
  } else { 
    abort_unless(mode == PPCF_SET);
    if ( (poff - off != 8) )
      return NULL;
  }
  hdr = crthdr(sizeof(struct hdr_parse), PPT_ICMP, start, off, 8, plen, 0,
               &icmp_hparse_ops);
  if ( hdr ) {
    icmp = hdr_header(hdr, struct icmph);
    memset(icmp, 0, sizeof(*icmp));
  }
  return hdr;
}


static void icmp_update(struct hdr_parse *hdr)
{
  if ( hdr_totlen(hdr) < 8 ) {
    hdr->error = PPERR_TOOSMALL;
    return;
  }
  if ( hdr_hlen(hdr) < 8 ) {
    hdr->error = PPERR_HLEN;
    return;
  }
  /* TODO: check by type? */
}


static int icmp_fixcksum(struct hdr_parse *hdr)
{
  struct icmph *icmp = hdr_header(hdr, struct icmph);
  if ( (hdr_hlen(hdr) != 8) || (hdr_parent(hdr)->type != PPT_IPV4) )
    return -1;
  icmp->cksum = 0;
  icmp->cksum = ~ones_sum(hdr, hdr_totlen(hdr), 0);
  return 0;
}


/* -- IPv6 functions -- */

static int ipv6_follows(struct hdr_parse *phdr)
{
  ushort etype;
  if ( phdr->type == PPT_ETHERNET ) {
    unpack(&hdr_header(phdr, struct eth2h)->ethtype, 2, "h", &etype);
    return (etype == ETHTYPE_IPV6) && (hdr_plen(phdr) > 0);
  }
  if ( phdr->type == PPT_ICMP6 ) {
    struct icmp6h *icmp6 = hdr_header(phdr, struct icmp6h);
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
         (proto == IPPROT_V6_DSTOPS);
}


/* search for jumbogram options */
static int parse_ipv6_hopopt(struct ipv6_parse *ip6hdr, struct ipv6h *ip6,
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
      ip6hdr->hdr.error |= PPERR_OPTLEN;
      return -1;
    }
    if ( *p == 0xC2 ) { /* jumbogram option */
      if ( (p[1] != 4) || (ip6->len != 0) ) {
        ip6hdr->hdr.error |= PPERR_OPTERR;
        return -1;
      }
      ip6hdr->jlenoff = p - (byte_t *)ip6;
    }
    p += p[1] + 2;
  }
  return 0;
}


static int parse_ipv6_opt(struct ipv6_parse *ip6hdr, struct ipv6h *ip6, 
                          size_t len)
{
  size_t xlen = 0;
  uint8_t nexth;
  uint olen;
  byte_t *p;

  if ( !isv6ext(ip6->nxthdr) ) {
    ip6hdr->hdr.poff = ip6hdr->hdr.hoff + 40;
    ip6hdr->nexth = ip6->nxthdr;
    return 0;
  }
  p = (byte_t *)ip6 + 40;
  do {
    if ( (xlen + 8 < xlen) || (xlen + 8 > len) ) {
      ip6hdr->hdr.error |= PPERR_OPTLEN;
      return -1;
    }
    nexth = p[0];
    olen = (p[1] << 3) + 8;
    if ( (xlen + olen < xlen) || (xlen + olen > len) ) {
      ip6hdr->hdr.error |= PPERR_OPTLEN;
      return -1;
    }
    /* hop-by-hop options can only come first */
    if ( nexth == IPPROT_V6_HOPOPT ) {
      if ( p != (byte_t *)ip6 + 40 ) {
        ip6hdr->hdr.error |= PPERR_OPTERR;
      } else {
        if ( parse_ipv6_hopopt(ip6hdr, ip6, p, olen) < 0 )
          return -1;
      }
    }

    xlen += olen;
    p += olen;
  } while (isv6ext(nexth));

  return 0;
}


static struct hdr_parse *ipv6_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  struct ipv6_parse *ip6hdr;
  struct ipv6h *ip6;
  ushort paylen;
  size_t tlen;

  abort_unless(ipv6_follows(phdr));
  hdr = newhdr(sizeof(struct ipv6_parse), PPT_IPV6, phdr, &ipv6_hparse_ops);
  ip6hdr = (struct ipv6_parse *)hdr;
  if ( !hdr )
    return NULL;
  ip6hdr->nexth = 0;
  ip6hdr->jlenoff = 0;
  ip6 = hdr_header(hdr, struct ipv6h);

  if ( IPV6H_PVERSION(ip6) != 6 ) {
    hdr->error |= PPERR_INVALID;
    goto done;
  }

  tlen = hdr_totlen(hdr);
  if ( tlen < 40 ) {
    hdr->error |= PPERR_TOOSMALL;
    hdr->poff = hdr->toff = hdr->eoff = hdr->hoff;
    goto done;
  }

  unpack(&ip6->len, 2, "h", &paylen);
  if ( tlen < (uint32_t)paylen + 40 ) {
    hdr->error |= PPERR_LENGTH;
  } 

  /* sets hlen */
  if ( parse_ipv6_opt(ip6hdr, ip6, tlen - 40) < 0 )
    goto done;

  if ( (paylen == 0) && (ip6hdr->jlenoff > 0) ) {
    unsigned long jlen;
    unpack(hdr_payload(hdr) + ip6hdr->jlenoff, 4, "w", &jlen);
    if ( (jlen != hdr_totlen(hdr) - 40) || (jlen < 65536) )
      hdr->error |= PPERR_LENGTH;
  } else if ( tlen > (uint32_t)paylen + 40 ) {
    hdr->toff = hdr->hoff + 40 + paylen;
  }

done:
  return hdr;
}


static struct hdr_parse *ipv6_create(byte_t *start, size_t off, size_t len,
                                     size_t poff, size_t plen, int mode)
{
  abort_unless(poff >= off && plen <= len && poff + plen >= poff && off <= len 
               && start);
  struct hdr_parse *hdr;
  size_t hlen;
  if ( mode == PPCF_FILL ) {
    /* TODO support jumbo frames ? */
    if ( (len - off < 40) || (len - off > 65575) )
      return NULL;
    hlen = 40;
    poff = off + hlen;
    plen = len - 40;
  } else if ( mode == PPCF_WRAP ) { 
    if ( poff - off < 40 )
      return NULL;
    if ( len - off > 65575 )
      len = off + 65575;
    hlen = 40;
    off = poff - 40;
  } else { 
    abort_unless(mode == PPCF_SET);
    hlen = poff - off;
    if ( (hlen != 40) || (len - off > 65575) || (poff + plen < len) )
      return NULL;
  }
  hdr = crthdr(sizeof(struct ipv6_parse), PPT_IPV6, start, off, hlen, plen, 0, 
               &ipv6_hparse_ops);
  if ( hdr ) {
    struct ipv6_parse *ip6hdr = (struct ipv6_parse *)hdr;
    struct ipv6h *ip6 = hdr_header(hdr, struct ipv6h);
    ip6hdr->nexth = 0; /* TODO: fill in if we are WRAP or SET */
    ip6hdr->jlenoff = 0;
    memset(ip6, 0, 40);
    *(byte_t*)ip6 = 0x60;
    ip6->len = hton16(hdr_totlen(hdr));
  }
  return hdr;
}


static void ipv6_update(struct hdr_parse *hdr)
{
  if ( hdr_totlen(hdr) < 40 ) {
    hdr->error = PPERR_TOOSMALL;
    return;
  }
  if ( hdr_hlen(hdr) < 40 ) {
    hdr->error = PPERR_HLEN;
    return;
  }
  /* TODO: parse options */
}


static size_t ipv6_getfield(struct hdr_parse *hdr, unsigned fid, 
                            unsigned num, size_t *len)
{
  if ( len != NULL )
    *len = 0;
  /* TODO: options here */
  return 0;
}


static int ipv6_fixlen(struct hdr_parse *hdr)
{
  struct ipv6h *ip6;
  ushort plen;
  abort_unless(hdr && hdr->data);
  ip6 = hdr_header(hdr, struct ipv6h);
  if ( hdr_plen(hdr) > 65535 )
    return -1;
  plen = hdr_plen(hdr);
  pack(&ip6->len, 2, "h", plen);
  return 0;
}


static struct hdr_parse *ipv6_copy(struct hdr_parse *ohdr, byte_t *buffer)
{
  /* TODO; initialize option parsing */
  return simple_copy(ohdr, buffer);
}


static void ipv6_free(struct hdr_parse *hdr)
{
  /* TODO: fix when option parsing is complete */
  freehdr(hdr);
}


/* -- op structures for default initialization -- */
struct pparse_ops none_pparse_ops = {
  none_follows, 
  none_parse, 
  none_create
};
struct hparse_ops none_hparse_ops = {
  default_update,
  default_getfield,
  default_fixlen,
  default_fixcksum,
  simple_copy,
  default_free
};
struct pparse_ops eth_pparse_ops = {
  eth_follows,
  eth_parse,
  eth_create
};
struct hparse_ops eth_hparse_ops = {
  eth_update,
  default_getfield,
  default_fixlen,
  default_fixcksum,
  simple_copy,
  default_free
};
struct pparse_ops arp_pparse_ops = { 
  arp_follows,
  arp_parse,
  arp_create
};
struct hparse_ops arp_hparse_ops = {
  arp_update,
  arp_getfield,
  arp_fixlen,
  default_fixcksum,
  simple_copy,
  default_free
};
struct pparse_ops ipv4_pparse_ops = { 
  ipv4_follows,
  ipv4_parse,
  ipv4_create
};
struct hparse_ops ipv4_hparse_ops = {
  ipv4_update,
  ipv4_getfield,
  ipv4_fixlen,
  ipv4_fixcksum,
  ipv4_copy,
  ipv4_free
};
struct pparse_ops ipv6_pparse_ops = { 
  ipv6_follows,
  ipv6_parse,
  ipv6_create
};
struct hparse_ops ipv6_hparse_ops = {
  ipv6_update,
  ipv6_getfield,
  ipv6_fixlen,
  default_fixcksum,
  ipv6_copy,
  ipv6_free
};
struct pparse_ops icmp_pparse_ops = { 
  icmp_follows,
  icmp_parse,
  icmp_create
};
struct hparse_ops icmp_hparse_ops = {
  icmp_update,
  default_getfield,
  default_fixlen,
  icmp_fixcksum,
  simple_copy,
  default_free
};
struct pparse_ops icmpv6_pparse_ops = { 
  default_follows,
  default_parse,
  default_create
};
struct hparse_ops icmpv6_hparse_ops = {
  default_update,
  default_getfield,
  default_fixlen,
  default_fixcksum,
  default_copy,
  default_free
};
struct pparse_ops udp_pparse_ops = {
  udp_follows,
  udp_parse,
  udp_create
};
struct hparse_ops udp_hparse_ops = {
  udp_update,
  default_getfield,
  udp_fixlen,
  udp_fixcksum,
  simple_copy,
  default_free
};
struct pparse_ops tcp_pparse_ops = { 
  tcp_follows,
  tcp_parse,
  tcp_create
};
struct hparse_ops tcp_hparse_ops = {
  tcp_update,
  tcp_getfield,
  tcp_fixlen,
  tcp_fixcksum,
  tcp_copy,
  tcp_free
};
