#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "pptcpip.h"
#include "util.h"
#include <cat/emalloc.h>
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
                                size_t off, size_t hlen, size_t len, 
                                struct hparse_ops *ops)
{
  struct hdr_parse *hdr;
  if ( hlen > len )
    return NULL;
  abort_unless(sz >= sizeof(struct hdr_parse));
  hdr = emalloc(sz);
  hdr->size = sz;
  hdr->type = type;
  hdr->data = buf;
  hdr->error = 0;
  hdr->hoff = off;
  hdr->poff = off + hlen;
  hdr->toff = off + len;
  hdr->eoff = hdr->poff;
  hdr->ops = ops;
  l_init(&hdr->node);
  return hdr;
}


static int default_follows(struct hdr_parse *phdr) 
{
  return 0;
}


static struct hdr_parse *default_parse(struct hdr_parse *phdr)
{
  return NULL;
}


static struct hdr_parse *default_create(byte_t *start, size_t off, size_t len)
{
  return NULL;
}

static byte_t *default_getfield(struct hdr_parse *hdr, unsigned fid, int num,
                                size_t *len)
{
  return NULL;
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
  free(hdr);
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
  return (phdr->type == PPT_NONE) && (phdr->data != NULL) && 
         (hdr_plen(phdr) > 0);
}


static struct hdr_parse *none_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  abort_unless(none_follows(phdr));
  return newhdr(sizeof(*hdr), PPT_NONE, phdr, &none_hparse_ops);
}


static struct hdr_parse *none_create(byte_t *start, size_t off, size_t len)
{
  struct hdr_parse *hdr;
  hdr = crthdr(sizeof(struct hdr_parse), PPT_NONE, start, off, 0, len, 
               &none_hparse_ops);
  return hdr;
}

/* -- ops for Ethernet type -- */
static int eth_follows(struct hdr_parse *phdr) 
{
  return (phdr->type == PPT_NONE) && (phdr->data != NULL);
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
  if ( hdr_hlen(hdr) < ETHHLEN ) { 
    hdr->error = PPERR_TOOSMALL;
    hdr->poff = hdr->toff = hdr->eoff = hdr->hoff;
  } else {
    hdr->poff = hdr->hoff + ETHHLEN;
  }
  return hdr;
}


static struct hdr_parse *eth_create(byte_t *start, size_t off, size_t len)
{
  struct hdr_parse *hdr;
  if ( start == NULL || len < ETHHLEN )
    return NULL;
  hdr = crthdr(sizeof(struct hdr_parse), PPT_ETHERNET, start, off, ETHHLEN, len,
               &eth_hparse_ops);
  if ( hdr ) {
    memset(start + off, 0, ETHHLEN);
  }
  return hdr;
}


/* -- ops for ARP type -- */
static int arp_follows(struct hdr_parse *phdr) 
{
  uint16_t etype;
  if ( (phdr->type != PPT_ETHERNET) || (phdr->data == NULL) )
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


static byte_t *arp_getfield(struct hdr_parse *hdr, unsigned fid, int num,
                            size_t *len)
{
  if ( hdr == NULL || fid != ARPFLD_ETHARP || num != 0 || hdr_hlen(hdr) == 0 ||
       hdr_plen(hdr) < 20 || memcmp(hdr_header(hdr,void), ethiparpstr, 6) != 0 )
    return NULL;
  if ( len != NULL )
    *len = 20;
  return hdr_header(hdr, byte_t);
}


static int arp_fixlen(struct hdr_parse *hdr)
{
  if ( hdr_hlen(hdr) < 8 )
    return -1;
  return 0;
}


static struct hdr_parse *arp_create(byte_t *start, size_t off, size_t len)
{
  struct hdr_parse *hdr;
  struct arph *arp;
  if ( start == NULL || len < sizeof(*arp) )
    return NULL;
  hdr = crthdr(sizeof(struct hdr_parse), PPT_ARP, start, off, sizeof(*arp), len,
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
  uint16_t etype;
  if ( phdr->data == NULL )
    return 0;
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
  uint16_t iplen, sum;

  abort_unless(ipv4_follows(phdr));
  switch(phdr->type) {
  case PPT_ETHERNET:
  case PPT_ICMP:
    break;
  default:
    return NULL;
  }
  /* TODO: change size when we add provisions for option parsing */
  hdr = newhdr(sizeof(*hdr), PPT_IPV4, phdr, &ipv4_hparse_ops);
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
    if ( iplen < hdr_plen(hdr) )
      hdr->error |= PPERR_LENGTH;
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


static struct hdr_parse *ipv4_create(byte_t *start, size_t off, size_t len)
{
  struct hdr_parse *hdr;
  struct ipv4h *ip;
  if ( start == NULL || len < sizeof(*ip) )
    return NULL;
  if ( len > 65535 )
    len = 65535;
  hdr = crthdr(sizeof(struct hdr_parse), PPT_IPV4, start, off, sizeof(*ip), len,
               &ipv4_hparse_ops);
  if ( hdr ) {
    ip = hdr_header(hdr, struct ipv4h);
    memset(ip, 0, sizeof(*ip));
    ip->vhl = 0x45;
    ip->len = ntoh16(hdr_totlen(hdr));
  }
  return hdr;
}


static byte_t *ipv4_getfield(struct hdr_parse *hdr, unsigned fid, int num,
                             size_t *len)
{
  /* TODO: parse options */
  return NULL;
}


static int ipv4_fixlen(struct hdr_parse *hdr)
{
  struct ipv4h *ip;
  size_t hlen;
  uint16_t tlen;
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
  free(hdr);
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
    ph.totlen = hdr_totlen(hdr);
    sum = ones_sum(&ph, 12, 0);
  } else {
    abort_unless(phdr->type == PPT_IPV6);
    struct pseudo6h ph;
    struct ipv6h *ip6 = hdr_header(hdr, struct ipv6h);
    memset(&ph, 0, sizeof(ph));
    ph.saddr = ip6->saddr;
    ph.daddr = ip6->daddr;
    ph.proto = proto;
    ph.totlen = hdr_totlen(hdr);
    sum = ones_sum(&ph, 40, 0);
  }
  return ~ones_sum(hdr_payload(hdr), hdr_plen(hdr), sum);
}


/* -- parse options for UDP protocol -- */
static int udp_follows(struct hdr_parse *phdr) 
{
  if ( phdr->data == NULL )
    return 0;
  if ( phdr->type == PPT_IPV4 ) {
    struct ipv4h *ip = hdr_header(phdr, struct ipv4h);
    return ip->proto == IPPROT_UDP;
  } else if ( phdr->type == PPT_IPV6 ) {
    /* TODO: implement IPV6 next header finding */
    return 0;
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


static struct hdr_parse *udp_create(byte_t *start, size_t off, size_t len)
{
  struct hdr_parse *hdr;
  struct udph *udp;
  if ( start == NULL || len < sizeof(*udp) )
    return NULL;
  if ( len > 65535 ) 
    len = 65535;
  hdr = crthdr(sizeof(struct hdr_parse), PPT_UDP, start, off, sizeof(*udp), len,
               &udp_hparse_ops);
  if ( hdr ) {
    udp = hdr_header(hdr, struct udph);
    memset(udp, 0, sizeof(*udp));
    pack(&udp->len, 2, "h", (uint16_t)hdr_totlen(hdr));
  }
  return hdr;
}


static int udp_fixlen(struct hdr_parse *hdr)
{
  if ( hdr_hlen(hdr) != 8 )
    return -1;
  if ( hdr_plen(hdr) > 65527 )
    return -1;
  pack(&hdr_header(hdr, struct udph)->len, 2, "h", (uint16_t)hdr_totlen(hdr));
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
  if ( ((phdr->type != PPT_IPV4) && (phdr->type != PPT_IPV6)) || 
       (phdr->data == NULL) )
    return 0;

  switch(phdr->type) {
  case PPT_IPV4: {
    struct ipv4h *ip = hdr_header(phdr, struct ipv4h);
    return ip->proto == IPPROT_TCP;
  } break;
  case PPT_IPV6: {
    return 0; /* TODO */
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


static struct hdr_parse *tcp_create(byte_t *start, size_t off, size_t len)
{
  struct hdr_parse *hdr;
  struct tcph *tcp;
  if ( start == NULL || len < sizeof(*tcp) )
    return NULL;
  hdr = crthdr(sizeof(struct hdr_parse), PPT_TCP, start, off, sizeof(*tcp), len,
                &tcp_hparse_ops);
  if ( hdr ) {
    memset(hdr_header(hdr, void), 0, sizeof(*tcp));
    tcp = hdr_header(hdr, struct tcph);
    tcp->doff = 0x50;
  }
  return hdr;
}


static byte_t *tcp_getfield(struct hdr_parse *hdr, unsigned fid, int num,
                            size_t *len)
{
  /* TODO: parse options */
  return NULL;
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
  free(hdr);
}


/* -- ICMP Protocol functions -- */
static int icmp_follows(struct hdr_parse *phdr) 
{
  return (phdr->data != NULL) &&
         (phdr->type == PPT_IPV4) &&
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


static struct hdr_parse *icmp_create(byte_t *start, size_t off, size_t len)
{
  struct hdr_parse *hdr;
  struct icmph *icmp;
  if ( start == NULL || len < sizeof(*icmp) )
    return NULL;
  hdr = crthdr(sizeof(struct hdr_parse), PPT_ICMP, start, off, sizeof(*icmp), 
               len, &icmp_hparse_ops);
  if ( hdr ) {
    icmp = hdr_header(hdr, struct icmph);
    memset(icmp, 0, sizeof(*icmp));
  }
  return hdr;
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


/* -- op structures for default initialization -- */
struct pparse_ops none_pparse_ops = {
  none_follows, 
  none_parse, 
  none_create
};
struct hparse_ops none_hparse_ops = {
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
  ipv4_getfield,
  ipv4_fixlen,
  ipv4_fixcksum,
  ipv4_copy,
  ipv4_free
};
struct pparse_ops ipv6_pparse_ops = { 
  default_follows,
  default_parse,
  default_create
};
struct hparse_ops ipv6_hparse_ops = {
  default_getfield,
  default_fixlen,
  default_fixcksum,
  default_copy,
  default_free
};
struct pparse_ops icmp_pparse_ops = { 
  icmp_follows,
  icmp_parse,
  icmp_create
};
struct hparse_ops icmp_hparse_ops = {
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
  tcp_getfield,
  tcp_fixlen,
  tcp_fixcksum,
  tcp_copy,
  tcp_free
};
