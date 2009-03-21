#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "pptcpip.h"
#include "util.h"
#include <cat/emalloc.h>
#include <string.h>

extern struct hparse_ops none_hparse_ops;
extern struct hparse_ops eth_hparse_ops;
extern struct hparse_ops arp_hparse_ops;
extern struct hparse_ops ipv4_hparse_ops;
extern struct hparse_ops ipv6_hparse_ops;
extern struct hparse_ops icmp_hparse_ops;
extern struct hparse_ops icmpv6_hparse_ops;
extern struct hparse_ops udp_hparse_ops;
extern struct hparse_ops tcp_hparse_ops;

/* copy from here
static int _follows(struct hdr_parse *phdr) { return 0; }

static struct hdr_parse *_parse(struct hdr_parse *phdr) { return NULL; }

static void _free_parse(struct hdr_parse *hdr) { }

static byte_t *_getfield(struct hdr_parse *hdr, unsigned fid, int num,
                             size_t *len) { return NULL; }

static void _fixcksum(struct hdr_parse *hdr) { } 
*/

static struct hdr_parse *newhdr(size_t sz, unsigned type, 
                                struct hdr_parse *phdr, struct hparse_ops *ops)
{
  struct hdr_parse *hdr;
  abort_unless(sz >= sizeof(struct hdr_parse));
  hdr = emalloc(sz);
  hdr->type = type;
  hdr->parent = phdr;
  hdr->next = NULL;
  hdr->error = 0;
  hdr->header = phdr->payload;
  hdr->hlen = phdr->plen;
  hdr->payload = phdr->payload + phdr->plen;
  hdr->plen = 0;
  hdr->ops = ops;
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

static void default_free_parse(struct hdr_parse *hdr)
{
  free(hdr);
}


static byte_t *default_getfield(struct hdr_parse *hdr, unsigned fid, int num,
                                size_t *len)
{
  return NULL;
}


static void default_fixcksum(struct hdr_parse *hdr)
{
}


/* -- ops for the "NONE" protocol type -- */
static int none_follows(struct hdr_parse *phdr) 
{
  return (phdr->type == PPT_NONE) && (phdr->payload != NULL) && 
         (phdr->plen > 0);
}


static struct hdr_parse *none_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  abort_unless(none_follows(phdr));
  return newhdr(sizeof(*hdr), PPT_NONE, phdr, &none_hparse_ops);
}


/* -- ops for Ethernet type -- */
static int eth_follows(struct hdr_parse *phdr) 
{
  return (phdr->type == PPT_NONE) && (phdr->payload != NULL);
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
  if ( hdr->hlen < 14 ) { 
    hdr->error = PPERR_TOSMALL;
  } else {
    hdr->payload = hdr->header + 14;
    hdr->plen = hdr->hlen - 14;
    hdr->hlen = 14;
  }
  return hdr;
}


/* -- ops for ARP type -- */
static int arp_follows(struct hdr_parse *phdr) 
{
  uint16_t etype;
  if ( (phdr->type != PPT_ETHERNET) || (phdr->payload == NULL) )
    return 0;
  unpack(phdr->header + 12, 2, "h", &etype);
  return etype == ETHTYPE_ARP;
}


static byte_t ethiparpstr[6] = { 0x00, 0x01, 0x08, 0x00, 6, 4 };

static struct hdr_parse *arp_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  struct arph *arp;
  abort_unless(arp_follows(phdr));
  switch(phdr->type) {
  case PPT_ARP:
    break;
  default:
    return NULL;
  }
  hdr = newhdr(sizeof(*hdr), PPT_ARP, phdr, &arp_hparse_ops);
  if ( hdr->hlen < 8 ) {
    hdr->error = PPERR_TOSMALL;
  } else { 
    hdr->payload = hdr->header + 8;
    hdr->plen = hdr->hlen - 8;
    hdr->hlen = 8;
    /* check for short ether-ip ARP packet */
    if ( (memcmp(ethiparpstr, hdr->header, sizeof(ethiparpstr)) == 0) &&
         (hdr->plen < 20) )
      hdr->error = PPERR_INVALID;
  }
  return hdr;
}


static byte_t *arp_getfield(struct hdr_parse *hdr, unsigned fid, int num,
                            size_t *len)
{
  if ( hdr == NULL || fid != ARPFLD_ETHARP || num != 0 || 
       hdr->hlen == 0 || hdr->plen < 20 || 
       memcmp(hdr->header, ethiparpstr, 6) != 0 )
    return NULL;
  if ( len != NULL )
    *len = 20;
  return hdr->header;
}


/* -- ops for IPV4 type -- */
static int ipv4_follows(struct hdr_parse *phdr) 
{
  uint16_t etype;
  if ( (phdr->type != PPT_ETHERNET) || (phdr->payload == NULL) )
    return 0;
  unpack(phdr->header + 12, 2, "h", &etype);
  return (etype == ETHTYPE_IP) && (phdr->plen > 0) && 
         (IPH_VERSION(*(struct ipv4h*)phdr->payload) == 4);
}


static struct hdr_parse *ipv4_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  struct ipv4h *ip;
  int hlen, tlen;
  uint16_t iplen, frag, sum;

  abort_unless(ipv4_follows(phdr));
  switch(phdr->type) {
  case PPT_ETHERNET:
    break;
  default:
    return NULL;
  }
  /* TODO: change size when we add provisions for option parsing */
  hdr = newhdr(sizeof(*hdr), PPT_IPV4, phdr, &ipv4_hparse_ops);
  ip = (struct ipv4h *)hdr->header;
  hlen = IPH_HLEN(*ip);
  if ( hdr->hlen < 20 ) {
    hdr->error |= PPERR_TOSMALL;
  } else if ( hlen < hdr->hlen )  {
    hdr->error |= PPERR_HLEN;
  } else {
    tlen = hdr->hlen;
    hdr->hlen = hlen;
    hdr->payload = hdr->header + hlen;
    unpack(&ip->len, 2, "h", &iplen);
    if ( iplen < tlen - hlen )
      hdr->error |= PPERR_LENGTH;
    else
      hdr->plen = tlen - hlen;
    sum = ~ones_sum(ip, IPH_HLEN(*ip), 0);
    if ( sum != 0 ) {
        hdr->error |= PPERR_CKSUM;
        return hdr;
    }
    if ( ip->fragoff != 0 ) {
      if ( (uint32_t)IPH_FRAGOFF(ntoh32(ip->fragoff)) + iplen > 65535 )
        hdr->error |= PPERR_INVALID;
      if ( IPH_RF(*ip) )
        hdr->error |= PPERR_INVALID;
    }
    if ( hlen > 20 ) { 
      /* TODO: parse IP options */
    }
  }
  return hdr;
}


static void ipv4_free_parse(struct hdr_parse *hdr)
{
  /* TODO: fix when option parsing is complete */
  free(hdr);
}


static byte_t *ipv4_getfield(struct hdr_parse *hdr, unsigned fid, int num,
                             size_t *len)
{
  /* TODO: parse options */
  return NULL;
}


static void ipv4_fixcksum(struct hdr_parse *hdr)
{
  uint16_t sum;
  struct ipv4h *ip;
  abort_unless(hdr && hdr->header);
  ip = (struct ipv4h *)hdr->header;
  ip->cksum = 0;
  ip->cksum = ~ones_sum(ip, IPH_HLEN(*ip), 0);
}



/* parse options for UDP protocol */
static int udp_follows(struct hdr_parse *phdr) 
{
  if ( phdr->payload == NULL )
    return 0;
  if ( phdr->type != PPT_IPV4 ) {
    struct ipv4h *ip = (struct ipv4h *)phdr->header;
    return ip->proto == IPPROT_UDP;
  } else if ( phdr->type != PPT_IPV6 ) {
    /* TODO: implement IPV6 next header finding */
    return 0;
  } else { 
    return 0;
  }
}


uint16_t tcpudp_cksum(struct hdr_parse *hdr, uint8_t proto)
{
  struct hdr_parse *phdr = hdr->parent;
  uint16_t sum = 0;
  if ( phdr->type == PPT_IPV4 ) {
    struct pseudoh ph;
    struct ipv4h *ip = (struct ipv4h *)phdr->header;
    memset(&ph, 0, sizeof(ph));
    ph.saddr = ip->saddr;
    ph.daddr = ip->daddr;
    ph.proto = proto;
    ph.totlen = hdr->plen + hdr->hlen;
    sum = ones_sum(&ph, 12, 0);
  } else {
    abort_unless(phdr->type == PPT_IPV6);
    struct pseudo6h ph;
    struct ipv6h *ip6 = (struct ipv6h *)phdr->header;
    memset(&ph, 0, sizeof(ph));
    ph.saddr = ip6->saddr;
    ph.daddr = ip6->daddr;
    ph.proto = proto;
    ph.totlen = hdr->plen + hdr->hlen;
    sum = ones_sum(&ph, 40, 0);
  }
  return ~ones_sum(hdr->payload, hdr->plen, sum);
}


static struct hdr_parse *udp_parse(struct hdr_parse *phdr)
{
  struct hdr_parse *hdr;
  uint32_t tlen;
  uint16_t sum;
  struct udph *udp;

  abort_unless(ipv4_follows(phdr));
  switch(phdr->type) {
  case PPT_IPV4:
  case PPT_IPV6:
    break;
  default:
    return NULL;
  }
  hdr = newhdr(sizeof(*hdr), PPT_UDP, phdr, &udp_hparse_ops);
  if ( hdr->hlen < 8 ) {
    hdr->error |= PPERR_LENGTH;
  } else {
    tlen = hdr->hlen;
    hdr->hlen = 8;
    hdr->payload = hdr->header + 8;
    hdr->plen = tlen - 8;
    udp = (struct udph *)hdr->header;
    if ( (udp->cksum != 0) && (tcpudp_cksum(hdr, IPPROT_UDP) != 0) )
      hdr->error |= PPERR_CKSUM;
  }
  return hdr;
}


static void udp_fixcksum(struct hdr_parse *hdr)
{
  struct udph *udp = (struct udph *)hdr->header;
  uint16_t sum;
  udp->cksum = 0;
  udp->cksum = tcpudp_cksum(hdr, IPPROT_UDP);
}


/* -- op structures for default initialization -- */
struct pparse_ops none_pparse_ops = {
  none_follows, none_parse, default_free_parse
};
struct hparse_ops none_hparse_ops = {
  default_getfield, default_fixcksum
};
struct pparse_ops eth_pparse_ops = { 
  eth_follows, eth_parse, default_free_parse
};
struct hparse_ops eth_hparse_ops = {
  default_getfield, default_fixcksum
};
struct pparse_ops arp_pparse_ops = { 
  arp_follows, arp_parse, default_free_parse
};
struct hparse_ops arp_hparse_ops = {
  arp_getfield, default_fixcksum
};
struct pparse_ops ipv4_pparse_ops = { 
  ipv4_follows, ipv4_parse, ipv4_free_parse
};
struct hparse_ops ipv4_hparse_ops = {
  ipv4_getfield, ipv4_fixcksum
};
struct pparse_ops ipv6_pparse_ops = { 
  default_follows, default_parse, default_free_parse
};
struct hparse_ops ipv6_hparse_ops = {
  default_getfield, default_fixcksum
};
struct pparse_ops icmp_pparse_ops = { 
  default_follows, default_parse, default_free_parse
};
struct hparse_ops icmp_hparse_ops = {
  default_getfield, default_fixcksum
};
struct pparse_ops icmpv6_pparse_ops = { 
  default_follows, default_parse, default_free_parse
};
struct hparse_ops icmpv6_hparse_ops = {
  default_getfield, default_fixcksum
};
struct pparse_ops udp_pparse_ops = {
  udp_follows, udp_parse, default_free_parse
};
struct hparse_ops udp_hparse_ops = {
  default_getfield, udp_fixcksum
};
struct pparse_ops tcp_pparse_ops = { 
  default_follows, default_parse, default_free_parse
};
struct hparse_ops tcp_hparse_ops = {
  default_getfield, default_fixcksum
};
