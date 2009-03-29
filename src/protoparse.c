#include "protoparse.h"
#include "pptcpip.h"
#include <errno.h>
#include <cat/stduse.h>
#include <string.h>


struct proto_parser proto_parsers[PPT_MAX+1];
struct pparse_ops proto_parser_ops[PPT_MAX+1];


int register_proto_parser(unsigned type, struct pparse_ops *ppo)
{
  struct proto_parser *pp;
  if ( (type > PPT_MAX) || (ppo == NULL) || (ppo->follows == NULL) || 
       (ppo->parse == NULL) || (ppo->create == NULL) ) {
    errno = EINVAL;
    return -1;
  }
  pp = &proto_parsers[type];
  if ( pp->valid ) {
    errno = EACCES;
    return -1;
  }
  pp->type = type;
  pp->children = clist_newlist();
  proto_parser_ops[type] = *ppo;
  pp->ops = &proto_parser_ops[type];
  pp->valid = 1;
  return 0;
}


int add_proto_parser_parent(unsigned cldtype, unsigned partype)
{
  struct proto_parser *par, *cld;
  if ( (cldtype > PPT_MAX) || (partype > PPT_MAX) ) {
    errno = EINVAL;
    return -1;
  }
  par = &proto_parsers[partype];
  cld = &proto_parsers[cldtype];
  if ( !par->valid || !cld->valid ) {
    errno = EINVAL;
    return -1;
  }
  clist_enq(par->children, unsigned, cldtype);
  return 0;
}


void deregister_proto_parser(unsigned type)
{
  struct proto_parser *pp;
  if ( (type <= PPT_MAX) && (pp = &proto_parsers[type])->valid ) {
    clist_freelist(pp->children);
    pp->children = NULL;
    pp->valid = 0;
    pp->ops = NULL;
  }
}


void install_default_proto_parsers()
{
  register_proto_parser(PPT_NONE, &none_pparse_ops);
  register_proto_parser(PPT_ETHERNET, &eth_pparse_ops);
  add_proto_parser_parent(PPT_ETHERNET, PPT_NONE);
  register_proto_parser(PPT_ARP, &arp_pparse_ops);
  add_proto_parser_parent(PPT_ARP, PPT_ETHERNET);
  register_proto_parser(PPT_IPV4, &ipv4_pparse_ops);
  add_proto_parser_parent(PPT_IPV4, PPT_ETHERNET);
  register_proto_parser(PPT_IPV6, &ipv6_pparse_ops);
  add_proto_parser_parent(PPT_IPV6, PPT_ETHERNET);
  register_proto_parser(PPT_ICMP, &icmp_pparse_ops);
  add_proto_parser_parent(PPT_ICMP, PPT_IPV4);
  add_proto_parser_parent(PPT_IPV4, PPT_ICMP); /* embedded headers in ICMP */
  register_proto_parser(PPT_ICMP6, &icmpv6_pparse_ops);
  add_proto_parser_parent(PPT_ICMP6, PPT_IPV6);
  register_proto_parser(PPT_UDP, &udp_pparse_ops);
  add_proto_parser_parent(PPT_UDP, PPT_IPV4);
  add_proto_parser_parent(PPT_UDP, PPT_IPV6);
  register_proto_parser(PPT_TCP, &tcp_pparse_ops);
  add_proto_parser_parent(PPT_TCP, PPT_IPV4);
  add_proto_parser_parent(PPT_TCP, PPT_IPV6);
}


int parse_from(struct hdr_parse *phdr)
{
  struct hdr_parse *last = phdr, *nhdr;
  struct proto_parser *pp, *nextpp;
  struct list *child;
  unsigned cldid;
  int errval;

  abort_unless(phdr && phdr->type <= PPT_MAX);
  pp = &proto_parsers[phdr->type];
  abort_unless(pp->valid);
  last = phdr;
  while ( pp && (hdr_plen(last) > 0) ) {
    nextpp = NULL;
    l_for_each(child, pp->children) {
      cldid = clist_data(child, unsigned);
      if ( (cldid > PPT_MAX) || !(nextpp = &proto_parsers[cldid])->valid ) {
        errval = EINVAL;
        goto err;
      }
      if ( (*nextpp->ops->follows)(last) )
        break;
      nextpp = NULL;
    }
    pp = nextpp;
    if ( nextpp ) {
      if ( !(nhdr = (*nextpp->ops->parse)(last)) ) {
        errval = errno;
        goto err;
      }
      last->next = nhdr;
      nhdr->parent = last;
      /* don't continue parsing if the lengths are screwed up */
      if ( (nhdr->error & PPERR_HLENMASK) ) 
        break;
      last = nhdr;
    }
  }

  return 0;

err:
  if ( phdr->next ) {
    hdr_free(phdr->next, 1);
    phdr->next = NULL;
  }
  errno = errval;
  return -1;
}


struct hdr_parse *parse_packet(unsigned ppidx, byte_t *pkt, size_t off, 
                               size_t pktlen)
{
  struct hdr_parse dummyhdr = { 0 }, *rhdr = NULL;
  struct proto_parser *pp = &proto_parsers[PPT_NONE];
  if ( !pkt || pktlen < 1 || off > pktlen || !pp->valid ) {
    errno = EINVAL;
    return NULL;
  }
  dummyhdr.type = PPT_NONE;
  dummyhdr.data = pkt;
  dummyhdr.hoff = off;
  dummyhdr.poff = off;
  dummyhdr.toff = off + pktlen;
  dummyhdr.eoff = off + pktlen;
  if ( parse_from(&dummyhdr) == 0 ) {
    if ( (rhdr = dummyhdr.next) )
      rhdr->parent = NULL;
  }
  return rhdr;
}


int reparse_packet(struct hdr_parse *phdr)
{
  if ( (phdr->type > PPT_MAX) || !proto_parsers[phdr->type].valid || 
      !phdr->data ) {
    errno = EINVAL;
    return -1;
  }
  return parse_from(phdr);
}


size_t hdr_total_len(struct hdr_parse *hdr)
{
  if ( !hdr )
    return 0;
  return hdr->eoff - hdr->hoff;
}


void hdr_free(struct hdr_parse *hdr, int freechildren)
{
  struct hdr_parse *next;
  if ( freechildren ) {
    while ( hdr != NULL ) {
      next = hdr->next;
      abort_unless(hdr->ops && hdr->ops->free);
      (*hdr->ops->free)(hdr);
      hdr = next;
    }
  } else if ( hdr ) {
    abort_unless(hdr->ops && hdr->ops->free);
    (*hdr->ops->free)(hdr);
  }
}


struct hdr_parse *hdr_copy(struct hdr_parse *ohdr, byte_t *buffer)
{
  struct hdr_parse *first = NULL, *last = NULL, *hdr;
  while ( ohdr ) {
    abort_unless(ohdr->ops && ohdr->ops->copy);
    if ( !(hdr = (*ohdr->ops->copy)(ohdr, buffer)) )
      goto err;
    if ( !first )
      first = hdr;
    hdr->parent = last;
    hdr->next = NULL;
    if ( last )
      last->next = hdr;
    ohdr = ohdr->next;
  }
  return first;
err:
  hdr_free(first, 1);
  return NULL;
}


void hdr_set_packet_buffer(struct hdr_parse *hdr, byte_t *buffer)
{
  while ( hdr ) {
    hdr->data = buffer;
    hdr = hdr->next;
  }
}


byte_t *hdr_getfield(struct hdr_parse *hdr, unsigned fid, int num, size_t *len)
{
  abort_unless(hdr && hdr->ops && hdr->ops->getfield);
  return (*hdr->ops->getfield)(hdr, fid, num, len);
}


int hdr_fix_cksum(struct hdr_parse *hdr)
{
  abort_unless(hdr && hdr->ops && hdr->ops->fixcksum);
  return (*hdr->ops->fixcksum)(hdr);
}


int hdr_fix_len(struct hdr_parse *hdr)
{
  abort_unless(hdr && hdr->ops && hdr->ops->fixlen);
  return (*hdr->ops->fixlen)(hdr);
}


void hdr_remove(struct hdr_parse *hdr)
{
  struct hdr_parse *thdr;
  if ( !hdr )
    return;
  if ( (thdr = hdr->parent) )
    thdr->next = hdr->next;
  if ( (thdr = hdr->next) )
    thdr->parent = hdr->parent;
  hdr->next = NULL;
  hdr->parent = NULL;
  hdr_free(hdr, 0);
}


struct hdr_parse *create_parse(unsigned ppidx, byte_t *pkt, size_t len, 
                               size_t off, struct hdr_parse *phdr)
{
  size_t maxhlen, mintoff, maxtoff;
  struct hdr_parse *hdr, *prev = NULL, *next = phdr;
  struct proto_parser *pp;

  if ( (ppidx > PPT_MAX) || !(pp = &proto_parsers[ppidx])->valid )
    return NULL;
  if ( phdr && (phdr->data != pkt) )
    return NULL;
  if ( off > len )
    return NULL;

  if ( next ) { 
    while ( next->poff < off ) { 
      prev = next;
      next = next->next;
    }
  }

  if ( prev ) {
    if ( next ) {
      maxhlen = next->hoff - prev->poff;
      mintoff = next->eoff;
      maxtoff = prev->toff;
    } else {
      maxhlen = hdr_plen(prev);
      mintoff = off;
      maxtoff = prev->toff;
    }
  } else if ( next ) { 
    maxhlen = next->hoff - off;
    mintoff = next->toff;
    maxtoff = mintoff + (len - next->eoff);
  } else {
    maxhlen = len;
    mintoff = 0;
    maxtoff = len;
  }

  hdr = (*pp->ops->create)(phdr->data, off, maxhlen, mintoff, maxtoff);
  if ( !hdr )
    return NULL;
  hdr->parent = prev;
  hdr->next = next;
  if ( next )
    next->parent = hdr;
  if ( prev )
    prev->next = hdr;
  return hdr;
}


void splice_adjust(struct hdr_parse *hdr, size_t off, size_t len, int moveup)
{
  while ( hdr != NULL ) {
    if ( (off <= hdr->hoff) && moveup )
      hdr->hoff += len;
    else if ( (off > hdr->hoff) && !moveup )
      hdr->hoff -= len;

    /* NOTE: if on the border between the header and the payload, we */
    /* favor expanding the payload, not the header. */
    if ( (off < hdr->poff) && moveup )
      hdr->poff += len;
    else if ( (off >= hdr->poff) && !moveup )
      hdr->poff -= len;

    if ( (off <= hdr->toff) && moveup )
      hdr->toff += len;
    else if ( (off > hdr->toff) && !moveup )
      hdr->poff -= len;

    if ( (off <= hdr->eoff) && moveup )
      hdr->eoff += len;
    else if ( (off >= hdr->eoff) && !moveup )
      hdr->eoff -= len;

    hdr = hdr->next;
  }
}


int hdr_splice(struct hdr_parse *hdr, size_t off, size_t len, int moveup)
{
  byte_t *op, *np;
  size_t mlen;
  if ( hdr == NULL )
    return -1;
  if ( (off < hdr->hoff) || (off > hdr->eoff) )
    return -1;
  if ( !moveup && (len > hdr->hoff) )
    return -1;

  if ( hdr->data != NULL ) {
    if ( moveup ) { 
      op = hdr->data + off;
      np = op + len;
      mlen = hdr_total_len(hdr) - off;
    } else {
      op = hdr->data + hdr->hoff;
      np = op - len;
      mlen = off;
    }
    memmove(np, op, mlen);
    memset(op, 0x5F, len);
  }
  splice_adjust(hdr, off, len, moveup);
}


int cut_adjust(struct hdr_parse *hdr, size_t off, size_t len, int moveup)
{
  size_t ohoff, opoff, otoff, oeoff;
  if ( hdr == NULL )
    return 0;

  ohoff = hdr->hoff;
  opoff = hdr->poff;
  otoff = hdr->toff;
  oeoff = hdr->eoff;

  if ( off <= hdr->hoff ) {
    /* comes before this header */
    if ( !moveup ) {
      hdr->hoff -= len;
      hdr->poff -= len;
      hdr->toff -= len;
      hdr->eoff -= len;
    }
  } else if ( off <= hdr->poff ) { 
    if ( len > hdr_hlen(hdr) )
      return -1;
    /* comes in the middle or at the end of the header */
    if ( moveup ) {
      hdr->hoff += len;
    } else {
      hdr->poff -= len;
      hdr->toff -= len;
      hdr->eoff -= len;
    }
  } else if ( off <= hdr->toff ) {
    /* comes in the middle or at the end of the payload */
    if ( len > hdr_plen(hdr) )
      return -1;
    if ( moveup ) {
      hdr->hoff += len;
      hdr->poff += len;
    } else {
      hdr->toff -= len;
      hdr->eoff -= len;
    }
  } else if ( off <= hdr->eoff ) { 
      if ( len > hdr_tlen(hdr) )
        return -1;
    /* comes in the middle or at the end of the trailer */
    if ( !moveup ) {
      hdr->eoff -= len;
    } else { 
      hdr->hoff += len;
      hdr->poff += len;
      hdr->toff += len;
    }
  } else { 
    /* else it comes after the end of the trailer */
    if ( moveup ) { 
      hdr->hoff += len;
      hdr->poff += len;
      hdr->toff += len;
      hdr->eoff += len;
    }
  }

  if ( cut_adjust(hdr->next, off, len, moveup) < 0 ) {
    hdr->hoff = ohoff;
    hdr->poff = opoff;
    hdr->toff = otoff;
    hdr->eoff = oeoff;
    return -1;
  }

  return 0;
}


int hdr_cut(struct hdr_parse *hdr, size_t off, size_t len, int moveup)
{
  size_t pktlen, ohoff;
  byte_t *op, *np;
  size_t mlen;

  if ( (hdr == NULL) || (hdr->data == NULL) )
    return -1;
  if ( (off < hdr->hoff) || (off > hdr->eoff) )
    return -1;
  pktlen = hdr_total_len(hdr);
  if ( len > pktlen )
    return - 1;
  ohoff = hdr->hoff;
  if ( cut_adjust(hdr, off, len, moveup) < 0 )
    return -1;

  if ( hdr->data != NULL ) {
    if ( moveup ) {
      op = hdr->data + ohoff;
      np = op + len;
      mlen = off - ohoff;
    } else { 
      np = hdr->data + off;
      op = np + len;
      mlen = pktlen - len;
    }
    memmove(np, op, mlen);
    if ( moveup )
      memset(op, 0x6e, len);
    else
      memset(np + mlen, 0x6e, len);
  }

  return 0;
}


int hdr_adj_hstart(struct hdr_parse *hdr, ptrdiff_t amt)
{
  if ( !hdr )
    return -1;
  if ( amt < 0 ) { 
    abort_unless(-amt > 0); /* edge case for minimum neg value in 2s comp */
    struct hdr_parse *phdr;
    if ( (phdr = hdr->parent) && (-amt > hdr->hoff - phdr->eoff) )
      return -1;
  } else if ( amt > 0 ) {
    if ( amt > hdr_hlen(hdr) )
      return -1;
  }
  hdr->hoff += amt;
  return 0;
}


int hdr_adj_hlen(struct hdr_parse *hdr, ptrdiff_t amt)
{
  if ( !hdr )
    return -1;
  if ( amt < 0 ) { 
    abort_unless(-amt > 0); /* edge case for minimum neg value in 2s comp */
    if ( -amt > hdr_hlen(hdr)  )
      return -1;
  } else if ( amt > 0 ) {
    struct hdr_parse *nhdr;
    if ( (nhdr = hdr->next) && (amt > nhdr->hoff - hdr->poff) )
      return -1;
    if ( amt > hdr_plen(hdr) )
      return -1;
  }
  hdr->poff += amt;
  return 0;
}


int hdr_adj_plen(struct hdr_parse *hdr, ptrdiff_t amt)
{
  if ( !hdr )
    return -1;

  if ( amt < 0 ) {
    abort_unless(-amt > 0); /* edge case for minimum neg value in 2s comp */
    if ( -amt > hdr_plen(hdr) )
      return -1;
  } else {
    struct hdr_parse *phdr;
    if ( (phdr = hdr->parent) && (amt > phdr->toff - hdr->toff) )
      return -1;
  }
  hdr->toff += amt;
  if ( hdr->toff > hdr->eoff )
    hdr->eoff = hdr->toff;
}


int hdr_adj_tlen(struct hdr_parse *hdr, ptrdiff_t amt)
{
  if ( !hdr )
    return -1;
  if ( amt < 0 ) { 
    abort_unless(-amt > 0); /* edge case for minimum neg value in 2s comp */
    if ( -amt > hdr_tlen(hdr) )
      return -1;
  } else if ( amt > 0 ) {
    struct hdr_parse *phdr;
    if ( (phdr = hdr->parent) && (amt > phdr->toff - hdr->eoff) )
      return -1;
  }
  hdr->eoff += amt;
  return 0;
}


