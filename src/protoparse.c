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


struct hdr_parse *hdr_create_parse(byte_t *buf, size_t off, size_t buflen)
{
  struct proto_parser *pp;
  struct hdr_parse *hdr;
  if ( (off > buflen) || !(pp = &proto_parsers[PPT_NONE])->valid || !buf ) {
    errno = EINVAL;
    return NULL;
  }
  abort_unless(pp->ops && pp->ops->create);
  if ( !(hdr = (*pp->ops->create)(buf, 0, buflen)) ) {
    errno = ENOMEM;
    return NULL;
  }
  hdr->hoff = 0;
  hdr->poff = off;
  hdr->eoff = hdr->toff = buflen;
  return hdr;
}


struct hdr_parse *hdr_parse_packet(unsigned ppidx, byte_t *pkt, size_t off, 
                                   size_t pktlen, size_t buflen)
{
  struct hdr_parse *first, *last, *nhdr;
  struct proto_parser *pp, *nextpp;
  struct list *child;
  unsigned cldid;
  int errval;

  /* assume the rest of the sanity checks are in hdr_create_parse */
  if ( (pktlen > buflen) || (pktlen > buflen - off) ) {
    errno = EINVAL;
    return NULL;
  }
  if ( !(first = hdr_create_parse(pkt, off, buflen)) )
    return NULL;
  if ( ppidx == PPT_NONE )
    return first;
  first->toff = off + pktlen;
  pp = &proto_parsers[PPT_NONE];

  last = first;
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
      /* don't continue parsing if the lengths are screwed up */
      if ( (nhdr->error & PPERR_HLENMASK) ) 
        break;
      last = nhdr;
    }
  }

  return first;

err:
  hdr_free(first, 1);
  errno = errval;
  return NULL;
}


int hdr_add(unsigned ppidx, struct hdr_parse *phdr)
{
  struct proto_parser *pp;
  if ( (ppidx > PPT_MAX) || !(pp = &proto_parsers[ppidx])->valid || !phdr ||
       !hdr_islast(phdr) ) {
    errno = EINVAL;
    return -1;
  }
  if ( (*pp->ops->create)(phdr->data, phdr->poff, hdr_plen(phdr)) == NULL )
    return -1;
  else
    return 0;
}


void hdr_free(struct hdr_parse *hdr, int freeall)
{
  struct hdr_parse *next;
  if ( !hdr )
    return;
  if ( freeall ) {
    while ( !hdr_islast(hdr) ) {
      next = hdr_child(hdr);
      l_rem(&next->node);
      abort_unless(next->ops && next->ops->free);
      (*next->ops->free)(next);
    }
  }
  abort_unless(hdr->ops && hdr->ops->free);
  l_rem(&hdr->node);
  (*hdr->ops->free)(hdr);
}


struct hdr_parse *hdr_copy(struct hdr_parse *ohdr, byte_t *buffer)
{
  struct hdr_parse *first = NULL, *last, *t, *hdr;

  if ( !ohdr || !buffer )
    return NULL;

  t = ohdr;
  do {
    abort_unless(t->ops && t->ops->copy);
    if ( !(hdr = (*t->ops->copy)(t, buffer)) )
      goto err;
    if ( !first ) {
      l_init(&hdr->node);
      first = hdr;
    } else {
      l_ins(&last->node, &hdr->node);
    }
    last = hdr;
    t = hdr_child(t);
  } while ( t != ohdr );

  return first;

err:
  hdr_free(first, 1);
  return NULL;
}


void hdr_set_packet_buffer(struct hdr_parse *hdr, byte_t *buffer)
{
  while ( hdr ) {
    hdr->data = buffer;
    hdr = hdr_child(hdr);
  }
}


unsigned int hdr_update(struct hdr_parse *hdr)
{
  abort_unless(hdr && hdr->ops && hdr->ops->update);
  (*hdr->ops->update)(hdr);
  return hdr->error;
}


size_t hdr_get_field(struct hdr_parse *hdr, unsigned fid, unsigned num,
                     size_t *len)
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


void insert_adjust(struct hdr_parse *hdr, size_t off, size_t len, int moveup)
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

    hdr = hdr_child(hdr);
  }
}


int hdr_insert(struct hdr_parse *hdr, size_t off, size_t len, int moveup)
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
      mlen = hdr_totlen(hdr) - off;
    } else {
      op = hdr->data + hdr->hoff;
      np = op - len;
      mlen = off;
    }
    memmove(np, op, mlen);
    memset(op, 0x5F, len);
  }
  insert_adjust(hdr, off, len, moveup);
  return 0;
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

  if ( cut_adjust(hdr_child(hdr), off, len, moveup) < 0 ) {
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
  pktlen = hdr_totlen(hdr);
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
  if ( !hdr || hdr_isfirst(hdr) )
    return -1;
  if ( amt < 0 ) { 
    abort_unless(-amt > 0); /* edge case for minimum neg value in 2s comp */
    if (-amt > hdr->hoff - hdr_parent(hdr)->eoff )
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
    if ( !hdr_islast(hdr) && (amt > hdr_child(hdr)->hoff - hdr->poff) )
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
    if ( hdr_isfirst(hdr) ) {
      if ( amt > hdr_tlen(hdr) )
        return -1;
    } else {
      if ( amt > hdr_parent(hdr)->toff - hdr->toff )
        return -1;
    }
  }
  hdr->toff += amt;
  if ( hdr->toff > hdr->eoff )
    hdr->eoff = hdr->toff;
  return 0;
}


int hdr_adj_tlen(struct hdr_parse *hdr, ptrdiff_t amt)
{
  if ( !hdr || hdr_isfirst(hdr) )
    return -1;
  if ( amt < 0 ) { 
    abort_unless(-amt > 0); /* edge case for minimum neg value in 2s comp */
    if ( -amt > hdr_tlen(hdr) )
      return -1;
  } else if ( amt > 0 ) {
    if ( amt > hdr_parent(hdr)->toff - hdr->eoff )
      return -1;
  }
  hdr->eoff += amt;
  return 0;
}


