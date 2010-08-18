#include "protoparse.h"
#include "pptcpip.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>


struct proto_parser proto_parsers[PPT_MAX+1];
struct proto_parser_ops proto_parser_ops[PPT_MAX+1];


struct childnode {
	struct list 	entry;
	uint		cldtype;
};

#define l2cldn(le)  container((le), struct childnode, entry)


int register_proto_parser(unsigned type, struct proto_parser_ops *ppo)
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
  l_init(&pp->children);
  proto_parser_ops[type] = *ppo;
  pp->ops = &proto_parser_ops[type];
  pp->valid = 1;
  return 0;
}


/* NB:  In the future I may change the allocation model for this part of */
/* the library to a static allocation of childnodes, etc.... */
int add_proto_parser_parent(unsigned cldtype, unsigned partype)
{
  struct proto_parser *par, *cld;
  struct childnode *cnode;
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
  if ( (cnode = malloc(sizeof(*cnode))) == NULL )
    return -1;
  cnode->cldtype = cldtype;
  l_enq(&par->children, &cnode->entry);
  return 0;
}


void deregister_proto_parser(unsigned type)
{
  struct proto_parser *pp;
  if ( (type <= PPT_MAX) && (pp = &proto_parsers[type])->valid ) {
    while ( !l_isempty(&pp->children) )
      free(l2cldn(l_deq(&pp->children)));
    pp->valid = 0;
    pp->ops = NULL;
  }
}


void install_default_proto_parsers()
{
  register_proto_parser(PPT_NONE, &none_proto_parser_ops);
  register_proto_parser(PPT_ETHERNET, &eth_proto_parser_ops);
  register_proto_parser(PPT_ARP, &arp_proto_parser_ops);
  add_proto_parser_parent(PPT_ARP, PPT_ETHERNET);
  register_proto_parser(PPT_IPV4, &ipv4_proto_parser_ops);
  add_proto_parser_parent(PPT_IPV4, PPT_ETHERNET);
  register_proto_parser(PPT_IPV6, &ipv6_proto_parser_ops);
  add_proto_parser_parent(PPT_IPV6, PPT_ETHERNET);
  register_proto_parser(PPT_ICMP, &icmp_proto_parser_ops);
  add_proto_parser_parent(PPT_ICMP, PPT_IPV4);
  add_proto_parser_parent(PPT_IPV4, PPT_ICMP); /* embedded headers in ICMP */
  register_proto_parser(PPT_ICMP6, &icmpv6_proto_parser_ops);
  add_proto_parser_parent(PPT_ICMP6, PPT_IPV6);
  register_proto_parser(PPT_UDP, &udp_proto_parser_ops);
  add_proto_parser_parent(PPT_UDP, PPT_IPV4);
  add_proto_parser_parent(PPT_UDP, PPT_IPV6);
  register_proto_parser(PPT_TCP, &tcp_proto_parser_ops);
  add_proto_parser_parent(PPT_TCP, PPT_IPV4);
  add_proto_parser_parent(PPT_TCP, PPT_IPV6);
}


int prp_can_follow(unsigned partype, unsigned cldtype)
{
  struct proto_parser *ppp, *cpp;
  struct list *l;
  if ( (partype > PPT_MAX) || !(ppp = &proto_parsers[partype])->valid )
    return 0;
  if ( (cldtype > PPT_MAX) || !(cpp = &proto_parsers[cldtype])->valid )
    return 0;
  l_for_each(l, &ppp->children)
    if ( l2cldn(l)->cldtype == cldtype )
      return 1;
  return 0;
}


struct prparse *prp_next_in_region(struct prparse *from, struct prparse *reg)
{
  struct prparse *prp;
  abort_unless(from && reg);
  for ( prp = prp_next(from) ; 
        !prp_list_end(prp) && (prp->hoff <= reg->eoff) ; 
        prp = prp_next(prp) ) {
    if ( prp->region == reg )
      return prp;
  }
  return NULL;
}


int prp_region_empty(struct prparse *reg)
{
  abort_unless(reg);
  return (prp_next_in_region(reg, reg) == NULL);
}


struct prparse *prp_create_parse(byte_t *buf, size_t off, size_t len)
{
  struct proto_parser *pp = &proto_parsers[PPT_NONE];
  struct prparse *prp;
  if ( !pp->valid || !buf ) {
    errno = EINVAL;
    return NULL;
  }
  abort_unless(pp->ops && pp->ops->create);
  prp = (*pp->ops->create)(buf, off, len, 0, len, PPCF_FILL);
  prp->region = NULL;
  return prp;
}


struct prparse *prp_parse_packet(unsigned ppidx, byte_t *pkt, size_t off,
                                 size_t len)
{
  struct prparse *first, *last, *nprp;
  struct proto_parser *pp, *lastpp;
  struct list *child;
  unsigned cldid;
  int errval;

  if ( (ppidx > PPT_MAX) || !(pp = &proto_parsers[ppidx])->valid ) {
    errno = EINVAL;
    return NULL;
  }

  if ( !(first = prp_create_parse(pkt, off, len)) )
    return NULL;

  last = first;
  do { 
    if ( !(nprp = (*pp->ops->parse)(last)) ) {
      errval = errno;
      goto err;
    }
    /* don't continue parsing if the lengths are screwed up */
    if ( (nprp->error & PPERR_HLENMASK) || !prp_plen(nprp) ) 
      break;
    last = nprp;
    lastpp = pp;
    l_for_each(child, &lastpp->children) {
      cldid = l2cldn(child)->cldtype;
      abort_unless(cldid <= PPT_MAX); 
      pp = &proto_parsers[cldid];
      abort_unless(pp->valid);
      if ( (*pp->ops->follows)(last) )
        break;
      pp = NULL;
    }
  } while ( pp );

  return first;

err:
  prp_free(first, 1);
  errno = errval;
  return NULL;
}


int prp_push(unsigned ppidx, struct prparse *pprp, int mode)
{
  struct proto_parser *pp;
  size_t off, len, plen, hlen;
  struct prparse *prp, *next;

  if ( (ppidx > PPT_MAX) || !(pp = &proto_parsers[ppidx])->valid || !pprp ) {
    errno = EINVAL;
    return -1;
  }

  off = pprp->poff;
  len = prp_plen(pprp);
  if ( mode == PPCF_FILL ) {
    hlen = 0;
    plen = 0;
  } else if ( mode == PPCF_WRAP ) {
    if ( prp_region_empty(pprp) ) {
      errno = EINVAL;
      return -1;
    }
    hlen = prp_next(pprp)->hoff - off; 
    off = prp_next(pprp)->hoff;
    plen = prp_totlen(prp_next(pprp));
  } else if ( mode == PPCF_WRAPFILL ) {
    next = prp_next(pprp);
    /* make sure the list is non-empty and both prev and next are in the */
    /* same region.  Also, the previous parse must enclose the next parse */
    if ( (next == pprp) || (next->region != pprp) ) {
      errno = EINVAL;
      return -1;
    }
    hlen = next->hoff - off; 
    plen = prp_totlen(next);
  } else {
    errno = EINVAL;
    return -1;
  }

  prp = (*pp->ops->create)(pprp->data, off, len, hlen, plen, mode);
  if ( prp == NULL )
    return -1;
  prp->region = pprp;
  if ( mode == PPCF_WRAP || mode == PPCF_WRAPFILL )
    next->region = prp;

  l_ins(&pprp->node, &prp->node);
  return 0;
}


void prp_free(struct prparse *prp, int freeall)
{
  struct prparse *next;
  if ( !prp )
    return;
  if ( freeall ) {
    while ( !l_isempty(&prp->node) ) {
      next = prp_next(prp);
      l_rem(&next->node);
      abort_unless(next->ops && next->ops->free);
      (*next->ops->free)(next);
    }
  }
  abort_unless(prp->ops && prp->ops->free);
  l_rem(&prp->node);
  (*prp->ops->free)(prp);
}


struct prparse *prp_copy(struct prparse *oprp, byte_t *buffer)
{
  struct prparse *first = NULL, *last, *t, *prp;

  if ( !oprp || !buffer )
    return NULL;

  t = oprp;
  do {
    abort_unless(t->ops && t->ops->copy);
    if ( !(prp = (*t->ops->copy)(t, buffer)) )
      goto err;
    if ( !first ) {
      l_init(&prp->node);
      first = prp;
    } else {
      l_ins(&last->node, &prp->node);
    }
    last = prp;
    t = prp_next(t);
  } while ( t != oprp );

  return first;

err:
  prp_free(first, 1);
  return NULL;
}


void prp_set_packet_buffer(struct prparse *prp, byte_t *buffer)
{
  while ( prp ) {
    prp->data = buffer;
    prp = prp_next(prp);
  }
}


unsigned int prp_update(struct prparse *prp)
{
  abort_unless(prp && prp->ops && prp->ops->update);
  (*prp->ops->update)(prp);
  return prp->error;
}


size_t prp_get_field(struct prparse *prp, unsigned fid, unsigned num,
                     size_t *len)
{
  abort_unless(prp && prp->ops && prp->ops->getfield);
  return (*prp->ops->getfield)(prp, fid, num, len);
}


int prp_fix_cksum(struct prparse *prp)
{
  abort_unless(prp && prp->ops && prp->ops->fixcksum);
  return (*prp->ops->fixcksum)(prp);
}


int prp_fix_len(struct prparse *prp)
{
  abort_unless(prp && prp->ops && prp->ops->fixlen);
  return (*prp->ops->fixlen)(prp);
}


static void insert_adjust(struct prparse *prp, size_t off, size_t len, 
		          int moveup)
{
  while ( prp != NULL ) {
    if ( (off <= prp->hoff) && moveup )
      prp->hoff += len;
    else if ( (off > prp->hoff) && !moveup )
      prp->hoff -= len;

    /* NOTE: if on the border between the header and the payload, we */
    /* favor expanding the payload, not the header. */
    if ( (off < prp->poff) && moveup )
      prp->poff += len;
    else if ( (off >= prp->poff) && !moveup )
      prp->poff -= len;

    if ( (off <= prp->toff) && moveup )
      prp->toff += len;
    else if ( (off > prp->toff) && !moveup )
      prp->poff -= len;

    if ( (off <= prp->eoff) && moveup )
      prp->eoff += len;
    else if ( (off >= prp->eoff) && !moveup )
      prp->eoff -= len;

    prp = prp_next(prp);
  }
}


int prp_insert(struct prparse *prp, size_t off, size_t len, int moveup)
{
  byte_t *op, *np;
  size_t mlen;
  if ( prp == NULL )
    return -1;
  if ( (off < prp->hoff) || (off > prp->eoff) )
    return -1;
  if ( !moveup && (len > prp->hoff) )
    return -1;

  if ( prp->data != NULL ) {
    if ( moveup ) { 
      op = prp->data + off;
      np = op + len;
      mlen = prp_totlen(prp) - off;
    } else {
      op = prp->data + prp->hoff;
      np = op - len;
      mlen = off;
    }
    memmove(np, op, mlen);
    memset(op, 0x5F, len);
  }
  insert_adjust(prp, off, len, moveup);
  return 0;
}


static int cut_adjust(struct prparse *prp, size_t off, size_t len, int moveup)
{
  size_t ohoff, opoff, otoff, oeoff;
  if ( prp == NULL )
    return 0;

  ohoff = prp->hoff;
  opoff = prp->poff;
  otoff = prp->toff;
  oeoff = prp->eoff;

  if ( off <= prp->hoff ) {
    /* comes before this header */
    if ( !moveup ) {
      prp->hoff -= len;
      prp->poff -= len;
      prp->toff -= len;
      prp->eoff -= len;
    }
  } else if ( off <= prp->poff ) { 
    if ( len > prp_hlen(prp) )
      return -1;
    /* comes in the middle or at the end of the header */
    if ( moveup ) {
      prp->hoff += len;
    } else {
      prp->poff -= len;
      prp->toff -= len;
      prp->eoff -= len;
    }
  } else if ( off <= prp->toff ) {
    /* comes in the middle or at the end of the payload */
    if ( len > prp_plen(prp) )
      return -1;
    if ( moveup ) {
      prp->hoff += len;
      prp->poff += len;
    } else {
      prp->toff -= len;
      prp->eoff -= len;
    }
  } else if ( off <= prp->eoff ) { 
      if ( len > prp_tlen(prp) )
        return -1;
    /* comes in the middle or at the end of the trailer */
    if ( !moveup ) {
      prp->eoff -= len;
    } else { 
      prp->hoff += len;
      prp->poff += len;
      prp->toff += len;
    }
  } else { 
    /* else it comes after the end of the trailer */
    if ( moveup ) { 
      prp->hoff += len;
      prp->poff += len;
      prp->toff += len;
      prp->eoff += len;
    }
  }

  if ( cut_adjust(prp_next(prp), off, len, moveup) < 0 ) {
    prp->hoff = ohoff;
    prp->poff = opoff;
    prp->toff = otoff;
    prp->eoff = oeoff;
    return -1;
  }

  return 0;
}


int prp_cut(struct prparse *prp, size_t off, size_t len, int moveup)
{
  size_t pktlen, ohoff;
  byte_t *op, *np;
  size_t mlen;

  if ( (prp == NULL) || (prp->data == NULL) )
    return -1;
  if ( (off < prp->hoff) || (off > prp->eoff) )
    return -1;
  pktlen = prp_totlen(prp);
  if ( len > pktlen )
    return - 1;
  ohoff = prp->hoff;
  if ( cut_adjust(prp, off, len, moveup) < 0 )
    return -1;

  if ( prp->data != NULL ) {
    if ( moveup ) {
      op = prp->data + ohoff;
      np = op + len;
      mlen = off - ohoff;
    } else { 
      np = prp->data + off;
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


int prp_adj_start(struct prparse *prp, ptrdiff_t amt)
{
  struct prparse *region;
  struct prparse *trav;
  size_t nhoff;
  if ( !prp ) {
    errno = EINVAL;
    return -1;
  }
  if ( amt < 0 ) {
    amt = -amt;
    if ( (amt < 0) || (amt > prp->hoff) ) {
      errno = EINVAL;
      return -1;
    }
    region = prp->region;
    if ( region == NULL ) {
      /* root region */
      prp->hoff -= amt;
    } else {
      /* verify that start offset can't go below region start offset */
      if ( prp->hoff - amt < region->hoff ) {
        errno = EINVAL;
        return -1;
      }
      prp->hoff -= amt;
      /* maintain order in list by starting offset */
      trav = prp_prev(prp);
      if ( trav->hoff > prp->hoff ) { 
        l_rem(&prp->node);
        do {
          trav = prp_prev(trav);
        } while ( trav->hoff > prp->hoff );
        l_ins(&trav->node, &prp->node);
      }
    }
  } else { /* amt >= 0 */
    if ( amt > prp_hlen(prp) ) {
      errno = EINVAL;
      return -1;
    }
    nhoff = prp->hoff + amt;
    /* Can't adjust start offset of a non-empty region past the start offset */
    /* of its contained parses. */
    trav = prp_next_in_region(prp, prp);
    if ( (trav != NULL) && (nhoff > trav->hoff) ) {
      errno = EINVAL;
      return -1;
    }
    trav = prp_next(prp);
    /* maintain order in list by starting offset */
    if ( !prp_list_end(trav) && (nhoff > trav->hoff) ) {
      l_rem(&prp->node);
      do { 
        trav = prp_next(trav);
      } while ( !prp_list_end(trav) && (nhoff > trav->hoff) );
      l_ins(&prp_prev(trav)->node, &prp->node);
    }

    prp->hoff = nhoff;
  }
  return 0;
}


int prp_adj_poff(struct prparse *prp, ptrdiff_t amt)
{
  if ( !prp ) {
    errno = EINVAL;
    return -1;
  }
  if ( amt < 0 ) { 
    amt = -amt;
    if ( (amt < 0) || (amt > prp_hlen(prp)) ) {
      errno = EINVAL;
      return -1;
    }
    prp->poff -= amt;
  } else {
    if ( amt > prp_plen(prp) ) {
      errno = EINVAL;
      return -1;
    }
    prp->poff += amt;
  }
  return 0;
}


int prp_adj_toff(struct prparse *prp, ptrdiff_t amt)
{
  if ( !prp ) {
    errno = EINVAL;
    return -1;
  }
  if ( amt < 0 ) { 
    amt = -amt;
    if ( (amt < 0) || (amt > prp_plen(prp)) ) {
      errno = EINVAL;
      return -1;
    }
    prp->toff -= amt;
  } else {
    if ( amt > prp_tlen(prp) ) {
      errno = EINVAL;
      return -1;
    }
    prp->toff += amt;
  }
  return 0;
}


int prp_adj_end(struct prparse *prp, ptrdiff_t amt)
{
  if ( !prp ) {
    errno = EINVAL;
    return -1;
  }
  if ( amt < 0 ) { 
    amt = -amt;
    if ( (amt < 0) || (amt > prp_tlen(prp)) ) {
      errno = EINVAL;
      return -1;
    }
    prp->eoff -= amt;
  } else {
    struct prparse *region = prp->region;
    if ( region == NULL ) {
      prp->eoff += amt;
    } else {
      /* verify that start offset can't go below region start offset */
      if ( (amt > region->eoff) || (region->eoff - amt < prp->eoff) ) {
        errno = EINVAL;
        return -1;
      }
      prp->eoff += amt;
    }
  }
  return 0;
}


int prp_adj_plen(struct prparse *prp, ptrdiff_t amt)
{
  if ( !prp ) {
    errno = EINVAL;
    return -1;
  }
  if ( amt < 0 ) { 
    amt = -amt;
    if ( (amt < 0) || (amt > prp_plen(prp)) ) {
      errno = EINVAL;
      return -1;
    }
    prp->toff -= amt;
    prp->eoff -= amt;
  } else {
    struct prparse *region = prp->region;
    if ( region == NULL ) {
      prp->toff += amt;
      prp->eoff += amt;
    } else {
      /* verify that start offset can't go below region start offset */
      if ( (amt > region->eoff) || (region->eoff - amt < prp->eoff) ) {
        errno = EINVAL;
        return -1;
      }
      prp->toff += amt;
      prp->eoff += amt;
    }
  }
  return 0;
}


int prp_fix_region(struct prparse *reg)
{
  struct prparse *prp;
  size_t ustart, uend;

  /* malformed parse if the region isn't of type PRP_NONE */
  if ( !reg ) {
    errno = EINVAL;
    return -1;
  }

  if ( prp_region_empty(reg) ) { /* zero parses in region */
    reg->poff = reg->hoff;
    reg->toff = reg->eoff;
  } else {
    /* at least one parse in the region */
    ustart = reg->eoff;
    uend = reg->hoff;
    abort_unless(ustart > uend);
    for ( prp = prp_next_in_region(reg, reg) ; prp != NULL ; 
          prp = prp_next_in_region(prp, reg) ) {
      if ( prp->hoff < ustart )
        ustart = prp->hoff;
      if ( prp->eoff > uend )
        uend = prp->eoff;
    }
    abort_unless(ustart <= uend);
    reg->poff = ustart;
    reg->toff = uend;
  }

  return 0;
}
