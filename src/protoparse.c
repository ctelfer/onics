#include "protoparse.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>


static struct proto_parser *_pp_lookup(uint type);
static struct prparse *none_parse(struct prparse *pprp, uint *nextppt);
static struct prparse *none_create(byte_t *start, long off, long len,
                                   long hlen, long plen, int mode);

static struct proto_parser_ops none_proto_parser_ops = {
  none_parse, 
  none_create
};

struct proto_parser ieee_proto_parsers[PPT_PER_PF];
struct proto_parser net_proto_parsers[PPT_PER_PF];
struct proto_parser inet_proto_parsers[PPT_PER_PF];
struct proto_parser pp_proto_parsers[PPT_PER_PF] = { 
  { PPT_NONE, 1, &none_proto_parser_ops},
};



int pp_register(unsigned type, struct proto_parser_ops *ppo)
{
  struct proto_parser *pp;

  if ( (ppo == NULL) || (ppo->parse == NULL) || (ppo->create == NULL) ) {
    errno = EINVAL;
    return -1;
  }

  pp = _pp_lookup(type);
  if ( !pp ) {
    errno = EINVAL;
    return -1;
  }

  if ( pp->valid ) {
    errno = EACCES;
    return -1;
  }

  pp->type = type;
  pp->ops = ppo;
  pp->valid = 1;

  return 0;
}


static struct proto_parser *_pp_lookup(uint type)
{
  switch (PPT_FAMILY(type)) {
  case PPT_PF_INET:
    return &inet_proto_parsers[PPT_PROTO(type)];
  case PPT_PF_NET:
    return &net_proto_parsers[PPT_PROTO(type)];
  case PPT_PF_IEEE:
    return &ieee_proto_parsers[PPT_PROTO(type)];
  case PPT_PF_PP:
    if ( PPT_PROTO(type) >= PPT_PF_PP_RESERVED )
      return NULL;
    else
      return &pp_proto_parsers[PPT_PROTO(type)];
  default:
    return NULL;
  }
}


const struct proto_parser *pp_lookup(uint type)
{
  const struct proto_parser *pp = _pp_lookup(type);
  if ( pp && !pp->valid )
    pp = NULL;
  return pp;
}


int pp_unregister(uint type)
{
  struct proto_parser *pp;

  pp = _pp_lookup(type);
  if ( !pp ) {
    errno = EINVAL;
    return -1;
  }

  if ( !pp->valid ) {
    errno = EACCES;
    return -1;
  }

  pp->valid = 0;
  pp->ops = NULL;
  return 0;
}


/* -- ops for the "NONE" protocol type -- */

static void none_update(struct prparse *prp);
static int none_fixlen(struct prparse *prp);
static int none_fixcksum(struct prparse *prp);
static struct prparse *none_copy(struct prparse *oprp, byte_t *buffer);
static void none_free(struct prparse *prp);

static struct prparse_ops none_prparse_ops = {
  none_update,
  none_fixlen,
  none_fixcksum,
  none_copy,
  none_free
};


static struct prparse *none_parse(struct prparse *pprp, uint *nextppt)
{
  struct prparse *prp;

  abort_unless(pprp);
  abort_unless(nextppt);

  *nextppt = PPT_INVALID;
  prp = none_create(pprp->data, prp_poff(pprp), prp_plen(pprp),
                    0, prp_plen(pprp), PPCF_FILL);
  if ( prp != NULL ) {
    prp->region = pprp;
    l_ins(&pprp->node, &prp->node);
  }
  return prp;
}


static struct prparse *none_create(byte_t *start, long off, long len,
                                   long hlen, long plen, int mode)
{
  struct prparse *prp;

  abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);

  if ( mode != PPCF_FILL )
    return NULL;

  prp = malloc(sizeof(*prp));
  if ( !prp )
    return NULL;

  prp->type = PPT_NONE;
  prp->error = 0;
  prp->ops = &none_prparse_ops;
  l_init(&prp->node);
  prp->region = NULL;
  prp->data = start;
  prp->noff = PRP_OI_MIN_NUM;
  prp_soff(prp) = off;
  prp_eoff(prp) = prp_soff(prp) + len;
  prp_poff(prp) = prp_soff(prp) + hlen;
  prp_toff(prp) = prp_poff(prp) + plen;

  return prp;
}


static void none_update(struct prparse *prp)
{
}


static int none_fixlen(struct prparse *prp)
{
  return 0;
}


static int none_fixcksum(struct prparse *prp)
{
  return 0;
}


static struct prparse *none_copy(struct prparse *oprp, byte_t *buffer)
{
  return none_create(buffer, prp_soff(oprp), prp_totlen(oprp),
                     prp_hlen(oprp), prp_plen(oprp), PPCF_FILL);
}


static void none_free(struct prparse *prp)
{
  free(prp);
}



/* -- Protocol Parse Functions -- */
struct prparse *prp_next_in_region(struct prparse *from, struct prparse *reg)
{
  struct prparse *prp;
  abort_unless(from && reg);
  for ( prp = prp_next(from) ; 
        !prp_list_end(prp) && (prp_soff(prp) <= prp_eoff(reg)) ; 
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


struct prparse *prp_create_parse(byte_t *buf, long off, long len)
{
  if ( !buf || off < 0 || len < 0 ) {
    errno = EINVAL;
    return NULL;
  }
  return none_create(buf, off, len, 0, len, PPCF_FILL);
}


struct prparse *prp_parse_packet(unsigned ippt, byte_t *pkt, long off,
                                 long len)
{
  struct prparse *first, *prp;
  const struct proto_parser *pp;
  uint nextppt;
  int errval;

  pp = pp_lookup(ippt);
  if ( (off < 0) || (len < 0) || !pp ) {
    errno = EINVAL;
    return NULL;
  }

  if ( !(first = prp_create_parse(pkt, off, len)) )
    return NULL;

  prp = first;
  do { 
    nextppt = PPT_INVALID;
    if ( !(prp = (*pp->ops->parse)(prp, &nextppt)) ) {
      errval = errno;
      goto err;
    }
    /* don't continue parsing if the lengths are screwed up */
    if ( (prp->error & PPERR_HLENMASK) || !prp_plen(prp) ) 
      break;
    pp = pp_lookup(nextppt);
  } while ( pp );

  return first;

err:
  prp_free_all(first);
  errno = errval;
  return NULL;
}


int prp_push(unsigned ppidx, struct prparse *pprp, int mode)
{
  const struct proto_parser *pp;
  long off, len, plen, hlen;
  struct prparse *prp, *next;

  pp = pp_lookup(ppidx);
  if ( !pp || !pprp ) {
    errno = EINVAL;
    return -1;
  }

  off = prp_poff(pprp);
  len = prp_plen(pprp);
  if ( mode == PPCF_FILL ) {
    hlen = 0;
    plen = 0;
  } else if ( mode == PPCF_WRAP ) {
    long t;
    if ( prp_region_empty(pprp) ) {
      errno = EINVAL;
      return -1;
    }
    t = prp_soff(prp_next(pprp));
    hlen = t - off; 
    off = t;
    plen = prp_totlen(prp_next(pprp));
  } else if ( mode == PPCF_WRAPFILL ) {
    next = prp_next(pprp);
    /* make sure the list is non-empty and both prev and next are in the */
    /* same region.  Also, the previous parse must enclose the next parse */
    if ( (next == pprp) || (next->region != pprp) ) {
      errno = EINVAL;
      return -1;
    }
    hlen = prp_soff(next) - off; 
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


void prp_free(struct prparse *prp)
{
  struct prparse *next;
  if ( !prp )
    return;
  abort_unless(prp->ops && prp->ops->free);
  if ( prp->region == NULL ) {
    prp_free_all(prp);
    return;
  }
  for ( next = prp_next_in_region(prp, prp) ; next != NULL ; 
        next = prp_next_in_region(next, prp) )
    next->region = prp->region;
  l_rem(&prp->node);
  (*prp->ops->free)(prp);
}


void prp_free_all(struct prparse *prp)
{
  struct prparse *next, *prev;
  abort_unless(prp_list_head(prp));
  for ( next = prp_prev(prp) ; !prp_list_head(next) ; next = prev ) {
    abort_unless(next->ops && next->ops->free);
    prev = prp_prev(next);
    l_rem(&next->node);
    (*next->ops->free)(next);
  }
  abort_unless(prp->ops && prp->ops->free);
  l_rem(&prp->node);
  (*prp->ops->free)(prp);
}


static int parse_in_region(struct prparse *prp, struct prparse *reg)
{
  struct prparse *t = prp->region;
  while ( t != NULL ) { 
    if ( t == reg )
      return 1;
    t = t->region;
  }
  return 0;
}


/* This can be more elegantly coded with a recursive solution.  */
/* However, the hope is that this library could be used in a stack- */
/* constrained environment.  So, for now we prefer to do it */
/* iteratively.  */
void prp_free_region(struct prparse *prp)
{
  struct prparse *trav, *hold;

  if ( prp == NULL )
    return;

  /* find the last node potentially in the region */
  if ( prp->region == NULL ) {
    trav = prp_prev(prp); /* shortcut for root nodes */
  } else {
    hold = NULL;
    trav = prp_next(prp);
    while ( !prp_list_end(trav) && (prp_soff(trav) <= prp_eoff(prp)) ) {
      hold = trav;
      trav = prp_next(trav);
    }
    if ( hold == NULL )
      trav = prp;
    else
      trav = hold;
  }
  
  /* work backwards from last node potentially in the region */
  /* This is because working backwards we cannot delete a node */
  /* that might have a dangling region reference. */
  while ( trav != prp ) {
    hold = prp_prev(trav);
    if ( parse_in_region(trav, prp) ) { 
      abort_unless(trav->ops && trav->ops->free);
      l_rem(&trav->node);
      (*trav->ops->free)(trav);
    } 
    trav = hold;
  }

  abort_unless(prp->ops && prp->ops->free);
  l_rem(&prp->node);
  (*prp->ops->free)(prp);
}


struct prparse *prp_copy(struct prparse *oprp, byte_t *buffer)
{
  struct prparse *first = NULL, *trav, *last, *nprp, *oreg, *nreg;

  if ( !oprp || !buffer || oprp->region != NULL ) {
    errno = EINVAL;
    return NULL;
  }

  abort_unless(oprp->ops && oprp->ops->copy);
  if ( !(first = (*oprp->ops->copy)(oprp, buffer)) )
    goto err;

  for ( last = first, trav = prp_next(oprp) ; !prp_list_end(trav) ; 
        last = nprp, trav = prp_next(trav) ) {
    abort_unless(oprp->ops && oprp->ops->copy);
    if ( !(nprp = (*trav->ops->copy)(trav, buffer)) )
      goto err;
    l_ins(&last->node, &nprp->node);
  }

  /* patch up regions: recall that each parse (except the root parse) */
  /* MUST have a region that comes before it in the list. */
  for ( nprp = prp_next(first), trav = prp_next(oprp) ; 
        !prp_list_end(trav) ; 
        nprp = prp_next(nprp), trav = prp_next(trav) ) {
    oreg = prp_prev(trav);
    nreg = prp_prev(nprp);
    abort_unless(trav->region != NULL);
    while ( oreg != trav->region ) { 
      abort_unless(oreg != NULL);
      oreg = prp_prev(oreg);
      nreg = prp_prev(nreg);
    }
    nprp->region = nreg;
  }

  return first;

err:
  prp_free_all(first);
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


static void ubounds(struct prparse *reg, long *low, long *high)
{
  long uend = 0;
  struct prparse *prp;
  
  abort_unless(reg && low && high);

  prp = prp_next_in_region(reg, reg);
  if ( prp == NULL ) {
    /* zero parses in region */
    *low = prp_eoff(reg);
    *high = prp_soff(reg);
  } else {
    /* at least one parse in the region */
    *low = prp_soff(prp);
    for ( ; prp != NULL ; prp = prp_next_in_region(prp, reg) )
      if ( prp_eoff(prp) > uend )
        uend = prp_eoff(prp);
    abort_unless(*low <= uend);
    *high = uend;
    abort_unless(*low >= 0 && *high >= 0);
  }
}


int prp_insert(struct prparse *prp, long off, long len, int moveup)
{
  byte_t *op, *np;
  long mlen;
  long low, high;
  uint i;

  if ( prp == NULL || off < 0 || len < 0 ) {
    errno = EINVAL;
    return -1;
  }
  /* get the root region */
  while ( prp->region != NULL ) 
    prp = prp->region;
  /* find the lower and upper use boundaries */
  ubounds(prp, &low, &high);
  abort_unless(low >= 0 && high >= 0);
  if ( low >= high ) /* only happens on empty region */
    return 0;
  if ( (off < low) || (off > high) || 
       (moveup && (len > (prp_eoff(prp) - high))) || 
       (!moveup && (len > (low - prp_soff(prp)))) ) { 
    errno = EINVAL;
    return -1;
  }

  /* move the data */
  if ( prp->data != NULL ) {
    if ( moveup ) { 
      op = prp->data + off;
      np = op + len;
      mlen = prp_totlen(prp) - off;
    } else {
      op = prp->data + prp_soff(prp);
      np = op - len;
      mlen = off;
    }
    memmove(np, op, mlen);
    memset(op, 0x5F, len);
  }

  /* adjust all the offsets that should change */
  for ( prp = prp_next(prp) ; !prp_list_end(prp) ; prp = prp_next(prp) ) {
    if ( moveup ) {
      for ( i = 0 ; i < prp->noff ; ++i )
        if ( (prp->offs[i] != PRP_OFF_INVALID) && (prp->offs[i] >= off) )
          prp->offs[i] += len;
    } else {
      for ( i = 0 ; i < prp->noff ; ++i )
        if ( (prp->offs[i] != PRP_OFF_INVALID) && (prp->offs[i] < off) )
          prp->offs[i] -= len;
    }
  }

  return 0;
}


int prp_cut(struct prparse *prp, long off, long len, int moveup)
{
  byte_t *op, *np;
  long mlen;
  uint i;

  if ( prp == NULL || off < 0 || len < 0 ) {
    errno = EINVAL;
    return -1;
  }
  /* get the root region */
  while ( prp->region != NULL ) 
    prp = prp->region;
  if ( (off < prp_soff(prp)) || (off > prp_eoff(prp)) || 
       (len < prp_eoff(prp) - off) ) {
    errno = EINVAL;
    return -1;
  }

  if ( prp->data != NULL ) {
    if ( moveup ) {
      op = prp->data + prp_soff(prp);
      np = op + len;
      mlen = off - prp_soff(prp);
    } else {
      np = prp->data + off;
      op = np + len;
      mlen = (prp_eoff(prp) - off) - len;
    }
    memmove(np, op, mlen);
    if ( moveup )
      memset(op, 0x6e, len);
    else
      memset(np + mlen, 0x6e, len);
  }

  /* adjust all the offsets that should change */
  if ( moveup )
    off += len;
  for ( prp = prp_next(prp) ; !prp_list_end(prp) ; prp = prp_next(prp) ) {
    if ( moveup ) {
      for ( i = 0 ; i < prp->noff ; ++i )
        if ( (prp->offs[i] != PRP_OFF_INVALID) && (prp->offs[i] < off) )
          prp->offs[i] += len;
    } else {
      for ( i = 0 ; i < prp->noff ; ++i )
        if ( (prp->offs[i] != PRP_OFF_INVALID) && (prp->offs[i] >= off) )
          prp->offs[i] -= len;
    }
  }

  return 0;
}


int prp_adj_off(struct prparse *prp, uint oid, long amt)
{
  struct prparse *reg;
  struct prparse *trav;
  long newoff, blo, bhi;
  

  if ( !prp || (oid >= prp->noff) || (-amt == amt) ) {
    errno = EINVAL;
    return -1;
  }

  reg = prp->region;

  newoff = prp->offs[oid] + amt;

  switch (oid) {
  case PRP_OI_SOFF:
    if ( reg == NULL )
      blo = 0;
    else
      blo = prp_soff(reg);
    bhi = prp_poff(prp);
    break;
  case PRP_OI_POFF:
    blo = prp_soff(prp);
    bhi = prp_toff(prp);
    break;
  case PRP_OI_TOFF:
    blo = prp_poff(prp);
    bhi = prp_eoff(prp);
    break;
  case PRP_OI_EOFF:
    blo = prp_toff(prp);
    if ( reg == NULL )
      bhi = LONG_MAX;
    else
      bhi = prp_eoff(reg);
    break;
  default:
    blo = prp_soff(prp);
    bhi = prp_eoff(prp);
  }

  abort_unless(blo >= 0 && bhi >= 0);
  if ( (newoff < blo) || (newoff > bhi) )
    return -2;

  prp->offs[oid] = newoff;

  /* may need to adjust list placement */
  if ( (oid == PRP_OI_SOFF) && (reg != NULL) ) {
    trav = prp_prev(prp);
    if ( prp_soff(prp) < prp_soff(trav) ) {
      l_rem(&prp->node);
      do {
        trav = prp_prev(trav);
      } while ( prp_soff(prp) < prp_soff(trav) );
      l_ins(&trav->node, &prp->node);
    } else { 
      trav = prp_next(prp);
      if ( !prp_list_end(trav) && (prp_soff(prp) > prp_soff(trav)) ) {
        l_rem(&prp->node);
        do {
          trav = prp_next(trav);
        } while ( !prp_list_end(trav) && (prp_soff(prp) > prp_soff(trav)) );
        l_ins(trav->node.prev, &prp->node);
      }
    }
  }

  return 0;
}


int prp_adj_plen(struct prparse *prp, long amt)
{
  int rv;

  /* Note that if we move the trailer offset down successfully there should */
  /* be no reason we can't move the end offset down as well.  The same works */
  /* in reverse for moving the end and trailer offsets forward.  */
  if ( amt < 0 ) {
    if ( prp_adj_off(prp, PRP_OI_TOFF, amt) < 0 )
      return -2;
    rv = prp_adj_off(prp, PRP_OI_EOFF, amt);
    abort_unless(rv >= 0);
  } else {
    if ( prp_adj_off(prp, PRP_OI_EOFF, amt) < 0 )
      return -2;
    rv = prp_adj_off(prp, PRP_OI_TOFF, amt);
    abort_unless(rv >= 0);
  }

  return 0;
}


int prp_adj_unused(struct prparse *reg)
{
  long ustart, uend;

  /* malformed parse if the region isn't of type PRP_NONE */
  if ( !reg ) {
    errno = EINVAL;
    return -1;
  }

  ubounds(reg, &ustart, &uend);
  if ( ustart > uend ) { 
    prp_poff(reg) = prp_soff(reg);
    prp_toff(reg) = prp_eoff(reg);
  } else {
    prp_poff(reg) = ustart;
    prp_toff(reg) = uend;
  }

  return 0;
}
