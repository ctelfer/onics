#include "namespace.h"
#include <cat/stduse.h>

struct ns_namespace rootns = { NSTYPE_NS, 0, ".", NULL, NULL, NULL };

#define TYPEOK(t) ((t) >= NSTYPE_NS && (t) <= NSTYPE_RRANGE)


struct ns_element *ns_lookup(const char *name, int type)
{
  struct ns_namespace *ns;
  struct ns_element *elem = (struct ns_element *)&rootns;
  char *s, *p, *e;
  abort_unless(name);
  if ( !rootns.nametab )
    return NULL;
  p = s = estrdup(name);
  do { 
    if ( elem->nstype != NSTYPE_NS ) {
      elem = NULL;
      break;
    }
    if ( (e = strchr(p, '.')) )
      *e++ = '\0';
    ns = (struct ns_namespace *)elem;
    if ( !(elem = ht_get(ns, p)) )
      break;
    p = e;
  } while ( p != NULL );

  if ( elem && (type > 0) ) {
    if ( (type != elem->nstype) &&
         ((type != NSTYPE_VALUE) || !NSTYPE_ISVALUE(elem->nstype)) )
      elem = NULL;
  }

  free(s);
  return elem;
}


struct ns_element *ns_id_lookup(int *ida, int nids, int type)
{
  struct ns_namespace *ns;
  struct ns_element *elem = (struct ns_element *)&rootns;

  abort_unless(ida && nids > 0);
  if ( !rootns.nametab )
    return NULL;

  while ( nids > 0 ) {
    if ( elem->nstype != NSTYPE_NS )
      return NULL;
    ns = (struct ns_namespace *)elem;
    if ( !(elem = rb_get(ns->idtab, (void *)*ida)) )
      return NULL;
    --nids;
    ++ida;
  }

  if ( elem && (type > 0) ) {
    if ( (type != elem->nstype) &&
         ((type != NSTYPE_VALUE) || !NSTYPE_ISVALUE(elem->nstype)) )
      elem = NULL;
  }

  return elem;
}



int ns_register(struct ns_namespace *ns)
{
  if ( !rootns.nametab ) {
    root.nametab = rb_new(CAT_DT_STR);
    root.idtab = rb_new(CAT_DT_STR);
  }
  return ns_insert(&rootns, (struct ns_element *)ns);
}


int ns_insert(struct ns_namespace *ns, struct ns_element *elem)
{
  abort_unless(ns && ns->nametab && ns->idtab && elem && elem->name &&
               TYPEOK(elem->nstype));
  if ( rb_get(ns->nametab, elem->name) )
    return -1;
  if ( (elem->id >= 0) && rb_get(ns->idtab, elem->id) )
    return -1;
  rb_put(ns->nametab, ns->name, elem);
  if ( elem->id >= 0 )
    rb_put(ns->idtab, (void *)ns->id, elem);
  elem->parent = ns;
  return 0;
}


void ns_remove(struct ns_element *elem)
{
  struct ns_namespace *ns;
  abort_unless(elem && elem->parent);
  ns = elem->parent;
  abort_unless(ht_get(ns->nametab, elem->name) == elem);
  ht_clr(ns->nametab, elem->name);
  if ( elem->id >= 0 ) {
    abort_unless(ht_get(ns->idtab, (void *)elem->id) == elem);
    ht_clr(ns->idtab, (void *)elem->id);
  }
}


struct ns_namespace *ns_new_namespace(const char *name, int id)
{
  struct ns_namespace *ns;
  abort_unless(name);
  ns = emalloc(sizeof(struct ns_namespace));
  ns->nstype = NSTYPE_NS;
  ns->name = estrdup(name);
  ns->id = 1;
  ns->namemap = rb_new(CAT_DT_STR);
  ns->idmap = rb_new(CAT_DT_NUM);
  ns->parent = NULL;
  return ns;
}


struct ns_field *ns_new_field_h(const char *name, size_t off, size_t len, 
                                int inbits)
{
  struct ns_field *field;
  abort_unless(name);
  field = emalloc(sizeof(struct ns_field));
  field->nstype = NSTYPE_FIELD;
  field->id = 1;
  field->parent = NULL;
  field->name = estrdup(name);
  field->inbits = inbits;
  field->off = off;
  field->len = len;
  return field;
}

struct ns_field *ns_new_field(const char *name, size_t off, size_t len)
{
  return ns_new_field_h(name, off, len, 0);
}


struct ns_field *ns_new_bitfield(const char *name, size_t off, size_t len)
{
  return ns_new_field_h(name, off, len, 1);
}



struct ns_scalar *ns_new_scalar(const char *name, unsigned long val)
{
  struct ns_scalar *sclr;
  abort_unless(name);
  sclr = emalloc(sizeof(struct ns_scalar));
  sclr->nstype = NSTYPE_SCALAR;
  sclr->id = -1;
  sclr->name = estrdup(name);
  sclr->parent = NULL;
  sclr->value = val;
  return sclr;
}


struct ns_rawval *ns_new_raw(const char *name, struct raw *val)
{
  struct ns_rawval *rawval;
  abort_unless(name && val && val->data);
  rawval = emalloc(sizeof(struct ns_rawval));
  rawval->nstype = NSTYPE_RAW;
  rawval->id = -1;
  rawval->name = estrdup(name);
  retval->parent = NULL;
  rawval->ralue = erawdup(val);
  return rawval;
}


struct ns_masked *ns_new_masked(const char *name, struct raw *val, 
                                struct raw *mask)
{
  struct ns_masked *masked;
  abort_unless(name && val && val->data && mask && mask->data &&
               val->len == mask->len);
  masked = emalloc(sizeof(struct ns_masked));
  masked->nstype = NSTYPE_MASKED;
  masked->id = -1;
  masked->name = estrdup(name);
  masked->parent = NULL;
  masked->value = erawdup(val);
  masked->mask = erawdup(mask);
  return masked;
}


struct ns_masked *ns_new_prefixed(const char *name, struct raw *val, size_t len)
{
  struct ns_masked *masked;
  size_t n;
  abort_unless(name && val && val->data && mask && mask->data && (val->len > 0)
               (val->len <= len * 8));
  masked = emalloc(sizeof(struct ns_masked));
  masked->nstype = NSTYPE_MASKED;
  masked->id = -1;
  masked->name = estrdup(name);
  masked->parent = NULL;
  masked->value = erawdup(val);
  masked->mask = erawdup(val);
  n = (len + 7) / 8;
  memset(masked->mask, 0xff, n - 1);
  masked->mask->data[n-1] = -(1 << (8 - len % 8));
  if ( n < masked->mask->len )
    memset(&masked->mask->data[n], 0, masked->mask->len - n);
  return masked;
}


struct ns_ranges *ns_new_srange(const char *name, unsigned long low, 
                                unsigned long high)
{
  struct ns_ranges *ranges;
  struct ns_srange sr;
  abort_unless(name && low <= high);
  ranges->emalloc(sizeof(struct ns_ranges));
  ranges->nstype = NSTYPE_SRANGE;
  ranges->id = -1;
  ranges->name = estrdup(name);
  ranges->parent = NULL;
  ranges->ranges = clist_newlist();
  sr.low = low;
  sr.high = high;
  clist_enq(ranges->ranges, struct ns_srange, sr);
  return ranges;
}


void ns_add_srange(struct ns_ranges *ranges, unsigned long low, 
                   unsigned long high)
{
  struct ns_srange sr;
  abort_unless(ranges && low <= high && ranges->ranges &&
               ranges->nstype == NSTYPE_SRANGE);
  sr.low = low;
  sr.high = high;
  clist_enq(ranges->ranges, struct ns_srange, sr);
}


struct ns_ranges *ns_new_rrange(const char *name, struct raw *low, 
                                struct raw *high)
{
  struct ns_ranges *ranges;
  struct ns_rrange rr;
  size_t n;
  abort_unless(name && low && high && (low->len == high->len) &&
               (low->len > 0));
  for ( n = 0; n < low->len; ++n ) {
    if ( low->data[n] != high->data[n] ) {
      abort_unless(low->data[n] < high->data[n]);
      break;
    }
  }
  ranges->emalloc(sizeof(struct ns_ranges));
  ranges->nstype = NSTYPE_SRANGE;
  ranges->id = -1;
  ranges->name = estrdup(name);
  ranges->parent = NULL;
  ranges->ranges = clist_newlist();
  rr->low = erawdup(low);
  rr->high = erawdup(high);
  clist_enq(ranges->ranges, struct ns_rrange, rr);
  return ranges;
}


void ns_add_rrange(struct ns_ranges *ranges, struct raw *low, struct raw *high)
{
  struct ns_rrange rr;
  size_t n;
  abort_unless(ranges && low && high && (low->len == high->len) &&
               (low->len > 0));
  for ( n = 0; n < low->len; ++n ) {
    if ( low->data[n] != high->data[n] ) {
      abort_unless(low->data[n] < high->data[n]);
      break;
    }
  }
  rr->low = erawdup(low);
  rr->high = erawdup(high);
  clist_enq(ranges->ranges, struct ns_rrange, rr);
}


static void ns_apply_free(void *p, void *aux)
{
  (void)aux;
  ns_free(p);
}



void ns_free(struct ns_element *elem)
{
  abort_unless(elem && TYPEOK(elem->nstype));
  free(elem->name);
  switch(elem->nstype) {
  case NSTYPE_NS: {
    struct ns_namespace *ns = (struct ns_namespace *)elem;
    rb_apply(ns->nametab, ns_apply_free, NULL);
    rb_free(ns->nametab);
    rb_free(ns->idtab);
  } break;
  case NSTYPE_FIELD:
  case NSTYPE_SCALAR:
    break;
  case NSTYPE_RAW: {
    struct ns_rawval *rawval = (struct ns_rawval *)elem;
    free(rawval->value);
  } break;
  case NSTYPE_MASKED: {
    struct ns_masked *masked = (struct ns_masked *)elem;
    free(rawval->value);
    free(rawval->mask);
  } break;
  case NSTYPE_SRANGE: {
    struct ns_ranges *ranges = (struct ns_ranges *)elem;
    clist_freelist(ranges->ranges);
  } break;
  case NSTYPE_RRANGE: {
    struct ns_ranges *ranges = (struct ns_ranges *)elem;
    while ( !clist_isempty(ranges->ranges) ) {
      struct ns_rrange rr = clist_qnext(ranges->ranges, struct ns_ranges);
      clist_deq(ranges->ranges);
      free(rr->low);
      free(rr->high);
    }
    clist_freelist(ranges->ranges);
  } break;
  }
  free(elem);
}


