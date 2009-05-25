#ifndef __namespace_h
#define __namespace_h
#include <cat/cat.h>
#include <cat/rbtree.h>
#include <cat/list.h>

#define NSTYPE_ANY              -1
#define NSTYPE_NS               1
#define NSTYPE_FIELD            2
#define NSTYPE_SCALAR           3       /* exact scalar value */
#define NSTYPE_RAW              4       /* exact raw value */
#define NSTYPE_MASKED           5       /* masked raw value */
#define NSTYPE_SRANGE           6       /* scalar range */
#define NSTYPE_RRANGE           7       /* big endian binary range*/

#define NSTYPE_ISVALUE(t) (((t) >= NSTYPE_SCALAR) && ((t) <= NSTYPE_RRANGE))
#define NSTYPE_VALUE            8       /* not an actual type, but used */
                                        /* during lookups for SCALAR through */
                                        /* RRANGE types */

struct ns_element {
  int                   nstype;         /* NST_* */
  int                   id;
  char *                name;
  struct ns_namespace * parent;
};

/* 
 * a namespace has: 
 *   a unique name
 *   a table of fields, values and sub-namespaces (elements)
 * When we refer to fields or values in a namespace we use the following
 * notation:  "ns1.ns2...nsn.fieldorvalue".  Note that fields and values share
 * the same namespace and so do sub-namespaces.  (i.e. these will be checked
 * for uniqueness)
 */
struct ns_namespace {
  int                   nstype;         /* always NST_NS */
  int                   id;
  char *                name;
  struct ns_namespace * parent;
  struct rbtree *       nametab;
  struct rbtree *       idtab;
};


/*
 * A named field represents a fixed position field within some memory structure
 * (e.g. a protocol header). 
 */
struct ns_field {
  int                   nstype;         /* always NST_FIELD */
  int                   id;
  char *                name;
  struct ns_namespace * parent;
  int                   inbits;
  size_t                off;
  size_t                size;
};


struct ns_rrange {
  struct raw *          low;
  struct raw *          high;
};


struct ns_srange {
  unsigned long         low;
  unsigned long         high;
};


struct ns_scalar {
  int                   nstype;         /* NST_SCALAR */
  int                   id;
  const char *          name;
  struct ns_namespace * parent;
  unsigned long         value;
};


struct ns_rawval {
  int                   nstype;         /* NST_RAW */
  int                   id;
  const char *          name;
  struct ns_namespace * parent;
  struct raw *          value;
};


struct ns_masked {
  int                   nstype;         /* NST_MASKED */
  int                   id;
  const char *          name;
  struct ns_namespace * parent;
  struct raw *          value;
  struct raw *          mask;
};


struct ns_ranges {
  int                   nstype;         /* NST_SRANGE | NST_RRANGE */
  int                   id;
  const char *          name;
  struct ns_namespace * parent;
  size_t                len;
  struct list *         ranges;
};


/* 
 * if type >= 0, then only return non-null if the type of the element matches
 * the type provided.  The caller can pass in NSTYPE_VALUE for all value types.
 */
struct ns_namespace *ns_new_namespace(const char *name, int id);
int ns_insert(struct ns_namespace *ns, struct ns_element *elem);
void ns_remove(struct ns_element *elem);
struct ns_field *ns_new_field(const char *name, size_t off, size_t len);
struct ns_field *ns_new_bitfield(const char *name, size_t off, size_t len);

struct ns_scalar *ns_new_scalar(const char *name, unsigned long val);
struct ns_rawval *ns_new_raw(const char *name, struct raw *val);
struct ns_masked *ns_new_masked(const char *name, struct raw *val, 
                                struct raw *mask);
struct ns_masked *ns_new_prefixed(const char *name, struct raw *val,size_t len);
struct ns_ranges *ns_new_srange(const char *name, unsigned long low, 
                                unsigned long high);
void ns_add_srange(struct ns_ranges *ranges, unsigned long low, 
                   unsigned long high);
struct ns_ranges *ns_new_rrange(const char *name, struct raw *low, 
                                struct raw *high);
void ns_add_rrange(struct ns_ranges *ranges, struct raw *low, struct raw *high);
void ns_free(struct ns_element *elem);


int ns_register(struct ns_namespace *ns);
struct ns_element *ns_name_lookup(struct ns_namespace *ns, const char *name, 
                                  int type);
struct ns_element *ns_id_lookup(struct ns_namespace *ns, int *id, int nids, 
                                int type);
int ns_cmp_scalar(struct ns_element *elem, unsigned long val);
int ns_cmp_raw(struct ns_element *elem, void *p, size_t len);


#endif /* __namespace_h */
