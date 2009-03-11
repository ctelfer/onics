#include "protoparse.h"
#include <errno.h>
#include <cat/stduse.h>

struct proto_parser *proto_parsers[PPT_MAX+1] = { 0 };

int register_proto_parser(struct proto_parser *pp, unsigned type)
{
  if ( type > PPT_MAX ) {
    errno = EINVAL;
    return -1;
  }
  if ( proto_parsers[type] != NULL ) {
    errno = EACCES;
    return -1;
  }
  pp->type = type;
  pp->children = clist_newlist();
  proto_parsers[type] = pp;
  return 0;
}


int add_proto_parser_parent(struct proto_parser *pp, unsigned type)
{
  struct proto_parser *par;
  if ( (type > PPT_MAX) || (par = proto_parsers[type]) == NULL ) {
    errno = EINVAL;
    return -1;
  }
  clist_enq(par->children, struct proto_parser *, pp);
  return 0;
}


void deregister_proto_parser(struct proto_parser *pp)
{
  if ( (pp->type > PPT_MAX) || (proto_parsers[pp->type] != pp) )
    return;
  clist_freelist(pp->children);
  pp->children = NULL;
  proto_parsers[pp->type] = NULL;
}


static struct hdr_parse *parse_packet_help(struct proto_parser *thisp,
             struct hdr_parse *parp,
             byte_t *pkt, size_t pktlen)
{
  struct hdr_parse *newp;
  struct proto_parser *nextp;
  struct list *child;
  struct raw rest;
  if ( !(newp = (*thisp->parse)(parp, pkt, pktlen)) )
    return NULL;
  (*newp->get_payload)(newp, &rest);
  l_for_each(child, thisp->children) {
    nextp = clist_data(child, struct proto_parser *);
    if ( (*nextp->follows)(newp) ) {
      newp->next = parse_packet_help(nextp, newp, rest.data, 
                         rest.len);
      break;
    }
  }
  return newp;
}


struct hdr_parse *parse_packet(struct proto_parser *firstproto, byte_t *pkt, 
             size_t pktlen)
{
  return parse_packet_help(firstproto, NULL, pkt, pktlen);
}


void free_hdr_parse(struct hdr_parse *hp)
{
  struct proto_parser *pp;
  if ( hp == NULL )
    return;
  free_hdr_parse(hp->next);
  if ( (hp->type <= PPT_MAX) && ((pp = proto_parsers[hp->type]) != NULL) )
    (*pp->free_parse)(hp);

}

