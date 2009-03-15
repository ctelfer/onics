#include "protoparse.h"
#include "pptcpip.h"
#include <errno.h>
#include <cat/stduse.h>


struct proto_parser proto_parsers[PPT_MAX+1];
struct pparse_ops proto_parser_ops[PPT_MAX+1];


int register_proto_parser(unsigned type, struct pparse_ops *ppo)
{
  struct proto_parser *pp;
  if ( (type > PPT_MAX) || (ppo == NULL) || (ppo->follows == NULL) || 
       (ppo->parse == NULL) || (ppo->free_parse == NULL) ) {
    errno = EINVAL;
    return -1;
  }
  pp = &proto_parsers[type];
  if ( !pp->valid ) {
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
  par = &proto_parsers[cldtype];
  cld = &proto_parsers[partype];
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


static struct hdr_parse *parse_packet_help(struct proto_parser *thispp,
                                           struct hdr_parse *parhp)
{
  struct proto_parser *nextpp;
  struct hdr_parse *newhp = NULL;
  struct list *child;
  struct raw rest;
  unsigned cldid;
  if ( !(newhp = (*thispp->ops->parse)(parhp)) )
    return NULL;
  newhp->next = NULL;
  if ( newhp->error != 0 ) {
    l_for_each(child, thispp->children) {
      cldid = clist_data(child, unsigned);
      abort_unless(cldid <= PPT_MAX);
      nextpp = &proto_parsers[cldid];
      if ( (*nextpp->ops->follows)(newhp) ) {
        newhp->next = parse_packet_help(nextpp, newhp);
        break;
      }
    }
  }
  return newhp;
}


struct hdr_parse *parse_packet(unsigned firstpp, byte_t *pkt, size_t pktlen)
{
  struct hdr_parse hdr = { 0 }, *outh;
  if ( firstpp > PPT_MAX ) {
    errno = EINVAL;
    return NULL;
  }
  hdr.type = PPT_NONE;
  hdr.payload = pkt;
  hdr.plen = pktlen;
  outh = parse_packet_help(&proto_parsers[firstpp], &hdr);
  outh->parent = NULL;
  return outh;
}


void free_hdr_parse(struct hdr_parse *hp)
{
  struct proto_parser *pp;
  if ( hp == NULL )
    return;
  free_hdr_parse(hp->next);
  if ( (hp->type > PPT_MAX) || !(pp = &proto_parsers[hp->type])->valid )
    (*pp->ops->free_parse)(hp);
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
  register_proto_parser(PPT_ICMP6, &icmpv6_pparse_ops);
  add_proto_parser_parent(PPT_ICMP6, PPT_IPV6);
  register_proto_parser(PPT_UDP, &udp_pparse_ops);
  add_proto_parser_parent(PPT_UDP, PPT_IPV4);
  add_proto_parser_parent(PPT_UDP, PPT_IPV6);
  register_proto_parser(PPT_TCP, &udp_pparse_ops);
  add_proto_parser_parent(PPT_TCP, PPT_IPV4);
  add_proto_parser_parent(PPT_TCP, PPT_IPV6);
}



byte_t *hdr_getfield(struct hdr_parse *hp, unsigned fid, int num, size_t *len)
{
  abort_unless(hp && hp->ops);
  return (*hp->ops->getfield)(hp, fid, num, len);
}


void hdr_fix_cksum(struct hdr_parse *hp)
{
  abort_unless(hp && hp->ops);
  (*hp->ops->fixcksum)(hp);
}



