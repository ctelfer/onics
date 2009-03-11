#ifndef __prototparse_h
#define __prototparse_h
#include <cat/cat.h>

#define PPT_ETHERNET		0
#define PPT_ARP			1
#define PPT_IPV4		2
#define PPT_IPV6		3
#define PPT_ICMP		4
#define PPT_ICMP6		5
#define PPT_UDP			6
#define PPT_TCP			7
#define PPT_MAX			PPT_TCP

struct hdr_parse;

struct proto_parser {
  unsigned		type;
  struct list *		children;
  int			(*follows)(struct hdr_parse *parent);
  struct hdr_parse *	(*parse)(struct hdr_parse *parent, byte_t *start, 
                                 size_t maxlen);
  void			(*free_parse)(struct hdr_parse *parse);
};

struct hdr_parse {
  unsigned              type;
  struct hdr_parse *    parent;
  struct hdr_parse *    next;
  void *                (*get_header)();
  int                   (*has_field)(struct hdr_parse *hp, unsigned fid);
  scalar_t              (*get_field)(struct hdr_parse *hp, unsigned fid, 
		                     size_t *len);
  void                  (*set_sfield)(struct hdr_parse *hp, unsigned fid, 
                                      scalar_t val);
  void                  (*set_vfield)(struct hdr_parse *hp, unsigned fid,
                                      struct raw *val);
  void                  (*get_payload)(struct hdr_parse *hp, struct raw *data);
};

extern struct proto_parser *proto_parsers[];

int  register_proto_parser(struct proto_parser *pp, unsigned type);
int  add_proto_parser_parent(struct proto_parser *pp, unsigned type);
void deregister_proto_parser(struct proto_parser *pp);

struct hdr_parse *parse_packet(struct proto_parser *firstpp, byte_t *pkt, 
                               size_t pktlen);
void free_hdr_parse(struct hdr_parse *hp);

#endif /* __pktparse_h */
