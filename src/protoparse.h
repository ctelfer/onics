#ifndef __prototparse_h
#define __prototparse_h
#include <cat/cat.h>
#include <cat/cattypes.h>

#define PPT_NONE                0
#define PPT_ETHERNET		1
#define PPT_ARP			2
#define PPT_IPV4		3
#define PPT_IPV6		4
#define PPT_ICMP		5
#define PPT_ICMP6		6
#define PPT_UDP			7
#define PPT_TCP			8
#define PPT_MAX			100

#define PPERR_LENGTH            0x00000001
#define PPERR_CKSUM             0x00000002
#define PPERR_OPTPARSE          0x00000004
#define PPERR_INVALID           0x00000008 /* invalid combination of options */

struct hdr_parse;

struct pparse_ops {
  int			(*follows)(struct hdr_parse *phdr);
  struct hdr_parse *	(*parse)(struct hdr_parse *phdr);
  void			(*free_parse)(struct hdr_parse *hdr);
};

struct proto_parser {
  unsigned int	        type;
  unsigned int	        valid;
  struct list *	        children;
  struct pparse_ops *   ops;
};

struct hparse_ops {
  byte_t *      (*getfield)(struct hdr_parse *hdr, unsigned fid, int num, 
                            size_t *len);
  void          (*fixcksum)(struct hdr_parse *hdr);
};

struct hdr_parse {
  unsigned int          type;
  struct hdr_parse *    parent;
  struct hdr_parse *    next;
  uint32_t              error;
  byte_t *              header;
  size_t                hlen;
  byte_t *              payload;
  size_t                plen;
  struct hparse_ops *   ops;
};

int  register_proto_parser(unsigned type, struct pparse_ops *ops);
int  add_proto_parser_parent(unsigned cldtype, unsigned partype);
void deregister_proto_parser(unsigned type);
struct hdr_parse *parse_packet(unsigned firstpp, byte_t *pkt, size_t pktlen);
void free_hdr_parse(struct hdr_parse *hdr);
void install_default_proto_parsers();

scalar_t hdr_get_field(struct hdr_parse *hdr, unsigned fid, size_t *len);
void hdr_fix_cksum(struct hdr_parse *hdr);

#endif /* __protoparse_h */
