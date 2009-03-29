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

#define PPERR_TOSMALL           0x00000001
#define PPERR_HLEN              0x00000002
#define PPERR_LENGTH            0x00000004
#define PPERR_CKSUM             0x00000008
#define PPERR_OPTLEN            0x00000010
#define PPERR_INVALID           0x00000020 /* invalid combination of options */

struct hdr_parse;

struct pparse_ops {
  int			(*follows)(struct hdr_parse *phdr);
  struct hdr_parse *	(*parse)(struct hdr_parse *phdr);
  struct hdr_parse *	(*create)(byte_t *start, size_t off, 
                                  size_t maxhlen, size_t minlen, 
                                  size_t maxlen);
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
  int           (*fixlen)(struct hdr_parse *hdr);
  int           (*fixcksum)(struct hdr_parse *hdr);
  struct hdr_parse * (*copy)(struct hdr_parse *, byte_t *buffer);
  void		(*free)(struct hdr_parse *hdr);
};


/*
 Start of 
 Packet Buffer
   |                    Encapsulating Protocol Parse
   |      poff                                                    toff
   | ...----+-------------------------------------------------------+----...
   |        |     hoff      poff                  toff   toff+tlen  |
   | header |      +---------+---------------------+---------+      | trailer
   |        |      | header  | payload             | trailer |      |
   |        |      +---------+---------------------+---------+      |
   |        |      A         B    ^                C         D      |  
   | ...----+---------------------)---------------------------------+----...
   |        \_____/               |                          \_____/
               |                  |                             |
         may be 0-length     possible encapsulated        may be 0-length
                             packet contained here
 */

struct hdr_parse {
  size_t                size; 
  unsigned int          type;
  struct hdr_parse *    parent;
  struct hdr_parse *    next;
  byte_t *              data;
  uint32_t              error;
  size_t                hoff;
  size_t                poff;
  size_t                toff;
  size_t                eoff;
  struct hparse_ops *   ops;
};
#define hdr_hlen(hdr) ((hdr)->poff - (hdr)->hoff)
#define hdr_plen(hdr) ((hdr)->toff - (hdr)->poff)
#define hdr_tlen(hdr) ((hdr)->eoff - (hdr)->toff)
#define hdr_totlen(hdr) ((hdr)->eoff - (hdr)->hoff)
#define hdr_header(hdr, type) ((type *)((hdr)->data + (hdr)->hoff))
#define hdr_payload(hdr) ((void *)((hdr)->data + (hdr)->poff))
#define hdr_trailer(hdr, type) ((type *)((hdr)->data + (hdr)->toff))

int register_proto_parser(unsigned type, struct pparse_ops *ops);
int add_proto_parser_parent(unsigned cldtype, unsigned partype);
void deregister_proto_parser(unsigned type);
void install_default_proto_parsers();

struct hdr_parse *parse_packet(unsigned firstpp, byte_t *pkt, size_t off, 
                               size_t pktlen);
int reparse_packet(struct hdr_parse *hdr);
struct hdr_parse *create_parse(unsigned ppidx, byte_t *pkt, size_t len,
                               size_t off, struct hdr_parse *pkthdr);


void hdr_free(struct hdr_parse *hdr, int freechildren);
size_t hdr_total_len(struct hdr_parse *hdr);
struct hdr_parse *hdr_copy(struct hdr_parse *hdr, byte_t *buffer);
void hdr_set_packet_buffer(struct hdr_parse *hdr, byte_t *buffer);
scalar_t hdr_get_field(struct hdr_parse *hdr, unsigned fid, size_t *len);
int hdr_fix_cksum(struct hdr_parse *hdr);
int hdr_fix_len(struct hdr_parse *hdr);
void hdr_remove(struct hdr_parse *hdr);

/* insert and delete data from the parse (and packet) */
/* NOTE: when inserting on the boundary between a payload and header or */
/* a payload and trailer, hdr_splice() always favors inserting into the */
/* payload section.  You can use hdr_adj_* to correct this later as needed. */
int hdr_splice(struct hdr_parse *hdr, size_t off, size_t len, int moveup);
int hdr_cut(struct hdr_parse *hdr, size_t off, size_t len, int moveup);

/* expand or contract header/trailer within the encapsulating space */
/* Note that the point adjustments can't overrun their adjacent boundaries */
/* EXCEPT for the case of hdr_adj_plen() which can overrun the trailer but */
/* not the encapsulationg protocol's payload boundary (of course) */
int hdr_adj_hstart(struct hdr_parse *hdr, ptrdiff_t amt); /* adjust A */
int hdr_adj_hlen(struct hdr_parse *hdr, ptrdiff_t amt); /* adjust B */
int hdr_adj_plen(struct hdr_parse *hdr, ptrdiff_t amt); /* adjust C */
int hdr_adj_tlen(struct hdr_parse *hdr, ptrdiff_t amt); /* adjust D */

#endif /* __protoparse_h */
