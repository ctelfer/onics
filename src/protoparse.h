#ifndef __prototparse_h
#define __prototparse_h
#include <cat/cat.h>
#include <cat/cattypes.h>
#include <cat/list.h>

#define PPT_NONE                0
#define PPT_ETHERNET		1
#define PPT_ARP			2
#define PPT_IPV4		3
#define PPT_IPV6		4
#define PPT_ICMP		5
#define PPT_ICMP6		6
#define PPT_UDP			7
#define PPT_TCP			8
#define PPT_MAX			127
#define PPT_INVALID             (PPT_MAX + 1)

#define PPERR_TOOSMALL          0x0001
#define PPERR_HLEN              0x0002
#define PPERR_LENGTH            0x0004
#define PPERR_CKSUM             0x0008
#define PPERR_OPTLEN            0x0010
#define PPERR_OPTERR            0x0020
#define PPERR_INVALID           0x0040 /* invalid combination of options */

#define PPERR_HLENMASK          (PPERR_TOOSMALL|PPERR_HLEN)

#define PPCF_FILL               1       /* push inner (fill completely) */
#define PPCF_WRAP               2       /* push outer (wrap tightly) */
#define PPCF_SET                3       /* push in middle (exact fit) */

struct hdr_parse;

struct pparse_ops {
  int			(*follows)(struct hdr_parse *phdr);
  struct hdr_parse *	(*parse)(struct hdr_parse *phdr);
  struct hdr_parse *	(*create)(byte_t *start, size_t hoff, size_t buflen,
                                  size_t poff, size_t plen, int mode);
};

struct proto_parser {
  unsigned int	        type;
  unsigned int	        valid;
  struct list  	        children;
  struct pparse_ops *   ops;
};

struct hparse_ops {
  void          (*update)(struct hdr_parse *hdr);
  size_t        (*getfield)(struct hdr_parse *hdr, unsigned fid, 
                            unsigned num, size_t *len);
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
  struct list           node;
  byte_t *              data;
  unsigned int          error;
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
#define hdr_payload(hdr) ((byte_t *)((hdr)->data + (hdr)->poff))
#define hdr_trailer(hdr, type) ((type *)((hdr)->data + (hdr)->toff))
#define hdr_parent(hdr) container((hdr)->node.prev, struct hdr_parse, node)
#define hdr_child(hdr) container((hdr)->node.next, struct hdr_parse, node)
#define hdr_islast(hdr) (hdr_child(hdr)->type == PPT_NONE)
#define hdr_isfirst(hdr) ((hdr)->type == PPT_NONE)

/* install a protocol parser to handle a particular protocol type */
int register_proto_parser(unsigned type, struct pparse_ops *ops);

/* make 'cldtype' protocol a child of 'partype' (e.g. TCP and IP) */
/* this will cause the protocol parser to call 'cldtype's 'follows' */
/* function when it see's a 'partype' header in order to see if the */
/* child follows the parent */
int add_proto_parser_parent(unsigned cldtype, unsigned partype);

/* deregister a protocol type */
void deregister_proto_parser(unsigned type);

/* install a default TCP/IP suite of protocol parsers */
/* This is shorthand for calling register_proto_parser() and */
/* add_proto_parser_parent() for the default protocol parsers. */
void install_default_proto_parsers();



/* Tests whether the 'cldtype' protocol can follow the 'partype' protocol */
/* according to parent/child relationships in the protocol parser. */
int hdr_can_follow(unsigned partype, unsigned cldtype);

/* Creates a 'default' header parse at buf + off given pktlen bytes to use */
struct hdr_parse *hdr_create_parse(byte_t *buf, size_t off, size_t pktlen, 
                                   size_t buflen);

/* Create a new header in a parsed packet.  The "mode" determines how this */
/* header is created.  if mode == PPCF_FILL, then 'hdr' must be the */
/* innermost header and the new header will fill inside the curent one. If */
/* the mode is PPCF_WRAP, then 'hdr' must be the outer 'NONE' header and */
/* the new header will wrap all the other protocol headers.  Finally, if */
/* mode is PPCF_SET, then the 'hdr' must be a header with free space between */
/* it and its child (based on the offsets above).  The new header will take */
/* up exactly the space between parent and child. */
int hdr_push(unsigned ppidx, struct hdr_parse *hdr, int mode);


/* Given a buffer and start offset and a first protocol parser to start with */
/* parse all headers as automatically as possible */
struct hdr_parse *hdr_parse_packet(unsigned firstpp, byte_t *pbuf, size_t off, 
                                   size_t pktlen, size_t buflen);

/* Free a header parse, or, if freechildren is non-zero, also free all child */
/* headers of the current header parse */
void hdr_free(struct hdr_parse *hdr, int freechildren);


/* copy a header parse (but not the packet buffer itself) */
struct hdr_parse *hdr_copy(struct hdr_parse *hdr, byte_t *buffer);

/* Associate a header parse with a new packet buffer (which must be sized */
/* correctly based on the header parse. */
void hdr_set_packet_buffer(struct hdr_parse *hdr, byte_t *buffer);

/* re-parse and update the fields in 'hdr'.  (but not its children */
/* returns error field as a matter of convenience */
unsigned int hdr_update(struct hdr_parse *hdr);

/* Get a variable position field in a header.  'fid' denotes the type */
/* of field.  'idx' denotes the index of the field starting from 0 */
/* the 'len' parameter returns the length of the field, while the  */
/* function returns the offset of the field starting from the */
/* beginning of 'hdr' */
size_t hdr_get_field(struct hdr_parse *hdr, unsigned fid, unsigned idx, 
                     size_t *len);

/* fix up checksums in the 'hdr' protocol header */
int hdr_fix_cksum(struct hdr_parse *hdr);

/* fix up length fields in the 'hdr' protocol header based on 'hdr' */
/* protocol metadata */
int hdr_fix_len(struct hdr_parse *hdr);

/* insert and delete data from the parse (and packet) */
/* NOTE: when inserting on the boundary between a payload and header or */
/* a payload and trailer, hdr_splice() always favors inserting into the */
/* payload section.  You can use hdr_adj_* to correct this later as needed. */
int hdr_insert(struct hdr_parse *hdr, size_t off, size_t len, int moveup);
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
