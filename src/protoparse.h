#ifndef __prototparse_h
#define __prototparse_h
#include <cat/cat.h>
#include <cat/cattypes.h>
#include <cat/list.h>

/*
   A PPT_NONE type parse just represents a parsed region of a buffer that
   is its own unit.  (e.g. a packet, a SSL record, etc..)  The header
   and trailer represents unused slack space in the region.  It gets updated
   on any header adjustment for enclosed parses.
*/
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
#define PPCF_WRAPFILL           3       /* push in middle (exact fit) */
/*
create semantics -- fill
  -- off is start of new proto parse
  -- len is total length to work with
  -- hlen, plen, ignored

create semantics -- wrap
  -- off is start of payload of wrapped parse
  -- len is ignored
  -- hlen is max header length
  -- plen is length of wrapped parse

create semantics -- set
  -- off is start of new proto parse
  -- len is hlen + plen + tlen (derives tlen)
  -- hlen is exact header length
  -- plen is exact payload length (wrapped region length)
*/

struct prparse;

struct proto_parser_ops {
  int			(*follows)(struct prparse *pprp);
  struct prparse *	(*parse)(struct prparse *pprp);
  struct prparse *	(*create)(byte_t *buf, long off, long len,
                                  long hlen, long plen, int mode);
};

struct proto_parser {
  unsigned int	        type;
  unsigned int	        valid;
  struct list  	        children;
  struct proto_parser_ops * ops;
};

struct prparse_ops {
  void          (*update)(struct prparse *prp);
  int           (*fixlen)(struct prparse *prp);
  int           (*fixcksum)(struct prparse *prp);
  struct prparse * (*copy)(struct prparse *, byte_t *buffer);
  void		(*free)(struct prparse *prp);
};


/*
 Start of 
 Packet Buffer
   |                    Encapsulating Protocol Parse
   |      par.offs[prp.rlow]                                par.offs[prp.rhi]
   | ...----+-------------------------------------------------------+----...
   |        |  prp.start   prp.poff             prp.toff  prp.end   |
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

/* 
   A 'prparse' structure denotes a decode of the region of a protocol as well
   as decode of its various fields.  All protocol parses at a minimum have a
   starting offset, a header, payload and trailer fields.  All of these are
   have a length in bytes, which can be 0.  The protocol parses associated
   with a particular buffer are ordered by their start offsets.  So, if the 
   header or trailer offset of a header parse change, the parse may have to be
   moved in the list. 
*/

enum {
  PRP_OI_SOFF,
  PRP_OI_POFF,
  PRP_OI_TOFF,
  PRP_OI_EOFF,
  PRP_OI_MIN_NUM,
  PRP_OI_EXTRA = PRP_OI_MIN_NUM,
};

struct prparse {
  unsigned int          type;
  unsigned int          error;
  struct prparse_ops *  ops;
  struct list           node;
  struct prparse *	region;
  byte_t *              data;
  uint                  noff;
  long                  offs[PRP_OI_MIN_NUM];
};
#define prp_soff(prp) ((prp)->offs[PRP_OI_SOFF])
#define prp_poff(prp) ((prp)->offs[PRP_OI_POFF])
#define prp_toff(prp) ((prp)->offs[PRP_OI_TOFF])
#define prp_eoff(prp) ((prp)->offs[PRP_OI_EOFF])
#define prp_hlen(prp) (prp_poff(prp) - prp_soff(prp))
#define prp_plen(prp) (prp_toff(prp) - prp_poff(prp))
#define prp_tlen(prp) (prp_eoff(prp) - prp_toff(prp))
#define prp_totlen(prp) (prp_eoff(prp) - prp_soff(prp))
#define prp_header(prp, type) ((type *)((prp)->data + prp_soff(prp)))
#define prp_payload(prp) ((byte_t *)((prp)->data + prp_poff(prp)))
#define prp_trailer(prp, type) ((type *)((prp)->data + prp_toff(prp)))
#define prp_prev(prp) container((prp)->node.prev, struct prparse, node)
#define prp_next(prp) container((prp)->node.next, struct prparse, node)
#define prp_list_head(prp) ((prp)->region == NULL)
#define prp_list_end(prp) ((prp)->region == NULL)

/* install a protocol parser to handle a particular protocol type */
int register_proto_parser(unsigned type, struct proto_parser_ops *ops);

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
int prp_can_follow(unsigned partype, unsigned cldtype);

/* Find the next parse in the specified region or return NULL if none */
/* exists in the parse list.  use the region parse as the 'from' for */
/* to start at the beginning of a region.  NOTE, that on its own, this */
/* does not find subregions within the region.  One can use a recursive */
/* or even iterative process with this function to walk all sub regions */
/* as well.  Recursive is more elegant.  :) */
/*
   Recursive example:
   walk(from, reg) {
     next = prp_next_in_region(from, reg);
     if (next != NULL) {
       ** do X with prp **
       walk(next, next);
       walk(next, reg);
     }
   }

   Iterative example: 
   curreg = reg;
   prp = prp_next_in_region(reg, reg);
   while ( prp != NULL ) {
     ** do whatever with prp **
     prp2 = prp_next_in_region(prp, prp);
     if ( prp2 != NULL ) { 
       curreg = prp;
       prp = prp2;
     } else {
       do { 
         prp2 = prp_next_in_region(prp, curreg);
         if (prp2 == NULL) {
	   ** done with this region, go up one **
	   curreg = prp->region;
	 } else {
	   prp = prp2;
	 }
       } while ( prp == NULL && curreg != reg->region );
     }
   }
 */
struct prparse *prp_next_in_region(struct prparse *from, struct prparse *reg);

/* returns 1 if a region contains no parses that refer to it */
int prp_region_empty(struct prparse *reg);

/* Creates a 'default' header parse at buf + off given len bytes to use. */
/* The "data portion" (i.e. the space the protocol data is expected to */
/* take up) is pktlen bytes.  There are hdrm bytes reserved from off for */
/* growing at the front of the parse.  */
struct prparse *prp_create_parse(byte_t *buf, long off, long len);

/* Create a new header in a parsed packet.  The "mode" determines how this */
/* header is created.  if mode == PPCF_FILL, then 'prp' must be the */
/* innermost header and the new header will fill inside the curent one. If */
/* the mode is PPCF_WRAP, then 'prp' must be the outer 'NONE' header and */
/* the new header will wrap all the other protocol headers.  Finally, if */
/* mode is PPCF_WRAPFILL, then the 'prp' must be a header with free space */
/* between it and its child (based on the offsets above).  The new header */
/* will take up exactly the space between parent and child. */
int prp_push(unsigned ppidx, struct prparse *prp, int mode);


/* Given a buffer and start offset and a first protocol parser to start with */
/* parse all headers as automatically as possible */
struct prparse *prp_parse_packet(unsigned firstpp, byte_t *pbuf, long off, 
				 long len);

/* Free a parse.  All sub regions of the parse are made part of prp's */
/* parent region.  If prp is a root region, this is the equivalent of */
/* prp_free_all() on the entire parse. */
void prp_free(struct prparse *prp);

/* Free a complete parse tree.  prp->region == NULL */
void prp_free_all(struct prparse *prp);

/* Free a header parse, or, if freechildren is non-zero, also free all child */
/* headers of the current header parse */
void prp_free_region(struct prparse *prp);


/* copy a header parse (but not the packet buffer itself) */
struct prparse *prp_copy(struct prparse *prp, byte_t *buffer);

/* Associate a header parse with a new packet buffer (which must be sized */
/* correctly based on the header parse). */
void prp_set_packet_buffer(struct prparse *prp, byte_t *buffer);

/* re-parse and update the fields in 'prp'.  (but not its children */
/* returns error field as a matter of convenience */
unsigned int prp_update(struct prparse *prp);

/* fix up checksums in the 'prp' protocol header */
int prp_fix_cksum(struct prparse *prp);

/* fix up length fields in the 'prp' protocol header based on 'prp' */
/* protocol metadata */
int prp_fix_len(struct prparse *prp);

/* insert and delete data from the parse (and packet) */
/* NOTE: when inserting on the boundary between a payload and header or */
/* a payload and trailer, prp_splice() always favors inserting into the */
/* payload section.  You can use prp_adj_* to correct this later as needed. */
int prp_insert(struct prparse *prp, long off, long len, int moveup);
int prp_cut(struct prparse *prp, long off, long len, int moveup);

/* expand or contract header/trailer within the encapsulating space */
/* Note that the point adjustments can't overrun their adjacent boundaries. */
/* prp_adj_plen() moves both the trailer offset and ending offset in unison. */
/* It basically acts as shorthand for a common case of adding or chopping */
/* payload to a particular packet. */
int prp_adj_off(struct prparse *prp, uint oid, long amt); /* adjust an offset */
int prp_adj_plen(struct prparse *prp, long amt); /* adjust C+D */

/* Adjust a region so that its payload starts on the first unused byte */
/* at the beginning and it's trailer starts on unused byte at the end. */
/* A byte is "used" if it falls within some parse within the region or */
/* a dependent sub region. */
int prp_adj_unused(struct prparse *prp);

#endif /* __protoparse_h */
