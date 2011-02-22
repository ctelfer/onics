#ifndef __prototparse_h
#define __prototparse_h
#include <cat/cat.h>
#include <cat/cattypes.h>
#include <cat/list.h>

#define PPT_PROTO(ppt)		((ppt) & 0xFF)
#define PPT_FAMILY(ppt)		(((ppt) >> 8) & 0xFF)
#define PPT_BUILD(pf, proto)	((((pf) & 0xFF) << 8) | ((proto) & 0xFF))

/* Protocol Families */
#define PPT_PF_INET		0
#define PPT_PF_NET		1
#define PPT_PF_DLT		2
#define PPT_PF_PP		255
#define PPT_PER_PF		256

/*
   A PPT_NONE type parse just represents a parsed region of a buffer that
   is its own unit.  (e.g. a packet, a SSL record, etc..)  The header
   and trailer represents unused slack space in the region.  It gets updated
   on any header adjustment for enclosed parses.
   
   Parse types for family _PP indices 128-255 are reserved 
   "meta parse types".  They stand for entire classes of packets.
*/
#define PPT_NONE                PPT_BUILD(PPT_PF_PP, 0)
#define PPT_PF_PP_RESERVED	128
#define PPT_PCLASS_LINK		PPT_BUILD(PPT_PF_PP, 128)
#define PPT_PCLASS_TUNNEL	PPT_BUILD(PPT_PF_PP, 129)
#define PPT_PCLASS_NET		PPT_BUILD(PPT_PF_PP, 130)
#define PPT_PCLASS_XPORT	PPT_BUILD(PPT_PF_PP, 131)
#define PPT_USER1		PPT_BUILD(PPT_PF_PP, 192)
#define PPT_USER2		PPT_BUILD(PPT_PF_PP, 193)
#define PPT_USER3		PPT_BUILD(PPT_PF_PP, 194)
#define PPT_USER4		PPT_BUILD(PPT_PF_PP, 195)
#define PPT_USER5		PPT_BUILD(PPT_PF_PP, 196)
#define PPT_USER6		PPT_BUILD(PPT_PF_PP, 197)
#define PPT_USER7		PPT_BUILD(PPT_PF_PP, 198)
#define PPT_USER8		PPT_BUILD(PPT_PF_PP, 199)
#define PPT_ANY			PPT_BUILD(PPT_PF_PP, 254)
#define PPT_INVALID             PPT_BUILD(PPT_PF_PP, 255)

#define PPT_IS_PCLASS(ppt) \
  (((ppt) & PPT_BUILD(PPT_PF_PP, 252)) == PPT_BUILD(PPT_PF_PP, 128))


#define PPERR_TOOSMALL          0x0001
#define PPERR_HLEN              0x0002
#define PPERR_LENGTH            0x0004
#define PPERR_CKSUM             0x0008
#define PPERR_OPTLEN            0x0010
#define PPERR_OPTERR            0x0020
#define PPERR_INVALID           0x0040	/* invalid combination of options */

#define PPERR_HLENMASK          (PPERR_TOOSMALL|PPERR_HLEN)

#define PPCF_FILL               1	/* push inner (fill completely) */
#define PPCF_WRAP               2	/* push outer (wrap tightly) */
#define PPCF_WRAPFILL           3	/* push in middle (exact fit) */
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
	struct prparse *	(*parse)(struct prparse * pprp, uint *nextppt);

	struct prparse *	(*create)(byte_t * buf, ulong off, ulong len,
					  ulong hlen, ulong plen, int mode);
};

struct proto_parser {
	uint			type;
	uint			valid;
	struct proto_parser_ops *ops;
};

/* install a protocol parser to handle a particular protocol type */
int pp_register(uint type, struct proto_parser_ops *ops);

/* Get a protocol parser by type */
const struct proto_parser *pp_lookup(uint type);

/* unregister a protocol type */
int pp_unregister(uint type);



struct prparse_ops {
	void			(*update)(struct prparse * prp);
	int			(*fixlen)(struct prparse * prp);
	int			(*fixcksum)(struct prparse * prp);
	struct prparse *	(*copy)(struct prparse *, byte_t * buffer);
	void			(*free)(struct prparse * prp);
};


/*
 Start of 
 Packet Buffer
   |                    Encapsulating Protocol Parse
   |     par.poff                                                par.toff
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

/*
   A note for IPv6 and IPsec.  When an IPv6 packet has an ESP or AH header,
   that header is considered the start of the payload of the v6 packet.  It
   This is a specific example where the abstraction of encapsulating protocol
   parses breaks down.  IPsec is, in many ways, its own set of protocols that
   encapuslate data.  It is convenient to treat them as such.  However, IPv6
   destination options CAN come after the IPsec headers.  In the case of ESP
   with encryption, this is not data that we can parse anyways.  Nevertheless
   this won't always be the case.  Given this kind of "call" on how to
   interpret the fields, the "payload offset" is, therefore, the first byte
   of the protocol unit that isn't the purview of the encapsulating protocol.
   This does NOT always mean that there can't be protocol relevant bytes
   in the payload section.  But it won't typically be the case.
 */


#define PRP_OI_SOFF 0
#define PRP_OI_POFF 1
#define PRP_OI_TOFF 2
#define PRP_OI_EOFF 3
#define PRP_OI_MIN_NUM 4
#define PRP_OI_EXTRA PRP_OI_MIN_NUM
#define PRP_OFF_INVALID ((ulong)-1)


struct prparse {
	uint			type;
	uint			error;
	struct prparse_ops *	ops;
	struct list		node;
	struct prparse *	region;
	byte_t *		data;
	uint			noff;
	ulong			offs[PRP_OI_MIN_NUM];
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
#define prp_empty(prp) (l_isempty(&(prp)->node))

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

/* Create a new header in a parsed packet.  The "mode" determines how this */
/* header is created.  if mode == PPCF_FILL, then 'prp' must be the */
/* innermost header and the new header will fill inside the curent one. If */
/* the mode is PPCF_WRAP, then 'prp' must be the outer 'NONE' header and */
/* the new header will wrap all the other protocol headers.  Finally, if */
/* mode is PPCF_WRAPFILL, then the 'prp' must be a header with free space */
/* between it and its child (based on the offsets above).  The new header */
/* will take up exactly the space between parent and child. */
int prp_push(uint ppidx, struct prparse *prp, int mode);


/* Initializes a fresh parse of PPT_NONE.  This can be used to create the */
/* base for a full parse. */
void prp_init_parse(struct prparse *base, byte_t *buf, ulong len);

/* Given an initialized protocol parse header for a buffer (PPT_NONE) and */
/* an initial protocol parse type, parse the packet and add to the list */
/* of PRPs.  Returns -1 on an allocation error.  Otherwise, parse errors */
/* (which may be acceptable for certain applications) are stored in the */
/* error fields of the generated parses. */
int prp_parse_packet(struct prparse *base, uint firstppt);

/* Free a complete parse tree.  prp->region == NULL  This does not free. */
/* the base parse itself. (i.e. the root region) */
void prp_clear(struct prparse *prp);

/* Free a single parse.  All sub regions of the parse are made part of prp's */
/* parent region.  It is an error to call this on the root region. */
void prp_free_parse(struct prparse *prp);

/* Free a header parse, and all child headers.  If called on the root */
/* parse, then this is equivalent to prp_clear() */
void prp_free_region(struct prparse *prp);

/*
 * copy a header parse (but not the packet buffer itself).
 */
int prp_copy(struct prparse *nprp, struct prparse *oprp, byte_t *buffer);

/* Associate a header parse with a new packet buffer (which must be sized */
/* correctly based on the header parse). */
void prp_set_packet_buffer(struct prparse *prp, byte_t * buffer);

/* re-parse and update the fields in 'prp'.  (but not its children */
/* returns error field as a matter of convenience */
uint prp_update(struct prparse *prp);

/* fix up checksums in the 'prp' protocol header */
int prp_fix_cksum(struct prparse *prp);

/* fix up length fields in the 'prp' protocol header based on 'prp' */
/* protocol metadata */
int prp_fix_len(struct prparse *prp);

/* insert and delete data from the parse (and packet) */
/* NOTE: when inserting on the boundary between a payload and header or */
/* a payload and trailer, prp_insert() always favors inserting into the */
/* payload section.  You can use prp_adj_* to correct this later as needed. */
int prp_insert(struct prparse *prp, ulong off, ulong len, int moveup);
int prp_cut(struct prparse *prp, ulong off, ulong len, int moveup);

/* expand or contract header/trailer within the encapsulating space */
/* Note that the point adjustments can't overrun their adjacent boundaries. */
/* prp_adj_plen() moves both the trailer offset and ending offset in unison. */
/* It basically acts as shorthand for a common case of adding or chopping */
/* payload to a particular packet. */
int prp_adj_off(struct prparse *prp, uint oid, long amt);/* adjust an offset */
int prp_adj_plen(struct prparse *prp, long amt);	/* adjust C+D */

/* Adjust a region so that its payload starts on the first unused byte */
/* at the beginning and it's trailer starts on unused byte at the end. */
/* A byte is "used" if it falls within some parse within the region or */
/* a dependent sub region. */
int prp_adj_unused(struct prparse *prp);

#endif /* __protoparse_h */
