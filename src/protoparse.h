#ifndef __prototparse_h
#define __prototparse_h
#include <cat/cat.h>
#include <cat/cattypes.h>
#include <cat/list.h>
#include "prid.h"

/*
   A PRID_NONE type parse just represents a parsed region of a buffer that
   is its own unit.  (e.g. a packet, a SSL record, etc..)  The header
   and trailer represents unused slack space in the region.  It gets updated
   on any header adjustment for enclosed parses.
*/

#define PRP_ERR_TOOSMALL        0x0001
#define PRP_ERR_HLEN            0x0002
#define PRP_ERR_LENGTH          0x0004
#define PRP_ERR_CKSUM           0x0008
#define PRP_ERR_OPTLEN          0x0010
#define PRP_ERR_OPTERR          0x0020
#define PRP_ERR_INVALID         0x0040	/* invalid combination of options */
#define PRP_ERR_MAXBIT		6

#define PRP_ERR_HLENMASK        (PRP_ERR_TOOSMALL|PRP_ERR_HLEN)

#define PRP_ADD_FILL               1	/* push inner (fill completely) */
#define PRP_ADD_WRAP               2	/* push outer (wrap tightly) */
#define PRP_ADD_WRAPFILL           3	/* push in middle (exact fit) */
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
	struct prparse *	(*parse)(struct prparse *pprp, byte_t *buf,
					 uint *nextprid);

	struct prparse *	(*add)(ulong off, ulong len, ulong hlen, 
				       ulong plen, byte_t *buf, int mode);
};

struct proto_parser {
	uint			prid;
	uint			valid;
	struct proto_parser_ops *ops;
};

/* install a protocol parser to handle a particular protocol type */
int pp_register(uint prid, struct proto_parser_ops *ops);

/* Get a protocol parser by protocol ID */
const struct proto_parser *pp_lookup(uint prid);

/* unregister a protocol by protocol ID */
int pp_unregister(uint prid);



struct prparse_ops {
	void			(*update)(struct prparse *prp, byte_t *buf);
	int			(*fixlen)(struct prparse *prp, byte_t *buf);
	int			(*fixcksum)(struct prparse *prp, byte_t *buf);
	struct prparse *	(*copy)(struct prparse *prp);
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
	uint			prid;
	uint			error;
	struct prparse_ops *	ops;
	struct list		node;
	struct prparse *	region;
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
#define prp_header(prp, buf, type) ((type *)((byte_t *)(buf) + prp_soff(prp)))
#define prp_payload(prp, buf) ((byte_t *)(buf) + prp_poff(prp))
#define prp_trailer(prp, buf, type) ((type *)((byte_t *)(buf)+ prp_toff(prp)))
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
/* header is created.  if mode == PRP_ADD_FILL, then 'prp' must be the */
/* innermost header and the new header will fill inside the curent one. If */
/* the mode is PRP_ADD_WRAP, then 'prp' must be the outer 'NONE' header and */
/* the new header will wrap all the other protocol headers.  Finally, if */
/* mode is PRP_ADD_WRAPFILL, then the 'prp' must be a header with free space */
/* between it and its child (based on the offsets above).  The new header */
/* will take up exactly the space between parent and child.  If the 'buf' */
/* parameter is not NULL the operation will also create a default header */
/* and trailer in the buffer at the offsets indicated by the parse. */
int prp_add(uint prid, struct prparse *prp, byte_t *buf, int mode);


/* Initializes a fresh parse of PRID_NONE.  This can be used to create the */
/* base for a full parse. */
void prp_init_parse(struct prparse *base, ulong len);

/* Given an initialized protocol parse header for a buffer (PRID_NONE) and */
/* an initial protocol id, parse the packet and add to the list */
/* of PRPs.  Returns -1 on an allocation error.  Otherwise, parse errors */
/* (which may be acceptable for certain applications) are stored in the */
/* error fields of the generated parses. */
int prp_parse_packet(struct prparse *base, byte_t *buf, uint firstprid);

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
int prp_copy(struct prparse *nprp, struct prparse *oprp);

/* re-parse and update the fields in 'prp'.  (but not its children) */
/* returns error field as a matter of convenience */
uint prp_update(struct prparse *prp, byte_t *buf);

/* fix up checksums in the 'prp' protocol header */
int prp_fix_cksum(struct prparse *prp, byte_t *buf);

/* fix up length fields in the 'prp' protocol header based on 'prp' */
/* protocol metadata */
int prp_fix_len(struct prparse *prp, byte_t *buf);

/* insert and delete data from the parse (and packet) */
/* NOTE: when inserting on the boundary between a payload and header or */
/* a payload and trailer, prp_insert() always favors inserting into the */
/* payload section.  You can use prp_adj_* to correct this later as needed. */
/* The 'buf' option can be NULL.  If it isn't the code will move the */
/* bytes in the buffer along with the offsets. */
int prp_insert(struct prparse *prp, byte_t *buf, ulong off, ulong len, 
	       int moveup);
int prp_cut(struct prparse *prp, byte_t *buf, ulong off, ulong len, int moveup);

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
