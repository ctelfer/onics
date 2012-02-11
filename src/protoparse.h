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

struct prparse;

struct prpspec {
	uint			prid;
	ulong			off;
	ulong			hlen;
	ulong			plen;
	ulong			tlen;
};

struct proto_parser_ops {
	struct prparse *	(*parse)(struct prparse *reg, byte_t *buf,
					 ulong off, ulong maxlen);

	int			(*nxtcld)(struct prparse *reg, byte_t *buf,
					  struct prparse *cld, uint *prid,
					  ulong *off, ulong *maxlen);

	int			(*getspec)(struct prparse *prp, int enclose,
					   struct prpspec *ps);

	int			(*add)(struct prparse *reg, byte_t *buf, 
				       struct prpspec *ps, int enclose);
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
#define PRP_OFF_MAX (((ulong)-1) - 1)


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
#define prp_is_base(prp) ((prp)->region == NULL)
#define prp_list_head(prp) prp_is_base(prp)
#define prp_list_end(prp) prp_is_base(prp)
#define prp_empty(prp) (l_isempty(&(prp)->node))
#define prp_off_valid(prp, off) ((prp)->offs[(off)] != PRP_OFF_INVALID)

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

/* Initializes a fresh parse of PRID_NONE.  This can be used to create the */
/* base for a full parse. */
void prp_init_parse(struct prparse *base, ulong len);

/* Insert a parse into the parse list */
void prp_insert_parse(struct prparse *from, struct prparse *toins);

/* Given an initialized protocol parse header for a buffer (PRID_NONE) and */
/* an initial protocol id, parse the packet and add to the list */
/* of PRPs.  Returns -1 on an allocation error.  Otherwise, parse errors */
/* (which may be acceptable for certain applications) are stored in the */
/* error fields of the generated parses. */
int prp_parse_packet(struct prparse *base, byte_t *buf, uint firstprid);

/* Populate a default parse specification based on either enclosing */
/* the given parse or inserting the spec within the payload of the */
/* parse. The 'enclose' parameter.  If the function returns 0, then */
/* the spec is poulated with values appropriate to pass to prp_add(). */
int prp_get_spec(uint prid, struct prparse *prp, int enclose,
		 struct prpspec *ps);

/* Create a new header in a parsed packet.  The prpspec specifies the */
/* type and location of the header.  'reg' is the enclosing region for */
/* the parse.  Note that means one can not use prp_add() to generate an */
/* outermost parse. If the 'buf parameter is not NULL the operation */
/* will also create a 'default' packet format in the buffer at the */
/* offsets indicated by the prpspec.  If enclose is non-zero, then the */
/* operation will search for all parses in 'reg' that fall within the new */
/* parse's region and reassign them to refer to the new parse as their */
/* region */
int prp_add(struct prparse *reg, byte_t *buf, struct prpspec *ps, int enclose);

/* Free a complete parse tree.  prp->region == NULL  This does not free. */
/* the base parse itself. (i.e. the root region) */
void prp_clear(struct prparse *prp);

/* Free a single parse.  All sub regions of the parse are made part of prp's */
/* parent region.  It is an error to call this on the root region. */
void prp_free_parse(struct prparse *prp);

/* Free a header parse, and all child headers.  If called on the root */
/* parse, then this is equivalent to prp_clear() */
void prp_free_region(struct prparse *prp);

/* copy a header parse (but not the packet buffer itself). */
int prp_copy(struct prparse *nprp, struct prparse *oprp);

/* re-parse and update the fields in 'prp'.  (but not its children) */
/* returns error field as a matter of convenience */
uint prp_update(struct prparse *prp, byte_t *buf);

/* fix up checksums in the 'prp' protocol header */
int prp_fix_cksum(struct prparse *prp, byte_t *buf);

/* fix up length fields in the 'prp' protocol header based on 'prp' */
/* protocol metadata */
int prp_fix_len(struct prparse *prp, byte_t *buf);

/* insert data into the the packet and adjust parses.  The starting byte */
/* S = prp_soff(prp) + off.  That is, the 'off'th byte after the start of */
/* the parse.  if moveup is nonzero, then the function packet bytes [S,end] */
/* 'len' bytes forward in the packet and fills them with dummy values.  If */
/* 'moveup' is zero, then bytes [0,S-1] are shifted down 'len' bytes and */
/* the new space is filled with dummy values.  When 'moveup' is nonzero, */
/* all offsets >= S are increased by 'len'.  When 'moveup' is zero, all */
/* offsets < S are decreased by 'len'.  This function does not move invalid */
/* offsets. */
int prp_insert(struct prparse *prp, byte_t *buf, ulong off, ulong len, 
	       int moveup);

/* Remove data from a packet and adjust parses.  The starting byte is */
/* S = prp_soff(prp) + off.  That is, the 'off'th byte after the start */
/* of the parse.  if 'moveup' is non-zero then prp_cut() shfts bytes [0,S-1] */ 
/* len bytes forward and increments all parse offsets less than S */
/* by 'len'.  If 'moveup' is zero then prp_cut() shifts bytes [S+len,end] */
/* down to byte position S, and decrements all offsets >= S+len by 'len'. */
/* prp_cut() does not move invalid offsets.  offsets falling within the */
/* cut range are set to S. */
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


/* Internal call for use by protocol parse libraries to insert a newly */
/* created parse into a region and set it appropriately.  (for prp_add() */
/* calls.) */
void prp_add_insert(struct prparse *reg, struct prparse *toadd, int enclose);

#endif /* __protoparse_h */
