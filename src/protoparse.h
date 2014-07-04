/*
 * ONICS
 * Copyright 2012-2013
 * Christopher Adam Telfer
 *
 * protoparse.h -- API for manipulating protocol parses.
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
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
#define PRP_ERR_TRUNC           0x0004
#define PRP_ERR_CKSUM           0x0008
#define PRP_ERR_OPTLEN          0x0010
#define PRP_ERR_OPTERR          0x0020
#define PRP_ERR_INVALID         0x0040	/* invalid combination of options */
#define PRP_ERR_MAXBIT		6

#define PRP_ERR_HLENMASK        (PRP_ERR_TOOSMALL|PRP_ERR_HLEN)

struct prparse;

/*
 * This structure is used as a bare-bones specification for a protocol parse.
 * The protoparse library can request a protocol parser to generate such
 * a specification (see the proto_parser_ops getspec() function).  
 * Alternately, a user can provide a specification directly and request that
 * the protocol parser create the parse accordingly.  The specification
 * basically contains the protocol ID, the starting offset within some
 * buffer for the PDU and parse, and the length of the 3 main parse regions:
 * header, payload and trailer.  (any of which may be 0)
 */
struct prpspec {
	uint			prid;
	ulong			off;
	ulong			hlen;
	ulong			plen;
	ulong			tlen;
};


/*
 * This is the main interace for a protocol parser.  A protocol parser
 * must implement all 4.  Each function sets errno when they fail with
 * an error of some sort.
 */
struct proto_parser_ops {

	/*
	 * Parse a blob of data that either file information or another
	 * protocol parser has identified as being a PDU of this
	 * type of protocol.  Return the new parse on success or NULL
	 * on an error, setting errno appropriately.
	 *
	 * Parameters:
	 * + reg  -- the parent region enclosing this blob of data.
	 *           Usually the encapsulating protocol if one exists.
	 * + buf  -- a pointer to the buffer containing the PDU.
	 * + off  -- The offset of the start of the PDU within the buffer.
	 * + maxlen -- The maximum length that this PDU might be starting
	 *             from off.
	 *
	 * Returns a new protocol parse for the library to insert into
	 * the list of parses or NULL on an error.
	 */
	struct prparse *	(*parse)(struct prparse *reg, byte_t *buf,
					 ulong off, ulong maxlen);

	/*
	 * Determine the protocol of the next PDU ia buffer of data based
	 * on information from known PDUs.  The parsing library calls
	 * this function passing in an existing protocol parse created
	 * by this protocol parser.  It also passes in the last child
	 * of that parse or NULL if the parse has no children.  This
	 * function must then return a protocol ID of the protcol that
	 * follows this child in within the region, the starting offset
	 * of the PDU and the maximum length that that PDU can occupy.
	 *
	 * Parameters:
	 * + reg  -- The encapsulating region of the PDU.
	 * + buf  -- The buffer containing the PDU.
	 * + cld  -- The last child of 'reg' created or NULL if it has none.
	 * + prid -- A pointer to hold protocol ID of the next PDU.
	 * + off  -- A pointer to hold the starting offset of the next PDU.
	 * + maxlen -- A pointer to hold the maximum length of the next PDU.
	 *
	 * Returns 0 if there are no further identifiable PDUs in this
	 * region according to this protocol parser.  Returns 1 if the parser
	 * was able to identify a PDU.  In this case, 'prid', 'off' and
	 * 'maxlen' will all be set.  Otherwise their values are undefined.
	 */
	int			(*nxtcld)(struct prparse *reg, byte_t *buf,
					  struct prparse *cld, uint *prid,
					  ulong *off, ulong *maxlen);

	/*
	 * Generate a specification (struct prpspec) for a protocol parse for
	 * this protocol.  The new protocol parse would either enclose an
	 * existing parse or would be encapsulated within an existing parse.
	 * 
	 * Parameters:
	 * + prp  -- the parse to either enclose in a new parse or create a
	 *           new child parse of depending on the 'enclose' parameter.
	 * + enclose -- if non-zero generate a specification for a parse
	 *              enclosing the region of 'prp'.  Otherwise generate
	 *              a spec for embeddeding a new protocol parse within
	 *              the region of 'prp'.
	 * + ps  -- The new specification, suitable for the add funtion.
	 * 
	 * Returns 0 if successful and -1 on a failure setting errno
	 * appropriately.
	 */
	int			(*getspec)(struct prparse *prp, int enclose,
					   struct prpspec *ps);

	/*
	 * Create a new protocol parse with offsets based on a specification
	 * and insert it into the protocol parse chain.  The new parse
	 * will either enclose the 'reg' parse or will be enclosed by it
	 * depending on the 'enclose' parameter.  If the 'buf' parameter
	 * is not NULL, then the function must also initialize the PDU
	 * that this parse refers to with default values sufficient for
	 * an error free parsing.
	 *
	 * Paramters:
	 * + reg  -- the protocol parse to either enclose the new
	 *           parse or be enclosed by the new parse.  Will
	 *           never be the outermost parse if 'enclose' is non-zero.
	 * + buf  -- a buffer to put the new PDU in.  This parameter
	 *           can be NULL.  The function should still create a
	 *           new parse based on the specification in this case.
	 * + ps  -- The specification for the new parse and its PDU.
	 *          This will contain offsets with 'buf' (if 'buf' is
	 *          not NULL) and lengths for header, payload and trailer
	 *          regions.
	 * + enclose -- If set to non-zero the new parse and the new PDU
	 *              should enclose the 'reg' parse and its PDU.
	 *              Otherwise, 'reg' should be set to enclose the
	 *              new parse and its PDU.
	 *
	 * Returns 0 on success and -1 on failure setting errno appropriately.
	 */
	int			(*add)(struct prparse *reg, byte_t *buf, 
				       struct prpspec *ps, int enclose);
};


/*
 * A structure for a protocol parser used internally.
 */
struct proto_parser {
	uint			prid;
	uint			valid;
	struct proto_parser_ops *ops;
};

/* 
 * Install a protocol parser to handle a particular protocol type.
 * Returns 0 on success or -1 on error setting errno appropriately.
 */
int pp_register(uint prid, struct proto_parser_ops *ops);

/* 
 * Find a protocol parser by protocol ID.
 *
 * Returns the protocol parser or NULL on failure.
 */
const struct proto_parser *pp_lookup(uint prid);

/* 
 * Unregister the protocol parser by protocol ID.
 *
 * Returns 0 on success and -1 on failure.
 */
int pp_unregister(uint prid);



/*
 * This is a table of function pointers that the protocol parser populates
 * in every protocol parse it creates.  It basically encompasses the
 * operations that every parse should be able to carry out on its
 * corresponding PDU.
 */
struct prparse_ops {
	/*
	 * Re-parse the PDU using the same bounds for the PDU that are in
	 * 'prp' and update the fields of the parse.
	 *
	 * Parameters:
	 * + prp  -- The parse to update.
	 * + buf  -- The buffer that contains the actual PDU data.
	 */
	void			(*update)(struct prparse *prp, byte_t *buf);

	/*
	 * Fix the length field(s) (if any) of this PDU according to the 
	 * values in the the protocol parse.
	 *
	 * Parameters:
	 * + prp  -- The parse referring to the PDU whose length to fix.
	 * + buf  -- The buffer containing the actual PDU data.
	 *
	 * Returns 0 on success and -1 on error setting errno appropriately
	 */
	int			(*fixlen)(struct prparse *prp, byte_t *buf);

	/*
	 * Fix the checksum field(s) (if any) of this PDU according to the
	 * values in the the protocol parse.
	 *
	 * Parameters:
	 * + prp  -- The parse referring to the PDU whose length to fix.
	 * + buf  -- The buffer containing the actual PDU data.
	 * 
	 * Returns 0 on success and -1 on error setting errno appropriately.
	 */
	int			(*fixcksum)(struct prparse *prp, byte_t *buf);

	/*
	 * Copy a protocol parse and return the copy.
	 *
	 * Parameters:
	 * + prp  -- The protocol parse to copy.
	 *
	 * Returns the new protocol parse or NULL on an error setting errno
	 * appropriately.
	 */
	struct prparse *	(*copy)(struct prparse *prp);

	/*
	 * Free a protocol parse and its associated state.
	 *
	 * Parameters:
	 * + prp  -- The protocol parse to free.
	 */
	void			(*free)(struct prparse *prp);
};


/*
 * Start of 
 * Packet Buffer
 * |                    Encapsulating Protocol Parse
 * |     par.poff                                                par.toff
 * | ...----+-------------------------------------------------------+----...
 * |        |  prp.soff    prp.poff             prp.toff  prp.end   |
 * | header |      +---------+---------------------+---------+      | trailer
 * |        |      | header  | payload             | trailer |      |
 * |        |      +---------+---------------------+---------+      |
 * |        |      A         B    ^                C         D      |  
 * | ...----+---------------------)---------------------------------+----...
 * |        \_____/               |                          \_____/
 *             |                  |                             |
 *       may be 0-length     possible encapsulated        may be 0-length
 *                           packet contained here
 */

/* 
 * A 'prparse' structure denotes a decode of the region of a protocol as well
 * as decode of its various fields.  All protocol parses at a minimum have a
 * starting offset, a header, payload and trailer fields.  All of these are
 * have a length in bytes, which can be 0.  The protocol parses associated
 * with a particular buffer are ordered by their start offsets.  So, if the 
 * header or trailer offset of a header parse change, the parse may have to be
 * moved in the list. 
 */

/*
 * A note for IPv6 and IPsec.  When an IPv6 packet has an ESP or AH header,
 * that header is considered the start of the payload of the v6 packet.  It
 * This is a specific example where the abstraction of encapsulating protocol
 * parses breaks down.  IPsec is, in many ways, its own set of protocols that
 * encapuslate data.  It is convenient to treat them as such.  However, IPv6
 * destination options CAN come after the IPsec headers.  In the case of ESP
 * with encryption, this is not data that we can parse anyways.  Nevertheless
 * this won't always be the case.  Given this kind of "call" on how to
 * interpret the fields, the "payload offset" is, therefore, the first byte
 * of the protocol unit that isn't the purview of the encapsulating protocol.
 * This does NOT always mean that there can't be protocol relevant bytes
 * in the payload section.  But it won't typically be the case.
 */


#define PRP_OI_SOFF 0
#define PRP_OI_POFF 1
#define PRP_OI_TOFF 2
#define PRP_OI_EOFF 3
#define PRP_OI_MIN_NUM 4
#define PRP_OI_EXTRA PRP_OI_MIN_NUM
#define PRP_OI_INVALID ((uint)-1)
#define PRP_OFF_INVALID ((ulong)-1)
#define PRP_OFF_MAX (((ulong)-1) - 1)


/*
 * This structure represents a parse of a PDU.  Each parse contains
 * at least 4 offsets for the start of the PDU, the start of the
 * payload, the start of the trailer and the end of the packet.
 * The parse may also have further offsets beyond this.  That is:
 * noff >= 4 in a well-formed parse.  The protocol parser itself
 * is responsible for ensuring that sufficient memory is allocated
 * to contain the additional offsets plus any private state it
 * wishes to maintain.
 */
struct prparse {
	uint			prid;		/* protocol ID of the PDU */
	uint			error;		/* bitmap of PRP_ERR_* */
	struct prparse_ops *	ops;		/* table of parse func ptrs */
	struct list		node;		/* linked list node */
	struct prparse *	region;		/* the enclosing region */
	uint			noff;		/* # of parse offsets (>=4) */
	ulong			offs[PRP_OI_MIN_NUM];	/* the parse offsets */
};
#define prp_soff(_prp) ((_prp)->offs[PRP_OI_SOFF])
#define prp_poff(_prp) ((_prp)->offs[PRP_OI_POFF])
#define prp_toff(_prp) ((_prp)->offs[PRP_OI_TOFF])
#define prp_eoff(_prp) ((_prp)->offs[PRP_OI_EOFF])
#define prp_hlen(_prp) (prp_poff(_prp) - prp_soff(_prp))
#define prp_plen(_prp) (prp_toff(_prp) - prp_poff(_prp))
#define prp_tlen(_prp) (prp_eoff(_prp) - prp_toff(_prp))
#define prp_totlen(_prp) (prp_eoff(_prp) - prp_soff(_prp))
#define prp_header(_prp, _buf, _type) \
	((_type *)((byte_t *)(_buf) + prp_soff(_prp)))
#define prp_payload(_prp, _buf) ((byte_t *)(_buf) + prp_poff(_prp))
#define prp_trailer(_prp, _buf, _type) \
	((_type *)((byte_t *)(_buf) + prp_toff(_prp)))
#define prp_prev(_prp) container((_prp)->node.prev, struct prparse, node)
#define prp_next(_prp) container((_prp)->node.next, struct prparse, node)
#define prp_is_base(_prp) ((_prp)->region == NULL)
#define prp_list_head(_prp) prp_is_base(_prp)
#define prp_list_end(_prp) prp_is_base(_prp)
#define prp_empty(_prp) (l_isempty(&(_prp)->node))
#define prp_off_valid(_prp, _off) \
	( ((uint)(_off) < (_prp)->noff) && \
	  ((_prp)->offs[(uint)(_off)] != PRP_OFF_INVALID) )

#define prp_for_each(_prp, _plist)		\
	for ((_prp) = prp_next(_plist) ;	\
	     !prp_list_head(_prp) ;		\
	     (_prp) = prp_next(_prp))

#define prp_for_each_safe(_prp, _x_plist)			\
	for ((_prp) = prp_next(_plist), (_x) = prp_next(_prp) ;	\
	     !prp_list_head(_prp) ;				\
	     (_prp) = (_x), (_x) = prp_next(_prp))

/* 
 * Find the base region for this parse.  This is the root node of the 
 * of the parse tree and the parent of all other parses for a given
 * block of data (usually the whole packet in a buffer).
 */
struct prparse *prp_get_base(struct prparse *prp);

/*
 * Find the next parse in the specified region or return NULL if none
 * exists in the parse list.  use the region parse as the 'from' for
 * to start at the beginning of a region.  NOTE, that on its own, this
 * does not find subregions within the region.  One can use a recursive
 * or even iterative process with this function to walk all sub regions
 * as well.  Recursive is more elegant.  :)
 *
 * Recursive example:
 * walk(from, reg) {
 *   next = prp_next_in_region(from, reg);
 *   if (next != NULL) {
 *     ** do X with prp **
 *     walk(next, next);
 *     walk(next, reg);
 *   }
 * }
 *
 * Iterative example: 
 * curreg = reg;
 * prp = prp_next_in_region(reg, reg);
 * while ( prp != NULL ) {
 *   ** do whatever with prp **
 *   prp2 = prp_next_in_region(prp, prp);
 *   if ( prp2 != NULL ) { 
 *     curreg = prp;
 *     prp = prp2;
 *   } else {
 *     do { 
 *       prp2 = prp_next_in_region(prp, curreg);
 *       if (prp2 == NULL) {
 *         ** done with this region, go up one **
 *         curreg = prp->region;
 *       } else {
 *         prp = prp2;
 *       }
 *     } while ( prp == NULL && curreg != reg->region );
 *   }
 * }
 */
struct prparse *prp_next_in_region(struct prparse *from, struct prparse *reg);

/* returns 1 if a region contains no parses that refer to it */
int prp_region_empty(struct prparse *reg);

/*
 * Initializes a fresh parse of PRID_NONE.  This can be used to create the
 * base for a full parse. 
 */
void prp_init_parse(struct prparse *base, ulong len);

/* Insert a parse into the parse list */
void prp_insert_parse(struct prparse *from, struct prparse *toins);

/* remove a parse from a parse list */
void prp_remove_parse(struct prparse *prp);

/*
 * Given an initialized protocol parse header for a buffer (PRID_NONE) and
 * an initial protocol id, parse the packet and add to the list
 * of PRPs.  Returns -1 on an allocation error.  Otherwise, parse errors
 * (which may be acceptable for certain applications) are stored in the
 * error fields of the generated parses.
 */
int prp_parse_packet(struct prparse *base, byte_t *buf, uint firstprid);

/*
 * Populate a default parse specification based on either enclosing
 * the given parse or inserting the spec within the payload of the
 * parse. (based on the 'enclose' parameter.  If the function returns 0,
 * then the spec is poulated with values appropriate to pass to prp_add().
 */
int prp_get_spec(uint prid, struct prparse *prp, int enclose,
		 struct prpspec *ps);

/*
 * Create a new header in a parsed packet.  The prpspec specifies the
 * type and location of the header.  'reg' is the enclosing region for
 * the parse.  Note that means one can not use prp_add() to generate an
 * outermost parse. If the 'buf parameter is not NULL the operation
 * will also create a 'default' packet format in the buffer at the
 * offsets indicated by the prpspec.  If enclose is non-zero, then the
 * operation will search for outermost parses in 'reg' that fall within the
 * new parse's region and reassign them to refer to the new parse as their
 * region.
 */
int prp_add(struct prparse *reg, byte_t *buf, struct prpspec *ps, int enclose);

/*
 * Free a complete parse tree.  prp->region == NULL  This does not free.
 * the base parse itself. (i.e. the root region)
 */
void prp_clear(struct prparse *prp);

/*
 * Free a single parse.  All sub regions of the parse are made part of prp's
 * parent region.  It is an error to call this on the root region.
 */
void prp_free_parse(struct prparse *prp);

/*
 * Free a header parse, and all child headers.  If called on the root
 * parse, then this is equivalent to prp_clear()
 */
void prp_free_region(struct prparse *prp);

/* copy a header parse (but not the packet buffer itself). */
int prp_copy(struct prparse *nprp, struct prparse *oprp);

/*
 * re-parse and update the fields in 'prp'.  (but not its children)
 * returns error field as a matter of convenience
 */
uint prp_update(struct prparse *prp, byte_t *buf);

/* fix up checksums in the 'prp' protocol header */
int prp_fix_cksum(struct prparse *prp, byte_t *buf);

/*
 * fix up length fields in the 'prp' protocol header based on 'prp'
 * protocol metadata 
 */
int prp_fix_len(struct prparse *prp, byte_t *buf);

/*
 * insert data into the the packet and adjust parses.  The starting byte
 * S = prp_soff(prp) + off.  That is, the 'off'th byte after the start of
 * the parse.  if moveup is nonzero, then the function shifts bytes [S,end]
 * 'len' bytes forward in the packet and fills them with dummy values.  If
 * 'moveup' is zero, then it shifts bytes [0,S-1] down 'len' bytes and
 * the new space is filled with dummy values.  When 'moveup' is nonzero,
 * all offsets >= S are increased by 'len'.  When 'moveup' is zero, all
 * offsets < S are decreased by 'len'.  This function does not change offsets
 * set to PRP_OFF_INVALID.  It is illegal to specify a starting offset
 * before the payload offset or after the trailer offset of the outermost
 * parse.  (i.e. the outer PRID_NONE start and end).  This function will
 * move those offsets, however depending on the value of 'moveup'.
 */
int prp_insert(struct prparse *prp, byte_t *buf, ulong off, ulong len, 
	       int moveup);

/*
 * Remove data from a packet and adjust parses.  The starting byte is
 * S = prp_soff(prp) + off.  That is, the 'off'th byte after the start
 * of the parse.  if 'moveup' is non-zero then prp_cut() shfts bytes [0,S-1]
 * len bytes forward and increments all parse offsets less than S
 * by 'len'.  If 'moveup' is zero then prp_cut() shifts bytes [S+len,end]
 * down to byte position S, and decrements all offsets >= S+len by 'len'.
 * prp_cut() does not move PRP_OFF_INVALID offsets.  offsets falling within
 * range of removed bytes are set to S. It is illegal to cut bytes that are
 * outside of the region [poff,toff] of the outermost parse. (i.e. the
 * outer PRID_NONE start and end).  This function will move those offsets
 * however, depending on the value of 'moveup'.
 */
int prp_cut(struct prparse *prp, byte_t *buf, ulong off, ulong len, int moveup);

/*
 * expand or contract header/trailer within the encapsulating space
 * Note that an offset adjustment can't overrun its adjacent offsets.
 * prp_adj_plen() moves both the trailer offset and ending offset in unison.
 * It basically acts as shorthand for a common case of adding or chopping
 * payload to a particular packet. 
 */
int prp_adj_off(struct prparse *prp, uint oid, long amt);/* adjust an offset */
int prp_adj_plen(struct prparse *prp, long amt);	/* adjust C+D */

/*
 * Adjust a region so that its payload starts on the first used byte at the
 * beginning and it's trailer starts on first unused byte at the end.  A byte
 * is "used" if it falls within some parse within the region or a dependent
 * sub region.
 */
int prp_adj_unused(struct prparse *prp);

/*
 * Internal call for use by protocol parse libraries to insert a newly
 * created parse into a region and set it appropriately.  (for prp_add()
 * calls.)
 */
void prp_add_insert(struct prparse *reg, struct prparse *toadd, int enclose);

#endif /* __protoparse_h */
