/*
 * This is a sample protocol parsing dynamic library that parses the
 * mythical protocol YAP (Yet Another Protocol).  It is an L2 encapsulating
 * protocol with a "checksum" and "length" field.  It generally comes between
 * an Ethernet header and an IP/IPv6 header.  (although it can go between
 * any two headers with valid ethertypes).
 *
 * The header is 8 bytes long and like this:
 *
 *  31         16 15          0
 * +-------------+-------------+
 * |    Tag      |   Length    |
 * +-------------+-------------+
 * |   Etype     |  Checksum   |
 * +-------------+-------------+
 *
 * The tag is an arbitrary 16 bit value.
 * The length is the length of the payload that follows.
 * The etype is the Ethernet protocol type of the header that follows.
 * The checksum is an XOR of all the other three fields.
 * The protocol has the mythical Ethertype of 0x9999
 *
 * The purpose of this is just to serve as a demonstration of the basics of
 * how to create an ONICS protocol parser and compile it for dynamic inclusion
 * in the ONICS tool suite.
 */
#include <stdlib.h> /* malloc/free */
#include <stdint.h> /* uint*_t */
#include <string.h> /* memset/memcpy */
#include <arpa/inet.h> /* ntohs */
#include <errno.h>  /* errno, E* */

/* ONICS headers you need.  Do NOT compile in the sources. */
/* Just use the headers for types and prototypes. */
#include <prload.h>
#include <prid.h>
#include <protoparse.h>
#include <ns.h>
#include <util.h>

/* Our new protocol header */
struct yaph {
	uint16_t tag;	/* arbitrary */
	uint16_t len;   /* length of payload */
	uint16_t etype; /* ethertype of next header */
	uint16_t csum;	/* xor of header bytes */
};
#define YAPHLEN 8

/* This protocol is an L2 tunnel header, so it has an ethertype */
#define YAPETYPE 0x9999

/* We select a PRID for our usage from the user-defined list. */
#define YAPPRID  PRID_BUILD(PRID_PF_USER_FIRST, 0)


/* forward declarations */
struct proto_parser_ops yap_ops;
struct prparse_ops yap_parse_ops;


/* 
 * This function parses a PDU and stores the parse info in 'prp'
 */
static void yap_update(struct prparse *prp, byte_t *buf)
{
	struct yaph *yh;
	uint16_t len;

	prp->error = 0;				/* reset error */
	if (prp_totlen(prp) < YAPHLEN) {	/* check for truncation */
		prp->error |= PRP_ERR_TOOSMALL;
		/* if there's no full header, consider all fields invalid */
		return;
	}

	/* Set the payload offset based on the parsed header length */
	prp_poff(prp) = prp_soff(prp) + YAPHLEN;

	/* There is no trailer: set the trailer offset to the end of the PDU */
	prp_toff(prp) = prp_eoff(prp);

	/* Get a pointer to the YP header */
	yh = prp_header(prp, buf, struct yaph);

	/* perform the "checksum" check */
	/* our checksum is just a simple xor here */
	if (yh->tag ^ yh->len ^ yh->etype ^ yh->csum)
		prp->error |= PRP_ERR_CKSUM;

	/* Check the length field of the header */
	len = ntohs(yh->len);
	if (len != prp_plen(prp)) {
		if (prp_plen(prp) < len)
			prp->error |= PRP_ERR_TRUNC;
		else
			prp->error |= PRP_ERR_INVALID;
	}
}


/*
 * This function updates any fields in the header that tell
 * which protocol follows this protocol.
 */
static int yap_fixnxt(struct prparse *prp, byte_t *buf)
{
	struct yaph *yh = prp_header(prp, buf, struct yaph);
	struct prparse *next;

	/* Find the next PDU after ours */
	next = prp_next_in_region(prp, prp);
	if (next != NULL) {
		/* if it exists, then set this header's ethertype */
		/* based on the PRID mapping of the PDU. */
		yh->etype = htons(pridtoetype(next->prid));

		/* if the etype == 0, then we couldn't find the mapping */
		if (yh->etype == 0)
			return -1;
	}
	return 0;
}


/*
 * This function creates a copy of a parse.  The protoparse 
 * API does not know how parses are allocated (or copied).
 * The protocol library handles this detail.
 */
static struct prparse *yap_copy(struct prparse *oprp)
{
	struct prparse *prp;
       	prp = calloc(sizeof(struct prparse), 1);
	if (prp == NULL)
		return NULL;
	memcpy(prp, oprp, sizeof(*prp));
	return prp;
}


/*
 * This function fixes any length fields in the PDU based
 * on the values in the parse.  This can include both
 * header and data lengths.
 */
int yap_fixlen(struct prparse *prp, byte_t *buf)
{
	struct yaph *yh = prp_header(prp, buf, struct yaph);
	yh->len = htons(prp_plen(prp));
	return 0;
}


/*
 * This function fixes any checksum fields in the PDU.
 */
int yap_fixcksum(struct prparse *prp, byte_t *buf)
{
	struct yaph *yh = prp_header(prp, buf, struct yaph);
	yh->csum = yh->tag ^ yh->len ^ yh->etype;
	return 0;
}


/*
 * This function frees a protocol parse.  The protoparse
 * library does not know how the systems allocate and free
 * parses.  That is the responsibility of the protcol library.
 */
void yap_free(struct prparse *prp)
{
	free(prp);
}


/*
 * All prparse structures will refer to this structure.  It
 * defines the functions that operate on this parse.
 */
struct prparse_ops yap_parse_ops = {
	yap_update,
	yap_fixnxt,
	yap_fixlen,
	yap_fixcksum,
	yap_copy,
	yap_free,
};


/* Helper function to allocate and initialize a new yap parse */
static struct prparse *newypprp(struct prparse *reg, ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = calloc(sizeof(struct prparse), 1);
	if (prp == NULL)
		return NULL;
	prp_init_parse(prp, YAPPRID, off, 0, maxlen, 0, &yap_parse_ops,
		       reg, 0);
	return prp;
}


/*
 * This function actually parses a PDU given a parent region, a
 * pointer to the buffer, a starting offset for the PDU and a
 * maximum length that the PDU can cover.  It must allocate and
 * return a new parse structure.  It can generally just allocate
 * the data structure and call the _update() function to populate
 * the parse offsets.
 */
static struct prparse *yap_parse(struct prparse *reg, byte_t *buf,
				    ulong off, ulong maxlen)
{
	struct prparse *prp;
	prp = newypprp(reg, off, maxlen);
	if (prp != NULL)
		yap_update(prp, buf);
	return prp;
}


/*
 * This function determines the PRID and the boundaries of the next
 * PDU to parse.  The 'parent' parameter is the parse of the current PDU.
 * This function returns the PRID, offset and length of the next
 * region in 'buf' containing a PDU.  The function returns 0 if there is
 * some inner protocol to parse or 1 if there is not.
 *
 * The 'cld' parameter deserves special mention.  The first time the
 * system invokes this function, cld will be NULL.  Each subsequent
 * invocation will return the protocol parse of the last PDU that the
 * system instantiated.  This is to support protocols like SSL where,
 * for example, there are multiple records within a stream or fragments
 * within a record.  For a protocol like TCP or in this case yap
 * where there is at most one embedded PDU, the function should return 0
 * on all subsequent calls (i.e. when the 'cld' parameter is non-NULL).
 */
static int yap_nxtcld(struct prparse *parent, byte_t *buf,
			 struct prparse *cld, uint *prid, ulong *off,
			 ulong *maxlen)
{
	struct yaph *yh = (struct yaph *)(buf + prp_soff(parent));

	/* only one embedded packet per yap PDU */
	/* if called a second time, return NULL */
	if (cld != NULL)
		return 0;

	/* Determine the PRID of the embedded packet by ethertype. */
	/* If we can't, report no child protocol */
	*prid = etypetoprid(ntohs(yh->etype));
	if (*prid == 0)
		return 0;
	/* Payload offset will be start of inner PDU */
	*off = prp_poff(parent);
	/* Payload length will be the maximum length of the PDU */
	*maxlen = prp_plen(parent);

	/* return that we found a child protocol */
	return 1;
}


/*
 * This function returns the specification of a new PDU and parse to create.
 * In essence, the library should just invoke prpspec_init() with the correct
 * parameters for PRID, header length and trailer length.  'prp' is the
 * the parse of the protocol that the new PDU either contains (if 'enclose' is
 * non-zero) or is contained within (if 'enclose' equals 0).
 *
 * This enclosing/enclosed PDU might change the parameters of the new PDU.
 * For example, might require a larger header or trailer (due to options) or
 * might require a special PRID for a specific sub-protocol.
 */
static int yap_getspec(struct prparse *prp, int enclose, struct prpspec *ps)
{
	return prpspec_init(ps, prp, YAPPRID, YAPHLEN, 0, enclose);
}


/*
 * This function adds a new PDU and parse to a packet buffer.  It takes
 * a specification ('ps') that the function must use to create the PDU.
 * It also indicates via 'enclose' whether the PDU should enclose or
 * be enclosed by the PDU that 'reg' refers to.  'buf', as always,
 * is a pointer to the start of the buffer and all parse offsets are
 * based on using it as a base.  The 'buf' parameter could be NULL in
 * theory if the parse doesn't refer to an actual packet.
 */
static int yap_add(struct prparse *reg, byte_t *buf, struct prpspec *ps,
		      int enclose)
{
	struct prparse *prp;
	struct prparse *cld;
	struct yaph *yh;

	/* If the spec doesn't give enough headroom, it's an error */
	if (ps->hlen != YAPHLEN) {
		errno = EINVAL;
		return -1;
	}

	/* allocate the parse and if unable, it's an error */
	prp = newypprp(reg, ps->off, ps->plen + ps->hlen);
	if (prp == NULL)
		return -1;

	/* set the payload offset of the new parse */
	prp_poff(prp) = prp_soff(prp) + ps->hlen;

	/* add the new parse to the parse list */
	prp_add_insert(reg, prp, enclose);

	if (buf) {
		/* fill in the default yp header fields */
		yh = prp_header(prp, buf, struct yaph);
		memset(yh, 0, YAPHLEN);
		yh->tag = htons(0xdead);
		yh->len = htons(prp_plen(prp));

		/* If this PDU encloses another, then try to set the */
		/* ethertype field in the packet */
		cld = prp_next_in_region(prp, prp);
		if (cld != NULL)
			yh->etype = htons(pridtoetype(cld->prid));
		else
			yh->etype = 0;

		/* set the checksum */
		yh->csum = yh->tag ^ yh->len ^ yh->etype;
	}

	return 0;
}


/*
 * These are the function pointers for the protocol parser.
 */
struct proto_parser_ops yap_ops = { 
	yap_parse,
	yap_nxtcld,
	yap_getspec,
	yap_add
};



/*
 * This section defines a namespace for the yap protocol.  It enables the
 * tools to refer to protocol fields by name and know their widths.
 *
 * We are going to declare:
 *  yap       --> the protocol namespace
 *  yap.tag   --> the tag field of the protocol header
 *  yap.len   --> the length field of the protocol header
 *  yap.etype --> the ethertype field of the protocol header
 *  yap.csum  --> the checksum field of the protocol header
 *
 * The NS_*_I() macros define structure initializers for the various data
 * structures.
 */
#define ALEN(arr) (sizeof(arr) / sizeof(arr[0]))

/* Forward declaration for the array of subfields from the yap namespace */
extern struct ns_elem *yap_ns_elems[4];

/* 
 * parameters are:
 *   - short name
 *   - namespace parent (NULL for the root)
 *   - PRID
 *   - protocol class if any (otherwise PRID_NONE)
 *   - long name
 *   - format function for printing the protocol name
 *   - array of sub-elements
 *   - number of sub-elements
 */
struct ns_namespace yap_ns =
	NS_NAMESPACE_I("yap", NULL, YAPPRID, PRID_PCLASS_TUNNEL,
		       "Yet Another Protocol", NULL, yap_ns_elems,
		       ALEN(yap_ns_elems));

/*
 * packet field parameters are:
 *  - short name
 *  - namespace parent
 *  - PRID of the PDU that this field belongs to
 *  - offset of this field from the start of the packet
 *  - length of this field in bytes (other macros initialize bitfields)
 *  - long name of the field
 *  - format function for the value
 *    ns_fmt_hex and ns_fmt_dec provide hex and decimal printing
 */
struct ns_pktfld yap_ns_tag =
	NS_BYTEFIELD_I("tag", &yap_ns, YAPPRID, 0, 2, "Tag", &ns_fmt_hex);
struct ns_pktfld yap_ns_len =
	NS_BYTEFIELD_I("len", &yap_ns, YAPPRID, 2, 2, "Length", &ns_fmt_dec);
struct ns_pktfld yap_ns_etype =
	NS_BYTEFIELD_I("etype", &yap_ns, YAPPRID, 4, 2, "Ethertype",
		       &ns_fmt_hex);
struct ns_pktfld yap_ns_csum =
	NS_BYTEFIELD_I("csum", &yap_ns, YAPPRID, 6, 2, "Checksum",
		       &ns_fmt_hex);

/* Now the actual definition of the sub-element array */
struct ns_elem *yap_ns_elems[] = {
	(struct ns_elem *)&yap_ns_tag,
	(struct ns_elem *)&yap_ns_len,
	(struct ns_elem *)&yap_ns_etype,
	(struct ns_elem *)&yap_ns_csum
};


/* This function is used as the parameter to the register_protocol() function.*/
static struct oproto _yap = {
	YAPPRID, &yap_ops, &yap_ns, YAPETYPE
};


/* Required functions */

/* Perform all initialization required for this library file */
int load(void)
{
	/* register the yap protocol based on the '_yap' struct */
	return register_protocol(&_yap);
}


/* Perform all finalization required for this library file */
void unload(void)
{
	/* unregister the yap protocol based on the '_yap' struct */
	unregister_protocol(&_yap);
}
