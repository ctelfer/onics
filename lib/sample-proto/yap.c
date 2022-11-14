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
struct pdu_ops yap_pdu_ops;


/* 
 * This function parses a PDU and stores the parse info in 'pdu'
 */
static void yap_update(struct pdu *pdu, byte_t *buf)
{
	struct yaph *yh;
	uint16_t len;

	pdu->error = 0;				/* reset error */
	if (pdu_totlen(pdu) < YAPHLEN) {	/* check for truncation */
		pdu->error |= PDU_ERR_TOOSMALL;
		/* if there's no full header, consider all fields invalid */
		return;
	}

	/* Set the payload offset based on the parsed header length */
	pdu_poff(pdu) = pdu_soff(pdu) + YAPHLEN;

	/* There is no trailer: set the trailer offset to the end of the PDU */
	pdu_toff(pdu) = pdu_eoff(pdu);

	/* Get a pointer to the YP header */
	yh = pdu_header(pdu, buf, struct yaph);

	/* perform the "checksum" check */
	/* our checksum is just a simple xor here */
	if (yh->tag ^ yh->len ^ yh->etype ^ yh->csum)
		pdu->error |= PDU_ERR_CKSUM;

	/* Check the length field of the header */
	len = ntohs(yh->len);
	if (len != pdu_plen(pdu)) {
		if (pdu_plen(pdu) < len)
			pdu->error |= PDU_ERR_TRUNC;
		else
			pdu->error |= PDU_ERR_INVALID;
	}
}


/*
 * This function updates any fields in the header that tell
 * which protocol follows this protocol.
 */
static int yap_fixnxt(struct pdu *pdu, byte_t *buf)
{
	struct yaph *yh = pdu_header(pdu, buf, struct yaph);
	struct pdu *next;

	/* Find the next PDU after ours */
	next = pdu_next_in_region(pdu, pdu);
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
static struct pdu *yap_copy(struct pdu *opdu)
{
	struct pdu *pdu;
       	pdu = calloc(sizeof(struct pdu), 1);
	if (pdu == NULL)
		return NULL;
	memcpy(pdu, opdu, sizeof(*pdu));
	return pdu;
}


/*
 * This function fixes any length fields in the PDU based
 * on the values in the parse.  This can include both
 * header and data lengths.
 */
int yap_fixlen(struct pdu *pdu, byte_t *buf)
{
	struct yaph *yh = pdu_header(pdu, buf, struct yaph);
	yh->len = htons(pdu_plen(pdu));
	return 0;
}


/*
 * This function fixes any checksum fields in the PDU.
 */
int yap_fixcksum(struct pdu *pdu, byte_t *buf)
{
	struct yaph *yh = pdu_header(pdu, buf, struct yaph);
	yh->csum = yh->tag ^ yh->len ^ yh->etype;
	return 0;
}


/*
 * This function frees a protocol parse.  The protoparse
 * library does not know how the systems allocate and free
 * parses.  That is the responsibility of the protcol library.
 */
void yap_free(struct pdu *pdu)
{
	free(pdu);
}


/*
 * All pdu structures will refer to this structure.  It
 * defines the functions that operate on this parse.
 */
struct pdu_ops yap_pdu_ops = {
	yap_update,
	yap_fixnxt,
	yap_fixlen,
	yap_fixcksum,
	yap_copy,
	yap_free,
};


/* Helper function to allocate and initialize a new yap parse */
static struct pdu *newyppdu(struct pdu *reg, ulong off, ulong maxlen)
{
	struct pdu *pdu;
	pdu = calloc(sizeof(struct pdu), 1);
	if (pdu == NULL)
		return NULL;
	pdu_init(pdu, YAPPRID, off, 0, maxlen, 0, &yap_pdu_ops, reg, 0);
	return pdu;
}


/*
 * This function actually parses a PDU given a parent region, a
 * pointer to the buffer, a starting offset for the PDU and a
 * maximum length that the PDU can cover.  It must allocate and
 * return a new parse structure.  It can generally just allocate
 * the data structure and call the _update() function to populate
 * the parse offsets.
 */
static struct pdu *yap_parse(struct pdu *reg, byte_t *buf,
				    ulong off, ulong maxlen)
{
	struct pdu *pdu;
	pdu = newyppdu(reg, off, maxlen);
	if (pdu != NULL)
		yap_update(pdu, buf);
	return pdu;
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
static int yap_nxtcld(struct pdu *parent, byte_t *buf,
			 struct pdu *cld, uint *prid, ulong *off,
			 ulong *maxlen)
{
	struct yaph *yh = (struct yaph *)(buf + pdu_soff(parent));

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
	*off = pdu_poff(parent);
	/* Payload length will be the maximum length of the PDU */
	*maxlen = pdu_plen(parent);

	/* return that we found a child protocol */
	return 1;
}


/*
 * This function returns the specification of a new PDU and parse to create.
 * In essence, the library should just invoke pduspec_init() with the correct
 * parameters for PRID, header length and trailer length.  'pdu' is the
 * the parse of the protocol that the new PDU either contains (if 'enclose' is
 * non-zero) or is contained within (if 'enclose' equals 0).
 *
 * This enclosing/enclosed PDU might change the parameters of the new PDU.
 * For example, might require a larger header or trailer (due to options) or
 * might require a special PRID for a specific sub-protocol.
 */
static int yap_getspec(struct pdu *pdu, int enclose, struct pduspec *ps)
{
	return pduspec_init(ps, pdu, YAPPRID, YAPHLEN, 0, enclose);
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
static int yap_add(struct pdu *reg, byte_t *buf, struct pduspec *ps,
		   int enclose)
{
	struct pdu *pdu;
	struct pdu *cld;
	struct yaph *yh;

	/* If the spec doesn't give enough headroom, it's an error */
	if (ps->hlen != YAPHLEN) {
		errno = EINVAL;
		return -1;
	}

	/* allocate the parse and if unable, it's an error */
	pdu = newyppdu(reg, ps->off, ps->plen + ps->hlen);
	if (pdu == NULL)
		return -1;

	/* set the payload offset of the new parse */
	pdu_poff(pdu) = pdu_soff(pdu) + ps->hlen;

	/* add the new parse to the parse list */
	pdu_add_insert(reg, pdu, enclose);

	if (buf) {
		/* fill in the default yp header fields */
		yh = pdu_header(pdu, buf, struct yaph);
		memset(yh, 0, YAPHLEN);
		yh->tag = htons(0xdead);
		yh->len = htons(pdu_plen(pdu));

		/* If this PDU encloses another, then try to set the */
		/* ethertype field in the packet */
		cld = pdu_next_in_region(pdu, pdu);
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
