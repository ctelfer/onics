/*
 * Copyright 2009 -- Christopher Telfer
 * See attached licence.
 */
#ifndef __xpkt_h
#define __xpkt_h
#include <cat/cat.h>
#include <cat/cattypes.h>
#include "config.h"

/*
 * Format:  
 *  - packet_len(4) 		- must be >= tag len + offset(dltype) + 8
 *  - dltype(2)			- one of dltype.h: not INVALID
 *  - tag_len(2)		- 0 - 65532.  Must be multiple of 4.
 *  - tags(tag_len)
 *  - dltype offset padding	- depends on dltype but should be in 0-7
 *  - payload(packet_len - tag_len - offset(dltype) - 8)
 */
#define XPKT_HLEN	8
#define XPKT_TAG_MINW	1
#define XPKT_TAG_MAXW	255
struct xpkthdr {
	uint32_t		len;
	uint16_t		dltype;
	uint16_t		tlen;
};


struct xpkt {
	struct xpkthdr		hdr;
	uint32_t		tags[1];
};


struct xpkt_tag_hdr {
	byte_t			type;
	byte_t			nwords;
	uint16_t		xhword;
};


static NETTOOLS_INLINE uint32_t xpkt_doff(struct xpkt *x)
{
	abort_unless(x);
	return XPKT_HLEN + x->hdr.tlen * 4;
}


/* Returns the pointer to the beginning of data for an unpacked packet */
static NETTOOLS_INLINE void *xpkt_data(struct xpkt *x)
{
	abort_unless(x);
	return (byte_t *)x->tags + xpkt_doff(x);
}


/* Returns the length of the data portion of an unpacked packet */
static NETTOOLS_INLINE uint32_t xpkt_data_len(struct xpkt *x)
{
	uint32_t doff;
	abort_unless(x);
	doff = xpkt_doff(x);
	abort_unless(doff <= x->hdr.len);
	return x->hdr.len - doff;
}


/* Unpack an xpkt header from network byte order */
void xpkt_unpack_hdr(struct xpkthdr *xh);


/* 
 * Validate the fields in an xpkt header
 * Returns:
 *   0 Success
 *  -1 Invalid packet length
 *  -2 Invalid tag length
 */
int xpkt_validate_hdr(struct xpkthdr *xh);


/* Pack an xpkt header to network byte order */
void xpkt_pack_hdr(struct xpkthdr *xh);


/* 
 * Unpack and validate a set of xpkt tags from network byte order.
 * The validation step is necessary because the lengths of each
 * tag must be "ok" for the unpack to succeed.
 * Returns:
 *   0 Success
 *  -1 Tag overflow
 *  -2 Invalid tag type
 *  -3 Invalid tag length
 */
int xpkt_unpack_tags(uint32_t *tags, uint16_t tlen);


/*
 * Validate xpkt tag specific attributes.
 * Returns:
 *   0 Success
 *  -1 Duplicate tag where only one permitted;
 *  -2 Tag-specific error
 */
int xpkt_validate_tags(uint32_t *tags, uint16_t tlen);


/* Pack a set of xpkt tags to network byte order.  This routine assumes that */
/* the tags are valid. */
void xpkt_pack_tags(uint32_t *tags, uint16_t tlen);


/*
 * Return the next tag for an xpkt given a current one.  If 'cur' == NULL
 * then the function returns the first xpkt tag if there is one.  The
 * function returns NULL if there are no more tags.
 */
struct xpkt_tag_hdr *xpkt_next_tag(struct xpkt *x, struct xpkt_tag_hdr *cur);


/*
 * Find a tag type it's type.  The idx parameter specifies which tag of the
 * particular type gets returned.  Tags are indexed starting from 0.  So,
 * to find the second parse info tag one would call:
 *
 *    .... = xpkt_find_tag(x, XPKT_TAG_PARSE, 1);
 *
 * To walk find the Nth tag of any type do:
 *
 *    .... = xpkt_find_tag(x, XPKT_TAG_ANY, N-1);
 *
 * This function will work equally well whether the xpkt is packed or not.
 */
struct xpkt_tag_hdr *xpkt_find_tag(struct xpkt *x, byte_t type, int idx);


/*
 * Return the index of a tag within the xpkt.  (for use with xpkt_del_tag)
 * for example. 
 * Returns:
 *  >= 0 - The tag index
 *  <  0 - Tag not found within the packet
 */
int xpkt_find_tag_idx(struct xpkt *x, struct xpkt_tag_hdr *xth);

/*
 * Insert a tag into the xpkt.  The 'moveup' field determines how the
 * tag will be inserted:
 * - 0 - clobber the first region of nops of sufficient size 
 *       for the tag.
 * - 1 - Push all data after the tags up to make space for the tag.
 *       This method assumes there is sufficient space past the packet
 *       ending and that data after the xpkt can be clobbered.
 *
 * Returns:
 *  0 -> Operation succeeded
 * -1 -> Tag malformed
 * -2 -> Duplicate tag of a type that can have only one per xpkt
 * -3 -> Insufficient nop space and method == NOPCLOB.  OR insufficient
 *       tag space (will roll over tag length).
 */
int xpkt_add_tag(struct xpkt *x, struct xpkt_tag_hdr *xth, int moveup);

/*
 * Delete a tag from the xpkt.  The 'pulldown' field determines how the
 * tag will be deleted:
 * - 0 - Clobber the existing tag space with NOPS.
 * - 1 - Pull from the end of the packet down
 *
 * Returns
 *  0 -> success
 * -1 -> malformed tag
 */
int xpkt_del_tag(struct xpkt *x, byte_t tag, int idx, int pulldown);


/* tag definitions */

#define XPKT_TAG_NOP		0
#define XPKT_TAG_TIMESTAMP	1
#define XPKT_TAG_SNAPINFO	2
#define XPKT_TAG_INIFACE	3
#define XPKT_TAG_OUTIFACE	4
#define XPKT_TAG_FLOW		5
#define XPKT_TAG_CLASS		6
#define XPKT_TAG_PARSEINFO	7
#define XPKT_TAG_NUM_TYPES	8	/* Number of basic types defined */

#define XPKT_TAG_INVALID	127
#define XPKT_TAG_ANY		XPKT_TAG_INVALID
#define XPKT_TAG_APPINFO	128	/* first non-basic tag type */


#define XPKT_TAG_NOP_NWORDS		1
struct xpkt_tag_nop {
	byte_t			type;	/* 0 */
	byte_t			nwords; /* 1 */
	uint16_t		zero;	/* 0 */
};

void xpkt_tag_nop_init(struct xpkt_tag_nop *t);


#define XPKT_TAG_TIMESTAMP_NWORDS	3
struct xpkt_tag_ts {
	byte_t			type;	/* 1 */
	byte_t			nwords; /* 3 */
	uint16_t		zero;	/* 0 */
	uint32_t		sec;
	uint32_t		nsec;
};

void xpkt_tag_ts_init(struct xpkt_tag_ts *t, uint32_t sec, uint32_t nsec);


#define XPKT_TAG_SNAPINFO_NWORDS	2
struct xpkt_tag_snapinfo {
	byte_t			type;	/* 2 */
	byte_t			nwords; /* 2 */
	uint16_t		zero;	/* 0 */
	uint32_t		wirelen;
};

void xpkt_tag_si_init(struct xpkt_tag_snapinfo *t, uint32_t wirelen);


#define XPKT_TAG_INIFACE_NWORDS		1
#define XPKT_TAG_OUTIFACE_NWORDS	1
struct xpkt_tag_iface {
	byte_t			type;	/* 3|4 */
	byte_t			nwords; /* 1 */
	uint16_t		iface;
};

void xpkt_tag_iif_init(struct xpkt_tag_iface *t, uint16_t iface);
void xpkt_tag_oif_init(struct xpkt_tag_iface *t, uint16_t iface);


#define XPKT_TAG_FLOW_NWORDS		3
struct xpkt_tag_flowid {
	byte_t			type;	/* 5 */
	byte_t			nwords; /* 3 */
	uint16_t		zero;	/* 0 */
	uint64_t		flowid;
};

void xpkt_tag_flowid_init(struct xpkt_tag_flowid *t, uint64_t id);


#define XPKT_TAG_CLASS_NWORDS		3
struct xpkt_tag_class {
	byte_t			type;	/* 6 */
	byte_t			nwords; /* 3 */
	uint16_t		zero;	/* 0 */
	uint64_t		tag;
};

void xpkt_tag_class_init(struct xpkt_tag_class *t, uint64_t tag);


#define XPKT_TAG_PARSEINFO_NWORDS	3
struct xpkt_tag_parseinfo {
	byte_t			type;	/* 6 */
	byte_t			nwords; /* 3 */
	uint16_t		proto;
	uint32_t		off;
	uint32_t		len;
};

void xpkt_tag_pi_init(struct xpkt_tag_parseinfo *t, uint16_t proto,
		      uint32_t off, uint32_t len);


struct xpkt_tag_appinfo {
	byte_t			type;	/* 6 */
	byte_t			nwords; /* 3 */
	uint16_t		subtype;
	byte_t			data[254 * 4];
};

/* nw is the number of words of data in the tag */
/* if nw == 0, then p must not be null and nw must be <= 254 */
void xpkt_tag_ai_init(struct xpkt_tag_appinfo *t, uint16_t subtype,
		      uint32_t *p, uint nw);

#endif /* __xpkt_h */
