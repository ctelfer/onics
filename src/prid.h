#ifndef __prid_h
#define __prid_h

#define PRID_PROTO(prid)	((prid) & 0xFF)
#define PRID_FAMILY(prid)	(((prid) >> 8) & 0xFF)
#define PRID_BUILD(pf, proto)	((((pf) & 0xFF) << 8) | ((proto) & 0xFF))

/* Protocol Families */
#define PRID_PF_INET		0
#define PRID_PF_NET		1
#define PRID_PF_DLT		2
#define PRID_PF_RES		255
#define PRID_PER_PF		256

/*
   Protocol types for family _RES indices 128-255 are reserved 
   "meta protocol types".  They stand for entire classes of packets
   or special cases like 'no type', 'invalid' or 'any' (for matching).
*/
#define PRID_NONE               PRID_BUILD(PRID_PF_RES, 0)
#define PRID_META_MIN_PROTO	128
#define PRID_PCLASS_LINK	PRID_BUILD(PRID_PF_RES, 128)
#define PRID_PCLASS_TUNNEL	PRID_BUILD(PRID_PF_RES, 129)
#define PRID_PCLASS_NET		PRID_BUILD(PRID_PF_RES, 130)
#define PRID_PCLASS_XPORT	PRID_BUILD(PRID_PF_RES, 131)
#define PRID_PCLASS_MIN		PRID_PCLASS_LINK
#define PRID_PCLASS_MAX		PRID_PCLASS_XPORT
#define PRID_IS_PCLASS(prid) \
  (((prid) & PRID_BUILD(PRID_PF_RES, 252)) == PRID_BUILD(PRID_PF_RES, 128))
#define PRID_USER1		PRID_BUILD(PRID_PF_RES, 192)
#define PRID_USER2		PRID_BUILD(PRID_PF_RES, 193)
#define PRID_USER3		PRID_BUILD(PRID_PF_RES, 194)
#define PRID_USER4		PRID_BUILD(PRID_PF_RES, 195)
#define PRID_USER5		PRID_BUILD(PRID_PF_RES, 196)
#define PRID_USER6		PRID_BUILD(PRID_PF_RES, 197)
#define PRID_USER7		PRID_BUILD(PRID_PF_RES, 198)
#define PRID_USER8		PRID_BUILD(PRID_PF_RES, 199)
#define PRID_ANY		PRID_BUILD(PRID_PF_RES, 254)
#define PRID_INVALID            PRID_BUILD(PRID_PF_RES, 255)
#define PRID_MAX		PRID_INVALID


/* Standard protocol IDs */

/* standard data link layer protocols */
#define PRID_RAWPKT		PRID_BUILD(PRID_PF_DLT, 0)
#define PRID_ETHERNET2		PRID_BUILD(PRID_PF_DLT, 1)
#define PRID_DLT_MIN		PRID_RAWPKT
#define PRID_DLT_MAX		PRID_ETHERNET2

/* standard network level protocols */
#define PRID_IPV4		PRID_BUILD(PRID_PF_NET, 0)
#define PRID_IPV6		PRID_BUILD(PRID_PF_NET, 1)
#define PRID_ARP		PRID_BUILD(PRID_PF_NET, 2)

/* any IP protocol has a PRID of PRIT_BUILD(PRID_PF_INET, ip_proto) */
#define PRID_ICMP		PRID_BUILD(PRID_PF_INET, 1)
#define PRID_TCP		PRID_BUILD(PRID_PF_INET, 6)
#define PRID_UDP		PRID_BUILD(PRID_PF_INET, 17)
#define PRID_GRE		PRID_BUILD(PRID_PF_INET, 47)
#define PRID_ESP		PRID_BUILD(PRID_PF_INET, 50)
#define PRID_AH			PRID_BUILD(PRID_PF_INET, 51)
#define PRID_ICMP6		PRID_BUILD(PRID_PF_INET, 58)
#define PRID_SCTP		PRID_BUILD(PRID_PF_INET, 132)


#endif /* __prid_h */
