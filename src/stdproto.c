#include "config.h"
#include "protoparse.h"
#include "tcpip_hdrs.h"
#include "stdproto.h"
#include "util.h"
#include "ns.h"
#include <cat/emalloc.h>
#include <cat/pack.h>
#include <string.h>
#include <stdlib.h>

extern struct prparse_ops eth_prparse_ops;
extern struct prparse_ops arp_prparse_ops;
extern struct prparse_ops ipv4_prparse_ops;
extern struct prparse_ops ipv6_prparse_ops;
extern struct prparse_ops icmp_prparse_ops;
extern struct prparse_ops icmpv6_prparse_ops;
extern struct prparse_ops udp_prparse_ops;
extern struct prparse_ops tcp_prparse_ops;


struct ipv6_parse {
	struct prparse prp;
	uint8_t nexth;
	long jlenoff;
};


struct arp_parse {
	struct prparse prp;
	long xfields[PRP_ARP_NXFIELDS];
};


struct ip_parse {
	struct prparse prp;
	long xfields[PRP_IP_NXFIELDS];
};


struct tcp_parse {
	struct prparse prp;
	long xfields[PRP_TCP_NXFIELDS];
};


static void resetxfields(struct prparse *prp)
{
	uint i;
	for (i = PRP_OI_EXTRA; i < prp->noff; ++i)
		prp->offs[i] = PRP_OFF_INVALID;
}


/* NB:  right now we are using emalloc() fpr header allocation, but we */
/* may not do that in the future.  When that happens, we need to change */
/* newprp, crtprp, and freeprp */
static struct prparse *newprp(size_t sz, unsigned type,
			      struct prparse *pprp, struct prparse_ops *ops,
			      uint nxfields)
{
	struct prparse *prp;
	abort_unless(sz >= sizeof(struct prparse));
	prp = emalloc(sz);
	prp->type = type;
	prp->data = pprp->data;
	prp->error = 0;
	prp_soff(prp) = prp_poff(pprp);
	prp_eoff(prp) = prp_toff(pprp);
	prp_poff(prp) = prp_soff(prp);
	prp_toff(prp) = prp_eoff(prp);
	prp->noff = PRP_OI_MIN_NUM + nxfields;
	prp->ops = ops;
	/* all of the default protocol parsers nest layers within layers  */
	/* this won't be true for all protocol parsers */
	prp->region = pprp;
	l_ins(&pprp->node, &prp->node);
	resetxfields(prp);
	return prp;
}

static struct prparse *crtprp(size_t sz, unsigned type, byte_t * buf,
			      long off, long hlen, long plen,
			      long tlen, struct prparse_ops *ops, uint nxfields)
{
	struct prparse *prp;
	abort_unless(sz >= sizeof(struct prparse));
	prp = emalloc(sz);
	prp->type = type;
	prp->data = buf;
	prp->error = 0;
	prp_soff(prp) = off;
	prp_poff(prp) = off + hlen;
	prp_toff(prp) = off + hlen + plen;
	prp_eoff(prp) = off + hlen + plen + tlen;
	prp->noff = PRP_OI_MIN_NUM + nxfields;
	abort_unless(prp_soff(prp) >= 0 && prp_poff(prp) >= prp_soff(prp) &&
		     prp_toff(prp) >= prp_poff(prp) &&
		     prp_eoff(prp) >= prp_toff(prp));
	prp->ops = ops;
	l_init(&prp->node);
	resetxfields(prp);
	return prp;
}


static NETTOOLS_INLINE void freeprp(struct prparse *prp)
{
	free(prp);
}


static struct prparse *default_parse(struct prparse *pprp, uint * nextppt)
{
	return NULL;
}


static struct prparse *default_create(byte_t * start, long off, long len,
				      long hlen, long plen, int mode)
{
	return NULL;
}


static void default_update(struct prparse *prp)
{
	resetxfields(prp);
}


static int default_fixlen(struct prparse *prp)
{
	return 0;
}


static int default_fixcksum(struct prparse *prp)
{
	return 0;
}


static void default_free(struct prparse *prp)
{
	/* presently unused */
	(void)default_create;
	(void)default_parse;
	(void)default_update;
	freeprp(prp);
}


static struct prparse *simple_copy(struct prparse *oprp, size_t psize,
				   byte_t * buffer)
{
	struct prparse *prp;
	if (oprp == NULL)
		return NULL;
	prp = emalloc(psize);
	memcpy(prp, oprp, psize);
	prp->region = NULL;
	l_init(&prp->node);
	prp->data = buffer;
	return prp;
}


static struct prparse *default_copy(struct prparse *oprp, byte_t * buffer)
{
	return simple_copy(oprp, sizeof(struct prparse), buffer);
}


/* -- ops for Ethernet type -- */
/* TODO: add vlan parsing */
static struct prparse *eth_parse(struct prparse *pprp, uint * nextppt)
{
	struct prparse *prp;
	ushort etype;
	struct eth2h *eh;

	abort_unless(pprp && nextppt);

	prp = newprp(sizeof(*prp), PPT_ETHERNET2, pprp, &eth_prparse_ops, 0);
	if (!prp)
		return NULL;
	if (prp_totlen(prp) < ETHHLEN) {
		prp->error = PPERR_TOOSMALL;
		*nextppt = PPT_INVALID;
	} else {
		prp_poff(prp) = prp_soff(prp) + ETHHLEN;
		eh = prp_header(prp, struct eth2h);
		unpack(&eh->ethtype, 2, "h", &etype);
		switch (etype) {
		case ETHTYPE_IP:
			*nextppt = PPT_IPV4;
			break;
		case ETHTYPE_IPV6:
			*nextppt = PPT_IPV6;
			break;
		case ETHTYPE_ARP:
			*nextppt = PPT_ARP;
			break;
		default:
			*nextppt = PPT_INVALID;
		}
	}
	return prp;
}


static struct prparse *eth_create(byte_t * start, ulong off, ulong len,
				  ulong hlen, ulong plen, int mode)
{
	struct prparse *prp;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len && start);

	if (mode == PPCF_FILL) {
		if (len < ETHHLEN)
			return NULL;
		plen = len - ETHHLEN;
		hlen = ETHHLEN;
	} else if (mode == PPCF_WRAP) {
		if (hlen < ETHHLEN)
			return NULL;
		hlen = ETHHLEN;
		off -= ETHHLEN;
		len = plen + hlen;
	} else {
		abort_unless(len - plen >= hlen);
		abort_unless(mode == PPCF_WRAPFILL);
		if (hlen < ETHHLEN)
			return NULL;
	}
	prp = crtprp(sizeof(struct prparse), PPT_ETHERNET2, start, off, hlen,
		     plen, 0, &eth_prparse_ops, 0);
	if (prp)
		memset(start + off, 0, ETHHLEN);

	return prp;
}


static void eth_update(struct prparse *prp)
{
	if (prp_totlen(prp) < ETHHLEN) {
		prp->error |= PPERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) != ETHHLEN)
		prp->error |= PPERR_HLEN;
}


/* -- ops for ARP type -- */
static byte_t ethiparpstr[6] = {0, 1, 8, 0, 6, 4 };

static struct prparse *arp_parse(struct prparse *pprp, uint * nextppt)
{
	struct prparse *prp;

	abort_unless(pprp && nextppt);

	prp = newprp(sizeof(struct arp_parse), PPT_ARP, pprp, &arp_prparse_ops,
		     PRP_ARP_NXFIELDS);
	if (!prp)
		return NULL;
	*nextppt = PPT_INVALID;

	if (prp_totlen(prp) < 8) {
		prp->error = PPERR_TOOSMALL;
	} else {
		prp_poff(prp) = prp_soff(prp) + 8;
		/* check for short ether-ip ARP packet */
		if (!
		    (memcmp
		     (ethiparpstr, prp_header(prp, void), sizeof(ethiparpstr)))
		    && (prp_plen(prp) < 20))
			 prp->error = PPERR_INVALID;
		prp->offs[PRP_ARPFLD_ETHARP] = prp_soff(prp);
	}
	return prp;
}


static void arp_update(struct prparse *prp)
{
	if (prp_totlen(prp) < 8) {
		prp->error |= PPERR_TOOSMALL;
		return;
	}
	prp_poff(prp) = prp_soff(prp) + 8;
	resetxfields(prp);
	if (!(memcmp(ethiparpstr, prp_header(prp, void), sizeof(ethiparpstr)))
	    && (prp_plen(prp) < 20)) {
		prp->error = PPERR_INVALID;
	} else {
		prp->offs[PRP_ARPFLD_ETHARP] = prp_soff(prp);
	}
}


static int arp_fixlen(struct prparse *prp)
{
	if (prp_hlen(prp) < 8)
		return -1;
	return 0;
}


static struct prparse *arp_create(byte_t * start, ulong off, ulong len,
				  ulong hlen, ulong plen, int mode)
{
	struct prparse *prp;
	struct arph *arp;
	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len && start);
	if ((mode != PPCF_FILL) || (len < 8))
		return NULL;
	prp =
	    crtprp(sizeof(struct arp_parse), PPT_ARP, start, off, 8, len - 8, 0,
		   &arp_prparse_ops, PRP_ARP_NXFIELDS);
	if (prp) {
		memset(start + off, 0, prp_totlen(prp));
		if (prp_plen(prp) >= 20) {
			prp_toff(prp) = prp_eoff(prp) = prp_poff(prp) + 20;
			prp->offs[PRP_ARPFLD_ETHARP] = prp_soff(prp);
			arp = prp_header(prp, struct arph);
			pack(&arp, 8, "hhbbh", ARPT_ETHERNET, ETHTYPE_IP, 6, 4,
			     ARPOP_REQUEST);
		}
	}
	return prp;
}

static struct prparse *arp_copy(struct prparse *oprp, byte_t * buffer)
{
	return simple_copy(oprp, sizeof(struct arp_parse), buffer);
}

/* -- ops for IPV4 type -- */
static struct prparse *ipv4_parse(struct prparse *pprp, uint * nextppt)
{
	struct prparse *prp;
	struct ipv4h *ip;
	int hlen, tlen;
	ushort iplen;
	uint16_t sum;

	/* TODO: change size when we add provisions for option parsing */
	prp = newprp(sizeof(struct ip_parse), PPT_IPV4, pprp, &ipv4_prparse_ops,
		     PRP_IP_NXFIELDS);
	if (!prp)
		return NULL;

	ip = prp_header(prp, struct ipv4h);
	hlen = IPH_HLEN(*ip);
	tlen = prp_totlen(prp);
	if (tlen < 20) {
		prp->error |= PPERR_TOOSMALL;
		*nextppt = PPT_INVALID;
	} else if (hlen > tlen) {
		prp->error |= PPERR_HLEN;
		*nextppt = PPT_INVALID;
	} else {
		if ((ip->vhl & 0xf0) != 0x40)
			prp->error |= PPERR_INVALID;
		prp_poff(prp) = prp_soff(prp) + hlen;
		unpack(&ip->len, 2, "h", &iplen);
		if (iplen > prp_totlen(prp))
			prp->error |= PPERR_LENGTH;
		else if (iplen < prp_totlen(prp))
			prp_toff(prp) = prp_soff(prp) + iplen;
		sum = ~ones_sum(ip, hlen, 0);
		if (sum != 0) {
			prp->error |= PPERR_CKSUM;
			return prp;
		}
		if (ip->fragoff != 0) {
			uint16_t fragoff = ntoh32(ip->fragoff);
			if ((uint32_t) IPH_FRAGOFF(fragoff) + iplen > 65535)
				prp->error |= PPERR_INVALID;
			if ((IPH_RFMASK & fragoff))
				prp->error |= PPERR_INVALID;
		}
		if (hlen > 20) {
			/* TODO: parse IP options */
		}
		*nextppt = PPT_BUILD(PPT_PF_INET, ip->proto);
	}
	return prp;
}


static struct prparse *ipv4_create(byte_t * start, ulong off, ulong len,
				   ulong hlen, ulong plen, int mode)
{
	struct prparse *prp;
	struct ipv4h *ip;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len && start);

	if (mode == PPCF_FILL) {
		if ((len < 20) || (len > 65535))
			return NULL;
		hlen = 20;
		plen = len - 20;
	} else if (mode == PPCF_WRAP) {
		if (hlen < 20)
			return NULL;
		if (plen > 65515)
			plen = 65515;
		hlen = 20;
		off -= 20;
	} else {
		abort_unless(mode == PPCF_WRAPFILL);
		if ((hlen < 20) || (hlen > 60) || ((hlen & 0x3) != 0) ||
		    (len != plen + hlen) || (len > 65535))
			return NULL;
	}
	prp =
	    crtprp(sizeof(struct ip_parse), PPT_IPV4, start, off, hlen, plen, 0,
		   &ipv4_prparse_ops, PRP_IP_NXFIELDS);
	if (prp) {
		ip = prp_header(prp, struct ipv4h);
		memset(ip, 0, prp_hlen(prp));
		ip->vhl = 0x40 | (hlen >> 2);
		ip->len = hton16(prp_totlen(prp));
		/* TODO: fill options with noops if header > 20? */
	}
	return prp;
}


static void ipv4_update(struct prparse *prp)
{
	resetxfields(prp);
	if (prp_totlen(prp) < 20) {
		prp->error |= PPERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < 20) {
		prp->error |= PPERR_HLEN;
		return;
	}
	/* TODO: parse options */
}


static int ipv4_fixlen(struct prparse *prp)
{
	struct ipv4h *ip;
	long hlen;
	ushort tlen;

	abort_unless(prp && prp->data);

	ip = prp_header(prp, struct ipv4h);
	hlen = prp_hlen(prp);
	if ((hlen < 20) || (hlen > 60) || (hlen > prp_totlen(prp)))
		return -1;
	ip->vhl = 0x40 | (hlen >> 2);
	if (prp_totlen(prp) > 65535)
		return -1;
	tlen = prp_totlen(prp);
	pack(&ip->len, 2, "h", tlen);
	return 0;
}


static int ipv4_fixcksum(struct prparse *prp)
{
	long hlen;
	struct ipv4h *ip;

	abort_unless(prp && prp->data);
	ip = prp_header(prp, struct ipv4h);
	hlen = IPH_HLEN(*ip);
	if (hlen < 20)
		return -1;
	ip->cksum = 0;
	ip->cksum = ~ones_sum(ip, IPH_HLEN(*ip), 0);

	return 0;
}


static struct prparse *ipv4_copy(struct prparse *oprp, byte_t * buffer)
{
	return simple_copy(oprp, sizeof(struct ip_parse), buffer);
}


static void ipv4_free(struct prparse *prp)
{
	freeprp(prp);
}


static uint16_t pseudo_cksum(struct prparse *prp, uint8_t proto)
{
	struct prparse *pprp = prp->region;
	uint16_t sum = 0;
	if (pprp->type == PPT_IPV4) {
		struct pseudoh ph;
		struct ipv4h *ip = prp_header(pprp, struct ipv4h);
		memset(&ph, 0, sizeof(ph));
		ph.saddr = ip->saddr;
		ph.daddr = ip->daddr;
		ph.proto = proto;
		ph.totlen = ntoh16(prp_totlen(prp));
		sum = ones_sum(&ph, 12, 0);
	} else {
		struct pseudo6h ph;
		struct ipv6h *ip6 = prp_header(pprp, struct ipv6h);
		abort_unless(pprp->type == PPT_IPV6);
		memset(&ph, 0, sizeof(ph));
		ph.saddr = ip6->saddr;
		ph.daddr = ip6->daddr;
		ph.proto = proto;
		ph.totlen = ntoh32(prp_totlen(prp));
		sum = ones_sum(&ph, 40, 0);
	}
	return ~ones_sum(prp_header(prp, void), prp_totlen(prp), sum);
}


/* -- parse options for UDP protocol -- */
static struct prparse *udp_parse(struct prparse *pprp, uint * nextppt)
{
	struct prparse *prp;
	struct udph *udp;

	switch (pprp->type) {
	case PPT_IPV4:
	case PPT_IPV6:
		break;
	default:
		return NULL;
	}
	prp = newprp(sizeof(*prp), PPT_UDP, pprp, &udp_prparse_ops, 0);
	if (!prp)
		return NULL;
	*nextppt = PPT_INVALID;
	if (prp_totlen(prp) < 8) {
		prp->error |= PPERR_TOOSMALL;
	} else if ((pprp->error & PPERR_LENGTH)) {
		prp_poff(prp) = prp_soff(prp) + 8;
		prp->error |= PPERR_LENGTH;
		prp->error |= PPERR_CKSUM;
	} else {
		prp_poff(prp) = prp_soff(prp) + 8;
		udp = prp_header(prp, struct udph);
		if ((udp->cksum != 0) && (pseudo_cksum(prp, IPPROT_UDP) != 0))
			prp->error |= PPERR_CKSUM;
	}
	return prp;
}


static struct prparse *udp_create(byte_t * start, ulong off, ulong len,
				  ulong hlen, ulong plen, int mode)
{
	struct prparse *prp;
	struct udph *udp;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len && start);

	if (mode == PPCF_FILL) {
		if (len < 8)
			return NULL;
		hlen = 8;
		plen = len - 8;
		if (plen > 65527)
			return NULL;
	} else if (mode == PPCF_WRAP) {
		if (hlen < 8)
			return NULL;
		hlen = 8;
		off -= 8;
		if (plen > 65527)
			plen = 65527;
	} else {
		abort_unless(mode == PPCF_WRAPFILL);
		if ((hlen != 8) || (plen > 65527) || (len != hlen + plen))
			return NULL;
	}
	prp = crtprp(sizeof(*prp), PPT_UDP, start, off, hlen, plen, 0,
		     &udp_prparse_ops, 0);
	if (prp) {
		udp = prp_header(prp, struct udph);
		memset(udp, 0, sizeof(*udp));
		pack(&udp->len, 2, "h", (ushort) prp_totlen(prp));
	}
	return prp;
}


static void udp_update(struct prparse *prp)
{
	if (prp_totlen(prp) < 8) {
		prp->error = PPERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < 8) {
		prp->error = PPERR_HLEN;
		return;
	}
}


static int udp_fixlen(struct prparse *prp)
{
	if (prp_hlen(prp) != 8)
		return -1;
	if (prp_plen(prp) > 65527)
		return -1;
	pack(&prp_header(prp, struct udph)->len, 2, "h",
	     (ushort) prp_totlen(prp));
	return 0;
}


static int udp_fixcksum(struct prparse *prp)
{
	struct udph *udp = prp_header(prp, struct udph);
	abort_unless(prp->region);
	if ((prp_hlen(prp) != 8) ||
	    ((prp->region->type != PPT_IPV4) &&
	     (prp->region->type != PPT_IPV6)))
		return -1;
	udp->cksum = 0;
	udp->cksum = pseudo_cksum(prp, IPPROT_UDP);
	return 0;
}


/* -- TCP functions -- */
static struct prparse *tcp_parse(struct prparse *pprp, uint * nextppt)
{
	struct prparse *prp;
	struct tcph *tcp;
	int hlen, tlen;

	switch (pprp->type) {
	case PPT_IPV4:
	case PPT_IPV6:
		break;
	default:
		return NULL;
	}

	prp = newprp(sizeof(struct tcp_parse), PPT_TCP, pprp, &tcp_prparse_ops,
		     PRP_TCP_NXFIELDS);
	if (!prp)
		return NULL;
	*nextppt = PPT_INVALID;
	tcp = prp_header(prp, struct tcph);
	hlen = TCPH_HLEN(*tcp);
	tlen = prp_totlen(prp);
	if (tlen < 20) {
		prp->error |= PPERR_TOOSMALL;
	} else if (hlen > tlen) {
		prp->error |= PPERR_HLEN;
	} else if ((pprp->error & PPERR_LENGTH)) {
		prp_poff(prp) = prp_soff(prp) + hlen;
		prp->error |= PPERR_LENGTH;
		prp->error |= PPERR_CKSUM;
	} else {
		prp_poff(prp) = prp_soff(prp) + hlen;
		if (pseudo_cksum(prp, IPPROT_TCP) != 0)
			prp->error |= PPERR_CKSUM;
		if (hlen > 20) {
			/* TODO: parse TCP options */
		}
	}
	return prp;
}


static struct prparse *tcp_create(byte_t * start, ulong off, ulong len,
				  ulong hlen, ulong plen, int mode)
{
	struct prparse *prp;
	struct tcph *tcp;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len && start);

	if (mode == PPCF_FILL) {
		if (len < 20)
			return NULL;
		hlen = 20;
		plen = len - 20;
	} else if (mode == PPCF_WRAP) {
		if (hlen < 20)
			return NULL;
		hlen = 20;
		off -= 20;
		len = plen + hlen;
	} else {
		abort_unless(mode == PPCF_WRAPFILL);
		if ((hlen < 20) || (hlen > 60) || ((hlen & 3) != 0) ||
		    (len != hlen + plen))
			return NULL;
	}
	prp =
	    crtprp(sizeof(struct tcp_parse), PPT_TCP, start, off, hlen, plen, 0,
		   &tcp_prparse_ops, PRP_TCP_NXFIELDS);
	if (prp) {
		memset(prp_header(prp, void), 0, prp_hlen(prp));
		tcp = prp_header(prp, struct tcph);
		tcp->doff = hlen << 2;
	}
	return prp;
}


static void tcp_update(struct prparse *prp)
{
	resetxfields(prp);
	if (prp_totlen(prp) < 20) {
		prp->error = PPERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < 20) {
		prp->error = PPERR_HLEN;
		return;
	}
	/* TODO: parse options */
}


static int tcp_fixlen(struct prparse *prp)
{
	struct tcph *tcp;
	long hlen;

	abort_unless(prp && prp->data);
	tcp = prp_header(prp, struct tcph);
	hlen = prp_hlen(prp);
	if ((hlen < 20) || (hlen > 60) || (hlen > prp_totlen(prp)))
		return -1;
	tcp->doff = hlen << 2;

	return 0;
}


static int tcp_fixcksum(struct prparse *prp)
{
	struct tcph *tcp = prp_header(prp, struct tcph);
	abort_unless(prp->region);
	if ((prp->region->type != PPT_IPV4) && (prp->region->type != PPT_IPV6))
		return -1;
	tcp->cksum = 0;
	tcp->cksum = pseudo_cksum(prp, IPPROT_TCP);
	return 0;
}


static struct prparse *tcp_copy(struct prparse *oprp, byte_t * buffer)
{
	return simple_copy(oprp, sizeof(struct tcp_parse), buffer);
}


static void tcp_free(struct prparse *prp)
{
	freeprp(prp);
}


/* -- ICMP Protocol functions -- */
#if 0
if (pprp->type == PPT_ICMP) {
	struct icmph *icmp = prp_header(pprp, struct icmph);
}
#endif
static struct prparse *icmp_parse(struct prparse *pprp, uint * nextppt)
{
	struct prparse *prp;
	struct icmph *icmp;
	uint16_t csum;

	prp = newprp(sizeof(*prp), PPT_ICMP, pprp, &icmp_prparse_ops, 0);
	if (!prp)
		return NULL;
	*nextppt = PPT_INVALID;

	if (prp_totlen(prp) < 8) {
		prp->error |= PPERR_TOOSMALL;
		goto done;
	}
	if ((pprp->error & PPERR_LENGTH)) {
		prp_poff(prp) = prp_soff(prp) + 8;
		prp->error |= PPERR_LENGTH;
		prp->error |= PPERR_CKSUM;
		goto done;
	} else {
		prp_poff(prp) = prp_soff(prp) + 8;
		icmp = prp_header(prp, struct icmph);
		csum = ~ones_sum(icmp, prp_totlen(prp), 0);
		if (csum)
			prp->error |= PPERR_CKSUM;
	}
	/* types which can have a returned IP header in them */
	if ((icmp->type == ICMPT_DEST_UNREACH) ||
	    (icmp->type == ICMPT_TIME_EXCEEDED) ||
	    (icmp->type == ICMPT_PARAM_PROB) ||
	    (icmp->type == ICMPT_SRC_QUENCH) ||
	    (icmp->type == ICMPT_REDIRECT)) {
		*nextppt = PPT_IPV4;
	}

done:
	return prp;
}


static struct prparse *icmp_create(byte_t * start, ulong off, ulong len,
				   ulong hlen, ulong plen, int mode)
{
	struct prparse *prp;
	struct icmph *icmp;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len && start);

	if (mode == PPCF_FILL) {
		if (len < 8)
			return NULL;
		hlen = 8;
		plen = len - 8;
	} else if (mode == PPCF_WRAP) {
		if (hlen < 8)
			return NULL;
		hlen = 8;
		off -= 8;
	} else {
		abort_unless(mode == PPCF_WRAPFILL);
		if ((hlen != 8) || (len != hlen + plen))
			return NULL;
	}
	prp = crtprp(sizeof(struct prparse), PPT_ICMP, start, off, hlen, plen, 
	             0, &icmp_prparse_ops, 0);
	if (prp) {
		icmp = prp_header(prp, struct icmph);
		memset(icmp, 0, sizeof(*icmp));
	}
	return prp;
}


static void icmp_update(struct prparse *prp)
{
	if (prp_totlen(prp) < 8) {
		prp->error = PPERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < 8) {
		prp->error = PPERR_HLEN;
		return;
	}
	/* TODO: check by type? */
}


static int icmp_fixcksum(struct prparse *prp)
{
	struct icmph *icmp = prp_header(prp, struct icmph);
	if ((prp_hlen(prp) != 8) || (prp->region->type != PPT_IPV4))
		return -1;
	icmp->cksum = 0;
	icmp->cksum = ~ones_sum(icmp, prp_totlen(prp), 0);
	return 0;
}


/* -- IPv6 functions -- */
static int isv6ext(uint8_t proto)
{
	/* we consider IPsec protocols their own protocol */
	return (proto == IPPROT_V6_HOPOPT) ||
	    (proto == IPPROT_V6_ROUTE_HDR) ||
	    (proto == IPPROT_V6_FRAG_HDR) ||
	    (proto == IPPROT_V6_DSTOPS) || (proto == IPPROT_AH);
}


/* search for jumbogram options */
static int parse_ipv6_hopopt(struct ipv6_parse *ip6prp, struct ipv6h *ip6,
			     byte_t * p, long olen)
{
	byte_t *end = p + olen;

	abort_unless(olen >= 0);

	p += 2;
	while (p < end) {
		if (*p == 0) {	/* pad1 option */
			++p;
			continue;
		}
		if (p + p[1] + 2 > end) {	/* padn + all other options */
			ip6prp->prp.error |= PPERR_OPTLEN;
			return -1;
		}
		if (*p == 0xC2) {	/* jumbogram option */
			if ((p[1] != 4) || (ip6->len != 0)
			    || (ip6prp->jlenoff > 0)
			    || (((p - (byte_t *) ip6) & 3) != 2)) {
				ip6prp->prp.error |= PPERR_OPTERR;
				return -1;
			}
			ip6prp->jlenoff = p - (byte_t *) ip6;
		}
		p += p[1] + 2;
	}
	return 0;
}


static int parse_ipv6_opt(struct ipv6_parse *ip6prp, struct ipv6h *ip6,
			  long len)
{
	size_t xlen = 0;
	uint8_t nexth;
	uint olen;
	byte_t *p;

	abort_unless(len >= 0);

	nexth = ip6->nxthdr;
	p = (byte_t *) ip6 + 40;

	while (isv6ext(nexth)) {
		if ((xlen + 8 < xlen) || (xlen + 8 > len)) {
			ip6prp->prp.error |= PPERR_OPTLEN;
			return -1;
		}
		if (nexth == IPPROT_AH)	/* AH is idiotic and useless */
			olen = (p[1] << 2) + 8;
		else
			olen = (p[1] << 3) + 8;
		if ((xlen + olen < xlen) || (xlen + olen > len)) {
			ip6prp->prp.error |= PPERR_OPTLEN;
			return -1;
		}
		/* hop-by-hop options can only come first */
		if (nexth == IPPROT_V6_HOPOPT) {
			if (p != (byte_t *) ip6 + 40) {
				ip6prp->prp.error |= PPERR_OPTERR;
			} else {
				if (parse_ipv6_hopopt(ip6prp, ip6, p, olen) < 0)
					return -1;
			}
		}

		nexth = p[0];
		xlen += olen;
		p += olen;
	}

	prp_poff(&ip6prp->prp) = prp_soff(&ip6prp->prp) + 40 + xlen;
	ip6prp->nexth = nexth;

	return 0;
}


static struct prparse *ipv6_parse(struct prparse *pprp, uint * nextppt)
{
	struct prparse *prp;
	struct ipv6_parse *ip6prp;
	struct ipv6h *ip6;
	ushort paylen;
	long tlen;

	prp =
	    newprp(sizeof(struct ipv6_parse), PPT_IPV6, pprp, &ipv6_prparse_ops,
		   0);
	ip6prp = (struct ipv6_parse *)prp;
	if (!prp)
		return NULL;
	*nextppt = PPT_INVALID;
	ip6prp->nexth = 0;
	ip6prp->jlenoff = 0;
	ip6 = prp_header(prp, struct ipv6h);

	if (IPV6H_PVERSION(ip6) != 6) {
		prp->error |= PPERR_INVALID;
		goto done;
	}

	tlen = prp_totlen(prp);
	if (tlen < 40) {
		prp->error |= PPERR_TOOSMALL;
		goto done;
	}

	unpack(&ip6->len, 2, "h", &paylen);
	if (tlen < (uint32_t) paylen + 40) {
		prp->error |= PPERR_LENGTH;
	}

	/* sets hlen */
	if (parse_ipv6_opt(ip6prp, ip6, tlen - 40) < 0)
		goto done;

	if ((paylen == 0) && (ip6prp->jlenoff > 0)) {
		unsigned long jlen;
		unpack(prp_payload(prp) + ip6prp->jlenoff, 4, "w", &jlen);
		if ((jlen != prp_totlen(prp) - 40) || (jlen < 65536))
			prp->error |= PPERR_LENGTH;
	} else if (tlen > (uint32_t) paylen + 40) {
		prp_toff(prp) = prp_soff(prp) + 40 + paylen;
	}
	*nextppt = PPT_BUILD(PPT_PF_INET, ip6prp->nexth);

 done:
	return prp;
}


static struct prparse *ipv6_create(byte_t * start, ulong off, ulong len,
				   ulong hlen, ulong plen, int mode)
{
	struct prparse *prp;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len && start);

	if (mode == PPCF_FILL) {
		/* TODO support jumbo frames ? */
		if ((len < 40) || (len > 65575))
			return NULL;
		hlen = 40;
		plen = len - 40;
	} else if (mode == PPCF_WRAP) {
		if (hlen < 40)
			return NULL;
		if (plen > 65535)
			len = 65535;
		hlen = 40;
		off -= 40;
	} else {
		abort_unless(mode == PPCF_WRAPFILL);
		if ((hlen != 40) || (plen > 65535) || (hlen + plen != len))
			return NULL;
	}
	prp =
	    crtprp(sizeof(struct ipv6_parse), PPT_IPV6, start, off, hlen, plen,
		   0, &ipv6_prparse_ops, 0);
	if (prp) {
		struct ipv6_parse *ip6prp = (struct ipv6_parse *)prp;
		struct ipv6h *ip6 = prp_header(prp, struct ipv6h);
		ip6prp->nexth = 0;
		ip6prp->jlenoff = 0;
		memset(ip6, 0, prp_hlen(prp));
		*(byte_t *) ip6 = 0x60;
		ip6->len = hton16(prp_totlen(prp));
	}
	return prp;
}


static void ipv6_update(struct prparse *prp)
{
	if (prp_totlen(prp) < 40) {
		prp->error = PPERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < 40) {
		prp->error = PPERR_HLEN;
		return;
	}
	/* TODO: parse options */
}


static int ipv6_fixlen(struct prparse *prp)
{
	struct ipv6h *ip6;
	ushort plen;
	abort_unless(prp && prp->data);
	ip6 = prp_header(prp, struct ipv6h);
	if (prp_plen(prp) > 65535)
		return -1;
	plen = prp_plen(prp);
	pack(&ip6->len, 2, "h", plen);
	return 0;
}


static struct prparse *ipv6_copy(struct prparse *oprp, byte_t * buffer)
{
	return simple_copy(oprp, sizeof(struct ipv6_parse), buffer);
}


static void ipv6_free(struct prparse *prp)
{
	freeprp(prp);
}


/* -- ICMPv6 Functions -- */
static struct prparse *icmp6_parse(struct prparse *pprp, uint * nextppt)
{
	struct prparse *prp;
	struct icmp6h *icmp6;

	prp = newprp(sizeof(*prp), PPT_ICMP6, pprp, &icmpv6_prparse_ops, 0);
	if (!prp)
		return NULL;
	*nextppt = PPT_INVALID;
	if (prp_totlen(prp) < 8) {
		prp->error |= PPERR_TOOSMALL;
		goto done;
	}
	if ((pprp->error & PPERR_LENGTH)) {
		prp_poff(prp) = prp_soff(prp) + 8;
		prp->error |= PPERR_LENGTH;
		prp->error |= PPERR_CKSUM;
	} else {
		abort_unless(pprp->type == PPT_IPV6);
		prp_poff(prp) = prp_soff(prp) + 8;
		if (pseudo_cksum(prp, IPPROT_ICMPV6) != 0)
			prp->error |= PPERR_CKSUM;
	}
	icmp6 = prp_header(pprp, struct icmp6h);
	if ((icmp6->type == ICMP6T_DEST_UNREACH) ||
	    (icmp6->type == ICMP6T_PKT_TOO_BIG) ||
	    (icmp6->type == ICMP6T_TIME_EXCEEDED) ||
	    (icmp6->type == ICMP6T_PARAM_PROB))
		*nextppt = PPT_IPV6;

 done:
	return prp;
}


static struct prparse *icmp6_create(byte_t * start, ulong off, ulong len,
				    ulong hlen, ulong plen, int mode)
{
	struct prparse *prp;
	struct icmp6h *icmp6;

	abort_unless(off >= 0 && len >= 0 && hlen >= 0 && plen >= 0);
	abort_unless(plen <= len && start);

	if (mode == PPCF_FILL) {
		if (len < 8)
			return NULL;
		hlen = 8;
		plen = len - 8;
	} else if (mode == PPCF_WRAP) {
		if (hlen < 8)
			return NULL;
		hlen = 8;
		off -= 8;
	} else {
		abort_unless(mode == PPCF_WRAPFILL);
		if ((hlen != 8) || (len != hlen + plen))
			return NULL;
	}
	prp = crtprp(sizeof(struct prparse), PPT_ICMP6, start, off, hlen, plen,
		     0, &icmpv6_prparse_ops, 0);
	if (prp) {
		icmp6 = prp_header(prp, struct icmp6h);
		memset(icmp6, 0, sizeof(*icmp6));
	}
	return prp;
}


static void icmp6_update(struct prparse *prp)
{
	if (prp_totlen(prp) < 8) {
		prp->error = PPERR_TOOSMALL;
		return;
	}
	if (prp_hlen(prp) < 8) {
		prp->error = PPERR_HLEN;
		return;
	}
	/* TODO: check by type? */
}


static int icmp6_fixcksum(struct prparse *prp)
{
	struct icmp6h *icmp6 = prp_header(prp, struct icmp6h);
	if ((prp_hlen(prp) != 8) || (prp->region->type != PPT_IPV6))
		return -1;
	icmp6->cksum = 0;
	icmp6->cksum = pseudo_cksum(prp, IPPROT_ICMPV6);
	return 0;
}


/* -- op structures for default initialization -- */
struct proto_parser_ops eth_proto_parser_ops = {
	eth_parse,
	eth_create
};

struct prparse_ops eth_prparse_ops = {
	eth_update,
	default_fixlen,
	default_fixcksum,
	default_copy,
	default_free
};

struct proto_parser_ops arp_proto_parser_ops = {
	arp_parse,
	arp_create
};

struct prparse_ops arp_prparse_ops = {
	arp_update,
	arp_fixlen,
	default_fixcksum,
	arp_copy,
	default_free
};

struct proto_parser_ops ipv4_proto_parser_ops = {
	ipv4_parse,
	ipv4_create
};

struct prparse_ops ipv4_prparse_ops = {
	ipv4_update,
	ipv4_fixlen,
	ipv4_fixcksum,
	ipv4_copy,
	ipv4_free
};

struct proto_parser_ops ipv6_proto_parser_ops = {
	ipv6_parse,
	ipv6_create
};

struct prparse_ops ipv6_prparse_ops = {
	ipv6_update,
	ipv6_fixlen,
	default_fixcksum,
	ipv6_copy,
	ipv6_free
};

struct proto_parser_ops icmp_proto_parser_ops = {
	icmp_parse,
	icmp_create
};

struct prparse_ops icmp_prparse_ops = {
	icmp_update,
	default_fixlen,
	icmp_fixcksum,
	default_copy,
	default_free
};

struct proto_parser_ops icmpv6_proto_parser_ops = {
	icmp6_parse,
	icmp6_create
};

struct prparse_ops icmpv6_prparse_ops = {
	icmp6_update,
	default_fixlen,
	icmp6_fixcksum,
	default_copy,
	default_free
};

struct proto_parser_ops udp_proto_parser_ops = {
	udp_parse,
	udp_create
};

struct prparse_ops udp_prparse_ops = {
	udp_update,
	udp_fixlen,
	udp_fixcksum,
	default_copy,
	default_free
};

struct proto_parser_ops tcp_proto_parser_ops = {
	tcp_parse,
	tcp_create
};

struct prparse_ops tcp_prparse_ops = {
	tcp_update,
	tcp_fixlen,
	tcp_fixcksum,
	tcp_copy,
	tcp_free
};




/* --------- Namespaces ---------- */

#define STDPROTO_NS_ELEN	64
#define STDPROTO_NS_SUB_ELEN	16
/* TODO add option fields */
/* TODO: add vlan fields*/

extern struct ns_elem *stdproto_eth2_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace eth2_ns = 
	NS_NAMESPACE_I("eth", NULL, PPT_ETHERNET2, stdproto_eth2_ns_elems);

static struct ns_pktfld eth2_ns_dst =
	NS_BYTEFIELD_I("dst", &eth2_ns, PPT_ETHERNET2, 0, 6);
static struct ns_pktfld eth2_ns_src =
	NS_BYTEFIELD_I("src", &eth2_ns, PPT_ETHERNET2, 6, 6);
static struct ns_pktfld eth2_ns_ethtype =
	NS_BYTEFIELD_I("ethtype", &eth2_ns, PPT_ETHERNET2, 12, 2);
static struct ns_pktfld eth2_ns_payload =
	NS_BYTEFIELD_IDX_I("payload", &eth2_ns, PPT_TCP, 0, 0, PRP_OI_POFF);

struct ns_elem *stdproto_eth2_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&eth2_ns_dst, (struct ns_elem *)&eth2_ns_src,
	(struct ns_elem *)&eth2_ns_ethtype, (struct ns_elem *)&eth2_ns_payload
};


extern struct ns_elem *stdproto_arp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace arp_ns = 
	NS_NAMESPACE_I("arp", NULL, PPT_ARP, stdproto_arp_ns_elems);

static struct ns_pktfld arp_ns_hwfmt =
	NS_BYTEFIELD_I("hwfmt", &arp_ns, PPT_ARP, 0, 2);
static struct ns_pktfld arp_ns_prfmt =
	NS_BYTEFIELD_I("prfmt", &arp_ns, PPT_ARP, 2, 2);
static struct ns_pktfld arp_ns_hwlen =
	NS_BYTEFIELD_I("hwlen", &arp_ns, PPT_ARP, 4, 1);
static struct ns_pktfld arp_ns_prlen =
	NS_BYTEFIELD_I("prlen", &arp_ns, PPT_ARP, 5, 1);
static struct ns_pktfld arp_ns_op =
	NS_BYTEFIELD_I("op", &arp_ns, PPT_ARP, 6, 2);
static struct ns_pktfld arp_ns_sndhwaddr =
	NS_BYTEFIELD_IDX_I("sndhwaddr", &arp_ns, PPT_ARP, 8, 6, 
			   PRP_ARPFLD_ETHARP);
static struct ns_pktfld arp_ns_sndpraddr =
	NS_BYTEFIELD_IDX_I("sndpraddr", &arp_ns, PPT_ARP, 14, 4, 
			   PRP_ARPFLD_ETHARP);
static struct ns_pktfld arp_ns_trghwaddr =
	NS_BYTEFIELD_IDX_I("trghwaddr", &arp_ns, PPT_ARP, 18, 6, 
			   PRP_ARPFLD_ETHARP);
static struct ns_pktfld arp_ns_trgpraddr =
	NS_BYTEFIELD_IDX_I("trgpraddr", &arp_ns, PPT_ARP, 24, 4, 
			   PRP_ARPFLD_ETHARP);

struct ns_elem *stdproto_arp_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&arp_ns_hwfmt, (struct ns_elem *)&arp_ns_prfmt, 
	(struct ns_elem *)&arp_ns_hwlen, (struct ns_elem *)&arp_ns_prlen, 
	(struct ns_elem *)&arp_ns_op,
	(struct ns_elem *)&arp_ns_sndhwaddr, 
	(struct ns_elem *)&arp_ns_sndpraddr, 
	(struct ns_elem *)&arp_ns_trghwaddr, 
	(struct ns_elem *)&arp_ns_trgpraddr,
};


extern struct ns_elem *stdproto_ipv4_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace ipv4_ns = 
	NS_NAMESPACE_I("ip", NULL, PPT_IPV4, stdproto_ipv4_ns_elems);

static struct ns_pktfld ipv4_ns_vers =
	NS_BITFIELD_I("vers", &ipv4_ns, PPT_IPV4, 0, 0, 4);
static struct ns_pktfld ipv4_ns_hlen =
	NS_BITFIELD_I("hlen", &ipv4_ns, PPT_IPV4, 0, 4, 4);
static struct ns_pktfld ipv4_ns_diffsrv =
	NS_BITFIELD_I("diffsrv", &ipv4_ns, PPT_IPV4, 1, 0, 6);
static struct ns_pktfld ipv4_ns_ecn =
	NS_BITFIELD_I("ecn", &ipv4_ns, PPT_IPV4, 1, 6, 2);
static struct ns_pktfld ipv4_ns_len =
	NS_BYTEFIELD_I("len", &ipv4_ns, PPT_IPV4, 2, 2);
static struct ns_pktfld ipv4_ns_id =
	NS_BYTEFIELD_I("id", &ipv4_ns, PPT_IPV4, 4, 2);
static struct ns_pktfld ipv4_ns_rf =
	NS_BITFIELD_I("rf", &ipv4_ns, PPT_IPV4, 6, 0, 1);
static struct ns_pktfld ipv4_ns_df =
	NS_BITFIELD_I("df", &ipv4_ns, PPT_IPV4, 6, 1, 1);
static struct ns_pktfld ipv4_ns_mf =
	NS_BITFIELD_I("mf", &ipv4_ns, PPT_IPV4, 6, 2, 1);
static struct ns_pktfld ipv4_ns_fragoff =
	NS_BITFIELD_I("fragoff", &ipv4_ns, PPT_IPV4, 6, 3, 13);
static struct ns_pktfld ipv4_ns_ttl =
	NS_BYTEFIELD_I("ttl", &ipv4_ns, PPT_IPV4, 8, 1);
static struct ns_pktfld ipv4_ns_proto =
	NS_BYTEFIELD_I("proto", &ipv4_ns, PPT_IPV4, 9, 1);
static struct ns_pktfld ipv4_ns_cksum =
	NS_BYTEFIELD_I("cksum", &ipv4_ns, PPT_IPV4, 10, 2);
static struct ns_pktfld ipv4_ns_saddr =
	NS_BYTEFIELD_I("saddr", &ipv4_ns, PPT_IPV4, 12, 4);
static struct ns_pktfld ipv4_ns_daddr =
	NS_BYTEFIELD_I("daddr", &ipv4_ns, PPT_IPV4, 16, 4);
static struct ns_pktfld ipv4_ns_opt =
	NS_BYTEFIELD_I("opt", &ipv4_ns, PPT_IPV4, 20, 0);
static struct ns_pktfld ipv4_ns_payload =
	NS_BYTEFIELD_IDX_I("payload", &ipv4_ns, PPT_IPV4, 0, 0, PRP_OI_POFF);

struct ns_elem *stdproto_ipv4_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&ipv4_ns_vers, (struct ns_elem *)&ipv4_ns_hlen,
	(struct ns_elem *)&ipv4_ns_diffsrv, (struct ns_elem *)&ipv4_ns_ecn,
	(struct ns_elem *)&ipv4_ns_len, (struct ns_elem *)&ipv4_ns_id, 
	(struct ns_elem *)&ipv4_ns_rf, (struct ns_elem *)&ipv4_ns_df,
	(struct ns_elem *)&ipv4_ns_mf, (struct ns_elem *)&ipv4_ns_fragoff,
	(struct ns_elem *)&ipv4_ns_ttl, (struct ns_elem *)&ipv4_ns_proto,
	(struct ns_elem *)&ipv4_ns_cksum, (struct ns_elem *)&ipv4_ns_saddr,
	(struct ns_elem *)&ipv4_ns_daddr, (struct ns_elem *)&ipv4_ns_opt,
	(struct ns_elem *)&ipv4_ns_payload
};


extern struct ns_elem *stdproto_ipv6_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace ipv6_ns = 
	NS_NAMESPACE_I("ip6", NULL, PPT_IPV6, stdproto_ipv6_ns_elems);

static struct ns_pktfld ipv6_ns_vers =
	NS_BITFIELD_I("vers", &ipv6_ns, PPT_IPV6, 0, 0, 4);
static struct ns_pktfld ipv6_ns_class =
	NS_BITFIELD_I("class", &ipv6_ns, PPT_IPV6, 0, 4, 8);
static struct ns_pktfld ipv6_ns_flowid =
	NS_BITFIELD_I("flowid", &ipv6_ns, PPT_IPV6, 0, 12, 20);
static struct ns_pktfld ipv6_ns_len =
	NS_BYTEFIELD_I("len", &ipv6_ns, PPT_IPV6, 4, 2);
static struct ns_pktfld ipv6_ns_nxthdr =
	NS_BYTEFIELD_I("nxthdr", &ipv6_ns, PPT_IPV6, 6, 1);
static struct ns_pktfld ipv6_ns_hoplim =
	NS_BYTEFIELD_I("hoplim", &ipv6_ns, PPT_IPV6, 7, 1);
static struct ns_pktfld ipv6_ns_saddr =
	NS_BYTEFIELD_I("saddr", &ipv6_ns, PPT_IPV6, 8, 16);
static struct ns_pktfld ipv6_ns_daddr =
	NS_BYTEFIELD_I("daddr", &ipv6_ns, PPT_IPV6, 24, 16);
static struct ns_pktfld ipv6_ns_exth =
	NS_BYTEFIELD_I("exth", &ipv6_ns, PPT_IPV4, 20, 0);
static struct ns_pktfld ipv6_ns_payload =
	NS_BYTEFIELD_IDX_I("payload", &ipv6_ns, PPT_IPV6, 0, 0, PRP_OI_POFF);

struct ns_elem *stdproto_ipv6_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&ipv6_ns_vers, (struct ns_elem *)&ipv6_ns_class,
	(struct ns_elem *)&ipv6_ns_flowid, (struct ns_elem *)&ipv6_ns_len,
	(struct ns_elem *)&ipv6_ns_nxthdr, (struct ns_elem *)&ipv6_ns_hoplim,
	(struct ns_elem *)&ipv6_ns_saddr, (struct ns_elem *)&ipv6_ns_daddr,
	(struct ns_elem *)&ipv6_ns_exth, (struct ns_elem *)&ipv6_ns_payload
};


extern struct ns_elem *stdproto_icmp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace icmp_ns = 
	NS_NAMESPACE_I("icmp", NULL, PPT_ICMP, stdproto_icmp_ns_elems);

static struct ns_pktfld icmp_ns_type =
	NS_BYTEFIELD_I("type", &icmp_ns, PPT_ICMP, 0, 1);
static struct ns_pktfld icmp_ns_code =
	NS_BYTEFIELD_I("code", &icmp_ns, PPT_ICMP, 1, 1);
static struct ns_pktfld icmp_ns_cksum =
	NS_BYTEFIELD_I("cksum", &icmp_ns, PPT_ICMP, 2, 2);
static struct ns_pktfld icmp_ns_id =
	NS_BYTEFIELD_I("id", &icmp_ns, PPT_ICMP, 4, 2);
static struct ns_pktfld icmp_ns_seq =
	NS_BYTEFIELD_I("seq", &icmp_ns, PPT_ICMP, 6, 2);
static struct ns_pktfld icmp_ns_mtu =
	NS_BYTEFIELD_I("mtu", &icmp_ns, PPT_ICMP, 6, 2);
static struct ns_pktfld icmp_ns_ptr =
	NS_BYTEFIELD_I("ptr", &icmp_ns, PPT_ICMP, 4, 1);
static struct ns_pktfld icmp_ns_gateway =
	NS_BYTEFIELD_I("gw", &icmp_ns, PPT_ICMP, 4, 4);
static struct ns_pktfld icmp_ns_unused =
	NS_BYTEFIELD_I("unused", &icmp_ns, PPT_ICMP, 4, 4);
static struct ns_pktfld icmp_ns_payload =
	NS_BYTEFIELD_IDX_I("payload", &icmp_ns, PPT_ICMP, 0, 0, PRP_OI_POFF);

struct ns_elem *stdproto_icmp_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&icmp_ns_type, (struct ns_elem *)&icmp_ns_code,
	(struct ns_elem *)&icmp_ns_cksum, (struct ns_elem *)&icmp_ns_id,
	(struct ns_elem *)&icmp_ns_seq, (struct ns_elem *)&icmp_ns_mtu,
	(struct ns_elem *)&icmp_ns_ptr, (struct ns_elem *)&icmp_ns_gateway,
	(struct ns_elem *)&icmp_ns_unused, (struct ns_elem *)&icmp_ns_payload
};


extern struct ns_elem *stdproto_icmp6_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace icmp6_ns = 
	NS_NAMESPACE_I("icmp6", NULL, PPT_ICMP6, stdproto_icmp6_ns_elems);

static struct ns_pktfld icmp6_ns_type =
	NS_BYTEFIELD_I("type", &icmp6_ns, PPT_ICMP6, 0, 1);
static struct ns_pktfld icmp6_ns_code =
	NS_BYTEFIELD_I("code", &icmp6_ns, PPT_ICMP6, 1, 1);
static struct ns_pktfld icmp6_ns_cksum =
	NS_BYTEFIELD_I("cksum", &icmp6_ns, PPT_ICMP6, 2, 2);
static struct ns_pktfld icmp6_ns_hdata =
	NS_BYTEFIELD_I("hdata", &icmp6_ns, PPT_ICMP6, 4, 4);
static struct ns_pktfld icmp6_ns_payload =
	NS_BYTEFIELD_IDX_I("payload", &icmp6_ns, PPT_ICMP6, 0, 0, PRP_OI_POFF);

struct ns_elem *stdproto_icmp6_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&icmp6_ns_type, (struct ns_elem *)&icmp6_ns_code, 
	(struct ns_elem *)&icmp6_ns_cksum, (struct ns_elem *)&icmp6_ns_hdata,
	(struct ns_elem *)&icmp6_ns_payload
};


extern struct ns_elem *stdproto_udp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace udp_ns = 
	NS_NAMESPACE_I("udp", NULL, PPT_UDP, stdproto_udp_ns_elems);

static struct ns_pktfld udp_ns_sport =
	NS_BYTEFIELD_I("sport", &udp_ns, PPT_UDP, 0, 2);
static struct ns_pktfld udp_ns_dport =
	NS_BYTEFIELD_I("dport", &udp_ns, PPT_UDP, 2, 2);
static struct ns_pktfld udp_ns_len =
	NS_BYTEFIELD_I("len", &udp_ns, PPT_UDP, 4, 2);
static struct ns_pktfld udp_ns_cksum =
	NS_BYTEFIELD_I("cksum", &udp_ns, PPT_UDP, 6, 2);
static struct ns_pktfld udp_ns_payload =
	NS_BYTEFIELD_IDX_I("payload", &udp_ns, PPT_UDP, 0, 0, PRP_OI_POFF);

struct ns_elem *stdproto_udp_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&udp_ns_sport, (struct ns_elem *)&udp_ns_dport, 
	(struct ns_elem *)&udp_ns_len, (struct ns_elem *)&udp_ns_cksum,
	(struct ns_elem *)&udp_ns_payload
};


extern struct ns_elem *stdproto_tcp_ns_elems[STDPROTO_NS_ELEN];
static struct ns_namespace tcp_ns = 
	NS_NAMESPACE_I("tcp", NULL, PPT_TCP, stdproto_tcp_ns_elems);

static struct ns_pktfld tcp_ns_sport =
	NS_BYTEFIELD_I("sport", &tcp_ns, PPT_TCP, 0, 2);
static struct ns_pktfld tcp_ns_dport =
	NS_BYTEFIELD_I("dport", &tcp_ns, PPT_TCP, 2, 2);
static struct ns_pktfld tcp_ns_seqn =
	NS_BYTEFIELD_I("seqn", &tcp_ns, PPT_TCP, 4, 4);
static struct ns_pktfld tcp_ns_ackn =
	NS_BYTEFIELD_I("ackn", &tcp_ns, PPT_TCP, 8, 4);
static struct ns_pktfld tcp_ns_doff =
	NS_BITFIELD_I("doff", &tcp_ns, PPT_TCP, 12, 0, 4);
static struct ns_pktfld tcp_ns_resv =
	NS_BITFIELD_I("resv", &tcp_ns, PPT_TCP, 12, 4, 3);
static struct ns_pktfld tcp_ns_nsum =
	NS_BITFIELD_I("nsum", &tcp_ns, PPT_TCP, 12, 7, 1);
static struct ns_pktfld tcp_ns_ece =
	NS_BITFIELD_I("ece", &tcp_ns, PPT_TCP, 13, 0, 1);
static struct ns_pktfld tcp_ns_cwr =
	NS_BITFIELD_I("cwr", &tcp_ns, PPT_TCP, 13, 1, 1);
static struct ns_pktfld tcp_ns_urg =
	NS_BITFIELD_I("urg", &tcp_ns, PPT_TCP, 13, 2, 1);
static struct ns_pktfld tcp_ns_ack =
	NS_BITFIELD_I("ack", &tcp_ns, PPT_TCP, 13, 3, 1);
static struct ns_pktfld tcp_ns_psh =
	NS_BITFIELD_I("psh", &tcp_ns, PPT_TCP, 13, 4, 1);
static struct ns_pktfld tcp_ns_rst =
	NS_BITFIELD_I("rst", &tcp_ns, PPT_TCP, 13, 5, 1);
static struct ns_pktfld tcp_ns_syn =
	NS_BITFIELD_I("syn", &tcp_ns, PPT_TCP, 13, 6, 1);
static struct ns_pktfld tcp_ns_fin =
	NS_BITFIELD_I("fin", &tcp_ns, PPT_TCP, 13, 7, 1);
static struct ns_pktfld tcp_ns_win =
	NS_BYTEFIELD_I("win", &tcp_ns, PPT_TCP, 14, 2);
static struct ns_pktfld tcp_ns_cksum =
	NS_BYTEFIELD_I("cksum", &tcp_ns, PPT_TCP, 16, 2);
static struct ns_pktfld tcp_ns_urgp =
	NS_BYTEFIELD_I("urgp", &tcp_ns, PPT_TCP, 18, 2);
static struct ns_pktfld tcp_ns_opt =
	NS_BYTEFIELD_I("opt", &tcp_ns, PPT_TCP, 20, 0);
static struct ns_pktfld tcp_ns_payload =
	NS_BYTEFIELD_IDX_I("payload", &tcp_ns, PPT_TCP, 0, 0, PRP_OI_POFF);

/* option forward declarations */
extern struct ns_elem *stdproto_tcp_mss_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_tcp_wscale_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_tcp_sackok_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_tcp_sack_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_tcp_ts_ns_elems[STDPROTO_NS_SUB_ELEN];
extern struct ns_elem *stdproto_tcp_md5_ns_elems[STDPROTO_NS_SUB_ELEN];

/* TCP MSS Option */
static struct ns_namespace tcp_mss_ns = 
	NS_NAMESPACE_IDX_I("mss", &tcp_ns, PPT_TCP, PRP_TCPFLD_MSS,
			   stdproto_tcp_mss_ns_elems);
static struct ns_pktfld tcp_mss_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_mss_ns, PPT_TCP, 0, 1, PRP_TCPFLD_MSS);
static struct ns_pktfld tcp_mss_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_mss_ns, PPT_TCP, 1, 1, PRP_TCPFLD_MSS);
static struct ns_pktfld tcp_mss_mss =
	NS_BYTEFIELD_IDX_I("mss", &tcp_mss_ns, PPT_TCP, 2, 2, PRP_TCPFLD_MSS);
struct ns_elem *stdproto_tcp_mss_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_mss_kind, (struct ns_elem *)&tcp_mss_len,
	(struct ns_elem *)&tcp_mss_mss,
};

/* TCP Window Scale Option */
static struct ns_namespace tcp_wscale_ns = 
	NS_NAMESPACE_IDX_I("wscale", &tcp_ns, PPT_TCP, PRP_TCPFLD_WSCALE,
			   stdproto_tcp_wscale_ns_elems);
static struct ns_pktfld tcp_wscale_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_wscale_ns, PPT_TCP, 0, 1, 
			   PRP_TCPFLD_WSCALE);
static struct ns_pktfld tcp_wscale_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_wscale_ns, PPT_TCP, 1, 1, 
			   PRP_TCPFLD_WSCALE);
static struct ns_pktfld tcp_wscale_scale =
	NS_BYTEFIELD_IDX_I("scale", &tcp_wscale_ns, PPT_TCP, 2, 2,
			   PRP_TCPFLD_WSCALE);
struct ns_elem *stdproto_tcp_wscale_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_wscale_kind, (struct ns_elem *)&tcp_wscale_len,
	(struct ns_elem *)&tcp_wscale_scale,
};

/* TCP Selective Acknowledgement Permitted Option */
static struct ns_namespace tcp_sackok_ns = 
	NS_NAMESPACE_IDX_I("sackok", &tcp_ns, PPT_TCP, PRP_TCPFLD_SACKOK,
			   stdproto_tcp_sackok_ns_elems);
static struct ns_pktfld tcp_sackok_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_sackok_ns, PPT_TCP, 0, 1, 
			   PRP_TCPFLD_SACKOK);
static struct ns_pktfld tcp_sackok_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_sackok_ns, PPT_TCP, 1, 1, 
			   PRP_TCPFLD_SACKOK);
struct ns_elem *stdproto_tcp_sackok_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_sackok_kind, (struct ns_elem *)&tcp_sackok_len,
};

/* TCP Selective Acknowledgement Option */
static struct ns_namespace tcp_sack_ns = 
	NS_NAMESPACE_IDX_I("sack", &tcp_ns, PPT_TCP, PRP_TCPFLD_SACK,
			   stdproto_tcp_sack_ns_elems);
static struct ns_pktfld tcp_sack_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_sack_ns, PPT_TCP, 0, 1, 
			   PRP_TCPFLD_SACK);
static struct ns_pktfld tcp_sack_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_sack_ns, PPT_TCP, 1, 1, 
			   PRP_TCPFLD_SACK);
static struct ns_pktfld tcp_sack_blocks =
	NS_BYTEFIELD_IDX_I("blocks", &tcp_sack_ns, PPT_TCP, 2, 0, 
			   PRP_TCPFLD_SACK);
struct ns_elem *stdproto_tcp_sack_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_sack_kind, (struct ns_elem *)&tcp_sack_len,
	(struct ns_elem *)&tcp_sack_blocks,
};


/* TCP Timestamp Option */
static struct ns_namespace tcp_ts_ns = 
	NS_NAMESPACE_IDX_I("ts", &tcp_ns, PPT_TCP, PRP_TCPFLD_TSTAMP,
			   stdproto_tcp_ts_ns_elems);
static struct ns_pktfld tcp_ts_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_ts_ns, PPT_TCP, 0, 1, 
			   PRP_TCPFLD_TSTAMP);
static struct ns_pktfld tcp_ts_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_ts_ns, PPT_TCP, 1, 1, 
			   PRP_TCPFLD_TSTAMP);
static struct ns_pktfld tcp_ts_val =
	NS_BYTEFIELD_IDX_I("val", &tcp_ts_ns, PPT_TCP, 2, 4, 
			   PRP_TCPFLD_TSTAMP);
static struct ns_pktfld tcp_ts_echo =
	NS_BYTEFIELD_IDX_I("echo", &tcp_ts_ns, PPT_TCP, 6, 4, 
			   PRP_TCPFLD_TSTAMP);
struct ns_elem *stdproto_tcp_ts_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_ts_kind, (struct ns_elem *)&tcp_ts_len,
	(struct ns_elem *)&tcp_ts_val, (struct ns_elem *)&tcp_ts_echo,
};


/* TCP MD5 Signature Option */
static struct ns_namespace tcp_md5_ns = 
	NS_NAMESPACE_IDX_I("md5", &tcp_ns, PPT_TCP, PRP_TCPFLD_MD5,
			   stdproto_tcp_md5_ns_elems);
static struct ns_pktfld tcp_md5_kind =
	NS_BYTEFIELD_IDX_I("kind", &tcp_md5_ns, PPT_TCP, 0, 1, 
			   PRP_TCPFLD_MD5);
static struct ns_pktfld tcp_md5_len =
	NS_BYTEFIELD_IDX_I("len", &tcp_md5_ns, PPT_TCP, 1, 1, 
			   PRP_TCPFLD_MD5);
static struct ns_pktfld tcp_md5_sig =
	NS_BYTEFIELD_IDX_I("sig", &tcp_md5_ns, PPT_TCP, 2, 16, 
			   PRP_TCPFLD_MD5);
struct ns_elem *stdproto_tcp_md5_ns_elems[STDPROTO_NS_SUB_ELEN] = {
	(struct ns_elem *)&tcp_md5_kind, (struct ns_elem *)&tcp_md5_len,
	(struct ns_elem *)&tcp_md5_sig,
};

struct ns_elem *stdproto_tcp_ns_elems[STDPROTO_NS_ELEN] = {
	(struct ns_elem *)&tcp_ns_sport, (struct ns_elem *)&tcp_ns_dport,
	(struct ns_elem *)&tcp_ns_seqn, (struct ns_elem *)&tcp_ns_ackn,
	(struct ns_elem *)&tcp_ns_doff, (struct ns_elem *)&tcp_ns_resv,
	(struct ns_elem *)&tcp_ns_nsum, (struct ns_elem *)&tcp_ns_ece,
	(struct ns_elem *)&tcp_ns_cwr, (struct ns_elem *)&tcp_ns_urg,
	(struct ns_elem *)&tcp_ns_ack, (struct ns_elem *)&tcp_ns_psh,
	(struct ns_elem *)&tcp_ns_rst, (struct ns_elem *)&tcp_ns_syn,
	(struct ns_elem *)&tcp_ns_fin, (struct ns_elem *)&tcp_ns_win,
	(struct ns_elem *)&tcp_ns_cksum, (struct ns_elem *)&tcp_ns_urgp,
	(struct ns_elem *)&tcp_ns_opt, (struct ns_elem *)&tcp_ns_payload,

	/* Options */
	(struct ns_elem *)&tcp_mss_ns,
	(struct ns_elem *)&tcp_wscale_ns,
	(struct ns_elem *)&tcp_sackok_ns,
	(struct ns_elem *)&tcp_sack_ns,
	(struct ns_elem *)&tcp_ts_ns,
	(struct ns_elem *)&tcp_md5_ns,
};


int register_std_proto()
{
	if (pp_register(PPT_ETHERNET2, &eth_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PPT_ARP, &arp_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PPT_IPV4, &ipv4_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PPT_IPV6, &ipv6_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PPT_ICMP, &icmp_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PPT_ICMP6, &icmpv6_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PPT_UDP, &udp_proto_parser_ops) < 0)
		goto fail;
	if (pp_register(PPT_TCP, &tcp_proto_parser_ops) < 0)
		goto fail;

	if (ns_add_elem(NULL, (struct ns_elem *)&eth2_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&arp_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&ipv4_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&ipv6_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&icmp_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&icmp6_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&udp_ns) < 0)
		goto fail;
	if (ns_add_elem(NULL, (struct ns_elem *)&tcp_ns) < 0)
		goto fail;

	return 0;
fail:
	unregister_std_proto();
	return -1;
}


void unregister_std_proto()
{
	pp_unregister(PPT_ETHERNET2);
	pp_unregister(PPT_ARP);
	pp_unregister(PPT_IPV4);
	pp_unregister(PPT_IPV6);
	pp_unregister(PPT_ICMP);
	pp_unregister(PPT_ICMP6);
	pp_unregister(PPT_UDP);
	pp_unregister(PPT_TCP);

	ns_rem_elem((struct ns_elem *)&eth2_ns);
	ns_rem_elem((struct ns_elem *)&arp_ns);
	ns_rem_elem((struct ns_elem *)&ipv4_ns);
	ns_rem_elem((struct ns_elem *)&ipv6_ns);
	ns_rem_elem((struct ns_elem *)&icmp_ns);
	ns_rem_elem((struct ns_elem *)&icmp6_ns);
	ns_rem_elem((struct ns_elem *)&udp_ns);
	ns_rem_elem((struct ns_elem *)&tcp_ns);
}
